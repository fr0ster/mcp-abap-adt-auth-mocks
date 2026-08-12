/**
 * The three client authentication methods a real token endpoint accepts.
 *
 * They are not interchangeable in practice: UAA sends only HTTP Basic and puts
 * no `client_id` in the body, while OIDC puts `client_id` in the body. A mock
 * that assumed one shape would reject a real client.
 */

import type { RecordedRequest } from './server';

export interface ClientAuth {
  clientId?: string;
  clientSecret?: string;
  /**
   * True as soon as an `Authorization: Basic` header is present, whether or
   * not it could be parsed. Basic having been *attempted* — not merely
   * having *succeeded* — is what RFC 6749 §5.2's 401-with-`WWW-Authenticate`
   * rule is conditioned on: a client that sent a malformed Basic header
   * still authenticated "via the header" in the sense that clause cares
   * about.
   *
   * `auth-scheme` is matched case-insensitively (RFC 7235 §2.1: it is a
   * `token`, and tokens in this grammar are case-insensitive keywords —
   * `basic`, `BASIC` and `BaSiC` are the same scheme), and one-or-more
   * spaces before the payload are tolerated (RFC 7235's grammar is
   * `auth-scheme 1*SP token68`, not exactly one). A bare `Basic` with no
   * payload at all still counts as an attempt — see `malformedBasic` below.
   */
  usedAuthorizationHeader: boolean;
  /**
   * True when an `Authorization: Basic` header was present but could not be
   * read as a credential: its payload is not valid base64, it decodes to a
   * value with no `:` separator, or there is no payload at all (a bare
   * `Basic`, or `Basic` followed only by spaces). The bare-scheme case is
   * deliberately treated as an attempt rather than as "no Basic": a client
   * that sends the scheme keyword names Basic as its method, and the
   * alternative — quietly falling through to the body — is exactly the hole
   * a malformed-payload Basic header closed in the previous round, reopened
   * for a caller that sends the scheme and nothing else. This is refused
   * before any fallback to body credentials and before the duplicate-method
   * check below — a malformed attempt is its own mistake, not a reason to
   * try the body instead. See `authenticateClient` in `./clients`.
   */
  malformedBasic: boolean;
  /**
   * True when the request uses more than one authentication method (RFC
   * 6749 §2.3: "The client MUST NOT use more than one authentication method
   * in each request"), or when a body `client_id` disagrees with the one
   * decoded from Basic.
   *
   * A body `client_id` that merely *agrees* with Basic is neither: RFC 6749
   * §3.2.1 says "a client MAY use the 'client_id' request parameter to
   * identify itself when sending requests to the token endpoint", and a
   * bare, agreeing `client_id` authenticates nothing an attacker could not
   * already read off the Basic header — it is identification, not a second
   * credential. A body `client_secret` is different: it is itself a
   * credential, so presenting it alongside Basic is two authentication
   * methods in the same request and is refused even when the two secrets
   * happen to match.
   *
   * Never true when `malformedBasic` is true: a malformed Basic attempt has
   * no decoded `basicId` to compare the body against, and it is refused on
   * its own before this comparison would mean anything.
   */
  conflict: boolean;
}

/**
 * Decodes one half of a Basic credential per RFC 6749 §2.3.1: the client
 * identifier and secret are `application/x-www-form-urlencoded`-encoded
 * before being placed in the `user-pass` and Base64-encoded, so `+` means
 * space and the rest is `decodeURIComponent`. A credential that fails to
 * decode is returned raw rather than thrown on — a malformed credential must
 * still reach the comparison below and lose as `invalid_client`, not crash
 * the request.
 */
function decodeFormComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}

/**
 * RFC 4648 §4 standard base64: zero or more four-character groups from the
 * alphabet, then an optional final group padded to four characters with one
 * or two `=`. Matched against the whole payload before it is ever handed to
 * `Buffer.from(…, 'base64')`, which is lenient — it silently drops
 * characters outside the alphabet rather than failing — so relying on it to
 * reject `!!!` would not work; this check gives the payload's shape an
 * explicit yes/no answer first.
 */
const BASE64_SHAPE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Matches the `Basic` auth-scheme per RFC 7235 §2.1/§2 grammar
 * (`credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`):
 * the scheme keyword itself is case-insensitive, and when a payload follows
 * it is separated by one or more spaces, not exactly one. Anchored at both
 * ends so a different scheme that merely starts with these letters — e.g.
 * `Basicish xyz` — does not match. Capture group 1 is the payload; it is
 * `undefined` for a bare `Basic` and `''` for `Basic` followed only by
 * spaces, both of which `readClientAuth` treats as an attempted-but-empty
 * payload (see `malformedBasic`'s doc comment).
 */
const BASIC_SCHEME = /^basic(?:[ ]+(.*))?$/i;

export function readClientAuth(req: RecordedRequest): ClientAuth {
  const header = req.headers.authorization ?? '';
  let basicId: string | undefined;
  let basicSecret: string | undefined;
  let malformedBasic = false;
  // Presence, not success: an attempt that turns out unparsable still
  // attempted Basic, and RFC 6749 §5.2's 401-with-WWW-Authenticate rule is
  // conditioned on the attempt, not on whether it happened to parse.
  const basicMatch = BASIC_SCHEME.exec(header);
  const usedAuthorizationHeader = basicMatch !== null;

  if (basicMatch) {
    // A bare `Basic` (group 1 undefined) is treated the same as an empty
    // payload: BASE64_SHAPE accepts '' (zero groups), Buffer.from('', …)
    // decodes to '', and the missing ':' below flags it malformed — no
    // special case needed beyond defaulting to ''.
    const payload = basicMatch[1] ?? '';
    if (BASE64_SHAPE.test(payload)) {
      const decoded = Buffer.from(payload, 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep >= 0) {
        basicId = decodeFormComponent(decoded.slice(0, sep));
        basicSecret = decodeFormComponent(decoded.slice(sep + 1));
      } else {
        malformedBasic = true;
      }
    } else {
      malformedBasic = true;
    }
  }

  const bodyId = req.body.client_id;
  const bodySecret = req.body.client_secret;

  return {
    clientId: basicId ?? bodyId,
    clientSecret: basicSecret ?? bodySecret,
    usedAuthorizationHeader,
    malformedBasic,
    // Two authentication methods: Basic plus a body client_secret, whether
    // or not it agrees with the Basic secret. Or one method presented
    // inconsistently: a body client_id that disagrees with Basic's. A body
    // client_id that merely agrees with Basic is neither — see the
    // `conflict` doc comment above. Never evaluated as true for a malformed
    // Basic attempt, which has no decoded basicId to compare against and is
    // refused on its own before this would run.
    conflict:
      usedAuthorizationHeader &&
      !malformedBasic &&
      ((bodyId !== undefined && bodyId !== basicId) ||
        bodySecret !== undefined),
  };
}
