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
  /** True when credentials arrived in the Authorization header. */
  usedAuthorizationHeader: boolean;
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

export function readClientAuth(req: RecordedRequest): ClientAuth {
  const header = req.headers.authorization ?? '';
  let basicId: string | undefined;
  let basicSecret: string | undefined;

  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep >= 0) {
      basicId = decodeFormComponent(decoded.slice(0, sep));
      basicSecret = decodeFormComponent(decoded.slice(sep + 1));
    }
  }

  const bodyId = req.body.client_id;
  const bodySecret = req.body.client_secret;
  const usedAuthorizationHeader = basicId !== undefined;

  return {
    clientId: basicId ?? bodyId,
    clientSecret: basicSecret ?? bodySecret,
    usedAuthorizationHeader,
    // Two authentication methods: Basic plus a body client_secret, whether
    // or not it agrees with the Basic secret. Or one method presented
    // inconsistently: a body client_id that disagrees with Basic's. A body
    // client_id that merely agrees with Basic is neither — see the
    // `conflict` doc comment above.
    conflict:
      usedAuthorizationHeader &&
      ((bodyId !== undefined && bodyId !== basicId) ||
        bodySecret !== undefined),
  };
}
