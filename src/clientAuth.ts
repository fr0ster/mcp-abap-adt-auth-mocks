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
  /** True when header and body both carry a client_id and they disagree. */
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

  return {
    clientId: basicId ?? bodyId,
    clientSecret: basicSecret ?? bodySecret,
    usedAuthorizationHeader: basicId !== undefined,
    conflict:
      basicId !== undefined && bodyId !== undefined && basicId !== bodyId,
  };
}
