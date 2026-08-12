/**
 * RFC 6749 §5.2 error responses.
 *
 * `invalid_client` is the one case with a conditional status: 401 with a
 * matching `WWW-Authenticate` when the client authenticated through the
 * `Authorization` header, 400 otherwise. Always answering 401 would enshrine
 * behaviour the specification does not require.
 */

import type * as http from 'node:http';

export function sendOAuthError(
  res: http.ServerResponse,
  error: string,
  description: string,
  opts: { usedAuthorizationHeader?: boolean } = {},
): void {
  const viaHeader = opts.usedAuthorizationHeader === true;
  res.statusCode = error === 'invalid_client' && viaHeader ? 401 : 400;
  if (res.statusCode === 401) {
    res.setHeader('WWW-Authenticate', 'Basic realm="mock"');
  }
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({ error, error_description: description }));
}
