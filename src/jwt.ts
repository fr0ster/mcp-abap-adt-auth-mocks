/**
 * Mints syntactically valid JWTs.
 *
 * Nothing in the family verifies the signature — providers only parse the
 * payload for `exp` — so the signature segment is deliberately not
 * cryptographically meaningful. What matters is the shape: three parts, and a
 * base64url payload carrying `exp` and `iat`.
 */

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

export function mintJwt(opts: {
  expiresInSeconds: number;
  claims?: Record<string, unknown>;
}): string {
  const iat = Math.floor(Date.now() / 1000);
  const header = b64url({ alg: 'RS256', typ: 'JWT' });
  const payload = b64url({
    iat,
    exp: iat + opts.expiresInSeconds,
    ...opts.claims,
  });
  return `${header}.${payload}.mock-signature-not-verified`;
}
