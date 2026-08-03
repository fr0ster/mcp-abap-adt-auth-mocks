import { describe, expect, it } from '@jest/globals';
import { mintJwt } from '../jwt';

describe('mintJwt', () => {
  // BaseTokenProvider.parseExpirationFromJWT splits on '.', requires exactly
  // three parts and reads `exp`. Anything else yields undefined expiry, and a
  // provider handed such a token has no basis to consider it fresh.
  it('produces three dot-separated parts', () => {
    expect(mintJwt({ expiresInSeconds: 60 }).split('.')).toHaveLength(3);
  });

  it('carries exp and iat the way a provider reads them', () => {
    const before = Math.floor(Date.now() / 1000);
    const token = mintJwt({ expiresInSeconds: 3600 });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.exp - claims.iat).toBe(3600);
  });

  it('can mint an already-expired token', () => {
    const token = mintJwt({ expiresInSeconds: -1 });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));
  });

  it('merges extra claims', () => {
    const token = mintJwt({ expiresInSeconds: 60, claims: { sub: 'u1' } });
    const claims = JSON.parse(
      Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
    );
    expect(claims.sub).toBe('u1');
  });
});
