import { describe, expect, it } from '@jest/globals';
import { sendOAuthError } from '../oauthErrors';
import { startServer } from '../server';

describe('sendOAuthError', () => {
  it('answers 400 with an RFC 6749 body', async () => {
    const s = await startServer({
      'GET /e': (_r, res) => sendOAuthError(res, 'invalid_grant', 'bad code'),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(400);
      expect(
        (await res.json()) as { error: string; error_description: string },
      ).toEqual({
        error: 'invalid_grant',
        error_description: 'bad code',
      });
    } finally {
      await s.close();
    }
  });

  // RFC 6749 §5.2: 401 with WWW-Authenticate only when the client tried to
  // authenticate through the Authorization header; 400 otherwise. A mock that
  // always answered 401 would enshrine behaviour the RFC does not require.
  it('answers 401 with WWW-Authenticate for invalid_client via the header', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_client', 'nope', {
          usedAuthorizationHeader: true,
        }),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/^Basic/);
    } finally {
      await s.close();
    }
  });

  it('answers 400 for invalid_client sent in the body', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_client', 'nope', {
          usedAuthorizationHeader: false,
        }),
    });
    try {
      expect((await fetch(`${s.url}/e`)).status).toBe(400);
    } finally {
      await s.close();
    }
  });

  // The conditional status is scoped to invalid_client specifically, not to
  // "any error sent via the header" — a non-invalid_client error must stay at
  // 400 with no WWW-Authenticate even when usedAuthorizationHeader is true.
  it('answers 400 with no WWW-Authenticate for invalid_grant via the header', async () => {
    const s = await startServer({
      'GET /e': (_r, res) =>
        sendOAuthError(res, 'invalid_grant', 'bad code', {
          usedAuthorizationHeader: true,
        }),
    });
    try {
      const res = await fetch(`${s.url}/e`);
      expect(res.status).toBe(400);
      expect(res.headers.get('www-authenticate')).toBeNull();
    } finally {
      await s.close();
    }
  });
});
