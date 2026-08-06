import { describe, expect, it } from '@jest/globals';
import { startMockUaa } from '../uaa';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

/** Drives /authorize the way a browser would, returning the code it lands with. */
async function getCode(
  url: string,
  redirectUri: string,
  clientId = 'mock-client',
): Promise<string> {
  const res = await fetch(
    `${url}/oauth/authorize?client_id=${encodeURIComponent(clientId)}` +
      `&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}`,
    { redirect: 'manual' },
  );
  const location = res.headers.get('location') ?? '';
  return new URL(location).searchParams.get('code') ?? '';
}

describe('mock UAA', () => {
  it('redirects to the redirect_uri with a code', async () => {
    const uaa = await startMockUaa();
    try {
      const code = await getCode(uaa.url, 'http://localhost:61001/callback');
      expect(code).toBeTruthy();
    } finally {
      await uaa.close();
    }
  });

  it('exchanges the code for a JWT access token and a refresh token', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as {
        access_token: string;
        refresh_token: string;
      };
      expect(json.access_token.split('.')).toHaveLength(3);
      expect(json.refresh_token).toBeTruthy();
    } finally {
      await uaa.close();
    }
  });

  // This is the refusal the previous arc had to guard by hand, twice.
  it('refuses a redirect_uri that differs from the authorize request', async () => {
    const uaa = await startMockUaa();
    try {
      const code = await getCode(uaa.url, 'http://localhost:61001/callback');
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:3001/callback',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('refuses a code used twice', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const exchange = () =>
        fetch(`${uaa.url}/oauth/token`, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            authorization: basic('mock-client', 'mock-secret'),
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
          }).toString(),
        });
      expect((await exchange()).status).toBe(200);
      const second = await exchange();
      expect(second.status).toBe(400);
      expect(((await second.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('refuses an expired code', async () => {
    const uaa = await startMockUaa({ codeLifetimeMs: 50 });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      await new Promise((r) => setTimeout(r, 120));
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('refuses a code that was never issued', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'never-issued',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('answers 401 with WWW-Authenticate when Basic credentials are wrong', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'wrong'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBeTruthy();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_client',
      );
    } finally {
      await uaa.close();
    }
  });

  it('answers 401 with WWW-Authenticate when the client_id is not registered at all', async () => {
    const uaa = await startMockUaa();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri);
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('nobody', 'whatever'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toBeTruthy();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_client',
      );
    } finally {
      await uaa.close();
    }
  });

  it('redirects with error=access_denied when told to deny', async () => {
    const uaa = await startMockUaa({ authorize: 'deny' });
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}`,
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('access_denied');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await uaa.close();
    }
  });

  it('journals what the client sent', async () => {
    const uaa = await startMockUaa();
    try {
      await getCode(uaa.url, 'http://localhost:49999/callback');
      const authorize = uaa.requests.find((r) => r.path === '/oauth/authorize');
      expect(authorize?.query.redirect_uri).toBe(
        'http://localhost:49999/callback',
      );
    } finally {
      await uaa.close();
    }
  });

  // The registry lookup and the secret comparison are two questions, and every
  // case above answers both at once: an unknown client that also presents a
  // wrong secret is refused by the comparison, whatever the lookup does. With
  // `requireClientSecret: false` the comparison is skipped, so the lookup is
  // the only thing left — and this is the only case that proves it works.
  it('refuses an unregistered client even when no secret is required', async () => {
    const uaa = await startMockUaa({ requireClientSecret: false });
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('nobody', ''),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_client',
      );
    } finally {
      await uaa.close();
    }
  });

  // A code belongs to the client it was issued to. A server that only checks
  // "is this a client I know" lets one client redeem another's consent.
  it('refuses a code issued to a different client', async () => {
    const uaa = await startMockUaa({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri, 'first-client');
      expect(code).toBeTruthy();

      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(400);
      const json = (await res.json()) as {
        error: string;
        error_description?: string;
      };
      expect(json.error).toBe('invalid_grant');
      expect(json.error_description).toMatch(/different client/i);
    } finally {
      await uaa.close();
    }
  });

  it('refuses an unregistered client_id without redirecting to it', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=nobody&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_request',
      );
    } finally {
      await uaa.close();
    }
  });
});
