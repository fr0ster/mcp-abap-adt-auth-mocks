import { describe, expect, it } from '@jest/globals';
import { startMockUaa } from '../uaa';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

// RFC 6749 §2.3.1: the client identifier and secret are
// application/x-www-form-urlencoded-encoded *before* going into `user-pass`.
// `encodeURIComponent` matches form encoding for every character this suite
// exercises (it never needs the `+`-for-space rule the server also honours).
const basicFormEncoded = (id: string, secret: string) =>
  `Basic ${Buffer.from(
    `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`,
  ).toString('base64')}`;

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

  // RFC 6749 §2.3.1 requires the client identifier and secret to be
  // form-decoded after Base64. A registered secret containing ':' — the
  // sharpest case, since ':' is also the user-pass separator — must survive
  // that decoding, or a real client whose secret needs encoding is refused
  // as invalid_client for a mismatch the mock introduced itself.
  it('accepts Basic credentials whose id and secret contain a colon', async () => {
    const uaa = await startMockUaa({
      clients: [{ clientId: 'client:one', clientSecret: 'secret:two' }],
    });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const code = await getCode(uaa.url, redirectUri, 'client:one');
      expect(code).toBeTruthy();
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basicFormEncoded('client:one', 'secret:two'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
        }).toString(),
      });
      expect(res.status).toBe(200);
      const json = (await res.json()) as { access_token: string };
      expect(json.access_token.split('.')).toHaveLength(3);
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

  // Every error redirect (missing response_type, wrong response_type,
  // access_denied) and the success redirect all mirror state the same way —
  // this pins the success and access_denied cases, since only the missing
  // response_type case was covered before.
  it('mirrors state on the success redirect', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}` +
          '&state=st-success',
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('code')).toBeTruthy();
      expect(location.searchParams.get('state')).toBe('st-success');
    } finally {
      await uaa.close();
    }
  });

  it('mirrors state on the access_denied redirect', async () => {
    const uaa = await startMockUaa({ authorize: 'deny' });
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}` +
          '&state=st-deny',
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('access_denied');
      expect(location.searchParams.get('state')).toBe('st-deny');
    } finally {
      await uaa.close();
    }
  });

  // OIDC mirrors on `incoming !== undefined`; until now UAA mirrored on
  // truthiness (`if (req.query.state)`), so `state=` (present but empty) was
  // silently dropped instead of mirrored — the same "empty is not absent"
  // distinction the SAML RelayState work already settled. Regressing UAA back
  // to a truthiness check makes this the case that catches it: the other
  // state tests all use a non-empty value and cannot tell the two checks
  // apart.
  it('mirrors an empty state as empty, not absent', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}` +
          '&state=',
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.has('state')).toBe(true);
      expect(location.searchParams.get('state')).toBe('');
    } finally {
      await uaa.close();
    }
  });

  it('journals what the client sent', async () => {
    const uaa = await startMockUaa({
      clients: [
        {
          clientId: 'mock-client',
          clientSecret: 'mock-secret',
          redirectUris: ['http://localhost:49999/callback'],
        },
      ],
    });
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

  // RFC 6749 §3.1.2.3: a redirect_uri must be registered, exactly, before it
  // is trusted with anything — including a code for a client the mock does
  // know. Otherwise this mock models an open redirect: any URI reachable
  // through a known client_id would get a code, silently hiding a consumer's
  // typo'd or attacker-controlled callback.
  it('refuses an unregistered redirect_uri without redirecting to it', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('https://attacker.invalid/cb')}`,
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

  // The companion to the refusal above: a *registered but non-default* URI
  // must be accepted. Without this, "compare against the registered list"
  // could regress to "compare against the hardcoded default" and still pass
  // the refusal test, since https://attacker.invalid/cb is neither.
  it('accepts a registered non-default redirect_uri', async () => {
    const uaa = await startMockUaa({
      clients: [
        {
          clientId: 'mock-client',
          clientSecret: 'mock-secret',
          redirectUris: ['http://localhost:5555/other-callback'],
        },
      ],
    });
    try {
      const code = await getCode(
        uaa.url,
        'http://localhost:5555/other-callback',
      );
      expect(code).toBeTruthy();
    } finally {
      await uaa.close();
    }
  });

  // RFC 6749 §3.1.2.3 requires exact, byte-for-byte comparison against a
  // registered value — never a prefix or origin match. Every other case in
  // this suite either matches exactly or differs in *origin*
  // (attacker.invalid), so none of them would catch a comparison relaxed to
  // "same origin" or "starts with". These two are same-origin, same-scheme,
  // registered client — differing only in path or trailing slash — which is
  // exactly the shape a same-origin or prefix comparison would let through.
  it('refuses a redirect_uri that shares the origin but not the path, against the default registration', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/evil')}`,
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

  it('refuses the registered redirect_uri with a trailing slash appended', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback/')}`,
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

  // A registered list *replaces* the default, it does not extend it — a mock
  // configured only for a client's real callback must not go on silently
  // accepting DEFAULT_REDIRECT_URI too. createClientRegistry falls back to
  // [DEFAULT_REDIRECT_URI] only when redirectUris is entirely absent
  // (src/clients.ts:56); a registry that appended the default to whatever was
  // declared would pass every other test in this file, since all of them
  // either omit redirectUris or already include the URI they exercise.
  it('refuses the default redirect_uri once a client is registered with a different one', async () => {
    const uaa = await startMockUaa({
      clients: [
        {
          clientId: 'mock-client',
          clientSecret: 'mock-secret',
          redirectUris: ['https://prod.example/cb'],
        },
      ],
    });
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=code` +
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

  // RFC 6749 §4.1.2.1: this refusal falls after the trust boundary
  // (client_id and redirect_uri are already valid), so it is reported at the
  // callback rather than answered directly — the same shape as the OIDC
  // mock's PKCE refusals.
  it('refuses an authorize request with no response_type', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}` +
          '&state=st-1',
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.origin + location.pathname).toBe(
        'http://localhost:61001/callback',
      );
      expect(location.searchParams.get('error')).toBe('invalid_request');
      expect(location.searchParams.get('error_description')).toMatch(
        /response_type is required/,
      );
      expect(location.searchParams.get('state')).toBe('st-1');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await uaa.close();
    }
  });

  it('refuses a response_type other than code, at the callback', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?client_id=mock-client&response_type=token` +
          `&redirect_uri=${encodeURIComponent('http://localhost:61001/callback')}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe(
        'unsupported_response_type',
      );
      expect(location.searchParams.get('error_description')).toMatch(/token/);
      expect(location.searchParams.get('code')).toBeNull();
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

  // The guard is in src/clients.ts and shared by both mocks, so this one case
  // covers the OIDC mock too: presenting two disagreeing identities — one via
  // the Authorization header, a different one in the body — must be refused
  // rather than resolved by trusting whichever the header named.
  // clientAuth.test.ts only proves readClientAuth *sets* conflict: true; this
  // proves a caller *acts* on it.
  it('refuses a client whose header and body identities disagree', async () => {
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
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
          client_id: 'other-client',
        }).toString(),
      });
      expect(res.status).toBe(401);
      const json = (await res.json()) as {
        error: string;
        error_description?: string;
      };
      expect(json.error).toBe('invalid_client');
      expect(json.error_description).toMatch(/disagree/);
    } finally {
      await uaa.close();
    }
  });

  // Finding 2 (sixth review, PR #1): a malformed Authorization: Basic header
  // used to leave basicId undefined, so usedAuthorizationHeader came out
  // false and the mock fell straight through to valid body credentials —
  // Basic was attempted and failed, but the caller got in anyway. The guard
  // lives in src/clients.ts and is shared by both mocks, so this one case
  // covers the OIDC mock too. The description is asserted on a fragment
  // this refusal alone produces — neither the "more than one client
  // authentication method" text oidc.test.ts checks for its own duplicate-
  // method case, nor "disagree" above, nor "unknown client" appear in it.
  it('refuses a malformed Authorization: Basic header even when the body carries valid credentials', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: 'Basic !!!',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
          client_id: 'mock-client',
          client_secret: 'mock-secret',
        }).toString(),
      });
      // A malformed Basic attempt still counts as "via the header" for RFC
      // 6749 §5.2's status-code rule, so this is 401 with WWW-Authenticate,
      // not 400.
      expect(res.status).toBe(401);
      expect(res.headers.get('www-authenticate')).toMatch(/Basic/);
      const json = (await res.json()) as {
        error: string;
        error_description?: string;
      };
      expect(json.error).toBe('invalid_client');
      expect(json.error_description).toMatch(/not a well-formed Basic/);
    } finally {
      await uaa.close();
    }
  });

  // The other half of "malformed": valid base64 that simply has no ':' once
  // decoded. Buffer.from(…, 'base64') would happily decode this — only an
  // explicit search for the separator catches it.
  it('refuses an Authorization: Basic header whose payload decodes without a colon', async () => {
    const uaa = await startMockUaa();
    try {
      const noColon = Buffer.from('nocolonhere').toString('base64');
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${noColon}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'irrelevant',
          redirect_uri: 'http://localhost:61001/callback',
        }).toString(),
      });
      expect(res.status).toBe(401);
      const json = (await res.json()) as {
        error: string;
        error_description?: string;
      };
      expect(json.error).toBe('invalid_client');
      expect(json.error_description).toMatch(/not a well-formed Basic/);
    } finally {
      await uaa.close();
    }
  });

  // The OIDC twin is oidc.test.ts's 'refuses an authorize request with no
  // redirect_uri at all'; this mock had no counterpart, and deleting
  // uaa.ts:114-118 turns this into new URL(undefined) throwing, which the
  // server core reports as a 500 mock_failure instead of a 400 invalid_request.
  it('refuses an authorize request with no redirect_uri at all', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await fetch(
        `${uaa.url}/oauth/authorize?${new URLSearchParams({
          client_id: 'mock-client',
          response_type: 'code',
        }).toString()}`,
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
