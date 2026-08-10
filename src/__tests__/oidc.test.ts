import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import { startMockOidc } from '../oidc';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function authorizeUrl(base: string, params: Record<string, string>) {
  return `${base}/authorize?${new URLSearchParams({
    client_id: 'mock-client',
    response_type: 'code',
    redirect_uri: 'http://localhost:61001/callback',
    ...params,
  }).toString()}`;
}

/** Drives /authorize the way a browser would, with PKCE, returning the code and its verifier. */
async function getOidcCode(
  base: string,
  redirectUri: string,
  clientId = 'mock-client',
): Promise<{ code: string; verifier: string }> {
  const { verifier, challenge } = pkce();
  const res = await fetch(
    `${base}/authorize?${new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString()}`,
    { redirect: 'manual' },
  );
  const code =
    new URL(res.headers.get('location') ?? '').searchParams.get('code') ?? '';
  return { code, verifier };
}

describe('mock OIDC', () => {
  it('serves a discovery document naming its own endpoints', async () => {
    const oidc = await startMockOidc();
    try {
      const doc = (await (
        await fetch(`${oidc.url}/.well-known/openid-configuration`)
      ).json()) as { authorization_endpoint: string; token_endpoint: string };
      expect(doc.authorization_endpoint).toBe(`${oidc.url}/authorize`);
      expect(doc.token_endpoint).toBe(`${oidc.url}/token`);
    } finally {
      await oidc.close();
    }
  });

  // RFC 6749 §4.1.2.1 draws the line at trust: once client_id and redirect_uri
  // check out, the error belongs at the callback. That is the path the client
  // actually walks, and reproducing it is most of why this mock exists — a
  // direct 400 would leave the client's error handling untested.
  it('reports a missing code_challenge at the callback, not in the response', async () => {
    const oidc = await startMockOidc();
    try {
      const res = await fetch(authorizeUrl(oidc.url, { state: 'st-42' }), {
        redirect: 'manual',
      });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.origin + location.pathname).toBe(
        'http://localhost:61001/callback',
      );
      expect(location.searchParams.get('error')).toBe('invalid_request');
      // Deliberately narrower than /code_challenge/: that pattern also matches
      // the code_challenge_method mismatch message below ("unsupported
      // code_challenge_method: ..." contains "code_challenge"), so it would
      // stay green even if the dedicated presence check were deleted and this
      // request fell through to the method check instead (undefined !== 'S256').
      expect(location.searchParams.get('error_description')).toMatch(
        /PKCE is required/,
      );
      // State is mirrored on the error path too — a client that validates it
      // must be able to, or it cannot safely match the error to its request.
      expect(location.searchParams.get('state')).toBe('st-42');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  it('reports a code_challenge_method other than S256 at the callback', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'plain',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('invalid_request');
      expect(location.searchParams.get('error_description')).toMatch(/plain/);
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  // Also proves the RFC 6749 §2.3/§3.2.1 judgement call in clientAuth.ts:
  // this request presents Basic *and* a body client_id — exactly the shape
  // the family's own OIDC client sends for every confidential-client token
  // request — and must still succeed, because a body client_id that merely
  // identifies the client agreeing with Basic is not a second authentication
  // method.
  it('exchanges a code when the verifier matches the challenge (Basic plus an agreeing body client_id)', async () => {
    const oidc = await startMockOidc();
    try {
      const { verifier, challenge } = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(
        redirected.headers.get('location') ?? '',
      ).searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: verifier,
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(200);
    } finally {
      await oidc.close();
    }
  });

  // The other half of the same judgement call, exercised end-to-end: a body
  // client_secret is itself a credential, so presenting it alongside Basic
  // is two authentication methods in the same request — refused even though
  // every value agrees with what Basic carries.
  it('refuses a token request presenting both Basic and a body client_secret, even when they agree', async () => {
    const oidc = await startMockOidc();
    try {
      const { verifier, challenge } = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(
        redirected.headers.get('location') ?? '',
      ).searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: verifier,
          client_id: 'mock-client',
          client_secret: 'mock-secret',
        }).toString(),
      });
      // invalid_client via the Authorization header answers 401 per RFC
      // 6749 §5.2 — see oauthErrors.ts — not the 400 every other refusal in
      // this file uses.
      expect(res.status).toBe(401);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe('invalid_client');
    } finally {
      await oidc.close();
    }
  });

  it('refuses a verifier that does not derive the challenge', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const other = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(
        redirected.headers.get('location') ?? '',
      ).searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          // Well-formed per RFC 7636 §4.1 (43 chars, base64url alphabet is a
          // subset of unreserved) — this must fail for deriving the wrong
          // challenge, not for its shape, which is what distinguishes this
          // case from the two below.
          code_verifier: other.verifier,
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        error: string;
        error_description: string;
      };
      expect(body.error).toBe('invalid_grant');
      expect(body.error_description).toMatch(/does not derive/);
    } finally {
      await oidc.close();
    }
  });

  // RFC 7636 §4.1: code_verifier = 43*128unreserved. A 1-character verifier
  // violates the length floor that carries PKCE's security property, and
  // must be refused before the hash comparison even runs — a real server
  // would never accept it, so this mock accepting it would teach a consumer
  // a mistake that only surfaces against the real thing.
  it('refuses a code_verifier that is too short to be RFC 7636 shape-valid', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(
        redirected.headers.get('location') ?? '',
      ).searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: 'x',
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        error: string;
        error_description: string;
      };
      expect(body.error).toBe('invalid_request');
      expect(body.error_description).toMatch(/43-128/);
    } finally {
      await oidc.close();
    }
  });

  // The character-class half of the same shape rule: 43 characters, but
  // every one of them is outside RFC 7636's unreserved set. Long enough to
  // clear the length floor, so this proves the charset check independently
  // of the length check above.
  it('refuses a code_verifier containing a character outside the unreserved set', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const redirected = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      const code = new URL(
        redirected.headers.get('location') ?? '',
      ).searchParams.get('code');
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: 'http://localhost:61001/callback',
          code_verifier: '!'.repeat(43),
          client_id: 'mock-client',
        }).toString(),
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        error: string;
        error_description: string;
      };
      expect(body.error).toBe('invalid_request');
      expect(body.error_description).toMatch(/43-128/);
    } finally {
      await oidc.close();
    }
  });

  // §4.2 gives code_challenge the same shape as code_verifier. Checked at
  // /authorize, so — like the PKCE-required and method-mismatch refusals
  // above it — it is reported at the callback rather than answered
  // directly.
  it('refuses a code_challenge that violates the RFC 7636 shape, at the callback', async () => {
    const oidc = await startMockOidc();
    try {
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: 'too-short',
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('invalid_request');
      expect(location.searchParams.get('error_description')).toMatch(/43-128/);
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  // The UAA twin has no counterpart test at all — every OIDC test until now
  // sent only 'authorization_code'.
  it('refuses a grant_type other than authorization_code', async () => {
    const oidc = await startMockOidc();
    try {
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'client_credentials',
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'unsupported_grant_type',
      );
    } finally {
      await oidc.close();
    }
  });

  // The UAA twin is uaa.test.ts's 'refuses a code used twice'.
  it('refuses a code used twice', async () => {
    const oidc = await startMockOidc();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const { code, verifier } = await getOidcCode(oidc.url, redirectUri);
      const exchange = () =>
        fetch(`${oidc.url}/token`, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            authorization: basic('mock-client', 'mock-secret'),
          },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri,
            code_verifier: verifier,
          }).toString(),
        });
      expect((await exchange()).status).toBe(200);
      const second = await exchange();
      expect(second.status).toBe(400);
      expect(((await second.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await oidc.close();
    }
  });

  // The UAA twin is uaa.test.ts's 'refuses an expired code', using the same
  // codeLifetimeMs option.
  it('refuses an expired code', async () => {
    const oidc = await startMockOidc({ codeLifetimeMs: 50 });
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const { code, verifier } = await getOidcCode(oidc.url, redirectUri);
      await new Promise((r) => setTimeout(r, 120));
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await oidc.close();
    }
  });

  // The UAA twin is uaa.test.ts's 'refuses a redirect_uri that differs from
  // the authorize request'.
  it('refuses a redirect_uri that differs from the authorize request', async () => {
    const oidc = await startMockOidc();
    try {
      const redirectUri = 'http://localhost:61001/callback';
      const { code, verifier } = await getOidcCode(oidc.url, redirectUri);
      const res = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('mock-client', 'mock-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'http://localhost:3001/callback',
          code_verifier: verifier,
        }).toString(),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await oidc.close();
    }
  });

  it('mirrors state back unchanged', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).toBe('st-42');
    } finally {
      await oidc.close();
    }
  });

  it('returns a different state when asked for wrongState', async () => {
    const oidc = await startMockOidc({ state: 'wrongState' });
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).not.toBe('st-42');
      expect(location.searchParams.get('state')).toBeTruthy();
    } finally {
      await oidc.close();
    }
  });

  it('omits state entirely when asked for missingState', async () => {
    const oidc = await startMockOidc({ state: 'missingState' });
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-42',
        }),
        { redirect: 'manual' },
      );
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('state')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  // The same rule as Task 4, restated here because "model it on uaa.ts" is
  // exactly the kind of instruction that loses a check in translation.
  it('refuses a code issued to a different client', async () => {
    const oidc = await startMockOidc({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const { verifier, challenge } = pkce();
      const redirectUri = 'http://localhost:61001/callback';
      const res = await fetch(
        `${oidc.url}/authorize?${new URLSearchParams({
          client_id: 'first-client',
          response_type: 'code',
          redirect_uri: redirectUri,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }).toString()}`,
        { redirect: 'manual' },
      );
      const code = new URL(res.headers.get('location') ?? '').searchParams.get(
        'code',
      );
      expect(code).toBeTruthy();

      const exchange = await fetch(`${oidc.url}/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code ?? '',
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }).toString(),
      });
      expect(exchange.status).toBe(400);
      expect(((await exchange.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await oidc.close();
    }
  });

  // The first trust-boundary refusal: with no redirect_uri there is nowhere to
  // send an error to, so it can only be answered here.
  it('refuses an authorize request with no redirect_uri at all', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        `${oidc.url}/authorize?${new URLSearchParams({
          client_id: 'mock-client',
          response_type: 'code',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }).toString()}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_request',
      );
    } finally {
      await oidc.close();
    }
  });

  // The other side of the same rule: an unregistered client means the
  // redirect_uri it supplied cannot be trusted either, so this error must NOT
  // travel to the callback — sending it there would hand an attacker a
  // redirector. Contrast with the two PKCE cases above.
  it('refuses an unregistered client_id without redirecting to it', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          client_id: 'nobody',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_request',
      );
    } finally {
      await oidc.close();
    }
  });

  // The UAA twin is uaa.test.ts's 'refuses an unregistered redirect_uri
  // without redirecting to it'. Same rule, same reason: an unregistered
  // redirect_uri is exactly as untrustworthy as an unregistered client_id,
  // for a known client_id just as much as an unknown one.
  it('refuses an unregistered redirect_uri without redirecting to it', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          redirect_uri: 'https://attacker.invalid/cb',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
        { redirect: 'manual' },
      );
      expect(res.status).toBe(400);
      expect(res.headers.get('location')).toBeNull();
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_request',
      );
    } finally {
      await oidc.close();
    }
  });

  // The companion to the refusal above: a *registered but non-default* URI
  // must be accepted, proving the registered list is actually consulted
  // rather than a hardcoded default being compared.
  it('accepts a registered non-default redirect_uri', async () => {
    const oidc = await startMockOidc({
      clients: [
        {
          clientId: 'mock-client',
          clientSecret: 'mock-secret',
          redirectUris: ['http://localhost:5555/other-callback'],
        },
      ],
    });
    try {
      const { code } = await getOidcCode(
        oidc.url,
        'http://localhost:5555/other-callback',
      );
      expect(code).toBeTruthy();
    } finally {
      await oidc.close();
    }
  });

  // RFC 6749 §4.1.2.1: this falls after the trust boundary (client_id and
  // redirect_uri are already valid), so — like the two PKCE refusals above —
  // it is reported at the callback rather than answered directly. PKCE
  // parameters are included so that, were the response_type check deleted,
  // the request would fall through and receive a code instead of merely
  // hitting a different refusal.
  it('refuses an authorize request with no response_type, at the callback', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        `${oidc.url}/authorize?${new URLSearchParams({
          client_id: 'mock-client',
          redirect_uri: 'http://localhost:61001/callback',
          code_challenge: challenge,
          code_challenge_method: 'S256',
          state: 'st-9',
        }).toString()}`,
        { redirect: 'manual' },
      );
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.searchParams.get('error')).toBe('invalid_request');
      // Deliberately narrower than /response_type/: that also matches the
      // unsupported_response_type message below.
      expect(location.searchParams.get('error_description')).toMatch(
        /response_type is required/,
      );
      expect(location.searchParams.get('state')).toBe('st-9');
      expect(location.searchParams.get('code')).toBeNull();
    } finally {
      await oidc.close();
    }
  });

  it('refuses a response_type other than code, at the callback', async () => {
    const oidc = await startMockOidc();
    try {
      const { challenge } = pkce();
      const res = await fetch(
        authorizeUrl(oidc.url, {
          response_type: 'token',
          code_challenge: challenge,
          code_challenge_method: 'S256',
        }),
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
      await oidc.close();
    }
  });
});
