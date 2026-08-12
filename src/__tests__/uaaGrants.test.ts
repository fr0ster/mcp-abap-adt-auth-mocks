import { describe, expect, it } from '@jest/globals';
import { startMockUaa } from '../uaa';

const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

const post = (url: string, body: Record<string, string>) =>
  fetch(`${url}/oauth/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: basic('mock-client', 'mock-secret'),
    },
    body: new URLSearchParams(body).toString(),
  });

describe('refresh grant', () => {
  it('mints a consistent expired-access + valid-refresh pair', async () => {
    const uaa = await startMockUaa();
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const claims = JSON.parse(
        Buffer.from(pair.accessToken.split('.')[1], 'base64url').toString(
          'utf8',
        ),
      );
      expect(claims.exp).toBeLessThan(Math.floor(Date.now() / 1000));

      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(res.status).toBe(200);
      expect(
        ((await res.json()) as { access_token: string }).access_token.split(
          '.',
        ),
      ).toHaveLength(3);
    } finally {
      await uaa.close();
    }
  });

  it('rotates the refresh token and refuses the superseded one', async () => {
    const uaa = await startMockUaa({ rotateRefreshTokens: true });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const first = (await (
        await post(uaa.url, {
          grant_type: 'refresh_token',
          refresh_token: pair.refreshToken,
        })
      ).json()) as { refresh_token: string };
      expect(first.refresh_token).not.toBe(pair.refreshToken);

      const reuse = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(reuse.status).toBe(400);
      const body = (await reuse.json()) as {
        error: string;
        error_description?: string;
      };
      expect(body.error).toBe('invalid_grant');
      expect(body.error_description).toMatch(/rotation/i);
    } finally {
      await uaa.close();
    }
  });

  it('keeps the refresh token when rotation is off', async () => {
    const uaa = await startMockUaa({ rotateRefreshTokens: false });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const body = (await (
        await post(uaa.url, {
          grant_type: 'refresh_token',
          refresh_token: pair.refreshToken,
        })
      ).json()) as { refresh_token: string };
      expect(body.refresh_token).toBe(pair.refreshToken);
    } finally {
      await uaa.close();
    }
  });

  it('refuses an unknown refresh token', async () => {
    const uaa = await startMockUaa();
    try {
      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: 'never-issued',
      });
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('fails every refresh when told to', async () => {
    const uaa = await startMockUaa({ failRefresh: true });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh();
      const res = await post(uaa.url, {
        grant_type: 'refresh_token',
        refresh_token: pair.refreshToken,
      });
      expect(res.status).toBe(400);
    } finally {
      await uaa.close();
    }
  });

  // A refresh token carries the same authorization a code does, so it crosses
  // a client boundary just as badly. `post` hardcodes `mock-client`, so this
  // one authenticates explicitly as the second client.
  it('refuses a refresh token presented by a different client', async () => {
    const uaa = await startMockUaa({
      clients: [
        { clientId: 'first-client', clientSecret: 'first-secret' },
        { clientId: 'second-client', clientSecret: 'second-secret' },
      ],
    });
    try {
      const pair = uaa.mintExpiredAccessWithValidRefresh('first-client');
      const res = await fetch(`${uaa.url}/oauth/token`, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: basic('second-client', 'second-secret'),
        },
        body: new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: pair.refreshToken,
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
});

describe('SAML bearer grant', () => {
  const GRANT = 'urn:ietf:params:oauth:grant-type:saml2-bearer';
  const assertionXml =
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">' +
    '<saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>';

  // A realistic Response *contains* an Assertion. A check that merely looks for
  // the substring "Assertion" anywhere passes this and proves nothing — which
  // is why the fixture is not an empty element.
  const responseXml =
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1">' +
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
    '<saml:Assertion ID="_a1"><saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>' +
    '</samlp:Response>';

  it('accepts a base64url Assertion in strict mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(assertionXml, 'utf8').toString('base64url'),
      });
      expect(res.status).toBe(200);
      expect(
        ((await res.json()) as { access_token: string }).access_token.split(
          '.',
        ),
      ).toHaveLength(3);
    } finally {
      await uaa.close();
    }
  });

  // What auth-providers sends today: a whole base64 samlp:Response, with an
  // Assertion nested inside it. Standard base64 (not base64url) of this exact
  // fixture carries '+' and '=' padding, so the *encoding* check is the one
  // that fires here — not the document-element check, which never runs.
  it('refuses a base64 samlp:Response in strict mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(responseXml, 'utf8').toString('base64'),
      });
      expect(res.status).toBe(400);
      const json = (await res.json()) as {
        error: string;
        error_description?: string;
      };
      expect(json.error).toBe('invalid_grant');
      expect(json.error_description).toMatch(/base64url/);
    } finally {
      await uaa.close();
    }
  });

  // The mirror of the case below: content beyond reproach (a well-formed
  // Assertion), encoding wrong (base64, not base64url). Without this, the
  // encoding check could be deleted unnoticed — the content check alone would
  // still refuse a Response, but this fixture is an Assertion, so only the
  // encoding check stands between it and acceptance.
  it('refuses a well-formed Assertion that is base64 rather than base64url', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const encoded = Buffer.from(assertionXml, 'utf8').toString('base64');
      expect(encoded).not.toMatch(/^[A-Za-z0-9_-]+$/);
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: encoded,
      });
      expect(res.status).toBe(400);
      expect(
        ((await res.json()) as { error_description?: string })
          .error_description,
      ).toMatch(/base64url/);
    } finally {
      await uaa.close();
    }
  });

  // The encoding check alone cannot carry this. Here the encoding is beyond
  // reproach — Node's base64url is unpadded and uses no + or / — so the refusal
  // can only come from asking what the document element is.
  it('refuses a Response that is correctly base64url-encoded', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const encoded = Buffer.from(responseXml, 'utf8').toString('base64url');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: encoded,
      });
      expect(res.status).toBe(400);
      expect(
        ((await res.json()) as { error_description?: string })
          .error_description,
      ).toMatch(/Response/);
    } finally {
      await uaa.close();
    }
  });

  it('refuses something that is not XML at all', async () => {
    const uaa = await startMockUaa({ samlBearer: 'strict' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from('not xml', 'utf8').toString('base64url'),
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        'invalid_grant',
      );
    } finally {
      await uaa.close();
    }
  });

  it('accepts the same thing in lenient mode', async () => {
    const uaa = await startMockUaa({ samlBearer: 'lenient' });
    try {
      const res = await post(uaa.url, {
        grant_type: GRANT,
        assertion: Buffer.from(responseXml, 'utf8').toString('base64'),
      });
      expect(res.status).toBe(200);
    } finally {
      await uaa.close();
    }
  });
});
