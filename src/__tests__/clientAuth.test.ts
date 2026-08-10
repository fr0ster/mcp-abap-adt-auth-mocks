import { describe, expect, it } from '@jest/globals';
import { readClientAuth } from '../clientAuth';
import type { RecordedRequest } from '../server';

const base: RecordedRequest = {
  method: 'POST',
  path: '/oauth/token',
  query: {},
  headers: {},
  body: {},
  raw: '',
};

describe('readClientAuth', () => {
  // UAA sends credentials only as Basic and puts no client_id in the body;
  // OIDC puts client_id in the body. A mock assuming either shape would
  // reject one of the family's own clients.
  it('reads client_secret_basic', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
    });
    expect(r).toMatchObject({
      clientId: 'cid',
      clientSecret: 'secret',
      usedAuthorizationHeader: true,
      conflict: false,
    });
  });

  it('reads client_secret_post', () => {
    const r = readClientAuth({
      ...base,
      body: { client_id: 'cid', client_secret: 'secret' },
    });
    expect(r).toMatchObject({
      clientId: 'cid',
      clientSecret: 'secret',
      usedAuthorizationHeader: false,
      conflict: false,
    });
  });

  it('reads a public client — id in the body, no secret', () => {
    const r = readClientAuth({ ...base, body: { client_id: 'cid' } });
    expect(r).toMatchObject({
      clientId: 'cid',
      clientSecret: undefined,
      conflict: false,
    });
  });

  it('flags a conflict when Basic and body disagree', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'other' },
    });
    expect(r.conflict).toBe(true);
  });

  // RFC 6749 §3.2.1: "a client MAY use the 'client_id' request parameter to
  // identify itself when sending requests to the token endpoint." A body
  // client_id that merely agrees with Basic authenticates nothing an
  // attacker could not already read off the Authorization header — it is
  // identification, not a second credential — so this is not the "more than
  // one authentication method" §2.3 forbids. This is also the shape the
  // family's own OIDC client sends for every confidential-client token
  // request (see `@mcp-abap-adt/auth-providers`' `exchangeAuthorizationCode`
  // in its `src/auth/oidcToken.ts`): client_id always in the body, Basic
  // added whenever a secret exists. A mock that refused this would refuse
  // its own family's real traffic.
  it('does not flag a conflict when a body client_id merely identifies the same client as Basic', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'cid' },
    });
    expect(r.conflict).toBe(false);
  });

  // The part of RFC 6749 §2.3 the old implementation missed entirely: it
  // compared only client_id, so Basic plus a body client_secret sailed
  // through as long as the two client_ids matched — even though a body
  // client_secret is itself a credential, making this two authentication
  // methods in one request regardless of whether the secrets agree.
  it('flags a conflict when Basic and body both carry a client_secret, even if everything agrees', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'cid', client_secret: 'secret' },
    });
    expect(r.conflict).toBe(true);
  });

  it('flags a conflict when Basic is present and the body carries a client_secret with no client_id', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_secret: 'secret' },
    });
    expect(r.conflict).toBe(true);
  });
});
