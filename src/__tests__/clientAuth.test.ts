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

  it('does not flag a conflict when Basic and body agree', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
      body: { client_id: 'cid' },
    });
    expect(r.conflict).toBe(false);
  });
});
