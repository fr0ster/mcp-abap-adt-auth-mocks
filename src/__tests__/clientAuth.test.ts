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

  // Finding 2 (sixth review, PR #1): the old implementation only ever set
  // usedAuthorizationHeader from whether basicId came out defined, so a
  // Basic header that failed to parse looked identical to no Basic header
  // at all. `!!!` cannot be base64-decoded meaningfully — `Buffer.from`
  // itself is lenient (it drops invalid characters rather than throwing),
  // so only an explicit shape check catches this.
  it('flags malformedBasic, and still usedAuthorizationHeader, for a payload that is not valid base64', () => {
    const r = readClientAuth({
      ...base,
      headers: { authorization: 'Basic !!!' },
      body: { client_id: 'cid', client_secret: 'secret' },
    });
    expect(r.malformedBasic).toBe(true);
    expect(r.usedAuthorizationHeader).toBe(true);
  });

  // `!!!` alone does not prove the base64-shape check is load-bearing: it
  // contains no valid base64 characters at all, so `Buffer.from` decodes it
  // to '' either way, and the *separate* "no colon" branch below would
  // catch it even with the shape check deleted entirely. This payload is
  // built to defeat that: it is `cid:secret`'s valid encoding with one `!`
  // spliced into the middle — `BASE64_SHAPE` must refuse it outright, but
  // `Buffer.from(…, 'base64')` is lenient enough to strip the `!` and
  // decode the rest anyway, landing on the exact credential a well-formed
  // header would have carried. Only the explicit shape check — not the
  // colon check — can catch this one.
  it('flags malformedBasic for a payload with an invalid character that Buffer.from would silently decode around', () => {
    const valid = Buffer.from('cid:secret').toString('base64');
    const tampered = `${valid.slice(0, 2)}!${valid.slice(2)}`;
    // Sanity check on the premise: Node's lenient base64 decoder really
    // does strip the invalid character and recover a well-formed-looking
    // credential from it, which is exactly why a shape check is needed.
    expect(Buffer.from(tampered, 'base64').toString('utf8')).toBe('cid:secret');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${tampered}` },
    });
    expect(r.malformedBasic).toBe(true);
    expect(r.clientId).toBeUndefined();
  });

  // The other half of "malformed": valid base64 that decodes to a value
  // with no ':' separator at all, so there is no id/secret split to make.
  it('flags malformedBasic for a payload that is valid base64 but decodes without a colon', () => {
    const noColon = Buffer.from('nocolonhere').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${noColon}` },
    });
    expect(r.malformedBasic).toBe(true);
    expect(r.usedAuthorizationHeader).toBe(true);
  });

  it('does not flag malformedBasic for a well-formed Basic header', () => {
    const basic = Buffer.from('cid:secret').toString('base64');
    const r = readClientAuth({
      ...base,
      headers: { authorization: `Basic ${basic}` },
    });
    expect(r.malformedBasic).toBe(false);
  });

  // conflict is documented to never fire for a malformed Basic attempt —
  // there is no decoded basicId to compare the body against — even though
  // the body here carries exactly the shape (a bare client_secret) that
  // flags a conflict against a well-formed Basic header above.
  it('does not flag a conflict for a malformed Basic header even when the body carries a client_secret', () => {
    const r = readClientAuth({
      ...base,
      headers: { authorization: 'Basic !!!' },
      body: { client_secret: 'secret' },
    });
    expect(r.malformedBasic).toBe(true);
    expect(r.conflict).toBe(false);
  });

  // Finding (this review, PR #1): RFC 7235 §2.1 makes auth-scheme a `token`,
  // and tokens in this grammar are case-insensitive keywords, so
  // `Authorization: basic …` names the same scheme as `Basic …`. The old
  // `header.startsWith('Basic ')` check missed this entirely — a lowercase
  // scheme looked like no Basic header at all, so usedAuthorizationHeader
  // stayed false and the request fell through to body credentials, the
  // exact hole the malformed-Basic guard above closed for the wrong casing.
  describe('scheme case and spacing (RFC 7235 §2.1)', () => {
    it('reads client_secret_basic when the scheme is lowercase "basic"', () => {
      const basic = Buffer.from('cid:secret').toString('base64');
      const r = readClientAuth({
        ...base,
        headers: { authorization: `basic ${basic}` },
      });
      expect(r).toMatchObject({
        clientId: 'cid',
        clientSecret: 'secret',
        usedAuthorizationHeader: true,
        malformedBasic: false,
      });
    });

    it('reads client_secret_basic when the scheme is mixed-case "BaSiC"', () => {
      const basic = Buffer.from('cid:secret').toString('base64');
      const r = readClientAuth({
        ...base,
        headers: { authorization: `BaSiC ${basic}` },
      });
      expect(r).toMatchObject({
        clientId: 'cid',
        clientSecret: 'secret',
        usedAuthorizationHeader: true,
        malformedBasic: false,
      });
    });

    // RFC 7235's grammar is `auth-scheme 1*SP token68` — one or more
    // spaces, not exactly one. A client that pads the separator is still
    // well-formed.
    it('tolerates more than one space between the scheme and the payload', () => {
      const basic = Buffer.from('cid:secret').toString('base64');
      const r = readClientAuth({
        ...base,
        headers: { authorization: `Basic   ${basic}` },
      });
      expect(r).toMatchObject({
        clientId: 'cid',
        clientSecret: 'secret',
        usedAuthorizationHeader: true,
        malformedBasic: false,
      });
    });

    // The lowercase scheme must not only be *recognised* — it must feed the
    // same malformed-payload refusal a canonically-cased header does.
    // `readClientAuth` itself still reports the body's client_id/secret
    // here (it always exposes both halves; refusing on `malformedBasic`
    // before ever reading them is `authenticateClient`'s job in
    // `clients.ts`) — the full "does not authenticate via the body" claim
    // is proved end-to-end in uaa.test.ts's matching case, which observes
    // a 401 rather than a 200.
    it('flags malformedBasic for a lowercase "basic" header with an unparsable payload', () => {
      const r = readClientAuth({
        ...base,
        headers: { authorization: 'basic !!!' },
        body: { client_id: 'cid', client_secret: 'secret' },
      });
      expect(r.usedAuthorizationHeader).toBe(true);
      expect(r.malformedBasic).toBe(true);
    });

    // Decision: a bare `Basic` — the scheme with no payload at all — is
    // treated as an attempted-but-malformed Basic header, not as "no Basic
    // was attempted". The alternative (treating it as absent) would let a
    // client send exactly this plus valid body credentials and authenticate
    // via the body, reopening the fallback hole the malformed-Basic guard
    // exists to close, just for an empty payload instead of an invalid one.
    it('flags malformedBasic, and usedAuthorizationHeader, for a bare "Basic" scheme with no payload', () => {
      const r = readClientAuth({
        ...base,
        headers: { authorization: 'Basic' },
        body: { client_id: 'cid', client_secret: 'secret' },
      });
      expect(r.usedAuthorizationHeader).toBe(true);
      expect(r.malformedBasic).toBe(true);
    });

    // Same decision, reached via trailing spaces instead of no space at
    // all: `Basic   ` (scheme, spaces, nothing else) has a payload of ''
    // once the separator is consumed, which is exactly the bare case above.
    it('flags malformedBasic for "Basic" followed only by spaces', () => {
      const r = readClientAuth({
        ...base,
        headers: { authorization: 'Basic   ' },
      });
      expect(r.usedAuthorizationHeader).toBe(true);
      expect(r.malformedBasic).toBe(true);
    });

    // Anchoring proof: a scheme that merely starts with the same letters —
    // not "Basic" plus a separator — is a different scheme and must not be
    // recognised as Basic at all.
    it('does not treat a scheme that only starts with "basic" as Basic', () => {
      const r = readClientAuth({
        ...base,
        headers: { authorization: 'Basicish xyz' },
        body: { client_id: 'cid', client_secret: 'secret' },
      });
      expect(r.usedAuthorizationHeader).toBe(false);
      expect(r.malformedBasic).toBe(false);
      expect(r.clientId).toBe('cid');
    });
  });
});
