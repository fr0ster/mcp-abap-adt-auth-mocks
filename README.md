# @mcp-abap-adt/auth-mocks

[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://stand-with-ukraine.pp.ua)

Protocol-faithful mock authorization servers (UAA/OAuth2, OIDC, SAML IdP) for
testing `@mcp-abap-adt` packages.

## Installation

```bash
npm install --save-dev @mcp-abap-adt/auth-mocks
```

## Overview

This package is a standalone developer tool: it speaks HTTP, OAuth2 and SAML,
and imports nothing from `@mcp-abap-adt/*`. It exists so that other packages in
the family can test their authorization flows against a mock UAA/OAuth2
server, a mock OIDC provider and a mock SAML identity provider —
deterministically, without a live tenant.

Every mock starts and stops inside a test; nothing here is meant to run in
production. Each `start*` function returns a handle with `.url`, `.port`,
`.requests` (every request the mock received, oldest first, for assertions)
and `close()`.

**These mocks do not replace live testing.** They prove the mock's own
behaviour is internally consistent and, for SAML, that an independent
verifier accepts what it should and rejects what it checks — they do not
prove the mock's wire format matches a real UAA, a real OIDC provider or a
real identity provider. See
["What signature verification here does and does not prove"](#what-signature-verification-here-does-and-does-not-prove)
below for exactly what is and is not established, and keep running the real
thing against a live tenant.

## Quick start: `visit` and the `openUrl` seam

None of the mocks post a SAML assertion to the ACS themselves, and none of
them are reached without someone following a redirect. That someone is
normally a browser. `visit()` is a fake one, reduced to exactly what an
authorization flow needs: it follows HTTP redirects and, when it lands on an
auto-submitting HTML form (how the SAML POST binding works), it submits that
form too.

`visit` exists to be handed to whatever seam a consumer already uses to open
a browser. In `@mcp-abap-adt/auth-providers`, that seam is `openUrl` on the
default strategies (`browserCallbackStrategy`, `oidcCallbackStrategy`,
`samlCallbackStrategy`) — the provider builds an authorization URL and calls
`openUrl` with it instead of launching Chrome:

```ts
import { startMockUaa, visit } from "@mcp-abap-adt/auth-mocks";
import {
  AuthorizationCodeProvider,
  browserCallbackStrategy,
} from "@mcp-abap-adt/auth-providers";

const uaa = await startMockUaa();
try {
  const provider = new AuthorizationCodeProvider({
    uaaUrl: uaa.url,
    clientId: "mock-client",
    clientSecret: "mock-secret",
    authorization: browserCallbackStrategy({
      // openUrl's signature also carries a browser name and the bound
      // redirect URI, neither of which visit() needs — it only wants the
      // URL to fetch.
      openUrl: async (url) => {
        await visit(url);
      },
    }),
  });

  const { authorizationToken } = await provider.getTokens();
} finally {
  await uaa.close();
}
```

`visit(url)` itself needs nothing beyond the URL — no browser, no consumer
package, no shared state. That is why `src/browser.ts` imports nothing from
the rest of this package: it is a browser, not a mock-aware helper, and the
wiring above is what turns it into one for the duration of a login.

## Mocks are strict by default

Every mock refuses what a real server would refuse, so a client's mistake
shows up as the mock's answer instead of an assertion written by whoever
wrote the mistake:

- **An unregistered `client_id`** is refused directly at `/authorize` (never
  redirected — an unregistered client's `redirect_uri` cannot be trusted
  either).
- **An unregistered `redirect_uri`** is refused the same way, directly and
  never redirected, even for a `client_id` the mock does know. A `UaaClient`
  carries `redirectUris?: string[]`, defaulting to
  `['http://localhost:61001/callback']` — the callback
  `@mcp-abap-adt/auth-providers` uses by default — and the match is exact,
  byte-for-byte string comparison (RFC 6749 §3.1.2.3), never a prefix or
  origin match. Without this a registered `client_id` would carry any
  `redirect_uri` through, including an attacker's — an open redirect — and a
  provider misconfigured with the wrong callback would pass silently instead
  of being refused.
- **`response_type` must be exactly `code`.** Missing or set to anything else
  (`token`, for instance), `/authorize` refuses it. Unlike the two checks
  above, this falls _after_ the trust boundary — `client_id` and
  `redirect_uri` are already valid — so per RFC 6749 §4.1.2.1 it is reported
  **at the callback**: a `302` carrying `error` (`invalid_request` when
  absent, `unsupported_response_type` when present but wrong),
  `error_description`, and the mirrored `state`.
- **A wrong or missing client secret** at the token endpoint is refused as
  `invalid_client`, with a `401` + `WWW-Authenticate` when the credentials
  arrived via the `Authorization` header and a `400` when they arrived in the
  body, matching RFC 6749 §5.2 exactly rather than always answering one or
  the other.
- **Presenting two client authentication methods in one request** is refused
  as `invalid_client` too (RFC 6749 §2.3: "The client MUST NOT use more than
  one authentication method in each request"): an `Authorization: Basic`
  header together with a body `client_secret`, or a body `client_id` that
  disagrees with the one Basic carries — refused even when every value
  agrees, because a body `client_secret` is itself a credential and
  presenting it alongside Basic is two credentials regardless of whether
  they match. A bare, _agreeing_ body `client_id` alongside Basic **is**
  permitted: RFC 6749 §3.2.1 lets a client "use the `client_id` request
  parameter to identify itself when sending requests to the token
  endpoint", and identification is not authentication — an agreeing
  `client_id` tells the server nothing an attacker could not already read
  off the Basic header. This is also the shape
  `@mcp-abap-adt/auth-providers`' own OIDC client sends on every
  confidential-client token request (`client_id` always in the body, Basic
  added whenever a secret exists), so a mock that refused it would refuse
  its own family's real traffic. Implemented once in `src/clientAuth.ts`,
  shared by both mocks.
- **A malformed `Authorization: Basic` header is refused, never silently
  ignored.** A payload that is not valid base64, or that decodes to a value
  with no `:` separator, used to leave `usedAuthorizationHeader` looking
  `false` — as if Basic had never been attempted — so a caller who botched
  Basic could still get in on valid body credentials, and a malformed
  attempt against a client requiring Basic was answered `invalid_client` as
  a plain unknown-client 400 rather than the 401 RFC 6749 §5.2 requires once
  Basic was attempted. `readClientAuth` now tracks the header's _presence_
  (`usedAuthorizationHeader`, true the moment a request carries the `Basic`
  auth-scheme) separately from whether it could be _parsed_
  (`malformedBasic`); `authenticateClient` refuses on `malformedBasic` with
  its own `invalid_client` message, before any fallback to body credentials
  and before the duplicate-method check above — a malformed attempt is its
  own mistake, not license to try the body instead. Because
  `Buffer.from(…, 'base64')` is lenient (it silently strips characters
  outside the alphabet rather than failing), the payload's shape is checked
  explicitly first, against RFC 4648 §4's standard base64 grammar.
- **The `Basic` auth-scheme is matched case-insensitively**, and tolerates
  more than one space before its payload: RFC 7235 §2.1's grammar is
  `auth-scheme 1*SP token68`, and `auth-scheme` is a `token` — a
  case-insensitive keyword — so `basic`, `BASIC` and `BaSiC` all name the
  same scheme, and one-or-more spaces (not exactly one) separate it from the
  payload. `Authorization: basic …` used to look like no Basic header at
  all, so `usedAuthorizationHeader` stayed `false` and the request fell
  through to body credentials — the same hole the malformed-Basic fix above
  closed, left open for every casing but the exact string `Basic`. A bare
  `Basic` with no payload at all is treated as an attempted-but-malformed
  Basic header, not as "no Basic was attempted", for the same reason: the
  alternative would let a client send the bare scheme plus valid body
  credentials and authenticate via the body.
- **A code or a refresh token is bound to the client it was issued to.**
  Register two clients and try to redeem the first client's code, or its
  refresh token, while authenticated as the second, and the mock answers
  `invalid_grant` — "the code/refresh token was issued to a different
  client" — even though the credential itself is real and unexpired. This
  rule is implemented once, in `src/clients.ts`, and shared by both the UAA
  and OIDC mocks so they cannot disagree about what "issued to" means.
- **A used or expired authorization code** is refused, as is a
  **`redirect_uri`** that does not match the one used to request the code.
- **The OIDC mock demands PKCE.** `/authorize` refuses a request with no
  `code_challenge`, no `code_challenge_method`, or a method other than
  `S256`. Both `code_challenge` (at `/authorize`, per RFC 7636 §4.2) and
  `code_verifier` (at `/token`, per §4.1) are also checked against RFC
  7636's `43*128unreserved` shape before anything is hashed or compared —
  `43` to `128` characters from `ALPHA / DIGIT / "-" / "." / "_" / "~"`. The
  two refusals a malformed or non-deriving verifier can get are different
  and mean different things: a value that does not fit the shape is refused
  as `invalid_request` — a malformed request, refused before the hash is
  even computed — while a well-formed value that simply does not derive the
  stored challenge is refused as `invalid_grant`, the existing
  proof-of-possession failure. `/token` then verifies the presented
  `code_verifier` derives the challenge. `state` is mirrored back unchanged
  by default, never judged — validating `state` is the client's job, and a
  mock that checked it would hide whether the client does.
  `startMockOidc({ state: 'wrongState' })` and `{ state: 'missingState' }`
  exist to test that the client notices when a server does not behave.
- **The OIDC mock demands `scope=openid`.** OIDC Core §3.1.2.1 makes
  `openid` a required member of `scope` — without it a request is a plain
  OAuth request, not an OIDC one, and a consumer that stopped sending it
  would otherwise pass silently against a mock that advertises OIDC
  discovery. Checked after the trust boundary, so — like `response_type`
  and PKCE — refused **at the callback** as `invalid_scope`: RFC 6749
  §4.1.2.1 defines `invalid_scope` as "the requested scope is invalid,
  unknown, or malformed," which is exactly this failure, and reusing
  `invalid_request` would make a scope problem indistinguishable from a
  structurally malformed request. `scope` is first checked against RFC
  6749 §3.3's whole `scope = scope-token *( SP scope-token )` grammar —
  one or more space-separated tokens, no leading or trailing space, no
  doubled space — and only a value that passes is then tokenised and
  matched as whole tokens: `scope=openidx` is refused as not containing
  `openid`, not accepted by a substring check that would wrongly see
  `openid` inside it, and `scope=openid%20%20profile` (a doubled space) or
  a leading/trailing space is refused as malformed before `openid`
  membership is even checked — with its own `invalid_scope` message, since
  a malformed scope and a well-formed scope missing `openid` are different
  mistakes. The ASCII character-class the grammar restricts each token to
  (RFC 6749 §3.3's `%x21 / %x23-5B / %x5D-7E`) is enforced; no other corner
  of the production is relaxed.
- **Refresh tokens rotate by default** (`rotateRefreshTokens: true`): each
  refresh exchange invalidates the presented token and issues a new one, and
  presenting an already-superseded token is refused as reuse — configurable
  to `false` for servers that hand back the same refresh token indefinitely,
  since both behaviours exist among real UAAs.
- **The SAML bearer grant**
  (`urn:ietf:params:oauth:grant-type:saml2-bearer`) can be `'strict'` (the
  default), `'lenient'`, or `'off'` — see
  [RFC 7522 and `samlBearer: 'strict'`](#rfc-7522-and-samlbearer-strict)
  below.
- **The SAML IdP trusts a registered ACS, never whatever the request
  names.** `SamlOptions.acsUrls` is the SAML twin of `UaaClient.redirectUris`
  above, checked the same way: an `AuthnRequest`'s
  `AssertionConsumerServiceURL` must match one of `acsUrls` **exactly**,
  byte-for-byte — never by origin or prefix. There is no fixed default,
  because every test's ACS runs on an ephemeral port; omitting `acsUrls`
  entirely refuses **every** `AuthnRequest` with a `400`, the faithful
  model for an IdP with no service-provider metadata at all. Without this
  check a forged `AuthnRequest` could aim a signed assertion at an
  attacker-controlled URL. See
  [Mock SAML IdP](#mock-saml-idp-startmocksamlidp) below.
- **An `AuthnRequest` must carry `ID`, `Version="2.0"` and a valid
  `IssueInstant`.** SAML Core §3.2.1 makes all three required on
  `RequestAbstractType`; `/sso` now refuses a request missing any of them
  with a `400` naming which one, rather than silently treating a missing
  `ID` as an empty `InResponseTo`. `ID` must additionally be a well-formed
  `xs:ID` (`NCName`) — no leading digit, no spaces or colons — refusing a
  non-empty but malformed value such as `ID="123"` or
  `ID="contains spaces"` that previously flowed straight into
  `InResponseTo`; only the ASCII subset of `NCName` is checked. And
  `IssueInstant` is validated as an actual calendar date, not merely a
  parseable one: `Date.parse` normalises rather than rejecting, so
  `IssueInstant="2026-02-30T00:00:00Z"` used to silently become 2 March and
  pass — the check now round-trips the captured year/month/day/etc. through
  `Date.UTC` and refuses anything that does not survive unchanged, while
  still accepting a genuine leap day (`2028-02-29T00:00:00Z`). Its `Z`/`±HH:MM`
  offset, if present, is range-checked too: `xsd:dateTime` (XML Schema Part 2
  §3.2.7) caps it at ±14:00 — hours `00`–`14`, minutes `00`–`59`, and when the
  hour is `14` the minute must be `00` — so `IssueInstant="…+99:99"` or
  `"…+14:01"` are refused even though both have the right shape; `+14:00` and
  `-14:00` (the legal extremes) are still accepted.
- **An `AuthnRequest`'s `Destination`, when present, must name this IdP's own
  `/sso` endpoint** (SAML Core §3.2.1). A request delivered here carrying
  `Destination="https://other-idp.example/sso"` is refused with a `400` —
  otherwise a request built for one IdP could be replayed at another that
  happens to trust the same relying party. `Destination` is optional on
  `RequestAbstractType`, and an `AuthnRequest` that omits it is accepted by
  deliberate choice, not oversight: this family's own `AuthnRequest` builder
  never sets it, and there is nothing to compare against when it is missing.

## Options reference

Every option is optional; the defaults are what a test gets by passing nothing.

### `startMockUaa(options?: UaaOptions)` and `startMockOidc(options?: OidcOptions)`

`OidcOptions` extends `UaaOptions`, so both accept everything below. Fields
inherited but inert for OIDC are marked.

| Option                       | Default                       | Meaning                                                                                                                              |
| ---------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `clients`                    | one client, see below         | Registered clients: `UaaClient[]`, each `{ clientId, clientSecret, redirectUris? }`.                                                 |
| `clientId` / `clientSecret`  | `mock-client` / `mock-secret` | Shorthand for a single registered client. Ignored when `clients` is given.                                                           |
| `redirectUris` (per client)  | `[DEFAULT_REDIRECT_URI]`      | Permitted redirect URIs, compared byte-for-byte. A registered list **replaces** the default, it does not extend it.                  |
| `codeLifetimeMs`             | `2000`                        | How long an authorization code stays redeemable. Short so an expiry test need not wait.                                              |
| `accessTokenLifetimeSeconds` | `3600`                        | `exp` − `iat` on the minted JWT.                                                                                                     |
| `authorize`                  | `'allow'`                     | `'deny'` redirects to the callback with `error=access_denied`. Inert for OIDC.                                                       |
| `requireClientSecret`        | `true`                        | `false` skips the secret comparison; the registry lookup still refuses an unregistered client.                                       |
| `rotateRefreshTokens`        | `true`                        | Issue a new refresh token per refresh and refuse the superseded one. Inert for OIDC.                                                 |
| `failRefresh`                | `false`                       | Refuse every refresh with `invalid_grant`. Inert for OIDC.                                                                           |
| `samlBearer`                 | `'strict'`                    | `'strict'` enforces RFC 7522 §2.1, `'lenient'` accepts what the family sends today, `'off'` disables the grant. Inert for OIDC.      |
| `state` (OIDC only)          | `'mirror'`                    | `'wrongState'` returns a different value, `'missingState'` omits it. The mock never _validates_ `state` — that is the client's duty. |

`DEFAULT_REDIRECT_URI` is exported, so a test registering an extra URI
alongside the default need not retype the literal.

### `startMockSamlIdp(options?: SamlOptions)`

| Option     | Default      | Meaning                                                                                                                                                                                  |
| ---------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `acsUrls`  | none         | Permitted `AssertionConsumerServiceURL` values, compared byte-for-byte. **With none registered the IdP refuses every `AuthnRequest`** — no service-provider metadata, no single sign-on. |
| `variant`  | `'valid'`    | Which single field of the response to corrupt; see the variants table.                                                                                                                   |
| `issuer`   | `'mock-idp'` | The `Issuer` on both the `Response` and the `Assertion`.                                                                                                                                 |
| `audience` | `'mock-sp'`  | The `Audience` inside `AudienceRestriction`.                                                                                                                                             |

`SamlVariant` is exported for typing a variant table of your own.

### Handles and results

`startServer`, `startMockUaa`, `startMockOidc` and `startMockSamlIdp` all
resolve to a `MockHandle`: `url`, `port`, `requests` — every
`RecordedRequest` the mock received, oldest first, carrying `method`, `path`,
`query`, `headers`, `body` and `raw` — and `close()`, which resolves only
once the port is actually free. `MockUaa` adds
`mintExpiredAccessWithValidRefresh()`; `MockSamlIdp` adds `certificatePem`,
`setVariant()`, `lastAssertionId()` and `repeatLastAssertion()`.

`visit(url)` resolves to a `VisitResult`: `finalUrl`, `status`, `body`.

## Mock UAA (`startMockUaa`)

Authorization code grant at `GET /oauth/authorize` / `POST /oauth/token`,
refresh at the same token endpoint, and the SAML 2.0 bearer grant. Access
tokens are syntactically valid JWTs (`mintJwt`) carrying `exp`/`iat`; nothing
in the family verifies their signature, only the shape and expiry.
`mintExpiredAccessWithValidRefresh()` returns an already-expired access token
paired with a still-valid refresh token, for a refresh test that would
otherwise need to hand-craft a JWT or run a code flow and wait.

## Mock OIDC (`startMockOidc`)

Discovery at `GET /.well-known/openid-configuration`, PKCE demanded at
`/authorize` and verified at `/token`, `scope` required to include `openid`,
`state` mirrored (or deliberately corrupted, see above). Client and
redirect_uri binding, client authentication, and the shape of a
callback-reported error are the same functions the UAA mock uses, from
`src/clients.ts` — not a second, independently-written copy that could
quietly disagree.

### What this does and does not prove

The token exchange returns no `id_token`, though OIDC Core §3.1.3.3 requires
one for an `openid`-scoped authorization code exchange — a consumer whose
provider never validates an `id_token` passes silently against this mock.
The discovery document is a deliberate minimum subset — `issuer`,
`authorization_endpoint`, `token_endpoint`,
`code_challenge_methods_supported`, and `response_types_supported` — and
omits `jwks_uri`, `subject_types_supported`, and
`id_token_signing_alg_values_supported`, all three required by OIDC
Discovery §3, so a client using a conformant discovery library would refuse
it. A consumer's `id_token` handling therefore has no judge in this suite;
**live testing against a real OIDC provider remains necessary** and is not
made obsolete by these tests passing.

## Mock SAML IdP (`startMockSamlIdp`)

`GET /sso` turns an HTTP-Redirect-bound `AuthnRequest` into an
auto-submitting HTML form carrying a `samlp:Response`, signed with a fresh,
per-instance, in-memory key pair and certificate (`generateKeyMaterial`,
`signXml`, `certificatePem` on the handle). It never posts to the ACS
itself — only a browser, or `visit()` standing in for one, does that; see
[Quick start](#quick-start-visit-and-the-openurl-seam) above.

Strict by default here too: the inflated request's document element must be
`AuthnRequest` in the `urn:oasis:names:tc:SAML:2.0:protocol` namespace — both
the local name and the namespace, not either alone — or `/sso` refuses it
with a `400`. The same reasoning the RFC 7522 assertion check already
applies to the SAML bearer grant (`uaa.ts`'s `rejectNonAssertion`): what
matters is the _document element_, not whether the attributes this handler
reads happen to decode somewhere in the document. A `samlp:LogoutRequest`
correctly namespaced but wrongly named, or a document in the right shape but
the wrong namespace, are both refused.

Once the document element checks out, four more rules apply, in order:

1. **`ID`, `Version` and `IssueInstant` are required** (SAML Core §3.2.1,
   `RequestAbstractType`). `ID` must be non-empty, `Version` must be exactly
   `"2.0"`, and `IssueInstant` must parse as an `xsd:dateTime`. A request
   missing any of these previously received a full signed response — a
   missing `ID` silently became an empty `InResponseTo` rather than being
   refused.

   `ID` is further required to be a well-formed `xs:ID`
   (`NCName`, XML Namespaces 1.0 §3): a leading letter or underscore, then
   letters, digits, `.`, `-` or `_` — no leading digit, no spaces or
   colons. Only the ASCII subset of `NCName` is implemented; the full
   production's non-ASCII `NameStartChar`/`NameChar` ranges are not. A
   non-empty but malformed `ID` such as `"123"` or `"contains spaces"` was
   previously accepted and forwarded into `InResponseTo` unchanged.

   `IssueInstant`'s calendar is validated too, not just its lexical shape:
   `Date.parse` normalises an impossible date rather than rejecting it —
   `2026-02-30T00:00:00Z` used to silently become 2 March and pass. The
   check now captures the year, month, day, hour, minute and second from
   the pattern, rebuilds the corresponding UTC instant with `Date.UTC`, and
   refuses unless every field survives unchanged; a genuine leap day
   (`2028-02-29T00:00:00Z`) still passes. Deliberately not implemented: the
   `xsd:dateTime` end-of-day form (`24:00:00`), leap seconds, and negative
   (BCE) years.

   `IssueInstant`'s offset (`Z` or `±HH:MM`) is bounds-checked separately
   from the calendar round-trip above: `xsd:dateTime` (XML Schema Part 2
   §3.2.7) caps it at ±14:00 — hours `00`–`14`, minutes `00`–`59`, and when
   the hour is exactly `14` the minute must be `00`. The old shape regex
   matched any two digits on either side of the offset's colon and the
   round-trip never read it, so `+99:99` and `+14:01` both passed as long as
   the calendar portion was valid; `+14:00` and `-14:00`, the legal extremes,
   are still accepted, as is a plain `Z`.

2. **`Destination`, if present, must name this IdP's own `/sso` endpoint**
   (SAML Core §3.2.1). A recipient that receives a message carrying a
   `Destination` must check it names the endpoint the message actually
   arrived at, or a request built for one IdP could be replayed at another
   that happens to trust the same relying party. `Destination` is optional
   on `RequestAbstractType`, and its absence is accepted — deliberately, not
   by oversight: this family's own `AuthnRequest` builder never sets it, and
   there is nothing to compare against when it is missing.
3. **`AssertionConsumerServiceURL` must be present**, as before.
4. **`AssertionConsumerServiceURL` must be registered.** `SamlOptions.acsUrls`
   is the service-provider metadata a real IdP consults before trusting a
   redirect target — the SAML twin of `UaaClient.redirectUris` in
   `src/clients.ts`, checked the same way: exact, byte-for-byte string
   comparison, never origin or prefix matching. There is no default:

   ```ts
   const acs = await startServer({
     "POST /callback": (req, res) => {
       /* ... */
     },
   });
   const idp = await startMockSamlIdp({
     acsUrls: [`${acs.url}/callback`],
   });
   ```

   Omitting `acsUrls` is not a permissive default — it means this IdP has
   no relying party registered at all, so `/sso` refuses **every**
   `AuthnRequest` with a `400` naming the missing registration, which is
   the faithful model: a real IdP with no service-provider metadata has
   nowhere it is willing to deliver an assertion to either.

### Corruption variants

`startMockSamlIdp({ variant })` and `idp.setVariant(v)` select one of twelve
shapes. Every variant changes exactly one field of an otherwise-valid
response, so a rejection is attributable to that field rather than to an
accumulation of mistakes. The **Verified by** column names what actually
proved each row: `@node-saml/node-saml@5.1.0`'s `validatePostResponseAsync`
where it inspects that field, or "structural (canary)" where it does not —
read directly from the installed library's source
(`src/__tests__/samlVerification.test.ts`), not assumed from its docs.

| Variant             | What changes                                               | Verified by                               |
| ------------------- | ---------------------------------------------------------- | ----------------------------------------- |
| `valid`             | (nothing — the baseline)                                   | node-saml: accepted                       |
| `unsigned`          | no `<Signature>` at all                                    | node-saml: rejected (`Invalid signature`) |
| `wrongKey`          | signed with an unrelated key pair                          | node-saml: rejected (`Invalid signature`) |
| `tamperedAfterSign` | signed content mutated after signing                       | node-saml: rejected (`Invalid signature`) |
| `expired`           | `NotOnOrAfter` in the past                                 | node-saml: rejected                       |
| `notYetValid`       | `NotBefore` in the future                                  | node-saml: rejected                       |
| `wrongAudience`     | `Audience` does not match                                  | node-saml: rejected                       |
| `wrongInResponseTo` | `InResponseTo` names no live request                       | node-saml: rejected                       |
| `statusFailure`     | `<samlp:Status>` reports failure                           | **structural (canary)** — see below       |
| `wrongIssuer`       | `Issuer` does not match                                    | **structural (canary)** — see below       |
| `wrongDestination`  | `Response@Destination` does not match the ACS              | **structural (canary)** — see below       |
| `wrongRecipient`    | `SubjectConfirmationData@Recipient` does not match the ACS | **structural (canary)** — see below       |

**Four of the twelve rows have no independent judge here**, for two distinct
reasons, both confirmed by reading `node_modules/@node-saml/node-saml`'s
source rather than assumed from its documentation:

- `wrongDestination` and `wrongRecipient` — node-saml's response validation
  never reads `Destination` or `Recipient` at all. Its source shows
  `Recipient` does not occur outside test fixtures, and `Destination` occurs
  only in the code that _builds_ an outgoing request, never in the code that
  _validates_ an incoming response.
- `statusFailure` and `wrongIssuer` — node-saml only reads the top-level
  `<samlp:Status>` inside the branch guarded by `if (!("Assertion" in
response))` — that is, whenever _any_ `Assertion` element is present in
  the response at all, signed or not, not specifically because it is
  validly signed — and only compares `idpIssuer` against the message on the
  **logout** path (`verifyIssuer`, called from `verifyLogoutRequest` /
  `verifyLogoutResponse`), never from `validatePostResponseAsync`. A
  Responder-failure status or a forged issuer riding alongside an Assertion
  is accepted outright on this path.

All four are asserted **structurally** instead (the corrupted field is
present and differs from `valid`, and the verifier resolves rather than
rejects) and pinned as **canaries**: if a future version of node-saml starts
checking one of them, the corresponding test in
`src/__tests__/samlVerification.test.ts` will start failing — signalling
"this field is judged now," not a defect in the mock. Until then, a mock IdP
that gets any of these four fields wrong has no automated judge in this
suite at all; only a live test against a relying party that enforces its
own checks on these fields would catch it.

### Replay: a sequence, not a variant

A replayed SAML assertion is, in isolation, perfectly valid — that is
exactly why replay is dangerous, and exactly why no off-the-shelf verifier
rejects one on sight. Remembering which assertion IDs have already been
consumed is the relying party's job, not the identity provider's, so this
package cannot offer "the replay variant" the way it offers `wrongAudience`
or `expired`. What it offers instead is the two-step shape that _makes_
replay dangerous:

```ts
const idp = await startMockSamlIdp({ acsUrls: [`${acs.url}/callback`] });
// ... deliver an assertion once ...
idp.repeatLastAssertion(); // one-shot: reuses the previous assertion's ID next time
// ... deliver again ...
```

Both deliveries are individually valid and share one assertion ID. A
verifier that has never seen the first one accepts the second exactly as
readily — which is the point: nothing in the second message is malformed,
so only a relying party that remembers assertion IDs it has already
consumed can catch the replay. This package proves the two deliveries are
indistinguishable to a naive verifier rather than pretending to detect the
replay itself — that detection is exactly what a consuming package's own
validation strategy is responsible for building and is what this mock exists
to let it be tested against.

There is a trap immediately next door that looks like replay detection but
is not: node-saml's _request_-ID cache is one-shot (`removeAsync` on
`InResponseTo` after a successful validation), so a **second, freshly-minted**
assertion answering the same, already-consumed `AuthnRequest` is rejected
too — for a reason that has nothing to do with the assertion ID repeating.
`src/__tests__/samlVerification.test.ts` covers this with a _fresh_ second
assertion specifically so the rejection cannot be mistaken for replay
detection.

### RFC 7522 and `samlBearer: 'strict'`

`startMockUaa({ samlBearer: 'strict' })` (the default) enforces RFC 7522
§2.1: the `assertion` parameter of the SAML 2.0 bearer grant must be a
**base64url**-encoded (no `+`, `/`, or padding) **`<saml:Assertion>`** as the
document's own root element — not a `<samlp:Response>` wrapping one, and not
base64 with the standard alphabet.

This surfaced a real finding about a consumer rather than about the mock:
`exchangeSamlAssertion` in `@mcp-abap-adt/auth-providers` currently sends a
**base64** `samlp:Response`, not a base64url `Assertion`. Against
`samlBearer: 'strict'`, that request is refused. `samlBearer: 'lenient'`
accepts whatever a real, permissive UAA might accept without enforcing the
RFC's document-shape requirement, and `samlBearer: 'off'` refuses the grant
outright (`unsupported_grant_type`), for testing a server that never enabled
it. Use `'strict'` to hold a client to the RFC; use `'lenient'` or `'off'`
only to reproduce a specific real server's looser or absent behaviour —
reaching for `'lenient'` just to make a non-conformant client's test pass
would hide the same finding this package exists to surface.

## What signature verification here does and does not prove

`src/signing.ts` generates a fresh, in-memory, self-signed certificate per
mock instance and signs SAML assertions with XML-DSig via `xml-crypto`. Its
own test suite (`src/__tests__/signing.test.ts`) exists to prove the
signature is real — bound to the content and to the private key — not to
prove the mock IdP is a faithful stand-in for a real one. Concretely:

- The package's own tests verify a signature with `xml-crypto` — the same
  library that produced it. A canonicalisation or signing bug shared between
  producing and checking the signature would not be caught here.
- `@node-saml/node-saml`, used elsewhere in this family's test suites,
  independently checks signature validity, `Conditions` timestamps and
  `Audience` at the SAML-profile level — but it shares `xml-crypto`
  underneath for the actual cryptography, so it is not an independent
  implementation of XML-DSig either.
- As detailed in [Corruption variants](#corruption-variants) above, it
  checks **none of `Destination`, `SubjectConfirmationData@Recipient`, the
  top-level `<samlp:Status>`, or the Assertion's `Issuer`** on the response
  path this suite exercises, so a mock IdP that gets any of those four
  wrong has no judge in this suite.
- It has **no assertion-ID replay cache** — replaying a captured assertion is
  not something this package or `@node-saml/node-saml` will flag; replay
  detection is the relying party's responsibility (see
  [Replay: a sequence, not a variant](#replay-a-sequence-not-a-variant)
  above).
- None of the above proves canonicalisation matches what a real identity
  provider produces. A green suite here is evidence the mock's own signature
  round-trips and that an independent library accepts what it should and
  rejects what it checks, not evidence the mock's SAML profile matches a
  live IdP byte-for-byte. **Live testing against a real identity provider
  remains necessary** and is not made obsolete by these tests passing.
