# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-03

### Added

- `SamlOptions` gains `signWhat?: 'assertion' | 'response'`, defaulting to
  `'assertion'` — every existing consumer keeps exactly what they already
  get. `'response'` signs the whole `samlp:Response` instead of just the
  `Assertion`, so a relying party's validator can treat `Status` and
  `Destination` as controls rather than as unsigned content it must trust
  anyway. `signXml` already supported signing an arbitrary referenced
  element; this only wires `startMockSamlIdp`'s one signing call to it.

### Licence

- **This package is now `LGPL-3.0-only`.** It was MIT up to and including 0.1.1, and
  those versions stay MIT — a licence change is not retroactive, and anyone
  already using 0.1.1 under MIT keeps that grant for 0.1.1.

  The library licence of the GNU family, chosen for what it does *not* ask:
  linking it into your own program — importing it, as every consumer of an npm
  package does — does not put your program under the LGPL. What it asks is that
  changes to this library stay free and that your users can substitute their own
  build of it.

  Both texts ship in the package: `LICENSE` is the LGPL, `COPYING` is the GPL it
  is written on top of. The LGPL is a set of additional permissions over the GPL,
  so it cannot be read without both.

  Copyright © 2026 Oleksii Kyslytsia.

## [0.1.1] - 2026-08-12

Patch release. Three items parked during 0.1.0's review, none changing this
package's public API.

### Changed

- **`visit` now submits only an auto-submitting form, matching the README's
  documented contract.** Previously it submitted *any* `<form method="post">`
  it landed on, regardless of whether the page auto-submitted it. It now
  submits a POST form only when the page also carries the auto-submit signal
  the SAML IdP actually emits — a `submit()` call inside `<body onload="…">`
  — and otherwise returns that page as the `VisitResult`, unposted. **A
  consumer relying on the old, lenient behaviour** — a callback page carrying
  a POST form with no `onload` auto-submit, that was previously posted
  anyway — must now either add the auto-submit script the real SAML POST
  binding uses, or submit the form itself (e.g. via a follow-up `fetch` to
  `result.body`'s form action) rather than relying on `visit` to do it.
- `visit`'s redirect cap now permits exactly the 10 hops `MAX_REDIRECTS`
  names, not 11: the loop bound was `hop <= MAX_REDIRECTS`, off by one
  against the constant's own name.

### Fixed

- `src/__tests__/samlVerification.test.ts`'s four canaries for fields
  `@node-saml/node-saml` does not check (`wrongDestination`,
  `wrongRecipient`, `statusFailure`, `wrongIssuer`) now assert on the
  resolved profile's `nameID`, rather than `resolves.toBeDefined()` — an
  assertion a null-profile resolution would also have satisfied, silently
  losing coverage if a future version of the verifier ever started
  answering a corrupted response that way instead of throwing.

## [0.1.0] - 2026-08-12

First release. Protocol-faithful mock authorization servers — UAA/OAuth2,
OIDC, and a SAML 2.0 identity provider — for testing `@mcp-abap-adt`
packages' authorization flows deterministically, without a live tenant.

The package has not been published before, so everything below ships as one
initial version. Nothing here changes a contract anyone was relying on.

### Added

- `startMockUaa` — authorization code, refresh with configurable rotation and
  reuse detection, and the SAML bearer grant with a strict RFC 7522 mode.
  Strict by default: an unregistered client, a wrong secret, or a code or
  refresh token presented by a client other than the one it was issued to
  are all refused the way a real server would refuse them.
- `startMockOidc` — discovery, PKCE demanded at `/authorize` and verified at
  `/token`, and `state` mirrored rather than judged.
- `startMockSamlIdp` — signs with a per-instance certificate, returns an
  auto-submitting form for the browser to deliver, and can violate one rule
  at a time across twelve variants, independently verified against
  `@node-saml/node-saml` where it checks the field and pinned as a canary
  where it does not.
- `visit` — a fake browser that follows redirects and submits forms, wired
  into a strategy through `openUrl`.
- `generateKeyMaterial` / `signXml` — per-instance RSA key material and
  XML-DSig signing, exposed for building further test fixtures.
- A README documenting the `visit` + `openUrl` wiring, what each mock
  refuses by default, the SAML corruption-variant table (with the four rows
  no independent verifier here judges), the two-step shape of assertion
  replay, and what signature verification in this package does and does not
  prove.

### Strictness added while the pull request was under review

Each of these was found by external review of the pull request, and each is
a refusal the mock performs rather than a behaviour it offers. They are
listed apart from the features above because they describe what the mocks
will not accept.

- `startMockOidc`'s `/token` now rejects a `code_verifier` that does not fit
  RFC 7636's `43*128unreserved` shape, refused as `invalid_request` before
  the hash comparison even runs — distinct from `invalid_grant`, which a
  well-formed verifier that simply does not derive the stored
  `code_challenge` still receives. `/authorize` applies the same shape check
  to `code_challenge` per RFC 7636 §4.2.
- Every mock now refuses a token request that presents two client
  authentication methods at once (RFC 6749 §2.3): an `Authorization: Basic`
  header together with a body `client_secret`, or a body `client_id` that
  disagrees with the one Basic carries — even when every value agrees. A
  bare, agreeing body `client_id` alongside Basic is still permitted (RFC
  6749 §3.2.1: identification, not authentication), which is also the shape
  `@mcp-abap-adt/auth-providers`' own OIDC client sends on every
  confidential-client token request.
- `startMockSamlIdp`'s `GET /sso` now requires the inflated request's
  document element to be `AuthnRequest` in the SAML protocol namespace —
  both the local name and the namespace — refusing anything else with a
  `400`, the same reasoning the SAML bearer grant's assertion check already
  applies.
- `startMockOidc`'s `/authorize` now requires `scope` to include `openid`
  (OIDC Core §3.1.2.1), tokenised on the RFC 6749 §3.3 single-`SP`
  delimiter and matched as a whole token — `scope=openidx` does not
  satisfy it. Checked after the trust boundary, so refused **at the
  callback** as `invalid_scope`, mirroring `state`, the same shape as the
  existing `response_type` and PKCE refusals. `scope` is now also checked
  against RFC 6749 §3.3's whole `scope = scope-token *( SP scope-token )`
  grammar **before** the `openid` membership test runs: a doubled space
  (`"openid  profile"`), a leading space (`" openid"`) or a trailing space
  (`"openid "`) each produced an empty token that a plain `.split(' ')` +
  `.includes` membership test silently ignored, letting a malformed
  `scope` through. Refused as `invalid_scope` with its own message,
  distinct from "must include openid", since the two are different
  mistakes.
- `SamlOptions` gains `acsUrls?: string[]`, the SAML twin of
  `UaaClient.redirectUris`. `startMockSamlIdp`'s `GET /sso` now refuses an
  `AuthnRequest` whose `AssertionConsumerServiceURL` is not registered in
  `acsUrls`, by exact byte-for-byte match — never origin or prefix. There
  is no default: omitting `acsUrls` entirely refuses **every**
  `AuthnRequest` with a `400`, since an IdP with no service-provider
  metadata has no relying party to deliver to. every existing
  call to `startMockSamlIdp` that expects a delivered assertion must now
  pass `acsUrls` naming its ACS.
- `startMockSamlIdp`'s `GET /sso` now requires the inflated `AuthnRequest`
  to carry a non-empty `ID`, `Version` exactly `"2.0"`, and an
  `IssueInstant` that parses as an `xsd:dateTime` (SAML Core §3.2.1,
  `RequestAbstractType`), refusing anything else with a `400` naming the
  missing or invalid attribute. Previously a missing `ID` silently became
  an empty `InResponseTo` rather than being refused. an
  `AuthnRequest` built without `IssueInstant` (or with a missing `ID` or a
  `Version` other than `"2.0"`) is now refused instead of answered.
- `ID` is now additionally required to be a well-formed `xs:ID`
  (`NCName`, XML Namespaces 1.0 §3): a leading letter or underscore, then
  letters, digits, `.`, `-` or `_`. `ID="123"` and `ID="contains spaces"`
  were previously accepted (only non-emptiness was checked) and flowed
  straight into `InResponseTo`; both are now refused with a `400`. Only
  the ASCII subset of `NCName` is implemented — the full production's
  non-ASCII `NameStartChar`/`NameChar` ranges are not. an
  `AuthnRequest` whose `ID` is non-empty but not an ASCII `NCName` is now
  refused instead of answered.
- `IssueInstant`'s calendar is now validated, not just its lexical shape
  and `Date.parse`-ability: `Date.parse` normalises an impossible date
  rather than rejecting it (`2026-02-30T00:00:00Z` silently became 2
  March and passed; `2026-04-31T12:00:00Z` similarly became 1 May). The
  check now round-trips the year/month/day/hour/minute/second captured
  from the pattern through `Date.UTC` and refuses unless every field
  survives unchanged — a genuine leap day (`2028-02-29T00:00:00Z`) is
  still accepted. Deliberately not implemented: the `xsd:dateTime`
  end-of-day form (`24:00:00`), leap seconds, and the calendar semantics
  of a negative (BCE) year. an `AuthnRequest` whose
  `IssueInstant` names a calendar date that does not exist is now refused
  instead of answered with a silently-normalised date.
- `IssueInstant`'s `Z`/`±HH:MM` offset is now range-checked, not just
  shape-matched: `xsd:dateTime` (XML Schema Part 2 §3.2.7) bounds it at
  ±14:00 — hours `00`–`14`, minutes `00`–`59`, and when the hour is exactly
  `14` the minute must be `00` — which the old regex never expressed, so
  `+99:99` and `+14:01` both passed as long as the calendar portion was
  valid. `+14:00` and `-14:00` (the legal maximum and minimum) are still
  accepted, as is a plain `Z`. an `AuthnRequest` whose
  `IssueInstant` offset is out of range is now refused instead of answered.
- A malformed `Authorization: Basic` header — a payload that is not valid
  base64, or that decodes to a value with no `:` separator — is now refused
  as `invalid_client` (401 + `WWW-Authenticate`, since Basic was attempted)
  instead of being silently ignored in favour of valid body credentials.
  Previously an unparsable Basic header left `usedAuthorizationHeader` and
  every downstream check believing no Basic attempt had been made at all, so
  a caller who botched Basic could still get in via `client_id`/`client_secret`
  in the body. `readClientAuth` now reports the header's presence
  (`usedAuthorizationHeader`) separately from whether it parsed
  (`malformedBasic`); `authenticateClient` refuses on `malformedBasic` before
  any fallback to body credentials and before the duplicate-method check.
- The `Basic` auth-scheme is now matched case-insensitively, and tolerates
  more than one space before its payload, per RFC 7235 §2.1's grammar
  (`auth-scheme 1*SP token68`, with `auth-scheme` a case-insensitive
  `token`). `Authorization: basic …` — or any other casing — used to look
  like no Basic header at all (`header.startsWith('Basic ')`), so
  `usedAuthorizationHeader` stayed `false` and the request fell through to
  body credentials: exactly the fallback hole the malformed-Basic fix above
  closed, left open for every casing but the exact string `Basic`. A bare
  `Basic` with no payload is treated as an attempted-but-malformed Basic
  header, consistent with that same fix, rather than as no attempt at all.
- `startMockSamlIdp`'s `GET /sso` now checks the inflated `AuthnRequest`'s
  `Destination` attribute, when present, against the IdP's own `/sso`
  endpoint (SAML Core §3.2.1) and refuses a mismatch with a `400` — a
  request built for one IdP could otherwise be replayed at another that
  trusts the same relying party. `Destination` is optional on
  `RequestAbstractType`; an `AuthnRequest` that omits it is still accepted,
  by deliberate choice — this family's own `AuthnRequest` builder never sets
  it, and there is nothing to compare against when it is missing. One that
  names a different endpoint is refused.
