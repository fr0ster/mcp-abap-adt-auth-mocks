# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

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
  metadata has no relying party to deliver to. **Breaking**: every existing
  call to `startMockSamlIdp` that expects a delivered assertion must now
  pass `acsUrls` naming its ACS.
- `startMockSamlIdp`'s `GET /sso` now requires the inflated `AuthnRequest`
  to carry a non-empty `ID`, `Version` exactly `"2.0"`, and an
  `IssueInstant` that parses as an `xsd:dateTime` (SAML Core §3.2.1,
  `RequestAbstractType`), refusing anything else with a `400` naming the
  missing or invalid attribute. Previously a missing `ID` silently became
  an empty `InResponseTo` rather than being refused. **Breaking**: an
  `AuthnRequest` built without `IssueInstant` (or with a missing `ID` or a
  `Version` other than `"2.0"`) is now refused instead of answered.
- `ID` is now additionally required to be a well-formed `xs:ID`
  (`NCName`, XML Namespaces 1.0 §3): a leading letter or underscore, then
  letters, digits, `.`, `-` or `_`. `ID="123"` and `ID="contains spaces"`
  were previously accepted (only non-emptiness was checked) and flowed
  straight into `InResponseTo`; both are now refused with a `400`. Only
  the ASCII subset of `NCName` is implemented — the full production's
  non-ASCII `NameStartChar`/`NameChar` ranges are not. **Breaking**: an
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
  of a negative (BCE) year. **Breaking**: an `AuthnRequest` whose
  `IssueInstant` names a calendar date that does not exist is now refused
  instead of answered with a silently-normalised date.

## [0.1.0] - 2026-08-07

First release. Protocol-faithful mock authorization servers — UAA/OAuth2,
OIDC, and a SAML 2.0 identity provider — for testing `@mcp-abap-adt`
packages' authorization flows deterministically, without a live tenant.

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
