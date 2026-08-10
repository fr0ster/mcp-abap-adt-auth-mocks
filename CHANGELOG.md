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
