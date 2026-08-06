# @mcp-abap-adt/auth-mocks

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
server, a mock OIDC provider and a mock SAML identity provider — deterministically,
without a live tenant.

Everything a mock server starts and stops inside a test; nothing here is meant
to run in production.

## Status

Skeleton only. Mock servers land in subsequent releases.

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
  independently checks signature validity, `Conditions` timestamps,
  `Audience`, `Issuer` and `InResponseTo` — but it shares `xml-crypto`
  underneath for the actual cryptography, so it is not an independent
  implementation of XML-DSig either.
- It checks **neither `Destination` nor `SubjectConfirmationData@Recipient`**,
  so a mock IdP that gets those two fields wrong has no judge in this suite.
- It has **no assertion-ID replay cache** — replaying a captured assertion is
  not something this package or `@node-saml/node-saml` will flag; replay
  detection is the relying party's responsibility.
- None of the above proves canonicalisation matches what a real identity
  provider produces. A green suite here is evidence the mock's own signature
  round-trips, not evidence the mock's SAML profile matches a live IdP.
  **Live testing against a real identity provider remains necessary** and is
  not made obsolete by these tests passing.
