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
