/**
 * A mock UAA authorization server.
 *
 * Strict by default: it refuses what a real server refuses, so a client's
 * mistake surfaces as this server's answer rather than as an assertion written
 * by the same person who wrote the mistake.
 */

import { randomUUID } from 'node:crypto';
import { DOMParser } from '@xmldom/xmldom';
import { readClientAuth } from './clientAuth';
import {
  type ClientRegistryOptions,
  createClientRegistry,
  refusedForeignCode,
  refusedUnregisteredClient,
} from './clients';
import { mintJwt } from './jwt';
import { sendOAuthError } from './oauthErrors';
import { type MockHandle, startServer } from './server';

export interface UaaOptions extends ClientRegistryOptions {
  /** Short by default so an expiry test does not have to wait. */
  codeLifetimeMs?: number;
  accessTokenLifetimeSeconds?: number;
  authorize?: 'allow' | 'deny';
  requireClientSecret?: boolean;
  /** Both behaviours exist in the wild; a client must survive either. */
  rotateRefreshTokens?: boolean;
  failRefresh?: boolean;
  /** 'strict' enforces RFC 7522 §2.1: a base64url-encoded Assertion. */
  samlBearer?: 'strict' | 'lenient' | 'off';
}

export interface MockUaa extends MockHandle {
  /**
   * An access token already expired alongside a refresh token still valid.
   * Without this a refresh test must hand-craft a JWT or run a code flow and
   * wait — the first is duplication, the second is slow.
   */
  mintExpiredAccessWithValidRefresh(clientId?: string): {
    accessToken: string;
    refreshToken: string;
  };
}

interface IssuedCode {
  redirectUri: string;
  clientId: string;
  issuedAt: number;
  used: boolean;
}

const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
/** base64url: no + or /, and padding is not part of the alphabet. */
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Returns a reason to refuse, or null to accept.
 *
 * The encoding check cannot stand alone — a base64 string may contain no `+`
 * or `/` by chance — and the content check cannot stand alone either, because
 * a `samlp:Response` contains an `Assertion`. So the content check asks what
 * the *document element* is, not what appears somewhere inside it.
 */
function rejectNonAssertion(raw: string): string | null {
  if (!BASE64URL.test(raw)) {
    return 'RFC 7522 §2.1 requires base64url encoding without padding';
  }

  try {
    const decoded = Buffer.from(raw, 'base64url').toString('utf8');
    const root = new DOMParser().parseFromString(
      decoded,
      'text/xml',
    ).documentElement;
    if (!root) return 'the assertion parameter did not decode to XML';
    if (
      root.localName === 'Assertion' &&
      root.namespaceURI === SAML_ASSERTION_NS
    ) {
      return null;
    }
    return `RFC 7522 §2.1 requires a single Assertion as the document element, not a ${root.localName}`;
  } catch {
    return 'the assertion parameter did not decode to XML';
  }
}

export async function startMockUaa(options: UaaOptions = {}): Promise<MockUaa> {
  const registry = createClientRegistry(options);
  const codeLifetimeMs = options.codeLifetimeMs ?? 2000;
  const accessLifetime = options.accessTokenLifetimeSeconds ?? 3600;
  const requireSecret = options.requireClientSecret !== false;
  const denies = options.authorize === 'deny';
  const rotate = options.rotateRefreshTokens !== false;
  const failRefresh = options.failRefresh === true;
  const samlBearer = options.samlBearer ?? 'strict';

  const codes = new Map<string, IssuedCode>();

  /** refresh token → the client it belongs to */
  const refreshTokens = new Map<string, string>();
  const supersededRefreshTokens = new Set<string>();

  const issueRefreshToken = (clientId: string): string => {
    const token = `refresh-${randomUUID()}`;
    refreshTokens.set(token, clientId);
    return token;
  };

  const handle = await startServer({
    'GET /oauth/authorize': (req, res) => {
      const redirectUri = req.query.redirect_uri;
      if (!redirectUri) {
        sendOAuthError(res, 'invalid_request', 'redirect_uri is required');
        return;
      }
      const requestedClientId = req.query.client_id;
      if (refusedUnregisteredClient(res, registry, requestedClientId)) return;
      const target = new URL(redirectUri);
      if (denies) {
        target.searchParams.set('error', 'access_denied');
        target.searchParams.set(
          'error_description',
          'the mock was told to deny',
        );
      } else {
        const code = randomUUID();
        codes.set(code, {
          redirectUri,
          // Non-null: refusedUnregisteredClient returned false, so it is set.
          clientId: requestedClientId as string,
          issuedAt: Date.now(),
          used: false,
        });
        target.searchParams.set('code', code);
      }
      if (req.query.state) target.searchParams.set('state', req.query.state);
      res.statusCode = 302;
      res.setHeader('Location', target.toString());
      res.end();
    },

    'POST /oauth/token': (req, res) => {
      const auth = readClientAuth(req);
      if (auth.conflict) {
        sendOAuthError(res, 'invalid_client', 'header and body disagree', {
          usedAuthorizationHeader: auth.usedAuthorizationHeader,
        });
        return;
      }
      const client = registry.find(auth.clientId);
      if (
        !client ||
        (requireSecret && auth.clientSecret !== client.clientSecret)
      ) {
        sendOAuthError(res, 'invalid_client', 'unknown client', {
          usedAuthorizationHeader: auth.usedAuthorizationHeader,
        });
        return;
      }

      if (req.body.grant_type === 'refresh_token') {
        const presented = req.body.refresh_token ?? '';
        if (failRefresh) {
          sendOAuthError(
            res,
            'invalid_grant',
            'the mock was told to fail every refresh',
          );
          return;
        }
        if (supersededRefreshTokens.has(presented)) {
          sendOAuthError(
            res,
            'invalid_grant',
            'refresh token already used (rotation)',
          );
          return;
        }
        const owner = refreshTokens.get(presented);
        if (owner === undefined) {
          sendOAuthError(res, 'invalid_grant', 'unknown refresh token');
          return;
        }
        if (owner !== auth.clientId) {
          sendOAuthError(
            res,
            'invalid_grant',
            'the refresh token was issued to a different client',
          );
          return;
        }
        let next = presented;
        if (rotate) {
          refreshTokens.delete(presented);
          supersededRefreshTokens.add(presented);
          next = issueRefreshToken(owner);
        }
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            access_token: mintJwt({ expiresInSeconds: accessLifetime }),
            refresh_token: next,
            token_type: 'bearer',
            expires_in: accessLifetime,
          }),
        );
        return;
      }

      if (
        req.body.grant_type === 'urn:ietf:params:oauth:grant-type:saml2-bearer'
      ) {
        if (samlBearer === 'off') {
          sendOAuthError(res, 'unsupported_grant_type', 'saml bearer disabled');
          return;
        }
        const raw = req.body.assertion ?? '';
        if (!raw) {
          sendOAuthError(res, 'invalid_grant', 'assertion is required');
          return;
        }
        if (samlBearer === 'strict') {
          const problem = rejectNonAssertion(raw);
          if (problem) {
            sendOAuthError(res, 'invalid_grant', problem);
            return;
          }
        }
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(
          JSON.stringify({
            access_token: mintJwt({ expiresInSeconds: accessLifetime }),
            token_type: 'bearer',
            expires_in: accessLifetime,
          }),
        );
        return;
      }

      if (req.body.grant_type !== 'authorization_code') {
        sendOAuthError(
          res,
          'unsupported_grant_type',
          String(req.body.grant_type),
        );
        return;
      }

      const issued = codes.get(req.body.code ?? '');
      if (!issued) {
        sendOAuthError(res, 'invalid_grant', 'unknown code');
        return;
      }
      // Without this, a server that knows two clients lets either redeem the
      // other's code and the identity in the token bears no relation to consent.
      if (refusedForeignCode(res, issued.clientId, auth.clientId)) return;
      if (issued.used) {
        sendOAuthError(res, 'invalid_grant', 'code already used');
        return;
      }
      if (Date.now() - issued.issuedAt > codeLifetimeMs) {
        sendOAuthError(res, 'invalid_grant', 'code expired');
        return;
      }
      if (issued.redirectUri !== req.body.redirect_uri) {
        sendOAuthError(
          res,
          'invalid_grant',
          `redirect_uri does not match the authorization request (${issued.redirectUri})`,
        );
        return;
      }

      issued.used = true;
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          access_token: mintJwt({ expiresInSeconds: accessLifetime }),
          refresh_token: issueRefreshToken(client.clientId),
          token_type: 'bearer',
          expires_in: accessLifetime,
        }),
      );
    },
  });
  return {
    ...handle,
    mintExpiredAccessWithValidRefresh(clientId = registry.all[0].clientId) {
      return {
        accessToken: mintJwt({ expiresInSeconds: -60 }),
        refreshToken: issueRefreshToken(clientId),
      };
    },
  };
}
