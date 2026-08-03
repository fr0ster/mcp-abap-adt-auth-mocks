/**
 * A mock UAA authorization server.
 *
 * Strict by default: it refuses what a real server refuses, so a client's
 * mistake surfaces as this server's answer rather than as an assertion written
 * by the same person who wrote the mistake.
 */

import { randomUUID } from 'node:crypto';
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
}

export type MockUaa = MockHandle;

interface IssuedCode {
  redirectUri: string;
  clientId: string;
  issuedAt: number;
  used: boolean;
}

export async function startMockUaa(options: UaaOptions = {}): Promise<MockUaa> {
  const registry = createClientRegistry(options);
  const codeLifetimeMs = options.codeLifetimeMs ?? 2000;
  const accessLifetime = options.accessTokenLifetimeSeconds ?? 3600;
  const requireSecret = options.requireClientSecret !== false;
  const denies = options.authorize === 'deny';

  const codes = new Map<string, IssuedCode>();

  // Task 5 replaces this with one that registers the token against its client.
  const issueRefreshToken = (_clientId: string): string =>
    `refresh-${randomUUID()}`;

  return startServer({
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
          // Non-null: registry.find(auth.clientId) above only succeeded because
          // auth.clientId was defined.
          refresh_token: issueRefreshToken(auth.clientId as string),
          token_type: 'bearer',
          expires_in: accessLifetime,
        }),
      );
    },
  });
}
