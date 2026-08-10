/**
 * A mock OIDC provider.
 *
 * Two rules distinguish it from the UAA mock:
 *
 * PKCE is demanded at both ends. `/authorize` refuses a request with no
 * `code_challenge`, no `code_challenge_method`, or a method other than
 * `S256` — verifying a challenge only when one happens to arrive would let a
 * non-PKCE request through while still satisfying the exchange rule. Both
 * `code_challenge` and `code_verifier` are also checked against RFC 7636's
 * `43*128unreserved` shape before anything is hashed or compared — a
 * verifier a real server would refuse for its shape must not exchange a
 * code here either.
 *
 * `state` is mirrored, never judged. Validating `state` is the client's duty,
 * and a mock that checked it would be doing the client's job while hiding
 * whether the client does it.
 *
 * The code is bound to its client by the same functions the UAA mock uses —
 * `authenticateClient`, `refusedUnregisteredClient`,
 * `refusedUnregisteredRedirectUri` and `refusedForeignCredential`, all
 * imported from `./clients` rather than restated, so the two mocks cannot
 * disagree about what "bound to its client" means. `sendRedirectError` is
 * shared the same way for the errors both mocks report at the callback
 * rather than directly (missing/unsupported `response_type`, and here,
 * PKCE).
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  authenticateClient,
  createClientRegistry,
  refusedForeignCredential,
  refusedUnregisteredClient,
  refusedUnregisteredRedirectUri,
  sendRedirectError,
} from './clients';
import { mintJwt } from './jwt';
import { sendOAuthError } from './oauthErrors';
import { type MockHandle, startServer } from './server';
import type { UaaOptions } from './uaa';

export interface OidcOptions extends UaaOptions {
  /**
   * 'mirror' (default) reflects state back unchanged, exactly as a client
   * expects. The other two exist to test that the client notices when a
   * server does not: 'wrongState' corrupts it, 'missingState' drops it.
   */
  state?: 'mirror' | 'wrongState' | 'missingState';
}

interface IssuedCode {
  redirectUri: string;
  clientId: string;
  challenge: string;
  issuedAt: number;
  used: boolean;
}

/**
 * RFC 7636 §4.1 and §4.2 give `code_verifier` and `code_challenge` the same
 * shape: `43*128unreserved`, where `unreserved = ALPHA / DIGIT / "-" / "."
 * / "_" / "~"`. The length floor is what carries the security property — a
 * verifier a real server would refuse for being too short (or too long, or
 * outside the character class) must not be allowed to exchange a code here
 * either. One predicate serves both parameters so the character class is
 * written once rather than drifting between the two call sites.
 */
const PKCE_SHAPE = /^[A-Za-z0-9\-._~]{43,128}$/;
function hasPkceShape(value: string): boolean {
  return PKCE_SHAPE.test(value);
}

export async function startMockOidc(
  options: OidcOptions = {},
): Promise<MockHandle> {
  const registry = createClientRegistry(options);
  const codeLifetimeMs = options.codeLifetimeMs ?? 2000;
  const accessLifetime = options.accessTokenLifetimeSeconds ?? 3600;
  const requireSecret = options.requireClientSecret !== false;
  const stateMode = options.state ?? 'mirror';

  const codes = new Map<string, IssuedCode>();

  /**
   * Mirrored, never judged: validating state is the client's duty, and a mock
   * that checked it would hide whether the client does. The corruption modes
   * exist to test that the client notices.
   */
  const applyState = (target: URL, incoming: string | undefined): void => {
    if (incoming === undefined) return;
    if (stateMode === 'mirror') target.searchParams.set('state', incoming);
    else if (stateMode === 'wrongState')
      target.searchParams.set('state', `not-${incoming}`);
    // 'missingState' sets nothing
  };

  // baseUrl is not known until the server binds; this holder is filled in
  // from the handle right below, before startMockOidc returns.
  const holder: { baseUrl: string } = { baseUrl: '' };

  const handle = await startServer({
    'GET /.well-known/openid-configuration': (_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          issuer: holder.baseUrl,
          authorization_endpoint: `${holder.baseUrl}/authorize`,
          token_endpoint: `${holder.baseUrl}/token`,
          code_challenge_methods_supported: ['S256'],
          response_types_supported: ['code'],
        }),
      );
    },

    'GET /authorize': (req, res) => {
      const redirectUri = req.query.redirect_uri;
      if (!redirectUri) {
        sendOAuthError(res, 'invalid_request', 'redirect_uri is required');
        return;
      }
      const requestedClientId = req.query.client_id;
      if (refusedUnregisteredClient(res, registry, requestedClientId)) return;
      const client = registry.find(requestedClientId);
      if (!client) return; // unreachable: refusedUnregisteredClient already confirmed it
      if (refusedUnregisteredRedirectUri(res, client, redirectUri)) return;

      const target = new URL(redirectUri);
      // Past this line client_id and redirect_uri are both trusted, so every
      // remaining refusal is reported at the callback rather than answered
      // directly.
      const redirectError = (error: string, description: string): void => {
        applyState(target, req.query.state);
        sendRedirectError(res, target, error, description);
      };

      const responseType = req.query.response_type;
      if (responseType === undefined) {
        redirectError('invalid_request', 'response_type is required');
        return;
      }
      if (responseType !== 'code') {
        redirectError(
          'unsupported_response_type',
          `unsupported response_type: ${responseType}`,
        );
        return;
      }

      const challenge = req.query.code_challenge;
      const method = req.query.code_challenge_method;
      if (!challenge || !method) {
        redirectError(
          'invalid_request',
          'PKCE is required: code_challenge and code_challenge_method',
        );
        return;
      }
      if (method !== 'S256') {
        redirectError(
          'invalid_request',
          `unsupported code_challenge_method: ${method}`,
        );
        return;
      }
      if (!hasPkceShape(challenge)) {
        redirectError(
          'invalid_request',
          'code_challenge must be 43-128 characters from the RFC 7636 §4.2 unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~")',
        );
        return;
      }

      const code = randomUUID();
      codes.set(code, {
        redirectUri,
        clientId: client.clientId,
        challenge,
        issuedAt: Date.now(),
        used: false,
      });
      target.searchParams.set('code', code);
      applyState(target, req.query.state);
      res.statusCode = 302;
      res.setHeader('Location', target.toString());
      res.end();
    },

    'POST /token': (req, res) => {
      const authenticated = authenticateClient(
        req,
        res,
        registry,
        requireSecret,
      );
      if (!authenticated) return;
      const { auth } = authenticated;

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
      // The binding check comes first, exactly as in uaa.ts, and by the same
      // function — a code redeemed by the wrong client is refused before its
      // verifier is even considered.
      if (refusedForeignCredential(res, 'code', issued.clientId, auth.clientId))
        return;

      const verifier = req.body.code_verifier ?? '';
      // The shape check comes first and refuses as invalid_request: a
      // verifier RFC 7636 §4.1 forbids (too short, too long, or outside the
      // unreserved character class) is a malformed request, not a failed
      // proof-of-possession. Only a well-formed verifier reaches the hash
      // comparison below, which is the separate question of whether it
      // derives the stored challenge.
      if (!hasPkceShape(verifier)) {
        sendOAuthError(
          res,
          'invalid_request',
          'code_verifier must be 43-128 characters from the RFC 7636 §4.1 unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~")',
        );
        return;
      }
      const derived = createHash('sha256').update(verifier).digest('base64url');
      if (derived !== issued.challenge) {
        sendOAuthError(
          res,
          'invalid_grant',
          'code_verifier does not derive code_challenge',
        );
        return;
      }
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
          token_type: 'bearer',
          expires_in: accessLifetime,
        }),
      );
    },
  });

  holder.baseUrl = handle.url;
  return handle;
}
