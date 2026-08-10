/**
 * The client registry, and the two refusals that keep a credential with the
 * client it was issued to.
 *
 * Both mocks import this. Authenticating a caller answers "do I know you";
 * these answer "is this yours", which is a different question and the one a
 * forgetful server gets wrong.
 */

import type * as http from 'node:http';
import { type ClientAuth, readClientAuth } from './clientAuth';
import { sendOAuthError } from './oauthErrors';
import type { RecordedRequest } from './server';

/** The callback `@mcp-abap-adt/auth-providers` uses by default. */
export const DEFAULT_REDIRECT_URI = 'http://localhost:61001/callback';

export interface UaaClient {
  clientId: string;
  clientSecret: string;
  /**
   * Permitted callback targets. Defaults to `[DEFAULT_REDIRECT_URI]` — not
   * "anything the client happens to send". RFC 6749 §3.1.2.3 requires exact,
   * byte-for-byte string comparison against a registered value, so a mock
   * that matched by prefix or origin would teach a habit a real server
   * refuses.
   */
  redirectUris?: string[];
}

export interface ClientRegistryOptions {
  /** Registered clients. A test proving a code cannot cross a boundary uses two. */
  clients?: UaaClient[];
  /** Shorthand for a single registered client. Ignored when `clients` is given. */
  clientId?: string;
  clientSecret?: string;
}

export interface ClientRegistry {
  /** Registered clients, in declaration order. */
  all: UaaClient[];
  find(clientId: string | undefined): UaaClient | undefined;
}

export function createClientRegistry(
  options: ClientRegistryOptions = {},
): ClientRegistry {
  const declared = options.clients ?? [
    {
      clientId: options.clientId ?? 'mock-client',
      clientSecret: options.clientSecret ?? 'mock-secret',
    },
  ];
  const all = declared.map((c) => ({
    ...c,
    redirectUris: c.redirectUris ?? [DEFAULT_REDIRECT_URI],
  }));
  return {
    all,
    find: (clientId) => all.find((c) => c.clientId === clientId),
  };
}

/**
 * RFC 6749 §4.1.2.1: an unregistered client means the redirect_uri it supplied
 * cannot be trusted either, so this error is answered directly and never
 * redirected — redirecting it would hand an attacker a redirector.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedUnregisteredClient(
  res: http.ServerResponse,
  registry: ClientRegistry,
  clientId: string | undefined,
): boolean {
  if (clientId && registry.find(clientId)) return false;
  sendOAuthError(
    res,
    'invalid_request',
    'client_id is missing or not registered',
  );
  return true;
}

/**
 * RFC 6749 §3.1.2.3: a redirect_uri must match a registered value exactly —
 * no prefix or origin matching. It is checked only once the client itself is
 * known, but before anything is trusted with a redirect: an unregistered
 * redirect_uri is exactly as untrustworthy as an unregistered client_id, and
 * for the same reason — answering it with a redirect would hand an attacker
 * a redirector for a known client.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedUnregisteredRedirectUri(
  res: http.ServerResponse,
  client: UaaClient,
  redirectUri: string,
): boolean {
  if (client.redirectUris?.includes(redirectUri)) return false;
  sendOAuthError(
    res,
    'invalid_request',
    'redirect_uri is not registered for this client',
  );
  return true;
}

/**
 * A credential belongs to the client it was issued to.
 *
 * Takes the credential's name so a code and a refresh token can share one
 * implementation while still saying which one was presented. They are the same
 * rule: a refresh token carries the authorization a code carried, so it crosses
 * a client boundary just as badly.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedForeignCredential(
  res: http.ServerResponse,
  credential: 'code' | 'refresh token',
  issuedTo: string,
  authenticatedAs: string | undefined,
): boolean {
  if (issuedTo === authenticatedAs) return false;
  sendOAuthError(
    res,
    'invalid_grant',
    `the ${credential} was issued to a different client`,
  );
  return true;
}

/**
 * RFC 6749 §4.1.2.1: once client_id and redirect_uri are trusted, every later
 * refusal at the authorization endpoint is reported *at the callback* — a 302
 * to `target` carrying `error` and `error_description` — rather than answered
 * directly. Both mocks hit this shape (OIDC for PKCE, and both for
 * response_type), so it is written once here rather than as two redirect
 * builders that could drift apart on status code or header name.
 *
 * `state`, if the caller wants it mirrored, must already be set on `target`
 * before this is called — OIDC's corruption modes (`wrongState`,
 * `missingState`) mean "mirror the incoming state" is not the same operation
 * in both mocks, so this only sends what it is given.
 */
export function sendRedirectError(
  res: http.ServerResponse,
  target: URL,
  error: string,
  description: string,
): void {
  target.searchParams.set('error', error);
  target.searchParams.set('error_description', description);
  res.statusCode = 302;
  res.setHeader('Location', target.toString());
  res.end();
}

/**
 * Authenticates the caller against the registry: reads the credentials,
 * rejects more than one authentication method or a header/body client_id
 * disagreement (see `ClientAuth.conflict`), and checks the secret.
 *
 * Returns null when it has already answered, meaning the caller must stop.
 * Otherwise returns both the registered client and the credentials as read —
 * callers need the latter to ask the separate question `refusedForeignCredential`
 * answers.
 */
export function authenticateClient(
  req: RecordedRequest,
  res: http.ServerResponse,
  registry: ClientRegistry,
  requireSecret: boolean,
): { auth: ClientAuth; client: UaaClient } | null {
  const auth = readClientAuth(req);
  if (auth.conflict) {
    sendOAuthError(
      res,
      'invalid_client',
      'more than one client authentication method was used (RFC 6749 §2.3), or the body client_id disagrees with the Authorization header',
      { usedAuthorizationHeader: auth.usedAuthorizationHeader },
    );
    return null;
  }
  const client = registry.find(auth.clientId);
  if (!client || (requireSecret && auth.clientSecret !== client.clientSecret)) {
    sendOAuthError(res, 'invalid_client', 'unknown client', {
      usedAuthorizationHeader: auth.usedAuthorizationHeader,
    });
    return null;
  }
  return { auth, client };
}
