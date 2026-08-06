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

export interface UaaClient {
  clientId: string;
  clientSecret: string;
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
  const all = options.clients ?? [
    {
      clientId: options.clientId ?? 'mock-client',
      clientSecret: options.clientSecret ?? 'mock-secret',
    },
  ];
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
 * Authenticates the caller against the registry: reads the credentials, rejects
 * a header/body disagreement, and checks the secret.
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
    sendOAuthError(res, 'invalid_client', 'header and body disagree', {
      usedAuthorizationHeader: auth.usedAuthorizationHeader,
    });
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
