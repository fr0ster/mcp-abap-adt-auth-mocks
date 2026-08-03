/**
 * The client registry, and the two refusals that keep a credential with the
 * client it was issued to.
 *
 * Both mocks import this. Authenticating a caller answers "do I know you";
 * these answer "is this yours", which is a different question and the one a
 * forgetful server gets wrong.
 */

import type * as http from 'node:http';
import { sendOAuthError } from './oauthErrors';

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
 * A code belongs to the client it was issued to.
 *
 * Returns true when it answered, meaning the caller must stop.
 */
export function refusedForeignCode(
  res: http.ServerResponse,
  issuedTo: string,
  authenticatedAs: string | undefined,
): boolean {
  if (issuedTo === authenticatedAs) return false;
  sendOAuthError(
    res,
    'invalid_grant',
    'the code was issued to a different client',
  );
  return true;
}
