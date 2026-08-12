/**
 * Mock authorization servers for testing @mcp-abap-adt packages.
 *
 * Everything here starts and stops inside a test. Nothing imports the packages
 * this exists to test: a mock that knows those types would eventually agree
 * with their mistakes instead of catching them.
 */

export type { VisitResult } from './browser';
export { visit } from './browser';
export type { UaaClient } from './clients';
export { DEFAULT_REDIRECT_URI } from './clients';
export type { OidcOptions } from './oidc';
export { startMockOidc } from './oidc';
export type { MockSamlIdp, SamlOptions, SamlVariant } from './saml';
export { startMockSamlIdp } from './saml';
export type { MockHandle, RecordedRequest } from './server';
export type { KeyMaterial } from './signing';
export { generateKeyMaterial, signXml } from './signing';
export type { MockUaa, UaaOptions } from './uaa';
export { startMockUaa } from './uaa';
