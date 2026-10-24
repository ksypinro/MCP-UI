import { API_BASE_URL, AUTH_BASE_URL, MCP_BASE_URL } from '../config.ts';

/**
 * The permissions from spec section 7.3.
 *
 * All three are requested at initial authorization rather than minimised to
 * devices:read. Minimising would make the first switch flip trigger a 403
 * insufficient_scope and a re-consent prompt mid-interaction, which is a poor
 * experience for a light switch and slow to correct: hosts cache discovery
 * documents globally for minutes. Step-up is supported, but must not be part
 * of the normal path.
 */
export const SCOPES = ['devices:read', 'devices:control', 'devices:create'] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * What discovery advertises: the device scopes plus `offline_access`, which
 * MCP 2026-07-28 uses to ask for a refresh token (SEP-2207). It is listed in
 * the 401 challenge's scope hint too, so a host that requests exactly what
 * the hint names still gets one.
 */
export const SCOPES_SUPPORTED = [...SCOPES, 'offline_access'] as const;

/** Whether a raw scope parameter asks for offline_access. */
export function requestsOfflineAccess(raw: unknown): boolean {
  return typeof raw === 'string' && raw.split(/\s+/).includes('offline_access');
}

/**
 * Off by default: public clients receive a refresh token whether or not they
 * name offline_access, because withholding one would force a host that does
 * not name it to re-link every hour.
 */
export function refreshRequiresOfflineAccess(): boolean {
  return process.env.REQUIRE_OFFLINE_ACCESS_FOR_REFRESH === 'true';
}

export function isScope(value: string): value is Scope {
  return (SCOPES as readonly string[]).includes(value);
}

/** Parses a space-delimited scope string, keeping only what we define. */
export function parseScopes(raw: unknown): Scope[] {
  if (typeof raw !== 'string') return [];
  const unique = new Set(raw.split(/\s+/).filter(Boolean).filter(isScope));
  return SCOPES.filter((scope) => unique.has(scope));
}

export const ISSUER = AUTH_BASE_URL;

/**
 * The canonical URI of the MCP server, per RFC 8707 section 2: no fragment,
 * no trailing slash. Tokens are bound to this and to nothing else.
 */
export const RESOURCE_URI = `${MCP_BASE_URL}/mcp`;

/**
 * The REST API as a protected resource: the audience of the first-party
 * app's tokens. Kept distinct from RESOURCE_URI so a token for one is never
 * accepted by the other.
 */
export const API_RESOURCE = API_BASE_URL;

/**
 * The first-party iOS app, as an OAuth client.
 *
 * Defined here rather than registered at run time: it is ours, its redirect
 * URIs are configuration, and it is the one client that skips the consent
 * screen and must use PAR and DPoP. Its callbacks are a universal link on the
 * API host (once an Apple team is configured) and a reverse-DNS private-use
 * scheme for development; PKCE plus a DPoP key bound at PAR time make a code
 * intercepted through the latter useless. The scheme is lower case because
 * URL schemes are case-insensitive and are normalised to lower case in
 * transit; comparing a mixed-case one exactly would fail.
 */
export const FIRST_PARTY_CLIENT_ID = 'iot-switch-ios';

export function firstPartyRedirectUris(): string[] {
  const configured = process.env.FIRST_PARTY_REDIRECT_URIS
    ?? `com.example.iotswitch:/oauth/callback,${API_BASE_URL}/oauth/callback`;
  return configured.split(',').map((entry) => entry.trim()).filter(Boolean);
}

/** The DPoP signature algorithms accepted (RFC 9449). */
export const DPOP_ALGORITHMS = ['ES256', 'EdDSA'] as const;

/** Pushed authorization requests live this long (RFC 9126). */
export const PAR_TTL_SECONDS = 60;

export const AUTHORIZATION_CODE_TTL_SECONDS = 60;
export const PENDING_AUTHORIZATION_TTL_SECONDS = 15 * 60;
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600;
/**
 * The iOS app's access tokens (token N): short, because the app refreshes
 * cheaply and holds them only in memory. Architecture section 7.
 */
export const NATIVE_ACCESS_TOKEN_TTL_SECONDS = Number(process.env.NATIVE_ACCESS_TOKEN_TTL_SECONDS ?? 600);
export const OAUTH_REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600;

/**
 * Dynamic Client Registration is open by definition, so it needs a ceiling.
 *
 * The ceiling only works alongside eviction. A cap with nothing expiring under
 * it is not a rate control, it is a permanent lockout waiting to happen: fill
 * it once and no host can ever connect again.
 */
export const MAX_REGISTERED_CLIENTS = 500;

/**
 * How long a registration that never completed an authorization is kept.
 * A real client registers and authorizes within minutes.
 */
export const UNUSED_CLIENT_TTL_SECONDS = 24 * 3600;

/**
 * How long after a rotation a duplicate refresh with the old token is answered
 * with the same response rather than treated as theft. Covers a host that
 * refreshes from two workers at once, and a response lost in transit.
 */
export const REFRESH_GRACE_SECONDS = Number(process.env.REFRESH_GRACE_SECONDS ?? 30);
