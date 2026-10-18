import { AUTH_BASE_URL, MCP_BASE_URL } from '../config.ts';

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
 * name offline_access, because it is not yet confirmed that every host does,
 * and withholding one would force a host to re-link every hour. Turn on once
 * host-check shows both hosts send it.
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

export const AUTHORIZATION_CODE_TTL_SECONDS = 60;
export const PENDING_AUTHORIZATION_TTL_SECONDS = 15 * 60;
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 3600;
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
