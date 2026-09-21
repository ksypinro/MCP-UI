import { BASE_URL } from '../config.ts';

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

export function isScope(value: string): value is Scope {
  return (SCOPES as readonly string[]).includes(value);
}

/** Parses a space-delimited scope string, keeping only what we define. */
export function parseScopes(raw: unknown): Scope[] {
  if (typeof raw !== 'string') return [];
  const unique = new Set(raw.split(/\s+/).filter(Boolean).filter(isScope));
  return SCOPES.filter((scope) => unique.has(scope));
}

export const ISSUER = BASE_URL;

/**
 * The canonical URI of the MCP server, per RFC 8707 section 2: no fragment,
 * no trailing slash. Tokens are bound to this and to nothing else.
 */
export const RESOURCE_URI = `${BASE_URL}/mcp`;

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
