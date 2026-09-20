/** Phase 0 spike configuration. Throwaway; not the product. */

export const PORT = Number(process.env.PORT ?? 3000);

/**
 * Public origin, no trailing slash. Everything OAuth depends on this being
 * stable and identical to the URL registered as the connector, because it
 * becomes the issuer, the RFC 8707 resource indicator, and the token audience.
 * Hosts cache discovery documents globally by URL for minutes, so changing it
 * mid-test produces stale-cache behaviour that looks like a code bug.
 */
export const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');

/** Canonical MCP server URI, per RFC 8707 section 2. No fragment, no trailing slash. */
export const RESOURCE_URI = `${BASE_URL}/mcp`;

export const SCOPES = ['devices:read', 'devices:control', 'devices:create'] as const;
export type Scope = (typeof SCOPES)[number];

/**
 * Tools that require a bearer token. The HTTP gate in index.ts reads this set
 * before the JSON-RPC body reaches the MCP SDK; see spec section 7.5.
 */
export const PROTECTED_TOOLS: Record<string, Scope> = {
  list_devices: 'devices:read',
  get_device: 'devices:read',
  control_device: 'devices:control'
};

/** How many devices to seed, chosen to overflow a host inline card on purpose. */
export const SEED_DEVICE_COUNT = 12;
