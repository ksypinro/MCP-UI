import type { Scope } from '../oauth/config.ts';

/** The endpoint path. Fixed: it is the canonical resource URI tokens are bound to. */
export const MCP_PATH = '/mcp';

/**
 * Tools that require a bearer token, and the scope each one needs.
 *
 * The HTTP gate reads this before the JSON-RPC body reaches the MCP SDK.
 * Anything absent here is public and reaches its handler without a token.
 */
export const PROTECTED_TOOLS: Readonly<Record<string, Scope>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, Scope>, {
    list_devices: 'devices:read',
    get_device: 'devices:read',
    control_device: 'devices:control',
    add_device: 'devices:create'
  })
);

export function requiredScopeFor(toolName: string): Scope | null {
  // Object.hasOwn, not `in`: a plain object literal would match inherited keys
  // like "toString" and classify them as protected tools.
  return Object.hasOwn(PROTECTED_TOOLS, toolName) ? PROTECTED_TOOLS[toolName]! : null;
}

export const SERVER_INFO = { name: 'iot-switch', version: '0.1.0' } as const;
