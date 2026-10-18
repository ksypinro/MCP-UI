import type { Scope } from '../oauth/config.ts';
import { policyFor } from './policy.ts';

/** The endpoint path. Fixed: it is the canonical resource URI tokens are bound to. */
export const MCP_PATH = '/mcp';

/**
 * The scope a tool requires, from the policy table (mcp/policy.ts). Null for
 * a public tool, and for a name this server does not have; the gate treats
 * the latter as protected anyway, so an unknown tool is never anonymous.
 */
export function requiredScopeFor(toolName: string): Scope | null {
  return policyFor(toolName)?.scope ?? null;
}

export const SERVER_INFO = { name: 'iot-switch', version: '0.1.0' } as const;

/**
 * The per-tool security scheme ChatGPT reads to decide whether a tool needs
 * account linking. Derived from the policy table so the two cannot disagree.
 */
export type SecurityScheme = { type: 'noauth' } | { type: 'oauth2'; scopes: Scope[] };

export function securitySchemesFor(toolName: string): SecurityScheme[] {
  const scope = requiredScopeFor(toolName);
  return scope ? [{ type: 'oauth2', scopes: [scope] }] : [{ type: 'noauth' }];
}
