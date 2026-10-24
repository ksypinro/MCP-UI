/**
 * The single source of what each MCP tool requires.
 *
 * The HTTP gate reads the scope from here before the SDK sees a request; the
 * tool registrations read their annotations from here; ChatGPT's security
 * schemes are derived from here; and the write budget a tool spends comes
 * from here. One table, so none of those can disagree with another.
 *
 * Annotations are honest hints for a host's approval prompts. They grant
 * nothing: the server checks scope on every call whatever a tool declares.
 */

import type { Scope } from '../oauth/config.ts';
import type { WriteKind } from '../write-budgets.ts';

export interface ToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  idempotentHint: boolean;
  openWorldHint: boolean;
}

export interface ToolPolicy {
  /** The scope a token must hold to call this tool; null for a public tool. */
  scope: Scope | null;
  annotations: ToolAnnotations;
  /** The write budget a call spends, if it changes anything. */
  budget: WriteKind | null;
}

const READ_ONLY: ToolAnnotations = {
  readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false
};

/**
 * Not idempotent: replaying either write fails (a version conflict, a name
 * clash) rather than repeating, and a dishonest hint invites a host to retry
 * something that cannot be retried. Not destructive: a device has two states
 * and either is reachable.
 */
const WRITE: ToolAnnotations = {
  readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false
};

export const TOOL_POLICY: Readonly<Record<string, ToolPolicy>> = Object.freeze(
  Object.assign(Object.create(null) as Record<string, ToolPolicy>, {
    list_devices: { scope: 'devices:read', annotations: READ_ONLY, budget: null },
    get_device: { scope: 'devices:read', annotations: READ_ONLY, budget: null },
    control_device: { scope: 'devices:control', annotations: WRITE, budget: 'control' },
    add_device: { scope: 'devices:create', annotations: WRITE, budget: 'create' },
    get_auth_status: { scope: null, annotations: READ_ONLY, budget: null },
    show_auth: { scope: null, annotations: READ_ONLY, budget: null },
    show_add_device: { scope: null, annotations: READ_ONLY, budget: null }
  } satisfies Record<string, ToolPolicy>)
);

/** The policy for `name`, or null for a tool this server does not have. */
export function policyFor(name: string): ToolPolicy | null {
  // Object.hasOwn, not `in`: inherited keys like "toString" are not tools.
  return Object.hasOwn(TOOL_POLICY, name) ? TOOL_POLICY[name]! : null;
}

/** The annotations a tool is registered with. Throws for a tool missing from the table. */
export function annotationsFor(name: string): ToolAnnotations {
  const policy = policyFor(name);
  if (!policy) throw new Error(`No policy for tool ${name}`);
  return policy.annotations;
}
