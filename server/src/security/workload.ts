/**
 * Workload identities: which component is calling the Device Service.
 *
 * Every internal token names the workload it was issued to (`act.sub`) and is
 * bound to it (`cnf.jkt`). The Device Service accepts a token only from the
 * workload it names, so a token lifted from the MCP adapter is useless to
 * anything else.
 *
 * While every component runs in one process, a workload is a capability: an
 * object created once at start-up whose binding value is random and exists
 * nowhere else, handed only to the adapter it identifies. When components
 * run separately the binding becomes the thumbprint of the workload's mTLS
 * certificate (cnf x5t#S256), and the check moves to the TLS layer.
 */

import { createHash, randomBytes } from 'node:crypto';

export type WorkloadName = 'mcp-rs' | 'api-gw';

export interface Workload {
  readonly name: WorkloadName;
  /** The binding value internal tokens carry in cnf.jkt. */
  readonly jkt: string;
}

export function createWorkload(name: WorkloadName): Workload {
  return Object.freeze({
    name,
    jkt: createHash('sha256').update(randomBytes(32)).digest('base64url')
  });
}

/** The URI form used in `act.sub`, the way a service mesh would name it. */
export function workloadUri(workload: Workload): string {
  return `spiffe://iot-switch/${workload.name}`;
}
