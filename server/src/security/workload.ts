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
 * certificate (cnf x5t#S256): the authorization server binds the token to the
 * certificate the adapter presented when it asked, and the Device Service
 * accepts it only over a connection made with that same certificate.
 */

import { createHash, randomBytes } from 'node:crypto';

export type WorkloadName = 'mcp-rs' | 'api-gw';

/** What an internal token is bound to: a per-process value, or a certificate (RFC 8705). */
export type Confirmation = { jkt: string } | { 'x5t#S256': string };

export interface Workload {
  readonly name: WorkloadName;
  /** The binding internal tokens carry in `cnf`. */
  readonly cnf: Confirmation;
}

/** A workload in this process: its binding is random and exists nowhere else. */
export function createWorkload(name: WorkloadName): Workload {
  return Object.freeze({
    name,
    cnf: Object.freeze({ jkt: createHash('sha256').update(randomBytes(32)).digest('base64url') })
  });
}

/** A workload identified by the client certificate it presented over mTLS. */
export function certificateWorkload(name: WorkloadName, certificateDer: Buffer): Workload {
  return Object.freeze({
    name,
    cnf: Object.freeze({ 'x5t#S256': createHash('sha256').update(certificateDer).digest('base64url') })
  });
}

/** Whether a token's `cnf` claim names exactly this binding. */
export function confirms(claim: unknown, expected: Confirmation): boolean {
  if (!claim || typeof claim !== 'object') return false;
  const entries = Object.entries(expected);
  const presented = claim as Record<string, unknown>;
  return entries.every(([key, value]) => presented[key] === value)
    && Object.keys(presented).length === entries.length;
}

/** The URI form used in `act.sub`, the way a service mesh would name it. */
export function workloadUri(workload: Workload): string {
  return `spiffe://iot-switch/${workload.name}`;
}

/** The workload a SPIFFE URI names, if it is one of ours. */
export function workloadNamed(uri: string): WorkloadName | null {
  const match = /^spiffe:\/\/iot-switch\/(mcp-rs|api-gw)$/.exec(uri);
  return match ? match[1] as WorkloadName : null;
}
