import type { Queryable } from '../db/index.ts';
import type { Identity } from './types.ts';

/**
 * Spec section 11. Deliberately narrow: verified actor, device, what changed,
 * outcome, channel, request id. No request bodies, because a request body is
 * exactly where a password would be if anyone ever got that wrong.
 */
export interface AuditEvent {
  action: 'device.create' | 'device.control';
  deviceId: string | null;
  oldState: string | null;
  newState: string | null;
  outcome: 'ok' | 'rejected';
}

export async function record(tx: Queryable, identity: Identity, event: AuditEvent): Promise<void> {
  await tx.query(
    `INSERT INTO audit_events
       (actor_account_id, device_id, action, old_state, new_state, outcome, channel, request_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      identity.accountId,
      event.deviceId,
      event.action,
      event.oldState,
      event.newState,
      event.outcome,
      identity.channel,
      identity.requestId ?? null
    ]
  );
}
