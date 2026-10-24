/**
 * Revocation events, so caches built on a grant drop it the moment it ends.
 *
 * Every protected request still verifies its credential live, so a revoked
 * grant is refused at the edge regardless; this makes sure no internal token
 * minted for it survives either.
 *
 * A hub is one process's view. Domain code publishes to the process hub
 * without being handed it; caches subscribe to it. With more than one process,
 * `bridgeRevocations` (stores/redis.ts) joins the hubs over Redis pub/sub:
 * what one process publishes, every other one hears.
 */

export type RevocationEvent =
  | { type: 'grant.revoked'; grantId: string }
  /** Every grant of an account: "sign out everywhere", a password change. */
  | { type: 'account.revoked'; accountId: string }
  /** Every grant held by a client. */
  | { type: 'client.blocked'; clientId: string };

/** Set on an event that arrived from another process, so it is not sent back. */
export type ReceivedEvent = RevocationEvent & { remote?: true };

type Listener = (event: ReceivedEvent) => void;

export class RevocationHub {
  private readonly listeners = new Set<Listener>();

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  publish(event: ReceivedEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // A failing listener must not stop revocation reaching the others.
      }
    }
  }
}

/** This process's hub. */
export const processRevocations = new RevocationHub();

export function grantRevoked(grantId: string): void {
  processRevocations.publish({ type: 'grant.revoked', grantId });
}

export function accountRevoked(accountId: string): void {
  processRevocations.publish({ type: 'account.revoked', accountId });
}
