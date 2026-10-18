/**
 * Revocation events, so caches built on a grant drop it the moment it ends.
 *
 * Every protected request still verifies its credential live, so a revoked
 * grant is refused at the edge regardless; this makes sure no internal token
 * minted for it survives either. In one process it is a list of listeners;
 * across processes the same interface sits on a shared bus.
 */

type Listener = (grantId: string) => void;

const listeners = new Set<Listener>();

export function onGrantRevoked(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function grantRevoked(grantId: string): void {
  for (const listener of listeners) {
    try {
      listener(grantId);
    } catch {
      // A failing listener must not stop revocation reaching the others.
    }
  }
}
