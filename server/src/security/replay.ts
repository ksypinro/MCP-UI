/**
 * Single-use identifiers: a DPoP proof's `jti` may be presented once.
 *
 * With one process a map is enough. With several, a proof refused by one
 * could be replayed against the next, so the shared implementation lives in
 * Redis (`SET NX EX`, stores/redis.ts).
 */

export interface ReplayStore {
  /** True the first time `key` is seen within `ttlSeconds`, false after. */
  claim(key: string, ttlSeconds: number): Promise<boolean>;
}

/** Per-process store. Bounded: expired entries are swept as the map grows. */
export class MemoryReplayStore implements ReplayStore {
  private readonly seen = new Map<string, number>();

  async claim(key: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    if (this.seen.size > 10_000) for (const [k, expiry] of this.seen) if (expiry <= now) this.seen.delete(k);
    const expiry = this.seen.get(key);
    if (expiry !== undefined && expiry > now) return false;
    this.seen.set(key, now + ttlSeconds * 1000);
    return true;
  }
}
