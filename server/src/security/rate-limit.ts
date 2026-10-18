/**
 * Fixed-window rate limiting, split into a store-backed bucket and the
 * Express middleware that most routes use.
 *
 * The bucket is separate from the middleware because some limits can only be
 * keyed once a request has been authenticated: the MCP endpoint has to verify
 * a token before it knows whether to count the request against a grant or
 * against an address. Choosing the bucket from an *unverified* token let any
 * caller mint a fresh, empty bucket per request by sending a random bearer.
 *
 * The store is an interface so that a shared store can replace the in-memory
 * one when more than one process serves traffic.
 */

import type { Request, RequestHandler } from 'express';
import { AppError } from '../errors.ts';

export interface BucketStore {
  /** Counts one hit against `key` and returns the window's running total. */
  hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

/** Per-process store. Bounded: expired windows are swept as the map grows. */
export class MemoryBucketStore implements BucketStore {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();

  async hit(key: string, windowMs: number): Promise<{ count: number; resetAt: number }> {
    const now = Date.now();
    const entry = this.windows.get(key);
    if (!entry || entry.resetAt <= now) {
      const fresh = { count: 1, resetAt: now + windowMs };
      this.windows.set(key, fresh);
      if (this.windows.size > 10_000) {
        for (const [k, v] of this.windows) if (v.resetAt <= now) this.windows.delete(k);
      }
      return fresh;
    }
    entry.count += 1;
    return entry;
  }
}

export type BucketResult = { ok: true } | { ok: false; retryAfter: number };

/** A limit of `limit` hits per `windowMs`, counted in `store`. */
export function bucket(store: BucketStore, limit: number, windowMs: number) {
  return async (key: string): Promise<BucketResult> => {
    const { count, resetAt } = await store.hit(key, windowMs);
    if (count <= limit) return { ok: true };
    return { ok: false, retryAfter: Math.max(1, Math.ceil((resetAt - Date.now()) / 1000)) };
  };
}

/**
 * Express middleware over a bucket. Spec section 7.2.
 *
 * The key is a parameter because the right one differs by route:
 * credential-guessing surfaces are limited by address, but an authenticated
 * routine operation must not be, or everyone behind one NAT shares a quota.
 */
export function rateLimit(
  limit: number,
  windowMs: number,
  keyOf: (req: Request) => string = (req) => `${req.ip ?? 'unknown'}:${req.path}`,
  store: BucketStore = new MemoryBucketStore()
): RequestHandler {
  const take = bucket(store, limit, windowMs);
  return (req, res, next) => {
    take(keyOf(req)).then((result) => {
      if (result.ok) return next();
      res.setHeader('retry-after', String(result.retryAfter));
      next(new AppError('RATE_LIMITED'));
    }, next);
  };
}
