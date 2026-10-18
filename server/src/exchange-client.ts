/**
 * How an edge adapter obtains internal tokens: exchange once, reuse while
 * the token has more than ten seconds left, forget it the moment its grant is
 * revoked. Plan 2.5.
 *
 * One client per adapter, holding that adapter's workload. The cache lives
 * in memory only and is keyed by grant and scope, so two people never share
 * an entry and one scope never stands in for another.
 */

import type { Db } from './db/index.ts';
import { AppError } from './errors.ts';
import { exchangeToken } from './oauth/exchange.ts';
import type { Scope } from './oauth/config.ts';
import { onGrantRevoked } from './revocation.ts';
import type { Workload } from './security/workload.ts';
import type { VerifiedCaller } from './domain/types.ts';
import { InternalTokenRefused } from './device-service/verify.ts';

const REUSE_MARGIN_MS = 10_000;

export class ExchangeClient {
  readonly workload: Workload;
  private readonly db: Db;
  private readonly cache = new Map<string, { token: string; expiresAt: number }>();

  constructor(db: Db, workload: Workload) {
    this.db = db;
    this.workload = workload;
    onGrantRevoked((grantId) => {
      for (const key of this.cache.keys()) if (key.startsWith(`${grantId}\u0000`)) this.cache.delete(key);
    });
  }

  /** Cached entries, for tests. */
  get size(): number {
    return this.cache.size;
  }

  async tokenFor(caller: VerifiedCaller, scope: Scope): Promise<string> {
    const key = `${caller.grantId}\u0000${scope}`;
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt - Date.now() > REUSE_MARGIN_MS) return cached.token;

    const exchanged = await exchangeToken(this.db, { workload: this.workload, subjectToken: caller.credential, scope });
    this.cache.set(key, { token: exchanged.token, expiresAt: Date.now() + exchanged.expiresIn * 1000 });
    return exchanged.token;
  }

  private forget(caller: VerifiedCaller, scope: Scope): void {
    this.cache.delete(`${caller.grantId}\u0000${scope}`);
  }

  /**
   * Runs `call` with an internal token for `scope`. If the Device Service
   * refuses the token — a key rotated, or it expired in flight — the token is
   * exchanged afresh and the call retried once. A second refusal is a fault
   * in this server, not in the caller, and is reported as one.
   */
  async run<T>(caller: VerifiedCaller, scope: Scope, call: (token: string, peer: Workload) => Promise<T>): Promise<T> {
    try {
      return await call(await this.tokenFor(caller, scope), this.workload);
    } catch (error) {
      if (!(error instanceof InternalTokenRefused)) throw error;
      this.forget(caller, scope);
      try {
        return await call(await this.tokenFor(caller, scope), this.workload);
      } catch (retryError) {
        if (retryError instanceof InternalTokenRefused) {
          process.stderr.write(`[exchange] ${caller.requestId} ${retryError.message}\n`);
          throw new AppError('INTERNAL_ERROR');
        }
        throw retryError;
      }
    }
  }
}
