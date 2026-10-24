/**
 * How an edge adapter obtains internal tokens: exchange once, reuse while
 * the token has more than ten seconds left, forget it the moment its grant is
 * revoked.
 *
 * One client per adapter, holding that adapter's workload. The cache lives
 * in memory only and is keyed by grant and scope, so two people never share
 * an entry and one scope never stands in for another. Each entry remembers
 * its account and client too, so revoking either drops it.
 */

import type { Db } from './db/index.ts';
import { AppError } from './errors.ts';
import { exchangeToken } from './oauth/exchange.ts';
import type { Scope } from './oauth/config.ts';
import { processRevocations, type RevocationEvent, type RevocationHub } from './revocation.ts';
import type { Workload } from './security/workload.ts';
import type { VerifiedCaller } from './domain/types.ts';
import { InternalTokenRefused } from './device-service/verify.ts';
import { metrics } from './observability/metrics.ts';
import { log } from './observability/log.ts';

const REUSE_MARGIN_MS = 10_000;

interface CacheEntry {
  token: string; expiresAt: number; grantId: string; accountId: string; clientId: string;
}

function revokes(event: RevocationEvent, entry: CacheEntry): boolean {
  switch (event.type) {
    case 'grant.revoked': return entry.grantId === event.grantId;
    case 'account.revoked': return entry.accountId === event.accountId;
    case 'client.blocked': return entry.clientId === event.clientId;
  }
}

/**
 * Trades a caller's token for an internal one. In one process this calls the
 * exchange directly; split into processes it is a request to the
 * authorization server over mTLS (split/remote.ts).
 */
export type Exchanger = (subjectToken: string, scope: Scope) => Promise<{ token: string; expiresIn: number }>;

export class ExchangeClient {
  readonly workload: Workload;
  private readonly exchanger: Exchanger;
  private readonly cache = new Map<string, CacheEntry>();

  /** An exchange client in this process, exchanging against `db` directly. */
  static local(db: Db, workload: Workload, revocations: RevocationHub = processRevocations): ExchangeClient {
    return new ExchangeClient(workload, (subjectToken, scope) => exchangeToken(db, { workload, subjectToken, scope }), revocations);
  }

  constructor(workload: Workload, exchanger: Exchanger, revocations: RevocationHub = processRevocations) {
    this.exchanger = exchanger;
    this.workload = workload;
    revocations.subscribe((event) => {
      for (const [key, entry] of this.cache) if (revokes(event, entry)) this.cache.delete(key);
    });
  }

  /** Cached entries, for tests. */
  get size(): number {
    return this.cache.size;
  }

  async tokenFor(caller: VerifiedCaller, scope: Scope): Promise<string> {
    const key = `${caller.grantId}\u0000${scope}`;
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt - Date.now() > REUSE_MARGIN_MS) {
      metrics.inc('exchange_cache', { result: 'hit' });
      return cached.token;
    }
    metrics.inc('exchange_cache', { result: 'miss' });

    const exchanged = await this.exchanger(caller.credential, scope);
    this.cache.set(key, {
      token: exchanged.token, expiresAt: Date.now() + exchanged.expiresIn * 1000,
      grantId: caller.grantId, accountId: caller.accountId, clientId: caller.clientId
    });
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
          log('error', 'internal_token_refused_twice', { requestId: caller.requestId, detail: retryError.message });
          throw new AppError('INTERNAL_ERROR');
        }
        throw retryError;
      }
    }
  }
}
