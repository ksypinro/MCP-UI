/**
 * Security metrics, in the Prometheus text format.
 *
 * Counters only, labelled, per process: a scraper sums across processes.
 * Exposed by the entry point on a separate, internal listener (METRICS_PORT),
 * never on a public host.
 *
 * Each counter answers a question an operator will ask during an incident:
 * are refresh tokens being stolen (refresh_theft_detected), is someone
 * replaying DPoP proofs (dpop_rejected{reason="replay"}), is the CIMD fetcher
 * being aimed at internal addresses (cimd_fetch{result="denied_range"}), is a
 * runaway agent hitting the write budgets (budget_exhausted).
 */

type Labels = Record<string, string>;

const HELP: Record<string, string> = {
  refresh_rotated: 'Refresh tokens rotated.',
  refresh_grace_replay: 'Duplicate refreshes inside the grace window, answered with the sealed response.',
  refresh_theft_detected: 'Rotated refresh tokens presented again outside the window; the grant was revoked.',
  dpop_rejected: 'DPoP proofs refused, by reason.',
  challenge_issued: 'Authorization challenges sent at the MCP endpoint, by status.',
  exchange_cache: 'Internal-token cache lookups, by result.',
  budget_exhausted: 'Writes over a write budget, by tool and mode.',
  cimd_fetch: 'Client metadata document fetches, by result.',
  log_secrets_redacted: 'Token-shaped strings removed from log lines.',
  log_fields_dropped: 'Log fields dropped because they are not on the allowlist.',
  alerts_raised: 'Alerts raised, by alert.'
};

type Listener = (name: string, labels: Labels) => void;

class Registry {
  private readonly counters = new Map<string, Map<string, number>>();
  private readonly listeners = new Set<Listener>();

  inc(name: string, labels: Labels = {}, by = 1): void {
    const key = JSON.stringify(Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)));
    const series = this.counters.get(name) ?? new Map<string, number>();
    series.set(key, (series.get(key) ?? 0) + by);
    this.counters.set(name, series);
    for (const listener of this.listeners) listener(name, labels);
  }

  /** The current value of one series, for tests. */
  value(name: string, labels: Labels = {}): number {
    const key = JSON.stringify(Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)));
    return this.counters.get(name)?.get(key) ?? 0;
  }

  onIncrement(listener: Listener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Prometheus text exposition format. */
  render(): string {
    const lines: string[] = [];
    for (const [name, series] of [...this.counters].sort(([a], [b]) => a.localeCompare(b))) {
      const metric = `iotsw_${name}_total`;
      if (HELP[name]) lines.push(`# HELP ${metric} ${HELP[name]}`);
      lines.push(`# TYPE ${metric} counter`);
      for (const [key, count] of series) {
        const labels = (JSON.parse(key) as Array<[string, string]>)
          .map(([k, v]) => `${k}="${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`).join(',');
        lines.push(`${metric}${labels ? `{${labels}}` : ''} ${count}`);
      }
    }
    // The exchange cache hit ratio, derived, so a dashboard needs no query for it.
    const hits = this.value('exchange_cache', { result: 'hit' });
    const misses = this.value('exchange_cache', { result: 'miss' });
    if (hits + misses > 0) {
      lines.push('# HELP iotsw_exchange_cache_hit_ratio Share of internal-token lookups served from cache.');
      lines.push('# TYPE iotsw_exchange_cache_hit_ratio gauge');
      lines.push(`iotsw_exchange_cache_hit_ratio ${(hits / (hits + misses)).toFixed(4)}`);
    }
    return `${lines.join('\n')}\n`;
  }
}

export const metrics = new Registry();
