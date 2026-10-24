/**
 * Alerts raised in-process, as log lines at level "alert". Plan 4.8.
 *
 * The same conditions are written as Prometheus rules in ops/alerts.yml for a
 * deployment that scrapes the metrics; these exist so that a single process
 * with nothing scraping it still says, loudly, when one of them happens.
 *
 * - Refresh token theft: every occurrence. A legitimate client never does it.
 * - DPoP replay burst: more than DPOP_REPLAY_ALERT_PER_MINUTE replayed proofs
 *   in a minute (default 10). One is a retry bug; many is someone replaying.
 * - CIMD fetch aimed at a denied address range: every occurrence. Someone is
 *   probing whether this server will fetch internal URLs for them.
 */

import { log } from './log.ts';
import { metrics } from './metrics.ts';

const MINUTE = 60_000;

function raise(alert: string, fields: Record<string, unknown> = {}): void {
  metrics.inc('alerts_raised', { alert });
  log('alert', alert, { alert, ...fields });
}

let started = false;

export function startAlerts(): void {
  if (started) return;
  started = true;
  const replays: number[] = [];
  let lastReplayAlert = 0;

  metrics.onIncrement((name, labels) => {
    if (name === 'refresh_theft_detected') raise('refresh_token_theft');
    if (name === 'cimd_fetch' && labels.result === 'denied_range') raise('cimd_denied_range');
    if (name === 'dpop_rejected' && labels.reason === 'replay') {
      const now = Date.now();
      replays.push(now);
      while (replays.length > 0 && replays[0]! <= now - MINUTE) replays.shift();
      const limit = Number(process.env.DPOP_REPLAY_ALERT_PER_MINUTE ?? 10);
      if (replays.length > limit && now - lastReplayAlert > MINUTE) {
        lastReplayAlert = now;
        raise('dpop_replay_burst', { count: replays.length, windowSeconds: 60, limit });
      }
    }
  });
}
