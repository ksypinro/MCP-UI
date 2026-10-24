/**
 * Write budgets: a hard ceiling on how fast any one grant can change things.
 * Architecture section 8.6.
 *
 * Host approval of a write is a MAY in the MCP Apps specification, and a
 * person who clicked "always allow" has stopped looking. So the server keeps
 * its own deterministic limit. A model steered by a hostile device name into
 * flapping a switch, or into adding hundreds of devices, runs into it whatever
 * the host's settings say. Budgets are per grant, so one host's runaway agent
 * cannot spend the iOS app's allowance; the per-device limit holds across
 * grants, because the device is what is being flapped.
 *
 * Enforced by default. WRITE_BUDGETS=report logs what would have been
 * refused and allows it, for measuring real usage against a changed limit.
 */

import { MemoryBucketStore, bucket, type BucketResult, type BucketStore } from './security/rate-limit.ts';
import { metrics } from './observability/metrics.ts';
import { log } from './observability/log.ts';

export type WriteKind = 'control' | 'create';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

export class WriteBudgets {
  private readonly controlPerGrant: (key: string) => Promise<BucketResult>;
  private readonly controlPerDevice: (key: string) => Promise<BucketResult>;
  private readonly createPerGrant: (key: string) => Promise<BucketResult>;

  constructor(store: BucketStore = new MemoryBucketStore()) {
    this.controlPerGrant = bucket(store, 20, MINUTE);
    this.controlPerDevice = bucket(store, 6, MINUTE);
    this.createPerGrant = bucket(store, 10, HOUR);
  }

  /**
   * Counts one write against the budgets it falls under. In report mode an
   * over-budget write is logged and allowed.
   */
  async spend(kind: WriteKind, grantId: string, deviceId?: string): Promise<BucketResult> {
    const results = kind === 'control'
      ? [
          await this.controlPerGrant(`control-grant:${grantId}`),
          ...(deviceId ? [await this.controlPerDevice(`control-device:${deviceId}`)] : [])
        ]
      : [await this.createPerGrant(`create-grant:${grantId}`)];

    const refused = results.find((result) => !result.ok);
    if (!refused) return { ok: true };
    const tool = kind === 'control' ? 'control_device' : 'add_device';
    const enforcing = process.env.WRITE_BUDGETS !== 'report';
    metrics.inc('budget_exhausted', { tool, mode: enforcing ? 'enforce' : 'report' });
    if (!enforcing) {
      log('warn', 'write_budget_exceeded', { tool, grantId, reason: 'report-only: allowed' });
      return { ok: true };
    }
    return refused;
  }
}
