/**
 * Load test for the phase 4 exit review: the tool-call and refresh paths.
 *
 *   npm start                       # with DATABASE_URL and REDIS_URL for the real thing
 *   npm run load -- [base] [users] [seconds]
 *
 * Signs in `users` virtual hosts (default 20) against the server at `base`
 * (default http://localhost:4000), each with its own account and device,
 * then for `seconds` (default 30) each one loops: list devices, switch its
 * device, and every tenth round refresh its token, as a host would. Reports
 * throughput, latency percentiles and every non-success by status.
 *
 * Raise AUTH_RATE_LIMIT_PER_MINUTE and AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE on
 * the server first: signing in many users from one address is exactly what
 * those limits stop.
 */

import { randomBytes } from 'node:crypto';
import { authorizeAs, exchange, json } from '../../test/oauth-helpers.ts';
import { callTool } from '../../test/mcp-helpers.ts';

const base = process.argv[2] ?? 'http://localhost:4000';
const users = Number(process.argv[3] ?? 20);
const seconds = Number(process.argv[4] ?? 30);

interface Sample { kind: string; ms: number; status: number }
const samples: Sample[] = [];

async function timed<T extends { status: number }>(kind: string, run: () => Promise<T>): Promise<T> {
  const started = performance.now();
  const result = await run();
  samples.push({ kind, ms: performance.now() - started, status: result.status });
  return result;
}

async function virtualHost(index: number, until: number): Promise<void> {
  const authorization = await authorizeAs(base, { username: `load${randomBytes(4).toString('hex')}${index}` });
  let tokens = (await exchange(base, authorization)).body as Record<string, string>;
  const created = await callTool(base, 'add_device', { name: `Load Lamp ${index}` }, tokens.access_token);
  let device = created.body?.result?.structuredContent?.device;
  for (let round = 0; Date.now() < until; round++) {
    await timed('list_devices', () => callTool(base, 'list_devices', {}, tokens.access_token));
    if (device) {
      const switched = await timed('control_device', () => callTool(base, 'control_device', {
        deviceId: device.id, state: device.state === 'on' ? 'off' : 'on', expectedVersion: device.version
      }, tokens.access_token));
      device = switched.body?.result?.structuredContent?.device ?? device;
    }
    if (round % 10 === 9) {
      const refreshed = await timed('refresh', async () => {
        const response = await fetch(`${base}/token`, json({
          grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: authorization.clientId
        }));
        return { status: response.status, body: await response.json() as Record<string, string> };
      });
      if (refreshed.status === 200) tokens = refreshed.body;
    }
  }
}

const percentile = (values: number[], p: number) => values[Math.min(values.length - 1, Math.floor((p / 100) * values.length))] ?? 0;

process.stdout.write(`signing in ${users} hosts at ${base}…\n`);
const until = Date.now() + seconds * 1000 + 15_000;
const started = Date.now();
await Promise.all(Array.from({ length: users }, (_, i) => virtualHost(i, until)));
const elapsed = (Date.now() - started) / 1000;

process.stdout.write(`\n${samples.length} requests in ${elapsed.toFixed(1)} s, ${(samples.length / elapsed).toFixed(1)} per second\n\n`);
for (const kind of [...new Set(samples.map((sample) => sample.kind))]) {
  const of = samples.filter((sample) => sample.kind === kind);
  const ms = of.map((sample) => sample.ms).sort((a, b) => a - b);
  const failures = of.filter((sample) => sample.status !== 200);
  const byStatus = Object.entries(Object.groupBy(failures, (sample) => String(sample.status))).map(([s, list]) => `${s}×${list!.length}`).join(' ');
  process.stdout.write(`  ${kind.padEnd(15)} n=${String(of.length).padEnd(6)} p50 ${percentile(ms, 50).toFixed(0)} ms  p95 ${percentile(ms, 95).toFixed(0)} ms  p99 ${percentile(ms, 99).toFixed(0)} ms  ${failures.length ? `failures ${byStatus}` : 'no failures'}\n`);
}
