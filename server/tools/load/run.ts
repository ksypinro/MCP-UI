/**
 * Load test for the phase 4 exit review: the tool-call and refresh paths.
 *
 *   npm start                       # with DATABASE_URL and REDIS_URL for the real thing
 *   npm run load -- [base] [users] [seconds] [requests per second per user]
 *
 * Signs in `users` virtual hosts (default 20) against the server at `base`
 * (default http://localhost:4000), each with its own account and device,
 * then for `seconds` (default 30) each one loops, at `rate` requests a second
 * (default 4): list devices, switch its device, and every tenth round refresh
 * its token, as a host would. The pace matters: the MCP endpoint allows 600
 * requests a minute per grant, so an unpaced loop measures the rate limiter,
 * not the service. Reports throughput, latency percentiles, rate-limited
 * answers, and every other non-success by status.
 *
 * LOAD_TIMELINE=<seconds> also prints status counts per interval, for the
 * failover drill: stop Redis or PostgreSQL mid-run and watch what the server
 * answers while it is gone and after it returns.
 *
 * For profile M, where the MCP endpoint is its own host, set LOAD_MCP_URL to
 * it; `base` stays the authorization server.
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
const rate = Number(process.argv[5] ?? 4);
const mcp = process.env.LOAD_MCP_URL ?? base;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface Sample { kind: string; ms: number; status: number; at: number }
const samples: Sample[] = [];

async function timed<T extends { status: number }>(kind: string, run: () => Promise<T>): Promise<T> {
  const started = performance.now();
  const result = await run();
  samples.push({ kind, ms: performance.now() - started, status: result.status, at: Date.now() });
  return result;
}

async function virtualHost(index: number, authorization: Awaited<ReturnType<typeof authorizeAs>>, deadline: () => number): Promise<void> {
  let tokens = (await exchange(base, authorization)).body as Record<string, string>;
  const created = await callTool(mcp, 'add_device', { name: `Load Lamp ${index}` }, tokens.access_token);
  let device = created.body?.result?.structuredContent?.device;
  // Two requests a round; spread the rounds so each user averages `rate`.
  const roundMs = 2000 / rate;
  await sleep(Math.random() * roundMs);
  for (let round = 0; Date.now() < deadline(); round++) {
    const roundStarted = Date.now();
    await timed('list_devices', () => callTool(mcp, 'list_devices', {}, tokens.access_token));
    if (device) {
      const switched = await timed('control_device', () => callTool(mcp, 'control_device', {
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
    await sleep(Math.max(0, roundMs - (Date.now() - roundStarted)));
  }
}

const percentile = (values: number[], p: number) => values[Math.min(values.length - 1, Math.floor((p / 100) * values.length))] ?? 0;

process.stdout.write(`signing in ${users} hosts at ${base}, then ${rate} requests a second each for ${seconds} s…\n`);
// Every host signs in first, so the measured window is steady state only.
const ready: Array<() => void> = [];
const allIn = Promise.all(Array.from({ length: users }, () => new Promise<void>((resolve) => ready.push(resolve))));
let until = Number.POSITIVE_INFINITY;
let started = 0;
const hosts = Array.from({ length: users }, async (_, i) => {
  const authorization = await authorizeAs(base, { username: `load${randomBytes(4).toString('hex')}${i}` });
  ready[i]!();
  await allIn;
  return virtualHost(i, authorization, () => until);
});
await allIn;
started = Date.now();
until = started + seconds * 1000;
await Promise.all(hosts);
const elapsed = (Date.now() - started) / 1000;

process.stdout.write(`\n${samples.length} requests in ${elapsed.toFixed(1)} s, ${(samples.length / elapsed).toFixed(1)} per second\n\n`);
for (const kind of [...new Set(samples.map((sample) => sample.kind))]) {
  const of = samples.filter((sample) => sample.kind === kind);
  const ms = of.map((sample) => sample.ms).sort((a, b) => a - b);
  const limited = of.filter((sample) => sample.status === 429).length;
  const failures = of.filter((sample) => sample.status !== 200 && sample.status !== 429);
  const byStatus = Object.entries(Object.groupBy(failures, (sample) => String(sample.status))).map(([s, list]) => `${s}×${list!.length}`).join(' ');
  process.stdout.write(`  ${kind.padEnd(15)} n=${String(of.length).padEnd(6)} p50 ${percentile(ms, 50).toFixed(0)} ms  p95 ${percentile(ms, 95).toFixed(0)} ms  p99 ${percentile(ms, 99).toFixed(0)} ms  ${limited ? `rate-limited ${limited}  ` : ''}${failures.length ? `failures ${byStatus}` : 'no failures'}\n`);
}

const interval = Number(process.env.LOAD_TIMELINE ?? 0);
if (interval > 0) {
  process.stdout.write(`\ntimeline, ${interval} s intervals\n`);
  for (let from = started; from < started + elapsed * 1000; from += interval * 1000) {
    const window = samples.filter((sample) => sample.at >= from && sample.at < from + interval * 1000);
    const counts = Object.entries(Object.groupBy(window, (sample) => String(sample.status)))
      .sort(([a], [b]) => a.localeCompare(b)).map(([status, list]) => `${status}×${list!.length}`).join('  ');
    process.stdout.write(`  ${String(Math.round((from - started) / 1000)).padStart(4)} s  ${counts || '(none)'}\n`);
  }
}
