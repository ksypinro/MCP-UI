/**
 * Profile M as four real processes.
 *
 * Starts the authorization server, the MCP resource server, the API gateway
 * and the Device Service from their entry points, each with its own
 * certificate, sharing PostgreSQL and Redis, then drives an MCP client
 * through them. Needs TEST_DATABASE_URL and TEST_REDIS_URL (CI's PostgreSQL
 * leg sets both); skipped otherwise, because PGlite cannot be shared between
 * processes.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';

const DATABASE = process.env.TEST_DATABASE_URL;
const REDIS = process.env.TEST_REDIS_URL;
const skip = DATABASE && REDIS ? false : 'set TEST_DATABASE_URL and TEST_REDIS_URL to run profile M as processes';

const freePort = () => new Promise<number>((resolve) => {
  const server = createServer().listen(0, '127.0.0.1', () => {
    const { port } = server.address() as { port: number };
    server.close(() => resolve(port));
  });
});

let dir: string;
const children: ChildProcess[] = [];
const ports: Record<string, number> = {};

async function waitFor(url: string, init?: RequestInit): Promise<void> {
  for (let i = 0; i < 100; i++) {
    try {
      const response = await fetch(url, init);
      if (response.status < 500) return;
    } catch { /* not up yet */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${url} never came up`);
}

before(async () => {
  if (skip) return;
  dir = await mkdtemp(join(tmpdir(), 'iotsw-profile-m-'));
  const { makeProfileMCertificates } = await import('../tools/split/certs.ts');
  const certs = makeProfileMCertificates(dir);
  for (const name of ['as', 'internal', 'rs', 'gw', 'ds']) ports[name] = await freePort();

  const urls = {
    AUTH_BASE_URL: `http://localhost:${ports.as}`,
    MCP_BASE_URL: `http://localhost:${ports.rs}`,
    API_BASE_URL: `http://localhost:${ports.gw}`
  };
  // What the test process itself computes (resource URIs) must match.
  Object.assign(process.env, urls, { AUTH_RATE_LIMIT_PER_MINUTE: '100000', AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE: '100000' });

  const shared = {
    ...process.env, ...urls,
    DATABASE_URL: DATABASE!, DATABASE_SCHEMA: `m_${randomBytes(6).toString('hex')}`,
    REDIS_URL: REDIS!, REDIS_PREFIX: `iotsw-m:${randomBytes(6).toString('hex')}:`,
    TOKEN_PEPPERS: `1:${randomBytes(32).toString('base64')}`,
    PASSWORD_PEPPER: `1:${randomBytes(32).toString('base64')}`,
    INTERNAL_MAC_KEY: randomBytes(32).toString('base64'),
    TLS_CA: certs.ca.cert,
    AUTH_RATE_LIMIT_PER_MINUTE: '100000', AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE: '100000'
  };
  delete (shared as Record<string, unknown>).DATABASE_ISOLATION;
  const start = (entry: string, env: Record<string, string>) => {
    const child = spawn(process.execPath, [`src/entry/${entry}.ts`], { env: { ...shared, ...env }, stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr!.on('data', (chunk) => process.stderr.write(`[${entry}] ${chunk}`));
    children.push(child);
  };

  // The authorization server first: it creates the schema the others use.
  start('as', { PORT: String(ports.as), INTERNAL_PORT: String(ports.internal), TLS_CERT: certs.auth.cert, TLS_KEY: certs.auth.key });
  await waitFor(`${urls.AUTH_BASE_URL}/healthz`);
  start('ds', {
    PORT: String(ports.ds), TLS_CERT: certs['device-service'].cert, TLS_KEY: certs['device-service'].key,
    JWKS_URL: `${urls.AUTH_BASE_URL}/.well-known/jwks.json`
  });
  const edge = { AUTH_INTERNAL_URL: `https://localhost:${ports.internal}`, DEVICE_SERVICE_URL: `https://localhost:${ports.ds}` };
  start('rs', { ...edge, PORT: String(ports.rs), TLS_CERT: certs['mcp-rs'].cert, TLS_KEY: certs['mcp-rs'].key });
  start('gw', { ...edge, PORT: String(ports.gw), TLS_CERT: certs['api-gw'].cert, TLS_KEY: certs['api-gw'].key });
  await Promise.all([waitFor(`${urls.MCP_BASE_URL}/healthz`), waitFor(`${urls.API_BASE_URL}/healthz`)]);
});

after(async () => {
  for (const child of children) child.kill('SIGTERM');
  await Promise.all(children.map((child) => new Promise((resolve) => (child.exitCode !== null ? resolve(null) : child.once('exit', resolve)))));
  if (dir) await rm(dir, { recursive: true, force: true });
});

test('an MCP host signs a person in and controls a device through four processes', { skip }, async () => {
  const { tokenFor, callTool, structured } = await import('./mcp-helpers.ts');
  const as = { db: null as never, base: `http://localhost:${ports.as}`, close: async () => {} };
  const rs = `http://localhost:${ports.rs}`;

  const { accessToken } = await tokenFor(as);
  const added = await callTool(rs, 'add_device', { name: 'Four Process Lamp' }, accessToken);
  assert.equal(added.status, 200, JSON.stringify(added.body));
  const device = structured(added).device;
  const switched = await callTool(rs, 'control_device', { deviceId: device.id, state: 'on', expectedVersion: device.version }, accessToken);
  assert.equal(structured(switched).device.state, 'on');

  // Revoked at the authorization server, refused at the edge on the next
  // call: the event crossed processes over Redis.
  const revoke = await fetch(`http://localhost:${ports.as}/revoke`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: accessToken, client_id: 'unused' })
  });
  assert.ok(revoke.status < 500);
  let status = 0;
  for (let i = 0; i < 20; i++) {
    status = (await callTool(rs, 'list_devices', {}, accessToken)).status;
    if (status === 401) break;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(status, 401);
});
