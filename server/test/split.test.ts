/**
 * Profile M: the components apart, talking over mutual TLS. Plan 4.7.
 *
 * The authorization server's internal listener and the Device Service run on
 * real TLS sockets with certificates from a test CA; the MCP resource server
 * and the API gateway are built with the remote clients, exactly as their
 * entry points build them. They share one database here only because PGlite
 * cannot be shared between processes; the four-process run against
 * PostgreSQL is test/split-processes.test.ts.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { createServer, type Server } from 'node:http';
import { decodeJwt } from 'jose';
import { createDb, type Db } from '../src/db/index.ts';
import { apiRouter, authServerRouter, baseApp, finishApp, type EdgeDeps } from '../src/http/app.ts';
import { mcpRoutes } from '../src/mcp/routes.ts';
import { memoryInfrastructure } from '../src/stores/index.ts';
import { ExchangeClient } from '../src/exchange-client.ts';
import { WriteBudgets } from '../src/write-budgets.ts';
import { deviceServiceApp, internalAuthApp } from '../src/split/servers.ts';
import { mtlsAgent, mtlsServer, ownWorkload, postJson, type TlsFiles } from '../src/split/tls.ts';
import { remoteDeviceService, remoteExchanger, remoteVerifier } from '../src/split/remote.ts';
import { useJwksUrl } from '../src/device-service/verify.ts';
import { establishGrant, revokeGrantNow } from '../src/oauth/store.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { API_RESOURCE, FIRST_PARTY_CLIENT_ID } from '../src/oauth/config.ts';
import type { WorkloadName } from '../src/security/workload.ts';
import { issue, makeCa, makeProfileMCertificates } from '../tools/split/certs.ts';
import { callTool, structured, tokenFor } from './mcp-helpers.ts';
import type { Harness } from './oauth-helpers.ts';

let dir: string;
let db: Db;
let as: Harness;
const servers: Array<{ close(cb?: () => void): unknown }> = [];
const files: Record<string, TlsFiles> = {};
let internalUrl: string;
let deviceUrl: string;
let rsBase: string;
let gwBase: string;

async function tlsFiles(issued: { cert: string; key: string }, ca: string): Promise<TlsFiles> {
  return { cert: await readFile(issued.cert), key: await readFile(issued.key), ca: await readFile(ca) };
}

async function listen(server: Server | ReturnType<typeof mtlsServer>): Promise<number> {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(null)));
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

function edge(name: WorkloadName): EdgeDeps {
  const agent = mtlsAgent(files[name]!);
  const infra = memoryInfrastructure();
  return {
    infra,
    verifier: remoteVerifier(internalUrl, agent, infra.revocations),
    exchange: new ExchangeClient(ownWorkload(files[name]!, name), remoteExchanger(internalUrl, agent), infra.revocations),
    devices: remoteDeviceService(deviceUrl, agent),
    budgets: new WriteBudgets(infra.buckets)
  };
}

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'iotsw-split-'));
  const certs = makeProfileMCertificates(dir);
  for (const name of ['auth', 'device-service', 'mcp-rs', 'api-gw'] as const) files[name] = await tlsFiles(certs[name], certs.ca.cert);
  // Attackers' certificates: an unknown workload from our CA, a real
  // workload name from another CA, and one claiming two identities.
  files.rogue = await tlsFiles(issue(dir, certs.ca, 'rogue', ['spiffe://iot-switch/rogue']), certs.ca.cert);
  const otherCa = makeCa(join(dir, 'other'), 'other');
  files.foreign = { ...await tlsFiles(issue(join(dir, 'other'), otherCa, 'mcp-rs', ['spiffe://iot-switch/mcp-rs']), otherCa.cert), ca: await readFile(certs.ca.cert) };
  files.twoFaced = await tlsFiles(issue(dir, certs.ca, 'two', ['spiffe://iot-switch/mcp-rs', 'spiffe://iot-switch/api-gw']), certs.ca.cert);

  process.env.AUTH_RATE_LIMIT_PER_MINUTE = '100000';
  process.env.AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE = '100000';
  db = await createDb();

  // The authorization server's public side, for signing people in.
  const publicApp = baseApp();
  publicApp.use(authServerRouter(db, memoryInfrastructure()));
  const asPort = await listen(createServer(finishApp(publicApp)));
  as = { db, base: `http://127.0.0.1:${asPort}`, close: async () => {} };

  internalUrl = `https://localhost:${await listen(mtlsServer(files.auth!, internalAuthApp(db)))}`;
  // The Device Service verifies with the published keys, as in its own process.
  useJwksUrl(`${as.base}/.well-known/jwks.json`);
  deviceUrl = `https://localhost:${await listen(mtlsServer(files['device-service']!, deviceServiceApp(db)))}`;

  const rs = baseApp();
  rs.use(mcpRoutes(edge('mcp-rs')));
  rsBase = `http://127.0.0.1:${await listen(createServer(finishApp(rs)))}`;

  const gw = baseApp();
  gw.use(apiRouter(edge('api-gw'), null));
  gwBase = `http://127.0.0.1:${await listen(createServer(finishApp(gw)))}`;
});

after(async () => {
  for (const server of servers) await new Promise((resolve) => server.close(() => resolve(null)));
  await db.close();
  await rm(dir, { recursive: true, force: true });
});

test('an MCP call goes edge → introspection → exchange → Device Service, all over mTLS', async () => {
  const { accessToken } = await tokenFor(as);
  const added = await callTool(rsBase, 'add_device', { name: 'Split Lamp' }, accessToken);
  assert.equal(added.status, 200, JSON.stringify(added.body));
  const device = structured(added).device;
  const switched = await callTool(rsBase, 'control_device', { deviceId: device.id, state: 'on', expectedVersion: device.version }, accessToken);
  assert.equal(structured(switched).device.state, 'on');
  assert.equal(structured(await callTool(rsBase, 'list_devices', {}, accessToken)).devices.length, 1);

  const { rows } = await db.query<{ via: string }>(
    'SELECT via FROM audit_events WHERE device_id = $1 ORDER BY id DESC LIMIT 1', [device.id]
  );
  assert.equal(rows[0]?.via, 'spiffe://iot-switch/mcp-rs', 'the audit names the workload that called');
});

test('the gateway serves the app with no database of its own, and the password endpoints are gone', async () => {
  const { accessToken: hostToken } = await tokenFor(as);
  const verified = await verifyOAuthAccessToken(db, hostToken);
  assert.ok(verified.ok);
  const app = await establishGrant(db, {
    code: 'none', accountId: verified.accountId, clientId: FIRST_PARTY_CLIENT_ID, resource: API_RESOURCE,
    scope: 'devices:read devices:control devices:create', withRefresh: false, dpopJkt: null
  });
  const auth = { authorization: `Bearer ${app.accessToken}` };

  const list = await fetch(`${gwBase}/v1/devices`, { headers: auth });
  assert.equal(list.status, 200);
  const me = await fetch(`${gwBase}/v1/auth/me`, { headers: auth });
  assert.equal(me.status, 200);
  assert.equal((await me.json() as any).account.id, verified.accountId);

  const login = await fetch(`${gwBase}/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(login.status, 410);
  const wrongDoor = await fetch(`${gwBase}/v1/devices`, { headers: { authorization: `Bearer ${hostToken}` } });
  assert.equal(wrongDoor.status, 401, 'an MCP token is not introspected for the gateway');
});

test('the Device Service refuses a valid internal token over another workload\'s certificate', async () => {
  const { accessToken } = await tokenFor(as);
  const mcpAgent = mtlsAgent(files['mcp-rs']!);
  const exchanged = await postJson(mcpAgent, `${internalUrl}/token-exchange`, { subject_token: accessToken, scope: 'devices:read' });
  assert.equal(exchanged.status, 200);
  const tokenB = exchanged.body.access_token as string;
  assert.ok((decodeJwt(tokenB) as any).cnf['x5t#S256'], 'bound to a certificate, not a per-process value');

  const own = await postJson(mcpAgent, `${deviceUrl}/devices/list`, {}, { authorization: `Bearer ${tokenB}` });
  assert.equal(own.status, 200, 'over the certificate it was issued to');

  const stolen = await postJson(mtlsAgent(files['api-gw']!), `${deviceUrl}/devices/list`, {}, { authorization: `Bearer ${tokenB}` });
  assert.equal(stolen.status, 401);
  assert.equal(stolen.body.error, 'internal_token_refused');
});

test('peers outside the allowlist are refused, and a foreign CA cannot even connect', async () => {
  for (const name of ['rogue', 'twoFaced']) {
    const agent = mtlsAgent(files[name]!);
    assert.equal((await postJson(agent, `${internalUrl}/introspect`, { token: 'x' })).status, 403, name);
    assert.equal((await postJson(agent, `${deviceUrl}/devices/list`, {})).status, 403, name);
  }
  await assert.rejects(postJson(mtlsAgent(files.foreign!), `${deviceUrl}/devices/list`, {}), 'TLS refuses another CA');
  // A server certificate is checked too: the auth server's is not the Device Service's host.
  await assert.rejects(postJson(mtlsAgent({ ...files['mcp-rs']!, ca: files.foreign!.cert }), `${internalUrl}/introspect`, {}));
});

test('each edge may introspect only tokens for its own resource', async () => {
  const { accessToken } = await tokenFor(as);
  const fromGateway = await postJson(mtlsAgent(files['api-gw']!), `${internalUrl}/introspect`, { token: accessToken });
  assert.deepEqual(fromGateway.body, { active: false });
  const fromMcp = await postJson(mtlsAgent(files['mcp-rs']!), `${internalUrl}/introspect`, { token: accessToken });
  assert.equal(fromMcp.body.active, true);
});

test('a revocation empties the edge\'s introspection cache at once', async () => {
  const { accessToken } = await tokenFor(as);
  assert.equal((await callTool(rsBase, 'list_devices', {}, accessToken)).status, 200, 'now cached at the edge');
  const verified = await verifyOAuthAccessToken(db, accessToken);
  assert.ok(verified.ok);
  // In one test process the edge hears the authorization server's hub
  // directly; across processes the Redis bridge carries the same event.
  await revokeGrantNow(db, verified.grantId);
  assert.equal((await callTool(rsBase, 'list_devices', {}, accessToken)).status, 401, 'refused on the next call, not after the cache expires');
});

test('an unreachable authorization server is a 503 at the edge, never a pass', async () => {
  const deps = edge('mcp-rs');
  const dead = { ...deps, verifier: remoteVerifier('https://localhost:1', mtlsAgent(files['mcp-rs']!), deps.infra.revocations) };
  const rs = baseApp();
  rs.use(mcpRoutes(dead));
  const base = `http://127.0.0.1:${await listen(createServer(finishApp(rs)))}`;
  const { accessToken } = await tokenFor(as);
  const response = await callTool(base, 'list_devices', {}, accessToken);
  assert.equal(response.status, 503);
});
