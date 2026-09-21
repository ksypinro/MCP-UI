/**
 * The MCP server. Spec sections 7.5, 8.1, 8.2 and 8.3, and acceptance
 * criteria AC-12, AC-21, AC-22, AC-24 and AC-25.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { SCOPES } from '../src/oauth/config.ts';
import { startServer, type Harness } from './oauth-helpers.ts';
import {
  callTool, initialize, isToolError, rpc, structured, toolsList, tokenFor
} from './mcp-helpers.ts';

let h: Harness;
let token: string;

before(async () => {
  h = await startServer();
  token = (await tokenFor(h)).accessToken;
});
after(async () => { await h.close(); });

/* ------------------------------------------------- AC-12: anonymous access */

test('a host can initialize without a token', async () => {
  const response = await initialize(h.base);
  assert.equal(response.status, 200);
  assert.equal(response.body.result.serverInfo.name, 'iot-switch');
  assert.ok(response.body.result.capabilities.tools);
});

test('tool discovery works without a token and exposes no private data', async () => {
  const response = await toolsList(h.base);
  assert.equal(response.status, 200);

  const names = response.body.result.tools.map((tool: { name: string }) => tool.name).sort();
  assert.deepEqual(names, ['add_device', 'control_device', 'get_auth_status', 'get_device', 'list_devices']);

  // Discovery is public, so nothing in it may depend on who is asking.
  assert.doesNotMatch(JSON.stringify(response.body), /dev_|acc_|Bedroom/);
});

test('the public status tool reports signed out rather than failing', async () => {
  const response = await callTool(h.base, 'get_auth_status');
  assert.equal(response.status, 200);
  assert.equal(structured(response).authenticated, false);
  assert.equal(structured(response).username, undefined);
});

test('tools declare honest annotations and explicit visibility', async () => {
  const tools: any[] = (await toolsList(h.base)).body.result.tools;
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));

  assert.equal(byName.list_devices.annotations.readOnlyHint, true);
  assert.equal(byName.control_device.annotations.readOnlyHint, false);
  assert.equal(byName.control_device.annotations.destructiveHint, false);
  // Replaying either of these fails rather than repeating, so neither may
  // claim to be idempotent: a host may retry on that hint.
  assert.equal(byName.control_device.annotations.idempotentHint, false);
  assert.equal(byName.add_device.annotations.idempotentHint, false);

  assert.deepEqual(byName.get_auth_status._meta.ui.visibility, ['app']);
  assert.deepEqual(byName.list_devices._meta.ui.visibility, ['model', 'app']);
});

test('control_device tells a caller to read before writing', async () => {
  const tools: any[] = (await toolsList(h.base)).body.result.tools;
  const control = tools.find((tool) => tool.name === 'control_device');

  // A model with no current version must fetch one; the description is the
  // only place that can be said.
  assert.match(control.description, /expectedVersion/);
  assert.match(control.description, /get_device or list_devices/);
  assert.equal(control.inputSchema.properties.state.enum.join(','), 'on,off');
});

/* --------------------------------------------------- AC-24: the challenge */

test('an unauthenticated protected call is a transport 401, not a tool error', async () => {
  const response = await callTool(h.base, 'list_devices');

  // A 200 carrying isError is an application failure: the host hands the text
  // to the model and moves on, and no authentication prompt ever appears.
  assert.equal(response.status, 401, 'must be a transport-level refusal');
  assert.equal(response.body?.result, undefined, 'and not a JSON-RPC result');
});

test('the challenge carries everything a host needs to authorize', async () => {
  const response = await callTool(h.base, 'list_devices');
  const challenge = response.headers.get('www-authenticate') ?? '';

  assert.match(challenge, /^Bearer /);
  assert.match(challenge, /resource_metadata="[^"]*\/\.well-known\/oauth-protected-resource\/mcp"/);
  for (const scope of SCOPES) {
    assert.ok(challenge.includes(scope), `challenge omits ${scope}`);
  }
});

test('the metadata the challenge points at is actually served', async () => {
  const challenge = (await callTool(h.base, 'list_devices')).headers.get('www-authenticate') ?? '';
  const url = challenge.match(/resource_metadata="([^"]+)"/)?.[1];
  assert.ok(url);

  // The URL is absolute and built from BASE_URL, so follow only its path here.
  const metadata = await fetch(`${h.base}${new URL(url).pathname}`).then((r) => r.json()) as any;
  assert.ok(metadata.resource.endsWith('/mcp'));
  assert.ok(Array.isArray(metadata.authorization_servers));
});

test('an invalid token is challenged exactly like no token', async () => {
  const response = await callTool(h.base, 'list_devices', {}, 'not-a-real-token');
  assert.equal(response.status, 401);
  assert.match(response.headers.get('www-authenticate') ?? '', /Bearer /);
});

test('a batch containing a protected call is challenged as a whole', async () => {
  const response = await rpc(h.base, [
    { jsonrpc: '2.0', id: 900, method: 'tools/call', params: { name: 'get_auth_status', arguments: {} } },
    { jsonrpc: '2.0', id: 901, method: 'tools/call', params: { name: 'list_devices', arguments: {} } }
  ]);
  // Otherwise a protected call rides along beside a public one.
  assert.equal(response.status, 401);
});

test('a tool name that is only an inherited property is not treated as protected', async () => {
  // `in` on a plain object matches toString and constructor. Classifying those
  // as protected tools would answer 401 for a tool that does not exist.
  const response = await callTool(h.base, 'toString');
  assert.notEqual(response.status, 401);
});

/* ------------------------------------------------- AC-25: scope behaviour */

test('a read-only token gets 403 insufficient_scope naming every scope', async () => {
  const readOnly = (await tokenFor(h, { scope: 'devices:read' })).accessToken;

  const read = await callTool(h.base, 'list_devices', {}, readOnly);
  assert.equal(read.status, 200, 'a read-only token can still read');

  const write = await callTool(
    h.base, 'control_device', { deviceId: 'dev_x', state: 'on', expectedVersion: 1 }, readOnly
  );
  assert.equal(write.status, 403);
  const challenge = write.headers.get('www-authenticate') ?? '';
  assert.match(challenge, /error="insufficient_scope"/);
  // Re-consenting with only the missing scope would drop the ones already held.
  for (const scope of SCOPES) assert.ok(challenge.includes(scope));
});

test('a token minted for another resource is refused at the gate', async () => {
  const other = (await tokenFor(h)).accessToken;
  await h.db.query(`UPDATE oauth_access_tokens SET audience = 'https://elsewhere.example/mcp'`);

  const response = await callTool(h.base, 'list_devices', {}, other);
  assert.equal(response.status, 401, 'RFC 8707: valid elsewhere is not valid here');

  // Restore, since the harness shares one database across the file.
  await h.db.query(
    `UPDATE oauth_access_tokens SET audience = (SELECT resource FROM oauth_grants LIMIT 1)`
  );
});

/* ----------------------------------------------------- authorized calls */

test('the four device operations work over MCP', async () => {
  const mine = (await tokenFor(h)).accessToken;

  const empty = await callTool(h.base, 'list_devices', {}, mine);
  assert.deepEqual(structured(empty).devices, []);
  assert.match(empty.body.result.content[0].text, /no devices/i);

  const added = await callTool(h.base, 'add_device', { name: 'Bedroom Lamp' }, mine);
  const device = structured(added).device;
  assert.equal(device.state, 'off', 'new devices start Off');
  assert.equal(device.version, 1);

  const fetched = await callTool(h.base, 'get_device', { deviceId: device.id }, mine);
  assert.equal(structured(fetched).device.id, device.id);

  const on = await callTool(
    h.base, 'control_device', { deviceId: device.id, state: 'on', expectedVersion: 1 }, mine
  );
  assert.equal(structured(on).device.state, 'on');
  assert.equal(structured(on).device.version, 2, 'the version comes from the server');

  const listed = await callTool(h.base, 'list_devices', {}, mine);
  assert.equal(structured(listed).devices.length, 1);
});

test('a stale version is a tool error, not a transport error', async () => {
  const mine = (await tokenFor(h)).accessToken;
  const device = structured(await callTool(h.base, 'add_device', { name: 'Desk Fan' }, mine)).device;
  await callTool(h.base, 'control_device', { deviceId: device.id, state: 'on', expectedVersion: 1 }, mine);

  const stale = await callTool(
    h.base, 'control_device', { deviceId: device.id, state: 'off', expectedVersion: 1 }, mine
  );

  // A conflict is a normal outcome the model should see and act on. Only
  // authorization failures are transport errors, because only those carry a
  // challenge a host can do something with.
  assert.equal(stale.status, 200);
  assert.ok(isToolError(stale));
  assert.equal(structured(stale).error.code, 'DEVICE_VERSION_CONFLICT');
});

test('a duplicate name and an unknown device are predictable tool errors', async () => {
  const mine = (await tokenFor(h)).accessToken;
  await callTool(h.base, 'add_device', { name: 'Porch Light' }, mine);

  const duplicate = await callTool(h.base, 'add_device', { name: 'porch light' }, mine);
  assert.equal(structured(duplicate).error.code, 'DEVICE_NAME_CONFLICT');

  const missing = await callTool(h.base, 'get_device', { deviceId: 'dev_nope' }, mine);
  assert.equal(structured(missing).error.code, 'DEVICE_NOT_FOUND');
});

test('invalid arguments are rejected before the service sees them', async () => {
  const mine = (await tokenFor(h)).accessToken;
  const bad = await callTool(
    h.base, 'control_device', { deviceId: 'dev_x', state: 'dim', expectedVersion: 1 }, mine
  );
  assert.ok(bad.status === 200 ? isToolError(bad) || bad.body.error : true);
});

/* ---------------------------------------------------- AC-21: isolation */

test('one account cannot see or touch another account\'s devices', async () => {
  const alice = (await tokenFor(h)).accessToken;
  const bob = (await tokenFor(h)).accessToken;

  const hers = structured(await callTool(h.base, 'add_device', { name: 'Hall Light' }, alice)).device;

  assert.deepEqual(structured(await callTool(h.base, 'list_devices', {}, bob)).devices, []);

  const peek = await callTool(h.base, 'get_device', { deviceId: hers.id }, bob);
  assert.equal(structured(peek).error.code, 'DEVICE_NOT_FOUND',
    'another account\'s device is indistinguishable from one that does not exist');

  const grab = await callTool(
    h.base, 'control_device', { deviceId: hers.id, state: 'on', expectedVersion: 1 }, bob
  );
  assert.equal(structured(grab).error.code, 'DEVICE_NOT_FOUND');

  const untouched = await callTool(h.base, 'get_device', { deviceId: hers.id }, alice);
  assert.equal(structured(untouched).device.state, 'off');
});

/* ------------------------------------------- AC-22: one set of devices */

test('MCP and the REST API are the same devices, and the channel is recorded', async () => {
  const account = await tokenFor(h);

  // Sign in to the first-party API as the same person.
  const session = await fetch(`${h.base}/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: account.username, password: 'correct horse battery staple' })
  }).then((r) => r.json()) as any;

  const viaMcp = structured(
    await callTool(h.base, 'add_device', { name: 'Shared Lamp' }, account.accessToken)
  ).device;

  const viaRest = await fetch(`${h.base}/v1/devices`, {
    headers: { authorization: `Bearer ${session.accessToken}` }
  }).then((r) => r.json()) as any;

  assert.ok(
    viaRest.devices.some((device: { id: string }) => device.id === viaMcp.id),
    'a device added over MCP is the same device the app sees'
  );

  const audit = await h.db.query<{ channel: string }>(
    'SELECT channel FROM audit_events WHERE device_id = $1', [viaMcp.id]
  );
  assert.equal(audit.rows[0]?.channel, 'mcp', 'the originating channel is recorded');
});

/* ------------------------------------------------------------- transport */

test('only POST is accepted at the endpoint', async () => {
  const get = await fetch(`${h.base}/mcp`);
  assert.equal(get.status, 405);
  assert.equal(get.headers.get('allow'), 'POST');
});
