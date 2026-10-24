/**
 * The tool policy table and write budgets.
 */

import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { TOOL_POLICY } from '../src/mcp/policy.ts';
import { createAccount } from '../src/domain/accounts.ts';
import { startServer, type Harness } from './oauth-helpers.ts';
import { appClientFor } from './app-helpers.ts';
import { callTool, errorCode, nextId, rpc, structured, tokenFor } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });
afterEach(() => { delete process.env.WRITE_BUDGETS; });

test('every registered tool has a policy, and every policy a tool', async () => {
  const listed = await rpc(h.base, { jsonrpc: '2.0', id: nextId(), method: 'tools/list' });
  const names = (listed.body.result.tools as Array<{ name: string; annotations: unknown }>).map((tool) => tool.name).sort();
  assert.deepEqual(names, Object.keys(TOOL_POLICY).sort());
  for (const tool of listed.body.result.tools as Array<{ name: string; annotations: unknown }>) {
    assert.deepEqual(tool.annotations, TOOL_POLICY[tool.name]!.annotations, `${tool.name} annotations come from the table`);
  }
});

async function deviceFor(token: string, name = `Lamp ${nextId()}`) {
  return structured(await callTool(h.base, 'add_device', { name }, token)).device as { id: string; version: number };
}

async function flip(token: string, device: { id: string; version: number }, times: number) {
  const codes: (string | undefined)[] = [];
  let version = device.version;
  for (let index = 0; index < times; index++) {
    const response = await callTool(h.base, 'control_device', {
      deviceId: device.id, state: index % 2 === 0 ? 'on' : 'off', expectedVersion: version
    }, token);
    const changed = structured(response)?.device;
    if (changed) version = changed.version;
    codes.push(errorCode(response));
  }
  return codes;
}

test('switching one device more than six times a minute is refused', async () => {
  const { accessToken } = await tokenFor(h);
  const device = await deviceFor(accessToken);
  const codes = await flip(accessToken, device, 7);
  assert.deepEqual(codes.slice(0, 6), [undefined, undefined, undefined, undefined, undefined, undefined]);
  assert.equal(codes[6], 'RATE_LIMITED', 'a tool error the model can read, not a transport 429');
});

test('more than twenty changes a minute across devices is refused', async () => {
  const { accessToken } = await tokenFor(h);
  const codes: (string | undefined)[] = [];
  for (let index = 0; index < 4; index++) codes.push(...await flip(accessToken, await deviceFor(accessToken), 6));
  assert.equal(codes.filter((code) => code === 'RATE_LIMITED').length, 4, 'the 21st to 24th are refused');
});

test('in report mode an over-budget change is allowed', async () => {
  process.env.WRITE_BUDGETS = 'report';
  const { accessToken } = await tokenFor(h);
  const codes = await flip(accessToken, await deviceFor(accessToken), 8);
  assert.ok(codes.every((code) => code === undefined));
});

test('budgets are per grant: another client of the same person keeps its own', async () => {
  const { accessToken, username } = await tokenFor(h);
  for (let index = 0; index < 4; index++) await flip(accessToken, await deviceFor(accessToken), 6);
  assert.equal(
    (await flip(accessToken, await deviceFor(accessToken), 1))[0], 'RATE_LIMITED',
    'precondition: the MCP grant has spent its control budget'
  );

  // The same person, through the iOS app: a different grant, a fresh budget.
  const { rows } = await h.db.query<{ id: string }>('SELECT id FROM accounts WHERE username = $1', [username]);
  const app = await appClientFor(h.db, h.base, rows[0]!.id);
  const created = (await app.call('POST', '/v1/devices', { body: { name: 'From the app' } })).body as { device: { id: string; version: number } };
  const switched = await app.call('PUT', `/v1/devices/${created.device.id}/state`, {
    body: { state: 'on', expectedVersion: created.device.version }
  });
  assert.equal(switched.status, 200);
});

test('the REST API refuses an over-budget change with 429 and Retry-After', async () => {
  const account = await createAccount(h.db, `rest${Date.now()}`, 'correct horse battery staple');
  const app = await appClientFor(h.db, h.base, account.id);
  const device = (await app.call('POST', '/v1/devices', { body: { name: 'Rest Lamp' } })).body as { device: { id: string; version: number } };

  let version = device.device.version;
  let last = null;
  for (let index = 0; index < 7; index++) {
    last = await app.call('PUT', `/v1/devices/${device.device.id}/state`, {
      body: { state: index % 2 === 0 ? 'on' : 'off', expectedVersion: version }
    });
    if (last.status === 200) version = last.body.device.version;
  }
  assert.equal(last?.status, 429);
  assert.ok(Number(last?.headers.get('retry-after')) > 0);
});

test('every change is audited with the client, grant and adapter behind it', async () => {
  const { accessToken } = await tokenFor(h);
  const device = await deviceFor(accessToken, 'Audited Lamp');
  await flip(accessToken, device, 1);

  const { rows } = await h.db.query<Record<string, string | null>>(
    `SELECT action, channel, client_id, grant_id, via, auth_method FROM audit_events WHERE device_id = $1 ORDER BY id`,
    [device.id]
  );
  assert.equal(rows.length, 2);
  for (const row of rows) {
    assert.equal(row.channel, 'mcp');
    assert.match(row.client_id ?? '', /^client_/);
    assert.match(row.grant_id ?? '', /^grant_/);
    assert.equal(row.via, 'spiffe://iot-switch/mcp-rs');
    assert.equal(row.auth_method, 'oauth');
  }

  const { rows: all } = await h.db.query<Record<string, unknown>>('SELECT * FROM audit_events');
  assert.ok(!JSON.stringify(all).includes('iotsw_'), 'no token in any audit column');
});
