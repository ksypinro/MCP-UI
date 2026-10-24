/** The REST API contract from spec section 6: statuses, codes, shapes. */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createDb, type Db } from '../src/db/index.ts';
import { createApp } from '../src/http/app.ts';
import { createAccount } from '../src/domain/accounts.ts';
import { AppClient, anonymous, appClientFor } from './app-helpers.ts';

const PASSWORD = 'correct horse battery staple';

let db: Db;
let server: Server;
let base: string;
let sam: AppClient;
let other: AppClient;

before(async () => {
  db = await createDb();
  server = createApp(db).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // Fixtures belong here, not in the first test. Assigning them from a test
  // makes every later case depend on execution order, and a broken fixture
  // then surfaces several cases downstream as an unexplained 401 rather than
  // where it happened.
  sam = await appClientFor(db, base, (await createAccount(db, 'sam', PASSWORD)).id);
  other = await appClientFor(db, base, (await createAccount(db, 'jordan', PASSWORD)).id);
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await db.close();
});

test('a body larger than the limit is a client error, not a server error', async () => {
  const res = await sam.call('POST', '/v1/devices', { raw: JSON.stringify({ name: 'x'.repeat(100_000) })
  });
  assert.equal(res.status, 413, 'an oversized body must not be reported as an internal error');
  assert.equal(res.body.error?.code, 'VALIDATION_FAILED');
});

test('protected endpoints refuse an absent, bogus or unbound token', async () => {
  for (const authorization of [undefined, 'Bearer nonsense', `Bearer ${sam.accessToken}`, `DPoP ${sam.accessToken}`]) {
    const res = await anonymous(base, 'GET', '/v1/devices', { authorization });
    assert.equal(res.status, 401, `${authorization?.slice(0, 12)} without a proof`);
    assert.equal(res.body.error?.code, 'UNAUTHENTICATED');
  }
});

test('every error carries a correlation id that matches the header', async () => {
  const res = await anonymous(base, 'GET', '/v1/devices');
  assert.ok(res.body.error?.requestId.startsWith('req_'));
  assert.equal(res.body.error?.requestId, res.requestId);
});

test('malformed JSON is a 400, not a 500', async () => {
  const res = await sam.call('POST', '/v1/devices', { raw: '{"name": ' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error?.code, 'MALFORMED_REQUEST');
});

test('creating a device returns 201 and an off device at version 1', async () => {
  const res = await sam.call<{ device: { id: string; state: string; version: number } }>('POST', '/v1/devices', { body: { name: 'Bedroom Lamp' } }
  );
  assert.equal(res.status, 201);
  assert.equal(res.body.device.state, 'off');
  assert.equal(res.body.device.version, 1);
});

test('a duplicate device name is a 409', async () => {
  const res = await sam.call('POST', '/v1/devices', { body: { name: 'bedroom lamp' } });
  assert.equal(res.status, 409);
  assert.equal(res.body.error?.code, 'DEVICE_NAME_CONFLICT');
});

test('an idempotency key makes a replayed create return the same device', async () => {
  const headers = { 'idempotency-key': 'abc-123' };
  const first = await sam.call<{ device: { id: string } }>('POST', '/v1/devices', { body: { name: 'Desk Fan' }, headers }
  );
  const replay = await sam.call<{ device: { id: string } }>('POST', '/v1/devices', { body: { name: 'Desk Fan' }, headers }
  );
  assert.equal(first.status, 201);
  assert.equal(replay.body.device.id, first.body.device.id);
});

test('the list returns only this account, oldest first', async () => {
  const mine = await sam.call<{ devices: { name: string }[] }>('GET', '/v1/devices');
  assert.equal(mine.status, 200);
  assert.deepEqual(mine.body.devices.map((d) => d.name), ['Bedroom Lamp', 'Desk Fan']);

  const theirs = await other.call<{ devices: unknown[] }>('GET', '/v1/devices');
  assert.deepEqual(theirs.body.devices, [], 'a new account has no devices');
});

test("another account's device is a 404, exactly like one that does not exist", async () => {
  const mine = await sam.call<{ devices: { id: string }[] }>('GET', '/v1/devices');
  const id = mine.body.devices[0]!.id;

  const foreign = await other.call('GET', `/v1/devices/${id}`);
  const missing = await other.call('GET', '/v1/devices/dev_does_not_exist');

  assert.equal(foreign.status, 404);
  assert.equal(missing.status, 404);
  assert.equal(foreign.body.error?.code, missing.body.error?.code);
  assert.equal(foreign.body.error?.message, missing.body.error?.message);
});

test('control requires expectedVersion, rejects invalid states, and detects staleness', async () => {
  const list = await sam.call<{ devices: { id: string; version: number }[] }>('GET', '/v1/devices');
  const device = list.body.devices[0]!;
  const path = `/v1/devices/${device.id}/state`;

  const missing = await sam.call('PUT', path, { body: { state: 'on' } });
  assert.equal(missing.status, 422);
  assert.equal(missing.body.error?.field, 'expectedVersion');

  const invalid = await sam.call('PUT', path, { body: { state: 'dim', expectedVersion: device.version } });
  assert.equal(invalid.status, 422);
  assert.equal(invalid.body.error?.code, 'INVALID_STATE');

  const ok = await sam.call<{ device: { state: string; version: number } }>('PUT', path, { body: { state: 'on', expectedVersion: device.version } }
  );
  assert.equal(ok.status, 200);
  assert.equal(ok.body.device.state, 'on');
  assert.equal(ok.body.device.version, device.version + 1);

  const stale = await sam.call('PUT', path, { body: { state: 'off', expectedVersion: device.version } });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error?.code, 'DEVICE_VERSION_CONFLICT');
});

test('another account cannot control a device it does not own', async () => {
  const list = await sam.call<{ devices: { id: string; version: number }[] }>('GET', '/v1/devices');
  const device = list.body.devices[0]!;
  const res = await other.call('PUT', `/v1/devices/${device.id}/state`, { body: { state: 'off', expectedVersion: device.version }
  });
  assert.equal(res.status, 404);

  const after = await sam.call<{ device: { state: string } }>('GET', `/v1/devices/${device.id}`);
  assert.equal(after.body.device.state, 'on', 'the device is untouched');
});

test('/v1/me identifies the caller without leaking secrets', async () => {
  const res = await sam.call<{ account: { username: string } }>('GET', '/v1/me');
  assert.equal(res.status, 200);
  assert.equal(res.body.account.username, 'sam');
  assert.ok(!JSON.stringify(res.body).includes('argon2'));
});

test('revoking the grant at the authorization server stops its token at once', async () => {
  const revoked = await fetch(`${base}/revoke`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: other.refreshToken!, client_id: 'iot-switch-ios' })
  });
  assert.equal(revoked.status, 200);
  assert.equal((await other.call('GET', '/v1/devices')).status, 401, 'an access token issued before revocation stops working');
});
