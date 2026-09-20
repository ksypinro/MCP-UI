/** The HTTP contract from spec sections 6 and 7.1: statuses, codes, shapes. */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createDb, type Db } from '../src/db/index.ts';
import { createApp } from '../src/http/app.ts';

const PASSWORD = 'correct horse battery staple';

let db: Db;
let server: Server;
let base: string;

before(async () => {
  db = await createDb();
  server = createApp(db).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await db.close();
});

interface Res<T = Record<string, never>> {
  status: number;
  body: T & { error?: { code: string; message: string; requestId: string; field?: string } };
  requestId: string | null;
}

async function call<T = Record<string, never>>(
  method: string,
  path: string,
  options: { token?: string; body?: unknown; raw?: string; headers?: Record<string, string> } = {}
): Promise<Res<T>> {
  const response = await fetch(base + path, {
    method,
    headers: {
      'content-type': 'application/json',
      ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
      ...options.headers
    },
    body: options.raw ?? (options.body === undefined ? undefined : JSON.stringify(options.body))
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : {},
    requestId: response.headers.get('x-request-id')
  };
}

interface Session { accessToken: string; refreshToken: string; account: { id: string; username: string } }

let sam: Session;
let other: Session;

test('sign-up returns 201 with an account and a session', async () => {
  const res = await call<Session>('POST', '/v1/auth/signup', { body: { username: 'sam', password: PASSWORD } });
  assert.equal(res.status, 201);
  assert.equal(res.body.account.username, 'sam');
  assert.ok(res.body.accessToken && res.body.refreshToken);
  assert.ok(!JSON.stringify(res.body).includes(PASSWORD), 'the password is never echoed');
  assert.ok(!('passwordHash' in (res.body.account as object)), 'the hash is never exposed');
  sam = res.body;

  const second = await call<Session>('POST', '/v1/auth/signup', { body: { username: 'jordan', password: PASSWORD } });
  assert.equal(second.status, 201, `second fixture account failed: ${JSON.stringify(second.body)}`);
  other = second.body;
});

test('a duplicate username is a 409 naming the field', async () => {
  const res = await call('POST', '/v1/auth/signup', { body: { username: 'SAM', password: PASSWORD } });
  assert.equal(res.status, 409);
  assert.equal(res.body.error?.code, 'USERNAME_TAKEN');
  assert.equal(res.body.error?.field, 'username');
});

test('a weak password is a 422 naming the field', async () => {
  const res = await call('POST', '/v1/auth/signup', { body: { username: 'newbie', password: 'short' } });
  assert.equal(res.status, 422);
  assert.equal(res.body.error?.code, 'VALIDATION_FAILED');
  assert.equal(res.body.error?.field, 'password');
});

test('login succeeds, and failure is generic', async () => {
  const ok = await call<Session>('POST', '/v1/auth/login', { body: { username: 'sam', password: PASSWORD } });
  assert.equal(ok.status, 200);

  const wrongPassword = await call('POST', '/v1/auth/login', { body: { username: 'sam', password: 'wrong-password-x' } });
  const unknownUser = await call('POST', '/v1/auth/login', { body: { username: 'nobody', password: PASSWORD } });

  assert.equal(wrongPassword.status, 401);
  assert.equal(unknownUser.status, 401);
  // Identical, so the endpoint cannot be used to discover which names exist.
  assert.equal(wrongPassword.body.error?.message, unknownUser.body.error?.message);
});

test('protected endpoints refuse an absent or bogus token', async () => {
  for (const options of [{}, { token: 'nonsense' }]) {
    const res = await call('GET', '/v1/devices', options);
    assert.equal(res.status, 401);
    assert.equal(res.body.error?.code, 'UNAUTHENTICATED');
  }
});

test('every error carries a correlation id that matches the header', async () => {
  const res = await call('GET', '/v1/devices');
  assert.ok(res.body.error?.requestId.startsWith('req_'));
  assert.equal(res.body.error?.requestId, res.requestId);
});

test('malformed JSON is a 400, not a 500', async () => {
  const res = await call('POST', '/v1/devices', { token: sam.accessToken, raw: '{"name": ' });
  assert.equal(res.status, 400);
  assert.equal(res.body.error?.code, 'MALFORMED_REQUEST');
});

test('creating a device returns 201 and an off device at version 1', async () => {
  const res = await call<{ device: { id: string; state: string; version: number } }>(
    'POST', '/v1/devices', { token: sam.accessToken, body: { name: 'Bedroom Lamp' } }
  );
  assert.equal(res.status, 201);
  assert.equal(res.body.device.state, 'off');
  assert.equal(res.body.device.version, 1);
});

test('a duplicate device name is a 409', async () => {
  const res = await call('POST', '/v1/devices', { token: sam.accessToken, body: { name: 'bedroom lamp' } });
  assert.equal(res.status, 409);
  assert.equal(res.body.error?.code, 'DEVICE_NAME_CONFLICT');
});

test('an idempotency key makes a replayed create return the same device', async () => {
  const headers = { 'idempotency-key': 'abc-123' };
  const first = await call<{ device: { id: string } }>(
    'POST', '/v1/devices', { token: sam.accessToken, body: { name: 'Desk Fan' }, headers }
  );
  const replay = await call<{ device: { id: string } }>(
    'POST', '/v1/devices', { token: sam.accessToken, body: { name: 'Desk Fan' }, headers }
  );
  assert.equal(first.status, 201);
  assert.equal(replay.body.device.id, first.body.device.id);
});

test('the list returns only this account, oldest first', async () => {
  const mine = await call<{ devices: { name: string }[] }>('GET', '/v1/devices', { token: sam.accessToken });
  assert.equal(mine.status, 200);
  assert.deepEqual(mine.body.devices.map((d) => d.name), ['Bedroom Lamp', 'Desk Fan']);

  const theirs = await call<{ devices: unknown[] }>('GET', '/v1/devices', { token: other.accessToken });
  assert.deepEqual(theirs.body.devices, [], 'a new account has no devices');
});

test("another account's device is a 404, exactly like one that does not exist", async () => {
  const mine = await call<{ devices: { id: string }[] }>('GET', '/v1/devices', { token: sam.accessToken });
  const id = mine.body.devices[0]!.id;

  const foreign = await call('GET', `/v1/devices/${id}`, { token: other.accessToken });
  const missing = await call('GET', '/v1/devices/dev_does_not_exist', { token: other.accessToken });

  assert.equal(foreign.status, 404);
  assert.equal(missing.status, 404);
  assert.equal(foreign.body.error?.code, missing.body.error?.code);
  assert.equal(foreign.body.error?.message, missing.body.error?.message);
});

test('control requires expectedVersion, rejects invalid states, and detects staleness', async () => {
  const list = await call<{ devices: { id: string; version: number }[] }>('GET', '/v1/devices', { token: sam.accessToken });
  const device = list.body.devices[0]!;
  const path = `/v1/devices/${device.id}/state`;

  const missing = await call('PUT', path, { token: sam.accessToken, body: { state: 'on' } });
  assert.equal(missing.status, 422);
  assert.equal(missing.body.error?.field, 'expectedVersion');

  const invalid = await call('PUT', path, { token: sam.accessToken, body: { state: 'dim', expectedVersion: device.version } });
  assert.equal(invalid.status, 422);
  assert.equal(invalid.body.error?.code, 'INVALID_STATE');

  const ok = await call<{ device: { state: string; version: number } }>(
    'PUT', path, { token: sam.accessToken, body: { state: 'on', expectedVersion: device.version } }
  );
  assert.equal(ok.status, 200);
  assert.equal(ok.body.device.state, 'on');
  assert.equal(ok.body.device.version, device.version + 1);

  const stale = await call('PUT', path, { token: sam.accessToken, body: { state: 'off', expectedVersion: device.version } });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error?.code, 'DEVICE_VERSION_CONFLICT');
});

test('another account cannot control a device it does not own', async () => {
  const list = await call<{ devices: { id: string; version: number }[] }>('GET', '/v1/devices', { token: sam.accessToken });
  const device = list.body.devices[0]!;
  const res = await call('PUT', `/v1/devices/${device.id}/state`, {
    token: other.accessToken,
    body: { state: 'off', expectedVersion: device.version }
  });
  assert.equal(res.status, 404);

  const after = await call<{ device: { state: string } }>('GET', `/v1/devices/${device.id}`, { token: sam.accessToken });
  assert.equal(after.body.device.state, 'on', 'the device is untouched');
});

test('/v1/auth/me identifies the caller without leaking secrets', async () => {
  const res = await call<{ account: { username: string } }>('GET', '/v1/auth/me', { token: sam.accessToken });
  assert.equal(res.status, 200);
  assert.equal(res.body.account.username, 'sam');
  assert.ok(!JSON.stringify(res.body).includes('argon2'));
});

test('refresh rotates, and logout invalidates the token already issued', async () => {
  const rotated = await call<{ accessToken: string; refreshToken: string }>(
    'POST', '/v1/auth/refresh', { body: { refreshToken: other.refreshToken } }
  );
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.refreshToken, other.refreshToken);

  const replay = await call('POST', '/v1/auth/refresh', { body: { refreshToken: other.refreshToken } });
  assert.equal(replay.status, 401, 'a rotated refresh token is dead');

  const loggedOut = await call('POST', '/v1/auth/logout', { token: sam.accessToken });
  assert.equal(loggedOut.status, 204);

  const afterLogout = await call('GET', '/v1/devices', { token: sam.accessToken });
  assert.equal(afterLogout.status, 401, 'an access token issued before logout stops working');
});
