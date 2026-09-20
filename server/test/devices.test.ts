import test from 'node:test';
import assert from 'node:assert/strict';
import { addDevice, controlDevice, getDevice, listDevices } from '../src/domain/devices.ts';
import { MAX_DEVICES_PER_ACCOUNT } from '../src/config.ts';
import { freshDb, makeIdentity, rejectsWithCode } from './helpers.ts';

test('a new device starts off, at version 1', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const device = await addDevice(db, me, { name: 'Bedroom Lamp' });

  assert.equal(device.name, 'Bedroom Lamp');
  assert.equal(device.state, 'off');
  assert.equal(device.version, 1);
  assert.equal(device.createdAt, device.updatedAt);
  await db.close();
});

test('names are tidied for display but folded for uniqueness', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const device = await addDevice(db, me, { name: '  Bedroom   Lamp  ' });
  assert.equal(device.name, 'Bedroom Lamp');

  await rejectsWithCode(() => addDevice(db, me, { name: 'bedroom lamp' }), 'DEVICE_NAME_CONFLICT');
  await rejectsWithCode(() => addDevice(db, me, { name: 'BEDROOM LAMP' }), 'DEVICE_NAME_CONFLICT');
  assert.equal((await listDevices(db, me)).length, 1);
  await db.close();
});

test('blank and over-long names are rejected', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  await rejectsWithCode(() => addDevice(db, me, { name: '   ' }), 'VALIDATION_FAILED');
  await rejectsWithCode(() => addDevice(db, me, { name: 'x'.repeat(65) }), 'VALIDATION_FAILED');
  assert.equal((await listDevices(db, me)).length, 0);
  await db.close();
});

test('devices are listed oldest first', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  for (const name of ['First', 'Second', 'Third']) await addDevice(db, me, { name });
  assert.deepEqual((await listDevices(db, me)).map((d) => d.name), ['First', 'Second', 'Third']);
  await db.close();
});

test('a switch changes state and consumes exactly one version', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });

  const on = await controlDevice(db, me, { deviceId: created.id, state: 'on', expectedVersion: 1 });
  assert.equal(on.state, 'on');
  assert.equal(on.version, 2);
  assert.notEqual(on.updatedAt, created.updatedAt);

  const off = await controlDevice(db, me, { deviceId: created.id, state: 'off', expectedVersion: 2 });
  assert.equal(off.state, 'off');
  assert.equal(off.version, 3);
  await db.close();
});

test('setting the state it already has consumes nothing', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });

  const noop = await controlDevice(db, me, { deviceId: created.id, state: 'off', expectedVersion: 1 });
  assert.equal(noop.state, 'off');
  assert.equal(noop.version, 1, 'version must not advance');
  assert.equal(noop.updatedAt, created.updatedAt, 'updatedAt must not advance');
  await db.close();
});

test('a stale version is refused and changes nothing', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });
  await controlDevice(db, me, { deviceId: created.id, state: 'on', expectedVersion: 1 });

  await rejectsWithCode(
    () => controlDevice(db, me, { deviceId: created.id, state: 'off', expectedVersion: 1 }),
    'DEVICE_VERSION_CONFLICT'
  );

  const after = await getDevice(db, me, created.id);
  assert.equal(after.state, 'on', 'the rejected write must not have applied');
  assert.equal(after.version, 2);
  await db.close();
});

test('replaying a successful control conflicts rather than inverting', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });
  await controlDevice(db, me, { deviceId: created.id, state: 'on', expectedVersion: 1 });

  // The point of expectedVersion: a retry after a lost response can never
  // silently undo the change it is retrying.
  await rejectsWithCode(
    () => controlDevice(db, me, { deviceId: created.id, state: 'on', expectedVersion: 1 }),
    'DEVICE_VERSION_CONFLICT'
  );
  assert.equal((await getDevice(db, me, created.id)).state, 'on');
  await db.close();
});

test('an invalid state is refused', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });
  await rejectsWithCode(
    () => controlDevice(db, me, { deviceId: created.id, state: 'dim' as 'on', expectedVersion: 1 }),
    'INVALID_STATE'
  );
  await db.close();
});

test("another account's device is indistinguishable from one that does not exist", async () => {
  const db = await freshDb();
  const alice = await makeIdentity(db);
  const bob = await makeIdentity(db);
  const hers = await addDevice(db, alice, { name: 'Bedroom Lamp' });

  await rejectsWithCode(() => getDevice(db, bob, hers.id), 'DEVICE_NOT_FOUND');
  await rejectsWithCode(() => getDevice(db, bob, 'dev_nonexistent'), 'DEVICE_NOT_FOUND');
  await rejectsWithCode(
    () => controlDevice(db, bob, { deviceId: hers.id, state: 'on', expectedVersion: 1 }),
    'DEVICE_NOT_FOUND'
  );

  assert.deepEqual(await listDevices(db, bob), []);
  assert.equal((await getDevice(db, alice, hers.id)).state, 'off', "Alice's device is untouched");
  await db.close();
});

test('the same name is free for a different account', async () => {
  const db = await freshDb();
  const alice = await makeIdentity(db);
  const bob = await makeIdentity(db);
  await addDevice(db, alice, { name: 'Bedroom Lamp' });
  const his = await addDevice(db, bob, { name: 'Bedroom Lamp' });
  assert.equal(his.name, 'Bedroom Lamp');
  await db.close();
});

test('an idempotency key makes a replayed create return the original device', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const first = await addDevice(db, me, { name: 'Bedroom Lamp', idempotencyKey: 'key-1' });
  const replay = await addDevice(db, me, { name: 'Bedroom Lamp', idempotencyKey: 'key-1' });

  assert.equal(replay.id, first.id);
  assert.equal((await listDevices(db, me)).length, 1);
  await db.close();
});

test('an idempotency key reused for a different device is refused', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const first = await addDevice(db, me, { name: 'Bedroom Lamp', idempotencyKey: 'k1' });

  // Returning `first` here would tell the caller it created a fan. It did not.
  await rejectsWithCode(
    () => addDevice(db, me, { name: 'Totally Different Fan', idempotencyKey: 'k1' }),
    'VALIDATION_FAILED'
  );

  const devices = await listDevices(db, me);
  assert.deepEqual(devices.map((d) => d.id), [first.id]);
  await db.close();
});

test('the device cap is enforced', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  for (let i = 0; i < MAX_DEVICES_PER_ACCOUNT; i++) await addDevice(db, me, { name: `Device ${i}` });
  await rejectsWithCode(() => addDevice(db, me, { name: 'One too many' }), 'DEVICE_LIMIT_REACHED');
  assert.equal((await listDevices(db, me)).length, MAX_DEVICES_PER_ACCOUNT);
  await db.close();
});

test('mutations are audited with actor, transition, and channel', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db, 'mcp');
  const created = await addDevice(db, me, { name: 'Bedroom Lamp' });
  await controlDevice(db, me, { deviceId: created.id, state: 'on', expectedVersion: 1 });
  await rejectsWithCode(
    () => controlDevice(db, me, { deviceId: created.id, state: 'off', expectedVersion: 1 }),
    'DEVICE_VERSION_CONFLICT'
  );

  const { rows } = await db.query<{ action: string; outcome: string; channel: string; new_state: string }>(
    'SELECT action, outcome, channel, new_state FROM audit_events ORDER BY id'
  );
  assert.deepEqual(rows.map((r) => `${r.action}:${r.outcome}`), [
    'device.create:ok',
    'device.control:ok',
    'device.control:rejected'
  ]);
  assert.ok(rows.every((r) => r.channel === 'mcp'), 'channel is recorded for every event');
  await db.close();
});
