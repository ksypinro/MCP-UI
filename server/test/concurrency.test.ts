/**
 * Acceptance criteria AC-09 and AC-10.
 *
 * An honest note on what these prove. PGlite is real PostgreSQL, so the UNIQUE
 * constraint and the conditional UPDATE behave exactly as they would on a
 * server — but it runs in-process and serialises queries, so the two callers
 * below never execute at literally the same instant. What is demonstrated is
 * that the *logic* is correct when two callers start from the same observed
 * state: one wins, one is refused, and no duplicate or lost update results.
 *
 * What is not yet demonstrated is behaviour under genuine row-level
 * contention on a multi-connection server. That requires pointing these same
 * tests at a real PostgreSQL, which is a change of one line in src/db. The
 * tests are written to need no modification when that happens.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { addDevice, controlDevice, listDevices } from '../src/domain/devices.ts';
import { freshDb, makeIdentity } from './helpers.ts';

interface Settled {
  fulfilled: number;
  codes: string[];
}

async function settle(promises: Promise<unknown>[]): Promise<Settled> {
  const results = await Promise.allSettled(promises);
  return {
    fulfilled: results.filter((r) => r.status === 'fulfilled').length,
    codes: results
      .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
      .map((r) => (r.reason as { code?: string }).code ?? String(r.reason))
  };
}

test('AC-09: concurrent creates of the same name produce exactly one device', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const { fulfilled, codes } = await settle(
    Array.from({ length: 8 }, () => addDevice(db, me, { name: 'Bedroom Lamp' }))
  );

  assert.equal(fulfilled, 1, 'exactly one create may succeed');
  assert.equal(codes.length, 7);
  assert.ok(codes.every((c) => c === 'DEVICE_NAME_CONFLICT'), `unexpected codes: ${codes.join(', ')}`);
  assert.equal((await listDevices(db, me)).length, 1);
  await db.close();
});

test('AC-09: concurrent creates differing only by case still produce one device', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const { fulfilled } = await settle([
    addDevice(db, me, { name: 'Bedroom Lamp' }),
    addDevice(db, me, { name: 'bedroom lamp' }),
    addDevice(db, me, { name: 'BEDROOM   LAMP' })
  ]);

  assert.equal(fulfilled, 1);
  assert.equal((await listDevices(db, me)).length, 1);
  await db.close();
});

test('AC-09: a replayed idempotency key never creates a second device', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);

  const results = await Promise.allSettled(
    Array.from({ length: 5 }, () => addDevice(db, me, { name: 'Bedroom Lamp', idempotencyKey: 'k' }))
  );
  const ids = new Set(
    results.filter((r) => r.status === 'fulfilled').map((r) => (r.value as { id: string }).id)
  );

  assert.equal(ids.size, 1, 'every caller that succeeded saw the same device');
  assert.equal((await listDevices(db, me)).length, 1);
  await db.close();
});

test('AC-10: two writers holding the same version, exactly one wins', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const device = await addDevice(db, me, { name: 'Bedroom Lamp' });

  const { fulfilled, codes } = await settle([
    controlDevice(db, me, { deviceId: device.id, state: 'on', expectedVersion: 1 }),
    controlDevice(db, me, { deviceId: device.id, state: 'off', expectedVersion: 1 })
  ]);

  assert.equal(fulfilled, 1, 'no lost update: only one writer may succeed');
  assert.deepEqual(codes, ['DEVICE_VERSION_CONFLICT']);

  const [after] = await listDevices(db, me);
  assert.equal(after?.version, 2, 'exactly one version was consumed');
  await db.close();
});

test('AC-10: many writers on one version consume exactly one version', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const device = await addDevice(db, me, { name: 'Bedroom Lamp' });

  const { fulfilled, codes } = await settle(
    Array.from({ length: 10 }, () =>
      controlDevice(db, me, { deviceId: device.id, state: 'on', expectedVersion: 1 })
    )
  );

  assert.equal(fulfilled, 1);
  assert.ok(codes.every((c) => c === 'DEVICE_VERSION_CONFLICT'));

  const [after] = await listDevices(db, me);
  assert.equal(after?.version, 2);
  assert.equal(after?.state, 'on');
  await db.close();
});

test('AC-10: a no-op racing a real change never invents a version', async () => {
  const db = await freshDb();
  const me = await makeIdentity(db);
  const device = await addDevice(db, me, { name: 'Bedroom Lamp' });

  // Both callers see version 1. One asks for the state it already has, the
  // other asks for a change. The no-op must not consume the version the real
  // change needs.
  const results = await Promise.allSettled([
    controlDevice(db, me, { deviceId: device.id, state: 'off', expectedVersion: 1 }),
    controlDevice(db, me, { deviceId: device.id, state: 'on', expectedVersion: 1 })
  ]);

  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 2, 'both are legitimate');

  const [after] = await listDevices(db, me);
  assert.equal(after?.state, 'on');
  assert.equal(after?.version, 2, 'only the real change advanced the version');
  await db.close();
});

test('two accounts writing concurrently do not interfere', async () => {
  const db = await freshDb();
  const alice = await makeIdentity(db);
  const bob = await makeIdentity(db);
  const hers = await addDevice(db, alice, { name: 'Bedroom Lamp' });
  const his = await addDevice(db, bob, { name: 'Bedroom Lamp' });

  const { fulfilled } = await settle([
    controlDevice(db, alice, { deviceId: hers.id, state: 'on', expectedVersion: 1 }),
    controlDevice(db, bob, { deviceId: his.id, state: 'on', expectedVersion: 1 })
  ]);

  assert.equal(fulfilled, 2, 'separate devices never contend');
  await db.close();
});
