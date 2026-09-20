/**
 * Spec section 11: accounts and devices survive a backend restart. An
 * in-memory map is explicitly not an acceptable only store, so this test
 * closes the database entirely and opens it again from disk.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDb } from '../src/db/index.ts';
import { MIGRATIONS } from '../src/db/migrations.ts';
import { createAccount, verifyCredentials } from '../src/domain/accounts.ts';
import { addDevice, controlDevice, listDevices } from '../src/domain/devices.ts';
import type { Identity } from '../src/domain/types.ts';

test('accounts, devices and state survive a full restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'iot-switch-'));

  try {
    let db = await createDb(dir);
    const account = await createAccount(db, 'sam', 'correct horse battery staple');
    const me: Identity = { accountId: account.id, channel: 'native' };

    const lamp = await addDevice(db, me, { name: 'Bedroom Lamp' });
    await addDevice(db, me, { name: 'Desk Fan' });
    await controlDevice(db, me, { deviceId: lamp.id, state: 'on', expectedVersion: 1 });

    await db.close();

    // Same directory, brand new process state.
    db = await createDb(dir);

    const account2 = await verifyCredentials(db, 'sam', 'correct horse battery staple');
    assert.equal(account2?.id, account.id, 'the account and its password hash survived');

    const devices = await listDevices(db, me);
    assert.deepEqual(devices.map((d) => d.name), ['Bedroom Lamp', 'Desk Fan'], 'ordering survived');
    assert.equal(devices[0]?.state, 'on', 'the switch position survived');
    assert.equal(devices[0]?.version, 2, 'the version survived');

    // And the schema is not reapplied on top of itself.
    const migrations = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM schema_migrations');
    assert.equal(migrations.rows[0]?.n, MIGRATIONS.length, 'migrations are applied once, not reapplied');

    await db.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
