/**
 * Fifty callers at once. AC-43.
 *
 * Run with `npm run test:pg` these execute on a PostgreSQL server through a
 * pool, so the fifty statements genuinely overlap and the guarantees below
 * rest on row locks and constraints, not on PGlite running one statement at
 * a time. Under `npm test` they still run, and prove the logic.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { addDevice, controlDevice, listDevices } from '../src/domain/devices.ts';
import { tokenDigest } from '../src/tokens/hash.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { freshDb, makeIdentity } from './helpers.ts';
import { authorizeAs, exchange, json, startServer, type Harness } from './oauth-helpers.ts';

const N = 50;

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

test('fifty concurrent refreshes of one token rotate it once, and every caller gets the same pair', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  const results = await Promise.all(Array.from({ length: N }, async () => {
    const response = await fetch(`${h.base}/token`, json({
      grant_type: 'refresh_token', refresh_token: first.body.refresh_token, client_id: authorization.clientId
    }));
    return { status: response.status, body: await response.json() as Record<string, string> };
  }));

  assert.ok(results.every((r) => r.status === 200), JSON.stringify(results.find((r) => r.status !== 200)?.body));
  assert.equal(new Set(results.map((r) => JSON.stringify(r.body))).size, 1);

  const { rows } = await h.db.query<{ live: number; total: number }>(
    `SELECT count(*) FILTER (WHERE replaced_by IS NULL AND revoked_at IS NULL)::int AS live,
            count(*)::int AS total
       FROM oauth_refresh_tokens
      WHERE grant_id = (SELECT grant_id FROM oauth_access_tokens WHERE token_hash = $1)`,
    [tokenDigest(results[0]!.body.access_token!)]
  );
  assert.deepEqual(rows[0], { live: 1, total: 2 }, 'one rotation: the original and one successor');
  assert.ok((await verifyOAuthAccessToken(h.db, results[0]!.body.access_token)).ok);
});

test('fifty concurrent redemptions of one code issue tokens at most once', async () => {
  const authorization = await authorizeAs(h.base);
  const grants = async () => (await h.db.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM oauth_grants WHERE client_id = $1', [authorization.clientId]
  )).rows[0]!.n;
  const before = await grants();
  const results = await Promise.all(Array.from({ length: N }, () => exchange(h.base, authorization)));

  const won = results.filter((r) => r.status === 200);
  assert.equal(won.length, 1, 'exactly one redemption succeeds');
  assert.ok(results.filter((r) => r.status !== 200).every((r) => r.body.error === 'invalid_grant'));
  assert.equal(await grants() - before, 1, 'one code, one grant');
});

test('fifty concurrent switches from one version: one wins, the rest are told it moved', async () => {
  const db = await freshDb();
  try {
    const me = await makeIdentity(db);
    const lamp = await addDevice(db, me, { name: 'Contended Lamp' });
    const results = await Promise.allSettled(Array.from({ length: N }, (_, i) =>
      controlDevice(db, me, { deviceId: lamp.id, state: i % 2 ? 'on' : 'off', expectedVersion: lamp.version })
    ));
    const won = results.filter((r) => r.status === 'fulfilled');
    const lost = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
    // A request for the state the device is already in is a no-op success, so
    // the "off" requests may all succeed without writing. What must never
    // happen is two writes from one version.
    const [after] = await listDevices(db, me);
    assert.ok(after!.version <= lamp.version + 1, `version moved by ${after!.version - lamp.version}`);
    assert.ok(lost.every((r) => (r.reason as { code?: string }).code === 'DEVICE_VERSION_CONFLICT'));
    assert.equal(won.length + lost.length, N);
  } finally {
    await db.close();
  }
});

test('fifty concurrent creates of one name make one device', async () => {
  const db = await freshDb();
  try {
    const me = await makeIdentity(db);
    const results = await Promise.allSettled(Array.from({ length: N }, () => addDevice(db, me, { name: 'Same Name' })));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    assert.equal((await listDevices(db, me)).length, 1);
  } finally {
    await db.close();
  }
});
