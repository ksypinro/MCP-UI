/**
 * The shared-state stores, one contract for every implementation. AC-44 and
 * AC-47.
 *
 * The in-memory stores always run. The Redis ones run when TEST_REDIS_URL is
 * set (CI sets it), each under a prefix of its own. Two Redis-backed
 * instances in one test stand for two processes: they share nothing but the
 * Redis server, exactly as two processes would.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryBucketStore, type BucketStore } from '../src/security/rate-limit.ts';
import { MemoryReplayStore, type ReplayStore } from '../src/security/replay.ts';
import { MemorySealedResponses, type SealedResponses } from '../src/oauth/sealed.ts';
import { RevocationHub, type ReceivedEvent } from '../src/revocation.ts';
import { isolatedPrefix, redisInfrastructure } from '../src/stores/index.ts';
import { ExchangeClient } from '../src/exchange-client.ts';
import { createWorkload } from '../src/security/workload.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import type { VerifiedCaller } from '../src/domain/types.ts';
import { createApp } from '../src/http/app.ts';
import { startServer, type Harness } from './oauth-helpers.ts';
import { tokenFor } from './mcp-helpers.ts';

const REDIS = process.env.TEST_REDIS_URL;
const needsRedis = REDIS ? false : 'set TEST_REDIS_URL to run against Redis';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface Stores { buckets: BucketStore; replay: ReplayStore; sealed: SealedResponses; close(): Promise<void> }

const implementations: Array<{ name: string; make: () => Promise<Stores>; skip: string | false }> = [
  {
    name: 'memory',
    skip: false,
    make: async () => ({
      buckets: new MemoryBucketStore(), replay: new MemoryReplayStore(), sealed: new MemorySealedResponses(),
      close: async () => {}
    })
  },
  {
    name: 'redis',
    skip: needsRedis,
    make: () => redisInfrastructure({ url: REDIS!, prefix: isolatedPrefix(), revocations: new RevocationHub() })
  }
];

for (const impl of implementations) {
  test(`${impl.name}: a bucket counts hits within its window and starts again after`, { skip: impl.skip }, async () => {
    const stores = await impl.make();
    try {
      assert.equal((await stores.buckets.hit('k', 300)).count, 1);
      assert.equal((await stores.buckets.hit('k', 300)).count, 2);
      const third = await stores.buckets.hit('k', 300);
      assert.equal(third.count, 3);
      assert.ok(third.resetAt > Date.now() && third.resetAt <= Date.now() + 300);
      assert.equal((await stores.buckets.hit('other', 300)).count, 1, 'keys are independent');
      await sleep(350);
      assert.equal((await stores.buckets.hit('k', 300)).count, 1, 'a new window');
    } finally {
      await stores.close();
    }
  });

  test(`${impl.name}: an id is claimed once until it expires`, { skip: impl.skip }, async () => {
    const stores = await impl.make();
    try {
      assert.equal(await stores.replay.claim('jti-1', 1), true);
      assert.equal(await stores.replay.claim('jti-1', 1), false);
      assert.equal(await stores.replay.claim('jti-2', 1), true);
      await sleep(1_100);
      assert.equal(await stores.replay.claim('jti-1', 1), true);
    } finally {
      await stores.close();
    }
  });

  test(`${impl.name}: a sealed response opens under its key, until it expires`, { skip: impl.skip }, async () => {
    const stores = await impl.make();
    try {
      await stores.sealed.seal('client:digest', { access_token: 'a', refresh_token: 'r' }, 1);
      assert.deepEqual(await stores.sealed.unseal('client:digest'), { access_token: 'a', refresh_token: 'r' });
      assert.equal(await stores.sealed.unseal('client:other'), null);
      await sleep(1_100);
      assert.equal(await stores.sealed.unseal('client:digest'), null);
    } finally {
      await stores.close();
    }
  });
}

test('redis: two processes share counts, used proof ids and sealed responses', { skip: needsRedis }, async () => {
  const prefix = isolatedPrefix();
  const a = await redisInfrastructure({ url: REDIS!, prefix, revocations: new RevocationHub() });
  const b = await redisInfrastructure({ url: REDIS!, prefix, revocations: new RevocationHub() });
  try {
    await a.buckets.hit('shared', 5_000);
    assert.equal((await b.buckets.hit('shared', 5_000)).count, 2, 'one limit, not one per process');

    assert.equal(await a.replay.claim('proof', 60), true);
    assert.equal(await b.replay.claim('proof', 60), false, 'a proof used at one process is used at all');

    await a.sealed.seal('k', { access_token: 'x' }, 30);
    assert.deepEqual(await b.sealed.unseal('k'), { access_token: 'x' }, 'a duplicate refresh may land anywhere');
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test('redis: a revocation in one process reaches every other', { skip: needsRedis }, async () => {
  const prefix = isolatedPrefix();
  const hubA = new RevocationHub();
  const hubB = new RevocationHub();
  const a = await redisInfrastructure({ url: REDIS!, prefix, revocations: hubA });
  const b = await redisInfrastructure({ url: REDIS!, prefix, revocations: hubB });
  try {
    const heardByB: ReceivedEvent[] = [];
    const heardByA: ReceivedEvent[] = [];
    hubB.subscribe((event) => heardByB.push(event));
    hubA.subscribe((event) => heardByA.push(event));

    hubA.publish({ type: 'grant.revoked', grantId: 'grant_1' });
    hubA.publish({ type: 'account.revoked', accountId: 'acct_1' });
    for (let i = 0; i < 50 && heardByB.length < 2; i++) await sleep(20);

    assert.deepEqual(heardByB, [
      { type: 'grant.revoked', grantId: 'grant_1', remote: true },
      { type: 'account.revoked', accountId: 'acct_1', remote: true }
    ]);
    await sleep(100);
    assert.equal(heardByA.length, 2, 'a process does not hear its own events twice');
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

test('redis: an unreachable store refuses with 503 rather than letting requests through', { skip: needsRedis }, async () => {
  const infra = await redisInfrastructure({ url: REDIS!, prefix: isolatedPrefix(), revocations: new RevocationHub() });
  await infra.close();

  await assert.rejects(infra.buckets.hit('k', 1_000), (error: any) => error.code === 'SERVICE_UNAVAILABLE');
  await assert.rejects(infra.replay.claim('k', 60), (error: any) => error.code === 'SERVICE_UNAVAILABLE');
  await assert.rejects(infra.sealed.seal('k', {}, 30), (error: any) => error.code === 'SERVICE_UNAVAILABLE');

  // And at the edge: a rate-limited route answers 503, not 200.
  const { freshDb } = await import('./helpers.ts');
  const db = await freshDb();
  const server = createApp(db, infra).listen(0);
  try {
    await new Promise((resolve) => server.once('listening', resolve));
    const port = (server.address() as { port: number }).port;
    const response = await fetch(`http://127.0.0.1:${port}/authorize?client_id=x`);
    assert.equal(response.status, 503);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await db.close();
  }
});

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

async function caller(): Promise<VerifiedCaller> {
  const { accessToken } = await tokenFor(h);
  const verified = await verifyOAuthAccessToken(h.db, accessToken);
  if (!verified.ok) throw new Error('token did not verify');
  return {
    kind: 'verified', accountId: verified.accountId, clientId: verified.clientId, grantId: verified.grantId,
    channel: 'mcp', scopes: verified.scopes, requestId: 'req_test', credential: accessToken
  };
}

test('cached internal tokens are dropped when their account or client is revoked', async () => {
  const hub = new RevocationHub();
  const client = ExchangeClient.local(h.db, createWorkload('mcp-rs'), hub);
  const me = await caller();
  await client.tokenFor(me, 'devices:read');
  await client.tokenFor(me, 'devices:control');
  assert.equal(client.size, 2);

  hub.publish({ type: 'account.revoked', accountId: 'someone_else' });
  assert.equal(client.size, 2, 'another account is untouched');
  hub.publish({ type: 'account.revoked', accountId: me.accountId });
  assert.equal(client.size, 0);

  await client.tokenFor(me, 'devices:read');
  hub.publish({ type: 'client.blocked', clientId: me.clientId });
  assert.equal(client.size, 0);
});

test('redis: revoking a grant in one process empties the cache in another', { skip: needsRedis }, async () => {
  const prefix = isolatedPrefix();
  const hubA = new RevocationHub();
  const hubB = new RevocationHub();
  const a = await redisInfrastructure({ url: REDIS!, prefix, revocations: hubA });
  const b = await redisInfrastructure({ url: REDIS!, prefix, revocations: hubB });
  try {
    const inB = ExchangeClient.local(h.db, createWorkload('mcp-rs'), hubB);
    const me = await caller();
    await inB.tokenFor(me, 'devices:read');
    assert.equal(inB.size, 1);

    hubA.publish({ type: 'grant.revoked', grantId: me.grantId });
    for (let i = 0; i < 50 && inB.size > 0; i++) await sleep(20);
    assert.equal(inB.size, 0, 'process B dropped the token after process A revoked the grant');
  } finally {
    await Promise.all([a.close(), b.close()]);
  }
});

