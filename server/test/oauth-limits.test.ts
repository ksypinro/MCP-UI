/**
 * Limits on the parts of the authorization server reachable without an
 * account. Their own process and server, because the shared harness raises
 * every limit so the main suite can run.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createDb } from '../src/db/index.ts';
import { createApp } from '../src/http/app.ts';
import { CimdCache, cimdFetchAllowed } from '../src/oauth/clients.ts';

test('showing the authorization page is rate limited by address', async () => {
  process.env.AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE = '5';
  const db = await createDb();
  const server = createApp(db).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 7; attempt++) {
      statuses.push((await fetch(`${base}/authorize?client_id=client_unknown`)).status);
    }
    assert.deepEqual(statuses.slice(0, 5), [400, 400, 400, 400, 400]);
    assert.equal(statuses[6], 429);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await db.close();
  }
});

test('client metadata fetches are budgeted per host', async () => {
  // GET /authorize with an unseen https client_id makes this server fetch a
  // URL of the caller's choosing; a ceiling per host stops it being used as
  // an amplifier against one target.
  const results: boolean[] = [];
  for (let attempt = 0; attempt < 21; attempt++) results.push(await cimdFetchAllowed('target.example'));
  assert.equal(results.filter(Boolean).length, 20);
  assert.equal(results[20], false);
  assert.equal(await cimdFetchAllowed('other.example'), true, 'the budget is per host');
});

test('resolved client documents are cached briefly and bounded', () => {
  let now = 1_000;
  const cache = new CimdCache({ ttlMs: 300_000, maxEntries: 2, now: () => now });
  const client = (id: string) => ({ clientId: id, redirectUris: ['https://a.example/cb'], displayHost: 'a.example' });

  cache.set('https://a.example/1', client('https://a.example/1'));
  assert.equal(cache.get('https://a.example/1')?.clientId, 'https://a.example/1');

  now += 300_001;
  assert.equal(cache.get('https://a.example/1'), null, 'expired entries are not served');

  cache.set('https://a.example/2', client('https://a.example/2'));
  cache.set('https://a.example/3', client('https://a.example/3'));
  cache.set('https://a.example/4', client('https://a.example/4'));
  assert.equal(cache.get('https://a.example/2'), null, 'the oldest entry is evicted at the bound');
  assert.ok(cache.get('https://a.example/4'));
});
