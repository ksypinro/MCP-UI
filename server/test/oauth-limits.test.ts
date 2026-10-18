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
import { cimdCacheSeconds, cimdFetchAllowed } from '../src/oauth/clients.ts';

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

test('a document is reused for as long as it asks, within a day', () => {
  assert.equal(cimdCacheSeconds(null), 300, 'silence means five minutes');
  assert.equal(cimdCacheSeconds('public, max-age=3600'), 3600);
  assert.equal(cimdCacheSeconds('max-age=5'), 60, 'never refetched more than once a minute');
  assert.equal(cimdCacheSeconds('max-age=31536000'), 86_400, 'never trusted for more than a day');
  assert.equal(cimdCacheSeconds('no-store'), 0);
  assert.equal(cimdCacheSeconds('private, no-cache'), 0);
});
