/**
 * Refresh-token rotation under concurrency, and single-use authorization
 * codes. RFC 9700 and OAuth 2.1 require rotation with reuse detection for
 * public clients; hosts refresh from several workers at once, so the same
 * token legitimately arrives twice.
 *
 * Run on PGlite these prove the logic, not row-lock behaviour under real
 * contention; that needs a Postgres server.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { tokenDigest } from '../src/tokens/hash.ts';
import { authorizeAs, exchange, json, startServer, type Harness } from './oauth-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

async function refresh(refreshToken: string, clientId: string) {
  const response = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId
  }));
  return { status: response.status, body: await response.json() as Record<string, string> };
}

async function grantWithRefreshToken() {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  return { clientId: authorization.clientId, refreshToken: first.body.refresh_token!, accessToken: first.body.access_token! };
}

async function ageRotations(seconds: number): Promise<void> {
  await h.db.query(
    `UPDATE oauth_refresh_tokens SET replaced_at = replaced_at - make_interval(secs => $1)
      WHERE replaced_at IS NOT NULL`,
    [seconds]
  );
}

test('concurrent refreshes with one token all succeed with the identical response', async () => {
  // Before, four concurrent refreshes revoked the grant in every run: each
  // read the token outside the transaction that rotated it.
  const grant = await grantWithRefreshToken();
  const results = await Promise.all(Array.from({ length: 8 }, () => refresh(grant.refreshToken, grant.clientId)));

  for (const result of results) assert.equal(result.status, 200, JSON.stringify(result.body));
  const bodies = new Set(results.map((r) => JSON.stringify(r.body)));
  assert.equal(bodies.size, 1, 'every caller holds the same pair, so the family stays one line');

  const { rows } = await h.db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM oauth_refresh_tokens r
       JOIN oauth_access_tokens a ON a.grant_id = r.grant_id
      WHERE r.replaced_by IS NULL AND r.revoked_at IS NULL
        AND a.token_hash = $1`,
    [tokenDigest(results[0]!.body.access_token!)]
  );
  assert.equal(rows[0]?.n, 1, 'exactly one live refresh token remains in the family');
  assert.ok((await verifyOAuthAccessToken(h.db, results[0]!.body.access_token)).ok);
});

test('a duplicate refresh inside the grace window gets the same tokens', async () => {
  const grant = await grantWithRefreshToken();
  const first = await refresh(grant.refreshToken, grant.clientId);
  const again = await refresh(grant.refreshToken, grant.clientId);
  assert.equal(again.status, 200);
  assert.deepEqual(again.body, first.body);
});

test('a duplicate from a different client is theft, even inside the window', async () => {
  const grant = await grantWithRefreshToken();
  const first = await refresh(grant.refreshToken, grant.clientId);
  const other = await refresh(grant.refreshToken, 'client_someone_else');
  assert.equal(other.status, 400);
  assert.equal((await verifyOAuthAccessToken(h.db, first.body.access_token!)).ok, false);
});

test('a replay after the grace window revokes the grant', async () => {
  const grant = await grantWithRefreshToken();
  const first = await refresh(grant.refreshToken, grant.clientId);
  await ageRotations(31);

  const replay = await refresh(grant.refreshToken, grant.clientId);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.equal((await verifyOAuthAccessToken(h.db, first.body.access_token!)).ok, false);
});

test('a replay after the successor was used revokes the grant, even inside the window', async () => {
  // Once the successor has been refreshed, the old token reappearing cannot
  // be a lost response or a racing worker.
  const grant = await grantWithRefreshToken();
  const first = await refresh(grant.refreshToken, grant.clientId);
  const second = await refresh(first.body.refresh_token!, grant.clientId);
  assert.equal(second.status, 200);

  const replay = await refresh(grant.refreshToken, grant.clientId);
  assert.equal(replay.status, 400);
  assert.equal((await verifyOAuthAccessToken(h.db, second.body.access_token!)).ok, false);
});

test('concurrent redemptions of one code yield exactly one token', async () => {
  const authorization = await authorizeAs(h.base);
  const results = await Promise.all(Array.from({ length: 8 }, () => exchange(h.base, authorization)));
  assert.equal(results.filter((r) => r.status === 200).length, 1);
  assert.ok(results.filter((r) => r.status !== 200).every((r) => r.body.error === 'invalid_grant'));
});
