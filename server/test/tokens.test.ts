/**
 * Token format and storage: typed, checksummed, and stored only as keyed
 * hashes under a pepper that lives outside the database.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mint, wellFormed, TOKEN_PATTERN } from '../src/tokens/format.ts';
import { tokenDigest, tokenDigestCandidates } from '../src/tokens/hash.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { authorizeAs, exchange, startServer, type Harness } from './oauth-helpers.ts';
import { callTool } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

test('a token names its kind and carries a checksum', () => {
  const token = mint('access');
  assert.match(token, /^iotsw_at_[A-Za-z0-9_-]{43}[0-9A-Za-z]{6}$/);
  assert.ok(wellFormed('access', token));
  assert.equal(wellFormed('refresh', token), false, 'one kind is never accepted as another');

  // Any single changed character fails the checksum.
  const index = 20;
  const flipped = token.slice(0, index) + (token[index] === 'A' ? 'B' : 'A') + token.slice(index + 1);
  assert.equal(wellFormed('access', flipped), false);
  assert.equal(wellFormed('access', 'Bearer nonsense'), false);

  assert.deepEqual(`log line ${token} end`.match(TOKEN_PATTERN), [token], 'the scrubber pattern finds it');
});

test('tokens are stored only as keyed hashes', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);
  const access = body.access_token!;

  const { rows } = await h.db.query<{ token_hash: string }>('SELECT token_hash FROM oauth_access_tokens');
  const stored = new Set(rows.map((row) => row.token_hash));
  assert.ok(stored.has(tokenDigest(access)));
  assert.equal(
    stored.has(createHash('sha256').update(access).digest('hex')), false,
    'a plain hash of the token is not in the database'
  );
});

test('a refresh token presented as an access token is refused', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);
  const response = await callTool(h.base, 'list_devices', {}, body.refresh_token);
  assert.equal(response.status, 401);
});

test('tokens issued under a retired pepper keep working until they expire', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);
  const before = tokenDigestCandidates(body.access_token!);
  assert.equal(before.length, 1);

  const { reloadKeysForRotation } = await import('../src/security/keys.ts');
  const { keys } = await import('../src/security/keys.ts');
  const current = keys();
  process.env.TOKEN_PEPPERS = `2:${Buffer.alloc(32, 7).toString('base64')},1:${current.tokenPeppers[0]!.key.toString('base64')}`;
  process.env.PASSWORD_PEPPER = `1:${current.passwordPepper.key.toString('base64')}`;
  process.env.INTERNAL_MAC_KEY = current.internalMacKey.toString('base64');
  try {
    reloadKeysForRotation();
    assert.notEqual(tokenDigest(body.access_token!), before[0], 'new tokens use the new pepper');
    assert.ok((await verifyOAuthAccessToken(h.db, body.access_token!)).ok, 'the old token still verifies');
  } finally {
    delete process.env.TOKEN_PEPPERS;
    delete process.env.PASSWORD_PEPPER;
    delete process.env.INTERNAL_MAC_KEY;
  }
});
