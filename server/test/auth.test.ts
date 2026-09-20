import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccount, verifyCredentials } from '../src/domain/accounts.ts';
import { refreshSession, revokeSession, startSession, verifyAccessToken } from '../src/domain/sessions.ts';
import { freshDb, rejectsWithCode } from './helpers.ts';

const PASSWORD = 'correct horse battery staple';

test('sign-up creates one account and rejects a duplicate under folding', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam.smith', PASSWORD);
  assert.equal(account.username, 'sam.smith');

  await rejectsWithCode(() => createAccount(db, 'SAM.SMITH', PASSWORD), 'USERNAME_TAKEN');
  await rejectsWithCode(() => createAccount(db, '  sam.smith  ', PASSWORD), 'USERNAME_TAKEN');

  const { rows } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM accounts');
  assert.equal(rows[0]?.n, 1);
  await db.close();
});

test('usernames and passwords are validated at the boundary', async () => {
  const db = await freshDb();
  await rejectsWithCode(() => createAccount(db, 'ab', PASSWORD), 'VALIDATION_FAILED');
  await rejectsWithCode(() => createAccount(db, 'x'.repeat(33), PASSWORD), 'VALIDATION_FAILED');
  await rejectsWithCode(() => createAccount(db, '.leading', PASSWORD), 'VALIDATION_FAILED');
  await rejectsWithCode(() => createAccount(db, 'trailing-', PASSWORD), 'VALIDATION_FAILED');
  await rejectsWithCode(() => createAccount(db, 'has space', PASSWORD), 'VALIDATION_FAILED');
  await rejectsWithCode(() => createAccount(db, 'valid.name', 'short'), 'VALIDATION_FAILED');
  await db.close();
});

test('a password is stored hashed and never trimmed', async () => {
  const db = await freshDb();
  const padded = '  spaces matter  ';
  await createAccount(db, 'sam', padded);

  const { rows } = await db.query<{ password_hash: string }>('SELECT password_hash FROM accounts');
  assert.ok(rows[0]?.password_hash.startsWith('$argon2id$'), 'argon2id, with parameters embedded');
  assert.ok(!rows[0]?.password_hash.includes('spaces'), 'the password itself is not recoverable');

  assert.ok(await verifyCredentials(db, 'sam', padded));
  assert.equal(await verifyCredentials(db, 'sam', padded.trim()), null, 'trimming would change the password');
  await db.close();
});

test('credential verification is case-insensitive on the username only', async () => {
  const db = await freshDb();
  await createAccount(db, 'Sam', PASSWORD);
  assert.ok(await verifyCredentials(db, 'sam', PASSWORD));
  assert.ok(await verifyCredentials(db, 'SAM', PASSWORD));
  assert.equal(await verifyCredentials(db, 'sam', PASSWORD.toUpperCase()), null);
  assert.equal(await verifyCredentials(db, 'nobody', PASSWORD), null);
  await db.close();
});

test('an access token resolves to its account', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const tokens = await startSession(db, account.id);

  const verified = await verifyAccessToken(db, tokens.accessToken);
  assert.equal(verified?.accountId, account.id);
  assert.equal(await verifyAccessToken(db, 'not-a-token'), null);
  assert.equal(await verifyAccessToken(db, null), null);
  await db.close();
});

test('tokens are stored hashed, not in the clear', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const tokens = await startSession(db, account.id);

  const stored = await db.query<{ token_hash: string }>('SELECT token_hash FROM access_tokens');
  assert.notEqual(stored.rows[0]?.token_hash, tokens.accessToken);

  const refresh = await db.query<{ refresh_token_hash: string }>('SELECT refresh_token_hash FROM sessions');
  assert.notEqual(refresh.rows[0]?.refresh_token_hash, tokens.refreshToken);
  await db.close();
});

test('logout invalidates access tokens that were already issued', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const tokens = await startSession(db, account.id);
  const session = await verifyAccessToken(db, tokens.accessToken);
  assert.ok(session);

  await revokeSession(db, session.sessionId);

  // Spec section 7.2: a token minted before logout must stop working at once,
  // which is why validation resolves against the session on every request.
  assert.equal(await verifyAccessToken(db, tokens.accessToken), null);
  await rejectsWithCode(() => refreshSession(db, tokens.refreshToken), 'UNAUTHENTICATED');
  await db.close();
});

test('refreshing rotates the refresh token and retires the old one', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const first = await startSession(db, account.id);

  const second = await refreshSession(db, first.refreshToken);
  assert.notEqual(second.refreshToken, first.refreshToken);
  assert.ok(await verifyAccessToken(db, second.accessToken));

  await rejectsWithCode(() => refreshSession(db, first.refreshToken), 'UNAUTHENTICATED');
  await db.close();
});

test('replaying a rotated refresh token revokes the whole family', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const first = await startSession(db, account.id);
  const second = await refreshSession(db, first.refreshToken);

  // A legitimate client never replays a rotated token, so this is treated as
  // theft: everything descended from it goes, including the token the thief
  // did not steal.
  await rejectsWithCode(() => refreshSession(db, first.refreshToken), 'UNAUTHENTICATED');

  assert.equal(await verifyAccessToken(db, second.accessToken), null, 'the live session is revoked too');
  await rejectsWithCode(() => refreshSession(db, second.refreshToken), 'UNAUTHENTICATED');
  await db.close();
});

test('separate sessions for one account are independent', async () => {
  const db = await freshDb();
  const account = await createAccount(db, 'sam', PASSWORD);
  const phone = await startSession(db, account.id);
  const laptop = await startSession(db, account.id);

  const phoneSession = await verifyAccessToken(db, phone.accessToken);
  await revokeSession(db, phoneSession!.sessionId);

  assert.equal(await verifyAccessToken(db, phone.accessToken), null);
  assert.ok(await verifyAccessToken(db, laptop.accessToken), 'logging out one device is not logging out all');
  await db.close();
});
