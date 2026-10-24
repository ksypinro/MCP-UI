/** Accounts: sign-up rules, username folding and password checks. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccount, verifyCredentials } from '../src/domain/accounts.ts';
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
