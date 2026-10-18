/**
 * Password storage: Argon2id over an HMAC under a pepper held outside the
 * database, with hashes from before peppering upgraded on the next sign-in.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { hash } from '@node-rs/argon2';
import { createDb } from '../src/db/index.ts';
import { createAccount, verifyCredentials } from '../src/domain/accounts.ts';
import { hashPassword, verifyPassword } from '../src/password.ts';

const PASSWORD = 'correct horse battery staple';

test('a stored hash cannot be checked without the pepper', async () => {
  const stored = await hashPassword(PASSWORD);
  assert.ok(await verifyPassword(stored.encoded, PASSWORD, stored.pepperVersion));
  // The same password, unpeppered, does not match: the database alone is not enough.
  assert.equal(await verifyPassword(stored.encoded, PASSWORD, null), false);
  assert.match(stored.encoded, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/, 'the plan\'s parameters');
});

test('a hash from before peppering still signs in, and is upgraded', async () => {
  const db = await createDb();
  const account = await createAccount(db, 'legacy-user', PASSWORD);
  const legacy = await hash(PASSWORD, { algorithm: 2 });
  await db.query('UPDATE accounts SET password_hash = $1, password_pepper_version = NULL WHERE id = $2', [legacy, account.id]);

  assert.ok(await verifyCredentials(db, 'legacy-user', PASSWORD));
  const { rows } = await db.query<{ password_hash: string; password_pepper_version: number | null }>(
    'SELECT password_hash, password_pepper_version FROM accounts WHERE id = $1', [account.id]
  );
  assert.equal(rows[0]?.password_pepper_version, 1);
  assert.notEqual(rows[0]?.password_hash, legacy);
  assert.ok(await verifyCredentials(db, 'legacy-user', PASSWORD), 'and still signs in afterwards');
  assert.equal(await verifyCredentials(db, 'legacy-user', 'wrong password entirely'), null);
  await db.close();
});
