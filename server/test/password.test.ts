/**
 * Password storage: Argon2id over an HMAC under a pepper held outside the
 * database.
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
  assert.ok(await verifyPassword(stored.encoded, PASSWORD));
  assert.equal(stored.pepperVersion, 1);
  assert.match(stored.encoded, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/, 'm = 64 MiB, t = 3, p = 1');
});

test('a hash of the bare password, without the pepper, never signs in', async () => {
  const db = await createDb();
  const account = await createAccount(db, 'pepper-user', PASSWORD);
  const unpeppered = await hash(PASSWORD, { algorithm: 2 });
  await db.query('UPDATE accounts SET password_hash = $1 WHERE id = $2', [unpeppered, account.id]);

  // What an attacker holding only the database could produce does not match.
  assert.equal(await verifyCredentials(db, 'pepper-user', PASSWORD), null);
  await db.close();
});
