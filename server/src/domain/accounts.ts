/**
 * Registration and credential verification. Spec sections 4.1 and 7.1.
 */

import { randomBytes } from 'node:crypto';
import type { Db, Queryable } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { normalizeUsername } from '../normalize.ts';
import { hashPassword, verifyPassword } from '../password.ts';
import { PASSWORD_MAX, PASSWORD_MIN, USERNAME_MAX, USERNAME_MIN } from '../config.ts';
import type { Account } from './types.ts';

interface AccountRow {
  id: string;
  username: string;
  password_hash: string;
  created_at: Date;
}

/**
 * ASCII only, and bounded at both ends by an alphanumeric.
 *
 * Restricting the character set is what makes the case-fold in normalize.ts
 * deterministic and homograph collisions impossible. Widening it later needs a
 * confusable-detection policy, not just a bigger regex.
 */
const USERNAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;

function toAccount(row: AccountRow): Account {
  return {
    id: row.id,
    username: row.username,
    createdAt: new Date(row.created_at).toISOString()
  };
}

export function validateUsername(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new AppError('VALIDATION_FAILED', 'Username is required.', 'username');
  }
  const username = raw.trim();
  if (username.length < USERNAME_MIN || username.length > USERNAME_MAX) {
    throw new AppError(
      'VALIDATION_FAILED',
      `Username must be between ${USERNAME_MIN} and ${USERNAME_MAX} characters.`,
      'username'
    );
  }
  if (!USERNAME_PATTERN.test(username)) {
    throw new AppError(
      'VALIDATION_FAILED',
      'Username may use letters, digits, dots, underscores and hyphens, and must start and end with a letter or digit.',
      'username'
    );
  }
  return username;
}

export function validatePassword(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new AppError('VALIDATION_FAILED', 'Password is required.', 'password');
  }
  // Deliberately not trimmed: leading and trailing spaces are legitimate
  // characters in a generated password, and silently removing them makes a
  // password that cannot be typed back in.
  if (raw.length < PASSWORD_MIN || raw.length > PASSWORD_MAX) {
    throw new AppError(
      'VALIDATION_FAILED',
      `Password must be between ${PASSWORD_MIN} and ${PASSWORD_MAX} characters.`,
      'password'
    );
  }
  return raw;
}

export async function createAccount(db: Db, rawUsername: unknown, rawPassword: unknown): Promise<Account> {
  const username = validateUsername(rawUsername);
  const password = validatePassword(rawPassword);
  const normalized = normalizeUsername(username);
  const passwordHash = await hashPassword(password);

  // Same reasoning as devices: let the unique index decide the winner, so two
  // simultaneous sign-ups for one name cannot both succeed.
  const { rows } = await db.query<AccountRow>(
    `INSERT INTO accounts (id, username, normalized_username, password_hash)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (normalized_username) DO NOTHING
     RETURNING id, username, password_hash, created_at`,
    [`acc_${randomBytes(9).toString('base64url')}`, username, normalized, passwordHash]
  );

  const row = rows[0];
  if (!row) throw new AppError('USERNAME_TAKEN', undefined, 'username');
  return toAccount(row);
}

/**
 * Returns null for both an unknown username and a wrong password. The caller
 * must not tell them apart either: spec section 7.2 requires one generic
 * failure, or the endpoint enumerates accounts.
 */
export async function verifyCredentials(
  db: Queryable,
  rawUsername: unknown,
  rawPassword: unknown
): Promise<Account | null> {
  if (typeof rawUsername !== 'string' || typeof rawPassword !== 'string') return null;

  const { rows } = await db.query<AccountRow>(
    'SELECT id, username, password_hash, created_at FROM accounts WHERE normalized_username = $1',
    [normalizeUsername(rawUsername)]
  );

  const row = rows[0];
  if (!row) {
    // Spend comparable time on an unknown username so that response timing
    // does not reveal which accounts exist. The decoy is a genuine hash
    // produced by the same function: a hand-written literal risks being
    // unparseable, in which case verify throws, returns immediately, and the
    // defence is silently absent precisely when it is needed.
    await verifyPassword(await decoyHash(), rawPassword);
    return null;
  }

  return (await verifyPassword(row.password_hash, rawPassword)) ? toAccount(row) : null;
}

let decoy: Promise<string> | null = null;
function decoyHash(): Promise<string> {
  decoy ??= hashPassword(randomBytes(32).toString('hex'));
  return decoy;
}

export async function getAccount(db: Queryable, accountId: string): Promise<Account | null> {
  const { rows } = await db.query<AccountRow>(
    'SELECT id, username, password_hash, created_at FROM accounts WHERE id = $1',
    [accountId]
  );
  const row = rows[0];
  return row ? toAccount(row) : null;
}
