/**
 * What a signed-in person can see and undo about their own account. AC-46.
 *
 * Every application that holds a grant is listed with what it can do and when
 * it last did anything, and each can be cut off on its own. "Sign out
 * everywhere" ends every grant and every browser session at once; so does
 * changing the password, because a password change usually means someone
 * else may have had it.
 */

import type { Db, Queryable } from '../db/index.ts';
import { hashPassword } from '../password.ts';
import { validatePassword, verifyCredentials, getAccount } from '../domain/accounts.ts';
import { AppError } from '../errors.ts';
import { accountRevoked } from '../revocation.ts';
import { FIRST_PARTY_CLIENT_ID, type Scope } from './config.ts';
import { knownClients } from './clients.ts';
import { revokeGrant } from './store.ts';
import { revokeAllAsSessions } from './session.ts';

export interface ConnectedApp {
  grantId: string;
  clientId: string;
  /** What can honestly be said about who this is, without fetching anything. */
  name: string;
  trust: 'verified' | 'unverified';
  /** Where an unverified app sends people, the only thing about it that is certain. */
  destination: string | null;
  scopes: Scope[];
  createdAt: Date;
  lastUsedAt: Date | null;
}

interface GrantRow {
  id: string; client_id: string; scope: string; created_at: Date; last_used_at: Date | null;
  client_name: string | null; redirect_uris: string | null; display_host: string | null;
}

export async function listConnectedApps(db: Queryable, accountId: string): Promise<ConnectedApp[]> {
  const { rows } = await db.query<GrantRow>(
    `SELECT g.id, g.client_id, g.scope, g.created_at, g.last_used_at,
            c.client_name, c.redirect_uris, m.display_host
       FROM oauth_grants g
       LEFT JOIN oauth_clients c ON c.client_id = g.client_id
       LEFT JOIN cimd_cache m ON m.client_id = g.client_id
      WHERE g.account_id = $1 AND g.revoked_at IS NULL
      ORDER BY COALESCE(g.last_used_at, g.created_at) DESC`,
    [accountId]
  );
  const known = knownClients();
  return rows.map((row) => {
    const scopes = row.scope.split(' ').filter((scope) => scope.startsWith('devices:')) as Scope[];
    const base = { grantId: row.id, clientId: row.client_id, scopes, createdAt: row.created_at, lastUsedAt: row.last_used_at };
    if (row.client_id === FIRST_PARTY_CLIENT_ID) {
      return { ...base, name: 'IoT Switch for iPhone', trust: 'verified' as const, destination: null };
    }
    if (row.client_id.startsWith('https://')) {
      return {
        ...base,
        name: row.display_host ?? new URL(row.client_id).host,
        trust: known.has(row.client_id) ? 'verified' as const : 'unverified' as const,
        destination: null
      };
    }
    // Registered dynamically: its name is whatever it said, so the
    // destination is shown beside it.
    const uris = row.redirect_uris ? JSON.parse(row.redirect_uris) as string[] : [];
    return {
      ...base,
      name: row.client_name ?? 'An unnamed application',
      trust: 'unverified' as const,
      destination: uris[0] ? new URL(uris[0]).host || uris[0] : null
    };
  });
}

/** Revokes one of this account's grants. Another account's grant is not found, not refused. */
export async function revokeConnectedApp(db: Db, accountId: string, grantId: string): Promise<boolean> {
  return db.transaction(async (tx) => {
    const { rows } = await tx.query(
      'SELECT id FROM oauth_grants WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL FOR UPDATE',
      [grantId, accountId]
    );
    if (rows.length === 0) return false;
    await revokeGrant(tx, grantId);
    return true;
  });
}

/**
 * Ends every grant (hosts and the iOS app alike) and every
 * authorization-server browser session for this account,
 * in one transaction, then tells every process to drop what it cached.
 */
export async function signOutEverywhere(db: Db, accountId: string): Promise<void> {
  await db.transaction(async (tx) => {
    const { rows } = await tx.query<{ id: string }>(
      'SELECT id FROM oauth_grants WHERE account_id = $1 AND revoked_at IS NULL FOR UPDATE', [accountId]
    );
    for (const { id } of rows) await revokeGrant(tx, id);
    await revokeAllAsSessions(tx, accountId);
  });
  accountRevoked(accountId);
}

/**
 * Changes the password, then signs out everywhere. The caller starts a fresh
 * browser session for the person who just proved they know both passwords.
 */
export async function changePassword(db: Db, accountId: string, current: unknown, next: unknown): Promise<void> {
  const account = await getAccount(db, accountId);
  if (!account) throw new AppError('UNAUTHENTICATED');
  if (!(await verifyCredentials(db, account.username, current))) {
    throw new AppError('VALIDATION_FAILED', 'Your current password is not right.', 'currentPassword');
  }
  const password = validatePassword(next);
  const hashed = await hashPassword(password);
  await db.query(
    'UPDATE accounts SET password_hash = $1, password_pepper_version = $2 WHERE id = $3',
    [hashed.encoded, hashed.pepperVersion, accountId]
  );
  await signOutEverywhere(db, accountId);
}
