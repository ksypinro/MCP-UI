/**
 * The authorization server's own browser session.
 *
 * Distinct from every token it issues: it exists only so that a person who
 * has just signed in is not asked for a password again while approving a
 * second application, and so that consent can require a recent sign-in.
 * It is never accepted anywhere but on the authorization server's pages.
 *
 * Idle for 30 minutes or older than 12 hours, it is gone. Stored as a keyed
 * hash, like every other credential.
 */

import type { Queryable } from '../db/index.ts';
import { mint, wellFormed } from '../tokens/format.ts';
import { tokenDigest, tokenDigestCandidates } from '../tokens/hash.ts';

export const AS_SESSION_IDLE_SECONDS = 30 * 60;
export const AS_SESSION_ABSOLUTE_SECONDS = 12 * 3600;

export interface AsSession {
  accountId: string;
  /** When the person last proved who they are. Consent to write scopes needs it recent. */
  authTime: Date;
  /** Seconds since authTime, computed by the database clock. */
  authAgeSeconds: number;
  acr: string;
}

export async function startAsSession(db: Queryable, accountId: string, acr: string): Promise<string> {
  const token = mint('session');
  await db.query(
    `INSERT INTO as_sessions (id_hash, account_id, auth_time, acr, idle_expires_at, absolute_expires_at)
     VALUES ($1, $2, now(), $3, now() + make_interval(secs => $4), now() + make_interval(secs => $5))`,
    [tokenDigest(token), accountId, acr, AS_SESSION_IDLE_SECONDS, AS_SESSION_ABSOLUTE_SECONDS]
  );
  return token;
}

/** The live session for this cookie value, extending its idle window, or null. */
export async function readAsSession(db: Queryable, token: unknown): Promise<AsSession | null> {
  if (!wellFormed('session', token)) return null;
  const { rows } = await db.query<{ account_id: string; auth_time: Date; acr: string; auth_age: number }>(
    `UPDATE as_sessions
        SET idle_expires_at = LEAST(now() + make_interval(secs => $2), absolute_expires_at)
      WHERE id_hash = ANY($1::text[])
        AND revoked_at IS NULL
        AND idle_expires_at > now()
        AND absolute_expires_at > now()
      RETURNING account_id, auth_time, acr,
                EXTRACT(EPOCH FROM (now() - auth_time))::int AS auth_age`,
    [tokenDigestCandidates(token), AS_SESSION_IDLE_SECONDS]
  );
  const row = rows[0];
  return row
    ? { accountId: row.account_id, authTime: new Date(row.auth_time), authAgeSeconds: row.auth_age, acr: row.acr }
    : null;
}

export async function revokeAsSession(db: Queryable, token: unknown): Promise<void> {
  if (!wellFormed('session', token)) return;
  await db.query(
    'UPDATE as_sessions SET revoked_at = now() WHERE id_hash = ANY($1::text[]) AND revoked_at IS NULL',
    [tokenDigestCandidates(token)]
  );
}

/** Every session for an account, for "sign out everywhere" and password changes. */
export async function revokeAllAsSessions(db: Queryable, accountId: string): Promise<void> {
  await db.query(
    'UPDATE as_sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL',
    [accountId]
  );
}
