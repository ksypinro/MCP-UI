/**
 * Session lifecycle for the first-party app. Spec sections 7.1 and 7.2.
 *
 * Access tokens are opaque random strings, stored hashed, and every protected
 * request resolves one against the sessions table. That is the cost of the
 * requirement that logout invalidates access tokens already issued: a signed
 * token validated only by signature and expiry cannot be withdrawn, so this
 * lookup is on the hot path by design rather than by accident.
 *
 * Refresh tokens rotate. Each refresh appends a row to the same family and
 * marks the old one replaced. Presenting a token that was already replaced
 * means it leaked, so the entire family is revoked rather than just that row.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { Db, Queryable } from '../db/index.ts';
import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS } from '../config.ts';
import { AppError } from '../errors.ts';

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  /** Seconds until the access token expires. */
  expiresIn: number;
}

export interface VerifiedSession {
  accountId: string;
  sessionId: string;
}

function newToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * SHA-256, not Argon2. These are 256-bit random values, not user-chosen
 * secrets: there is nothing to brute-force, and a slow hash on every request
 * would buy nothing while costing latency.
 */
function fingerprint(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

async function issueAccessToken(tx: Queryable, sessionId: string, accountId: string): Promise<string> {
  const token = newToken();
  await tx.query(
    `INSERT INTO access_tokens (token_hash, session_id, account_id, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
    [fingerprint(token), sessionId, accountId, ACCESS_TOKEN_TTL_SECONDS]
  );
  return token;
}

/** Starts a new session family. Used by sign-up and log-in. */
export async function startSession(db: Db, accountId: string): Promise<SessionTokens> {
  return db.transaction(async (tx) => {
    const sessionId = `ses_${randomBytes(9).toString('base64url')}`;
    const refreshToken = newToken();

    await tx.query(
      `INSERT INTO sessions (id, account_id, family_id, refresh_token_hash, expires_at)
       VALUES ($1, $2, $1, $3, now() + make_interval(secs => $4))`,
      [sessionId, accountId, fingerprint(refreshToken), REFRESH_TOKEN_TTL_SECONDS]
    );

    const accessToken = await issueAccessToken(tx, sessionId, accountId);
    return { accessToken, refreshToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS };
  });
}

/**
 * Resolves a bearer token to an identity, or null.
 *
 * The join is the point: a revoked or expired session invalidates every access
 * token issued under it, without having to find and delete them.
 */
export async function verifyAccessToken(db: Queryable, token: string | null): Promise<VerifiedSession | null> {
  if (!token) return null;
  const { rows } = await db.query<{ account_id: string; session_id: string }>(
    `SELECT t.account_id, t.session_id
       FROM access_tokens t
       JOIN sessions s ON s.id = t.session_id
      WHERE t.token_hash = $1
        AND t.expires_at > now()
        AND s.revoked_at IS NULL
        AND s.expires_at > now()`,
    [fingerprint(token)]
  );
  const row = rows[0];
  return row ? { accountId: row.account_id, sessionId: row.session_id } : null;
}

interface SessionRow {
  id: string;
  account_id: string;
  family_id: string;
  revoked_at: Date | null;
  replaced_by: string | null;
  expired: boolean;
}

export async function refreshSession(db: Db, refreshToken: unknown): Promise<SessionTokens> {
  if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
    throw new AppError('UNAUTHENTICATED', 'That session could not be refreshed.');
  }

  type Outcome =
    | { ok: true; tokens: SessionTokens }
    | { ok: false; reason: 'unknown' }
    | { ok: false; reason: 'reuse'; familyId: string };

  const outcome = await db.transaction<Outcome>(async (tx) => {
    const { rows } = await tx.query<SessionRow>(
      `SELECT id, account_id, family_id, revoked_at, replaced_by, (expires_at <= now()) AS expired
         FROM sessions WHERE refresh_token_hash = $1 FOR UPDATE`,
      [fingerprint(refreshToken)]
    );
    const session = rows[0];
    if (!session) return { ok: false, reason: 'unknown' };

    // This token was already exchanged. A legitimate client never replays a
    // rotated refresh token, so treat it as a leak. The revocation itself
    // happens after this transaction: performing it here would roll back
    // along with the refusal, and a theft would be detected and then quietly
    // forgiven.
    if (session.replaced_by !== null) {
      return { ok: false, reason: 'reuse', familyId: session.family_id };
    }

    if (session.revoked_at !== null || session.expired) {
      return { ok: false, reason: 'unknown' };
    }

    const nextId = `ses_${randomBytes(9).toString('base64url')}`;
    const nextRefresh = newToken();

    await tx.query(
      `INSERT INTO sessions (id, account_id, family_id, refresh_token_hash, expires_at)
       VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
      [nextId, session.account_id, session.family_id, fingerprint(nextRefresh), REFRESH_TOKEN_TTL_SECONDS]
    );
    // Marked replaced, but deliberately NOT revoked. Revoking here would kill
    // the outgoing access token the instant the refresh lands, so a client
    // that refreshes proactively — the ordinary pattern with 15-minute access
    // tokens — would fail every request it already had in flight. The old
    // access token expires on its own in minutes; the old refresh token is
    // already dead because replaced_by is set, and logout or detected reuse
    // still revokes the entire family.
    await tx.query('UPDATE sessions SET replaced_by = $1 WHERE id = $2', [nextId, session.id]);

    const accessToken = await issueAccessToken(tx, nextId, session.account_id);
    return { ok: true, tokens: { accessToken, refreshToken: nextRefresh, expiresIn: ACCESS_TOKEN_TTL_SECONDS } };
  });

  if (outcome.ok) return outcome.tokens;

  if (outcome.reason === 'reuse') {
    await db.transaction((tx) => revokeFamily(tx, outcome.familyId));
    throw new AppError('UNAUTHENTICATED', 'That session was revoked. Sign in again.');
  }

  throw new AppError('UNAUTHENTICATED', 'That session could not be refreshed.');
}

/**
 * Log out. Revokes the whole family, not just the current row: spec section
 * 7.1 revokes "the current first-party session and its refresh credentials",
 * and the rotated ancestors of this session are the same credential.
 */
export async function revokeSession(db: Db, sessionId: string): Promise<void> {
  await db.transaction(async (tx) => {
    const { rows } = await tx.query<{ family_id: string }>(
      'SELECT family_id FROM sessions WHERE id = $1',
      [sessionId]
    );
    const familyId = rows[0]?.family_id;
    if (familyId) await revokeFamily(tx, familyId);
  });
}

async function revokeFamily(tx: Queryable, familyId: string): Promise<void> {
  await tx.query(
    'UPDATE sessions SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL',
    [familyId]
  );
}

/**
 * Deletes what has already expired. Both tables are on the hot path — every
 * protected request joins them — so without a sweep the index behind that join
 * grows with uptime rather than with load, and latency degrades quietly.
 *
 * Returns the row counts so a caller can log or test them.
 */
export async function pruneExpired(db: Db): Promise<{ accessTokens: number; sessions: number }> {
  const tokens = await db.query('DELETE FROM access_tokens WHERE expires_at <= now()');
  // Only sessions that can no longer be refreshed by anyone. A revoked session
  // is kept until its window closes so that reuse of its refresh token is
  // still recognised as reuse rather than as an unknown token.
  const sessions = await db.query('DELETE FROM sessions WHERE expires_at <= now()');
  return { accessTokens: tokens.affectedRows, sessions: sessions.affectedRows };
}
