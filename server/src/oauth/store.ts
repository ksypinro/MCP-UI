/** Persistence for the authorization server. */

import type { Db, Queryable } from '../db/index.ts';
import { fingerprint, newId, newSecret } from './crypto.ts';
import {
  AUTHORIZATION_CODE_TTL_SECONDS, OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_REFRESH_TOKEN_TTL_SECONDS, PENDING_AUTHORIZATION_TTL_SECONDS, type Scope
} from './config.ts';

export interface PendingAuthorization {
  id: string;
  clientId: string;
  clientHost: string;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string;
  scopes: Scope[];
}

export async function createPendingAuthorization(
  db: Queryable, pending: Omit<PendingAuthorization, 'id'>
): Promise<string> {
  const id = newId('pa');
  await db.query(
    `INSERT INTO oauth_pending_authorizations
       (id, client_id, client_host, redirect_uri, state, code_challenge, resource, scope, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))`,
    [
      id, pending.clientId, pending.clientHost, pending.redirectUri, pending.state,
      pending.codeChallenge, pending.resource, pending.scopes.join(' '),
      PENDING_AUTHORIZATION_TTL_SECONDS
    ]
  );
  return id;
}

export async function readPendingAuthorization(
  db: Queryable, id: unknown
): Promise<PendingAuthorization | null> {
  if (typeof id !== 'string' || id.length === 0) return null;
  const { rows } = await db.query<{
    id: string; client_id: string; client_host: string; redirect_uri: string;
    state: string | null; code_challenge: string; resource: string; scope: string;
  }>(
    `SELECT id, client_id, client_host, redirect_uri, state, code_challenge, resource, scope
       FROM oauth_pending_authorizations
      WHERE id = $1 AND expires_at > now()`,
    [id]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    clientId: row.client_id,
    clientHost: row.client_host,
    redirectUri: row.redirect_uri,
    state: row.state,
    codeChallenge: row.code_challenge,
    resource: row.resource,
    scopes: row.scope.split(' ').filter(Boolean) as Scope[]
  };
}

export async function deletePendingAuthorization(db: Queryable, id: string): Promise<void> {
  await db.query('DELETE FROM oauth_pending_authorizations WHERE id = $1', [id]);
}

/* ------------------------------------------------------------------ codes */

/**
 * Claims the pending authorization and mints its code in one transaction.
 *
 * Returns null when someone else already claimed it. Doing these as two
 * statements leaves a window where two submissions of the same authorization
 * each mint a valid code.
 */
export async function claimAndIssueCode(
  db: Db, accountId: string, pending: PendingAuthorization
): Promise<string | null> {
  return db.transaction(async (tx) => {
    const claimed = await tx.query<{ id: string }>(
      'DELETE FROM oauth_pending_authorizations WHERE id = $1 RETURNING id',
      [pending.id]
    );
    if (claimed.rows.length !== 1) return null;
    return issueAuthorizationCode(tx, accountId, pending);
  });
}

async function issueAuthorizationCode(
  db: Queryable, accountId: string, pending: PendingAuthorization
): Promise<string> {
  const code = newSecret();
  await db.query(
    `INSERT INTO oauth_authorization_codes
       (code_hash, account_id, client_id, redirect_uri, code_challenge, resource, scope, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))`,
    [
      fingerprint(code), accountId, pending.clientId, pending.redirectUri,
      pending.codeChallenge, pending.resource, pending.scopes.join(' '),
      AUTHORIZATION_CODE_TTL_SECONDS
    ]
  );
  return code;
}

export interface AuthorizationCodeRecord {
  accountId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  scope: string;
  alreadyConsumed: boolean;
  expired: boolean;
  /** Set only if this code was successfully exchanged for a grant. */
  grantId: string | null;
}

interface CodeRow {
  account_id: string; client_id: string; redirect_uri: string; code_challenge: string;
  resource: string; scope: string; grant_id: string | null;
}

/**
 * Marks the code consumed and returns what it was. A code that was already
 * consumed is still returned, flagged, so the caller can treat replay as the
 * attack it probably is rather than as an unknown code.
 *
 * "First one wins" is a property of the statement itself: only a caller whose
 * UPDATE finds `consumed_at IS NULL` gets an unflagged record. An earlier
 * version compared `consumed_at < now()` afterwards, which is only safe while
 * statements run one at a time; on a Postgres server two concurrent
 * redemptions could both see the code as fresh.
 */
export async function consumeAuthorizationCode(
  db: Queryable, code: unknown
): Promise<AuthorizationCodeRecord | null> {
  if (typeof code !== 'string' || code.length === 0) return null;
  const hash = fingerprint(code);

  const { rows } = await db.query<CodeRow>(
    `UPDATE oauth_authorization_codes
        SET consumed_at = now()
      WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > now()
      RETURNING account_id, client_id, redirect_uri, code_challenge, resource, scope, grant_id`,
    [hash]
  );
  const fresh = rows[0];
  if (fresh) return toCodeRecord(fresh, false, false);

  // Nothing flipped: the code is unknown, expired, or already spent. Only a
  // read tells them apart.
  const { rows: misses } = await db.query<CodeRow & { already_consumed: boolean; expired: boolean }>(
    `SELECT account_id, client_id, redirect_uri, code_challenge, resource, scope, grant_id,
            (consumed_at IS NOT NULL) AS already_consumed,
            (expires_at <= now()) AS expired
       FROM oauth_authorization_codes WHERE code_hash = $1`,
    [hash]
  );
  const miss = misses[0];
  return miss ? toCodeRecord(miss, miss.already_consumed, miss.expired) : null;
}

function toCodeRecord(row: CodeRow, alreadyConsumed: boolean, expired: boolean): AuthorizationCodeRecord {
  return {
    accountId: row.account_id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    resource: row.resource,
    scope: row.scope,
    alreadyConsumed,
    expired,
    grantId: row.grant_id
  };
}

/* ----------------------------------------------------------------- grants */

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
}

export async function issueTokens(
  db: Queryable, grantId: string, audience: string, scope: string
): Promise<IssuedTokens> {
  const accessToken = newSecret();
  const refreshToken = newSecret();

  await db.query(
    `INSERT INTO oauth_access_tokens (token_hash, grant_id, audience, scope, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
    [fingerprint(accessToken), grantId, audience, scope, OAUTH_ACCESS_TOKEN_TTL_SECONDS]
  );
  await db.query(
    `INSERT INTO oauth_refresh_tokens (token_hash, grant_id, audience, scope, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
    [fingerprint(refreshToken), grantId, audience, scope, OAUTH_REFRESH_TOKEN_TTL_SECONDS]
  );

  return {
    accessToken, refreshToken,
    expiresIn: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
    scope
  };
}

/**
 * Revokes a grant and everything it issued. Takes a Queryable so it can run
 * inside a caller's transaction; use revokeGrantNow when there is none, so the
 * three statements cannot be left half-applied.
 */
export async function revokeGrant(db: Queryable, grantId: string): Promise<void> {
  await db.query('UPDATE oauth_grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL', [grantId]);
  await db.query('DELETE FROM oauth_access_tokens WHERE grant_id = $1', [grantId]);
  await db.query(
    'UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL',
    [grantId]
  );
}

export async function revokeGrantNow(db: Db, grantId: string): Promise<void> {
  await db.transaction((tx) => revokeGrant(tx, grantId));
}

/* --------------------------------------------------------- refresh tokens */

export interface RefreshTokenRecord {
  tokenHash: string;
  grantId: string;
  accountId: string;
  clientId: string;
  audience: string;
  scope: string;
  alreadyReplaced: boolean;
  revoked: boolean;
  expired: boolean;
  grantRevoked: boolean;
}

export async function readRefreshToken(
  db: Queryable, token: unknown
): Promise<RefreshTokenRecord | null> {
  if (typeof token !== 'string' || token.length === 0) return null;
  const { rows } = await db.query<{
    token_hash: string; grant_id: string; account_id: string; client_id: string;
    audience: string; scope: string; already_replaced: boolean; revoked: boolean;
    expired: boolean; grant_revoked: boolean;
  }>(
    `SELECT r.token_hash, r.grant_id, g.account_id, g.client_id, r.audience, r.scope,
            (r.replaced_by IS NOT NULL) AS already_replaced,
            (r.revoked_at IS NOT NULL) AS revoked,
            (r.expires_at <= now()) AS expired,
            (g.revoked_at IS NOT NULL) AS grant_revoked
       FROM oauth_refresh_tokens r
       JOIN oauth_grants g ON g.id = r.grant_id
      WHERE r.token_hash = $1`,
    [fingerprint(token)]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    tokenHash: row.token_hash, grantId: row.grant_id, accountId: row.account_id,
    clientId: row.client_id, audience: row.audience, scope: row.scope,
    alreadyReplaced: row.already_replaced, revoked: row.revoked,
    expired: row.expired, grantRevoked: row.grant_revoked
  };
}

export type RefreshOutcome =
  | { kind: 'rotated'; issued: IssuedTokens }
  /** A duplicate inside the grace window: answer with the sealed response. */
  | { kind: 'replay' }
  /** A rotated token presented outside the window. The grant is now revoked. */
  | { kind: 'theft' }
  | { kind: 'invalid'; reason: 'unknown' | 'dead' | 'wrong_client' }
  | { kind: 'invalid_target' }
  | { kind: 'invalid_scope' };

interface LockedRefreshRow {
  token_hash: string; grant_id: string; audience: string; scope: string; replaced_by: string | null;
  client_id: string; revoked: boolean; expired: boolean; grant_revoked: boolean;
  within_grace: boolean; successor_used: boolean;
}

/**
 * Rotates a refresh token: lock, decide, issue, retire — one transaction.
 *
 * Reading the token outside the transaction that rotates it let concurrent
 * refreshes interleave: on PGlite every race tripped reuse detection and
 * revoked the grant, and on a Postgres server two of them could both rotate
 * and fork the family. The row lock queues concurrent callers; the guarded
 * UPDATE retires the token at most once even if the lock were ever lost.
 *
 * A token that was already rotated is benign only if it is presented again
 * within `graceSeconds`, by the same client, before its successor has itself
 * been used. The caller then answers with the response it sealed the first
 * time (see sealed.ts). Anything else is treated as theft, and the whole grant
 * is revoked inside this transaction so the refusal cannot roll it back.
 *
 * `seal` runs inside the transaction, before commit, so a concurrent duplicate
 * that queues on the row lock always finds the response already sealed.
 */
export async function rotateRefresh(
  db: Db,
  presented: unknown,
  request: {
    clientId: string; resource: unknown; scope: unknown; graceSeconds: number;
    seal: (issued: IssuedTokens) => void;
  }
): Promise<RefreshOutcome> {
  if (typeof presented !== 'string' || presented.length === 0) return { kind: 'invalid', reason: 'unknown' };

  return db.transaction<RefreshOutcome>(async (tx) => {
    const { rows } = await tx.query<LockedRefreshRow>(
      `SELECT r.token_hash, r.grant_id, r.audience, r.scope, r.replaced_by, g.client_id,
              (r.revoked_at IS NOT NULL) AS revoked,
              (r.expires_at <= now()) AS expired,
              (g.revoked_at IS NOT NULL) AS grant_revoked,
              (r.replaced_at IS NOT NULL
                 AND r.replaced_at > now() - make_interval(secs => $2)) AS within_grace,
              EXISTS (SELECT 1 FROM oauth_refresh_tokens s
                       WHERE s.token_hash = r.replaced_by
                         AND (s.replaced_by IS NOT NULL OR s.revoked_at IS NOT NULL)) AS successor_used
         FROM oauth_refresh_tokens r
         JOIN oauth_grants g ON g.id = r.grant_id
        WHERE r.token_hash = $1
          FOR UPDATE OF r`,
      [fingerprint(presented), request.graceSeconds]
    );
    const row = rows[0];
    if (!row) return { kind: 'invalid', reason: 'unknown' };

    if (row.replaced_by !== null) {
      if (row.grant_revoked) return { kind: 'invalid', reason: 'dead' };
      if (row.within_grace && !row.successor_used && row.client_id === request.clientId) {
        return { kind: 'replay' };
      }
      // A legitimate client never replays a rotated token outside the window,
      // so take down the whole grant — including the token the thief did not
      // steal.
      await revokeGrant(tx, row.grant_id);
      return { kind: 'theft' };
    }

    if (row.revoked || row.grant_revoked || row.expired) return { kind: 'invalid', reason: 'dead' };
    if (row.client_id !== request.clientId) return { kind: 'invalid', reason: 'wrong_client' };
    if (request.resource !== undefined && request.resource !== row.audience) return { kind: 'invalid_target' };

    // A refresh may narrow scope but never widen it (RFC 6749 section 6).
    let scope = row.scope;
    if (typeof request.scope === 'string' && request.scope.trim().length > 0) {
      const granted = row.scope.split(' ').filter(Boolean);
      const requested = request.scope.split(/\s+/).filter(Boolean);
      if (requested.some((entry) => !granted.includes(entry))) return { kind: 'invalid_scope' };
      scope = requested.join(' ');
    }

    const issued = await issueTokens(tx, row.grant_id, row.audience, scope);
    await tx.query(
      `UPDATE oauth_refresh_tokens SET replaced_by = $1, replaced_at = now()
        WHERE token_hash = $2 AND replaced_by IS NULL`,
      [fingerprint(issued.refreshToken), row.token_hash]
    );
    request.seal(issued);
    return { kind: 'rotated', issued };
  });
}

/**
 * Creates the grant, records it against the code, and issues the first token
 * pair — all or nothing.
 *
 * Split across statements, a failure part way leaves either a grant with no
 * tokens, or a grant whose code carries no grant_id, which silently disarms
 * the replay protection for that code.
 */
export async function establishGrant(
  db: Db,
  options: { code: string; accountId: string; clientId: string; resource: string; scope: string }
): Promise<IssuedTokens> {
  return db.transaction(async (tx) => {
    const grantId = newId('grant');
    await tx.query(
      `INSERT INTO oauth_grants (id, account_id, client_id, resource, scope)
       VALUES ($1, $2, $3, $4, $5)`,
      [grantId, options.accountId, options.clientId, options.resource, options.scope]
    );
    await tx.query(
      'UPDATE oauth_authorization_codes SET grant_id = $1 WHERE code_hash = $2',
      [grantId, fingerprint(options.code)]
    );
    return issueTokens(tx, grantId, options.resource, options.scope);
  });
}

export async function revokeByRefreshToken(db: Db, token: string): Promise<void> {
  const record = await readRefreshToken(db, token);
  if (record) await revokeGrantNow(db, record.grantId);
}

export async function revokeByAccessToken(db: Db, token: string): Promise<void> {
  const { rows } = await db.query<{ grant_id: string }>(
    'SELECT grant_id FROM oauth_access_tokens WHERE token_hash = $1',
    [fingerprint(token)]
  );
  const grantId = rows[0]?.grant_id;
  if (grantId) await revokeGrantNow(db, grantId);
}

/** Deletes what has expired. Both tables are read on every protected call. */
export async function pruneExpiredOAuth(db: Db): Promise<void> {
  await db.query('DELETE FROM oauth_access_tokens WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_authorization_codes WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_pending_authorizations WHERE expires_at <= now()');
}
