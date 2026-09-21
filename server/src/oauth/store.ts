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

/**
 * Marks the code consumed and returns what it was. A code that was already
 * consumed is still returned, flagged, so the caller can treat replay as the
 * attack it probably is rather than as an unknown code.
 */
export async function consumeAuthorizationCode(
  db: Queryable, code: unknown
): Promise<AuthorizationCodeRecord | null> {
  if (typeof code !== 'string' || code.length === 0) return null;
  const { rows } = await db.query<{
    account_id: string; client_id: string; redirect_uri: string; code_challenge: string;
    resource: string; scope: string; already_consumed: boolean; expired: boolean;
    grant_id: string | null;
  }>(
    `UPDATE oauth_authorization_codes
        SET consumed_at = COALESCE(consumed_at, now())
      WHERE code_hash = $1
      RETURNING account_id, client_id, redirect_uri, code_challenge, resource, scope, grant_id,
                (consumed_at < now()) AS already_consumed,
                (expires_at <= now()) AS expired`,
    [fingerprint(code)]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    accountId: row.account_id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    resource: row.resource,
    scope: row.scope,
    alreadyConsumed: row.already_consumed,
    expired: row.expired,
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

export async function revokeGrant(db: Queryable, grantId: string): Promise<void> {
  await db.query('UPDATE oauth_grants SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL', [grantId]);
  await db.query('DELETE FROM oauth_access_tokens WHERE grant_id = $1', [grantId]);
  await db.query(
    'UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL',
    [grantId]
  );
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

/**
 * One transaction, because a rotation that issues without retiring leaves the
 * old refresh token valid *and* unmarked — so a later replay of it is not
 * recognised as reuse, losing the only signal that it leaked.
 */
export async function rotateRefreshToken(
  db: Db, previousHash: string, grantId: string, audience: string, scope: string
): Promise<IssuedTokens> {
  return db.transaction(async (tx) => {
    const issued = await issueTokens(tx, grantId, audience, scope);
    await tx.query(
      'UPDATE oauth_refresh_tokens SET replaced_by = $1 WHERE token_hash = $2',
      [fingerprint(issued.refreshToken), previousHash]
    );
    return issued;
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
  if (record) await revokeGrant(db, record.grantId);
}

export async function revokeByAccessToken(db: Db, token: string): Promise<void> {
  const { rows } = await db.query<{ grant_id: string }>(
    'SELECT grant_id FROM oauth_access_tokens WHERE token_hash = $1',
    [fingerprint(token)]
  );
  const grantId = rows[0]?.grant_id;
  if (grantId) await revokeGrant(db, grantId);
}

/** Deletes what has expired. Both tables are read on every protected call. */
export async function pruneExpiredOAuth(db: Db): Promise<void> {
  await db.query('DELETE FROM oauth_access_tokens WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_refresh_tokens WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_authorization_codes WHERE expires_at <= now()');
  await db.query('DELETE FROM oauth_pending_authorizations WHERE expires_at <= now()');
}
