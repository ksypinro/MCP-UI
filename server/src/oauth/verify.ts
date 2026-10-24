/**
 * Access token verification for the resource server.
 *
 * The MCP endpoint calls this on every protected tool call and turns the result into either an internal Identity or a
 * WWW-Authenticate challenge.
 */

import type { Queryable } from '../db/index.ts';
import { wellFormed } from '../tokens/format.ts';
import { tokenDigestCandidates } from '../tokens/hash.ts';
import { RESOURCE_URI, type Scope } from './config.ts';
import { touchGrant } from './grant-usage.ts';

export type VerifiedToken =
  | {
      ok: true; accountId: string; clientId: string; grantId: string; scopes: Scope[]; expiresIn: number;
      /** The DPoP key thumbprint this token is bound to, or null for a bearer token. */
      cnfJkt: string | null;
    }
  | { ok: false; reason: 'invalid_token' }
  | { ok: false; reason: 'insufficient_scope'; grantId: string; granted: Scope[]; required: Scope[] };

export async function verifyOAuthAccessToken(
  db: Queryable,
  token: string | null | undefined,
  requiredScopes: Scope[] = [],
  options: { audience?: string } = {}
): Promise<VerifiedToken> {
  const audience = options.audience ?? RESOURCE_URI;
  // Garbage is refused by checksum, without a database round trip.
  if (!wellFormed('access', token)) return { ok: false, reason: 'invalid_token' };

  const { rows } = await db.query<{
    account_id: string; client_id: string; grant_id: string; scope: string; audience: string; expires_in: number;
    cnf_jkt: string | null;
  }>(
    `SELECT g.account_id, g.client_id, t.grant_id, t.scope, t.audience, t.cnf_jkt,
            GREATEST(0, EXTRACT(EPOCH FROM (t.expires_at - now()))::int) AS expires_in
       FROM oauth_access_tokens t
       JOIN oauth_grants g ON g.id = t.grant_id
      WHERE t.token_hash = ANY($1::text[])
        AND t.expires_at > now()
        AND g.revoked_at IS NULL`,
    [tokenDigestCandidates(token)]
  );

  const row = rows[0];
  if (!row) return { ok: false, reason: 'invalid_token' };

  // RFC 8707: a token minted for another resource must never be accepted here,
  // however valid it is at that other resource. This is the check that stops
  // a token obtained for someone else's MCP server being replayed at ours.
  if (row.audience !== audience) return { ok: false, reason: 'invalid_token' };

  const granted = row.scope.split(' ').filter(Boolean) as Scope[];
  const missing = requiredScopes.filter((scope) => !granted.includes(scope));
  if (missing.length > 0) {
    return { ok: false, reason: 'insufficient_scope', grantId: row.grant_id, granted, required: requiredScopes };
  }

  // Best effort: a failure to record use must not fail the request.
  await touchGrant(db, row.grant_id).catch(() => {});

  return {
    ok: true,
    accountId: row.account_id,
    clientId: row.client_id,
    grantId: row.grant_id,
    scopes: granted,
    expiresIn: row.expires_in,
    cnfJkt: row.cnf_jkt
  };
}
