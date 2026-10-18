/**
 * Access token verification for the resource server.
 *
 * Phase 4's MCP server is the only consumer: it calls this on every protected
 * tool call and turns the result into either an internal Identity or a
 * WWW-Authenticate challenge.
 */

import type { Queryable } from '../db/index.ts';
import { wellFormed } from '../tokens/format.ts';
import { tokenDigestCandidates } from '../tokens/hash.ts';
import { RESOURCE_URI, type Scope } from './config.ts';

export type VerifiedToken =
  | { ok: true; accountId: string; clientId: string; grantId: string; scopes: Scope[] }
  | { ok: false; reason: 'invalid_token' }
  | { ok: false; reason: 'insufficient_scope'; grantId: string; granted: Scope[]; required: Scope[] };

export async function verifyOAuthAccessToken(
  db: Queryable,
  token: string | null | undefined,
  requiredScopes: Scope[] = []
): Promise<VerifiedToken> {
  // Garbage is refused by checksum, without a database round trip.
  if (!wellFormed('access', token)) return { ok: false, reason: 'invalid_token' };

  const { rows } = await db.query<{
    account_id: string; client_id: string; grant_id: string; scope: string; audience: string;
  }>(
    `SELECT g.account_id, g.client_id, t.grant_id, t.scope, t.audience
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
  if (row.audience !== RESOURCE_URI) return { ok: false, reason: 'invalid_token' };

  const granted = row.scope.split(' ').filter(Boolean) as Scope[];
  const missing = requiredScopes.filter((scope) => !granted.includes(scope));
  if (missing.length > 0) {
    return { ok: false, reason: 'insufficient_scope', grantId: row.grant_id, granted, required: requiredScopes };
  }

  return {
    ok: true,
    accountId: row.account_id,
    clientId: row.client_id,
    grantId: row.grant_id,
    scopes: granted
  };
}
