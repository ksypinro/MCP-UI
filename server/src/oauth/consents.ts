/**
 * What a person has approved, and when it may be reused.
 *
 * Remembered consent is what lets a second sign-in from the same application
 * skip the approval screen. It is also exactly what a confused-deputy attack
 * exploits: an attacker's client riding on consent the person gave to someone
 * else. So reuse is narrow:
 *
 * - Never for dynamically registered clients. DCR establishes nothing about
 *   who the client is, so every authorization asks again.
 * - Only for the same client, the same redirect host, and the same or fewer
 *   scopes than were approved.
 * - For a metadata-document client, only while the document is unchanged.
 * - For an unverified client, for 30 days; for a verified one, a year.
 */

import type { Queryable } from '../db/index.ts';
import { newId } from './crypto.ts';
import type { Scope } from './config.ts';
import type { PendingAuthorization } from './store.ts';

const UNVERIFIED_DAYS = 30;
const VERIFIED_DAYS = 365;

/** The host a redirect URI sends the person to, or its scheme for a private-use URI. */
export function redirectHost(redirectUri: string): string {
  const url = new URL(redirectUri);
  return url.host || url.protocol;
}

export function rememberable(pending: PendingAuthorization): boolean {
  return pending.clientKind !== 'dcr';
}

/** The id of a consent that covers this authorization, or null. */
export async function findRememberedConsent(
  db: Queryable, accountId: string, pending: PendingAuthorization
): Promise<string | null> {
  if (!rememberable(pending)) return null;
  const days = pending.clientTrust === 'verified' ? VERIFIED_DAYS : UNVERIFIED_DAYS;
  const { rows } = await db.query<{ id: string; scopes: string; document_digest: string | null }>(
    `SELECT id, scopes, document_digest FROM consents
      WHERE account_id = $1 AND client_id = $2 AND redirect_host = $3
        AND granted_at > now() - make_interval(days => $4)`,
    [accountId, pending.clientId, redirectHost(pending.redirectUri), days]
  );
  const row = rows[0];
  if (!row) return null;
  if (row.document_digest !== pending.documentDigest) return null;
  const granted = new Set(row.scopes.split(' '));
  return pending.scopes.every((scope) => granted.has(scope)) ? row.id : null;
}

/**
 * Records an approval. Returns its id, or null for a client whose consent is
 * never remembered (the approval still applies to this one authorization).
 */
export async function recordConsent(
  db: Queryable, accountId: string, pending: PendingAuthorization
): Promise<string | null> {
  if (!rememberable(pending)) return null;
  const host = redirectHost(pending.redirectUri);

  // Approving fewer scopes than before keeps the earlier, wider approval:
  // the union is what the person has agreed to across both.
  const { rows: existing } = await db.query<{ scopes: string; document_digest: string | null }>(
    'SELECT scopes, document_digest FROM consents WHERE account_id = $1 AND client_id = $2 AND redirect_host = $3',
    [accountId, pending.clientId, host]
  );
  const previous = existing[0];
  const union = new Set<Scope>(pending.scopes);
  // A changed document resets what was approved under the old one.
  if (previous && previous.document_digest === pending.documentDigest) {
    for (const scope of previous.scopes.split(' ').filter(Boolean)) union.add(scope as Scope);
  }

  const { rows } = await db.query<{ id: string }>(
    `INSERT INTO consents (id, account_id, client_id, redirect_host, scopes, document_digest)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT ON CONSTRAINT consents_account_client_host_key DO UPDATE
       SET scopes = EXCLUDED.scopes, document_digest = EXCLUDED.document_digest, granted_at = now()
     RETURNING id`,
    [newId('consent'), accountId, pending.clientId, host, [...union].sort().join(' '), pending.documentDigest]
  );
  return rows[0]?.id ?? null;
}
