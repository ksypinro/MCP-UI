/**
 * Passkeys: WebAuthn sign-in on the authorization server. AC-45.
 *
 * A password typed into a convincing copy of this page is a password lost. A
 * passkey is bound by the browser to this site's domain (the RP ID), so a
 * phishing page on any other domain cannot use it, however convincing it is.
 * That is why the RP ID is the authorization server's own host, and why the
 * origin and RP ID are checked on every ceremony, not trusted from the client.
 *
 * - User verification is required (biometric or device PIN), so a passkey is
 *   a full sign-in on its own, not a second factor.
 * - Challenges are single-use and short-lived, taken with DELETE … RETURNING.
 *   A registration challenge belongs to the signed-in account; a sign-in
 *   challenge to the browser that asked for it.
 * - The signature counter must move forward. An authenticator that reports a
 *   counter at or below the stored one (other than the zero many synced
 *   passkeys always report) looks cloned and is refused.
 */

import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse,
  verifyRegistrationResponse
} from '@simplewebauthn/server';
import type { Queryable } from '../db/index.ts';
import { ISSUER } from './config.ts';
import { log } from '../observability/log.ts';

const CHALLENGE_TTL_SECONDS = 5 * 60;
export const MAX_PASSKEYS = 10;

/** This server's WebAuthn identity: its own host, and its own origin. */
export function relyingParty(): { id: string; origin: string; name: string } {
  const url = new URL(ISSUER);
  return { id: url.hostname, origin: url.origin, name: 'IoT Switch' };
}

export interface Passkey {
  id: string;
  name: string;
  createdAt: Date;
  lastUsedAt: Date | null;
}

interface PasskeyRow {
  id: string; account_id: string; public_key: Uint8Array; counter: number; transports: string;
  name: string; created_at: Date; last_used_at: Date | null;
}

export async function listPasskeys(db: Queryable, accountId: string): Promise<Passkey[]> {
  const { rows } = await db.query<PasskeyRow>(
    'SELECT id, name, created_at, last_used_at FROM passkeys WHERE account_id = $1 ORDER BY created_at',
    [accountId]
  );
  return rows.map((row) => ({ id: row.id, name: row.name, createdAt: row.created_at, lastUsedAt: row.last_used_at }));
}

export async function deletePasskey(db: Queryable, accountId: string, id: string): Promise<boolean> {
  const { affectedRows } = await db.query('DELETE FROM passkeys WHERE id = $1 AND account_id = $2', [id, accountId]);
  return affectedRows === 1;
}

async function storeChallenge(
  db: Queryable, challenge: string, purpose: 'register' | 'authenticate', owner: { accountId?: string; binding?: string }
): Promise<void> {
  await db.query(
    `INSERT INTO webauthn_challenges (challenge, purpose, account_id, binding, expires_at)
     VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`,
    [challenge, purpose, owner.accountId ?? null, owner.binding ?? null, CHALLENGE_TTL_SECONDS]
  );
}

/** Takes the challenge if it is live and belongs to this owner. It can never be taken twice. */
async function takeChallenge(
  db: Queryable, challenge: string, purpose: 'register' | 'authenticate', owner: { accountId?: string; binding?: string }
): Promise<boolean> {
  const { rows } = await db.query(
    `DELETE FROM webauthn_challenges
      WHERE challenge = $1 AND purpose = $2 AND expires_at > now()
        AND account_id IS NOT DISTINCT FROM $3 AND binding IS NOT DISTINCT FROM $4
      RETURNING challenge`,
    [challenge, purpose, owner.accountId ?? null, owner.binding ?? null]
  );
  return rows.length === 1;
}

/** The challenge a WebAuthn response claims to answer, from its clientDataJSON. */
function challengeIn(response: { response?: { clientDataJSON?: unknown } }): string | null {
  const encoded = response?.response?.clientDataJSON;
  if (typeof encoded !== 'string' || encoded.length > 4096) return null;
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as { challenge?: unknown };
    return typeof parsed.challenge === 'string' ? parsed.challenge : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------ register */

export async function registrationOptions(
  db: Queryable, account: { id: string; username: string }
): Promise<Record<string, unknown>> {
  const rp = relyingParty();
  const existing = await db.query<{ id: string; transports: string }>(
    'SELECT id, transports FROM passkeys WHERE account_id = $1', [account.id]
  );
  const options = await generateRegistrationOptions({
    rpName: rp.name,
    rpID: rp.id,
    userName: account.username,
    userID: new TextEncoder().encode(account.id),
    attestationType: 'none',
    // The same authenticator twice is refused by the browser itself.
    excludeCredentials: existing.rows.map((row) => ({
      id: row.id, transports: row.transports ? row.transports.split(',') : undefined
    })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    supportedAlgorithmIDs: [-7, -8]
  });
  await storeChallenge(db, options.challenge, 'register', { accountId: account.id });
  return options as unknown as Record<string, unknown>;
}

export type RegistrationResult = { ok: true; passkey: Passkey } | { ok: false; reason: string };

export async function finishRegistration(
  db: Queryable, accountId: string, response: unknown, rawName: unknown
): Promise<RegistrationResult> {
  const challenge = challengeIn(response as never);
  if (!challenge || !(await takeChallenge(db, challenge, 'register', { accountId }))) {
    return { ok: false, reason: 'This request has expired. Try again.' };
  }
  const count = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM passkeys WHERE account_id = $1', [accountId]);
  if ((count.rows[0]?.n ?? 0) >= MAX_PASSKEYS) return { ok: false, reason: `At most ${MAX_PASSKEYS} passkeys per account.` };

  const rp = relyingParty();
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: response as never,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -8]
    });
  } catch {
    return { ok: false, reason: 'That passkey could not be verified.' };
  }
  if (!verification.verified) return { ok: false, reason: 'That passkey could not be verified.' };

  const { credential } = verification.registrationInfo;
  const name = typeof rawName === 'string' && rawName.trim() ? rawName.trim().slice(0, 60) : 'Passkey';
  const { rows } = await db.query<PasskeyRow>(
    `INSERT INTO passkeys (id, account_id, public_key, counter, transports, name)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (id) DO NOTHING
     RETURNING id, name, created_at, last_used_at`,
    [credential.id, accountId, Buffer.from(credential.publicKey), credential.counter,
      (credential.transports ?? []).join(','), name]
  );
  const row = rows[0];
  if (!row) return { ok: false, reason: 'That passkey is already registered.' };
  return { ok: true, passkey: { id: row.id, name: row.name, createdAt: row.created_at, lastUsedAt: row.last_used_at } };
}

/* -------------------------------------------------------- authenticate */

/** Options for "Sign in with a passkey": any of this site's passkeys, chosen by the person. */
export async function authenticationOptions(db: Queryable, binding: string): Promise<Record<string, unknown>> {
  const rp = relyingParty();
  const options = await generateAuthenticationOptions({ rpID: rp.id, userVerification: 'required' });
  await storeChallenge(db, options.challenge, 'authenticate', { binding });
  return options as unknown as Record<string, unknown>;
}

/** The account the passkey belongs to, or null. Any failure looks the same to the caller. */
export async function finishAuthentication(db: Queryable, binding: string, response: unknown): Promise<string | null> {
  const challenge = challengeIn(response as never);
  if (!challenge || !(await takeChallenge(db, challenge, 'authenticate', { binding }))) return null;

  const id = (response as { id?: unknown })?.id;
  if (typeof id !== 'string' || id.length > 1024) return null;
  const { rows } = await db.query<PasskeyRow>(
    'SELECT id, account_id, public_key, counter, transports FROM passkeys WHERE id = $1', [id]
  );
  const stored = rows[0];
  if (!stored) return null;

  const rp = relyingParty();
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: response as never,
      expectedChallenge: challenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      requireUserVerification: true,
      credential: {
        id: stored.id,
        publicKey: new Uint8Array(stored.public_key),
        counter: Number(stored.counter),
        transports: stored.transports ? stored.transports.split(',') as never : undefined
      }
    });
  } catch {
    return null;
  }
  if (!verification.verified) return null;

  // The counter moves forward, or the update matches nothing and the sign-in
  // is refused. Zero-to-zero is allowed: many synced passkeys never count.
  const next = verification.authenticationInfo.newCounter;
  const updated = await db.query(
    `UPDATE passkeys SET counter = $1, last_used_at = now()
      WHERE id = $2 AND (counter < $1 OR (counter = 0 AND $1 = 0))`,
    [next, stored.id]
  );
  if (updated.affectedRows !== 1) {
    log('warn', 'passkey_counter_not_advanced', { passkeyId: stored.id, accountId: stored.account_id, reason: 'possible cloned authenticator' });
    return null;
  }
  return stored.account_id;
}
