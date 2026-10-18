/**
 * How tokens are stored: HMAC-SHA256 under a pepper held outside the database.
 *
 * A plain SHA-256, as before, let anyone holding a copy of the database check
 * whether a token found elsewhere (in a log, say) was live, and look up whose
 * it was. With a keyed hash, the database alone reveals nothing usable.
 *
 * Lookups try every configured pepper, current first, so a pepper can be
 * rotated without invalidating tokens issued under the previous one; they
 * simply expire. New tokens are always stored under the current pepper.
 */

import { createHmac } from 'node:crypto';
import { keys } from '../security/keys.ts';

function hmac(key: Buffer, value: string): string {
  return createHmac('sha256', key).update(value).digest('hex');
}

/** The stored form of a token, under the current pepper. */
export function tokenDigest(token: string): string {
  const [current] = keys().tokenPeppers;
  if (!current) throw new Error('No token pepper configured');
  return hmac(current.key, token);
}

/** Every stored form this token could have, for `= ANY($n::text[])` lookups. */
export function tokenDigestCandidates(token: string): string[] {
  return keys().tokenPeppers.map(({ key }) => hmac(key, token));
}
