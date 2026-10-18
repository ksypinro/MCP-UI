import { createHmac } from 'node:crypto';
import { hash, verify } from '@node-rs/argon2';
import { keys } from './security/keys.ts';

/**
 * Argon2id with per-password salts, as required by spec section 7.2, applied
 * to an HMAC of the password under a pepper held outside the database.
 *
 * The pepper means a stolen copy of the accounts table alone cannot be
 * brute-forced offline: every guess needs a key that is not in it. The salt
 * and Argon2 parameters are embedded in the encoded hash, so the cost can be
 * raised later without a migration; the pepper version is stored beside it.
 *
 * Parameters follow the plan (m = 64 MiB, t = 3, p = 1). ARGON2_MEMORY_KIB and
 * ARGON2_TIME_COST exist so a test harness can lower them for speed; they are
 * read on every call so it can do so after import.
 *
 * The algorithm is given as its numeric value rather than the library's
 * `Algorithm` enum: that enum is an ambient const enum, which cannot survive
 * the type-stripping this project relies on to run TypeScript directly.
 */
const ARGON2ID = 2;

function options() {
  return {
    algorithm: ARGON2ID,
    memoryCost: Number(process.env.ARGON2_MEMORY_KIB ?? 65_536),
    timeCost: Number(process.env.ARGON2_TIME_COST ?? 3),
    parallelism: 1
  } as const;
}

function peppered(password: string): string {
  return createHmac('sha256', keys().passwordPepper.key).update(password, 'utf8').digest('base64');
}

export interface PasswordHash {
  encoded: string;
  pepperVersion: number;
}

export async function hashPassword(password: string): Promise<PasswordHash> {
  return {
    encoded: await hash(peppered(password), options()),
    pepperVersion: keys().passwordPepper.version
  };
}

/**
 * `pepperVersion` null means a hash written before peppering. It is checked
 * against the raw password, and the caller should rehash it on success.
 */
export async function verifyPassword(
  encodedHash: string, password: string, pepperVersion: number | null
): Promise<boolean> {
  try {
    return await verify(encodedHash, pepperVersion === null ? password : peppered(password));
  } catch {
    // A malformed stored hash must read as "wrong password", never as a crash
    // that distinguishes this account from one that does not exist.
    return false;
  }
}
