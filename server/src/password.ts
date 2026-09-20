import { hash, verify } from '@node-rs/argon2';

/**
 * Argon2id with per-password salts, as required by spec section 7.2.
 * The salt and parameters are embedded in the encoded hash, so no separate
 * column is needed and the cost can be raised later without a migration.
 *
 * The algorithm is given as its numeric value rather than the library's
 * `Algorithm` enum: that enum is an ambient const enum, which cannot survive
 * the type-stripping this project relies on to run TypeScript directly.
 */
const ARGON2ID = 2;
const OPTIONS = { algorithm: ARGON2ID } as const;

export function hashPassword(password: string): Promise<string> {
  return hash(password, OPTIONS);
}

export async function verifyPassword(encodedHash: string, password: string): Promise<boolean> {
  try {
    return await verify(encodedHash, password, OPTIONS);
  } catch {
    // A malformed stored hash must read as "wrong password", never as a crash
    // that distinguishes this account from one that does not exist.
    return false;
  }
}
