import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * SHA-256, not Argon2. Codes and tokens are 256-bit random values, not
 * user-chosen secrets: there is nothing to brute-force, and a slow hash on
 * every request would buy nothing while costing latency.
 */
export function fingerprint(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function newSecret(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString('base64url')}`;
}

/** PKCE S256, the only method this server advertises or accepts. */
export function verifyPkce(codeVerifier: unknown, codeChallenge: string): boolean {
  if (typeof codeVerifier !== 'string') return false;
  // RFC 7636 section 4.1.
  if (codeVerifier.length < 43 || codeVerifier.length > 128) return false;
  if (!/^[A-Za-z0-9\-._~]+$/.test(codeVerifier)) return false;

  const computed = Buffer.from(createHash('sha256').update(codeVerifier).digest('base64url'));
  const expected = Buffer.from(codeChallenge);
  return computed.length === expected.length && timingSafeEqual(computed, expected);
}
