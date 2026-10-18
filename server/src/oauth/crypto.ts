import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// Tokens and codes are minted by tokens/format.ts and stored by
// tokens/hash.ts. Identifiers that are not secrets are minted here.

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
