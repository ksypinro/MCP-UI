/**
 * Message authentication for values the browser carries back to us: CSRF
 * tokens and the like. Keyed by INTERNAL_MAC_KEY, separated by purpose so a
 * MAC minted for one use is never accepted for another.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { keys } from './keys.ts';

export function mac(purpose: string, ...parts: string[]): string {
  const hmac = createHmac('sha256', keys().internalMacKey);
  hmac.update(purpose);
  for (const part of parts) hmac.update(`\u0000${part}`);
  return hmac.digest('base64url');
}

export function macMatches(expected: string, presented: unknown): boolean {
  if (typeof presented !== 'string') return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(presented);
  return a.length === b.length && timingSafeEqual(a, b);
}
