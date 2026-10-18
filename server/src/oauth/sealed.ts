/**
 * Refresh responses kept briefly, encrypted, so a duplicate refresh can be
 * answered with exactly what the first one received.
 *
 * Refresh tokens rotate, and presenting one that was already rotated normally
 * means it leaked. But a host that refreshes from two workers at once, or
 * whose response was lost in transit, presents the old token again for
 * entirely innocent reasons. Revoking the grant then logs the user out for
 * nothing; issuing a second pair would fork the token family. Returning the
 * identical response does neither: the family stays one line, and the caller
 * ends up holding what it was already given.
 *
 * Entries live for the grace window only, are keyed by a hash of the
 * presented token, and are encrypted so that a heap dump of this map is not a
 * list of live tokens. The interface is what a shared store implements when
 * more than one process serves the token endpoint.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface SealedResponses {
  seal(key: string, body: unknown, ttlSeconds: number): void;
  /** The body sealed under `key`, or null if absent or expired. */
  unseal(key: string): unknown | null;
}

export class MemorySealedResponses implements SealedResponses {
  private readonly key = randomBytes(32);
  private readonly entries = new Map<string, { iv: Buffer; data: Buffer; tag: Buffer; expiresAt: number }>();

  seal(key: string, body: unknown, ttlSeconds: number): void {
    this.sweep();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(key));
    const data = Buffer.concat([cipher.update(JSON.stringify(body), 'utf8'), cipher.final()]);
    this.entries.set(key, { iv, data, tag: cipher.getAuthTag(), expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  unseal(key: string): unknown | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return null;
    }
    const decipher = createDecipheriv('aes-256-gcm', this.key, entry.iv);
    decipher.setAAD(Buffer.from(key));
    decipher.setAuthTag(entry.tag);
    return JSON.parse(Buffer.concat([decipher.update(entry.data), decipher.final()]).toString('utf8'));
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) if (entry.expiresAt <= now) this.entries.delete(key);
  }
}
