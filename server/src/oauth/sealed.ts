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
 * list of live tokens. With more than one process serving the token endpoint
 * the ciphertext lives in Redis (stores/redis.ts), under a key every process
 * derives from the same key material.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface SealedResponses {
  seal(key: string, body: unknown, ttlSeconds: number): Promise<void>;
  /** The body sealed under `key`, or null if absent or expired. */
  unseal(key: string): Promise<unknown | null>;
}

/**
 * AES-256-GCM with the store key as associated data, so a sealed body moved
 * to another key does not open. Shared by every implementation: what differs
 * is only where the ciphertext lives.
 */
export class Sealer {
  private readonly secret: Buffer;

  constructor(secret: Buffer = randomBytes(32)) {
    if (secret.length !== 32) throw new Error('The sealing key must be 32 bytes');
    this.secret = secret;
  }

  seal(key: string, body: unknown): Buffer {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.secret, iv);
    cipher.setAAD(Buffer.from(key));
    const data = Buffer.concat([cipher.update(JSON.stringify(body), 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]);
  }

  open(key: string, sealed: Buffer): unknown {
    const decipher = createDecipheriv('aes-256-gcm', this.secret, sealed.subarray(0, 12));
    decipher.setAAD(Buffer.from(key));
    decipher.setAuthTag(sealed.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]).toString('utf8'));
  }
}

/** Per-process store, under a key that never leaves this process. */
export class MemorySealedResponses implements SealedResponses {
  private readonly sealer = new Sealer();
  private readonly entries = new Map<string, { sealed: Buffer; expiresAt: number }>();

  async seal(key: string, body: unknown, ttlSeconds: number): Promise<void> {
    this.sweep();
    this.entries.set(key, { sealed: this.sealer.seal(key, body), expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async unseal(key: string): Promise<unknown | null> {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return null;
    }
    return this.sealer.open(key, entry.sealed);
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.entries) if (entry.expiresAt <= now) this.entries.delete(key);
  }
}
