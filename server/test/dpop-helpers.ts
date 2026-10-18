/**
 * A DPoP client key for tests: what the iOS app's Secure Enclave key, or a
 * host that supports DPoP, does on the wire.
 */

import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';
import { currentDpopNonce } from '../src/oauth/dpop.ts';

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

export class DpopKey {
  readonly jkt: string;
  private readonly privateKey: PrivateKey;
  private readonly publicJwk: JWK;

  private constructor(privateKey: PrivateKey, publicJwk: JWK, jkt: string) {
    this.privateKey = privateKey;
    this.publicJwk = publicJwk;
    this.jkt = jkt;
  }

  static async create(): Promise<DpopKey> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const publicJwk = await exportJWK(publicKey);
    return new DpopKey(privateKey, publicJwk, await calculateJwkThumbprint(publicJwk, 'sha256'));
  }

  /** A proof for one request. Defaults to a valid one; each field can be spoiled. */
  async proof(options: {
    htm: string; htu: string; accessToken?: string; nonce?: string | null;
    jti?: string; iat?: number; typ?: string; jwk?: JWK;
  }): Promise<string> {
    const claims: Record<string, unknown> = {
      htm: options.htm, htu: options.htu, jti: options.jti ?? randomBytes(12).toString('base64url')
    };
    const nonce = options.nonce === undefined ? currentDpopNonce() : options.nonce;
    if (nonce !== null) claims.nonce = nonce;
    if (options.accessToken) claims.ath = createHash('sha256').update(options.accessToken).digest('base64url');
    return new SignJWT(claims)
      .setProtectedHeader({ alg: 'ES256', typ: options.typ ?? 'dpop+jwt', jwk: options.jwk ?? this.publicJwk })
      .setIssuedAt(options.iat ?? Math.floor(Date.now() / 1000))
      .sign(this.privateKey);
  }
}
