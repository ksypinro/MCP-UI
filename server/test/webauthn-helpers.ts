/**
 * A software authenticator, for exercising the passkey ceremonies end to end
 * without a browser. It produces exactly what a platform authenticator does
 * for "none" attestation: a CBOR attestation object with a COSE P-256 key,
 * and assertions signed over authenticatorData ‖ SHA-256(clientDataJSON).
 *
 * Its knobs are the attacks: answering for another RP ID or origin, or not
 * advancing the signature counter.
 */

import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

/* -------------------------------------------------- just enough CBOR */

type Cbor = number | string | Uint8Array | Map<number | string, Cbor> | Record<string, never>;

function head(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 256) return Buffer.from([(major << 5) | 24, length]);
  const out = Buffer.alloc(3);
  out[0] = (major << 5) | 25;
  out.writeUInt16BE(length, 1);
  return out;
}

function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)]);
  const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(k), cbor(v as Cbor)])]);
}

/* ------------------------------------------------------ authenticator */

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const sha256 = (data: Uint8Array | string) => createHash('sha256').update(data).digest();

export interface Ceremony { rpId: string; origin: string }

export class SoftAuthenticator {
  readonly credentialId = randomBytes(16);
  private readonly privateKey: KeyObject;
  private readonly cose: Buffer;
  private readonly userHandle: Uint8Array | null = null;
  counter = 0;
  /** When false, the counter repeats instead of advancing: what a cloned key looks like. */
  advance = true;

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: 'jwk' });
    this.cose = cbor(new Map<number, Cbor>([
      [1, 2], [3, -7], [-1, 1],
      [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]
    ]));
  }

  get id(): string {
    return b64url(this.credentialId);
  }

  private authenticatorData(rpId: string, flags: number, attested?: Buffer): Buffer {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.counter);
    return Buffer.concat([sha256(rpId), Buffer.from([flags]), count, ...(attested ? [attested] : [])]);
  }

  /** navigator.credentials.create(), answered. `options.challenge` is base64url, as the server sent it. */
  create(options: { challenge: string }, at: Ceremony): Record<string, unknown> {
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.create', challenge: options.challenge, origin: at.origin, crossOrigin: false
    }));
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.credentialId.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLength, this.credentialId, this.cose]);
    // UP | UV | AT
    const authData = this.authenticatorData(at.rpId, 0x01 | 0x04 | 0x40, attested);
    const attestationObject = cbor(new Map<string, Cbor>([['fmt', 'none'], ['attStmt', {}], ['authData', authData]]));
    return {
      id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64url(clientDataJSON), attestationObject: b64url(attestationObject), transports: ['internal'] }
    };
  }

  /** navigator.credentials.get(), answered. */
  get(options: { challenge: string }, at: Ceremony): Record<string, unknown> {
    if (this.advance) this.counter += 1;
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge: options.challenge, origin: at.origin, crossOrigin: false
    }));
    const authData = this.authenticatorData(at.rpId, 0x01 | 0x04);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    return {
      id: this.id, rawId: this.id, type: 'public-key', clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON), authenticatorData: b64url(authData), signature: b64url(signature),
        ...(this.userHandle ? { userHandle: b64url(this.userHandle) } : {})
      }
    };
  }
}
