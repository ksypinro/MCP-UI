/**
 * Key material held by a key management service.
 *
 * Two kinds of secret, treated differently because of how they are used:
 *
 * - **Peppers and the MAC key** are hashed with on every request, so they must
 *   be in memory. They are stored as data keys encrypted under a KMS
 *   key-encryption key ("envelope encryption"), decrypted once at start-up,
 *   and never written anywhere in the clear. Whoever copies the key file gets
 *   ciphertext.
 * - **Internal-token signing keys** never leave the KMS. Each signature is a
 *   KMS call; there is one per grant and scope per minute, so the volume is
 *   small.
 *
 * Start-up fails closed: if any key cannot be decrypted or any signing key
 * cannot be read, the server does not start.
 *
 * `Kms` is the whole surface a provider adapter has to implement. `LocalKms` implements it in
 * software, for development and tests, with the same rule that private keys
 * are never handed out.
 */

import {
  createCipheriv, createDecipheriv, createPrivateKey, generateKeyPairSync, randomBytes, sign as cryptoSign,
  type JsonWebKey
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { thumbprint, type KeyMaterial, type SigningKey, type VersionedKey } from './keys.ts';

export interface Kms {
  readonly name: string;
  /** Encrypts a data key under the key-encryption key. `context` is bound as associated data. */
  encrypt(plaintext: Buffer, context: string): Promise<Buffer>;
  decrypt(ciphertext: Buffer, context: string): Promise<Buffer>;
  /** Creates an ES256 key inside the KMS and returns its id. */
  createSigningKey(): Promise<string>;
  /** The public half, as a JWK. */
  publicKey(keyId: string): Promise<JsonWebKey>;
  /** An ES256 signature over `data`, as raw r‖s (the JWS encoding). */
  sign(keyId: string, data: Buffer): Promise<Buffer>;
}

interface LocalKmsState {
  kek: string;
  keys: Record<string, JsonWebKey>;
}

/**
 * A software KMS: a key-encryption key and ES256 keys in a file of its own
 * (mode 0600), separate from the envelope file it unlocks. It stands in for a
 * cloud KMS in development and tests. In production it is no better than the
 * plain key file, and the server says so at start-up.
 */
export class LocalKms implements Kms {
  readonly name = 'local';
  private readonly path: string;
  private state: LocalKmsState;

  constructor(path: string) {
    this.path = path;
    if (existsSync(path)) {
      this.state = JSON.parse(readFileSync(path, 'utf8')) as LocalKmsState;
    } else {
      this.state = { kek: randomBytes(32).toString('base64'), keys: {} };
      this.save('wx');
    }
  }

  private save(flag: 'wx' | 'w'): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.state, null, 2), { mode: 0o600, flag });
  }

  async encrypt(plaintext: Buffer, context: string): Promise<Buffer> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(this.state.kek, 'base64'), iv);
    cipher.setAAD(Buffer.from(context));
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]);
  }

  async decrypt(ciphertext: Buffer, context: string): Promise<Buffer> {
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(this.state.kek, 'base64'), ciphertext.subarray(0, 12));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(ciphertext.subarray(12, 28));
    return Buffer.concat([decipher.update(ciphertext.subarray(28)), decipher.final()]);
  }

  async createSigningKey(): Promise<string> {
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const id = `local-${randomBytes(8).toString('hex')}`;
    this.state.keys[id] = privateKey.export({ format: 'jwk' });
    this.save('w');
    return id;
  }

  async publicKey(keyId: string): Promise<JsonWebKey> {
    const jwk = this.state.keys[keyId];
    if (!jwk) throw new Error(`KMS has no key ${keyId}`);
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
  }

  async sign(keyId: string, data: Buffer): Promise<Buffer> {
    const jwk = this.state.keys[keyId];
    if (!jwk) throw new Error(`KMS has no key ${keyId}`);
    return cryptoSign('sha256', data, { key: createPrivateKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' });
  }
}

/** The KMS named by KMS_PROVIDER. `local` is the provider built in. */
export function kmsFromEnvironment(defaultLocalPath: string): Kms | null {
  const provider = process.env.KMS_PROVIDER;
  if (!provider) return null;
  if (provider === 'local') return new LocalKms(process.env.LOCAL_KMS_FILE ?? defaultLocalPath);
  throw new Error(`KMS_PROVIDER=${provider} is not a known provider; "local" is the one built in.`);
}

/** What is written to disk: every secret wrapped, every signing key a KMS id. */
interface EnvelopeFile {
  kms: string;
  tokenPeppers: { version: number; wrapped: string }[];
  passwordPepper: { version: number; wrapped: string };
  internalMacKey: string;
  /** KMS key ids, current first. */
  signingKeyIds: string[];
}

const PEPPER_CONTEXT = (version: number) => `iot-switch:token-pepper:v${version}`;
const PASSWORD_CONTEXT = (version: number) => `iot-switch:password-pepper:v${version}`;
const MAC_CONTEXT = 'iot-switch:internal-mac-key';

async function signingKeyFromKms(kms: Kms, keyId: string): Promise<SigningKey> {
  const publicJwk = await kms.publicKey(keyId);
  return { kid: thumbprint(publicJwk), publicJwk, sign: (data) => kms.sign(keyId, data) };
}

async function wrap(kms: Kms, key: VersionedKey, context: string) {
  return { version: key.version, wrapped: (await kms.encrypt(key.key, context)).toString('base64') };
}

function write(path: string, file: EnvelopeFile, flag: 'wx' | 'w'): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(file, null, 2), { mode: 0o600, flag });
}

function read(path: string): EnvelopeFile {
  return JSON.parse(readFileSync(path, 'utf8')) as EnvelopeFile;
}

/** Creates an envelope file with fresh keys. Refuses to overwrite one. */
export async function createEnvelope(kms: Kms, path: string): Promise<void> {
  const file: EnvelopeFile = {
    kms: kms.name,
    tokenPeppers: [await wrap(kms, { version: 1, key: randomBytes(32) }, PEPPER_CONTEXT(1))],
    passwordPepper: await wrap(kms, { version: 1, key: randomBytes(32) }, PASSWORD_CONTEXT(1)),
    internalMacKey: (await kms.encrypt(randomBytes(32), MAC_CONTEXT)).toString('base64'),
    signingKeyIds: [await kms.createSigningKey()]
  };
  write(path, file, 'wx');
}

/**
 * Decrypts the envelope into key material. Any failure — a wrong KMS, a
 * tampered file, a key the KMS no longer has — throws, and the server does not
 * start.
 */
export async function openEnvelope(kms: Kms, path: string): Promise<KeyMaterial> {
  if (!existsSync(path)) await createEnvelope(kms, path);
  const file = read(path);
  if (file.kms !== kms.name) throw new Error(`The key file was made with the ${file.kms} KMS, not ${kms.name}`);

  const unwrap = async (entry: { version: number; wrapped: string }, context: string): Promise<VersionedKey> =>
    ({ version: entry.version, key: await kms.decrypt(Buffer.from(entry.wrapped, 'base64'), context) });

  return {
    tokenPeppers: await Promise.all(file.tokenPeppers.map((entry) => unwrap(entry, PEPPER_CONTEXT(entry.version)))),
    passwordPepper: await unwrap(file.passwordPepper, PASSWORD_CONTEXT(file.passwordPepper.version)),
    internalMacKey: await kms.decrypt(Buffer.from(file.internalMacKey, 'base64'), MAC_CONTEXT),
    signingKeys: await Promise.all(file.signingKeyIds.map((id) => signingKeyFromKms(kms, id)))
  };
}

/**
 * Adds a new token pepper and makes it current. The previous one stays, so
 * tokens hashed under it keep verifying (the store looks up every candidate)
 * until they expire; anything older is dropped. Run every 90 days.
 */
export async function rotateTokenPepper(kms: Kms, path: string): Promise<number> {
  const file = read(path);
  const next = Math.max(...file.tokenPeppers.map((entry) => entry.version)) + 1;
  file.tokenPeppers = [await wrap(kms, { version: next, key: randomBytes(32) }, PEPPER_CONTEXT(next)), file.tokenPeppers[0]!];
  write(path, file, 'w');
  return next;
}

/**
 * Adds a new signing key and makes it current. The previous key stays
 * published in the JWKS so tokens it signed a moment ago still verify; older
 * ones are dropped. Run every 30 days.
 */
export async function rotateSigningKey(kms: Kms, path: string): Promise<string> {
  const file = read(path);
  const id = await kms.createSigningKey();
  file.signingKeyIds = [id, file.signingKeyIds[0]!];
  write(path, file, 'w');
  return id;
}
