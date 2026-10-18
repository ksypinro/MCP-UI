/**
 * Secret key material: the token-hash peppers, the password pepper, and the
 * key that MACs CSRF tokens and browser bindings.
 *
 * Sources, in order:
 *
 * 1. Environment: TOKEN_PEPPERS ("2:<base64>,1:<base64>", current first),
 *    PASSWORD_PEPPER ("1:<base64>") and INTERNAL_MAC_KEY (base64). This is the
 *    production path, and where a KMS-backed provider will plug in later.
 * 2. A key file, configured by the server at start-up next to the database.
 *    Generated on first use with mode 0600. Losing it makes every stored
 *    password and token unverifiable, so back it up with the database.
 * 3. Otherwise, fresh random keys for this process only. That is what tests
 *    get, and it is refused when NODE_ENV is production.
 *
 * Signing keys for internal tokens (ES256) follow the same order, with
 * SIGNING_KEYS as a JSON array of private JWKs, current first. Unlike the
 * peppers they may be per-process even in production: an internal token
 * lives a minute and, while every component runs in one process, is only
 * ever verified by the process that signed it.
 */

import { createHash, generateKeyPairSync, randomBytes, type JsonWebKey } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface VersionedKey {
  version: number;
  key: Buffer;
}

/** A private ES256 key as a JWK, with its RFC 7638 thumbprint as `kid`. */
export interface SigningKey {
  kid: string;
  privateJwk: JsonWebKey;
  publicJwk: JsonWebKey;
}

export interface KeyMaterial {
  /** The first entry is current; the rest still verify during rotation. */
  tokenPeppers: VersionedKey[];
  passwordPepper: VersionedKey;
  internalMacKey: Buffer;
  /** The first entry signs; the rest are published for verification until retired. */
  signingKeys: SigningKey[];
}

/** RFC 7638 thumbprint of an EC public key. */
function thumbprint(jwk: JsonWebKey): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash('sha256').update(canonical).digest('base64url');
}

function toSigningKey(privateJwk: JsonWebKey): SigningKey {
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256' || !privateJwk.d) {
    throw new Error('Signing keys must be private P-256 JWKs');
  }
  const publicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: privateJwk.x, y: privateJwk.y };
  return { kid: thumbprint(publicJwk), privateJwk, publicJwk };
}

export function newSigningKey(): SigningKey {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return toSigningKey(privateKey.export({ format: 'jwk' }));
}

function signingKeysFromEnvironment(): SigningKey[] | null {
  if (!process.env.SIGNING_KEYS) return null;
  const parsed = JSON.parse(process.env.SIGNING_KEYS) as JsonWebKey[];
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error('SIGNING_KEYS must be a non-empty JSON array');
  return parsed.map(toSigningKey);
}

let keyFile: string | null = null;
let material: KeyMaterial | null = null;

/** Called once by the server entry point. Tests never call it. */
export function useKeyFile(path: string): void {
  keyFile = path;
  material = null;
}

/**
 * Drops the loaded material so the next use reads its source again. This is
 * how a rotation takes effect: publish the new pepper first in TOKEN_PEPPERS,
 * then reload. Tokens under the old one keep verifying until they expire.
 */
export function reloadKeysForRotation(): void {
  material = null;
}

export function keys(): KeyMaterial {
  material ??= fromEnvironment() ?? fromFile() ?? ephemeral();
  return material;
}

function parseVersioned(value: string): VersionedKey {
  const [version, key] = value.split(':');
  const parsed = Number(version);
  const bytes = Buffer.from(key ?? '', 'base64');
  if (!Number.isInteger(parsed) || parsed < 1 || bytes.length < 32) {
    throw new Error('Key material must be "<version>:<base64 of at least 32 bytes>"');
  }
  return { version: parsed, key: bytes };
}

function fromEnvironment(): KeyMaterial | null {
  const { TOKEN_PEPPERS, PASSWORD_PEPPER, INTERNAL_MAC_KEY } = process.env;
  if (!TOKEN_PEPPERS && !PASSWORD_PEPPER && !INTERNAL_MAC_KEY) return null;
  if (!TOKEN_PEPPERS || !PASSWORD_PEPPER || !INTERNAL_MAC_KEY) {
    // Half-configured is worse than unconfigured: it would silently mix a
    // stable pepper with a per-process one.
    throw new Error('Set all of TOKEN_PEPPERS, PASSWORD_PEPPER and INTERNAL_MAC_KEY, or none');
  }
  const internalMacKey = Buffer.from(INTERNAL_MAC_KEY, 'base64');
  if (internalMacKey.length < 32) throw new Error('INTERNAL_MAC_KEY must be at least 32 bytes');
  return {
    tokenPeppers: TOKEN_PEPPERS.split(',').map((entry) => parseVersioned(entry.trim())),
    passwordPepper: parseVersioned(PASSWORD_PEPPER),
    internalMacKey,
    signingKeys: signingKeysFromEnvironment() ?? [newSigningKey()]
  };
}

interface KeyFileShape {
  tokenPeppers: { version: number; key: string }[];
  passwordPepper: { version: number; key: string };
  internalMacKey: string;
  /** Absent in files written before signing keys existed; added on next start. */
  signingKeys?: JsonWebKey[];
}

function writeKeyFile(path: string, material: KeyMaterial, flag: 'wx' | 'w'): void {
  const shape: KeyFileShape = {
    tokenPeppers: material.tokenPeppers.map(({ version, key }) => ({ version, key: key.toString('base64') })),
    passwordPepper: { version: material.passwordPepper.version, key: material.passwordPepper.key.toString('base64') },
    internalMacKey: material.internalMacKey.toString('base64'),
    signingKeys: material.signingKeys.map((key) => key.privateJwk)
  };
  writeFileSync(path, JSON.stringify(shape, null, 2), { mode: 0o600, flag });
}

function fromFile(): KeyMaterial | null {
  if (!keyFile) return null;
  if (!existsSync(keyFile)) {
    const fresh = ephemeral(true);
    mkdirSync(dirname(keyFile), { recursive: true });
    writeKeyFile(keyFile, fresh, 'wx');
    return fresh;
  }
  const shape = JSON.parse(readFileSync(keyFile, 'utf8')) as KeyFileShape;
  const material: KeyMaterial = {
    tokenPeppers: shape.tokenPeppers.map(({ version, key }) => ({ version, key: Buffer.from(key, 'base64') })),
    passwordPepper: { version: shape.passwordPepper.version, key: Buffer.from(shape.passwordPepper.key, 'base64') },
    internalMacKey: Buffer.from(shape.internalMacKey, 'base64'),
    signingKeys: shape.signingKeys?.map(toSigningKey) ?? [newSigningKey()]
  };
  if (!shape.signingKeys) writeKeyFile(keyFile, material, 'w');
  return material;
}

function ephemeral(persisting = false): KeyMaterial {
  if (!persisting && process.env.NODE_ENV === 'production') {
    throw new Error('No key material configured. Set TOKEN_PEPPERS, PASSWORD_PEPPER and INTERNAL_MAC_KEY.');
  }
  return {
    tokenPeppers: [{ version: 1, key: randomBytes(32) }],
    passwordPepper: { version: 1, key: randomBytes(32) },
    internalMacKey: randomBytes(32),
    signingKeys: [newSigningKey()]
  };
}
