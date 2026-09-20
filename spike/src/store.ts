/**
 * In-memory state for the phase 0 spike. Deliberately not persistent: this
 * code answers host-behaviour questions and is then deleted. The real service
 * uses Postgres with the constraints named in spec sections 4.2 and 6.1.
 */

import { randomBytes, createHash, timingSafeEqual, scryptSync } from 'node:crypto';
import { SEED_DEVICE_COUNT, type Scope } from './config.js';

export type DeviceState = 'on' | 'off';

export interface Device {
  id: string;
  ownerId: string;
  name: string;
  normalizedName: string;
  state: DeviceState;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface Account {
  id: string;
  username: string;
  normalizedUsername: string;
  passwordHash: string;
  salt: string;
}

export interface AccessToken {
  sub: string;
  scopes: Scope[];
  /** RFC 8707 audience. A token minted for another resource must be rejected. */
  aud: string;
  expiresAt: number;
}

export interface AuthCode {
  sub: string;
  scopes: Scope[];
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  expiresAt: number;
}

const accounts = new Map<string, Account>();
const accountsByUsername = new Map<string, string>();
const devices = new Map<string, Device>();
const accessTokens = new Map<string, AccessToken>();
const authCodes = new Map<string, AuthCode>();
const registeredClients = new Map<string, { redirectUris: string[] }>();

let deviceSeq = 0;

/** Matches the fold defined in spec section 4.2: trim, collapse, NFKC, casefold. */
export function normalizeName(raw: string): string {
  return raw.trim().replace(/\s+/g, ' ').normalize('NFKC').toLowerCase();
}

/** Matches spec section 4.1: trim, NFKC, casefold. */
export function normalizeUsername(raw: string): string {
  return raw.trim().normalize('NFKC').toLowerCase();
}

function hashPassword(password: string, salt: string): string {
  return scryptSync(password, salt, 64).toString('hex');
}

export function createAccount(username: string, password: string): Account {
  const normalizedUsername = normalizeUsername(username);
  if (accountsByUsername.has(normalizedUsername)) {
    throw new Error('USERNAME_TAKEN');
  }
  const salt = randomBytes(16).toString('hex');
  const account: Account = {
    id: `acc_${randomBytes(6).toString('hex')}`,
    username: username.trim(),
    normalizedUsername,
    passwordHash: hashPassword(password, salt),
    salt
  };
  accounts.set(account.id, account);
  accountsByUsername.set(normalizedUsername, account.id);
  seedDevices(account.id);
  return account;
}

export function verifyCredentials(username: string, password: string): Account | null {
  const id = accountsByUsername.get(normalizeUsername(username));
  if (!id) return null;
  const account = accounts.get(id);
  if (!account) return null;
  const candidate = Buffer.from(hashPassword(password, account.salt), 'hex');
  const known = Buffer.from(account.passwordHash, 'hex');
  if (candidate.length !== known.length) return null;
  return timingSafeEqual(candidate, known) ? account : null;
}

export function getAccount(id: string): Account | undefined {
  return accounts.get(id);
}

/**
 * Seeds more devices than a host inline card is expected to show, so that the
 * clipping behaviour described in spec section 9.3 is observable rather than
 * theoretical.
 */
function seedDevices(ownerId: string): void {
  const names = [
    'Bedroom Lamp', 'Kitchen Downlights', 'Porch Light', 'Desk Fan',
    'Living Room Speaker', 'Hallway Nightlight', 'Garage Door Sensor', 'Coffee Machine',
    'Bathroom Extractor', 'Garden Floodlight', 'Bookshelf Strip', 'Studio Monitor'
  ].slice(0, SEED_DEVICE_COUNT);

  const now = Date.now();
  names.forEach((name, i) => {
    const id = `dev_${String(++deviceSeq).padStart(2, '0')}`;
    const createdAt = new Date(now + i).toISOString();
    devices.set(id, {
      id,
      ownerId,
      name,
      normalizedName: normalizeName(name),
      state: i % 4 === 0 ? 'on' : 'off',
      version: 1,
      createdAt,
      updatedAt: createdAt
    });
  });
}

/** Ordering is a server contract: createdAt ascending, id ascending as tie-breaker. */
export function listDevices(ownerId: string): Device[] {
  return [...devices.values()]
    .filter((d) => d.ownerId === ownerId)
    .sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
}

export function getDevice(ownerId: string, deviceId: string): Device | null {
  const device = devices.get(deviceId);
  // A device owned by someone else is reported as absent, never as forbidden.
  return device && device.ownerId === ownerId ? device : null;
}

export type ControlOutcome =
  | { ok: true; device: Device }
  | { ok: false; code: 'DEVICE_NOT_FOUND' | 'DEVICE_VERSION_CONFLICT'; device?: Device };

export function controlDevice(
  ownerId: string,
  deviceId: string,
  state: DeviceState,
  expectedVersion: number
): ControlOutcome {
  const device = getDevice(ownerId, deviceId);
  if (!device) return { ok: false, code: 'DEVICE_NOT_FOUND' };
  if (device.version !== expectedVersion) {
    return { ok: false, code: 'DEVICE_VERSION_CONFLICT', device };
  }
  // A request that does not change the state advances neither version nor updatedAt.
  if (device.state === state) return { ok: true, device };

  device.state = state;
  device.version += 1;
  device.updatedAt = new Date().toISOString();
  return { ok: true, device };
}

export function publicDevice(d: Device) {
  const { ownerId: _ownerId, normalizedName: _normalizedName, ...rest } = d;
  return rest;
}

export function issueAccessToken(sub: string, scopes: Scope[], aud: string, ttlSeconds = 3600): string {
  const token = randomBytes(32).toString('hex');
  accessTokens.set(token, { sub, scopes, aud, expiresAt: Date.now() + ttlSeconds * 1000 });
  return token;
}

export function readAccessToken(token: string | null): AccessToken | null {
  if (!token) return null;
  const record = accessTokens.get(token);
  if (!record) return null;
  if (record.expiresAt < Date.now()) {
    accessTokens.delete(token);
    return null;
  }
  return record;
}

export function revokeAccessToken(token: string): void {
  accessTokens.delete(token);
}

export function storeAuthCode(code: string, value: AuthCode): void {
  authCodes.set(code, value);
}

export function consumeAuthCode(code: string): AuthCode | null {
  const value = authCodes.get(code);
  if (!value) return null;
  authCodes.delete(code); // single use
  return value.expiresAt < Date.now() ? null : value;
}

export function registerClient(clientId: string, redirectUris: string[]): void {
  registeredClients.set(clientId, { redirectUris });
}

export function getRegisteredClient(clientId: string) {
  return registeredClients.get(clientId);
}

export function pkceS256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export function randomId(bytes = 24): string {
  return randomBytes(bytes).toString('hex');
}
