/**
 * DPoP (RFC 9449): proof that whoever presents a token holds the private key
 * it was bound to. Plan 3.1, architecture sections 5.6 and 8.1.
 *
 * A bearer token works for anyone who has it. A DPoP-bound token works only
 * alongside a fresh proof signed by one key: the token carries the key's
 * thumbprint (cnf.jkt), and each request carries a short-lived JWT signed by
 * it, naming the method and URL, hashing the token (ath), and echoing a
 * nonce the server issued. A token copied off a phone, or out of a log, is
 * useless without the key — which, for the iOS app, never leaves the Secure
 * Enclave.
 *
 * Nonces are stateless: an HMAC of the current five-minute window, so they
 * survive restarts and need no storage. The current and previous window are
 * accepted. Each proof's jti is remembered for two minutes so a captured
 * proof cannot be replayed within its own lifetime.
 */

import { createHash, createHmac } from 'node:crypto';
import { EmbeddedJWK, calculateJwkThumbprint, decodeProtectedHeader, jwtVerify } from 'jose';
import { keys } from '../security/keys.ts';
import { DPOP_ALGORITHMS } from './config.ts';

const NONCE_WINDOW_MS = 5 * 60_000;
const JTI_TTL_MS = 2 * 60_000;

export type DpopErrorCode = 'invalid_dpop_proof' | 'use_dpop_nonce';

export class DpopError extends Error {
  readonly code: DpopErrorCode;
  constructor(code: DpopErrorCode, message: string) {
    super(message);
    this.name = 'DpopError';
    this.code = code;
  }
}

function nonceFor(window: number): string {
  return createHmac('sha256', keys().internalMacKey).update(`dpop-nonce:${window}`).digest('base64url');
}

/** The nonce clients should use now. Sent in a DPoP-Nonce header. */
export function currentDpopNonce(): string {
  return nonceFor(Math.floor(Date.now() / NONCE_WINDOW_MS));
}

function nonceValid(nonce: unknown): boolean {
  if (typeof nonce !== 'string') return false;
  const window = Math.floor(Date.now() / NONCE_WINDOW_MS);
  return nonce === nonceFor(window) || nonce === nonceFor(window - 1);
}

/** Proof ids seen recently. Per process, like the other in-memory stores. */
const seen = new Map<string, number>();

function claimJti(key: string): boolean {
  const now = Date.now();
  if (seen.size > 10_000) for (const [k, expiry] of seen) if (expiry <= now) seen.delete(k);
  const expiry = seen.get(key);
  if (expiry !== undefined && expiry > now) return false;
  seen.set(key, now + JTI_TTL_MS);
  return true;
}

/**
 * The comparable form of an htu: scheme, host and port lowercased, path kept,
 * query and fragment dropped (RFC 9449 section 4.3).
 */
export function normalizeHtu(value: string): string | null {
  try {
    // The URL parser already lowercases scheme and host and drops a default
    // port; the path is case-sensitive and is kept as it is.
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return null;
  }
}

export interface ProofCheck {
  /** HTTP method of this request. */
  htm: string;
  /** Absolute URL of this request. */
  htu: string;
  /** The access token being presented, if any; its hash must match `ath`. */
  accessToken?: string;
  /** The thumbprint the proof's key must have, if the token is already bound. */
  expectedJkt?: string | null;
}

/** Verifies a DPoP proof and returns its key's thumbprint. Throws DpopError. */
export async function verifyDpopProof(proof: unknown, check: ProofCheck): Promise<{ jkt: string }> {
  if (typeof proof !== 'string' || proof.length === 0 || proof.length > 4096) {
    throw new DpopError('invalid_dpop_proof', 'A DPoP proof is required.');
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new DpopError('invalid_dpop_proof', 'The DPoP proof is malformed.');
  }
  // A proof carrying a private key is a client bug that leaks the key; refuse it.
  if (!header.jwk || 'd' in header.jwk) throw new DpopError('invalid_dpop_proof', 'The proof must carry a public key.');

  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: [...DPOP_ALGORITHMS],
      maxTokenAge: '60s',
      clockTolerance: 5
    }));
  } catch (error) {
    throw new DpopError('invalid_dpop_proof', `The DPoP proof did not verify: ${(error as Error).message}`);
  }

  if (typeof payload.jti !== 'string' || payload.jti.length < 8 || payload.jti.length > 256) {
    throw new DpopError('invalid_dpop_proof', 'The proof needs a unique jti.');
  }
  if (payload.htm !== check.htm.toUpperCase()) throw new DpopError('invalid_dpop_proof', 'htm does not match this request.');
  const presentedHtu = typeof payload.htu === 'string' ? normalizeHtu(payload.htu) : null;
  if (!presentedHtu || presentedHtu !== normalizeHtu(check.htu)) {
    throw new DpopError('invalid_dpop_proof', 'htu does not match this request.');
  }
  if (check.accessToken !== undefined) {
    const ath = createHash('sha256').update(check.accessToken).digest('base64url');
    if (payload.ath !== ath) throw new DpopError('invalid_dpop_proof', 'ath does not match the access token.');
  }

  const jkt = await calculateJwkThumbprint(header.jwk, 'sha256');
  if (check.expectedJkt && jkt !== check.expectedJkt) {
    throw new DpopError('invalid_dpop_proof', 'The proof was not signed by the key this token is bound to.');
  }

  // Checked after the signature, so an unauthenticated request cannot learn
  // or burn nonces, and before the jti is claimed, so a client that only
  // needed a fresh nonce can resend the same proof contents with it.
  if (!nonceValid(payload.nonce)) throw new DpopError('use_dpop_nonce', 'Use the nonce in the DPoP-Nonce header.');
  if (!claimJti(`${jkt}:${payload.jti}`)) throw new DpopError('invalid_dpop_proof', 'This proof was already used.');

  return { jkt };
}
