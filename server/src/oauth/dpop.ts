/**
 * DPoP (RFC 9449): proof that whoever presents a token holds the private key
 * it was bound to. Architecture sections 5.6 and 8.1.
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
 * proof cannot be replayed within its own lifetime, in a store every process
 * shares when there is more than one (security/replay.ts).
 */

import { createHash, createHmac } from 'node:crypto';
import { EmbeddedJWK, calculateJwkThumbprint, decodeProtectedHeader, jwtVerify } from 'jose';
import { keys } from '../security/keys.ts';
import { DPOP_ALGORITHMS } from './config.ts';
import type { ReplayStore } from '../security/replay.ts';
import { metrics } from '../observability/metrics.ts';

const NONCE_WINDOW_MS = 5 * 60_000;
const JTI_TTL_SECONDS = 120;

export type DpopErrorCode = 'invalid_dpop_proof' | 'use_dpop_nonce';

/** Why a proof was refused, for the dpop_rejected metric. Never shown to the client. */
export type DpopReason =
  | 'missing' | 'malformed' | 'private_key' | 'signature' | 'jti' | 'htm' | 'htu' | 'ath' | 'key_mismatch'
  | 'nonce' | 'replay' | 'scheme';

export class DpopError extends Error {
  readonly code: DpopErrorCode;
  readonly reason: DpopReason;
  constructor(code: DpopErrorCode, message: string, reason: DpopReason = code === 'use_dpop_nonce' ? 'nonce' : 'malformed') {
    super(message);
    this.name = 'DpopError';
    this.code = code;
    this.reason = reason;
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
  /** Where proof ids are remembered. Shared by every process serving traffic. */
  replay: ReplayStore;
}

/** Verifies a DPoP proof and returns its key's thumbprint. Throws DpopError, and counts it. */
export async function verifyDpopProof(proof: unknown, check: ProofCheck): Promise<{ jkt: string }> {
  try {
    return await verifyProof(proof, check);
  } catch (error) {
    if (error instanceof DpopError) metrics.inc('dpop_rejected', { reason: error.reason });
    throw error;
  }
}

async function verifyProof(proof: unknown, check: ProofCheck): Promise<{ jkt: string }> {
  if (typeof proof !== 'string' || proof.length === 0 || proof.length > 4096) {
    throw new DpopError('invalid_dpop_proof', 'A DPoP proof is required.', 'missing');
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new DpopError('invalid_dpop_proof', 'The DPoP proof is malformed.');
  }
  // A proof carrying a private key is a client bug that leaks the key; refuse it.
  if (!header.jwk || 'd' in header.jwk) throw new DpopError('invalid_dpop_proof', 'The proof must carry a public key.', 'private_key');

  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(proof, EmbeddedJWK, {
      typ: 'dpop+jwt',
      algorithms: [...DPOP_ALGORITHMS],
      maxTokenAge: '60s',
      clockTolerance: 5
    }));
  } catch (error) {
    throw new DpopError('invalid_dpop_proof', `The DPoP proof did not verify: ${(error as Error).message}`, 'signature');
  }

  if (typeof payload.jti !== 'string' || payload.jti.length < 8 || payload.jti.length > 256) {
    throw new DpopError('invalid_dpop_proof', 'The proof needs a unique jti.', 'jti');
  }
  if (payload.htm !== check.htm.toUpperCase()) throw new DpopError('invalid_dpop_proof', 'htm does not match this request.', 'htm');
  const presentedHtu = typeof payload.htu === 'string' ? normalizeHtu(payload.htu) : null;
  if (!presentedHtu || presentedHtu !== normalizeHtu(check.htu)) {
    throw new DpopError('invalid_dpop_proof', 'htu does not match this request.', 'htu');
  }
  if (check.accessToken !== undefined) {
    const ath = createHash('sha256').update(check.accessToken).digest('base64url');
    if (payload.ath !== ath) throw new DpopError('invalid_dpop_proof', 'ath does not match the access token.', 'ath');
  }

  const jkt = await calculateJwkThumbprint(header.jwk, 'sha256');
  if (check.expectedJkt && jkt !== check.expectedJkt) {
    throw new DpopError('invalid_dpop_proof', 'The proof was not signed by the key this token is bound to.', 'key_mismatch');
  }

  // Checked after the signature, so an unauthenticated request cannot learn
  // or burn nonces, and before the jti is claimed, so a client that only
  // needed a fresh nonce can resend the same proof contents with it.
  if (!nonceValid(payload.nonce)) throw new DpopError('use_dpop_nonce', 'Use the nonce in the DPoP-Nonce header.');
  if (!(await check.replay.claim(`dpop-jti:${jkt}:${payload.jti}`, JTI_TTL_SECONDS))) throw new DpopError('invalid_dpop_proof', 'This proof was already used.', 'replay');

  return { jkt };
}
