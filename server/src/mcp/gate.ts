/**
 * The authorization gate, at the HTTP layer.
 *
 * This runs on the parsed JSON-RPC body before the MCP SDK ever sees it,
 * because an unauthenticated protected call has to fail as an HTTP 401 with a
 * WWW-Authenticate challenge. Once a tool handler is running its return value
 * is already destined for a 200, and a 200 carrying isError is an
 * application-level failure: the host passes the text to the model and moves
 * on, and no authentication prompt appears. Spec section 7.5.
 */

import type { Request, Response } from 'express';
import { credentialFrom } from '../security/credentials.ts';
import { DpopError, currentDpopNonce, verifyDpopProof } from '../oauth/dpop.ts';
import type { ReplayStore } from '../security/replay.ts';
import { metrics } from '../observability/metrics.ts';
import { MCP_PATH } from './config.ts';
import type { TokenVerifier } from '../security/verifier.ts';
import { MCP_BASE_URL } from '../config.ts';
import { DPOP_ALGORITHMS, SCOPES_SUPPORTED, type Scope } from '../oauth/config.ts';
import { policyFor } from './policy.ts';
import type { Caller } from '../domain/types.ts';
import { AppError } from '../errors.ts';
import type { BucketResult } from '../security/rate-limit.ts';

const PRM_URL = `${MCP_BASE_URL}/.well-known/oauth-protected-resource/mcp`;

/** The presented token, in either scheme. Kept for callers that only need the value. */
export function bearerFrom(req: Request): string | null {
  return credentialFrom(req)?.token ?? null;
}

/**
 * Answers a request whose token is bound to a DPoP key but whose proof is
 * missing or wrong (RFC 9449 section 7.1). A fresh nonce rides along, so a
 * client told to use one can retry at once.
 */
function dpopChallenge(res: Response, error: DpopError): void {
  metrics.inc('challenge_issued', { status: '401', scheme: 'dpop' });
  res
    .status(401)
    .set('WWW-Authenticate',
      `DPoP error="${error.code}", error_description="${error.message}", algs="${DPOP_ALGORITHMS.join(' ')}"`)
    .set('DPoP-Nonce', currentDpopNonce())
    .json({ error: error.code, error_description: error.message });
}

/**
 * Every protected tool named in this body, and the scopes they need together.
 *
 * All of them, not the first one. A JSON-RPC body may be a batch, and the SDK
 * executes every call in it — so authorizing only the first protected call
 * lets any other ride in behind it. A devices:read token sending
 * [list_devices, control_device] was able to change a device's state.
 */
export function protectedCallsIn(body: unknown): { tools: string[]; scopes: Scope[] } {
  const tools: string[] = [];
  const scopes = new Set<Scope>();

  for (const message of Array.isArray(body) ? body : [body]) {
    if (!message || typeof message !== 'object') continue;
    const { method, params } = message as { method?: unknown; params?: { name?: unknown } };
    if (method !== 'tools/call') continue;
    const name = params?.name;
    if (typeof name !== 'string') continue;
    const policy = policyFor(name);
    // A name this server does not have is treated as protected, so the
    // answer to an unknown tool without a token is a challenge, never an
    // anonymous run. With a token, the SDK reports the tool as unknown.
    if (policy && !policy.scope) continue;
    tools.push(name);
    if (policy?.scope) scopes.add(policy.scope);
  }

  return { tools, scopes: [...scopes] };
}

/** The value of a WWW-Authenticate challenge, shared by the HTTP and tool-result forms. */
export function challengeValue(error: string, description: string, scopes: readonly string[]): string {
  return `Bearer error="${error}", error_description="${description}", `
    + `resource_metadata="${PRM_URL}", scope="${scopes.join(' ')}"`;
}

function challenge(
  res: Response, status: 401 | 403, error: string, description: string, scopes: readonly string[]
): void {
  metrics.inc('challenge_issued', { status: String(status), scheme: 'bearer' });
  res
    .status(status)
    .set('WWW-Authenticate', challengeValue(error, description, scopes))
    .json({ error, error_description: description });
}

/**
 * Whether this caller should receive its authorization challenge as a tool
 * result rather than as an HTTP status.
 *
 * ChatGPT starts account linking from a tool error carrying
 * `_meta["mcp/www_authenticate"]` on a tool that declares `securitySchemes`;
 * Claude starts it only from a transport 401. Off by default. When on, it
 * applies only to requests a proxy we control has marked as coming from
 * ChatGPT (by its mTLS client certificate), because the header is otherwise
 * forgeable and would let anyone downgrade a 401 into a tool error.
 */
function wantsToolChallenge(req: Request): boolean {
  return process.env.CHATGPT_TOOL_CHALLENGE === 'trusted-header'
    && Boolean(process.env.TRUST_PROXY)
    && req.get('x-verified-client') === 'chatgpt';
}

export interface GateLimits {
  /** Requests with no verified token, keyed by client address. */
  perAddress: (key: string) => Promise<BucketResult>;
  /** Requests whose token verified, keyed by grant. */
  perGrant: (key: string) => Promise<BucketResult>;
  /** Where DPoP proof ids are remembered. */
  replay: ReplayStore;
}

export type GateOutcome =
  | { proceed: true; caller: Caller; challenge?: string }
  | { proceed: false };

/**
 * Decides whether this request reaches the MCP layer, and with what identity.
 *
 * Public calls fall through with a null identity. `initialize`, `tools/list`
 * and `resources/read` are never gated, which is what lets a host discover the
 * server before anyone has signed in.
 *
 * The rate-limit bucket is chosen only after the token has been verified. A
 * verified token counts against its grant, so a host serving many users from
 * one egress address does not throttle them all together. Anything else — no
 * token, or a token that does not verify — counts against the address.
 * Choosing by the token *before* verifying it let a random bearer string buy a
 * fresh, empty bucket on every request.
 */
export async function gate(
  verifier: TokenVerifier, req: Request, res: Response, requestId: string, limits: GateLimits
): Promise<GateOutcome> {
  const credential = credentialFrom(req);
  const token = credential?.token ?? null;
  const wanted = protectedCallsIn(req.body);
  const verified = token ? await verifier.oauth(token, wanted.scopes) : null;

  const grantId = verified && (verified.ok || verified.reason === 'insufficient_scope')
    ? verified.grantId
    : null;
  const allowed = grantId
    ? await limits.perGrant(`mcp-grant:${grantId}`)
    : await limits.perAddress(`mcp-ip:${req.ip ?? 'unknown'}`);
  if (!allowed.ok) {
    res.setHeader('retry-after', String(allowed.retryAfter));
    throw new AppError('RATE_LIMITED');
  }

  // A token bound to a DPoP key is worthless without a proof from that key:
  // presented as a plain Bearer token, or with a bad proof, it is refused
  // however valid it otherwise is.
  if (verified?.ok && verified.cnfJkt && token) {
    try {
      if (credential?.scheme !== 'DPoP') throw new DpopError('invalid_dpop_proof', 'This token must be presented with the DPoP scheme.', 'scheme');
      await verifyDpopProof(req.get('dpop'), {
        htm: req.method, htu: `${MCP_BASE_URL}${MCP_PATH}`, accessToken: token, expectedJkt: verified.cnfJkt, replay: limits.replay
      });
    } catch (error) {
      if (!(error instanceof DpopError)) throw error;
      dpopChallenge(res, error);
      return { proceed: false };
    }
  }

  const anonymous: Caller = { kind: 'anonymous', requestId };
  const caller: Caller = verified?.ok && token
    ? {
        kind: 'verified', accountId: verified.accountId, clientId: verified.clientId,
        grantId: verified.grantId, channel: 'mcp', scopes: verified.scopes, requestId, credential: token
      }
    : anonymous;

  // Public calls behave differently for a signed-in caller, and
  // get_auth_status exists to say so, so the caller is still passed on.
  if (wanted.tools.length === 0) return { proceed: true, caller };

  // The union: a batch is authorized only if the token can make every
  // protected call in it.
  if (caller.kind === 'verified') return { proceed: true, caller };

  const insufficient = verified?.ok === false && verified.reason === 'insufficient_scope';
  const error = insufficient ? 'insufficient_scope' : 'invalid_token';
  const description = insufficient
    ? `Scope ${wanted.scopes.join(' ')} is required`
    : 'Authentication required for this tool';

  if (wantsToolChallenge(req)) {
    // Proceed anonymously: every protected handler then refuses, and carries
    // the challenge. Never as the token's caller — a token short of scope
    // must not reach a handler that trusts the gate for scope.
    return { proceed: true, caller: anonymous, challenge: challengeValue(error, description, SCOPES_SUPPORTED) };
  }

  // Name every scope the integration needs, not just the missing one: a
  // client that re-consents with only what this challenge lists can lose
  // permissions it already had.
  challenge(res, insufficient ? 403 : 401, error, description, SCOPES_SUPPORTED);
  return { proceed: false };
}
