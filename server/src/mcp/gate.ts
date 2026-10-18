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
import type { Db } from '../db/index.ts';
import { MCP_BASE_URL } from '../config.ts';
import { SCOPES_SUPPORTED, type Scope } from '../oauth/config.ts';
import { verifyOAuthAccessToken } from '../oauth/verify.ts';
import { requiredScopeFor } from './config.ts';
import type { Identity } from '../domain/types.ts';
import { AppError } from '../errors.ts';
import type { BucketResult } from '../security/rate-limit.ts';

const PRM_URL = `${MCP_BASE_URL}/.well-known/oauth-protected-resource/mcp`;

export function bearerFrom(req: Request): string | null {
  const header = req.get('authorization');
  if (!header || !/^bearer /i.test(header)) return null;
  return header.slice(7).trim() || null;
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
    const scope = requiredScopeFor(name);
    if (!scope) continue;
    tools.push(name);
    scopes.add(scope);
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
}

export type GateOutcome =
  | { proceed: true; identity: Identity | null; challenge?: string }
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
  db: Db, req: Request, res: Response, requestId: string, limits: GateLimits
): Promise<GateOutcome> {
  const token = bearerFrom(req);
  const wanted = protectedCallsIn(req.body);
  const verified = token ? await verifyOAuthAccessToken(db, token, wanted.scopes) : null;

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

  const identity: Identity | null = verified?.ok
    ? { accountId: verified.accountId, channel: 'mcp', requestId }
    : null;

  // Public calls behave differently for a signed-in caller, and
  // get_auth_status exists to say so, so the identity is still passed on.
  if (wanted.tools.length === 0) return { proceed: true, identity };

  // The union: a batch is authorized only if the token can make every
  // protected call in it.
  if (identity) return { proceed: true, identity };

  const insufficient = verified?.ok === false && verified.reason === 'insufficient_scope';
  const error = insufficient ? 'insufficient_scope' : 'invalid_token';
  const description = insufficient
    ? `Scope ${wanted.scopes.join(' ')} is required`
    : 'Authentication required for this tool';

  if (wantsToolChallenge(req)) {
    // Proceed with no identity: every protected handler then refuses, and
    // carries the challenge. Never with the token's identity — a token short
    // of scope must not reach a handler that trusts the gate for scope.
    return { proceed: true, identity: null, challenge: challengeValue(error, description, SCOPES_SUPPORTED) };
  }

  // Name every scope the integration needs, not just the missing one: a
  // client that re-consents with only what this challenge lists can lose
  // permissions it already had.
  challenge(res, insufficient ? 403 : 401, error, description, SCOPES_SUPPORTED);
  return { proceed: false };
}
