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
import { BASE_URL } from '../config.ts';
import { SCOPES, type Scope } from '../oauth/config.ts';
import { verifyOAuthAccessToken } from '../oauth/verify.ts';
import { requiredScopeFor } from './config.ts';
import type { Identity } from '../domain/types.ts';

const PRM_URL = `${BASE_URL}/.well-known/oauth-protected-resource/mcp`;

export function bearerFrom(req: Request): string | null {
  const header = req.get('authorization');
  if (!header || !/^bearer /i.test(header)) return null;
  return header.slice(7).trim() || null;
}

/**
 * The protected tool named in this body, if any.
 *
 * Handles a batch, because a batch containing one protected call must still
 * produce a challenge rather than slipping through alongside public ones.
 */
export function protectedToolIn(body: unknown): { tool: string; scope: Scope } | null {
  for (const message of Array.isArray(body) ? body : [body]) {
    if (!message || typeof message !== 'object') continue;
    const { method, params } = message as { method?: unknown; params?: { name?: unknown } };
    if (method !== 'tools/call') continue;
    const name = params?.name;
    if (typeof name !== 'string') continue;
    const scope = requiredScopeFor(name);
    if (scope) return { tool: name, scope };
  }
  return null;
}

function challenge(
  res: Response, status: 401 | 403, error: string, description: string, scopes: readonly Scope[]
): void {
  res
    .status(status)
    .set(
      'WWW-Authenticate',
      `Bearer error="${error}", error_description="${description}", ` +
        `resource_metadata="${PRM_URL}", scope="${scopes.join(' ')}"`
    )
    .json({ error, error_description: description });
}

export type GateOutcome =
  | { proceed: true; identity: Identity | null }
  | { proceed: false };

/**
 * Decides whether this request reaches the MCP layer, and with what identity.
 *
 * Public calls fall through with a null identity. `initialize`, `tools/list`
 * and `resources/read` are never gated, which is what lets a host discover the
 * server before anyone has signed in.
 */
export async function gate(db: Db, req: Request, res: Response, requestId: string): Promise<GateOutcome> {
  const token = bearerFrom(req);
  const wanted = protectedToolIn(req.body);

  if (!wanted) {
    // Still resolve a token when one is present: public tools behave
    // differently for a signed-in caller, and get_auth_status exists to say so.
    if (!token) return { proceed: true, identity: null };
    const verified = await verifyOAuthAccessToken(db, token);
    return {
      proceed: true,
      identity: verified.ok
        ? { accountId: verified.accountId, channel: 'mcp', requestId }
        : null
    };
  }

  const verified = await verifyOAuthAccessToken(db, token, [wanted.scope]);

  if (verified.ok) {
    return { proceed: true, identity: { accountId: verified.accountId, channel: 'mcp', requestId } };
  }

  if (verified.reason === 'insufficient_scope') {
    // Name every scope the integration needs, not just the missing one:
    // a client that re-consents with only what this challenge lists can lose
    // permissions it already had.
    challenge(res, 403, 'insufficient_scope', `Scope ${wanted.scope} is required`, SCOPES);
    return { proceed: false };
  }

  challenge(res, 401, 'invalid_token', 'Authentication required for this tool', SCOPES);
  return { proceed: false };
}
