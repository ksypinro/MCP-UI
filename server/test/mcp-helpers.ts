import { createHash, randomBytes } from 'node:crypto';
import {
  REDIRECT_URI, authorizeAs, exchange, form, json, pendingIdFrom, registerClient,
  type Harness
} from './oauth-helpers.ts';

export interface RpcResponse {
  status: number;
  headers: Headers;
  body: any;
}

/**
 * Speaks JSON-RPC to /mcp directly rather than through the SDK client.
 *
 * The HTTP status and the WWW-Authenticate header are the whole point of the
 * gate, and an SDK client hides both behind an exception.
 */
export async function rpc(
  base: string, message: unknown, token?: string | null
): Promise<RpcResponse> {
  const response = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // Streamable HTTP requires both.
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify(message)
  });
  const text = await response.text();
  let body: unknown = null;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: response.status, headers: response.headers, body };
}

let id = 0;
export const nextId = () => ++id;

export const initialize = (base: string, token?: string | null) =>
  rpc(base, {
    jsonrpc: '2.0', id: nextId(), method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } }
  }, token);

export const toolsList = (base: string, token?: string | null) =>
  rpc(base, { jsonrpc: '2.0', id: nextId(), method: 'tools/list' }, token);

export const callTool = (
  base: string, name: string, args: Record<string, unknown> = {}, token?: string | null
) => rpc(base, {
  jsonrpc: '2.0', id: nextId(), method: 'tools/call', params: { name, arguments: args }
}, token);

/** A full OAuth authorization, returning a usable access token. */
export async function tokenFor(
  h: Harness, options: { username?: string; scope?: string } = {}
): Promise<{ accessToken: string; username: string }> {
  const authorization = await authorizeAs(h.base, options);
  const { body } = await exchange(h.base, authorization);
  if (!body.access_token) throw new Error(`no token: ${JSON.stringify(body)}`);
  return { accessToken: body.access_token, username: authorization.username };
}

/**
 * A token for an account that already exists, at a chosen scope.
 *
 * authorizeAs signs up a new person each time, so it cannot produce two
 * differently scoped tokens for the same devices.
 */
export async function tokenForExisting(
  h: Harness, username: string, scope: string
): Promise<string> {
  const clientId = await registerClient(h.base);
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const page = await fetch(`${h.base}/authorize?` + new URLSearchParams({
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256', scope
  })).then((r) => r.text());
  const pending = pendingIdFrom(page);
  if (!pending) throw new Error('authorize did not render a form');

  const redirected = await fetch(`${h.base}/authorize`, form({
    pending, mode: 'login', username, password: 'correct horse battery staple'
  }));
  const location = redirected.headers.get('location');
  if (!location) throw new Error(`login did not redirect (${redirected.status})`);
  const code = new URL(location).searchParams.get('code');
  if (!code) throw new Error('no code in redirect');

  const body = await fetch(`${h.base}/token`, json({
    grant_type: 'authorization_code', code, code_verifier: verifier,
    redirect_uri: REDIRECT_URI, client_id: clientId
  })).then((r) => r.json()) as Record<string, string>;

  if (!body.access_token) throw new Error(`no token: ${JSON.stringify(body)}`);
  return body.access_token;
}

export function structured(response: RpcResponse): any {
  return response.body?.result?.structuredContent;
}

export function isToolError(response: RpcResponse): boolean {
  return response.body?.result?.isError === true;
}
