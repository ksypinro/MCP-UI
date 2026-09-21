import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { createDb, type Db } from '../src/db/index.ts';
import { createApp } from '../src/http/app.ts';

export interface Harness {
  db: Db;
  base: string;
  close: () => Promise<void>;
}

export async function startServer(): Promise<Harness> {
  // A suite makes far more authorization attempts in a minute than a person
  // ever would, and the shipped limit is set for the person. Raising it here
  // keeps the production default honest instead of loosening it for everyone.
  process.env.AUTH_RATE_LIMIT_PER_MINUTE = '100000';
  const db = await createDb();
  const server: Server = createApp(db).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    db,
    base,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
      await db.close();
    }
  };
}

export const REDIRECT_URI = 'http://127.0.0.1:41234/callback';

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

export async function registerClient(
  base: string, redirectUris: string[] = [REDIRECT_URI]
): Promise<string> {
  const response = await fetch(`${base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: redirectUris, client_name: 'Test Client' })
  });
  const body = await response.json() as { client_id?: string; error?: string };
  if (response.status !== 201 || !body.client_id) {
    // Swallowing this produced four confusing "Unrecognised application"
    // failures several tests later, when registration was in fact rate
    // limited. Fail where it happens.
    throw new Error(`registration failed: ${response.status} ${JSON.stringify(body)}`);
  }
  return body.client_id;
}

/**
 * One client shared across the tests that do not care which client they are.
 *
 * Registration is rate limited, as an open endpoint has to be, and registering
 * afresh in every test exhausts that budget partway through the file.
 */
let shared: { base: string; clientId: string } | null = null;

export async function sharedClient(base: string): Promise<string> {
  if (shared?.base === base) return shared.clientId;
  const clientId = await registerClient(base);
  shared = { base, clientId };
  return clientId;
}

export function authorizeUrl(
  base: string, params: Record<string, string | undefined>
): string {
  const url = new URL(`${base}/authorize`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.toString();
}

/** The hidden field carrying the opaque pending-authorization id. */
export function pendingIdFrom(html: string): string | null {
  return html.match(/name="pending" value="([^"]+)"/)?.[1] ?? null;
}

/**
 * `noUncheckedIndexedAccess` makes every lookup on a Record optional, and
 * response bodies are read that way throughout, so undefined is dropped here
 * rather than asserted away at fifteen call sites.
 */
function encode(fields: Record<string, string | undefined>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined) params.set(key, value);
  }
  return params;
}

export function form(fields: Record<string, string | undefined>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: encode(fields),
    redirect: 'manual'
  };
}

export function json(fields: Record<string, string | undefined>): RequestInit {
  return {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: encode(fields)
  };
}

export interface CompletedAuthorization {
  code: string;
  state: string | null;
  iss: string | null;
  clientId: string;
  verifier: string;
  username: string;
}

/** Drives a whole authorization the way a host would, ending with a code. */
export async function authorizeAs(
  base: string,
  options: { username?: string; scope?: string; state?: string; clientId?: string } = {}
): Promise<CompletedAuthorization> {
  const clientId = options.clientId ?? (await sharedClient(base));
  const { verifier, challenge } = pkcePair();
  const username = options.username ?? `user${randomBytes(4).toString('hex')}`;
  const state = options.state ?? 'state-value';

  const page = await fetch(authorizeUrl(base, {
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(options.scope !== undefined ? { scope: options.scope } : {})
  })).then((r) => r.text());

  const pending = pendingIdFrom(page);
  if (!pending) throw new Error(`authorize did not render a form: ${page.slice(0, 300)}`);

  const redirected = await fetch(`${base}/authorize`, form({
    pending, mode: 'signup', username, password: 'correct horse battery staple'
  }));

  const location = redirected.headers.get('location');
  if (!location) throw new Error(`authorize did not redirect (status ${redirected.status})`);
  const url = new URL(location);

  const code = url.searchParams.get('code');
  if (!code) throw new Error(`no code in redirect: ${location}`);

  return {
    code,
    state: url.searchParams.get('state'),
    iss: url.searchParams.get('iss'),
    clientId,
    verifier,
    username
  };
}

export async function exchange(
  base: string, authorization: CompletedAuthorization, overrides: Record<string, string | undefined> = {}
): Promise<{ status: number; body: Record<string, string> }> {
  const response = await fetch(`${base}/token`, json({
    grant_type: 'authorization_code',
    code: authorization.code,
    code_verifier: authorization.verifier,
    redirect_uri: REDIRECT_URI,
    client_id: authorization.clientId,
    ...overrides
  }));
  return { status: response.status, body: await response.json() as Record<string, string> };
}
