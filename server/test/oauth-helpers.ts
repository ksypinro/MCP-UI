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
  process.env.AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE = '100000';
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
    body: JSON.stringify({
      redirect_uris: redirectUris,
      client_name: 'Test Client',
      // Loopback callbacks are a native app's; anything else here is a web client's.
      application_type: redirectUris.every((uri) => new URL(uri).hostname === '127.0.0.1') ? 'native' : 'web'
    })
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

/** The hidden CSRF field every authorization form carries. */
export function csrfFrom(html: string): string | null {
  return html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? null;
}

/**
 * Just enough of a browser to walk the authorization pages: it keeps cookies
 * for the server's origin, and follows redirects that stay on it. A redirect
 * anywhere else — the client's callback — is where it stops.
 */
export class Browser {
  readonly base: string;
  readonly cookies = new Map<string, string>();

  constructor(base: string) {
    this.base = base;
  }

  async request(pathOrUrl: string, init: RequestInit = {}): Promise<Response> {
    const url = new URL(pathOrUrl, this.base);
    const headers = new Headers(init.headers);
    if (this.cookies.size > 0) {
      headers.set('cookie', [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; '));
    }
    const response = await fetch(url, { ...init, headers, redirect: 'manual' });
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split(';');
      const index = pair!.indexOf('=');
      const name = pair!.slice(0, index).trim();
      const value = pair!.slice(index + 1).trim();
      const expired = attributes.some((a) => /^\s*max-age=0\b/i.test(a) || /^\s*expires=Thu, 01 Jan 1970/i.test(a));
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    return response;
  }

  /** Follows same-origin redirects; returns the final response, or the first off-site Location. */
  async follow(response: Response): Promise<{ response: Response; offsite: URL | null }> {
    let current = response;
    for (let hops = 0; hops < 10; hops++) {
      const location = current.headers.get('location');
      if (current.status < 300 || current.status >= 400 || !location) return { response: current, offsite: null };
      const next = new URL(location, this.base);
      if (next.origin !== new URL(this.base).origin) return { response: current, offsite: next };
      current = await this.request(next.toString());
    }
    throw new Error('too many redirects');
  }

  get(path: string): Promise<Response> {
    return this.request(path);
  }

  post(path: string, fields: Record<string, string | undefined>): Promise<Response> {
    return this.request(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: encode(fields)
    });
  }
}

export interface SignInOutcome {
  /** Where the flow ended up: the client's callback, if it got that far. */
  callback: URL | null;
  /** The last page rendered by the server, if it stopped on one. */
  page: Response | null;
  html: string;
}

/**
 * Starts an authorization in `browser`, signs in (or up) when asked to, and
 * approves when shown the consent page. Stops at the client's callback or at
 * any page it does not know how to answer.
 */
export async function walkAuthorization(
  browser: Browser,
  query: Record<string, string | undefined>,
  credentials: { mode: 'login' | 'signup'; username: string; password?: string } | null,
  options: { approve?: boolean } = {}
): Promise<SignInOutcome> {
  let step = await browser.follow(await browser.get(authorizeUrl(browser.base, query)));
  for (let rounds = 0; rounds < 4; rounds++) {
    if (step.offsite) return { callback: step.offsite, page: null, html: '' };
    const html = await step.response.text();
    const pending = pendingIdFrom(html);
    const csrf = csrfFrom(html);
    if (!pending || !csrf) return { callback: null, page: step.response, html };

    if (html.includes('action="/login"') && credentials) {
      step = await browser.follow(await browser.post('/login', {
        pending, csrf, mode: credentials.mode, username: credentials.username,
        password: credentials.password ?? 'correct horse battery staple'
      }));
      credentials = { ...credentials, mode: 'login' };
      continue;
    }
    if (html.includes('action="/consent"') && options.approve !== false) {
      step = await browser.follow(await browser.post('/consent', { pending, csrf }));
      continue;
    }
    return { callback: null, page: step.response, html };
  }
  throw new Error('authorization did not finish');
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
  /** The browser the person used, still holding its authorization-server session. */
  browser: Browser;
}

/** Drives a whole authorization the way a host would, ending with a code. */
export async function authorizeAs(
  base: string,
  options: {
    username?: string; scope?: string; state?: string; clientId?: string;
    mode?: 'login' | 'signup'; browser?: Browser;
  } = {}
): Promise<CompletedAuthorization> {
  const clientId = options.clientId ?? (await sharedClient(base));
  const { verifier, challenge } = pkcePair();
  const username = options.username ?? `user${randomBytes(4).toString('hex')}`;
  const state = options.state ?? 'state-value';
  const browser = options.browser ?? new Browser(base);

  const outcome = await walkAuthorization(browser, {
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(options.scope !== undefined ? { scope: options.scope } : {})
  }, { mode: options.mode ?? 'signup', username });

  if (!outcome.callback) throw new Error(`authorization stopped on a page: ${outcome.html.slice(0, 300)}`);
  const code = outcome.callback.searchParams.get('code');
  if (!code) throw new Error(`no code in redirect: ${outcome.callback}`);

  return {
    code,
    state: outcome.callback.searchParams.get('state'),
    iss: outcome.callback.searchParams.get('iss'),
    clientId,
    verifier,
    username,
    browser
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
