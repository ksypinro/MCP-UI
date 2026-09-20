/**
 * Stub OAuth 2.1 authorization server for the phase 0 spike.
 *
 * Implements only what a host actually exercises, but implements those parts
 * to spec, because the point of the spike is to find out whether real hosts
 * complete the flow: RFC 9728 protected resource metadata at both well-known
 * paths, RFC 8414 authorization server metadata advertising S256 and CIMD,
 * PKCE S256, RFC 8707 resource indicators bound into the token audience, and
 * RFC 9207 iss on the authorization response.
 */

import { Router, type Request, type Response } from 'express';
import { BASE_URL, RESOURCE_URI, SCOPES, type Scope } from './config.js';
import {
  consumeAuthCode, createAccount, getRegisteredClient, issueAccessToken, pkceS256,
  randomId, registerClient, revokeAccessToken, storeAuthCode, verifyCredentials
} from './store.js';

export const oauthRouter: Router = Router();

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string
  );
}

/* ---------------------------------------------------------------- metadata */

function protectedResourceMetadata() {
  return {
    resource: RESOURCE_URI,
    authorization_servers: [BASE_URL],
    scopes_supported: SCOPES,
    bearer_methods_supported: ['header']
  };
}

// Served at both paths. Clients try the path-suffixed form first when the
// resource URL has a path component, per RFC 9728 section 3.1.
oauthRouter.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json(protectedResourceMetadata());
});
oauthRouter.get('/.well-known/oauth-protected-resource/mcp', (_req, res) => {
  res.json(protectedResourceMetadata());
});

oauthRouter.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    revocation_endpoint: `${BASE_URL}/revoke`,
    registration_endpoint: `${BASE_URL}/register`,
    scopes_supported: SCOPES,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    // Both are required before Claude will choose CIMD over a registration
    // endpoint: its CIMD client authenticates as a public client, so the token
    // endpoint must accept PKCE-only requests with no client secret.
    token_endpoint_auth_methods_supported: ['none'],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true
  });
});

/* ------------------------------------------------------- client resolution */

function loopbackEquivalent(a: URL, b: URL): boolean {
  const loopback = (h: string) => h === '127.0.0.1' || h === '[::1]' || h === '::1' || h === 'localhost';
  // RFC 8252 section 7.3: native apps bind an ephemeral port, so ignore it.
  return loopback(a.hostname) && loopback(b.hostname) && a.pathname === b.pathname;
}

function redirectUriAllowed(requested: string, allowed: string[]): boolean {
  let candidate: URL;
  try {
    candidate = new URL(requested);
  } catch {
    return false;
  }
  return allowed.some((entry) => {
    if (entry === requested) return true;
    try {
      const known = new URL(entry);
      return loopbackEquivalent(candidate, known);
    } catch {
      return false;
    }
  });
}

/**
 * Resolves a client_id to its allowed redirect URIs.
 *
 * A URL-shaped client_id is a Client ID Metadata Document: fetch it, require it
 * to be self-referential, and take its redirect_uris. Anything else must have
 * come through Dynamic Client Registration.
 */
async function resolveClient(clientId: string): Promise<{ redirectUris: string[]; displayHost: string } | null> {
  if (clientId.startsWith('https://')) {
    try {
      const response = await fetch(clientId, { headers: { accept: 'application/json' } });
      if (!response.ok) return null;
      const doc = (await response.json()) as { client_id?: string; redirect_uris?: string[] };
      if (doc.client_id !== clientId) return null; // must be self-referential
      if (!Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) return null;
      // The consent screen shows the host of the client_id URL, never the
      // self-asserted client_name, which the document's author controls.
      return { redirectUris: doc.redirect_uris, displayHost: new URL(clientId).host };
    } catch {
      return null;
    }
  }
  const registered = getRegisteredClient(clientId);
  return registered ? { redirectUris: registered.redirectUris, displayHost: clientId } : null;
}

/* ------------------------------------------------- dynamic client registration */

/** Unauthenticated by design (that is what DCR is), so it needs a ceiling. */
const MAX_REGISTRATIONS = 200;
let registrationCount = 0;

oauthRouter.post('/register', (req: Request, res: Response) => {
  const redirectUris = (req.body?.redirect_uris ?? []) as string[];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    res.status(400).json({ error: 'invalid_client_metadata' });
    return;
  }
  if (++registrationCount > MAX_REGISTRATIONS) {
    res.status(429).json({ error: 'too_many_registrations' });
    return;
  }
  const clientId = `client_${randomId(8)}`;
  registerClient(clientId, redirectUris);
  res.status(201).json({
    client_id: clientId,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code']
  });
});

/* ---------------------------------------------------------------- authorize */

interface PendingAuthorization {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  resource: string;
  scopes: Scope[];
  displayHost: string;
  expiresAt: number;
}

/**
 * Pending authorizations live here, keyed by an opaque id, and only the id is
 * ever given to the browser.
 *
 * An earlier revision round-tripped this record through the form as unsigned
 * base64. That let anyone craft a context naming their own redirect_uri and
 * PKCE challenge, walk a victim through a real login page showing a spoofed
 * client name, and receive a live authorization code they could redeem. Client
 * and redirect_uri are validated once, here, and the browser never gets a say.
 */
const pendingAuthorizations = new Map<string, PendingAuthorization>();
const MAX_PENDING = 500;

function putPending(pending: PendingAuthorization): string {
  if (pendingAuthorizations.size > MAX_PENDING) {
    const now = Date.now();
    for (const [key, value] of pendingAuthorizations) {
      if (value.expiresAt < now) pendingAuthorizations.delete(key);
    }
  }
  const id = randomId(24);
  pendingAuthorizations.set(id, pending);
  return id;
}

function takePending(id: unknown): PendingAuthorization | null {
  if (typeof id !== 'string') return null;
  const pending = pendingAuthorizations.get(id);
  if (!pending) return null;
  if (pending.expiresAt < Date.now()) {
    pendingAuthorizations.delete(id);
    return null;
  }
  return pending;
}

function renderLoginPage(pendingId: string, pending: PendingAuthorization, mode: 'login' | 'signup', error?: string): string {
  const payload = escapeHtml(pendingId);
  const isSignup = mode === 'signup';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>IoT Switch — ${isSignup ? 'Sign Up' : 'Log In'}</title>
<style>
  :root { color-scheme: light dark; --fg:#141413; --bg:#faf9f5; --muted:#73726c; --line:#d8d6cc; --accent:#141413; }
  @media (prefers-color-scheme: dark) { :root { --fg:#faf9f5; --bg:#1f1e1d; --muted:#9c9a92; --line:#3d3d3a; --accent:#faf9f5; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center; padding:24px;
         font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--fg); background:var(--bg); }
  .card { width:100%; max-width:380px; }
  h1 { font-size:20px; margin:0 0 4px; }
  p.sub { margin:0 0 20px; color:var(--muted); font-size:14px; }
  .tabs { display:flex; gap:8px; margin-bottom:20px; }
  .tabs a { flex:1; text-align:center; padding:9px; border:1px solid var(--line); border-radius:8px;
            text-decoration:none; color:var(--fg); font-size:14px; }
  .tabs a[aria-current="true"] { background:var(--accent); color:var(--bg); border-color:var(--accent); font-weight:600; }
  label { display:block; font-size:13px; font-weight:600; margin:0 0 6px; }
  input { width:100%; padding:11px 12px; font-size:16px; border:1px solid var(--line);
          border-radius:8px; background:var(--bg); color:var(--fg); margin-bottom:16px; }
  button { width:100%; padding:12px; font-size:15px; font-weight:600; border:0; border-radius:8px;
           background:var(--accent); color:var(--bg); cursor:pointer; }
  .err { background:#f7ecec; color:#7f2c28; padding:10px 12px; border-radius:8px; font-size:14px; margin-bottom:16px; }
  @media (prefers-color-scheme: dark) { .err { background:#602a28; color:#ee8884; } }
  .grant { margin-top:20px; padding-top:16px; border-top:1px solid var(--line); font-size:13px; color:var(--muted); }
  code { font-family:ui-monospace,monospace; font-size:12px; }
</style>
</head>
<body>
  <main class="card">
    <h1>IoT Switch</h1>
    <p class="sub">${isSignup ? 'Create an account to control your devices.' : 'Log in to control your devices.'}</p>
    <nav class="tabs">
      <a href="?${new URLSearchParams({ p: payload, mode: 'login' })}" aria-current="${!isSignup}">Log In</a>
      <a href="?${new URLSearchParams({ p: payload, mode: 'signup' })}" aria-current="${isSignup}">Sign Up</a>
    </nav>
    ${error ? `<p class="err">${escapeHtml(error)}</p>` : ''}
    <form method="post" action="/authorize">
      <input type="hidden" name="p" value="${payload}">
      <input type="hidden" name="mode" value="${mode}">
      <label for="u">Username</label>
      <input id="u" name="username" autocomplete="username" autocapitalize="none" autocorrect="off" required>
      <label for="pw">Password</label>
      <input id="pw" name="password" type="password"
             autocomplete="${isSignup ? 'new-password' : 'current-password'}" required>
      <button type="submit">${isSignup ? 'Sign Up' : 'Log In'}</button>
    </form>
    <p class="grant">
      <strong>${escapeHtml(pending.displayHost)}</strong> is requesting access to your devices:
      <code>${pending.scopes.join(' ')}</code>
    </p>
  </main>
</body>
</html>`;
}

oauthRouter.get('/authorize', async (req: Request, res: Response) => {
  // Mode switch on an authorization already in flight.
  if (typeof req.query.p === 'string') {
    const resume = takePending(req.query.p);
    if (!resume) {
      res.status(400).send('invalid_request: this authorization expired, start again from the app');
      return;
    }
    const mode = req.query.mode === 'signup' ? 'signup' : 'login';
    res.type('html').send(renderLoginPage(req.query.p, resume, mode));
    return;
  }

  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, resource, scope } = req.query;

  if (typeof client_id !== 'string' || typeof redirect_uri !== 'string') {
    res.status(400).send('invalid_request: client_id and redirect_uri are required');
    return;
  }
  if (code_challenge_method !== 'S256' || typeof code_challenge !== 'string') {
    res.status(400).send('invalid_request: PKCE with S256 is required');
    return;
  }

  const client = await resolveClient(client_id);
  if (!client) {
    res.status(400).send('invalid_client: client_id could not be resolved via CIMD or registration');
    return;
  }
  if (!redirectUriAllowed(redirect_uri, client.redirectUris)) {
    // Never redirect to an unverified URI; report in place instead.
    res.status(400).send('invalid_request: redirect_uri is not registered for this client');
    return;
  }

  const requested = typeof scope === 'string' ? scope.split(/\s+/).filter(Boolean) : [];
  const scopes = SCOPES.filter((s) => requested.length === 0 || requested.includes(s));
  if (scopes.length === 0) {
    // Issuing a token that authorizes nothing would leave the host in a
    // step-up loop it can never satisfy.
    res.status(400).send(`invalid_scope: none of "${escapeHtml(requested.join(' '))}" is supported`);
    return;
  }

  const pending: PendingAuthorization = {
    clientId: client_id,
    redirectUri: redirect_uri,
    state: typeof state === 'string' ? state : '',
    codeChallenge: code_challenge,
    resource: typeof resource === 'string' ? resource : RESOURCE_URI,
    scopes,
    displayHost: client.displayHost,
    expiresAt: Date.now() + 10 * 60_000
  };

  const pendingId = putPending(pending);
  res.type('html').send(renderLoginPage(pendingId, pending, 'login'));
});

oauthRouter.post('/authorize', (req: Request, res: Response) => {
  const pendingId = typeof req.body?.p === 'string' ? req.body.p : '';
  const pending = takePending(pendingId);
  const mode = req.body?.mode === 'signup' ? 'signup' : 'login';
  const username = String(req.body?.username ?? '');
  const password = String(req.body?.password ?? '');

  if (!pending) {
    res.status(400).send('invalid_request: authorization context lost');
    return;
  }

  let accountId: string;
  if (mode === 'signup') {
    try {
      accountId = createAccount(username, password).id;
    } catch {
      res.type('html').send(renderLoginPage(pendingId, pending, 'signup', 'That username is already taken.'));
      return;
    }
  } else {
    const account = verifyCredentials(username, password);
    if (!account) {
      // Generic message: never reveal whether the username exists.
      res.type('html').send(renderLoginPage(pendingId, pending, 'login', 'Invalid username or password.'));
      return;
    }
    accountId = account.id;
  }

  pendingAuthorizations.delete(pendingId);

  const code = randomId(24);
  storeAuthCode(code, {
    sub: accountId,
    scopes: pending.scopes,
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    resource: pending.resource,
    expiresAt: Date.now() + 60_000
  });

  const location = new URL(pending.redirectUri);
  location.searchParams.set('code', code);
  if (pending.state) location.searchParams.set('state', pending.state);
  location.searchParams.set('iss', BASE_URL); // RFC 9207
  res.redirect(302, location.toString());
});

/* -------------------------------------------------------------------- token */

oauthRouter.post('/token', (req: Request, res: Response) => {
  const { grant_type, code, code_verifier, redirect_uri, resource, client_id } = req.body ?? {};

  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }
  const record = typeof code === 'string' ? consumeAuthCode(code) : null;
  if (!record) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'unknown, used, or expired code' });
    return;
  }
  if (typeof code_verifier !== 'string' || pkceS256(code_verifier) !== record.codeChallenge) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
    return;
  }
  if (typeof redirect_uri === 'string' && redirect_uri !== record.redirectUri) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    return;
  }
  // OAuth 2.1 binds a code to the client it was issued to. With public clients
  // there is no secret to check, but the identity must still match.
  if (typeof client_id === 'string' && client_id !== record.clientId) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'client_id mismatch' });
    return;
  }

  // RFC 8707: the audience is the resource the client asked for, and the token
  // is only ever valid at that resource.
  const audience = typeof resource === 'string' && resource ? resource : record.resource;
  const token = issueAccessToken(record.sub, record.scopes, audience);

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: record.scopes.join(' ')
  });
});

oauthRouter.post('/revoke', (req: Request, res: Response) => {
  if (typeof req.body?.token === 'string') revokeAccessToken(req.body.token);
  res.status(200).end(); // RFC 7009: always 200, even for an unknown token
});
