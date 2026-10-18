/**
 * The hosted authorization pages: sign-in, then approval.
 *
 * Spec section 7.4: this is the only place a credential is ever typed. It is
 * server-rendered and entirely outside MCP — no tool sees it, no model sees
 * it, and nothing from it is returned to the client except an authorization
 * code on the registered redirect URI.
 *
 * Signing in and approving are separate steps. Signing in proves who the
 * person is, once per browser session; approving names what this particular
 * application is about to receive, every time it is not already remembered.
 */

import type { Scope } from './config.ts';

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] as string
  );
}

const SCOPE_DESCRIPTIONS: Record<Scope, string> = {
  'devices:read': 'See your devices and whether each one is on or off',
  'devices:control': 'Switch your devices on and off',
  'devices:create': 'Add new devices to your account'
};

export interface LoginPageOptions {
  /** CSP nonce for the inline stylesheet; see security/headers.ts. */
  nonce: string;
  pendingId: string;
  csrf: string;
  clientHost: string;
  mode: 'login' | 'signup';
  /** Signing in again because approving write access needs a recent sign-in. */
  reauth?: boolean;
  error?: string;
  username?: string;
}

export interface ConsentPageOptions {
  nonce: string;
  pendingId: string;
  csrf: string;
  username: string;
  clientHost: string;
  clientKind: 'cimd' | 'dcr' | 'preregistered';
  clientTrust: 'verified' | 'unverified';
  redirectUri: string;
  scopes: Scope[];
}

const STYLES = `
  :root {
    color-scheme: light dark;
    --fg: #141413; --muted: #6b6a64; --bg: #faf9f5; --surface: #ffffff;
    --line: #dcdad0; --accent: #141413; --accent-fg: #ffffff;
    --danger-bg: #f9ecec; --danger-fg: #7f2c28;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --fg: #faf9f5; --muted: #a3a199; --bg: #1a1a19; --surface: #242422;
      --line: #3b3a37; --accent: #faf9f5; --accent-fg: #141413;
      --danger-bg: #4a2422; --danger-fg: #efa9a5;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100dvh; display: grid; place-items: center; padding: 24px;
    font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: var(--fg); background: var(--bg);
  }
  .card {
    width: 100%; max-width: 400px; background: var(--surface);
    border: 1px solid var(--line); border-radius: 14px; padding: 28px 24px;
  }
  h1 { font-size: 20px; margin: 0 0 6px; }
  .lede { margin: 0 0 22px; color: var(--muted); font-size: 14px; }
  .tabs { display: flex; gap: 8px; margin-bottom: 22px; }
  .tabs a {
    flex: 1; text-align: center; padding: 10px; border: 1px solid var(--line);
    border-radius: 9px; text-decoration: none; color: var(--fg); font-size: 14px;
  }
  .tabs a[aria-current="page"] {
    background: var(--accent); color: var(--accent-fg); border-color: var(--accent); font-weight: 600;
  }
  label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
  input {
    width: 100%; padding: 12px; font-size: 16px; margin-bottom: 18px;
    border: 1px solid var(--line); border-radius: 9px;
    background: var(--bg); color: var(--fg);
  }
  button {
    width: 100%; padding: 13px; font-size: 15px; font-weight: 600; cursor: pointer;
    border: 0; border-radius: 9px; background: var(--accent); color: var(--accent-fg);
  }
  /* A class, not a style attribute: the page's CSP allows only the nonced
     stylesheet, and inline style attributes are not covered by a nonce. */
  button.cancel {
    display: block; text-align: center; margin-top: 14px; font-size: 14px;
    background: none; color: var(--muted); font-weight: 400; padding: 8px;
  }
  .error {
    background: var(--danger-bg); color: var(--danger-fg); padding: 11px 13px;
    border-radius: 9px; font-size: 14px; margin-bottom: 18px;
  }
  .grant { margin: 0 0 22px; padding: 14px; border: 1px solid var(--line); border-radius: 10px; }
  .grant p { margin: 0 0 8px; font-size: 14px; }
  .grant ul { margin: 0; padding-left: 20px; font-size: 14px; color: var(--muted); }
  .grant li { margin: 3px 0; }
  .host { font-weight: 600; word-break: break-all; }
  .badge {
    display: inline-block; font-size: 12px; font-weight: 600; padding: 2px 8px;
    border-radius: 999px; margin-left: 6px; vertical-align: 1px;
  }
  .badge.verified { background: #e3f3e8; color: #1d5b33; }
  .badge.unverified { background: var(--danger-bg); color: var(--danger-fg); }
  .note { font-size: 13px; color: var(--muted); margin: 10px 0 0; }
  .destination { font-size: 13px; margin: 12px 0 0; word-break: break-all; }
  .actions { display: grid; gap: 10px; }
  .secondary { background: none; color: var(--fg); border: 1px solid var(--line); }
  .signout { text-align: center; margin-top: 16px; font-size: 13px; color: var(--muted); }
  .signout button {
    display: inline; width: auto; padding: 0; background: none; color: var(--muted);
    font-size: 13px; font-weight: 400; text-decoration: underline;
  }
`;

function head(nonce: string, title: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style nonce="${escapeHtml(nonce)}">${STYLES}</style>
</head>`;
}

export function renderLoginPage(options: LoginPageOptions): string {
  const { nonce, pendingId, csrf, clientHost, mode, reauth, error, username = '' } = options;
  const isSignUp = mode === 'signup';
  const id = encodeURIComponent(pendingId);
  const lede = reauth
    ? 'Approving write access needs a recent sign-in. Sign in again to continue.'
    : isSignUp
      ? 'Create an account to connect your devices.'
      : 'Log in to connect your devices.';

  return `${head(nonce, `${isSignUp ? 'Sign up' : 'Log in'} to IoT Switch`)}
<body>
  <main class="card">
    <h1>IoT Switch</h1>
    <p class="lede">${lede}</p>
    <p class="lede">Continuing to <span class="host">${escapeHtml(clientHost)}</span>. You will see exactly what it is asking for before anything is shared.</p>

    ${reauth ? '' : `<nav class="tabs">
      <a href="/login?pending=${id}&amp;mode=login"
         ${!isSignUp ? 'aria-current="page"' : ''}>Log In</a>
      <a href="/login?pending=${id}&amp;mode=signup"
         ${isSignUp ? 'aria-current="page"' : ''}>Sign Up</a>
    </nav>`}

    ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}

    <form method="post" action="/login">
      <input type="hidden" name="pending" value="${escapeHtml(pendingId)}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <input type="hidden" name="mode" value="${isSignUp ? 'signup' : 'login'}">

      <label for="username">Username</label>
      <input id="username" name="username" value="${escapeHtml(username)}"
             autocomplete="username" autocapitalize="none" autocorrect="off"
             spellcheck="false" required>

      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="${isSignUp ? 'new-password' : 'current-password'}" required>

      <button type="submit">${isSignUp ? 'Sign Up and Continue' : 'Log In and Continue'}</button>
    </form>

    <form method="post" action="/consent/deny">
      <input type="hidden" name="pending" value="${escapeHtml(pendingId)}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <button type="submit" class="cancel">Cancel</button>
    </form>
  </main>
</body>
</html>`;
}

export function renderConsentPage(options: ConsentPageOptions): string {
  const { nonce, pendingId, csrf, username, clientHost, clientKind, clientTrust, redirectUri, scopes } = options;
  const destination = new URL(redirectUri);
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(destination.hostname);

  const badge = clientTrust === 'verified'
    ? '<span class="badge verified">Verified</span>'
    : '<span class="badge unverified">Unverified</span>';

  // What can honestly be said about who this is. A metadata-document client
  // is identified by the host that serves its document; a dynamically
  // registered one by nothing at all, so the only thing worth showing is
  // exactly where the approval will be sent.
  const identity = clientKind === 'dcr'
    ? '<p class="note">This application registered itself and has not been verified. Its name could be anything; check the address below.</p>'
    : clientTrust === 'unverified'
      ? '<p class="note">This application is identified by the website that publishes it. It has not been verified by IoT Switch.</p>'
      : '';

  const where = clientKind === 'dcr'
    ? `<p class="destination">You will be sent to <span class="host">${escapeHtml(redirectUri)}</span></p>`
    : `<p class="destination">You will be sent back to <span class="host">${escapeHtml(destination.host || destination.protocol)}</span></p>`;

  const loopbackWarning = loopback
    ? '<p class="note">This sends you back to a program running on this computer. Only continue if you started it.</p>'
    : '';

  return `${head(nonce, 'Allow access to IoT Switch?')}
<body>
  <main class="card">
    <h1>Allow access?</h1>
    <p class="lede">Signed in as <span class="host">${escapeHtml(username)}</span></p>

    <div class="grant">
      <p><span class="host">${escapeHtml(clientHost)}</span>${badge} is asking to:</p>
      <ul>
        ${scopes.map((scope) => `<li>${escapeHtml(SCOPE_DESCRIPTIONS[scope] ?? scope)}</li>`).join('\n        ')}
      </ul>
      ${identity}
      ${where}
      ${loopbackWarning}
    </div>

    <div class="actions">
      <form method="post" action="/consent">
        <input type="hidden" name="pending" value="${escapeHtml(pendingId)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button type="submit">Allow</button>
      </form>
      <form method="post" action="/consent/deny">
        <input type="hidden" name="pending" value="${escapeHtml(pendingId)}">
        <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
        <button type="submit" class="secondary">Deny</button>
      </form>
    </div>

    <form method="post" action="/logout" class="signout">
      <input type="hidden" name="pending" value="${escapeHtml(pendingId)}">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      Not ${escapeHtml(username)}? <button type="submit">Sign out</button>
    </form>
  </main>
</body>
</html>`;
}

/** Shown when there is no valid redirect URI to send an error back to. */
export function renderErrorPage(title: string, detail: string, nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style nonce="${escapeHtml(nonce)}">${STYLES}</style>
</head>
<body>
  <main class="card">
    <h1>${escapeHtml(title)}</h1>
    <p class="lede">${escapeHtml(detail)}</p>
    <p class="lede">Close this window and start again from the app that sent you here.</p>
  </main>
</body>
</html>`;
}
