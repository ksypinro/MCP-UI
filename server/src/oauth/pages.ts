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
  /** CSP nonce for the inline stylesheet and the passkey script; see security/headers.ts. */
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
  .or { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 13px; margin: 18px 0; }
  .or::before, .or::after { content: ""; flex: 1; border-top: 1px solid var(--line); }
  [hidden] { display: none !important; }
  .card.wide { max-width: 560px; }
  h2 { font-size: 15px; margin: 26px 0 10px; }
  .rows { list-style: none; margin: 0 0 6px; padding: 0; border: 1px solid var(--line); border-radius: 10px; }
  .rows li { display: flex; gap: 12px; align-items: center; padding: 12px 14px; border-top: 1px solid var(--line); }
  .rows li:first-child { border-top: 0; }
  .rows .what { flex: 1; min-width: 0; font-size: 14px; }
  .rows .what small { display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }
  .rows form { margin: 0; }
  .rows button, button.small { width: auto; padding: 7px 12px; font-size: 13px; }
  .empty { color: var(--muted); font-size: 14px; margin: 0 0 6px; }
  .ok { background: #e3f3e8; color: #1d5b33; padding: 11px 13px; border-radius: 9px; font-size: 14px; margin-bottom: 18px; }
  nav.account { display: flex; gap: 16px; font-size: 14px; margin: 0 0 8px; }
  nav.account a { color: var(--fg); }
  nav.account a[aria-current="page"] { font-weight: 600; text-decoration: none; }
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

    ${isSignUp ? '' : passkeySignIn(nonce, { csrf, pending: pendingId })}

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

/* --------------------------------------------------------------- passkeys */

/**
 * The page's one script: the WebAuthn ceremony (plan 4.5). It turns the
 * server's options into what the browser API wants, and the browser's answer
 * back into JSON, and does nothing else. Every decision is the server's.
 */
const PASSKEY_SCRIPT = `(() => {
  const button = document.getElementById('passkey');
  const problem = document.getElementById('passkey-error');
  if (!button) return;
  if (!window.PublicKeyCredential) { button.closest('[data-passkey]').hidden = true; return; }
  const encode = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const decode = (text) => Uint8Array.from(
    atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4)), (c) => c.charCodeAt(0));
  const ids = (list) => (list || []).map((entry) => ({ ...entry, id: decode(entry.id) }));
  const post = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
    });
    return { ok: response.ok, body: await response.json().catch(() => ({})) };
  };
  const show = (message) => { problem.textContent = message; problem.hidden = false; };
  const context = JSON.parse(button.dataset.context);
  button.addEventListener('click', async () => {
    button.disabled = true;
    problem.hidden = true;
    try {
      const started = await post(context.options, context.payload);
      if (!started.ok) return show(started.body.error || 'That did not start. Reload and try again.');
      const options = started.body;
      let credential;
      if (context.kind === 'register') {
        credential = await navigator.credentials.create({ publicKey: {
          ...options, challenge: decode(options.challenge),
          user: { ...options.user, id: decode(options.user.id) },
          excludeCredentials: ids(options.excludeCredentials)
        } });
      } else {
        credential = await navigator.credentials.get({ publicKey: {
          ...options, challenge: decode(options.challenge), allowCredentials: ids(options.allowCredentials)
        } });
      }
      const answer = credential.response;
      const response = context.kind === 'register'
        ? { clientDataJSON: encode(answer.clientDataJSON), attestationObject: encode(answer.attestationObject),
            transports: answer.getTransports ? answer.getTransports() : [] }
        : { clientDataJSON: encode(answer.clientDataJSON), authenticatorData: encode(answer.authenticatorData),
            signature: encode(answer.signature), userHandle: answer.userHandle ? encode(answer.userHandle) : undefined };
      const name = document.getElementById('passkey-name');
      const finished = await post(context.finish, {
        ...context.payload, name: name ? name.value : undefined,
        response: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response,
          clientExtensionResults: credential.getClientExtensionResults(),
          authenticatorAttachment: credential.authenticatorAttachment || undefined }
      });
      if (!finished.ok) return show(finished.body.error || 'That passkey did not work.');
      location.assign(finished.body.redirect);
    } catch (error) {
      // Cancelling the browser's prompt is a choice, not a failure.
      if (!error || error.name !== 'NotAllowedError') show('This browser could not use a passkey here.');
    } finally {
      button.disabled = false;
    }
  });
})();`;

function passkeyScript(nonce: string): string {
  return `<script nonce="${escapeHtml(nonce)}">${PASSKEY_SCRIPT}</script>`;
}

/** "Sign in with a passkey", for the login pages. `pending` is absent on the account sign-in page. */
function passkeySignIn(nonce: string, payload: { csrf: string; pending?: string }): string {
  const context = { kind: 'authenticate', options: '/passkey/options', finish: '/passkey/login', payload };
  return `<div data-passkey>
      <p class="or">or</p>
      <p class="error" id="passkey-error" role="alert" hidden></p>
      <button type="button" class="secondary" id="passkey" data-context="${escapeHtml(JSON.stringify(context))}">Sign in with a passkey</button>
    </div>
    ${passkeyScript(nonce)}`;
}

/* ---------------------------------------------------------------- account */

const when = (date: Date | null): string =>
  date ? new Date(date).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : 'never';

export interface AccountLoginPageOptions {
  nonce: string;
  csrf: string;
  error?: string;
  notice?: string;
  username?: string;
  reauth?: boolean;
}

/** Signing in to manage the account, outside any authorization request. */
export function renderAccountLoginPage(options: AccountLoginPageOptions): string {
  const { nonce, csrf, error, notice, username = '', reauth } = options;
  return `${head(nonce, 'Your IoT Switch account')}
<body>
  <main class="card">
    <h1>Your account</h1>
    <p class="lede">${reauth ? 'This needs a recent sign-in. Sign in again to continue.' : 'Sign in to see your passkeys and the apps connected to your devices.'}</p>
    ${notice ? `<p class="ok" role="status">${escapeHtml(notice)}</p>` : ''}
    ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
    <form method="post" action="/account/login">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <label for="username">Username</label>
      <input id="username" name="username" value="${escapeHtml(username)}"
             autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Log In</button>
    </form>
    ${passkeySignIn(nonce, { csrf })}
  </main>
</body>
</html>`;
}

export interface AccountPageOptions {
  nonce: string;
  csrf: string;
  username: string;
  passkeys: Array<{ id: string; name: string; createdAt: Date; lastUsedAt: Date | null }>;
  notice?: string;
  error?: string;
}

function accountNav(current: 'security' | 'apps'): string {
  return `<nav class="account">
      <a href="/account" ${current === 'security' ? 'aria-current="page"' : ''}>Sign-in &amp; security</a>
      <a href="/account/apps" ${current === 'apps' ? 'aria-current="page"' : ''}>Connected apps</a>
    </nav>`;
}

function signOutForms(csrf: string): string {
  return `<h2>Everywhere</h2>
    <form method="post" action="/account/signout-everywhere">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <button type="submit" class="secondary">Sign out everywhere</button>
      <p class="note">Ends every connected app, the iPhone app and every browser at once. Each will need you to sign in again.</p>
    </form>
    <form method="post" action="/account/logout" class="signout">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <button type="submit">Sign out of this page</button>
    </form>`;
}

export function renderAccountPage(options: AccountPageOptions): string {
  const { nonce, csrf, username, passkeys, notice, error } = options;
  const register = { kind: 'register', options: '/account/passkeys/options', finish: '/account/passkeys', payload: { csrf } };
  return `${head(nonce, 'Sign-in & security')}
<body>
  <main class="card wide">
    <h1>${escapeHtml(username)}</h1>
    ${accountNav('security')}
    ${notice ? `<p class="ok" role="status">${escapeHtml(notice)}</p>` : ''}
    ${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}

    <h2>Passkeys</h2>
    <p class="note">A passkey signs you in with your fingerprint, face or device PIN. It only works on this site, so a fake sign-in page cannot use it.</p>
    ${passkeys.length === 0 ? '<p class="empty">No passkeys yet.</p>' : `<ul class="rows">
      ${passkeys.map((key) => `<li>
        <span class="what">${escapeHtml(key.name)}<small>Added ${when(key.createdAt)} · last used ${when(key.lastUsedAt)}</small></span>
        <form method="post" action="/account/passkeys/${encodeURIComponent(key.id)}/delete">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <button type="submit" class="secondary">Remove</button>
        </form>
      </li>`).join('\n      ')}
    </ul>`}
    <div data-passkey>
      <label for="passkey-name">Name for a new passkey</label>
      <input id="passkey-name" maxlength="60" placeholder="e.g. My iPhone">
      <p class="error" id="passkey-error" role="alert" hidden></p>
      <button type="button" id="passkey" data-context="${escapeHtml(JSON.stringify(register))}">Add a passkey</button>
    </div>
    ${passkeyScript(nonce)}

    <h2>Password</h2>
    <form method="post" action="/account/password">
      <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
      <input type="text" name="username" value="${escapeHtml(username)}" autocomplete="username" hidden>
      <label for="current">Current password</label>
      <input id="current" name="currentPassword" type="password" autocomplete="current-password" required>
      <label for="new">New password</label>
      <input id="new" name="newPassword" type="password" autocomplete="new-password" required>
      <button type="submit" class="secondary">Change password</button>
      <p class="note">Changing your password signs you out everywhere else.</p>
    </form>

    ${signOutForms(csrf)}
  </main>
</body>
</html>`;
}

export interface AppsPageOptions {
  nonce: string;
  csrf: string;
  username: string;
  apps: Array<{
    grantId: string; name: string; trust: 'verified' | 'unverified'; destination: string | null;
    scopes: Scope[]; createdAt: Date; lastUsedAt: Date | null;
  }>;
  notice?: string;
}

export function renderAppsPage(options: AppsPageOptions): string {
  const { nonce, csrf, username, apps, notice } = options;
  return `${head(nonce, 'Connected apps')}
<body>
  <main class="card wide">
    <h1>${escapeHtml(username)}</h1>
    ${accountNav('apps')}
    ${notice ? `<p class="ok" role="status">${escapeHtml(notice)}</p>` : ''}
    <h2>Apps that can reach your devices</h2>
    ${apps.length === 0 ? '<p class="empty">Nothing is connected.</p>' : `<ul class="rows">
      ${apps.map((app) => `<li>
        <span class="what"><span class="host">${escapeHtml(app.name)}</span><span class="badge ${app.trust}">${app.trust === 'verified' ? 'Verified' : 'Unverified'}</span>
          <small>${app.scopes.map((scope) => escapeHtml(SCOPE_DESCRIPTIONS[scope] ?? scope)).join(' · ')}</small>
          ${app.destination ? `<small>Sends you to ${escapeHtml(app.destination)}</small>` : ''}
          <small>Connected ${when(app.createdAt)} · last used ${when(app.lastUsedAt)}</small></span>
        <form method="post" action="/account/apps/${encodeURIComponent(app.grantId)}/revoke">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}">
          <button type="submit" class="secondary">Disconnect</button>
        </form>
      </li>`).join('\n      ')}
    </ul>`}
    ${signOutForms(csrf)}
  </main>
</body>
</html>`;
}
