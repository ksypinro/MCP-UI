/**
 * Passkeys on the authorization server. Plan 4.5, AC-45.
 *
 * The ceremonies run end to end over HTTP with a software authenticator
 * (webauthn-helpers.ts) that signs with a real P-256 key, so SimpleWebAuthn
 * verifies genuine signatures, not stubs.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createAccount } from '../src/domain/accounts.ts';
import { relyingParty } from '../src/oauth/passkeys.ts';
import { RESOURCE_URI } from '../src/oauth/config.ts';
import { Browser, csrfFrom, pendingIdFrom, registerClient, startServer, authorizeUrl, pkcePair, REDIRECT_URI, type Harness } from './oauth-helpers.ts';
import { SoftAuthenticator } from './webauthn-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

let seq = 0;

/** Where a genuine ceremony happens: this server's RP ID and origin. */
const here = () => ({ rpId: relyingParty().id, origin: relyingParty().origin });
const PASSWORD = 'correct horse battery staple';

async function json(browser: Browser, path: string, body: unknown) {
  const response = await browser.request(path, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
  });
  return { status: response.status, body: await response.json() as Record<string, any> };
}

/** A new account, signed in on the account page with its password. */
async function signedInAccount(): Promise<{ browser: Browser; username: string; csrf: string }> {
  const username = `passkey${++seq}`;
  await createAccount(h.db, username, PASSWORD);
  const browser = new Browser(h.base);
  const page = await (await browser.get('/account/login')).text();
  const signedIn = await browser.follow(await browser.post('/account/login', { csrf: csrfFrom(page)!, username, password: PASSWORD }));
  const html = await signedIn.response.text();
  assert.ok(html.includes('Add a passkey'), 'reached the account page');
  return { browser, username, csrf: csrfFrom(html)! };
}

async function register(account: { browser: Browser; csrf: string }, key: SoftAuthenticator, at = here()) {
  const options = await json(account.browser, '/account/passkeys/options', { csrf: account.csrf });
  assert.equal(options.status, 200, JSON.stringify(options.body));
  return json(account.browser, '/account/passkeys', {
    csrf: account.csrf, name: 'Test key', response: key.create(options.body as { challenge: string }, at)
  });
}

/** Signs in with a passkey from the account sign-in page, in a fresh browser. */
async function passkeySignIn(key: SoftAuthenticator, at = here()) {
  const browser = new Browser(h.base);
  const csrf = csrfFrom(await (await browser.get('/account/login')).text())!;
  const options = await json(browser, '/passkey/options', { csrf });
  assert.equal(options.status, 200);
  const response = key.get(options.body as { challenge: string }, at);
  const result = await json(browser, '/passkey/login', { csrf, response });
  return { browser, csrf, options: options.body, response, result };
}

test('a passkey can be added from the account page, then used to sign in', async () => {
  const account = await signedInAccount();
  const key = new SoftAuthenticator();
  const added = await register(account, key);
  assert.equal(added.status, 200, JSON.stringify(added.body));
  assert.ok((await (await account.browser.get('/account')).text()).includes('Test key'));

  const { browser, result } = await passkeySignIn(key);
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.redirect, '/account');
  const page = await (await browser.get('/account')).text();
  assert.ok(page.includes(account.username), 'signed in as the passkey\'s account, without a password');

  const { rows } = await h.db.query<{ acr: string }>(
    "SELECT acr FROM as_sessions WHERE account_id = (SELECT id FROM accounts WHERE username = $1) ORDER BY auth_time DESC LIMIT 1",
    [account.username]
  );
  assert.equal(rows[0]?.acr, 'passkey');
});

test('a passkey completes an authorization in flight', async () => {
  const account = await signedInAccount();
  const key = new SoftAuthenticator();
  await register(account, key);

  const clientId = await registerClient(h.base);
  const browser = new Browser(h.base);
  const { challenge } = pkcePair();
  const login = await browser.follow(await browser.get(authorizeUrl(h.base, {
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, code_challenge: challenge,
    code_challenge_method: 'S256', state: 's1', resource: RESOURCE_URI, scope: 'devices:read'
  })));
  const html = await login.response.text();
  assert.ok(html.includes('Sign in with a passkey'));
  const pending = pendingIdFrom(html)!;
  const csrf = csrfFrom(html)!;

  const options = await json(browser, '/passkey/options', { pending, csrf });
  const result = await json(browser, '/passkey/login', { pending, csrf, response: key.get(options.body as never, here()) });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.match(result.body.redirect, /^\/consent\?pending=/);
  const consent = await (await browser.get(result.body.redirect)).text();
  assert.ok(consent.includes('Allow access?'), 'on to the consent screen, signed in by passkey');
});

test('a challenge answers once', async () => {
  const account = await signedInAccount();
  const key = new SoftAuthenticator();
  await register(account, key);
  const first = await passkeySignIn(key);
  assert.equal(first.result.status, 200);

  const replay = await json(first.browser, '/passkey/login', { csrf: first.csrf, response: first.response });
  assert.equal(replay.status, 400, 'the same signed answer is refused the second time');
});

test('a passkey made for another site, or answered at another origin, is refused', async () => {
  const account = await signedInAccount();
  const phished = await register(account, new SoftAuthenticator(), { rpId: 'iot-switch.evil.example', origin: 'https://iot-switch.evil.example' });
  assert.equal(phished.status, 400, 'registration for another RP id');

  const key = new SoftAuthenticator();
  await register(account, key);
  const elsewhere = await passkeySignIn(key, { rpId: here().rpId, origin: 'https://iot-switch.evil.example' });
  assert.equal(elsewhere.result.status, 400, 'an assertion collected on another origin');
  const otherRp = await passkeySignIn(key, { rpId: 'evil.example', origin: here().origin });
  assert.equal(otherRp.result.status, 400, 'an assertion for another RP id');
});

test('an authenticator whose counter stops advancing is refused', async () => {
  const account = await signedInAccount();
  const key = new SoftAuthenticator();
  await register(account, key);
  assert.equal((await passkeySignIn(key)).result.status, 200);
  key.advance = false;
  assert.equal((await passkeySignIn(key)).result.status, 400, 'a repeated counter looks like a clone');
});

test('adding a passkey needs a recent sign-in, and the right page', async () => {
  const account = await signedInAccount();
  const forged = await json(account.browser, '/account/passkeys/options', { csrf: 'forged' });
  assert.equal(forged.status, 403);

  await h.db.query(
    "UPDATE as_sessions SET auth_time = now() - interval '16 minutes' WHERE account_id = (SELECT id FROM accounts WHERE username = $1)",
    [account.username]
  );
  const stale = await json(account.browser, '/account/passkeys/options', { csrf: account.csrf });
  assert.equal(stale.status, 403);
  assert.equal(stale.body.redirect, '/account/login?reauth=1');
});

test('only the pages with the ceremony may run script', async () => {
  const browser = new Browser(h.base);
  const login = await browser.get('/account/login');
  const csp = login.headers.get('content-security-policy')!;
  assert.match(csp, /script-src 'nonce-[^']+'/);
  assert.match(csp, /connect-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline/);
  const nonce = csp.match(/script-src 'nonce-([^']+)'/)![1]!;
  const html = await login.text();
  assert.equal([...html.matchAll(/<script/g)].length, 1, 'one script');
  assert.ok(html.includes(`<script nonce="${nonce}">`));

  const account = await signedInAccount();
  const apps = await account.browser.get('/account/apps');
  assert.doesNotMatch(apps.headers.get('content-security-policy')!, /script-src/, 'no script where none is needed');
});
