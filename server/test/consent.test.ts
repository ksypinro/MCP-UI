/**
 * Sign-in, approval, and when an approval may be remembered.
 *
 * Remembered consent is convenient and is exactly what a confused-deputy
 * attack rides on, so these tests pin down when it applies and when the
 * person is asked again.
 */

import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  Browser, REDIRECT_URI, authorizeUrl, csrfFrom, exchange, pendingIdFrom, pkcePair, registerClient,
  startServer, walkAuthorization, type Harness
} from './oauth-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });
afterEach(() => { delete process.env.REQUIRE_OFFLINE_ACCESS_FOR_REFRESH; });

/** A metadata-document client, served from the cache so no network is needed. */
async function cimdClient(clientId: string, digest = 'digest-1'): Promise<string> {
  await h.db.query(
    `INSERT INTO cimd_cache (client_id, redirect_uris, display_host, digest, fetched_at, expires_at)
     VALUES ($1, $2, $3, $4, now(), now() + interval '1 hour')
     ON CONFLICT (client_id) DO UPDATE SET digest = EXCLUDED.digest`,
    [clientId, JSON.stringify([REDIRECT_URI]), new URL(clientId).host, digest]
  );
  return clientId;
}

function query(clientId: string, scope?: string) {
  return {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code', state: 's',
    code_challenge: pkcePair().challenge, code_challenge_method: 'S256',
    ...(scope ? { scope } : {})
  };
}

/** A browser that has signed in once and approved `clientId`. */
async function signedInBrowser(clientId: string, scope?: string) {
  const browser = new Browser(h.base);
  const username = `p${Date.now()}${Math.floor(Math.random() * 1e6)}`;
  const outcome = await walkAuthorization(browser, query(clientId, scope), { mode: 'signup', username });
  assert.ok(outcome.callback?.searchParams.get('code'), 'the first authorization completes');
  return { browser, username };
}

/** Starts another authorization in a signed-in browser without approving anything. */
async function again(browser: Browser, clientId: string, scope?: string) {
  return walkAuthorization(browser, query(clientId, scope), null, { approve: false });
}

test('a second authorization by the same client and scopes skips the approval screen', async () => {
  const clientId = await cimdClient('https://remembered.example/cimd.json');
  const { browser } = await signedInBrowser(clientId);
  const outcome = await again(browser, clientId);
  assert.ok(outcome.callback?.searchParams.get('code'), 'straight back to the client with a code');
});

test('asking for more than was approved asks again', async () => {
  const clientId = await cimdClient('https://wider.example/cimd.json');
  const { browser } = await signedInBrowser(clientId, 'devices:read');
  const outcome = await again(browser, clientId, 'devices:read devices:control');
  assert.equal(outcome.callback, null);
  assert.match(outcome.html, /Allow access\?/);
});

test('asking for less than was approved does not ask again', async () => {
  const clientId = await cimdClient('https://narrower.example/cimd.json');
  const { browser } = await signedInBrowser(clientId);
  const outcome = await again(browser, clientId, 'devices:read');
  assert.ok(outcome.callback?.searchParams.get('code'));
});

test('a dynamically registered client is asked every time', async () => {
  // DCR establishes nothing about who the client is, so remembering its
  // consent is exactly what a confused deputy would exploit.
  const clientId = await registerClient(h.base);
  const { browser } = await signedInBrowser(clientId);
  const outcome = await again(browser, clientId);
  assert.equal(outcome.callback, null);
  assert.match(outcome.html, /registered itself and has not been verified/);
});

test('a changed metadata document asks again', async () => {
  const clientId = await cimdClient('https://changed.example/cimd.json', 'digest-1');
  const { browser } = await signedInBrowser(clientId);
  await cimdClient(clientId, 'digest-2');
  const outcome = await again(browser, clientId);
  assert.equal(outcome.callback, null);
  assert.match(outcome.html, /Allow access\?/);
});

test('approving write access needs a recent sign-in', async () => {
  const clientId = await registerClient(h.base);
  const { browser } = await signedInBrowser(clientId);
  await h.db.query(`UPDATE as_sessions SET auth_time = auth_time - interval '16 minutes'`);

  const outcome = await again(browser, clientId);
  assert.equal(outcome.callback, null);
  assert.match(outcome.html, /needs a recent sign-in/);

  // Read-only access does not.
  const readOnly = await again(browser, clientId, 'devices:read');
  assert.match(readOnly.html, /Allow access\?/);
});

test('an idle session signs the person out', async () => {
  const clientId = await cimdClient('https://idle.example/cimd.json');
  const { browser } = await signedInBrowser(clientId);
  await h.db.query(`UPDATE as_sessions SET idle_expires_at = now() - interval '1 second'`);
  const outcome = await again(browser, clientId);
  assert.equal(outcome.callback, null);
  assert.match(outcome.html, /action="\/login"/);
});

test('a pending authorization cannot be completed in another browser', async () => {
  const first = new Browser(h.base);
  const clientId = await registerClient(h.base);
  const { response } = await first.follow(await first.get(authorizeUrl(h.base, query(clientId))));
  const html = await response.text();
  const pending = pendingIdFrom(html)!;

  // A different browser, with or without a binding cookie of its own.
  const second = new Browser(h.base);
  const elsewhere = await second.get(`/login?pending=${pending}`);
  assert.equal(elsewhere.status, 400);
  assert.match(await elsewhere.text(), /browser you started from/);
});

test('a form posted without its CSRF token is refused', async () => {
  const browser = new Browser(h.base);
  const clientId = await registerClient(h.base);
  const { response } = await browser.follow(await browser.get(authorizeUrl(h.base, query(clientId))));
  const pending = pendingIdFrom(await response.text())!;

  const forged = await browser.post('/login', {
    pending, csrf: 'not-the-token', mode: 'signup', username: `x${Date.now()}`, password: 'correct horse battery staple'
  });
  assert.equal(forged.status, 403);
  assert.equal(forged.headers.get('location'), null);
});

test('signing in always starts a fresh session', async () => {
  const clientId = await cimdClient('https://fixation.example/cimd.json');
  const { browser, username } = await signedInBrowser(clientId);
  const before = browser.cookies.get('as_session');

  const outcome = await walkAuthorization(browser, query(await registerClient(h.base)), null, { approve: false });
  const pending = pendingIdFrom(outcome.html)!;
  const csrf = csrfFrom(outcome.html)!;
  await browser.post('/logout', { pending, csrf });
  assert.equal(browser.cookies.has('as_session'), false, 'signing out clears the session');

  const login = await browser.follow(await browser.get(`/login?pending=${pending}`));
  const loginHtml = await login.response.text();
  await browser.post('/login', {
    pending, csrf: csrfFrom(loginHtml)!, mode: 'login', username, password: 'correct horse battery staple'
  });
  assert.ok(browser.cookies.get('as_session'));
  assert.notEqual(browser.cookies.get('as_session'), before, 'a new session, not the old one reused');
});

test('a refresh token needs offline_access only when configured to', async () => {
  const clientId = await registerClient(h.base);

  const withoutFlag = await walkAuthorization(new Browser(h.base), query(clientId, 'devices:read'), {
    mode: 'signup', username: `o${Date.now()}`
  });
  assert.ok(withoutFlag.callback);

  process.env.REQUIRE_OFFLINE_ACCESS_FOR_REFRESH = 'true';
  for (const [scope, expectRefresh] of [['devices:read', false], ['devices:read offline_access', true]] as const) {
    const { verifier, challenge } = pkcePair();
    const outcome = await walkAuthorization(new Browser(h.base), {
      ...query(clientId, scope), code_challenge: challenge
    }, { mode: 'signup', username: `o${Date.now()}${expectRefresh}` });
    const { body } = await exchange(h.base, {
      code: outcome.callback!.searchParams.get('code')!, clientId, verifier,
      state: null, iss: null, username: '', browser: new Browser(h.base)
    });
    assert.ok(body.access_token);
    assert.equal(Boolean(body.refresh_token), expectRefresh, `scope "${scope}"`);
  }
});
