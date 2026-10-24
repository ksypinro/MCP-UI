/**
 * Connected apps, sign out everywhere, and password change. AC-46.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { establishGrant } from '../src/oauth/store.ts';
import { API_RESOURCE, FIRST_PARTY_CLIENT_ID } from '../src/oauth/config.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { verifyCredentials } from '../src/domain/accounts.ts';
import { Browser, csrfFrom, startServer, type Harness } from './oauth-helpers.ts';
import { callTool, tokenFor, tokenForExisting } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

const PASSWORD = 'correct horse battery staple';

async function accountIdOf(username: string): Promise<string> {
  const { rows } = await h.db.query<{ id: string }>('SELECT id FROM accounts WHERE username = $1', [username]);
  return rows[0]!.id;
}

/** A person with two host grants and the iPhone app's grant, signed in on /account. */
async function personWithApps() {
  const first = await tokenFor(h, { scope: 'devices:read devices:control' });
  const second = await tokenForExisting(h, first.username, 'devices:read');
  const accountId = await accountIdOf(first.username);
  const app = await establishGrant(h.db, {
    code: 'none', accountId, clientId: FIRST_PARTY_CLIENT_ID, resource: API_RESOURCE,
    scope: 'devices:read devices:control devices:create offline_access', withRefresh: true, dpopJkt: null
  });

  const browser = new Browser(h.base);
  const login = await (await browser.get('/account/login')).text();
  await browser.follow(await browser.post('/account/login', { csrf: csrfFrom(login)!, username: first.username, password: PASSWORD }));
  const page = await (await browser.get('/account/apps')).text();
  return { username: first.username, accountId, hostA: first.accessToken, hostB: second, app: app.accessToken, browser, page, csrf: csrfFrom(page)! };
}

const live = async (token: string, audience?: string) => (await verifyOAuthAccessToken(h.db, token, [], audience ? { audience } : {})).ok;

test('every connected app is listed with what it can do and when it was last used', async () => {
  const person = await personWithApps();
  const grants = [...person.page.matchAll(/\/account\/apps\/([^/]+)\/revoke/g)].map((m) => decodeURIComponent(m[1]!));
  assert.equal(grants.length, 3, 'two hosts and the iPhone app');
  assert.ok(person.page.includes('IoT Switch for iPhone'));
  assert.ok(person.page.includes('Switch your devices on and off'));
  assert.ok(person.page.includes('last used never'), 'nothing has used a token yet');

  assert.equal((await callTool(h.base, 'list_devices', {}, person.hostA)).status, 200);
  const after = await (await person.browser.get('/account/apps')).text();
  assert.equal([...after.matchAll(/last used never/g)].length, 2, 'the app that called is no longer "never"');
  const { rows } = await h.db.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM oauth_grants WHERE account_id = $1 AND last_used_at IS NOT NULL', [person.accountId]
  );
  assert.ok(rows[0]!.n >= 1, 'verifying a token records that its grant was used');
});

test('disconnecting an app makes its token fail on the next call, and leaves the others', async () => {
  const person = await personWithApps();
  assert.equal((await callTool(h.base, 'list_devices', {}, person.hostA)).status, 200);

  const verified = await verifyOAuthAccessToken(h.db, person.hostA);
  assert.ok(verified.ok);
  const revoked = await person.browser.follow(await person.browser.post(
    `/account/apps/${encodeURIComponent(verified.grantId)}/revoke`, { csrf: person.csrf }
  ));
  assert.ok((await revoked.response.text()).includes('can no longer reach your devices'));

  assert.equal((await callTool(h.base, 'list_devices', {}, person.hostA)).status, 401, 'refused on its very next call');
  assert.ok(await live(person.hostB), 'the other app is untouched');
  assert.ok(await live(person.app, API_RESOURCE), 'the iPhone app is untouched');
});

test("another person's app cannot be disconnected from this page, nor with a forged form", async () => {
  const mine = await personWithApps();
  const theirs = await personWithApps();
  const theirGrant = await verifyOAuthAccessToken(h.db, theirs.hostA);
  assert.ok(theirGrant.ok);

  await mine.browser.post(`/account/apps/${encodeURIComponent(theirGrant.grantId)}/revoke`, { csrf: mine.csrf });
  assert.ok(await live(theirs.hostA), 'someone else\'s grant is not found, so not revoked');

  const myGrant = await verifyOAuthAccessToken(h.db, mine.hostA);
  assert.ok(myGrant.ok);
  await mine.browser.post(`/account/apps/${encodeURIComponent(myGrant.grantId)}/revoke`, { csrf: theirs.csrf });
  assert.ok(await live(mine.hostA), 'a CSRF value from another session is refused');
});

test('sign out everywhere ends the hosts, the iPhone app and this browser', async () => {
  const person = await personWithApps();
  const done = await person.browser.follow(await person.browser.post('/account/signout-everywhere', { csrf: person.csrf }));
  assert.ok((await done.response.text()).includes('Signed out everywhere'));

  assert.equal(await live(person.hostA), false);
  assert.equal(await live(person.hostB), false);
  assert.equal(await live(person.app, API_RESOURCE), false, 'the iPhone app too');
  const again = await person.browser.get('/account/apps');
  assert.equal(again.headers.get('location'), '/account/login', 'this browser is signed out as well');
});

test('changing the password signs out everything else, and only the new password works', async () => {
  const person = await personWithApps();
  const security = await (await person.browser.get('/account')).text();
  const csrf = csrfFrom(security)!;

  const wrong = await person.browser.post('/account/password', { csrf, currentPassword: 'not it', newPassword: 'an entirely new passphrase' });
  assert.equal(wrong.headers.get('location'), '/account?error=password');
  assert.ok(await live(person.hostA), 'a failed change changes nothing');

  const changed = await person.browser.post('/account/password', { csrf, currentPassword: PASSWORD, newPassword: 'an entirely new passphrase' });
  assert.equal(changed.headers.get('location'), '/account?done=password-changed');
  assert.equal(await live(person.hostA), false);
  assert.equal(await live(person.app, API_RESOURCE), false);
  assert.equal(await verifyCredentials(h.db, person.username, PASSWORD), null);
  assert.ok(await verifyCredentials(h.db, person.username, 'an entirely new passphrase'));
  assert.equal((await person.browser.get('/account')).status, 200, 'the person who changed it stays signed in here');
});
