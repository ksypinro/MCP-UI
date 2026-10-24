/**
 * The iOS app as an OAuth client: pushed authorization, sign-in in the
 * system browser, no consent screen, DPoP-bound tokens for the REST API.
 */

import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { API_RESOURCE, FIRST_PARTY_CLIENT_ID, ISSUER } from '../src/oauth/config.ts';
import { API_BASE_URL } from '../src/config.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { Browser, csrfFrom, json, pendingIdFrom, pkcePair, startServer, type Harness } from './oauth-helpers.ts';
import { callTool } from './mcp-helpers.ts';
import { DpopKey } from './dpop-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });
afterEach(() => {
  delete process.env.APPLE_TEAM_ID;
});

const CALLBACK = 'com.example.iotswitch:/oauth/callback';
const PASSWORD = 'correct horse battery staple';

function push(fields: Record<string, string | undefined>) {
  return fetch(`${h.base}/par`, json({
    client_id: FIRST_PARTY_CLIENT_ID, redirect_uri: CALLBACK, response_type: 'code',
    code_challenge_method: 'S256', scope: 'devices:read devices:control devices:create offline_access',
    state: 'app-state', ...fields
  }));
}

/** The whole app sign-in, as the iOS app performs it. Returns the token response. */
async function appSignIn(options: { key?: DpopKey; username?: string } = {}) {
  const key = options.key ?? await DpopKey.create();
  const { verifier, challenge } = pkcePair();
  const pushed = await push({ code_challenge: challenge, dpop_jkt: key.jkt, prompt: 'create' });
  assert.equal(pushed.status, 201);
  assert.ok(pushed.headers.get('dpop-nonce'), 'a nonce comes back with the pushed request');
  const { request_uri } = await pushed.json() as { request_uri: string };

  const browser = new Browser(h.base);
  const start = await browser.follow(await browser.get(
    `/authorize?client_id=${FIRST_PARTY_CLIENT_ID}&request_uri=${encodeURIComponent(request_uri)}`
  ));
  const html = await start.response.text();
  assert.match(html, /Sign Up and Continue/, 'prompt=create opens the sign-up form');

  const username = options.username ?? `app${randomBytes(4).toString('hex')}`;
  const after = await browser.follow(await browser.post('/login', {
    pending: pendingIdFrom(html)!, csrf: csrfFrom(html)!, mode: 'signup', username, password: PASSWORD
  }));
  assert.ok(after.offsite, 'no consent screen for our own app: straight back to it');
  assert.equal(after.offsite.protocol, 'com.example.iotswitch:');
  assert.equal(after.offsite.searchParams.get('state'), 'app-state');
  assert.equal(after.offsite.searchParams.get('iss'), ISSUER);
  const code = after.offsite.searchParams.get('code')!;

  const tokens = await fetch(`${h.base}/token`, {
    ...json({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: CALLBACK, client_id: FIRST_PARTY_CLIENT_ID }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await key.proof({ htm: 'POST', htu: `${ISSUER}/token` }) }
  });
  const body = await tokens.json() as Record<string, string>;
  return { key, body, status: tokens.status, username, verifier, code };
}

async function api(path: string, accessToken: string, key: DpopKey | null, init: { method?: string; scheme?: string; proof?: string } = {}) {
  const method = init.method ?? 'GET';
  const headers: Record<string, string> = { authorization: `${init.scheme ?? 'DPoP'} ${accessToken}` };
  if (init.proof) headers.dpop = init.proof;
  else if (key) headers.dpop = await key.proof({ htm: method, htu: `${API_BASE_URL}${path}`, accessToken });
  return fetch(`${h.base}${path}`, { method, headers });
}

test('the app signs in through PAR and gets DPoP-bound tokens for the API', async () => {
  const { key, body, status } = await appSignIn();
  assert.equal(status, 200, JSON.stringify(body));
  assert.equal(body.token_type, 'DPoP');
  assert.equal(body.expires_in, 600, 'the app\'s access tokens are short-lived');
  assert.ok(body.refresh_token);

  const verified = await verifyOAuthAccessToken(h.db, body.access_token, [], { audience: API_RESOURCE });
  assert.ok(verified.ok && verified.cnfJkt === key.jkt, 'bound to the app key, for the API');

  const devices = await api('/v1/devices', body.access_token!, key);
  assert.equal(devices.status, 200);
  const me = await api('/v1/me', body.access_token!, key);
  assert.equal(me.status, 200);
});

test('a bound token is useless without its key', async () => {
  const { key, body } = await appSignIn();
  const token = body.access_token!;

  assert.equal((await api('/v1/devices', token, null, { scheme: 'Bearer' })).status, 401, 'as a plain bearer token');
  assert.equal((await api('/v1/devices', token, await DpopKey.create())).status, 401, 'with another key');

  const proof = await key.proof({ htm: 'GET', htu: `${API_BASE_URL}/v1/devices`, accessToken: token });
  assert.equal((await api('/v1/devices', token, null, { proof })).status, 200);
  assert.equal((await api('/v1/devices', token, null, { proof })).status, 401, 'a proof cannot be replayed');

  const stale = await api('/v1/devices', token, null, {
    proof: await key.proof({ htm: 'GET', htu: `${API_BASE_URL}/v1/devices`, accessToken: token, nonce: null })
  });
  assert.equal(stale.status, 401);
  assert.match(stale.headers.get('www-authenticate') ?? '', /DPoP error="use_dpop_nonce"/);
  assert.ok(stale.headers.get('dpop-nonce'), 'and says which nonce to use');

  // An app token is for the REST API, not the MCP endpoint.
  assert.equal((await callTool(h.base, 'list_devices', {}, token)).status, 401);
});

test('refreshing needs the same key', async () => {
  const { key, body } = await appSignIn();
  const refresh = (headers: Record<string, string>) => fetch(`${h.base}/token`, {
    ...json({ grant_type: 'refresh_token', refresh_token: body.refresh_token, client_id: FIRST_PARTY_CLIENT_ID }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }
  });

  const withoutProof = await refresh({});
  assert.equal(withoutProof.status, 400);
  assert.equal(((await withoutProof.json()) as Record<string, string>).error, 'invalid_dpop_proof');

  const otherKey = await refresh({ dpop: await (await DpopKey.create()).proof({ htm: 'POST', htu: `${ISSUER}/token` }) });
  assert.equal(otherKey.status, 400);

  const ok = await refresh({ dpop: await key.proof({ htm: 'POST', htu: `${ISSUER}/token` }) });
  assert.equal(ok.status, 200);
  assert.equal(((await ok.json()) as Record<string, string>).token_type, 'DPoP');
});

test('a code bound to one key cannot be redeemed with another, and nothing is spent by trying', async () => {
  const key = await DpopKey.create();
  const { verifier, challenge } = pkcePair();
  const pushed = await push({ code_challenge: challenge, dpop_jkt: key.jkt });
  const { request_uri } = await pushed.json() as { request_uri: string };
  const browser = new Browser(h.base);
  const start = await browser.follow(await browser.get(`/authorize?client_id=${FIRST_PARTY_CLIENT_ID}&request_uri=${encodeURIComponent(request_uri)}`));
  const html = await start.response.text();
  const done = await browser.follow(await browser.post('/login', {
    pending: pendingIdFrom(html)!, csrf: csrfFrom(html)!, mode: 'signup', username: `k${Date.now()}`, password: PASSWORD
  }));
  const code = done.offsite!.searchParams.get('code')!;
  const redeem = (dpop?: string) => fetch(`${h.base}/token`, {
    ...json({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: CALLBACK, client_id: FIRST_PARTY_CLIENT_ID }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(dpop ? { dpop } : {}) }
  });

  assert.equal((await redeem()).status, 400, 'the app must always present a proof');
  const nonce = await redeem(await key.proof({ htm: 'POST', htu: `${ISSUER}/token`, nonce: null }));
  assert.equal(((await nonce.json()) as Record<string, string>).error, 'use_dpop_nonce');
  // Neither attempt touched the code: a proof is checked before it.
  const good = await redeem(await key.proof({ htm: 'POST', htu: `${ISSUER}/token` }));
  assert.equal(good.status, 200);
});

test('the app must push its request, bind a key, and ask only for the API', async () => {
  const { challenge } = pkcePair();
  const missingKey = await push({ code_challenge: challenge });
  assert.equal(missingKey.status, 400);

  const wrongResource = await push({ code_challenge: challenge, dpop_jkt: 'x'.repeat(43), resource: `${h.base}/mcp` });
  assert.equal(((await wrongResource.json()) as Record<string, string>).error, 'invalid_target');

  // Straight to /authorize, without pushing: refused, back to the app.
  const direct = await fetch(`${h.base}/authorize?${new URLSearchParams({
    client_id: FIRST_PARTY_CLIENT_ID, redirect_uri: CALLBACK, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256', dpop_jkt: 'x'.repeat(43)
  })}`, { redirect: 'manual' });
  assert.equal(new URL(direct.headers.get('location')!).searchParams.get('error'), 'invalid_request');
});

test('a pushed request is used once, and the browser cannot change it', async () => {
  const key = await DpopKey.create();
  const { challenge } = pkcePair();
  const { request_uri } = await (await push({ code_challenge: challenge, dpop_jkt: key.jkt })).json() as { request_uri: string };
  const url = `/authorize?client_id=${FIRST_PARTY_CLIENT_ID}&request_uri=${encodeURIComponent(request_uri)}&redirect_uri=${encodeURIComponent('https://attacker.example/cb')}`;

  const browser = new Browser(h.base);
  const first = await browser.follow(await browser.get(url));
  const html = await first.response.text();
  const done = await browser.follow(await browser.post('/login', {
    pending: pendingIdFrom(html)!, csrf: csrfFrom(html)!, mode: 'signup', username: `once${Date.now()}`, password: PASSWORD
  }));
  assert.equal(done.offsite?.protocol, 'com.example.iotswitch:', 'the pushed redirect_uri, not the query one');

  const second = await new Browser(h.base).get(url);
  assert.equal(second.status, 400, 'a request_uri works once');
});

test('the universal-link association is published only with an Apple team', async () => {
  assert.equal((await fetch(`${h.base}/.well-known/apple-app-site-association`)).status, 404);
  process.env.APPLE_TEAM_ID = 'ABCDE12345';
  const published = await fetch(`${h.base}/.well-known/apple-app-site-association`);
  assert.equal(published.status, 200);
  const body = await published.json() as { applinks: { details: Array<{ appIDs: string[] }> } };
  assert.deepEqual(body.applinks.details[0]!.appIDs, ['ABCDE12345.com.example.IoTSwitch']);

  const landing = await fetch(`${h.base}/oauth/callback?code=iotsw_ac_secret&state=s`);
  const html = await landing.text();
  assert.doesNotMatch(html, /iotsw_ac_secret/, 'the fallback page never echoes the code');
});

test('a host that offers DPoP gets bound tokens at the MCP endpoint too', async () => {
  const { authorizeAs } = await import('./oauth-helpers.ts');
  const key = await DpopKey.create();
  const authorization = await authorizeAs(h.base);
  const tokens = await fetch(`${h.base}/token`, {
    ...json({
      grant_type: 'authorization_code', code: authorization.code, code_verifier: authorization.verifier,
      redirect_uri: 'http://127.0.0.1:41234/callback', client_id: authorization.clientId
    }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', dpop: await key.proof({ htm: 'POST', htu: `${ISSUER}/token` }) }
  }).then((r) => r.json()) as Record<string, string>;
  assert.equal(tokens.token_type, 'DPoP');

  const asBearer = await callTool(h.base, 'list_devices', {}, tokens.access_token);
  assert.equal(asBearer.status, 401);

  const { MCP_BASE_URL } = await import('../src/config.ts');
  const proven = await fetch(`${h.base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      authorization: `DPoP ${tokens.access_token}`,
      dpop: await key.proof({ htm: 'POST', htu: `${MCP_BASE_URL}/mcp`, accessToken: tokens.access_token })
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_devices', arguments: {} } })
  });
  assert.equal(proven.status, 200);
});
