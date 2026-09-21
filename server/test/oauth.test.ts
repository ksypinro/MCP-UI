/**
 * The authorization server. Spec section 7.3, against MCP authorization
 * revision 2026-07-28.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { ISSUER, RESOURCE_URI, SCOPES } from '../src/oauth/config.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { redirectUriAllowed } from '../src/oauth/clients.ts';
import {
  REDIRECT_URI, authorizeAs, authorizeUrl, exchange, form, json,
  pendingIdFrom, pkcePair, registerClient, sharedClient, startServer, type Harness
} from './oauth-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

/* ------------------------------------------------------------- discovery */

test('protected resource metadata is served at both well-known paths', async () => {
  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const body = await fetch(h.base + path).then((r) => r.json()) as Record<string, unknown>;
    // Clients try the path-suffixed form first when the resource has a path;
    // answering only one makes discovery work for some hosts and not others.
    assert.equal(body.resource, RESOURCE_URI, `wrong resource at ${path}`);
    assert.deepEqual(body.authorization_servers, [ISSUER]);
    assert.deepEqual(body.scopes_supported, [...SCOPES]);
  }
});

test('authorization server metadata advertises what hosts gate on', async () => {
  const meta = await fetch(`${h.base}/.well-known/oauth-authorization-server`)
    .then((r) => r.json()) as Record<string, unknown>;

  assert.equal(meta.issuer, ISSUER);
  assert.deepEqual(meta.code_challenge_methods_supported, ['S256']);
  // Claude selects CIMD only when both of these are present, because its CIMD
  // client is public and the token endpoint must accept PKCE-only requests.
  assert.equal(meta.client_id_metadata_document_supported, true);
  assert.ok((meta.token_endpoint_auth_methods_supported as string[]).includes('none'));
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
  assert.ok((meta.grant_types_supported as string[]).includes('refresh_token'));
});

/* ----------------------------------------------------------- happy path */

test('a full authorization issues a token bound to this resource', async () => {
  const authorization = await authorizeAs(h.base, { state: 'xyz' });

  assert.equal(authorization.state, 'xyz', 'state is returned unchanged');
  assert.equal(authorization.iss, ISSUER, 'RFC 9207 iss is present');

  const { status, body } = await exchange(h.base, authorization);
  assert.equal(status, 200);
  assert.equal(body.token_type, 'Bearer');
  assert.ok(body.refresh_token);
  assert.equal(body.scope, SCOPES.join(' '), 'all three scopes by default');

  const verified = await verifyOAuthAccessToken(h.db, body.access_token, ['devices:control']);
  assert.ok(verified.ok, 'the token verifies for the resource server');
});

test('token responses are not cacheable', async () => {
  const authorization = await authorizeAs(h.base);
  const response = await fetch(`${h.base}/token`, json({
    grant_type: 'authorization_code', code: authorization.code,
    code_verifier: authorization.verifier, redirect_uri: REDIRECT_URI,
    client_id: authorization.clientId
  }));
  assert.match(response.headers.get('cache-control') ?? '', /no-store/);
});

/* ----------------------------------------------------- code protections */

test('a wrong PKCE verifier is refused', async () => {
  const authorization = await authorizeAs(h.base);
  const { verifier: wrong } = pkcePair();
  const { status, body } = await exchange(h.base, authorization, { code_verifier: wrong });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_grant');
});

test('a code is single use, and replaying it revokes what it produced', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  assert.equal(first.status, 200);

  const replay = await exchange(h.base, authorization);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');

  // OAuth 2.1: a replayed code means the code leaked, so whatever it produced
  // is suspect. Refusing the second exchange while leaving the first token
  // alive would hand the attacker exactly what they wanted.
  const verified = await verifyOAuthAccessToken(h.db, first.body.access_token);
  assert.equal(verified.ok, false, 'the token from the first exchange is revoked too');
});

test('a code cannot be redeemed by a different client', async () => {
  const authorization = await authorizeAs(h.base);
  const otherClient = await registerClient(h.base); // deliberately a different one
  const { status, body } = await exchange(h.base, authorization, { client_id: otherClient });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_grant');
});

test('a code cannot be redeemed against a different redirect_uri', async () => {
  const authorization = await authorizeAs(h.base);
  const { status, body } = await exchange(h.base, authorization, {
    redirect_uri: 'http://127.0.0.1:41234/somewhere-else'
  });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_grant');
});

test('the token endpoint requires client_id', async () => {
  const authorization = await authorizeAs(h.base);
  // OAuth 2.1 section 3.2.2: a client that does not authenticate MUST send
  // client_id. Without it the code is bound to nothing an attacker who holds
  // the code does not already have.
  const { status, body } = await exchange(h.base, authorization, { client_id: undefined });
  assert.equal(status, 400);
  assert.equal(body.error, 'invalid_request');
});

test('a refresh token cannot be redeemed by a different client', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  const other = await registerClient(h.base);

  const response = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: first.body.refresh_token, client_id: other
  }));
  assert.equal(response.status, 400);
  assert.equal((await response.json() as Record<string, string>).error, 'invalid_grant');
});

test('an unknown code is refused', async () => {
  const response = await fetch(`${h.base}/token`, json({
    grant_type: 'authorization_code', code: 'not-a-real-code',
    code_verifier: pkcePair().verifier, redirect_uri: REDIRECT_URI,
    client_id: await sharedClient(h.base)
  }));
  assert.equal(response.status, 400);
});

/* ------------------------------------------- authorization endpoint guards */

test('an unknown client is reported in place, never by redirecting', async () => {
  const response = await fetch(authorizeUrl(h.base, {
    client_id: 'client_does_not_exist', redirect_uri: REDIRECT_URI,
    response_type: 'code', code_challenge: pkcePair().challenge, code_challenge_method: 'S256'
  }), { redirect: 'manual' });

  assert.equal(response.status, 400);
  assert.equal(response.headers.get('location'), null,
    'redirecting on an unresolved client would make this an open redirector');
});

test('an unregistered redirect_uri is refused without redirecting to it', async () => {
  const clientId = await sharedClient(h.base);
  const response = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: 'https://attacker.example/steal',
    response_type: 'code', code_challenge: pkcePair().challenge, code_challenge_method: 'S256'
  }), { redirect: 'manual' });

  assert.equal(response.status, 400);
  assert.equal(response.headers.get('location'), null);
});

test('a missing or weak PKCE challenge is refused, via the registered redirect', async () => {
  const clientId = await sharedClient(h.base);
  const response = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code', state: 's'
  }), { redirect: 'manual' });

  const location = new URL(response.headers.get('location') ?? '');
  assert.equal(location.origin + location.pathname, REDIRECT_URI);
  assert.equal(location.searchParams.get('error'), 'invalid_request');
  assert.equal(location.searchParams.get('state'), 's');
  assert.equal(location.searchParams.get('iss'), ISSUER, 'errors carry iss too');
});

test('an unsupported response_type is refused', async () => {
  const clientId = await sharedClient(h.base);
  const response = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'token',
    code_challenge: pkcePair().challenge, code_challenge_method: 'S256'
  }), { redirect: 'manual' });
  const location = new URL(response.headers.get('location') ?? '');
  assert.equal(location.searchParams.get('error'), 'unsupported_response_type');
});

test('a token for another resource is refused rather than quietly reissued for ours', async () => {
  const clientId = await sharedClient(h.base);
  const response = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: pkcePair().challenge, code_challenge_method: 'S256',
    resource: 'https://someone-elses-api.example/mcp'
  }), { redirect: 'manual' });

  const location = new URL(response.headers.get('location') ?? '');
  assert.equal(location.searchParams.get('error'), 'invalid_target');
});

test('a scope request naming nothing we support is refused', async () => {
  const clientId = await sharedClient(h.base);
  const response = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: pkcePair().challenge, code_challenge_method: 'S256',
    scope: 'offline_access profile'
  }), { redirect: 'manual' });

  const location = new URL(response.headers.get('location') ?? '');
  // A token authorizing nothing would leave the client in a step-up loop it
  // can never satisfy.
  assert.equal(location.searchParams.get('error'), 'invalid_scope');
});

test('a narrower scope request is honoured exactly', async () => {
  const authorization = await authorizeAs(h.base, { scope: 'devices:read' });
  const { body } = await exchange(h.base, authorization);
  assert.equal(body.scope, 'devices:read');

  const verified = await verifyOAuthAccessToken(h.db, body.access_token, ['devices:control']);
  assert.equal(verified.ok, false);
  assert.equal(verified.ok === false ? verified.reason : '', 'insufficient_scope');
});

/* --------------------------------------------------- the forged-context bug */

test('an authorization context cannot be forged by the browser', async () => {
  // The spike round-tripped this record through the form as unsigned base64,
  // which let anyone name their own redirect_uri and PKCE challenge, walk a
  // victim through a genuine login page, and collect a live code. The browser
  // now carries only an opaque id that has to already exist here.
  const forged = Buffer.from(JSON.stringify({
    clientId: 'https://attacker.example/cimd.json',
    redirectUri: 'https://attacker.example/steal',
    codeChallenge: pkcePair().challenge,
    scopes: [...SCOPES]
  })).toString('base64');

  const response = await fetch(`${h.base}/authorize`, form({
    pending: forged, mode: 'signup', username: `v${Date.now()}`, password: 'correct horse battery staple'
  }));

  assert.equal(response.status, 400);
  assert.equal(response.headers.get('location'), null, 'no code is issued and nothing is redirected');
});

test('a pending authorization is spent once a code is issued', async () => {
  const clientId = await sharedClient(h.base);
  const { challenge } = pkcePair();
  const page = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256'
  })).then((r) => r.text());
  const pending = pendingIdFrom(page)!;

  const first = await fetch(`${h.base}/authorize`, form({
    pending, mode: 'signup', username: `spent${Date.now()}`, password: 'correct horse battery staple'
  }));
  assert.ok(first.headers.get('location')?.includes('code='));

  // Replaying the same pending id must not mint a second code for the same
  // authorization request.
  const second = await fetch(`${h.base}/authorize`, form({
    pending, mode: 'login', username: 'anyone', password: 'correct horse battery staple'
  }));
  assert.equal(second.status, 400);
  assert.equal(second.headers.get('location'), null);
});

/* ------------------------------------------------------------ credentials */

test('a wrong password re-renders the page and issues nothing', async () => {
  const existing = await authorizeAs(h.base);
  const clientId = await sharedClient(h.base);
  const { challenge } = pkcePair();
  const page = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256'
  })).then((r) => r.text());
  const pending = pendingIdFrom(page)!;

  const response = await fetch(`${h.base}/authorize`, form({
    pending, mode: 'login', username: existing.username, password: 'definitely-wrong-password'
  }));

  assert.equal(response.headers.get('location'), null);
  const html = await response.text();
  assert.match(html, /Invalid username or password/);
  assert.doesNotMatch(html, /code=/);
});

test('cancelling returns access_denied and mints no code', async () => {
  const clientId = await sharedClient(h.base);
  const { challenge } = pkcePair();
  const page = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    state: 'cancel-state', code_challenge: challenge, code_challenge_method: 'S256'
  })).then((r) => r.text());
  const pending = pendingIdFrom(page)!;

  const response = await fetch(`${h.base}/authorize/cancel`, form({ pending }));
  const location = new URL(response.headers.get('location') ?? '');

  assert.equal(location.searchParams.get('error'), 'access_denied');
  assert.equal(location.searchParams.get('state'), 'cancel-state');
  assert.equal(location.searchParams.get('code'), null);
});

test('the consent screen names the client and never echoes markup', async () => {
  const clientId = await sharedClient(h.base);
  const page = await fetch(authorizeUrl(h.base, {
    client_id: clientId, redirect_uri: REDIRECT_URI, response_type: 'code',
    code_challenge: pkcePair().challenge, code_challenge_method: 'S256'
  })).then((r) => r.text());

  assert.match(page, /127\.0\.0\.1:41234/, 'the consent screen identifies the client');
  assert.match(page, /Switch your devices on and off/, 'scopes are described in plain words');
  assert.doesNotMatch(page, /<script/i);
});

/* ---------------------------------------------------------------- refresh */

test('refreshing rotates and keeps the grant working', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);

  const refreshed = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: first.body.refresh_token,
    client_id: authorization.clientId
  })).then(async (r) => ({ status: r.status, body: await r.json() as Record<string, string> }));

  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.body.refresh_token, first.body.refresh_token);
  assert.ok((await verifyOAuthAccessToken(h.db, refreshed.body.access_token)).ok);
});

test('replaying a rotated refresh token revokes the entire grant', async () => {
  const authorization = await authorizeAs(h.base);
  const first = await exchange(h.base, authorization);
  const second = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: first.body.refresh_token,
    client_id: authorization.clientId
  })).then((r) => r.json()) as Record<string, string>;

  const replay = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: first.body.refresh_token,
    client_id: authorization.clientId
  }));
  assert.equal(replay.status, 400);

  // Including the token the thief did not steal.
  assert.equal((await verifyOAuthAccessToken(h.db, second.access_token)).ok, false);
});

test('a refresh cannot widen scope beyond the original grant', async () => {
  const authorization = await authorizeAs(h.base, { scope: 'devices:read' });
  const first = await exchange(h.base, authorization);

  const widened = await fetch(`${h.base}/token`, json({
    grant_type: 'refresh_token', refresh_token: first.body.refresh_token,
    client_id: authorization.clientId, scope: 'devices:read devices:control'
  }));
  assert.equal(widened.status, 400);
  assert.equal((await widened.json() as Record<string, string>).error, 'invalid_scope');
});

/* ------------------------------------------------------------- revocation */

test('revoking a refresh token kills the access token with it', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);
  assert.ok((await verifyOAuthAccessToken(h.db, body.access_token)).ok);

  const response = await fetch(`${h.base}/revoke`, json({
    token: body.refresh_token, token_type_hint: 'refresh_token'
  }));
  assert.equal(response.status, 200);

  assert.equal((await verifyOAuthAccessToken(h.db, body.access_token)).ok, false);
});

test('revoking an access token works without a hint', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);

  await fetch(`${h.base}/revoke`, json({ token: body.access_token }));

  assert.equal((await verifyOAuthAccessToken(h.db, body.access_token)).ok, false);
});

test('revoking an unknown token still answers 200', async () => {
  // RFC 7009: the endpoint must not become an oracle for which tokens exist.
  const response = await fetch(`${h.base}/revoke`, json({ token: 'never-issued' }));
  assert.equal(response.status, 200);
});

/* ------------------------------------------------------ token verification */

test('a token minted for another audience is refused', async () => {
  const authorization = await authorizeAs(h.base);
  const { body } = await exchange(h.base, authorization);

  await h.db.query(
    `UPDATE oauth_access_tokens SET audience = 'https://elsewhere.example/mcp'
      WHERE token_hash = encode(digest($1, 'sha256'), 'hex')`,
    [body.access_token]
  ).catch(async () => {
    // pgcrypto may be unavailable; fall back to rewriting every row, which is
    // equivalent for a single-token test.
    await h.db.query(`UPDATE oauth_access_tokens SET audience = 'https://elsewhere.example/mcp'`);
  });

  assert.equal((await verifyOAuthAccessToken(h.db, body.access_token)).ok, false,
    'RFC 8707: a token valid elsewhere is not valid here');
});

test('an absent or unknown token is refused', async () => {
  assert.equal((await verifyOAuthAccessToken(h.db, null)).ok, false);
  assert.equal((await verifyOAuthAccessToken(h.db, 'nonsense')).ok, false);
});

/* ---------------------------------------------------------- redirect rules */

test('loopback redirect URIs match with the port ignored', () => {
  // RFC 8252 section 7.3: a native app binds an ephemeral port at runtime and
  // cannot register it in advance.
  assert.ok(redirectUriAllowed('http://127.0.0.1:55123/callback', ['http://127.0.0.1:41234/callback']));
  assert.ok(redirectUriAllowed('http://localhost:9999/cb', ['http://localhost:1/cb']));

  assert.ok(!redirectUriAllowed('http://127.0.0.1:55123/other', ['http://127.0.0.1:41234/callback']));
  assert.ok(!redirectUriAllowed('https://evil.example/callback', ['http://127.0.0.1:41234/callback']));
  // Non-loopback hosts must still match exactly, port included.
  assert.ok(!redirectUriAllowed('https://app.example:8443/cb', ['https://app.example/cb']));
  assert.ok(!redirectUriAllowed('http://127.0.0.1:1/cb#fragment', ['http://127.0.0.1:1/cb']));
});
