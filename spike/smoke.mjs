/**
 * End-to-end smoke test for the phase 0 spike.
 *
 * Run this before spending time in a host UI. If it fails, the host was never
 * going to work, and debugging here is far cheaper than debugging inside
 * someone else's OAuth client.
 *
 *   node smoke.mjs [baseUrl]
 */

import { createHash, randomBytes } from 'node:crypto';

const BASE = (process.argv[2] ?? 'http://localhost:3000').replace(/\/$/, '');
const MCP = `${BASE}/mcp`;
const REDIRECT = 'http://127.0.0.1:41234/callback';

let passed = 0;
let failed = 0;

function check(name, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ok   ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

async function rpc(method, params, token) {
  const response = await fetch(MCP, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params })
  });
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* non-JSON body is itself data */ }
  return { status: response.status, headers: response.headers, body, text };
}

const call = (name, args, token) => rpc('tools/call', { name, arguments: args ?? {} }, token);

/** Drives the full authorization-code + PKCE flow the way a host would. */
async function authorize(scope, resource = MCP) {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const registration = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT] })
  }).then((r) => r.json());

  const authorizeUrl = new URL(`${BASE}/authorize`);
  authorizeUrl.search = new URLSearchParams({
    client_id: registration.client_id,
    redirect_uri: REDIRECT,
    response_type: 'code',
    state: 'xyz',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource,
    scope
  }).toString();

  const page = await fetch(authorizeUrl).then((r) => r.text());
  const payload = page.match(/name="p" value="([^"]+)"/)?.[1];
  if (!payload) throw new Error('authorize page did not render a form');

  const username = `spike_${randomBytes(4).toString('hex')}`;
  const redirected = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ p: payload, mode: 'signup', username, password: 'correct horse battery staple' }),
    redirect: 'manual'
  });

  const location = new URL(redirected.headers.get('location'));
  const token = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: location.searchParams.get('code'),
      code_verifier: verifier,
      redirect_uri: REDIRECT,
      resource
    })
  }).then((r) => r.json());

  return { token, location, username, verifier, registration };
}

/* ------------------------------------------------------------------ run */

section('Discovery');
for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
  const prm = await fetch(BASE + path).then((r) => r.json());
  check(`PRM served at ${path}`, prm.resource === MCP, `resource=${prm.resource}`);
}
const asMeta = await fetch(`${BASE}/.well-known/oauth-authorization-server`).then((r) => r.json());
check('AS advertises S256', asMeta.code_challenge_methods_supported?.includes('S256'));
check('AS advertises CIMD', asMeta.client_id_metadata_document_supported === true);
check('AS advertises token_endpoint_auth_methods none', asMeta.token_endpoint_auth_methods_supported?.includes('none'));
check('AS advertises iss parameter', asMeta.authorization_response_iss_parameter_supported === true);

section('Anonymous access');
const init = await rpc('initialize', {
  protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'smoke', version: '0' }
});
check('initialize succeeds without a token', init.status === 200 && !!init.body?.result);
const tools = await rpc('tools/list', {});
const toolNames = (tools.body?.result?.tools ?? []).map((t) => t.name);
check('tools/list succeeds without a token', tools.status === 200);
check('all six tools are discoverable', toolNames.length === 6, toolNames.join(', '));
const uiTools = (tools.body?.result?.tools ?? []).filter((t) => t._meta?.ui?.resourceUri);
check('UI tools carry _meta.ui.resourceUri', uiTools.length === 2, uiTools.map((t) => t.name).join(', '));
check('UI tools carry the ChatGPT alias', uiTools.every((t) => t._meta['openai/outputTemplate']));
const ping = await call('ping');
check('public tool callable without a token', ping.status === 200 && !ping.body?.result?.isError);
const status = await call('get_auth_status');
check('get_auth_status reports signed out', status.body?.result?.structuredContent?.authenticated === false);

const resources = await rpc('resources/list', {});
check('UI resources discoverable anonymously', (resources.body?.result?.resources ?? []).length === 2);
const read = await rpc('resources/read', { uri: 'ui://iot-spike/devices.html' });
const contents = read.body?.result?.contents?.[0];
check('UI resource readable anonymously', !!contents?.text);
check('UI resource uses the mcp-app mime type', contents?.mimeType === 'text/html;profile=mcp-app', contents?.mimeType);
check('UI resource contains no user data', !(contents?.text ?? '').includes('Bedroom Lamp'));

section('The challenge (spec section 7.5)');
const denied = await call('list_devices');
check('protected tool returns 401, not 200', denied.status === 401, `got ${denied.status}`);
const wwwAuth = denied.headers.get('www-authenticate') ?? '';
check('challenge is a Bearer challenge', wwwAuth.startsWith('Bearer '), wwwAuth);
check('challenge points at resource metadata', wwwAuth.includes('resource_metadata='), wwwAuth);
check('challenge names the required scopes', wwwAuth.includes('scope="devices:read'), wwwAuth);
check('body is not a tool result', denied.body?.result === undefined);

section('Authorized access');
const { token: grant } = await authorize('devices:read devices:control devices:create');
check('token issued', typeof grant.access_token === 'string');
check('token carries granted scope', grant.scope?.includes('devices:control'), grant.scope);

const listed = await call('list_devices', {}, grant.access_token);
const devices = listed.body?.result?.structuredContent?.devices ?? [];
check('list_devices succeeds with a token', listed.status === 200 && devices.length === 12, `${devices.length} devices`);
check('devices are ordered oldest first', devices[0]?.name === 'Bedroom Lamp', devices[0]?.name);
check('internal fields are not leaked', devices[0] && !('ownerId' in devices[0]) && !('normalizedName' in devices[0]));

section('Control semantics (spec section 6.1)');
const target = devices[1];
const flipped = await call('control_device',
  { deviceId: target.id, state: 'on', expectedVersion: target.version }, grant.access_token);
const updated = flipped.body?.result?.structuredContent?.device;
check('state change persists', updated?.state === 'on', JSON.stringify(updated));
check('version increments on a real change', updated?.version === target.version + 1, `v${updated?.version}`);

const replay = await call('control_device',
  { deviceId: target.id, state: 'on', expectedVersion: target.version }, grant.access_token);
check('replaying a consumed version conflicts',
  replay.body?.result?.structuredContent?.error?.code === 'DEVICE_VERSION_CONFLICT',
  JSON.stringify(replay.body?.result?.structuredContent));

const noop = await call('control_device',
  { deviceId: target.id, state: 'on', expectedVersion: updated.version }, grant.access_token);
const afterNoop = noop.body?.result?.structuredContent?.device;
check('no-op does not bump version', afterNoop?.version === updated.version, `v${afterNoop?.version}`);
check('no-op does not bump updatedAt', afterNoop?.updatedAt === updated.updatedAt);

section('Isolation');
const { token: other } = await authorize('devices:read devices:control devices:create');
const crossRead = await call('get_device', { deviceId: target.id }, other.access_token);
check('another account cannot read the device',
  crossRead.body?.result?.structuredContent?.error?.code === 'DEVICE_NOT_FOUND',
  JSON.stringify(crossRead.body?.result?.structuredContent));
const crossWrite = await call('control_device',
  { deviceId: target.id, state: 'off', expectedVersion: 1 }, other.access_token);
check('another account cannot control the device',
  crossWrite.body?.result?.structuredContent?.error?.code === 'DEVICE_NOT_FOUND');

section('Token binding and scope');
const forged = await call('list_devices', {}, 'not-a-real-token');
check('an unknown token is challenged', forged.status === 401);

// A token that is entirely valid, but minted for a different resource, must be
// refused here. This is the confused-deputy case RFC 8707 exists to prevent.
const { token: wrongAudience } = await authorize('devices:read', 'https://someone-elses-api.example/mcp');
check('a token for another resource is issued by the AS', typeof wrongAudience.access_token === 'string');
const audienceDenied = await call('list_devices', {}, wrongAudience.access_token);
check('a token for another resource is rejected', audienceDenied.status === 401, `got ${audienceDenied.status}`);

const { token: readOnly } = await authorize('devices:read');
const scopeDenied = await call('control_device',
  { deviceId: 'dev_01', state: 'on', expectedVersion: 1 }, readOnly.access_token);
check('insufficient scope returns 403', scopeDenied.status === 403, `got ${scopeDenied.status}`);
const scopeChallenge = scopeDenied.headers.get('www-authenticate') ?? '';
check('403 carries insufficient_scope', scopeChallenge.includes('error="insufficient_scope"'), scopeChallenge);
check('403 names every needed scope', scopeChallenge.includes('devices:control'), scopeChallenge);
const readStillWorks = await call('list_devices', {}, readOnly.access_token);
check('a read-only token can still read', readStillWorks.status === 200);

section('Authorization hardening (regressions)');

// An authorization context must not be constructible by the browser. This
// exact payload previously walked a victim through a real login page and
// handed a live code to an attacker-chosen redirect_uri.
const forgedContext = Buffer.from(JSON.stringify({
  clientId: 'https://attacker.example/cimd.json',
  redirectUri: 'https://attacker.example/steal',
  state: 's', codeChallenge: 'x', resource: MCP,
  scopes: ['devices:read'], displayHost: 'claude.ai', expiresAt: Date.now() + 999999
})).toString('base64');

const forgedGet = await fetch(`${BASE}/authorize?p=${encodeURIComponent(forgedContext)}`);
check('a forged authorization context is refused', forgedGet.status === 400, `got ${forgedGet.status}`);

const forgedPost = await fetch(`${BASE}/authorize`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ p: forgedContext, mode: 'signup', username: `x${Date.now()}`, password: 'a-very-long-password' }),
  redirect: 'manual'
});
check('a forged context issues no code', forgedPost.status === 400, `got ${forgedPost.status}`);
check('a forged context triggers no redirect', forgedPost.headers.get('location') === null,
  String(forgedPost.headers.get('location')));

// A scope set this server does not recognise must fail loudly rather than
// producing a token that authorizes nothing.
const registration = await fetch(`${BASE}/register`, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ redirect_uris: [REDIRECT] })
}).then((r) => r.json());
const badScope = new URL(`${BASE}/authorize`);
badScope.search = new URLSearchParams({
  client_id: registration.client_id, redirect_uri: REDIRECT, response_type: 'code',
  code_challenge: createHash('sha256').update('v').digest('base64url'),
  code_challenge_method: 'S256', resource: MCP, scope: 'offline_access profile'
}).toString();
check('an unsupported-only scope request is refused',
  (await fetch(badScope)).status === 400);

// A code is bound to the client it was issued to.
const { token: bindable, registration: issuedTo } = await authorize('devices:read');
check('baseline token still issues', typeof bindable.access_token === 'string', String(issuedTo?.client_id));

console.log(`\n${failed === 0 ? 'PASS' : 'FAIL'} — ${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
