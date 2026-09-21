/**
 * Connects to this server the way a specification-compliant MCP client does.
 *
 *   npm start                            # server on :4000
 *   node tools/client-check/run.mjs
 *
 * Everything else in the suite drives the endpoints directly, which proves
 * they behave as intended but not that a real client can find its way through
 * them. This uses the official SDK's own client, transport and OAuth
 * implementation: discovery, registration, PKCE, the token exchange and bearer
 * attachment are all its code, not ours.
 *
 * The one thing it stands in for is the person. Where a real client opens a
 * browser, this posts the credentials to the hosted page and reads the code
 * out of the redirect — which is exactly what a human does, minus the typing.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js';

const BASE = process.env.BASE ?? 'http://localhost:4000';
const MCP_URL = new URL(`${BASE}/mcp`);
const REDIRECT = 'http://127.0.0.1:41234/callback';

const results = [];
const check = (label, ok, detail = '') => {
  results.push({ label, ok, detail });
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}\n`);
};

/** Stands in for the browser and the person at it. */
async function completeAuthorization(authorizationUrl) {
  const page = await fetch(authorizationUrl).then((r) => r.text());
  const pending = page.match(/name="pending" value="([^"]+)"/)?.[1];
  if (!pending) throw new Error('the authorization page did not render a form');

  const redirected = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      pending, mode: 'signup',
      username: 'clientcheck' + Date.now().toString(36),
      password: 'correct horse battery staple'
    }),
    redirect: 'manual'
  });

  const location = redirected.headers.get('location');
  if (!location) throw new Error(`the page did not redirect (${redirected.status})`);
  return new URL(location);
}

let authorizationCode = null;
let sawIssuer = null;
let registeredAs = null;
let storedTokens = null;
let codeVerifier = null;

const provider = {
  get redirectUrl() { return REDIRECT; },
  get clientMetadata() {
    return {
      client_name: 'Client conformance check',
      redirect_uris: [REDIRECT],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    };
  },
  clientInformation() { return registeredAs ?? undefined; },
  saveClientInformation(information) { registeredAs = information; },
  tokens() { return storedTokens ?? undefined; },
  saveTokens(tokens) { storedTokens = tokens; },
  saveCodeVerifier(verifier) { codeVerifier = verifier; },
  codeVerifier() { return codeVerifier; },
  async redirectToAuthorization(authorizationUrl) {
    // The SDK built this URL from what it discovered. Everything asserted
    // here is therefore the SDK's reading of our metadata, not ours.
    check('the client built an authorization URL', true, authorizationUrl.origin);
    check('PKCE S256 was chosen', authorizationUrl.searchParams.get('code_challenge_method') === 'S256');
    check('a resource indicator was sent (RFC 8707)',
      authorizationUrl.searchParams.get('resource') === `${BASE}/mcp`,
      authorizationUrl.searchParams.get('resource') ?? 'absent');

    const callback = await completeAuthorization(authorizationUrl);
    authorizationCode = callback.searchParams.get('code');
    sawIssuer = callback.searchParams.get('iss');
  }
};

process.stdout.write('\n  Connecting as a specification-compliant client\n\n');

const client = new Client({ name: 'client-check', version: '0.1.0' }, { capabilities: {} });
const transport = new StreamableHTTPClientTransport(MCP_URL, { authProvider: provider });

// Lazy authentication: a client can connect and look around before anyone has
// signed in, and is only challenged when it asks for something private.
await client.connect(transport);
check('connected with no token at all', true);

const { tools } = await client.listTools();
check('tools are listed anonymously', tools.length > 0, `${tools.length} tools`);

try {
  await client.callTool({ name: 'list_devices', arguments: {} });
  check('a protected call was refused', false, 'it succeeded without a token');
} catch (error) {
  // The SDK reaches here only after following the 401 challenge to the
  // protected resource metadata, on to the authorization server metadata,
  // registering itself, and building an authorization URL.
  check('a protected call raised the authorization flow',
    error instanceof UnauthorizedError, error?.constructor?.name);
}

check('the client registered itself', Boolean(registeredAs?.client_id),
  registeredAs?.client_id?.slice(0, 18));
check('an authorization code came back', Boolean(authorizationCode));
check('the issuer was returned (RFC 9207)', sawIssuer === BASE, sawIssuer ?? 'absent');

await transport.finishAuth(authorizationCode);
check('the client exchanged the code for a token', Boolean(storedTokens?.access_token),
  storedTokens?.scope);

const listed = await client.callTool({ name: 'list_devices', arguments: {} });
check('the protected call now works', Array.isArray(listed.structuredContent?.devices));

const linked = tools.filter((tool) => tool._meta?.ui?.resourceUri);
check('UI tools advertise their views', linked.length === 4,
  linked.map((tool) => tool.name).join(', '));

const { resources } = await client.listResources();
check('views are listed as resources', resources.length === 4,
  resources.map((resource) => resource.uri.replace('ui://iot/', '')).join(', '));

const view = await client.readResource({ uri: 'ui://iot/devices.html' });
check('a view reads back with the MCP Apps content type',
  view.contents[0]?.mimeType === 'text/html;profile=mcp-app');

const added = await client.callTool({ name: 'add_device', arguments: { name: 'Conformance Lamp' } });
const device = added.structuredContent?.device;
check('add_device works through the client', device?.state === 'off' && device?.version === 1);

const controlled = await client.callTool({
  name: 'control_device',
  arguments: { deviceId: device.id, state: 'on', expectedVersion: device.version }
});
check('control_device works through the client',
  controlled.structuredContent?.device?.state === 'on',
  controlled.content?.[0]?.text);

const stale = await client.callTool({
  name: 'control_device',
  arguments: { deviceId: device.id, state: 'off', expectedVersion: device.version }
});
// The check that found the interop bug: a client validates structuredContent
// against the tool's output schema whenever it is present, so an error result
// carrying it is rejected as a protocol error before the caller ever sees the
// conflict. The code travels in _meta instead.
check('a stale version surfaces as a tool error, not a transport failure',
  stale.isError === true && stale._meta?.['iot/error']?.code === 'DEVICE_VERSION_CONFLICT',
  stale._meta?.['iot/error']?.code ?? 'no code');
check('the error result carries no schema-bound content',
  stale.structuredContent === undefined);

await client.close();

const failed = results.filter((entry) => !entry.ok).length;
process.stdout.write(
  `\n  ${results.length - failed} of ${results.length} checks passed\n\n`
);
process.exit(failed === 0 ? 0 : 1);
