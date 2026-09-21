/**
 * Gets this server host-ready and checks it before you involve a host.
 *
 *   node tools/host-check/run.mjs
 *
 * Opens a tunnel, starts the server told the origin it is reachable at,
 * verifies the whole discovery chain over real HTTPS, and prints the URL to
 * paste into Claude or ChatGPT along with what to look for.
 *
 * The point is that everything that can fail without a host should have
 * already failed here. What is left when this passes is exactly the set of
 * questions a host has to answer, and those are in spike/FINDINGS.md.
 */

import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const PORT = 4000;

async function tunnelUrl() {
  // ngrok publishes its own local API once a tunnel is up.
  for (let attempt = 0; attempt < 25; attempt++) {
    try {
      const { tunnels } = await fetch('http://localhost:4040/api/tunnels').then((r) => r.json());
      const https = tunnels.find((tunnel) => tunnel.public_url?.startsWith('https://'));
      if (https) return https.public_url;
    } catch { /* not up yet */ }
    await delay(400);
  }
  return null;
}

function die(message) {
  process.stderr.write(`\n  ${message}\n\n`);
  process.exit(1);
}

process.stdout.write('\n  Opening a tunnel...\n');
const ngrok = spawn('ngrok', ['http', String(PORT), '--log', 'stdout'], { stdio: 'ignore' });
ngrok.on('error', () => die(
  'ngrok is not installed or not on PATH.\n'
  + '  Any HTTPS tunnel works — start one to port 4000 and run:\n'
  + `  BASE_URL=https://your-hostname npm start`
));

const base = await tunnelUrl();
if (!base) die('The tunnel did not come up. Is ngrok authenticated? Try: ngrok config check');

process.stdout.write(`  Tunnel:  ${base}\n  Starting the server...\n`);
const server = spawn(process.execPath, ['src/index.ts'], {
  env: { ...process.env, BASE_URL: base },
  stdio: 'ignore'
});

const stop = () => { ngrok.kill(); server.kill(); };
process.on('SIGINT', () => { stop(); process.exit(0); });
process.on('SIGTERM', () => { stop(); process.exit(0); });

await delay(2500);

/* ------------------------------------------------------------- self-check */

const checks = [];
const check = (label, ok, detail = '') => checks.push({ label, ok, detail });
const headers = { 'ngrok-skip-browser-warning': 'true' };

try {
  const prm = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`, { headers })
    .then((r) => r.json());
  check('protected resource metadata names the tunnel', prm.resource === `${base}/mcp`, prm.resource);

  const meta = await fetch(`${base}/.well-known/oauth-authorization-server`, { headers })
    .then((r) => r.json());
  check('authorization server metadata agrees', meta.issuer === base);
  check('PKCE S256 advertised', meta.code_challenge_methods_supported?.includes('S256'));
  // Claude picks CIMD only when both of these are present.
  check('CIMD advertised', meta.client_id_metadata_document_supported === true);
  check('public clients accepted at the token endpoint',
    meta.token_endpoint_auth_methods_supported?.includes('none'));

  const anonymous = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
  });
  const tools = (await anonymous.json()).result?.tools ?? [];
  check('anonymous discovery works', anonymous.status === 200, `${tools.length} tools`);

  const denied = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_devices', arguments: {} } })
  });
  const challenge = denied.headers.get('www-authenticate') ?? '';
  // This is the one that decides whether a host offers to sign you in at all.
  check('a protected call answers 401 at the transport layer', denied.status === 401);
  check('the challenge points back through the tunnel',
    challenge.includes(`${base}/.well-known/oauth-protected-resource/mcp`));
  check('the challenge names the scopes', challenge.includes('devices:control'));
} catch (error) {
  stop();
  die(`The self-check could not reach the server: ${error.message}`);
}

process.stdout.write('\n');
for (const { label, ok, detail } of checks) {
  process.stdout.write(`  ${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? `  (${detail})` : ''}\n`);
}

if (checks.some((entry) => !entry.ok)) {
  stop();
  die('Fix these before involving a host — none of them need one.');
}

process.stdout.write(`
  Everything that can be checked without a host passes.

  Connector URL   ${base}/mcp

  Claude    Settings > Connectors > Add custom connector.
            Do it on web or desktop: a custom connector has to be added
            there before it appears on mobile. Then open that same
            conversation on your iPhone.

  ChatGPT   Settings > Connectors > Advanced > Developer mode.
            Web only.

  Then, in a conversation:

    "Sign in to IoT Switch"      Q1  does a Connect prompt appear?
    "Show my devices"            Q2  how many rows fit before it clips?
                                 Q3  does "Show all" go fullscreen?
    toggle a switch              Q4  is every write confirmed?
    open the same chat on iOS    Q5  does any of it reach the phone?

  Record what you see in spike/FINDINGS.md. Screenshots beat recollection.
  Ctrl-C to stop.

`);

// Hold the tunnel and server open.
await new Promise(() => {});
