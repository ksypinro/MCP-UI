/**
 * Renders the MCP App views against a running server, in a browser.
 *
 * Not a test and not shipped. It exists because the views cannot otherwise be
 * looked at: they only run inside an MCP host, and the alternative to this is
 * grepping their source and hoping. It earned its place immediately — it
 * found a handler-registry collision in the bridge that every unit test
 * passed straight over.
 *
 *   node tools/mock-host/run.mjs
 *
 * Expects the server on :4000. Seeds an account and a few devices, writes the
 * views out, serves them alongside a mock host on :8099, and prints the URL.
 */

import { createHash, randomBytes } from 'node:crypto';
import { writeFileSync, mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { uiResources } from '../../src/mcp/ui/index.ts';

const BASE = process.env.BASE ?? 'http://localhost:4000';
const REDIRECT = 'http://127.0.0.1:41234/callback';
const here = dirname(fileURLToPath(import.meta.url));

async function authorize() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const registration = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: 'Mock host' })
  }).then((r) => r.json());

  const page = await fetch(`${BASE}/authorize?` + new URLSearchParams({
    client_id: registration.client_id, redirect_uri: REDIRECT, response_type: 'code',
    code_challenge: challenge, code_challenge_method: 'S256'
  })).then((r) => r.text());

  const pending = page.match(/name="pending" value="([^"]+)"/)?.[1];
  if (!pending) throw new Error('the authorization page did not render a form');

  const redirected = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      pending, mode: 'signup',
      username: 'mockhost' + Date.now().toString(36),
      password: 'correct horse battery staple'
    }),
    redirect: 'manual'
  });

  const code = new URL(redirected.headers.get('location')).searchParams.get('code');
  const tokens = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, code_verifier: verifier,
      redirect_uri: REDIRECT, client_id: registration.client_id
    })
  }).then((r) => r.json());

  if (!tokens.access_token) throw new Error(`no token: ${JSON.stringify(tokens)}`);
  return tokens.access_token;
}

const call = (token, name, args) => fetch(`${BASE}/mcp`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    authorization: `Bearer ${token}`
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } })
}).then((r) => r.json());

const token = await authorize();

// Six, so the list has more than an inline card is meant to show.
for (const name of [
  'Bedroom Lamp', 'Kitchen Downlights', 'Porch Light',
  'Desk Fan', 'Hallway Nightlight', 'Studio Monitor'
]) {
  await call(token, 'add_device', { name });
}

const dir = mkdtempSync(join(tmpdir(), 'iot-mock-host-'));
for (const view of uiResources()) writeFileSync(join(dir, `${view.name}.html`), view.html);
copyFileSync(join(here, 'host.html'), join(dir, 'host.html'));

spawn(process.execPath, [join(here, 'serve.mjs'), dir], { stdio: 'inherit' });

process.stdout.write(
  `\n  open  http://localhost:8099/host.html?token=${token}\n\n`
  + '  Six devices seeded. The list shows four inline; "Show all" asks the\n'
  + '  host for fullscreen. Toggling a switch is a real round trip.\n\n'
);
