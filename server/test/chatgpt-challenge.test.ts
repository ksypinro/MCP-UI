/**
 * The ChatGPT form of the authorization challenge.
 *
 * Claude starts sign-in only from a transport 401. ChatGPT starts account
 * linking from a tool error carrying _meta["mcp/www_authenticate"] on a tool
 * that declares securitySchemes. The tool form is off by default and applies
 * only to requests a trusted proxy has marked as ChatGPT's.
 */

import test, { after, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, type Harness } from './oauth-helpers.ts';
import { callTool, nextId, rpc, tokenFor } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });
afterEach(() => {
  delete process.env.CHATGPT_TOOL_CHALLENGE;
  delete process.env.TRUST_PROXY;
});

async function callAsChatGpt(name: string, token?: string, args: Record<string, unknown> = {}) {
  const response = await fetch(`${h.base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'x-verified-client': 'chatgpt',
      ...(token ? { authorization: `Bearer ${token}` } : {})
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId(), method: 'tools/call', params: { name, arguments: args } })
  });
  return { status: response.status, body: await response.json() as any };
}

test('by default the challenge is a transport 401 even for a marked request', async () => {
  const response = await callAsChatGpt('list_devices');
  assert.equal(response.status, 401);
});

test('the marking header is ignored unless a trusted proxy is configured', async () => {
  // Otherwise anyone could downgrade the 401 into a tool error by sending it.
  process.env.CHATGPT_TOOL_CHALLENGE = 'trusted-header';
  const response = await callAsChatGpt('list_devices');
  assert.equal(response.status, 401);
});

test('a trusted ChatGPT request gets the challenge as a tool error', async () => {
  process.env.CHATGPT_TOOL_CHALLENGE = 'trusted-header';
  process.env.TRUST_PROXY = 'loopback';

  const response = await callAsChatGpt('list_devices');
  assert.equal(response.status, 200);
  const result = response.body.result;
  assert.equal(result.isError, true);
  assert.equal(result.structuredContent, undefined);
  const [value] = result._meta['mcp/www_authenticate'];
  assert.match(value, /^Bearer error="invalid_token"/);
  assert.match(value, /resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource\/mcp"/);
});

test('a token short of scope gets the tool challenge and never reaches the handler', async () => {
  process.env.CHATGPT_TOOL_CHALLENGE = 'trusted-header';
  process.env.TRUST_PROXY = 'loopback';
  const { accessToken } = await tokenFor(h, { scope: 'devices:read' });

  const response = await callAsChatGpt('add_device', accessToken, { name: 'Bedroom Lamp' });
  assert.equal(response.status, 200);
  assert.equal(response.body.result.isError, true);
  assert.match(response.body.result._meta['mcp/www_authenticate'][0], /error="insufficient_scope"/);

  // Nothing was created: the handler refused for want of an identity.
  const { accessToken: full } = await tokenFor(h);
  const listed = await callTool(h.base, 'list_devices', {}, full);
  assert.equal(listed.body.result.structuredContent.devices.length, 0);
});

test('every tool declares its security scheme, at the top level and in _meta', async () => {
  const response = await rpc(h.base, { jsonrpc: '2.0', id: nextId(), method: 'tools/list' });
  const tools = response.body.result.tools as any[];
  assert.ok(tools.length >= 7);
  for (const tool of tools) {
    assert.ok(Array.isArray(tool.securitySchemes), `${tool.name} has no securitySchemes`);
    assert.deepEqual(tool._meta.securitySchemes, tool.securitySchemes);
  }
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool.securitySchemes]));
  assert.deepEqual(byName.control_device, [{ type: 'oauth2', scopes: ['devices:control'] }]);
  assert.deepEqual(byName.show_auth, [{ type: 'noauth' }]);
});
