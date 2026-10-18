/**
 * Three origins: the authorization server, the MCP endpoint and the REST API
 * each answer only on their own host, so a cookie or page of one is never
 * reachable through another. Configured before the server is imported, which
 * is why this file has a process to itself.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

process.env.AUTH_BASE_URL = 'http://auth.iot.test';
process.env.MCP_BASE_URL = 'http://mcp.iot.test';
process.env.API_BASE_URL = 'http://api.iot.test';

let server: Server;
let port = 0;
let closeDb: () => Promise<void>;

before(async () => {
  const { createDb } = await import('../src/db/index.ts');
  const { createApp } = await import('../src/http/app.ts');
  const db = await createDb();
  closeDb = () => db.close();
  server = createApp(db).listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  port = (server.address() as AddressInfo).port;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closeDb();
});

function send(host: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = request({
      host: '127.0.0.1', port, method, path,
      headers: {
        host,
        accept: 'application/json, text/event-stream',
        ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: text }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

test('the authorization server answers only on its own host', async () => {
  const onAuth = await send('auth.iot.test', 'GET', '/.well-known/oauth-authorization-server');
  assert.equal(onAuth.status, 200);
  assert.equal(JSON.parse(onAuth.body).issuer, 'http://auth.iot.test');

  assert.equal((await send('mcp.iot.test', 'GET', '/.well-known/oauth-authorization-server')).status, 404);
  assert.equal((await send('mcp.iot.test', 'GET', '/authorize')).status, 404);
  assert.equal((await send('api.iot.test', 'GET', '/authorize')).status, 404);
});

test('the MCP endpoint and its resource metadata answer only on the MCP host', async () => {
  const prm = await send('mcp.iot.test', 'GET', '/.well-known/oauth-protected-resource/mcp');
  assert.equal(prm.status, 200);
  const metadata = JSON.parse(prm.body);
  assert.equal(metadata.resource, 'http://mcp.iot.test/mcp');
  assert.deepEqual(metadata.authorization_servers, ['http://auth.iot.test'], 'the issuer is the auth host');

  const list = { jsonrpc: '2.0', id: 1, method: 'tools/list' };
  assert.equal((await send('mcp.iot.test', 'POST', '/mcp', list)).status, 200);
  assert.equal((await send('auth.iot.test', 'POST', '/mcp', list)).status, 404);
  assert.equal((await send('auth.iot.test', 'GET', '/.well-known/oauth-protected-resource/mcp')).status, 404);
});

test('the REST API answers only on the API host', async () => {
  assert.equal((await send('api.iot.test', 'GET', '/v1/devices')).status, 401);
  assert.equal((await send('mcp.iot.test', 'GET', '/v1/devices')).status, 404);
  assert.equal((await send('auth.iot.test', 'GET', '/v1/devices')).status, 404);
});
