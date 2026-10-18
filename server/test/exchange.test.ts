/**
 * Token exchange (RFC 8693) and the internal tokens it mints. Plan 2.3 and
 * 2.5, architecture section 7.6.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { exchangeToken, INTERNAL_AUDIENCE } from '../src/oauth/exchange.ts';
import { ISSUER } from '../src/oauth/config.ts';
import { publicJwks } from '../src/oauth/jwks.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { startSession } from '../src/domain/sessions.ts';
import { createAccount } from '../src/domain/accounts.ts';
import { createWorkload } from '../src/security/workload.ts';
import { ExchangeClient } from '../src/exchange-client.ts';
import { revokeGrantNow } from '../src/oauth/store.ts';
import { keys, newSigningKey } from '../src/security/keys.ts';
import { createDeviceService } from '../src/device-service/service.ts';
import type { VerifiedCaller } from '../src/domain/types.ts';
import { startServer, type Harness } from './oauth-helpers.ts';
import { tokenFor } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

const mcp = createWorkload('mcp-rs');
const gateway = createWorkload('api-gw');

async function mcpCaller(scope?: string): Promise<VerifiedCaller> {
  const { accessToken } = await tokenFor(h, scope ? { scope } : {});
  const verified = await verifyOAuthAccessToken(h.db, accessToken);
  if (!verified.ok) throw new Error('token did not verify');
  return {
    kind: 'verified', accountId: verified.accountId, clientId: verified.clientId, grantId: verified.grantId,
    channel: 'mcp', scopes: verified.scopes, requestId: 'req_test', credential: accessToken
  };
}

test('an internal token names who, through what, for which one scope', async () => {
  const caller = await mcpCaller();
  const { token, expiresIn } = await exchangeToken(h.db, { workload: mcp, subjectToken: caller.credential, scope: 'devices:control' });

  const header = decodeProtectedHeader(token);
  assert.equal(header.typ, 'at+jwt');
  assert.equal(header.alg, 'ES256');
  assert.ok(publicJwks().keys.some((key) => key.kid === header.kid), 'signed by a published key');

  const claims = decodeJwt(token) as Record<string, any>;
  assert.equal(claims.iss, ISSUER);
  assert.equal(claims.aud, INTERNAL_AUDIENCE);
  assert.equal(claims.sub, caller.accountId);
  assert.equal(claims.client_id, caller.clientId);
  assert.equal(claims.grant_id, caller.grantId);
  assert.equal(claims.scope, 'devices:control', 'exactly one scope');
  assert.equal(claims.act.sub, 'spiffe://iot-switch/mcp-rs');
  assert.equal(claims.cnf.jkt, mcp.jkt);
  assert.ok(expiresIn <= 60 && claims.exp - claims.iat === expiresIn);
});

test('an exchange can narrow scope but never widen it', async () => {
  const caller = await mcpCaller('devices:read');
  await exchangeToken(h.db, { workload: mcp, subjectToken: caller.credential, scope: 'devices:read' });
  await assert.rejects(
    exchangeToken(h.db, { workload: mcp, subjectToken: caller.credential, scope: 'devices:control' }),
    (error: any) => error.code === 'INSUFFICIENT_SCOPE'
  );
});

test('each adapter may present only its own kind of credential', async () => {
  const caller = await mcpCaller();
  await assert.rejects(
    exchangeToken(h.db, { workload: gateway, subjectToken: caller.credential, scope: 'devices:read' }),
    (error: any) => error.code === 'UNAUTHENTICATED',
    'an MCP token presented by the REST gateway'
  );

  const account = await createAccount(h.db, `fp${Date.now()}`, 'correct horse battery staple');
  const session = await startSession(h.db, account.id);
  await assert.rejects(
    exchangeToken(h.db, { workload: mcp, subjectToken: session.accessToken, scope: 'devices:read' }),
    (error: any) => error.code === 'UNAUTHENTICATED',
    'a first-party token presented by the MCP adapter'
  );
  const internal = await exchangeToken(h.db, { workload: gateway, subjectToken: session.accessToken, scope: 'devices:read' });
  assert.equal((decodeJwt(internal.token) as any).client_id, 'iot-switch-ios');
});

test('an internal token never outlives the credential it came from', async () => {
  const caller = await mcpCaller();
  await h.db.query(
    `UPDATE oauth_access_tokens SET expires_at = now() + interval '20 seconds' WHERE grant_id = $1`,
    [caller.grantId]
  );
  const { expiresIn } = await exchangeToken(h.db, { workload: mcp, subjectToken: caller.credential, scope: 'devices:read' });
  assert.ok(expiresIn <= 20, `lifetime ${expiresIn}`);
});

test('a revoked grant cannot be exchanged, and its cached internal tokens are dropped', async () => {
  const caller = await mcpCaller();
  const client = new ExchangeClient(h.db, createWorkload('mcp-rs'));
  await client.tokenFor(caller, 'devices:read');
  assert.equal(client.size, 1);

  await revokeGrantNow(h.db, caller.grantId);
  assert.equal(client.size, 0, 'the revocation event emptied the cache');
  await assert.rejects(client.tokenFor(caller, 'devices:read'), (error: any) => error.code === 'UNAUTHENTICATED');
});

test('an internal token is reused while it has time left', async () => {
  const caller = await mcpCaller();
  const client = new ExchangeClient(h.db, createWorkload('mcp-rs'));
  const first = await client.tokenFor(caller, 'devices:read');
  assert.equal(await client.tokenFor(caller, 'devices:read'), first);
  assert.notEqual(await client.tokenFor(caller, 'devices:control'), first, 'one scope never stands in for another');
});

test('a refused internal token is exchanged afresh once', async () => {
  // Simulates a signing-key rotation between minting and use: the cached
  // token is signed by a key the Device Service no longer trusts.
  const caller = await mcpCaller();
  const workload = createWorkload('mcp-rs');
  const client = new ExchangeClient(h.db, workload);
  const devices = createDeviceService(h.db);
  await client.tokenFor(caller, 'devices:read');

  const signing = keys().signingKeys;
  const retired = signing.splice(0, signing.length, newSigningKey());
  try {
    const list = await client.run(caller, 'devices:read', (token, peer) => devices.list(token, peer, 'req_test'));
    assert.deepEqual(list, []);
  } finally {
    signing.splice(0, signing.length, ...retired);
  }
});
