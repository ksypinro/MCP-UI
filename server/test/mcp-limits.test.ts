/**
 * Endpoint limits. Each test gets its own server, because exhausting a budget
 * here would poison every anonymous call in a shared harness.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer } from './oauth-helpers.ts';
import { callTool, rpc, tokenFor } from './mcp-helpers.ts';

test('anonymous traffic to the endpoint is bounded', async () => {
  const h = await startServer();
  try {
    // Discovery must work without a token so a host can find the server before
    // anyone signs in — which makes it the one part of this endpoint reachable
    // without an account, and each request builds a server and compiles five
    // schemas.
    let limited = false;
    for (let attempt = 0; attempt < 80 && !limited; attempt++) {
      const response = await rpc(h.base, { jsonrpc: '2.0', id: attempt, method: 'tools/list' });
      if (response.status === 429) limited = true;
    }
    assert.ok(limited, 'anonymous discovery must not be unbounded');
  } finally {
    await h.close();
  }
});

test('random bearer tokens cannot escape the address bucket', async () => {
  // The bucket used to be chosen from the bearer header before the token was
  // verified, so a fresh random string bought a fresh, empty bucket: seventy
  // requests, zero refusals.
  const h = await startServer();
  try {
    let limited = 0;
    for (let attempt = 0; attempt < 70; attempt++) {
      const response = await rpc(
        h.base, { jsonrpc: '2.0', id: attempt, method: 'tools/list' }, `junk-${attempt}`
      );
      if (response.status === 429) limited++;
    }
    assert.ok(limited > 0, 'unverified tokens must count against the address');
  } finally {
    await h.close();
  }
});

test('a verified grant is not throttled by its address', async () => {
  // A host calls from shared egress addresses on behalf of all of its users.
  // Exhausting the address bucket must not lock out a signed-in grant.
  const h = await startServer();
  try {
    const { accessToken } = await tokenFor(h);
    for (let attempt = 0; attempt < 70; attempt++) {
      await rpc(h.base, { jsonrpc: '2.0', id: attempt, method: 'tools/list' });
    }
    const anonymous = await rpc(h.base, { jsonrpc: '2.0', id: 999, method: 'tools/list' });
    assert.equal(anonymous.status, 429, 'precondition: the address bucket is spent');

    const signedIn = await callTool(h.base, 'list_devices', {}, accessToken);
    assert.equal(signedIn.status, 200);
  } finally {
    await h.close();
  }
});
