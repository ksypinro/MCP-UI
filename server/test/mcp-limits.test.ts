/**
 * Endpoint limits. Its own server, because exhausting a budget here would
 * poison every anonymous call in a shared harness.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, type Harness } from './oauth-helpers.ts';
import { rpc } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

test('anonymous traffic to the endpoint is bounded', async () => {
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
});
