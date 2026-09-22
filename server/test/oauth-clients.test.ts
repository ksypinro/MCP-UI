/**
 * Client ID Metadata Document resolution.
 *
 * A client_id is a URL chosen by whoever starts an authorization, and this
 * server fetches it. That is a request-forgery primitive unless it is fenced
 * in, so most of what is tested here is what must NOT be fetched.
 */

import test from 'node:test';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import { createDb } from '../src/db/index.ts';
import { pinnedLookup, resolveClient } from '../src/oauth/clients.ts';

test('a client_id that is not a URL and not registered resolves to nothing', async () => {
  const db = await createDb();
  assert.equal(await resolveClient(db, 'client_unknown'), null);
  assert.equal(await resolveClient(db, ''), null);
  assert.equal(await resolveClient(db, undefined), null);
  assert.equal(await resolveClient(db, 42), null);
  await db.close();
});

test('plain HTTP is never fetched as a metadata document', async () => {
  const db = await createDb();
  // CIMD is HTTPS-only. Allowing http would let anyone on the path between us
  // and the document decide which redirect URIs a client is permitted.
  assert.equal(await resolveClient(db, 'http://example.com/cimd.json'), null);
  await db.close();
});

test('a metadata document on a private address is refused', async () => {
  const db = await createDb();

  // Each of these resolves inside the network the server is running in. Left
  // unchecked, a client_id is a way to make this server issue requests
  // against its own infrastructure — cloud metadata at 169.254.169.254 being
  // the usual target.
  for (const clientId of [
    'https://localhost/cimd.json',
    'https://127.0.0.1/cimd.json',
    'https://169.254.169.254/latest/meta-data/',
    'https://10.0.0.1/cimd.json',
    'https://192.168.1.1/cimd.json',
    'https://172.16.0.1/cimd.json',
    'https://[::1]/cimd.json'
  ]) {
    assert.equal(await resolveClient(db, clientId), null, `${clientId} must not be fetched`);
  }

  await db.close();
});

test('an absurdly long client_id is rejected before any lookup', async () => {
  const db = await createDb();
  assert.equal(await resolveClient(db, `https://example.com/${'x'.repeat(4000)}`), null);
  await db.close();
});

test('a redirect URI that would execute script is never registerable', async () => {
  const { isRegisterableRedirectUri } = await import('../src/oauth/clients.ts');

  // An earlier form of this check ended in `protocol !== 'http:'`, which
  // accepted everything that was not plain HTTP. A registered javascript:
  // redirect is a stored XSS payload that this server sends a live
  // authorization code to.
  assert.equal(isRegisterableRedirectUri('javascript:alert(1)'), false);
  assert.equal(isRegisterableRedirectUri('data:text/html,<script>x</script>'), false);
  assert.equal(isRegisterableRedirectUri('file:///etc/passwd'), false);
  assert.equal(isRegisterableRedirectUri('about:blank'), false);

  assert.equal(isRegisterableRedirectUri('https://app.example/callback'), true);
  assert.equal(isRegisterableRedirectUri('http://127.0.0.1:41234/callback'), true);
  assert.equal(isRegisterableRedirectUri('http://example.com/callback'), false, 'cleartext off-host');
  // Native apps legitimately use a reverse-DNS private-use scheme.
  assert.equal(isRegisterableRedirectUri('com.example.app:/oauth'), true);
  assert.equal(isRegisterableRedirectUri('https://app.example/cb#frag'), false);
});


test('pinned DNS supports Node connections with and without family autoselection', async () => {
  const { createServer, createConnection } = await import('node:net');
  const server = createServer(socket => socket.end());
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    for (const autoSelectFamily of [true, false]) {
      const socket = createConnection({
        host: 'metadata.example', port: address.port, autoSelectFamily,
        lookup: pinnedLookup({ address: '127.0.0.1', family: 4 })
      });
      try { await once(socket, 'connect'); }
      finally { socket.destroy(); }
    }
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});
