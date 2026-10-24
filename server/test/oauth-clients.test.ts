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
import { knownClients, pinnedLookup, resolveClient } from '../src/oauth/clients.ts';

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

  // A check ending in `protocol !== 'http:'` would accept everything that is
  // not plain HTTP. A registered javascript:
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

/* ------------------------------------------------- SSRF and CIMD hardening */

import { isForbiddenAddress, type CimdFetcher } from '../src/oauth/clients.ts';

test('only ordinary public unicast addresses may be fetched', () => {
  // Every IPv6 form that embeds an IPv4 address is refused too, so the cloud
  // metadata endpoint cannot be reached by spelling it differently. The old
  // hand-written check missed NAT64 and most of fe80::/10.
  for (const address of [
    '169.254.169.254', '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1',
    '2001::1', 'fe90::1', 'fc00::1', '100.64.0.1', '198.18.0.1', '192.0.2.1', '224.0.0.1',
    '0.0.0.0', '127.0.0.1', '::1', 'not an address'
  ]) {
    assert.equal(isForbiddenAddress(address), true, `${address} must be refused`);
  }
  for (const address of ['8.8.8.8', '2606:4700::1']) {
    assert.equal(isForbiddenAddress(address), false, `${address} is public`);
  }
});

function documentFetcher(document: unknown, options: { cacheControl?: string } = {}) {
  let calls = 0;
  const fetcher: CimdFetcher = async () => {
    calls++;
    return { status: 200, cacheControl: options.cacheControl ?? null, body: typeof document === 'string' ? document : JSON.stringify(document) };
  };
  return { fetcher, calls: () => calls };
}

test('a metadata document is resolved, cached, and reused without a second fetch', async () => {
  const db = await createDb();
  const clientId = 'https://client.example/cimd.json';
  const { fetcher, calls } = documentFetcher({ client_id: clientId, redirect_uris: ['https://client.example/cb'] });

  const first = await resolveClient(db, clientId, { fetcher });
  assert.equal(first?.kind, 'cimd');
  assert.equal(first?.displayHost, 'client.example');
  assert.equal(first?.trust, 'unverified');
  assert.match(first?.documentDigest ?? '', /^[0-9a-f]{64}$/);

  const second = await resolveClient(db, clientId, { fetcher });
  assert.deepEqual(second, first);
  assert.equal(calls(), 1, 'the cached document was used');
  await db.close();
});

test('a document that does not name itself, or is too large, is refused', async () => {
  const db = await createDb();
  const clientId = 'https://client.example/other.json';

  const impostor = documentFetcher({ client_id: 'https://someone.else/cimd.json', redirect_uris: ['https://client.example/cb'] });
  assert.equal(await resolveClient(db, clientId, { fetcher: impostor.fetcher }), null);

  // CIMD draft -02: about 5 KB is plenty for a real document.
  const padded = documentFetcher({ client_id: clientId, redirect_uris: ['https://client.example/cb'], padding: 'x'.repeat(6000) });
  assert.equal(await resolveClient(db, clientId, { fetcher: padded.fetcher }), null);
  await db.close();
});

test('a client on the known list is verified, everyone else is not', async () => {
  const db = await createDb();
  const clientId = 'https://chatgpt.com/oauth/client.json';
  const { fetcher } = documentFetcher({ client_id: clientId, redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'] });
  assert.equal((await resolveClient(db, clientId, { fetcher }))?.trust, 'verified');
  await db.close();
});

test('dynamic registration refuses anything it cannot accept in full', async () => {
  const { registerClient } = await import('../src/oauth/clients.ts');
  const db = await createDb();

  assert.deepEqual(
    await registerClient(db, { redirectUris: ['https://a.example/cb'], clientName: 'A', applicationType: undefined }),
    { error: 'invalid_client_metadata' },
    'application_type is required by MCP 2026-07-28'
  );
  assert.deepEqual(
    await registerClient(db, {
      redirectUris: ['https://a.example/cb', 'javascript:alert(1)'], clientName: 'A', applicationType: 'web'
    }),
    { error: 'invalid_redirect_uri' },
    'one bad URI refuses the whole registration instead of being dropped'
  );
  assert.deepEqual(
    await registerClient(db, { redirectUris: ['http://127.0.0.1:9/cb'], clientName: 'A', applicationType: 'web' }),
    { error: 'invalid_redirect_uri' },
    'a web client may not use a loopback callback'
  );

  const ok = await registerClient(db, {
    redirectUris: ['http://127.0.0.1:9/cb'], clientName: 'Native\u0007 App\n', applicationType: 'native'
  });
  assert.ok('clientId' in ok);
  assert.equal(ok.clientName, 'Native App', 'control characters are stripped');

  const resolved = await resolveClient(db, ok.clientId);
  assert.equal(resolved?.kind, 'dcr');
  assert.equal(resolved?.trust, 'unverified');
  await db.close();
});

test('Claude and ChatGPT are known by the client_ids they presented in host verification', () => {
  const saved = process.env.KNOWN_CLIENTS;
  delete process.env.KNOWN_CLIENTS;
  try {
    const known = knownClients();
    assert.ok(known.has('https://claude.ai/oauth/mcp-oauth-client-metadata'));
    assert.ok(known.has('https://chatgpt.com/oauth/client.json'));
    assert.equal(known.size, 2);
  } finally {
    if (saved !== undefined) process.env.KNOWN_CLIENTS = saved;
  }
});
