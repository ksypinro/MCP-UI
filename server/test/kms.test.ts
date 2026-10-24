/**
 * Key material through a KMS. Plan 4.3.
 *
 * Runs against LocalKms, the software KMS: the contract a cloud adapter must
 * meet once gate G4 picks one. This file installs its own key material for
 * the whole process, which is safe because node runs each test file in a
 * process of its own.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeProtectedHeader } from 'jose';
import { LocalKms, kmsFromEnvironment, openEnvelope, rotateSigningKey, rotateTokenPepper } from '../src/security/kms.ts';
import { keys, useKeyMaterial } from '../src/security/keys.ts';
import { exchangeToken } from '../src/oauth/exchange.ts';
import { verifyInternalToken } from '../src/device-service/verify.ts';
import { verifyOAuthAccessToken } from '../src/oauth/verify.ts';
import { publicJwks } from '../src/oauth/jwks.ts';
import { createWorkload } from '../src/security/workload.ts';
import { tokenDigest } from '../src/tokens/hash.ts';
import { startServer, type Harness } from './oauth-helpers.ts';
import { tokenFor } from './mcp-helpers.ts';

let dir: string;
let kms: LocalKms;
let envelope: string;
let h: Harness;

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'iotsw-kms-'));
  kms = new LocalKms(join(dir, 'local-kms.json'));
  envelope = join(dir, 'keys.kms.json');
  useKeyMaterial(await openEnvelope(kms, envelope));
  h = await startServer();
});

after(async () => {
  await h.close();
  await rm(dir, { recursive: true, force: true });
});

test('the key file holds only ciphertext and KMS key ids', async () => {
  const file = await readFile(envelope, 'utf8');
  const material = keys();
  for (const secret of [material.tokenPeppers[0]!.key, material.passwordPepper.key, material.internalMacKey]) {
    assert.ok(!file.includes(secret.toString('base64')), 'a secret appears in the clear');
    assert.ok(!file.includes(secret.toString('hex')), 'a secret appears in the clear');
  }
  assert.ok(!/"d"\s*:/.test(file), 'no private key component');
  assert.equal(material.signingKeys[0]!.privateJwk, undefined, 'the signing key stays in the KMS');
});

test('internal tokens signed inside the KMS verify against the published key', async () => {
  const workload = createWorkload('mcp-rs');
  const { accessToken } = await tokenFor(h);
  const { token } = await exchangeToken(h.db, { workload, subjectToken: accessToken, scope: 'devices:read' });
  assert.equal(decodeProtectedHeader(token).kid, keys().signingKeys[0]!.kid);
  const identity = await verifyInternalToken(token, workload, 'devices:read', 'req_test');
  assert.ok(identity.accountId);
});

test('start-up fails closed on a tampered file, another KMS, or a missing key', async () => {
  const original = await readFile(envelope, 'utf8');
  try {
    const parsed = JSON.parse(original);
    const flipped = Buffer.from(parsed.internalMacKey, 'base64');
    flipped[flipped.length - 1]! ^= 1;
    await writeFile(envelope, JSON.stringify({ ...parsed, internalMacKey: flipped.toString('base64') }));
    await assert.rejects(openEnvelope(kms, envelope), 'a tampered key does not open');

    await writeFile(envelope, original);
    const stranger = new LocalKms(join(dir, 'another-kms.json'));
    await assert.rejects(openEnvelope(stranger, envelope), "another KMS's key-encryption key does not open it");

    await writeFile(envelope, JSON.stringify({ ...parsed, signingKeyIds: ['local-gone'] }));
    await assert.rejects(openEnvelope(kms, envelope), /no key local-gone/);
  } finally {
    await writeFile(envelope, original);
  }
});

test('a provider without an adapter is refused by name', () => {
  process.env.KMS_PROVIDER = 'aws';
  try {
    assert.throws(() => kmsFromEnvironment(join(dir, 'x.json')), /gate G4/);
  } finally {
    delete process.env.KMS_PROVIDER;
  }
});

test('rotating the pepper keeps tokens from before it working', async () => {
  const { accessToken } = await tokenFor(h);
  const before = tokenDigest(accessToken);

  assert.equal(await rotateTokenPepper(kms, envelope), 2);
  useKeyMaterial(await openEnvelope(kms, envelope));

  assert.deepEqual(keys().tokenPeppers.map((pepper) => pepper.version), [2, 1]);
  assert.notEqual(tokenDigest(accessToken), before, 'new tokens are stored under the new pepper');
  assert.ok((await verifyOAuthAccessToken(h.db, accessToken)).ok, 'the old token still verifies');

  await rotateTokenPepper(kms, envelope);
  useKeyMaterial(await openEnvelope(kms, envelope));
  assert.deepEqual(keys().tokenPeppers.map((pepper) => pepper.version), [3, 2], 'two generations, no more');
});

test('rotating the signing key keeps the previous one published', async () => {
  const workload = createWorkload('mcp-rs');
  const { accessToken } = await tokenFor(h);
  const { token: signedBefore } = await exchangeToken(h.db, { workload, subjectToken: accessToken, scope: 'devices:read' });
  const previousKid = keys().signingKeys[0]!.kid;

  await rotateSigningKey(kms, envelope);
  useKeyMaterial(await openEnvelope(kms, envelope));

  const published = publicJwks().keys.map((key) => key.kid);
  assert.equal(published.length, 2);
  assert.ok(published.includes(previousKid));
  await verifyInternalToken(signedBefore, workload, 'devices:read', 'req_test');

  const { token: signedAfter } = await exchangeToken(h.db, { workload, subjectToken: accessToken, scope: 'devices:read' });
  assert.notEqual(decodeProtectedHeader(signedAfter).kid, previousKid);
});
