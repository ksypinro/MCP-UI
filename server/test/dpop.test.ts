/**
 * DPoP proof verification (RFC 9449), each refusal on its own. Plan 3.1.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { exportJWK, generateKeyPair } from 'jose';
import { DpopError, normalizeHtu, verifyDpopProof } from '../src/oauth/dpop.ts';
import { DpopKey } from './dpop-helpers.ts';
import { MemoryReplayStore } from '../src/security/replay.ts';

const replay = new MemoryReplayStore();

const HTU = 'https://api.iot.example/v1/devices';

async function refusedWith(promise: Promise<unknown>, code: DpopError['code']): Promise<void> {
  await assert.rejects(promise, (error: unknown) => error instanceof DpopError && error.code === code);
}

test('a valid proof yields its key thumbprint', async () => {
  const key = await DpopKey.create();
  const { jkt } = await verifyDpopProof(await key.proof({ htm: 'GET', htu: HTU, accessToken: 'tok' }), {
    htm: 'GET', htu: HTU, accessToken: 'tok', expectedJkt: key.jkt, replay
  });
  assert.equal(jkt, key.jkt);
});

test('a proof is refused unless every claim matches this request', async () => {
  const key = await DpopKey.create();
  const check = { htm: 'GET', htu: HTU, accessToken: 'tok', replay };
  const cases: Array<[string, Promise<string>]> = [
    ['another method', key.proof({ htm: 'POST', htu: HTU, accessToken: 'tok' })],
    ['another URL', key.proof({ htm: 'GET', htu: 'https://api.iot.example/v1/other', accessToken: 'tok' })],
    ['another token', key.proof({ htm: 'GET', htu: HTU, accessToken: 'different' })],
    ['no token hash', key.proof({ htm: 'GET', htu: HTU })],
    ['a stale iat', key.proof({ htm: 'GET', htu: HTU, accessToken: 'tok', iat: Math.floor(Date.now() / 1000) - 600 })],
    ['the wrong typ', key.proof({ htm: 'GET', htu: HTU, accessToken: 'tok', typ: 'JWT' })]
  ];
  for (const [label, proof] of cases) {
    await assert.rejects(verifyDpopProof(await proof, check), DpopError, label);
  }
  await assert.rejects(verifyDpopProof(undefined, check), DpopError, 'no proof at all');
  await assert.rejects(verifyDpopProof('not.a.jwt', check), DpopError, 'garbage');
});

test('the query string does not count, but the path does', async () => {
  const key = await DpopKey.create();
  const proof = await key.proof({ htm: 'GET', htu: `${HTU}?page=2` });
  await verifyDpopProof(proof, { htm: 'GET', htu: HTU, replay });
  assert.equal(normalizeHtu('HTTPS://API.iot.example:443/v1/Devices?x=1#y'), 'https://api.iot.example/v1/Devices');
});

test('a proof from another key is refused for a bound token', async () => {
  const key = await DpopKey.create();
  const other = await DpopKey.create();
  await refusedWith(
    verifyDpopProof(await other.proof({ htm: 'GET', htu: HTU }), { htm: 'GET', htu: HTU, expectedJkt: key.jkt, replay }),
    'invalid_dpop_proof'
  );
});

test('a proof without the server nonce asks for it', async () => {
  const key = await DpopKey.create();
  await refusedWith(verifyDpopProof(await key.proof({ htm: 'GET', htu: HTU, nonce: null }), { htm: 'GET', htu: HTU, replay }), 'use_dpop_nonce');
  await refusedWith(verifyDpopProof(await key.proof({ htm: 'GET', htu: HTU, nonce: 'made-up' }), { htm: 'GET', htu: HTU, replay }), 'use_dpop_nonce');
});

test('a proof cannot be replayed', async () => {
  const key = await DpopKey.create();
  const proof = await key.proof({ htm: 'GET', htu: HTU });
  await verifyDpopProof(proof, { htm: 'GET', htu: HTU, replay });
  await refusedWith(verifyDpopProof(proof, { htm: 'GET', htu: HTU, replay }), 'invalid_dpop_proof');
});

test('a proof carrying its private key is refused', async () => {
  const key = await DpopKey.create();
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const leaked = await exportJWK(privateKey);
  await refusedWith(
    verifyDpopProof(await key.proof({ htm: 'GET', htu: HTU, jwk: leaked }), { htm: 'GET', htu: HTU, replay }),
    'invalid_dpop_proof'
  );
});
