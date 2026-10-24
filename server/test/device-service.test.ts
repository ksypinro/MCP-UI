/**
 * The Device Service accepts nothing but a valid internal token from the
 * workload it names. Plan 2.4, architecture section 8.7.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SignJWT, importJWK } from 'jose';
import { createDb, type Db } from '../src/db/index.ts';
import { createAccount } from '../src/domain/accounts.ts';
import { createDeviceService } from '../src/device-service/service.ts';
import { InternalTokenRefused } from '../src/device-service/verify.ts';
import { INTERNAL_AUDIENCE } from '../src/oauth/exchange.ts';
import { ISSUER } from '../src/oauth/config.ts';
import { keys } from '../src/security/keys.ts';
import { createWorkload, workloadUri, type Workload } from '../src/security/workload.ts';

let db: Db;
let accountId: string;
const mcp = createWorkload('mcp-rs');
const gateway = createWorkload('api-gw');

before(async () => {
  db = await createDb();
  accountId = (await createAccount(db, 'service-user', 'correct horse battery staple')).id;
});
after(async () => { await db.close(); });

async function internalToken(overrides: {
  workload?: Workload; scope?: string; audience?: string; typ?: string; issuer?: string; expiresIn?: number;
} = {}): Promise<string> {
  const [signing] = keys().signingKeys;
  const key = await importJWK(signing!.privateJwk as never, 'ES256');
  const workload = overrides.workload ?? mcp;
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    client_id: 'client_test', grant_id: 'grant_test', scope: overrides.scope ?? 'devices:read',
    channel: 'mcp', auth_method: 'oauth', act: { sub: workloadUri(workload) }, cnf: workload.cnf
  })
    .setProtectedHeader({ alg: 'ES256', typ: overrides.typ ?? 'at+jwt', kid: signing!.kid })
    .setIssuer(overrides.issuer ?? ISSUER)
    .setAudience(overrides.audience ?? INTERNAL_AUDIENCE)
    .setSubject(accountId)
    .setIssuedAt(now)
    .setExpirationTime(now + (overrides.expiresIn ?? 60))
    .setJti('tb_test')
    .sign(key);
}

const refused = (error: unknown) => error instanceof InternalTokenRefused;

test('a valid internal token reaches the device rules as its subject', async () => {
  const service = createDeviceService(db);
  assert.deepEqual(await service.list(await internalToken(), mcp, 'req_1'), []);
});

test('every malformed or misdirected internal token is refused', async () => {
  const service = createDeviceService(db);
  const cases: Array<[string, Promise<string>, Workload]> = [
    ['another audience', internalToken({ audience: 'https://mcp.iot.example/mcp' }), mcp],
    ['another issuer', internalToken({ issuer: 'https://attacker.example' }), mcp],
    ['an ID token typ', internalToken({ typ: 'JWT' }), mcp],
    ['expired', internalToken({ expiresIn: -120 }), mcp],
    ['the wrong scope', internalToken({ scope: 'devices:control' }), mcp],
    ['presented by the other workload', internalToken({ workload: mcp }), gateway],
    ['bound to the other workload', internalToken({ workload: gateway }), mcp]
  ];
  for (const [label, token, peer] of cases) {
    await assert.rejects(service.list(await token, peer, 'req_1'), refused, label);
  }
});

test('alg none and HMAC key confusion never verify', async () => {
  const service = createDeviceService(db);
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: ISSUER, aud: INTERNAL_AUDIENCE, sub: accountId, iat: now, exp: now + 60, jti: 'x',
    scope: 'devices:read', client_id: 'c', grant_id: 'g', channel: 'mcp',
    act: { sub: workloadUri(mcp) }, cnf: mcp.cnf
  };

  const none = `${b64({ alg: 'none', typ: 'at+jwt' })}.${b64(claims)}.`;
  await assert.rejects(service.list(none, mcp, 'req_1'), refused, 'alg none');

  // Signing with the *public* key as an HMAC secret: the classic confusion.
  const publicKey = JSON.stringify(keys().signingKeys[0]!.publicJwk);
  const input = `${b64({ alg: 'HS256', typ: 'at+jwt', kid: keys().signingKeys[0]!.kid })}.${b64(claims)}`;
  const forged = `${input}.${createHmac('sha256', publicKey).update(input).digest('base64url')}`;
  await assert.rejects(service.list(forged, mcp, 'req_1'), refused, 'HS256 with the public key');
});

test('no adapter reaches the device rules except through the Device Service', () => {
  // The structural guarantee behind all of the above: if an adapter imported
  // the domain module directly, it could skip the internal token entirely.
  const src = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');
  for (const directory of ['mcp', 'http']) {
    for (const file of readdirSync(join(src, directory)).filter((name) => name.endsWith('.ts'))) {
      const text = readFileSync(join(src, directory, file), 'utf8');
      assert.doesNotMatch(text, /domain\/devices\.ts/, `${directory}/${file} imports the device rules directly`);
    }
  }
});
