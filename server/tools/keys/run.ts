/**
 * Key rotation for KMS-held key material. Plan 4.3.
 *
 *   npm run keys -- rotate-pepper     every 90 days
 *   npm run keys -- rotate-signing    every 30 days
 *
 * Reads KMS_PROVIDER, LOCAL_KMS_FILE and KMS_KEY_FILE as the server does.
 * Restart the server (or every process) afterwards to pick the new key up;
 * the previous one keeps verifying meanwhile.
 */

import { join } from 'node:path';
import { DATABASE_PATH } from '../../src/config.ts';
import { kmsFromEnvironment, rotateSigningKey, rotateTokenPepper } from '../../src/security/kms.ts';

const kms = kmsFromEnvironment(join(DATABASE_PATH, 'local-kms.json'));
if (!kms) {
  process.stderr.write('Set KMS_PROVIDER. Rotation here is for KMS-held keys; a plain key file rotates by editing TOKEN_PEPPERS.\n');
  process.exit(2);
}
const file = process.env.KMS_KEY_FILE ?? join(DATABASE_PATH, 'keys.kms.json');

switch (process.argv[2]) {
  case 'rotate-pepper':
    process.stdout.write(`token pepper v${await rotateTokenPepper(kms, file)} is now current\n`);
    break;
  case 'rotate-signing':
    process.stdout.write(`signing key ${await rotateSigningKey(kms, file)} is now current\n`);
    break;
  default:
    process.stderr.write('usage: npm run keys -- rotate-pepper | rotate-signing\n');
    process.exit(2);
}
