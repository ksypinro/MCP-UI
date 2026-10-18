/**
 * The public half of the keys that sign internal tokens.
 *
 * Published so that a Device Service in another process can verify them; in
 * a single process it reads the same keys directly. The current key and any
 * still being retired are listed, so a rotation never strands a token signed
 * a moment before it.
 */

import { Router } from 'express';
import { keys } from '../security/keys.ts';

export function publicJwks(): { keys: Array<Record<string, unknown>> } {
  return {
    keys: keys().signingKeys.map(({ kid, publicJwk }) => ({ ...publicJwk, kid, use: 'sig', alg: 'ES256' }))
  };
}

export const jwksRouter: Router = Router();

jwksRouter.get('/.well-known/jwks.json', (_req, res) => {
  res.set('Cache-Control', 'public, max-age=600').json(publicJwks());
});
