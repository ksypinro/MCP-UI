/**
 * The signed-in account, for the iOS app.
 *
 * Signing in, refreshing and signing out all happen at the authorization
 * server (OAuth, with PAR, PKCE and DPoP); the API only answers who the caller
 * is. It reads through the verifier, so the same route works in one process
 * and at a gateway that holds no database credentials.
 */

import { Router } from 'express';
import type { Infrastructure } from '../stores/index.ts';
import type { TokenVerifier } from '../security/verifier.ts';
import { AppError } from '../errors.ts';
import { authenticate, callerOf } from './middleware.ts';

export function accountRoutes(infra: Infrastructure, verifier: TokenVerifier): Router {
  const router = Router();
  router.get('/v1/me', authenticate(verifier, { required: true, replay: infra.replay }), async (_req, res) => {
    const account = await verifier.account(callerOf(res).accountId);
    if (!account) throw new AppError('UNAUTHENTICATED');
    res.json({ account });
  });
  return router;
}
