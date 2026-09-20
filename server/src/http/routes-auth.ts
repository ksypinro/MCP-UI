/** The authentication endpoints from spec section 7.1. */

import { Router } from 'express';
import type { Db } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { createAccount, getAccount, verifyCredentials } from '../domain/accounts.ts';
import { refreshSession, revokeSession, startSession } from '../domain/sessions.ts';
import { authenticate, context, identityOf, rateLimit } from './middleware.ts';

export function authRoutes(db: Db): Router {
  const router = Router();

  // Spec section 7.2. Generous enough not to bite a real user retyping a
  // password, tight enough that the endpoint is not a credential oracle.
  const limiter = rateLimit(10, 60_000);

  router.post('/v1/auth/signup', limiter, async (req, res) => {
    const body = req.body as { username?: unknown; password?: unknown } | undefined;
    const account = await createAccount(db, body?.username, body?.password);
    const tokens = await startSession(db, account.id);
    res.status(201).json({ account, ...tokens });
  });

  router.post('/v1/auth/login', limiter, async (req, res) => {
    const body = req.body as { username?: unknown; password?: unknown } | undefined;
    const account = await verifyCredentials(db, body?.username, body?.password);
    // One generic failure for both an unknown username and a wrong password.
    if (!account) throw new AppError('UNAUTHENTICATED');
    const tokens = await startSession(db, account.id);
    res.json({ account, ...tokens });
  });

  router.get('/v1/auth/me', authenticate(db, { required: true }), async (_req, res) => {
    const account = await getAccount(db, identityOf(res).accountId);
    if (!account) throw new AppError('UNAUTHENTICATED');
    res.json({ account });
  });

  router.post('/v1/auth/refresh', limiter, async (req, res) => {
    const body = req.body as { refreshToken?: unknown } | undefined;
    res.json(await refreshSession(db, body?.refreshToken));
  });

  router.post('/v1/auth/logout', authenticate(db, { required: true }), async (_req, res) => {
    const sessionId = context(res).sessionId;
    if (sessionId) await revokeSession(db, sessionId);
    res.status(204).end();
  });

  return router;
}
