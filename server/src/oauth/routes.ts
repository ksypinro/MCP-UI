import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { rateLimit } from '../http/middleware.ts';
import { metadataRouter } from './metadata.ts';
import { authorizeRoutes } from './authorize.ts';
import { tokenRoutes } from './token.ts';
import { registerClient } from './clients.ts';
import { revokeByAccessToken, revokeByRefreshToken } from './store.ts';

export function oauthRoutes(db: Db): Router {
  const router = Router();

  router.use(metadataRouter);

  // Rate limiting is applied per route, not across the board.
  //
  // Submitting credentials is a guessing surface and is limited by address.
  // The token endpoint is not: a host calls it from its own infrastructure on
  // behalf of every one of its users, so an address-keyed limit there would
  // throttle everybody at once the moment the integration became popular.
  const credentialLimiter = rateLimit(20, 60_000);
  router.post('/authorize', credentialLimiter);
  router.post('/register', credentialLimiter);

  router.use(authorizeRoutes(db));
  router.use(tokenRoutes(db));

  /** RFC 7591 Dynamic Client Registration. Open by design, capped in clients.ts. */
  router.post('/register', async (req: Request, res: Response) => {
    const redirectUris = Array.isArray(req.body?.redirect_uris)
      ? (req.body.redirect_uris as unknown[]).filter((uri): uri is string => typeof uri === 'string')
      : [];
    const clientName = typeof req.body?.client_name === 'string' ? req.body.client_name : undefined;

    const outcome = await registerClient(db, redirectUris, clientName);
    if ('error' in outcome) {
      res.status(400).json({
        error: outcome.error,
        error_description: outcome.error === 'registration_closed'
          ? 'This server is not accepting new client registrations.'
          : 'At least one valid redirect_uri is required.'
      });
      return;
    }

    res.status(201).set('Cache-Control', 'no-store').json({
      client_id: outcome.clientId,
      ...(clientName ? { client_name: clientName } : {}),
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code']
    });
  });

  /** RFC 7009. Always 200, even for a token we have never seen. */
  router.post('/revoke', async (req: Request, res: Response) => {
    const token = req.body?.token;
    if (typeof token === 'string' && token.length > 0) {
      const hint = req.body?.token_type_hint;
      if (hint === 'access_token') {
        await revokeByAccessToken(db, token);
      } else if (hint === 'refresh_token') {
        await revokeByRefreshToken(db, token);
      } else {
        // No usable hint: it is one or the other, and revoking a grant is
        // idempotent, so try both rather than guess.
        await revokeByRefreshToken(db, token);
        await revokeByAccessToken(db, token);
      }
    }
    res.status(200).set('Cache-Control', 'no-store').end();
  });

  return router;
}
