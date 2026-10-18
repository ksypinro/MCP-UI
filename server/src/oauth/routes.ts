import { Router, type Request, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { rateLimit } from '../http/middleware.ts';
import { metadataRouter } from './metadata.ts';
import { jwksRouter } from './jwks.ts';
import { authorizeRoutes } from './authorize.ts';
import { tokenRoutes } from './token.ts';
import { registerClient } from './clients.ts';
import { revokeByAccessToken, revokeByRefreshToken } from './store.ts';

export function oauthRoutes(db: Db): Router {
  const router = Router();

  router.use(metadataRouter);
  router.use(jwksRouter);

  // Rate limiting is applied per route, not across the board.
  //
  // Submitting credentials is a guessing surface and is limited by address.
  // The token endpoint is not: a host calls it from its own infrastructure on
  // behalf of every one of its users, so an address-keyed limit there would
  // throttle everybody at once the moment the integration became popular.
  //
  // Read here rather than at module load so a test harness can raise it for a
  // whole suite without weakening the default that ships.
  const perMinute = Number(process.env.AUTH_RATE_LIMIT_PER_MINUTE ?? 20);
  const credentialLimiter = rateLimit(perMinute, 60_000);
  router.post('/login', credentialLimiter);
  router.post('/register', credentialLimiter);

  // Showing the authorization page is not a credential submission, but it is
  // reachable without an account, writes a pending authorization, and may
  // fetch a client metadata document. Bounded by address for those reasons.
  const viewsPerMinute = Number(process.env.AUTHORIZE_VIEW_RATE_LIMIT_PER_MINUTE ?? 60);
  router.get('/authorize', rateLimit(viewsPerMinute, 60_000, (req) => `authorize-view:${req.ip ?? 'unknown'}`));
  router.post('/par', rateLimit(viewsPerMinute, 60_000, (req) => `par:${req.ip ?? 'unknown'}`));

  router.use(authorizeRoutes(db));
  router.use(tokenRoutes(db));

  /** RFC 7591 Dynamic Client Registration. Open by design, capped in clients.ts. */
  router.post('/register', async (req: Request, res: Response) => {
    const outcome = await registerClient(db, {
      redirectUris: req.body?.redirect_uris,
      clientName: req.body?.client_name,
      applicationType: req.body?.application_type
    });
    if ('error' in outcome) {
      res.status(400).set('Cache-Control', 'no-store').json({
        error: outcome.error,
        error_description: {
          registration_closed: 'This server is not accepting new client registrations.',
          invalid_redirect_uri: 'Every redirect_uri must be acceptable for the application_type, and at least one is required.',
          invalid_client_metadata: 'application_type must be "web" or "native".'
        }[outcome.error]
      });
      return;
    }

    // Echo what was stored, not what was sent.
    res.status(201).set('Cache-Control', 'no-store').json({
      client_id: outcome.clientId,
      ...(outcome.clientName ? { client_name: outcome.clientName } : {}),
      redirect_uris: outcome.redirectUris,
      application_type: outcome.applicationType,
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
