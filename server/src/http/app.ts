import express from 'express';
import type { Express } from 'express';
import type { Db } from '../db/index.ts';
import { errorHandler, notFound, withRequestId } from './middleware.ts';
import { authRoutes } from './routes-auth.ts';
import { deviceRoutes } from './routes-devices.ts';
import { oauthRoutes } from '../oauth/routes.ts';

export function createApp(db: Db): Express {
  const app = express();
  app.disable('x-powered-by');
  // Off unless deployed behind a proxy we control. Trusting X-Forwarded-For
  // unconditionally would let any client forge req.ip and walk around the
  // rate limit on the auth endpoints one fake address at a time.
  if (process.env.TRUST_PROXY) app.set('trust proxy', process.env.TRUST_PROXY);

  app.use(withRequestId());
  app.use(express.json({ limit: '64kb' }));
  // The hosted authorization page posts a form, and the OAuth token,
  // registration and revocation endpoints are specified as
  // application/x-www-form-urlencoded. Without this their bodies arrive
  // unparsed and every one of them fails as a malformed request.
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

  // The authorization server. Mounted at the root because its discovery
  // documents live at well-known paths that cannot be moved.
  app.use(oauthRoutes(db));

  app.use(authRoutes(db));
  app.use(deviceRoutes(db));

  app.use(notFound());
  app.use(errorHandler());
  return app;
}
