import express from 'express';
import type { Express, RequestHandler } from 'express';
import type { Db } from '../db/index.ts';
import { errorHandler, notFound, withRequestId } from './middleware.ts';
import { authRoutes } from './routes-auth.ts';
import { deviceRoutes } from './routes-devices.ts';
import { oauthRoutes } from '../oauth/routes.ts';
import { mcpRoutes } from '../mcp/routes.ts';
import { MCP_PATH } from '../mcp/config.ts';
import { API_BASE_URL, AUTH_BASE_URL, MCP_BASE_URL, SINGLE_ORIGIN } from '../config.ts';
import { createDeviceService } from '../device-service/service.ts';
import { ExchangeClient } from '../exchange-client.ts';
import { createWorkload } from '../security/workload.ts';
import { WriteBudgets } from '../write-budgets.ts';

/**
 * Mounts `router` only for requests addressed to `baseUrl`'s host.
 *
 * With one origin (local development) every router is mounted as before. With
 * three, the authorization server answers only on its own host, the MCP
 * endpoint only on its own, and so on, so a cookie or page of one can never be
 * reached through another. The Host header is compared as sent; a proxy in
 * front must preserve it.
 */
function onHost(baseUrl: string, router: RequestHandler): RequestHandler {
  if (SINGLE_ORIGIN) return router;
  const host = new URL(baseUrl).host.toLowerCase();
  return (req, res, next) => {
    if ((req.get('host') ?? '').toLowerCase() !== host) return next();
    router(req, res, next);
  };
}

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
  app.use(onHost(AUTH_BASE_URL, oauthRoutes(db)));

  // The MCP endpoint. Its own authorization gate runs inside, on the parsed
  // body, because a refusal there has to be an HTTP status rather than a tool
  // result.
  // The Device Service, and the two adapters that may call it. Each adapter
  // gets its own workload identity: internal tokens are bound to it, so one
  // adapter cannot use a token minted for the other. Write budgets are
  // shared, because they are counted per grant and per device, not per door.
  const devices = createDeviceService(db);
  const budgets = new WriteBudgets();
  const mcpExchange = new ExchangeClient(db, createWorkload('mcp-rs'));
  const apiExchange = new ExchangeClient(db, createWorkload('api-gw'));

  app.use(onHost(MCP_BASE_URL, mcpRoutes({ db, devices, exchange: mcpExchange, budgets })));

  app.use(onHost(API_BASE_URL, authRoutes(db)));
  app.use(onHost(API_BASE_URL, deviceRoutes({ db, devices, exchange: apiExchange, budgets })));

  app.use(notFound());
  app.use(errorHandler({ jsonRpcPaths: [MCP_PATH] }));
  return app;
}
