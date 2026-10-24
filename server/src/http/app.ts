import express, { Router } from 'express';
import type { Express, RequestHandler } from 'express';
import type { Db } from '../db/index.ts';
import { errorHandler, notFound, withRequestId } from './middleware.ts';
import { authRoutes, gatewayAuthRoutes } from './routes-auth.ts';
import { appLinkRoutes } from './app-links.ts';
import { deviceRoutes } from './routes-devices.ts';
import { oauthRoutes } from '../oauth/routes.ts';
import { mcpRoutes } from '../mcp/routes.ts';
import { MCP_PATH } from '../mcp/config.ts';
import { API_BASE_URL, AUTH_BASE_URL, MCP_BASE_URL, SINGLE_ORIGIN } from '../config.ts';
import { createDeviceService, type DeviceService } from '../device-service/service.ts';
import { ExchangeClient } from '../exchange-client.ts';
import { createWorkload } from '../security/workload.ts';
import { WriteBudgets } from '../write-budgets.ts';
import { localVerifier, type TokenVerifier } from '../security/verifier.ts';
import { memoryInfrastructure, type Infrastructure } from '../stores/index.ts';
import { useCimdFetchStore } from '../oauth/clients.ts';

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

/**
 * `infra` holds the counters, proof ids, sealed responses and revocation hub
 * the app shares with other processes. Without it, the app gets its own
 * in-memory set, which is right for one process and for tests.
 */
/** Express with the parts every component shares: request ids, body parsing, health. */
export function baseApp(): Express {
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
  return app;
}

/** The last two handlers every component needs. */
export function finishApp(app: Express): Express {
  app.use(notFound());
  app.use(errorHandler({ jsonRpcPaths: [MCP_PATH] }));
  return app;
}

/** What an edge adapter needs: who the caller is, how to exchange, where the devices are. */
export interface EdgeDeps {
  verifier: TokenVerifier;
  devices: DeviceService;
  exchange: ExchangeClient;
  budgets: WriteBudgets;
  infra: Infrastructure;
}

/** The authorization server: OAuth, the hosted pages, the account pages, JWKS. */
export function authServerRouter(db: Db, infra: Infrastructure): RequestHandler {
  if (infra.kind === 'redis') useCimdFetchStore(infra.buckets);
  return oauthRoutes(db, infra);
}

/** The REST API gateway. With `db` it also serves the legacy password endpoints. */
export function apiRouter(deps: EdgeDeps, db: Db | null): Router {
  const router = Router();
  router.use(appLinkRoutes());
  router.use(db ? authRoutes(db, deps.infra, deps.verifier) : gatewayAuthRoutes(deps.infra, deps.verifier));
  router.use(deviceRoutes(deps));
  return router;
}

/**
 * Everything in one process (profile S): the authorization server, the MCP
 * endpoint, the REST API and the Device Service, each still behind its own
 * host when the three origins differ.
 *
 * `infra` holds the counters, proof ids, sealed responses and revocation hub
 * the app shares with other processes. Without it, the app gets its own
 * in-memory set, which is right for one process and for tests.
 */
export function createApp(db: Db, infra: Infrastructure = memoryInfrastructure()): Express {
  const app = baseApp();

  // The authorization server. Mounted at the root because its discovery
  // documents live at well-known paths that cannot be moved.
  app.use(onHost(AUTH_BASE_URL, authServerRouter(db, infra)));

  // The Device Service, and the two adapters that may call it. Each adapter
  // gets its own workload identity: internal tokens are bound to it, so one
  // adapter cannot use a token minted for the other. Write budgets are
  // shared, because they are counted per grant and per device, not per door.
  const verifier = localVerifier(db);
  const devices = createDeviceService(db);
  const budgets = new WriteBudgets(infra.buckets);
  const mcpExchange = ExchangeClient.local(db, createWorkload('mcp-rs'), infra.revocations);
  const apiExchange = ExchangeClient.local(db, createWorkload('api-gw'), infra.revocations);

  // The MCP endpoint. Its own authorization gate runs inside, on the parsed
  // body, because a refusal there has to be an HTTP status rather than a tool
  // result.
  app.use(onHost(MCP_BASE_URL, mcpRoutes({ verifier, devices, exchange: mcpExchange, budgets, infra })));
  app.use(onHost(API_BASE_URL, apiRouter({ verifier, devices, exchange: apiExchange, budgets, infra }, db)));

  return finishApp(app);
}
