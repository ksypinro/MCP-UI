/**
 * The internal, mTLS-only listeners of profile M.
 *
 * - The authorization server's: `/introspect`, so the edge processes can
 *   verify callers without database credentials, and `/token-exchange`,
 *   which mints internal tokens bound to the certificate the asking workload
 *   presented (cnf x5t#S256).
 * - The Device Service's: the four operations, each needing an internal token
 *   bound to the certificate on this very connection.
 *
 * Neither is reachable from the internet, and neither trusts an address: the
 * peer is whatever its certificate says, and must be on the allowlist.
 */

import express, { type Express, type NextFunction, type Request, type Response } from 'express';
import type { TLSSocket } from 'node:tls';
import type { Db } from '../db/index.ts';
import { AppError, isAppError } from '../errors.ts';
import { exchangeToken } from '../oauth/exchange.ts';
import { verifyOAuthAccessToken } from '../oauth/verify.ts';
import { getAccount } from '../domain/accounts.ts';
import { API_RESOURCE, RESOURCE_URI, SCOPES, type Scope } from '../oauth/config.ts';
import { createDeviceService } from '../device-service/service.ts';
import { InternalTokenRefused } from '../device-service/verify.ts';
import type { Workload, WorkloadName } from '../security/workload.ts';
import { peerWorkload } from './tls.ts';
import { log } from '../observability/log.ts';

const EDGES: readonly WorkloadName[] = ['mcp-rs', 'api-gw'];

/** Which token audience each edge may ask about: its own, and nothing else. */
const AUDIENCE_OF: Record<WorkloadName, string> = { 'mcp-rs': RESOURCE_URI, 'api-gw': API_RESOURCE };

function internalApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));
  return app;
}

function requirePeer(allowed: readonly WorkloadName[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const peer = peerWorkload(req.socket as TLSSocket, allowed);
    if (!peer) {
      log('warn', 'internal_peer_refused', { path: req.path });
      res.status(403).json({ error: 'peer_not_allowed' });
      return;
    }
    res.locals.peer = peer;
    next();
  };
}

function internalErrors(error: unknown, _req: Request, res: Response, _next: NextFunction): void {
  if (error instanceof InternalTokenRefused) {
    res.status(401).json({ error: 'internal_token_refused' });
    return;
  }
  if (isAppError(error)) {
    res.status(error.status).json({ error: { code: error.code, message: error.message, field: error.field } });
    return;
  }
  log('error', 'internal_error', { error: error instanceof Error ? error : String(error) });
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Unexpected error.' } });
}

/** The authorization server's internal listener. */
export function internalAuthApp(db: Db): Express {
  const app = internalApp();
  app.use(requirePeer(EDGES));

  app.post('/introspect', async (req: Request, res: Response) => {
    const peer = res.locals.peer as Workload;
    const token = typeof req.body?.token === 'string' ? req.body.token : null;
    const verified = await verifyOAuthAccessToken(db, token, [], { audience: AUDIENCE_OF[peer.name] });
    if (!verified.ok) return void res.json({ active: false });
    res.json({
      active: true, kind: 'oauth', accountId: verified.accountId, clientId: verified.clientId,
      grantId: verified.grantId, scopes: verified.scopes, expiresIn: verified.expiresIn, cnfJkt: verified.cnfJkt
    });
  });

  app.post('/account', async (req: Request, res: Response) => {
    const account = typeof req.body?.accountId === 'string' ? await getAccount(db, req.body.accountId) : null;
    res.json({ account });
  });

  app.post('/token-exchange', async (req: Request, res: Response) => {
    const peer = res.locals.peer as Workload;
    const scope = req.body?.scope;
    if (typeof req.body?.subject_token !== 'string' || !SCOPES.includes(scope)) {
      throw new AppError('MALFORMED_REQUEST');
    }
    // The internal token is bound to the certificate this request came over.
    const exchanged = await exchangeToken(db, { workload: peer, subjectToken: req.body.subject_token, scope: scope as Scope });
    res.json({ access_token: exchanged.token, expires_in: exchanged.expiresIn, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' });
  });

  app.use(internalErrors);
  return app;
}

/** The Device Service's listener. */
export function deviceServiceApp(db: Db): Express {
  const app = internalApp();
  const service = createDeviceService(db);
  app.use(requirePeer(EDGES));

  const tokenOf = (req: Request): string => {
    const match = /^Bearer (.+)$/.exec(req.get('authorization') ?? '');
    if (!match) throw new InternalTokenRefused('no token');
    return match[1]!;
  };
  const requestIdOf = (req: Request): string =>
    typeof req.body?.requestId === 'string' ? req.body.requestId.slice(0, 64) : 'req_internal';

  app.post('/devices/list', async (req, res) => {
    res.json({ devices: await service.list(tokenOf(req), res.locals.peer, requestIdOf(req)) });
  });
  app.post('/devices/get', async (req, res) => {
    res.json({ device: await service.get(tokenOf(req), res.locals.peer, requestIdOf(req), String(req.body?.deviceId)) });
  });
  app.post('/devices/add', async (req, res) => {
    res.json({ device: await service.add(tokenOf(req), res.locals.peer, requestIdOf(req), req.body?.input ?? {}) });
  });
  app.post('/devices/control', async (req, res) => {
    res.json({ device: await service.control(tokenOf(req), res.locals.peer, requestIdOf(req), req.body?.input ?? {}) });
  });

  app.use(internalErrors);
  return app;
}
