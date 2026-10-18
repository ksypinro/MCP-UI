/**
 * The four device endpoints from spec section 6.
 *
 * Like the MCP tools, these are a thin adapter over the Device Service. They
 * check shape, spend the write budget, and exchange the caller's token for an
 * internal one; every rule lives behind the Device Service.
 */

import { Router, type Response } from 'express';
import type { Db } from '../db/index.ts';
import { AppError } from '../errors.ts';
import type { DeviceService } from '../device-service/service.ts';
import type { ExchangeClient } from '../exchange-client.ts';
import type { WriteBudgets } from '../write-budgets.ts';
import { authenticate, callerOf } from './middleware.ts';

export interface DeviceRouteDeps {
  db: Db;
  devices: DeviceService;
  exchange: ExchangeClient;
  budgets: WriteBudgets;
}

function refuseOverBudget(res: Response, retryAfter: number): never {
  res.setHeader('retry-after', String(retryAfter));
  throw new AppError('RATE_LIMITED', `Too many changes in a short time. Try again in ${retryAfter} seconds.`);
}

export function deviceRoutes(deps: DeviceRouteDeps): Router {
  const { db, devices, exchange, budgets } = deps;
  const router = Router();
  // Scoped to the device paths. Unscoped, it ran for every request that
  // reached this router, so any unknown path anywhere answered 401 rather
  // than 404.
  router.use('/v1/devices', authenticate(db, { required: true }));

  router.get('/v1/devices', async (_req, res) => {
    const caller = callerOf(res);
    const list = await exchange.run(caller, 'devices:read',
      (token, peer) => devices.list(token, peer, caller.requestId));
    res.json({ devices: list });
  });

  router.get('/v1/devices/:deviceId', async (req, res) => {
    const caller = callerOf(res);
    const device = await exchange.run(caller, 'devices:read',
      (token, peer) => devices.get(token, peer, caller.requestId, req.params.deviceId));
    res.json({ device });
  });

  router.put('/v1/devices/:deviceId/state', async (req, res) => {
    const caller = callerOf(res);
    const body = req.body as { state?: unknown; expectedVersion?: unknown } | undefined;

    // `state` and `expectedVersion` are checked here only for shape; the
    // service owns the rules, so the MCP adapter gets the same behaviour.
    if (body?.expectedVersion === undefined) {
      throw new AppError('VALIDATION_FAILED', 'expectedVersion is required.', 'expectedVersion');
    }

    const budget = await budgets.spend('control', caller.grantId, `${caller.accountId}:${req.params.deviceId}`);
    if (!budget.ok) refuseOverBudget(res, budget.retryAfter);

    const device = await exchange.run(caller, 'devices:control', (token, peer) => devices.control(token, peer, caller.requestId, {
      deviceId: req.params.deviceId,
      state: body?.state as 'on' | 'off',
      expectedVersion: body.expectedVersion as number
    }));
    res.json({ device });
  });

  router.post('/v1/devices', async (req, res) => {
    const caller = callerOf(res);
    const body = req.body as { name?: unknown } | undefined;
    if (typeof body?.name !== 'string') {
      throw new AppError('VALIDATION_FAILED', 'Device name is required.', 'name');
    }

    const budget = await budgets.spend('create', caller.grantId);
    if (!budget.ok) refuseOverBudget(res, budget.retryAfter);

    const idempotencyKey = req.get('idempotency-key');
    const name = body.name;
    const device = await exchange.run(caller, 'devices:create', (token, peer) => devices.add(token, peer, caller.requestId, {
      name,
      idempotencyKey: idempotencyKey && idempotencyKey.length <= 200 ? idempotencyKey : undefined
    }));
    res.status(201).json({ device });
  });

  return router;
}
