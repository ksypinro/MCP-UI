/** The four device endpoints from spec section 6. */

import { Router } from 'express';
import type { Db } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { addDevice, controlDevice, getDevice, listDevices } from '../domain/devices.ts';
import { authenticate, identityOf } from './middleware.ts';

export function deviceRoutes(db: Db): Router {
  const router = Router();
  router.use(authenticate(db, { required: true }));

  router.get('/v1/devices', async (_req, res) => {
    res.json({ devices: await listDevices(db, identityOf(res)) });
  });

  router.get('/v1/devices/:deviceId', async (req, res) => {
    res.json({ device: await getDevice(db, identityOf(res), req.params.deviceId) });
  });

  router.put('/v1/devices/:deviceId/state', async (req, res) => {
    const body = req.body as { state?: unknown; expectedVersion?: unknown } | undefined;

    // `state` and `expectedVersion` are checked here only for shape; the
    // service owns the rules, so the MCP adapter gets the same behaviour.
    if (body?.expectedVersion === undefined) {
      throw new AppError('VALIDATION_FAILED', 'expectedVersion is required.', 'expectedVersion');
    }

    const device = await controlDevice(db, identityOf(res), {
      deviceId: req.params.deviceId,
      state: body?.state as 'on' | 'off',
      expectedVersion: body.expectedVersion as number
    });
    res.json({ device });
  });

  router.post('/v1/devices', async (req, res) => {
    const body = req.body as { name?: unknown } | undefined;
    if (typeof body?.name !== 'string') {
      throw new AppError('VALIDATION_FAILED', 'Device name is required.', 'name');
    }

    const idempotencyKey = req.get('idempotency-key');
    const device = await addDevice(db, identityOf(res), {
      name: body.name,
      idempotencyKey: idempotencyKey && idempotencyKey.length <= 200 ? idempotencyKey : undefined
    });
    res.status(201).json({ device });
  });

  return router;
}
