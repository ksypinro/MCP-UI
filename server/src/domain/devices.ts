/**
 * The four device operations from spec section 6, as an internal module.
 *
 * Takes an Identity rather than an HTTP request so that the REST layer and the
 * MCP adapter share one implementation of the business rules, as spec section
 * 3 requires. Validation lives here too, so a tool call is validated exactly
 * like a request.
 */

import { randomBytes } from 'node:crypto';
import type { Db, Queryable } from '../db/index.ts';
import { AppError } from '../errors.ts';
import { displayDeviceName, normalizeDeviceName } from '../normalize.ts';
import { DEVICE_NAME_MAX, MAX_DEVICES_PER_ACCOUNT } from '../config.ts';
import { record } from './audit.ts';
import type { Device, DeviceState, Identity } from './types.ts';

interface DeviceRow {
  id: string;
  name: string;
  state: DeviceState;
  version: number;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = 'id, name, state, version, created_at, updated_at';

function toDevice(row: DeviceRow): Device {
  return {
    id: row.id,
    name: row.name,
    state: row.state,
    version: row.version,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString()
  };
}

function newDeviceId(): string {
  return `dev_${randomBytes(9).toString('base64url')}`;
}

/* ------------------------------------------------------------------ reads */

/** Spec section 4.3: created_at ascending, id ascending as the tie-breaker. */
export async function listDevices(db: Queryable, identity: Identity): Promise<Device[]> {
  const { rows } = await db.query<DeviceRow>(
    `SELECT ${COLUMNS} FROM devices WHERE owner_id = $1 ORDER BY created_at ASC, id ASC`,
    [identity.accountId]
  );
  return rows.map(toDevice);
}

/**
 * A device owned by somebody else is reported as absent, not as forbidden.
 * Spec section 6.3: the two cases must be indistinguishable, or the endpoint
 * confirms the existence of other people's device ids.
 */
export async function getDevice(db: Queryable, identity: Identity, deviceId: string): Promise<Device> {
  const { rows } = await db.query<DeviceRow>(
    `SELECT ${COLUMNS} FROM devices WHERE id = $1 AND owner_id = $2`,
    [deviceId, identity.accountId]
  );
  const row = rows[0];
  if (!row) throw new AppError('DEVICE_NOT_FOUND');
  return toDevice(row);
}

/* ----------------------------------------------------------------- create */

export interface AddDeviceInput {
  name: string;
  /** Spec section 6.2. Makes a replayed create return the original device. */
  idempotencyKey?: string | undefined;
}

export async function addDevice(db: Db, identity: Identity, input: AddDeviceInput): Promise<Device> {
  const name = displayDeviceName(input.name ?? '');
  if (name.length === 0) {
    throw new AppError('VALIDATION_FAILED', 'Device name is required.', 'name');
  }
  if (name.length > DEVICE_NAME_MAX) {
    throw new AppError('VALIDATION_FAILED', `Device name must be ${DEVICE_NAME_MAX} characters or fewer.`, 'name');
  }
  const normalizedName = normalizeDeviceName(name);

  return db.transaction(async (tx) => {
    if (input.idempotencyKey) {
      const replay = await findByIdempotencyKey(tx, identity, input.idempotencyKey);
      if (replay) return replay;
    }

    const { rows: counted } = await tx.query<{ n: number }>(
      'SELECT count(*)::int AS n FROM devices WHERE owner_id = $1',
      [identity.accountId]
    );
    if ((counted[0]?.n ?? 0) >= MAX_DEVICES_PER_ACCOUNT) {
      throw new AppError('DEVICE_LIMIT_REACHED');
    }

    // ON CONFLICT rather than catching a unique violation: inside a
    // transaction a failed statement aborts the whole transaction on
    // PostgreSQL, so catching the error would leave nothing usable to
    // continue with. Zero rows back means the name is taken.
    const { rows } = await tx.query<DeviceRow>(
      `INSERT INTO devices (id, owner_id, name, normalized_name, state)
       VALUES ($1, $2, $3, $4, 'off')
       ON CONFLICT ON CONSTRAINT devices_owner_name_key DO NOTHING
       RETURNING ${COLUMNS}`,
      [newDeviceId(), identity.accountId, name, normalizedName]
    );

    const row = rows[0];
    if (!row) {
      // Two identical creates racing: whoever lost still must not see a
      // second device, and a replay of the winner's key returns the winner.
      if (input.idempotencyKey) {
        const replay = await findByIdempotencyKey(tx, identity, input.idempotencyKey);
        if (replay) return replay;
      }
      throw new AppError('DEVICE_NAME_CONFLICT');
    }

    if (input.idempotencyKey) {
      await tx.query(
        `INSERT INTO idempotency_keys (account_id, endpoint, key, device_id)
         VALUES ($1, 'POST /v1/devices', $2, $3)
         ON CONFLICT DO NOTHING`,
        [identity.accountId, input.idempotencyKey, row.id]
      );
    }

    await record(tx, identity, {
      action: 'device.create',
      deviceId: row.id,
      oldState: null,
      newState: row.state,
      outcome: 'ok'
    });

    return toDevice(row);
  });
}

async function findByIdempotencyKey(
  tx: Queryable,
  identity: Identity,
  key: string
): Promise<Device | null> {
  const { rows } = await tx.query<DeviceRow>(
    `SELECT ${COLUMNS.split(', ').map((c) => `d.${c}`).join(', ')}
       FROM idempotency_keys k
       JOIN devices d ON d.id = k.device_id
      WHERE k.account_id = $1 AND k.endpoint = 'POST /v1/devices' AND k.key = $2`,
    [identity.accountId, key]
  );
  const row = rows[0];
  return row ? toDevice(row) : null;
}

/* ---------------------------------------------------------------- control */

export interface ControlDeviceInput {
  deviceId: string;
  state: DeviceState;
  expectedVersion: number;
}

export async function controlDevice(
  db: Db,
  identity: Identity,
  input: ControlDeviceInput
): Promise<Device> {
  if (input.state !== 'on' && input.state !== 'off') {
    throw new AppError('INVALID_STATE');
  }
  if (!Number.isInteger(input.expectedVersion) || input.expectedVersion < 1) {
    throw new AppError('VALIDATION_FAILED', 'expectedVersion must be a positive integer.', 'expectedVersion');
  }

  type Outcome =
    | { ok: true; device: Device }
    | { ok: false; code: 'DEVICE_NOT_FOUND' }
    | { ok: false; code: 'DEVICE_VERSION_CONFLICT'; currentState: DeviceState };

  const outcome = await db.transaction<Outcome>(async (tx) => {
    // The version check and the write are one statement, so two callers
    // holding the same version cannot both succeed: whoever arrives second
    // matches no row. Spec section 6.1.
    //
    // `state <> $1` excludes the no-op, which must not consume a version.
    const { rows: changed } = await tx.query<DeviceRow>(
      `UPDATE devices
          SET state = $1, version = version + 1, updated_at = now()
        WHERE id = $2 AND owner_id = $3 AND version = $4 AND state <> $1
        RETURNING ${COLUMNS}`,
      [input.state, input.deviceId, identity.accountId, input.expectedVersion]
    );

    const updated = changed[0];
    if (updated) {
      // Audited inside the transaction: the record of the change and the
      // change itself must land together or not at all.
      await record(tx, identity, {
        action: 'device.control',
        deviceId: updated.id,
        oldState: input.state === 'on' ? 'off' : 'on',
        newState: updated.state,
        outcome: 'ok'
      });
      return { ok: true, device: toDevice(updated) };
    }

    // No row matched. That is one of three different situations, and only a
    // read distinguishes them. It is inside the same transaction as the
    // update, so what it sees is consistent with what the update missed.
    const { rows: existing } = await tx.query<DeviceRow>(
      `SELECT ${COLUMNS} FROM devices WHERE id = $1 AND owner_id = $2`,
      [input.deviceId, identity.accountId]
    );
    const current = existing[0];

    if (!current) return { ok: false, code: 'DEVICE_NOT_FOUND' };

    if (current.version !== input.expectedVersion) {
      return { ok: false, code: 'DEVICE_VERSION_CONFLICT', currentState: current.state };
    }

    // Right version, already in the requested state. Spec section 6.1: return
    // the device untouched, advancing neither version nor updatedAt.
    return { ok: true, device: toDevice(current) };
  });

  if (outcome.ok) return outcome.device;

  // Rejections are audited *after* the transaction, in one of their own.
  // Recording them inside it would roll the record back along with the
  // rejection, and spec section 11 asks for the outcome of every attempt.
  //
  // A miss on a device we do not own is deliberately not audited: it names no
  // row of ours, and logging it would let anyone fill the table by guessing
  // identifiers.
  if (outcome.code === 'DEVICE_VERSION_CONFLICT') {
    await record(db, identity, {
      action: 'device.control',
      deviceId: input.deviceId,
      oldState: outcome.currentState,
      newState: input.state,
      outcome: 'rejected'
    });
  }

  throw new AppError(outcome.code);
}
