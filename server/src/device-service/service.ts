/**
 * The Device Service: the one implementation of the device rules, reachable
 * only with an internal token. Plan 2.4.
 *
 * It wraps domain/devices.ts, which still holds every rule — validation,
 * ownership, versions, auditing — unchanged. What this layer adds is that
 * nothing reaches those rules without a verified internal token naming the
 * person, the client, the grant and the workload acting for them, so the two
 * edge adapters cannot drift apart and neither can be skipped.
 */

import type { Db } from '../db/index.ts';
import { addDevice, controlDevice, getDevice, listDevices, type AddDeviceInput, type ControlDeviceInput } from '../domain/devices.ts';
import type { Device } from '../domain/types.ts';
import type { Workload } from '../security/workload.ts';
import { verifyInternalToken } from './verify.ts';

export interface DeviceService {
  list(token: string, peer: Workload, requestId: string): Promise<Device[]>;
  get(token: string, peer: Workload, requestId: string, deviceId: string): Promise<Device>;
  add(token: string, peer: Workload, requestId: string, input: AddDeviceInput): Promise<Device>;
  control(token: string, peer: Workload, requestId: string, input: ControlDeviceInput): Promise<Device>;
}

export function createDeviceService(db: Db): DeviceService {
  return {
    async list(token, peer, requestId) {
      return listDevices(db, await verifyInternalToken(token, peer, 'devices:read', requestId));
    },
    async get(token, peer, requestId, deviceId) {
      return getDevice(db, await verifyInternalToken(token, peer, 'devices:read', requestId), deviceId);
    },
    async add(token, peer, requestId, input) {
      return addDevice(db, await verifyInternalToken(token, peer, 'devices:create', requestId), input);
    },
    async control(token, peer, requestId, input) {
      return controlDevice(db, await verifyInternalToken(token, peer, 'devices:control', requestId), input);
    }
  };
}
