/**
 * The device tools from spec section 8.2.
 *
 * Each one is a thin translation over the same device service the REST API
 * uses — spec section 3 requires one implementation of the business rules, so
 * validation, ownership, version checks and auditing all happen there and are
 * not restated here.
 *
 * Reaching any of these handlers means the HTTP gate already verified a token
 * and the scope it needs. The identity check in each handler is defence in
 * depth, not the control.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Db } from '../db/index.ts';
import { AppError, isAppError } from '../errors.ts';
import { addDevice, controlDevice, getDevice, listDevices } from '../domain/devices.ts';
import { getAccount } from '../domain/accounts.ts';
import type { Device, Identity } from '../domain/types.ts';
import { SERVER_INFO } from './config.ts';
import { DEVICES_URI, DEVICE_URI, uiToolMeta } from './ui/index.ts';

const deviceShape = {
  id: z.string(),
  name: z.string(),
  state: z.enum(['on', 'off']),
  version: z.number().int(),
  createdAt: z.string(),
  updatedAt: z.string()
};

const deviceObject = z.object(deviceShape);

function describe(device: Device): string {
  return `${device.name} is ${device.state === 'on' ? 'On' : 'Off'}.`;
}

/**
 * Business failures are tool results, not transport failures.
 *
 * Note that argument validation is the one failure class that does NOT come
 * through here: the SDK rejects a bad enum or a missing field before the
 * handler runs, and returns isError with a text message and no
 * structuredContent. Anything reading structuredContent.error.code must
 * tolerate its absence. Loosening the published schema to route validation
 * through this function would be worse — hosts use the declared enum to
 * check a call before making it.
 *
 * A version conflict or a name clash is a normal outcome the model should see
 * and act on. Only missing or insufficient authorization is a transport
 * error, because only that has a challenge a host can act on. Spec sections
 * 7.5 and 8.3.
 */
function toolError(error: unknown) {
  const code = isAppError(error) ? error.code : 'INTERNAL_ERROR';
  const message = isAppError(error) ? error.message : 'Unexpected error.';
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: message }],
    structuredContent: { error: { code, message } }
  };
}

const READ_ONLY = {
  readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false
} as const;

export function registerDeviceTools(server: McpServer, db: Db, identity: Identity | null): void {
  server.registerTool(
    'list_devices',
    {
      title: 'List devices',
      description:
        'List every device on the signed-in account, oldest first. Each device includes the '
        + 'version required to change its state.',
      inputSchema: {},
      outputSchema: { devices: z.array(deviceObject) },
      annotations: READ_ONLY,
      _meta: uiToolMeta(DEVICES_URI)
    },
    async () => {
      if (!identity) return toolError(unauthenticated());
      try {
        const devices = await listDevices(db, identity);
        return {
          content: [{
            type: 'text',
            text: devices.length === 0
              ? 'This account has no devices yet.'
              : `${devices.length} device${devices.length === 1 ? '' : 's'}: `
                + devices.map(describe).join(' ')
          }],
          structuredContent: { devices }
        };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'get_device',
    {
      title: 'Get device',
      description:
        'Fetch one device by id, including the version required to change its state. '
        + 'Device ids come from list_devices; never guess one.',
      inputSchema: { deviceId: z.string().min(1).describe('The device id, from list_devices.') },
      outputSchema: { device: deviceObject },
      annotations: READ_ONLY,
      _meta: uiToolMeta(DEVICE_URI)
    },
    async ({ deviceId }) => {
      if (!identity) return toolError(unauthenticated());
      try {
        const device = await getDevice(db, identity, deviceId);
        return { content: [{ type: 'text', text: describe(device) }], structuredContent: { device } };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'control_device',
    {
      title: 'Control device',
      description:
        'Switch a device on or off. Requires expectedVersion, which must be the version from a '
        + 'current read: call get_device or list_devices first if you do not have one. If the '
        + 'version is stale the call is refused and nothing changes — read again and retry with '
        + 'the new version rather than resending.',
      inputSchema: {
        deviceId: z.string().min(1).describe('The device id, from list_devices.'),
        state: z.enum(['on', 'off']).describe('The state to set. There is no toggle.'),
        expectedVersion: z.number().int().positive()
          .describe('The version from your most recent read of this device.')
      },
      outputSchema: { device: deviceObject },
      annotations: {
        readOnlyHint: false,
        // Nothing is destroyed: a device has two states and either is reachable.
        destructiveHint: false,
        // Replaying this call with the same arguments fails with a version
        // conflict rather than repeating. Annotations are hints, but a
        // dishonest one invites a host to retry something that cannot be
        // retried.
        idempotentHint: false,
        openWorldHint: false
      },
      _meta: { ui: { visibility: ['model', 'app'] } }
    },
    async ({ deviceId, state, expectedVersion }) => {
      if (!identity) return toolError(unauthenticated());
      try {
        const device = await controlDevice(db, identity, { deviceId, state, expectedVersion });
        return { content: [{ type: 'text', text: describe(device) }], structuredContent: { device } };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'add_device',
    {
      title: 'Add device',
      description:
        'Add a device to the signed-in account. New devices start Off. Names must be unique '
        + 'within the account, ignoring case and surrounding whitespace.',
      inputSchema: { name: z.string().min(1).max(64).describe('A display name, 1 to 64 characters.') },
      outputSchema: { device: deviceObject },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        // A second identical call fails as a name conflict rather than
        // creating a second device, so it is not idempotent either.
        idempotentHint: false,
        openWorldHint: false
      },
      _meta: { ui: { visibility: ['model', 'app'] } }
    },
    async ({ name }) => {
      if (!identity) return toolError(unauthenticated());
      try {
        const device = await addDevice(db, identity, { name });
        return {
          content: [{ type: 'text', text: `Added ${device.name}. It starts Off.` }],
          structuredContent: { device }
        };
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'get_auth_status',
    {
      title: 'Authentication status',
      description:
        'Report whether this connection is signed in, and to which account. Never returns a '
        + 'token. Safe to call before authorizing.',
      inputSchema: {},
      outputSchema: {
        authenticated: z.boolean(),
        accountId: z.string().optional(),
        username: z.string().optional()
      },
      annotations: READ_ONLY,
      // App-only: the views need it, and the model has no reason to narrate
      // authentication state into a conversation. Spec section 8.2.
      _meta: { ui: { visibility: ['app'] } }
    },
    async () => {
      try {
        const account = identity ? await getAccount(db, identity.accountId) : null;
        return {
          content: [{
            type: 'text',
            text: account ? `Signed in as ${account.username}.` : 'Not signed in.'
          }],
          structuredContent: account
            ? { authenticated: true, accountId: account.id, username: account.username }
            : { authenticated: false }
        };
      } catch (error) {
        // Unguarded, an error here escapes to the SDK, which surfaces its
        // message as tool text — model-visible and user-visible. This is also
        // the only public tool, so it is reachable without a token.
        return toolError(error);
      }
    }
  );
}

function unauthenticated(): AppError {
  // Unreachable in practice: the gate refuses these calls at the transport
  // layer. If it is ever reached, the gate has a hole, and this says so
  // rather than quietly serving data.
  return new AppError('UNAUTHENTICATED', 'No verified identity on this request.');
}

export { SERVER_INFO };
