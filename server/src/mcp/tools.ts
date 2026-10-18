/**
 * The device tools from spec section 8.2.
 *
 * Each one is a thin translation over the Device Service the REST API also
 * uses — spec section 3 requires one implementation of the business rules,
 * so validation, ownership, version checks and auditing all happen there and
 * are not restated here.
 *
 * Reaching any of these handlers means the HTTP gate already verified a token
 * and the scope it needs. The caller check in each handler is defence in
 * depth, not the control. The handler never forwards the caller's token: it
 * exchanges it for an internal one naming this adapter and the single scope
 * the call needs (exchange-client.ts).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Db } from '../db/index.ts';
import { AppError, isAppError } from '../errors.ts';
import { getAccount } from '../domain/accounts.ts';
import type { Caller, Device, VerifiedCaller } from '../domain/types.ts';
import type { DeviceService } from '../device-service/service.ts';
import type { ExchangeClient } from '../exchange-client.ts';
import type { WriteBudgets } from '../write-budgets.ts';
import { SERVER_INFO } from './config.ts';
import { annotationsFor } from './policy.ts';
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
/** The namespaced key an error code travels under. */
export const ERROR_META_KEY = 'iot/error';

function toolError(error: unknown, challenge?: string) {
  const code = isAppError(error) ? error.code : 'INTERNAL_ERROR';
  const message = isAppError(error) ? error.message : 'Unexpected error.';
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: message }],
    // Deliberately no structuredContent.
    //
    // A client validates structuredContent against the declared outputSchema
    // whenever it is present, including on an error result — the SDK's own
    // client throws a protocol error rather than surfacing the tool error, so
    // every version conflict and name clash would reach a host as "structured
    // content does not match the tool's output schema" instead of something a
    // person could act on. The schema describes a success; an error is not
    // one. The code travels in _meta, which is not schema-bound.
    //
    // A challenge, when the gate hands one over, is the ChatGPT form of the
    // HTTP 401: the host starts account linking from it. See gate.ts.
    _meta: {
      [ERROR_META_KEY]: { code, message },
      ...(challenge ? { 'mcp/www_authenticate': [challenge] } : {})
    }
  };
}

export interface ToolDeps {
  db: Db;
  devices: DeviceService;
  exchange: ExchangeClient;
  budgets: WriteBudgets;
}

/**
 * The verified caller, or the refusal a protected handler returns. The gate
 * makes the anonymous branch unreachable in practice; if it is ever reached,
 * the gate has a hole, and this says so rather than quietly serving data.
 */
function verifiedOr(caller: Caller): VerifiedCaller | null {
  return caller.kind === 'verified' ? caller : null;
}

function unauthenticated(): AppError {
  return new AppError('UNAUTHENTICATED', 'No verified identity on this request.');
}

function overBudget(retryAfter: number): AppError {
  return new AppError('RATE_LIMITED', `Too many changes in a short time. Try again in ${retryAfter} seconds.`);
}

export function registerDeviceTools(
  server: McpServer, deps: ToolDeps, caller: Caller, challenge?: string
): void {
  const { db, devices, exchange, budgets } = deps;

  server.registerTool(
    'list_devices',
    {
      title: 'List devices',
      description:
        'List every device on the signed-in account, oldest first. Each device includes the '
        + 'version required to change its state.',
      inputSchema: {},
      outputSchema: { devices: z.array(deviceObject) },
      annotations: annotationsFor('list_devices'),
      _meta: uiToolMeta(DEVICES_URI)
    },
    async () => {
      const verified = verifiedOr(caller);
      if (!verified) return toolError(unauthenticated(), challenge);
      try {
        const list = await exchange.run(verified, 'devices:read',
          (token, peer) => devices.list(token, peer, verified.requestId));
        return {
          content: [{
            type: 'text',
            text: list.length === 0
              ? 'This account has no devices yet.'
              : `${list.length} device${list.length === 1 ? '' : 's'}: `
                + list.map(describe).join(' ')
          }],
          structuredContent: { devices: list }
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
      annotations: annotationsFor('get_device'),
      _meta: uiToolMeta(DEVICE_URI)
    },
    async ({ deviceId }) => {
      const verified = verifiedOr(caller);
      if (!verified) return toolError(unauthenticated(), challenge);
      try {
        const device = await exchange.run(verified, 'devices:read',
          (token, peer) => devices.get(token, peer, verified.requestId, deviceId));
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
      annotations: annotationsFor('control_device'),
      _meta: { ui: { visibility: ['model', 'app'] } }
    },
    async ({ deviceId, state, expectedVersion }) => {
      const verified = verifiedOr(caller);
      if (!verified) return toolError(unauthenticated(), challenge);
      try {
        // A tool error, not an HTTP 429: a transport 429 can make a host
        // retry on its own, which is the opposite of what a budget is for.
        const budget = await budgets.spend('control', verified.grantId, `${verified.accountId}:${deviceId}`);
        if (!budget.ok) return toolError(overBudget(budget.retryAfter));
        const device = await exchange.run(verified, 'devices:control',
          (token, peer) => devices.control(token, peer, verified.requestId, { deviceId, state, expectedVersion }));
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
      annotations: annotationsFor('add_device'),
      _meta: { ui: { visibility: ['model', 'app'] } }
    },
    async ({ name }) => {
      const verified = verifiedOr(caller);
      if (!verified) return toolError(unauthenticated(), challenge);
      try {
        const budget = await budgets.spend('create', verified.grantId);
        if (!budget.ok) return toolError(overBudget(budget.retryAfter));
        const device = await exchange.run(verified, 'devices:create',
          (token, peer) => devices.add(token, peer, verified.requestId, { name }));
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
      annotations: annotationsFor('get_auth_status'),
      // App-only: the views need it, and the model has no reason to narrate
      // authentication state into a conversation. Spec section 8.2.
      _meta: { ui: { visibility: ['app'] } }
    },
    async () => {
      try {
        const account = caller.kind === 'verified' ? await getAccount(db, caller.accountId) : null;
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

export { SERVER_INFO };
