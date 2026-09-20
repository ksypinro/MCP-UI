/**
 * Tool catalog and UI resources for the phase 0 spike.
 *
 * The catalog mirrors the shape proposed in spec section 8.2 so that whatever
 * the hosts do here transfers to the real implementation: four device
 * operations, plus public presentation and status helpers, and deliberately no
 * model-callable login tool.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { RESOURCE_URI } from './config.js';
import {
  controlDevice, getAccount, getDevice, listDevices, publicDevice, type AccessToken
} from './store.js';

const uiDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const html = (file: string) => readFileSync(join(uiDir, file), 'utf8');

export const UI_MIME = 'text/html;profile=mcp-app';
const AUTH_URI = 'ui://iot-spike/auth.html';
const DEVICES_URI = 'ui://iot-spike/devices.html';

/**
 * Every external origin is blocked unless declared here. The spike bundles
 * everything inline specifically so these lists can stay empty, which is the
 * posture the real app should keep.
 */
const EMPTY_CSP = { connectDomains: [], resourceDomains: [], baseUriDomains: [] };

function uiMeta(resourceUri: string) {
  return {
    ui: { resourceUri, visibility: ['model', 'app'] },
    // ChatGPT honours this as a compatibility alias for ui.resourceUri.
    'openai/outputTemplate': resourceUri
  };
}

function errorResult(code: string, message: string) {
  return {
    isError: true,
    content: [{ type: 'text' as const, text: `${code}: ${message}` }],
    structuredContent: { error: { code, message } }
  };
}

export function buildMcpServer(auth: AccessToken | null): McpServer {
  const server = new McpServer(
    { name: 'iot-switch-spike', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } }
  );

  /* ------------------------------------------------------------- resources */

  server.registerResource(
    'auth-ui', AUTH_URI,
    { title: 'Authentication entry', mimeType: UI_MIME, _meta: { ui: { csp: EMPTY_CSP, prefersBorder: true } } },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: UI_MIME, text: html('auth.html') }] })
  );

  server.registerResource(
    'devices-ui', DEVICES_URI,
    { title: 'Device list', mimeType: UI_MIME, _meta: { ui: { csp: EMPTY_CSP, prefersBorder: true } } },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: UI_MIME, text: html('devices.html') }] })
  );

  /* ---------------------------------------------------------- public tools */

  server.registerTool(
    'ping',
    {
      title: 'Ping',
      description: 'Liveness check. Requires no account and returns no user data.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
    },
    async () => ({
      content: [{ type: 'text', text: 'iot-switch-spike is reachable.' }],
      structuredContent: { ok: true, resource: RESOURCE_URI, time: new Date().toISOString() }
    })
  );

  server.registerTool(
    'show_auth',
    {
      title: 'Show sign-in',
      description: 'Display the sign-up / log-in entry card. Public; performs no authentication itself.',
      inputSchema: { mode: z.enum(['login', 'signup']).optional() },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      _meta: uiMeta(AUTH_URI)
    },
    async ({ mode }) => ({
      content: [{ type: 'text', text: 'Sign in to IoT Switch to see your devices.' }],
      structuredContent: { mode: mode ?? 'login', authenticated: Boolean(auth) }
    })
  );

  server.registerTool(
    'get_auth_status',
    {
      title: 'Authentication status',
      description: 'Report whether this connection is authenticated. Never returns tokens.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      // App-only, per the tool table in requirement.md section 8.2: the views
      // need it, the model has no reason to narrate authentication state.
      _meta: { ui: { visibility: ['app'] } }
    },
    async () => {
      const account = auth ? getAccount(auth.sub) : null;
      return {
        content: [{ type: 'text', text: account ? `Signed in as ${account.username}.` : 'Not signed in.' }],
        structuredContent: account
          ? { authenticated: true, accountId: account.id, username: account.username, scopes: auth?.scopes ?? [] }
          : { authenticated: false }
      };
    }
  );

  /* ------------------------------------------------------- protected tools */
  // Reaching these handlers at all means the HTTP gate in index.ts already
  // verified a bearer token; the identity check below is defence in depth.

  server.registerTool(
    'list_devices',
    {
      title: 'List devices',
      description: 'List every device owned by the signed-in account, oldest first.',
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      _meta: uiMeta(DEVICES_URI)
    },
    async () => {
      if (!auth) return errorResult('UNAUTHENTICATED', 'No verified identity on this request.');
      const devices = listDevices(auth.sub).map(publicDevice);
      return {
        content: [{ type: 'text', text: `${devices.length} device(s): ${devices.map((d) => `${d.name} (${d.state})`).join(', ')}` }],
        structuredContent: { devices }
      };
    }
  );

  server.registerTool(
    'get_device',
    {
      title: 'Get device',
      description: 'Fetch one owned device, including the version required to control it.',
      inputSchema: { deviceId: z.string().min(1) },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false }
    },
    async ({ deviceId }) => {
      if (!auth) return errorResult('UNAUTHENTICATED', 'No verified identity on this request.');
      const device = getDevice(auth.sub, deviceId);
      if (!device) return errorResult('DEVICE_NOT_FOUND', `No device ${deviceId} for this account.`);
      return {
        content: [{ type: 'text', text: `${device.name} is ${device.state === 'on' ? 'On' : 'Off'}.` }],
        structuredContent: { device: publicDevice(device) }
      };
    }
  );

  server.registerTool(
    'control_device',
    {
      title: 'Control device',
      description:
        'Set an owned device to on or off. Requires expectedVersion from a prior read, so call ' +
        'get_device or list_devices first if you do not have a current version.',
      inputSchema: {
        deviceId: z.string().min(1),
        state: z.enum(['on', 'off']),
        expectedVersion: z.number().int().positive()
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        // Replaying this call with the same arguments fails with a version
        // conflict rather than repeating. The annotation must say so.
        idempotentHint: false,
        openWorldHint: false
      }
    },
    async ({ deviceId, state, expectedVersion }) => {
      if (!auth) return errorResult('UNAUTHENTICATED', 'No verified identity on this request.');
      const outcome = controlDevice(auth.sub, deviceId, state, expectedVersion);
      if (!outcome.ok) {
        return outcome.code === 'DEVICE_NOT_FOUND'
          ? errorResult('DEVICE_NOT_FOUND', `No device ${deviceId} for this account.`)
          : errorResult('DEVICE_VERSION_CONFLICT', 'This device changed. Refresh it and try again.');
      }
      const device = publicDevice(outcome.device);
      return {
        content: [{ type: 'text', text: `${device.name} is now ${device.state === 'on' ? 'On' : 'Off'}.` }],
        structuredContent: { device }
      };
    }
  );

  return server;
}
