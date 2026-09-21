/**
 * The MCP App resources. Spec section 9.
 *
 * Every page is assembled from a shared stylesheet, a shared host bridge and
 * one view script, all inlined. Inlining is what lets `_meta.ui.csp` stay
 * empty: a host blocks every external origin by default, and a page that
 * needs none cannot be broken by that policy or widen it.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const assets = join(dirname(fileURLToPath(import.meta.url)), 'assets');
const read = (file: string) => readFileSync(join(assets, file), 'utf8');

/** The exact content type the MCP Apps extension defines. */
export const UI_MIME = 'text/html;profile=mcp-app';

export const AUTH_URI = 'ui://iot/auth.html';
export const DEVICES_URI = 'ui://iot/devices.html';
export const DEVICE_URI = 'ui://iot/device.html';
export const ADD_DEVICE_URI = 'ui://iot/add-device.html';

/**
 * No external origins, and no permissions.
 *
 * Camera, microphone and location are unavailable inside a host's mobile
 * WebView in any case, and this product needs none of them.
 */
export const EMPTY_CSP = Object.freeze({
  connectDomains: [] as string[],
  resourceDomains: [] as string[],
  baseUriDomains: [] as string[]
});

export interface UiResource {
  uri: string;
  name: string;
  title: string;
  description: string;
  html: string;
}

function page(title: string, bodyFile: string, scriptFile: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${title}</title>
<style>
${read('styles.css')}
</style>
</head>
<body>
${read(bodyFile)}
<script>
${read('bridge.js')}
</script>
<script>
${read(scriptFile)}
</script>
</body>
</html>
`;
}

/**
 * Built once at startup.
 *
 * These templates are cached by hosts globally, by URL. Nothing user-specific
 * may ever be built into one: per-account data arrives only through an
 * authorized tool result.
 */
let cached: UiResource[] | null = null;

export function uiResources(): UiResource[] {
  if (cached) return cached;
  cached = [
    {
      uri: AUTH_URI,
      name: 'auth',
      title: 'Sign in to IoT Switch',
      description: 'Signed-out entry point. Contains no credential fields.',
      html: page('Sign in to IoT Switch', 'auth.body.html', 'auth.js')
    },
    {
      uri: DEVICES_URI,
      name: 'devices',
      title: 'Devices',
      description: 'Your devices, each with a switch.',
      html: page('Devices', 'devices.body.html', 'devices.js')
    },
    {
      uri: DEVICE_URI,
      name: 'device',
      title: 'Device',
      description: 'One device, its state and a switch.',
      html: page('Device', 'device.body.html', 'device.js')
    },
    {
      uri: ADD_DEVICE_URI,
      name: 'add-device',
      title: 'Add a device',
      description: 'Add a device by name. New devices start Off.',
      html: page('Add a device', 'add-device.body.html', 'add-device.js')
    }
  ];
  return cached;
}

/** Metadata every UI resource carries. */
export function uiResourceMeta() {
  return { ui: { csp: EMPTY_CSP, prefersBorder: true } };
}

/**
 * Links a tool to the view that renders its result.
 *
 * `_meta.ui.resourceUri` is the MCP Apps standard field; ChatGPT honours
 * `openai/outputTemplate` as a compatibility alias, and emitting both is what
 * makes one server work in both hosts.
 */
export function uiToolMeta(resourceUri: string, visibility: string[] = ['model', 'app']) {
  return {
    ui: { resourceUri, visibility },
    'openai/outputTemplate': resourceUri
  };
}
