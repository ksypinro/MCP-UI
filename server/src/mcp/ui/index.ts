/**
 * The MCP App resources. Spec section 9.
 *
 * Every page is assembled from a shared stylesheet, a shared host bridge and
 * one view script, all inlined. Inlining is what lets `_meta.ui.csp` stay
 * empty: a host blocks every external origin by default, and a page that
 * needs none cannot be broken by that policy or widen it.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const assets = join(dirname(fileURLToPath(import.meta.url)), 'assets');
const read = (file: string) => readFileSync(join(assets, file), 'utf8');

/** The exact content type the MCP Apps extension defines. */
export const UI_MIME = 'text/html;profile=mcp-app';


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

/**
 * UI_DIAGNOSTICS=1 adds a panel to the device list that shows the build, a
 * random id for this copy of the view, and every message the host sent it.
 * For host verification only (spike/FINDINGS.md): it is how we learned what a
 * host actually does, as opposed to what the specification says it does.
 */
const DIAGNOSTICS = process.env.UI_DIAGNOSTICS === '1';

/** One hash over every asset, shown by the diagnostics panel. */
const BUILD = createHash('sha256')
  .update(['styles.css', 'bridge.js', 'devices.js', 'devices.body.html'].map(read).join('\n'))
  .digest('hex').slice(0, 8);

function page(title: string, bodyFile: string, scriptFile: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
${DIAGNOSTICS ? `<meta name="iot-build" content="${BUILD}">` : ''}
<title>${title}</title>
<style>
${read('styles.css')}
</style>
</head>
<body${DIAGNOSTICS ? ' data-diagnostics' : ''}>
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
 * Hosts cache these templates globally, by URI, and keep serving a cached
 * copy across reconnects: host verification found Claude web still running
 * the old device list after its code changed. So every URI carries a hash of
 * its page — `ui://iot/devices.3f9a1c2b.html` — and changed code is a new
 * template that every host must fetch. Nothing user-specific may ever be
 * built into one: per-account data arrives only through an authorized tool
 * result.
 */
function view(name: string, title: string, description: string): UiResource {
  const html = page(title, `${name}.body.html`, `${name}.js`);
  const hash = createHash('sha256').update(html).digest('hex').slice(0, 8);
  return { uri: `ui://iot/${name}.${hash}.html`, name, title, description, html };
}

const RESOURCES: readonly UiResource[] = Object.freeze([
  view('auth', 'Sign in to IoT Switch', 'Signed-out entry point. Contains no credential fields.'),
  view('devices', 'Devices', 'Your devices, each with a switch.'),
  view('device', 'Device', 'One device, its state and a switch.'),
  view('add-device', 'Add a device', 'Add a device by name. New devices start Off.')
]);

const uriOf = (name: string) => RESOURCES.find((resource) => resource.name === name)!.uri;

export const AUTH_URI = uriOf('auth');
export const DEVICES_URI = uriOf('devices');
export const DEVICE_URI = uriOf('device');
export const ADD_DEVICE_URI = uriOf('add-device');

export function uiResources(): UiResource[] {
  return [...RESOURCES];
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
