/**
 * The MCP App resources. Spec section 9, and acceptance criteria AC-17,
 * AC-23 and AC-28.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { uiResources } from '../src/mcp/ui/index.ts';

/** Exact, because 'ui://iot/add-device.html' also ends with 'device.html'. */
function view(name: 'auth' | 'devices' | 'device' | 'add-device') {
  const found = uiResources().find((resource) => resource.uri === `ui://iot/${name}.html`);
  if (!found) throw new Error(`no view named ${name}`);
  return found;
}
import { startServer, type Harness } from './oauth-helpers.ts';
import { callTool, rpc, structured, toolsList, tokenFor } from './mcp-helpers.ts';

let h: Harness;
before(async () => { h = await startServer(); });
after(async () => { await h.close(); });

const readResource = (uri: string, token?: string | null) =>
  rpc(h.base, { jsonrpc: '2.0', id: 1, method: 'resources/read', params: { uri } }, token);

/* ------------------------------------------------------------- discovery */

test('the four views are discoverable without a token', async () => {
  const response = await rpc(h.base, { jsonrpc: '2.0', id: 1, method: 'resources/list' });
  assert.equal(response.status, 200);

  const uris = response.body.result.resources.map((r: { uri: string }) => r.uri).sort();
  assert.deepEqual(uris, [
    'ui://iot/add-device.html', 'ui://iot/auth.html', 'ui://iot/device.html', 'ui://iot/devices.html'
  ]);
});

test('every view declares the exact MCP Apps content type', async () => {
  const response = await rpc(h.base, { jsonrpc: '2.0', id: 1, method: 'resources/list' });
  for (const resource of response.body.result.resources) {
    // Not text/html, and not a variation on the profile parameter: a host
    // matches this string to decide whether it is an app at all.
    assert.equal(resource.mimeType, 'text/html;profile=mcp-app', resource.uri);
  }
});

test('a view can be read anonymously, before anyone has signed in', async () => {
  const response = await readResource('ui://iot/auth.html');
  assert.equal(response.status, 200);
  const content = response.body.result.contents[0];
  assert.equal(content.mimeType, 'text/html;profile=mcp-app');
  assert.match(content.text, /<!doctype html>/i);
});

/* -------------------------------------------- AC-23: sandbox and isolation */

test('no view reaches for an external origin, and none is declared', async () => {
  const response = await rpc(h.base, { jsonrpc: '2.0', id: 1, method: 'resources/list' });

  for (const resource of response.body.result.resources) {
    const csp = resource._meta?.ui?.csp;
    assert.ok(csp, `${resource.uri} declares no csp`);
    // Everything is inlined precisely so these can stay empty. A host blocks
    // undeclared origins by default; a page needing none cannot be broken by
    // that policy, and cannot widen it.
    assert.deepEqual(csp.connectDomains, []);
    assert.deepEqual(csp.resourceDomains, []);
    assert.deepEqual(csp.baseUriDomains, []);
  }

  for (const view of uiResources()) {
    assert.doesNotMatch(view.html, /(?:src|href)\s*=\s*["']https?:/i, `${view.uri} loads something external`);
    assert.doesNotMatch(view.html, /<iframe/i, `${view.uri} nests a frame`);
  }
});

test('no view asks for a device permission it does not need', async () => {
  const response = await rpc(h.base, { jsonrpc: '2.0', id: 1, method: 'resources/list' });
  for (const resource of response.body.result.resources) {
    assert.equal(resource._meta?.ui?.permissions, undefined, resource.uri);
  }
});

test('no view can hold a token, and none renders user data as markup', () => {
  for (const view of uiResources()) {
    // A token in a view is a token in the host's storage, in its logs, and in
    // whatever the view sends onwards. Protected data arrives only as a tool
    // result.
    assert.doesNotMatch(view.html, /localStorage|sessionStorage|document\.cookie/,
      `${view.uri} reaches for browser storage`);
    assert.doesNotMatch(view.html, /Authorization|Bearer /,
      `${view.uri} mentions a credential header`);

    // Device names are user-supplied strings and every template here is
    // otherwise static, so nothing may be written as markup.
    assert.doesNotMatch(view.html, /\.innerHTML\s*=/, `${view.uri} assigns innerHTML`);
    assert.doesNotMatch(view.html, /document\.write/, `${view.uri} uses document.write`);
  }
});

test('the templates are identical for everyone', async () => {
  // Hosts cache these globally, by URL. Anything account-specific compiled
  // into one would be served to the next person who opens it.
  const anonymous = (await readResource('ui://iot/devices.html')).body.result.contents[0].text;

  const owner = await tokenFor(h);
  await callTool(h.base, 'add_device', { name: 'Bedroom Lamp' }, owner.accessToken);
  const authenticated = (await readResource('ui://iot/devices.html', owner.accessToken))
    .body.result.contents[0].text;

  assert.equal(anonymous, authenticated);
  assert.doesNotMatch(authenticated, /Bedroom Lamp|acc_|dev_/);
});

/* --------------------------------------------------- AC-17: presentation */

test('the presentation tools are public and link their views', async () => {
  const tools: any[] = (await toolsList(h.base)).body.result.tools;
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));

  assert.equal(byName.show_auth._meta.ui.resourceUri, 'ui://iot/auth.html');
  assert.equal(byName.show_add_device._meta.ui.resourceUri, 'ui://iot/add-device.html');

  // Public: a card that exists to get someone signed in cannot itself require
  // being signed in.
  assert.equal((await callTool(h.base, 'show_auth')).status, 200);
  assert.equal((await callTool(h.base, 'show_add_device')).status, 200);
});

test('the reading tools link the views that render their results', async () => {
  const tools: any[] = (await toolsList(h.base)).body.result.tools;
  const byName = Object.fromEntries(tools.map((tool) => [tool.name, tool]));

  assert.equal(byName.list_devices._meta.ui.resourceUri, 'ui://iot/devices.html');
  assert.equal(byName.get_device._meta.ui.resourceUri, 'ui://iot/device.html');
});

test('every UI tool also carries the ChatGPT alias', async () => {
  const tools: any[] = (await toolsList(h.base)).body.result.tools;
  for (const tool of tools) {
    const linked = tool._meta?.ui?.resourceUri;
    if (!linked) continue;
    // ChatGPT honours openai/outputTemplate as a compatibility alias, and
    // emitting both is what makes one server work in both hosts.
    assert.equal(tool._meta['openai/outputTemplate'], linked, tool.name);
  }
});

test('show_auth says nothing about who is signed in', async () => {
  const owner = await tokenFor(h);
  const response = await callTool(h.base, 'show_auth', {}, owner.accessToken);
  // The tool is public and its result is model-visible.
  assert.equal(structured(response).authenticated, false);
  assert.doesNotMatch(JSON.stringify(response.body), new RegExp(owner.username));
});

/* -------------------------------------------------- bridge and behaviour */

test('the bridge registers its listener before it starts the handshake', () => {
  const html = uiResources()[0]!.html;
  const listener = html.indexOf("window.addEventListener('message'");
  // The call, not the comment above the listener that mentions it.
  const handshake = html.indexOf("request('ui/initialize'");

  assert.ok(listener > -1 && handshake > -1);
  // A host may push tool-input or tool-result the instant the handshake
  // completes; a listener added afterwards misses the initial data.
  assert.ok(listener < handshake, 'the message listener must be registered first');
});

test('the bridge only accepts messages from the host', () => {
  for (const view of uiResources()) {
    assert.match(view.html, /event\.source !== window\.parent/, `${view.uri}`);
  }
});

test('the bridge reports a size only when it changed', () => {
  // The host may resize us in response, which fires resize, which lands back
  // in the reporter; echoing an unchanged value makes that a loop.
  assert.match(uiResources()[0]!.html, /if \(reported === lastReported\) return;/);
});

test('views take safe areas from the host, not from CSS env()', () => {
  const html = uiResources()[0]!.html;
  assert.match(html, /safeAreaInsets/);
  // Inside a chat WebView the page is not the thing the notch overlaps, and a
  // control rendered outside the insets cannot be tapped.
  assert.doesNotMatch(html, /env\(safe-area-inset/);
});

test('views use host style tokens rather than hardcoded colour', () => {
  const html = view('devices').html;
  assert.match(html, /var\(--color-text-primary/);
  assert.match(html, /var\(--color-background-primary/);
});

/* ----------------------------------------------------- AC-28: inline list */

test('the device list bounds what it renders inline and can ask for more', () => {
  const html = view('devices').html;

  // On a phone the conversation owns vertical scrolling and the host clips
  // inline overflow, so a long list rendered inline is partly unreachable.
  assert.match(html, /INLINE_ROW_BUDGET/);
  assert.match(html, /ui\/request-display-mode|requestDisplayMode/);
  assert.match(html, /availableDisplayModes: \['inline', 'fullscreen'\]|'inline', 'fullscreen'/);

  // And the number is still a guess, which the code has to admit.
  assert.match(html, /NOT MEASURED/);
});

test('the auth view contains no credential fields', () => {
  const html = view('auth').html;
  // Spec section 7.4: credentials are typed on the hosted authorization page
  // and nowhere else. A widget cannot authenticate an MCP connection.
  assert.doesNotMatch(html, /type\s*=\s*["']password["']/i);
  assert.doesNotMatch(html, /name\s*=\s*["']password["']/i);
  assert.match(html, /list_devices/, 'it asks for a protected read to trigger the host challenge');
  assert.doesNotMatch(html, /control_device|add_device/,
    'authentication must never be triggered by a mutation');
});

/* ------------------------------------------------- review regression tests */

test('a refresh asked to keep the message never clears it', () => {
  /*
   * Source-level, deliberately. This bug was found by rendering the view in
   * tools/mock-host and watching the status area, not by any assertion here:
   * the conflict handler set a message and then called a refresh whose
   * success branch cleared it, so the explanation existed for a few hundred
   * milliseconds and was never seen. Sampling the element twenty-four times
   * caught it empty every time.
   *
   * Reproducing that in a unit test needs a DOM; what is cheap to guard is
   * the shape of the mistake — an unguarded clear inside the reload.
   */
  for (const controlling of [view('devices'), view('device')]) {
    assert.match(controlling.html, /keepMessage/, `${controlling.uri} lost the keepMessage flag`);
    // The inverted flag that caused it.
    assert.doesNotMatch(controlling.html, /options\.quiet/, `${controlling.uri} still has the quiet flag`);
    // Every status write inside a reload has to be guarded by it.
    assert.doesNotMatch(controlling.html, /if \(options\.quiet\) say\(/, controlling.uri);
  }
});

test('a version conflict explains itself with what the device actually is', () => {
  // Spec section 5.6 step 7: refetch *and* explain. Reporting only that they
  // were too late leaves the person guessing what the device is now.
  for (const controlling of [view('devices'), view('device')]) {
    assert.match(controlling.html, /changed somewhere else, so your change was not applied/, controlling.uri);
    assert.match(controlling.html, /It is now /, `${controlling.uri} omits the reconciled state`);
  }
});

test('the detail view does not offer a refresh before it has a device', () => {
  const html = view('device').html;
  // The view learns which device it is showing from a host-pushed tool
  // result. Until one arrives the control cannot do anything, and a button
  // that silently does nothing is worse than one that is plainly unavailable.
  assert.match(html, /id="refresh" type="button" disabled/);
  assert.match(html, /\$\('refresh'\)\.disabled = false;/);
});
