/**
 * The host bridge, exercised rather than grepped.
 *
 * It is shared by all four views, so a fault here is a fault everywhere. It is
 * plain browser JavaScript, so it runs in a vm with just enough of a window to
 * behave normally.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createContext, runInContext } from 'node:vm';

const bridgeSource = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'mcp', 'ui', 'assets', 'bridge.js'),
  'utf8'
);

interface Loaded {
  app: any;
  sent: any[];
  deliver: (message: unknown, source?: unknown) => void;
  window: any;
}

function loadBridge(): Loaded {
  const sent: any[] = [];
  const listeners: Record<string, ((event: any) => void)[]> = {};

  const parent = { postMessage: (message: unknown) => { sent.push(message); } };
  const window: any = {
    parent,
    innerWidth: 402,
    addEventListener: (type: string, handler: (event: any) => void) => {
      (listeners[type] ??= []).push(handler);
    },
    setTimeout: (fn: () => void, ms: number) => setTimeout(fn, ms)
  };
  window.self = window;

  const document = {
    documentElement: {
      scrollHeight: 300,
      style: { setProperty: () => {} },
      setAttribute: () => {}
    }
  };

  const context = createContext({ window, document, setTimeout, clearTimeout, Promise, Map, Error, String, Boolean });
  runInContext(bridgeSource, context);

  return {
    app: window.mcpApp,
    sent,
    window,
    deliver: (message, source = parent) => {
      for (const handler of listeners.message ?? []) handler({ source, data: message });
    }
  };
}

test('the bridge exposes an app once evaluated', () => {
  const { app } = loadBridge();
  assert.equal(typeof app.start, 'function');
  assert.equal(typeof app.callTool, 'function');
  assert.equal(typeof app.on, 'function');
});

test('several handlers can listen to one notification', () => {
  // This is the bug that made "Show all" appear to do nothing: registering a
  // handler used to overwrite, so a view listening for host-context-changed
  // silently replaced the bridge's own handling of it. The bridge never
  // learned the display mode had changed, and the view was granted fullscreen
  // and then rendered as if it were still inline.
  const { app, deliver } = loadBridge();
  const calls: string[] = [];

  app.on('ui/notifications/tool-result', () => calls.push('first'));
  app.on('ui/notifications/tool-result', () => calls.push('second'));

  deliver({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: {} });

  assert.deepEqual(calls, ['first', 'second']);
});

test('the bridge keeps its own host-context handling when a view adds one', () => {
  const { app, deliver } = loadBridge();
  let viewSaw = false;
  app.on('ui/notifications/host-context-changed', () => { viewSaw = true; });

  deliver({
    jsonrpc: '2.0',
    method: 'ui/notifications/host-context-changed',
    params: { hostContext: { displayMode: 'fullscreen', safeAreaInsets: { top: 4 } } }
  });

  assert.ok(viewSaw, 'the view heard it');
  assert.equal(app.displayMode(), 'fullscreen', 'and so did the bridge');
});

test('one broken handler does not stop the others', () => {
  const { app, deliver } = loadBridge();
  let reached = false;
  app.on('ui/notifications/tool-result', () => { throw new Error('boom'); });
  app.on('ui/notifications/tool-result', () => { reached = true; });

  deliver({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: {} });

  assert.ok(reached, 'a misbehaving listener must not break the bridge for the rest');
});

test('messages from anything but the host are ignored', () => {
  const { app, deliver } = loadBridge();
  let called = false;
  app.on('ui/notifications/tool-result', () => { called = true; });

  // Origin is unpredictable inside a sandbox, so the sender is identified by
  // window reference instead.
  deliver({ jsonrpc: '2.0', method: 'ui/notifications/tool-result', params: {} }, { imposter: true });

  assert.equal(called, false);
});

test('a size is reported once, and again only when it changes', () => {
  const { app, sent, window } = loadBridge();

  app.reportSize();
  app.reportSize();
  const first = sent.filter((m) => m.method === 'ui/notifications/size-changed');
  assert.equal(first.length, 1, 'an unchanged size is not echoed');

  window.innerWidth = 500;
  app.reportSize();
  const second = sent.filter((m) => m.method === 'ui/notifications/size-changed');
  assert.equal(second.length, 2);
});

test('a tool error carries its code through to the view', async () => {
  const { app, sent, deliver } = loadBridge();

  const pending = app.callTool('control_device', { deviceId: 'dev_1' });
  const request = sent.find((m) => m.method === 'tools/call');
  assert.ok(request, 'the call was sent to the host');

  deliver({
    jsonrpc: '2.0',
    id: request.id,
    result: {
      isError: true,
      content: [{ type: 'text', text: 'This device changed.' }],
      // In _meta, not structuredContent: a client validates structuredContent
      // against the tool's output schema whenever it is present, and an error
      // is not the shape that schema describes.
      _meta: { 'iot/error': { code: 'DEVICE_VERSION_CONFLICT', message: 'This device changed.' } }
    }
  });

  await assert.rejects(pending, (error: any) => {
    assert.equal(error.code, 'DEVICE_VERSION_CONFLICT');
    return true;
  });
});

test('a tool result with no structuredContent still rejects cleanly', async () => {
  // Argument validation is rejected by the server SDK before our handler runs
  // and carries no structuredContent, so the code is legitimately absent.
  const { app, sent, deliver } = loadBridge();
  const pending = app.callTool('control_device', { state: 'dim' });
  const request = sent.find((m) => m.method === 'tools/call');

  deliver({
    jsonrpc: '2.0',
    id: request.id,
    result: { isError: true, content: [{ type: 'text', text: 'Invalid arguments' }] }
  });

  await assert.rejects(pending, (error: any) => {
    assert.match(error.message, /Invalid arguments/);
    assert.equal(error.code, undefined);
    return true;
  });
});

test('the handshake reports the display modes the view supports', async () => {
  const { app, sent, deliver } = loadBridge();

  const started = app.start({ displayModes: ['inline', 'fullscreen'] });
  const request = sent.find((m) => m.method === 'ui/initialize');
  assert.deepEqual(request.params.appCapabilities.availableDisplayModes, ['inline', 'fullscreen']);

  deliver({
    jsonrpc: '2.0', id: request.id,
    result: { hostCapabilities: { availableDisplayModes: ['inline'] }, hostContext: { displayMode: 'inline' } }
  });
  await started;

  // And announces itself ready only after the host has answered.
  assert.ok(sent.some((m) => m.method === 'ui/notifications/initialized'));
  assert.deepEqual(app.hostCapabilities().availableDisplayModes, ['inline']);
});
