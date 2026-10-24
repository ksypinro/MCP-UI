/**
 * The MCP Apps host bridge, shared by every view.
 *
 * One implementation on purpose. Two copies of a protocol handshake do not
 * stay identical, and the list and detail views exercise the same one.
 *
 * Nothing here ever holds a token. Protected data arrives only as the result
 * of a tool call the host chose to forward.
 */
(function () {
  'use strict';

  var nextId = 1;
  var pending = new Map();
  var handlers = new Map();
  var hostContext = {};
  var hostCapabilities = {};

  /**
   * The host's origin, learned from its answer to ui/initialize.
   *
   * Until then it is unknown — the sandbox proxy's origin is assigned by the
   * host — so the handshake request alone goes out with '*'. It carries
   * nothing but our name and version. Everything after it, including every
   * tool call, is addressed to the pinned origin, and anything arriving from
   * another origin is dropped. Posting with '*' throughout is the defect
   * behind CVE-2026-76894.
   */
  var hostOrigin = null;

  /**
   * With diagnostics on (UI_DIAGNOSTICS=1 on the server), a short record of
   * what the host sent: which messages, which fields, and the display mode
   * whenever one is mentioned. Never values that could be personal: device
   * data and tool results are reduced to their field names.
   */
  var tracing = Boolean(document.body && document.body.hasAttribute && document.body.hasAttribute('data-diagnostics'));
  var trace = [];
  var started = Date.now();

  function note(kind, method, payload) {
    if (!tracing) return;
    var fields = payload && typeof payload === 'object' ? Object.keys(payload) : [];
    var context = payload && (payload.hostContext || payload);
    var mode = context && (context.displayMode || context.mode);
    trace.push(((Date.now() - started) / 1000).toFixed(1) + 's ' + kind + ' ' + method
      + (fields.length ? ' {' + fields.join(',') + '}' : '')
      + (typeof mode === 'string' ? ' mode=' + mode : ''));
    if (trace.length > 40) trace.shift();
    var listeners = handlers.get('diagnostics');
    if (listeners) for (var i = 0; i < listeners.length; i++) { try { listeners[i](); } catch (e) { /* ignored */ } }
  }

  function post(message) {
    window.parent.postMessage(message, hostOrigin || '*');
  }

  function request(method, params, timeoutMs) {
    var id = nextId++;
    post({ jsonrpc: '2.0', id: id, method: method, params: params || {} });
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () {
        if (!pending.has(id)) return;
        pending.delete(id);
        reject(new Error(method + ' timed out'));
      }, timeoutMs || 60000);
      pending.set(id, { resolve: resolve, reject: reject, method: method, timer: timer });
    });
  }

  function notify(method, params) {
    post({ jsonrpc: '2.0', method: method, params: params || {} });
  }

  /**
   * Adds a handler. Several may listen to one notification: a view that
   * listens for host-context-changed must not replace the bridge's own
   * handling of it, or the bridge never learns the display mode changed and
   * a view granted fullscreen renders as if inline.
   */
  function on(method, handler) {
    var existing = handlers.get(method);
    if (existing) existing.push(handler);
    else handlers.set(method, [handler]);
  }

  // Registered before ui/initialize is ever sent. A host may push tool-input
  // or tool-result the instant the handshake completes, and a listener added
  // afterwards misses it.
  window.addEventListener('message', function (event) {
    // Only the host may drive this view. Origin is unpredictable inside a
    // sandbox, so the sender is identified by window reference instead.
    if (event.source !== window.parent) return;
    // Once pinned, the host's origin must match as well.
    if (hostOrigin && event.origin !== hostOrigin) return;

    var message = event.data;
    if (!message || typeof message !== 'object' || message.jsonrpc !== '2.0') return;

    if (message.id !== undefined && (message.result !== undefined || message.error !== undefined)) {
      var waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      note('reply', waiter.method, message.error ? { error: message.error.message } : message.result);
      // A sandboxed frame without allow-same-origin reports "null", which is
      // not an origin anything can be addressed to; stay unpinned and keep
      // relying on the source check above.
      if (waiter.method === 'ui/initialize' && !hostOrigin
          && typeof event.origin === 'string' && event.origin && event.origin !== 'null') {
        hostOrigin = event.origin;
      }
      if (message.error) {
        var error = new Error(message.error.message || 'The host refused that request.');
        error.rpc = message.error;
        waiter.reject(error);
      } else {
        waiter.resolve(message.result);
      }
      return;
    }

    if (typeof message.method === 'string') {
      // Notifications carry an object or nothing. Anything else is malformed
      // and is dropped rather than handed to a view.
      if (message.params !== undefined && (typeof message.params !== 'object' || message.params === null)) return;
      note('event', message.method, message.params);
      var listeners = handlers.get(message.method);
      if (listeners) {
        for (var i = 0; i < listeners.length; i++) {
          // One misbehaving listener must not stop the others, or break the
          // bridge for the rest of the session.
          try { listeners[i](message.params || {}); } catch (e) { /* ignored */ }
        }
      }
    }
  });

  /* ------------------------------------------------------------ sizing */

  var lastReported = '';

  function reportSize() {
    var width = window.innerWidth;
    var height = document.documentElement.scrollHeight;
    var reported = width + 'x' + height;
    // Only when it actually changed. The host may resize us in response,
    // which fires resize, which lands back here; echoing an unchanged value
    // turns that into an unbounded loop.
    if (reported === lastReported) return;
    lastReported = reported;
    notify('ui/notifications/size-changed', { width: width, height: height });
  }

  /* ------------------------------------------------------- host context */

  /**
   * `replace` is for the context ui/initialize returns, which is complete.
   * host-context-changed carries only the fields that changed (MCP Apps
   * 2026-01-26), so it is merged. Replacing it lost the display mode whenever
   * a host sent, say, only new container dimensions: Claude web granted
   * fullscreen and the list stayed at four rows.
   */
  function applyHostContext(context, replace) {
    hostContext = replace ? (context || {}) : Object.assign({}, hostContext, context || {});
    var insets = hostContext.safeAreaInsets || {};
    var root = document.documentElement;
    // Safe areas come from the host, not from CSS env(): inside a chat
    // WebView the page is not the thing the notch overlaps, and a control
    // rendered outside them cannot be tapped at all.
    root.style.setProperty('--safe-top', (insets.top || 0) + 'px');
    root.style.setProperty('--safe-right', (insets.right || 0) + 'px');
    root.style.setProperty('--safe-bottom', (insets.bottom || 0) + 'px');
    root.style.setProperty('--safe-left', (insets.left || 0) + 'px');
    if (hostContext.displayMode) root.setAttribute('data-display-mode', hostContext.displayMode);
    reportSize();
  }

  /* ---------------------------------------------------------------- API */

  var app = {
    hostContext: function () { return hostContext; },
    hostOrigin: function () { return hostOrigin; },
    hostCapabilities: function () { return hostCapabilities; },
    diagnostics: function () { return tracing ? trace.slice() : null; },
    displayMode: function () { return hostContext.displayMode || 'inline'; },

    /** Calls a tool through the host. The host decides whether to forward it. */
    callTool: function (name, args) {
      return request('tools/call', { name: name, arguments: args || {} }).then(function (result) {
        if (result && result.isError) {
          var text = result.content && result.content[0] && result.content[0].text;
          // The code travels in _meta rather than structuredContent, because a
          // client validates structuredContent against the tool's output
          // schema whenever it is present — including on an error, where the
          // schema describes a shape the error is not.
          var meta = (result._meta && result._meta['iot/error']) || {};
          var error = new Error(meta.message || text || 'That did not work.');
          // Argument validation is rejected before our handler runs and
          // carries no code at all, so it may legitimately be absent.
          error.code = meta.code;
          throw error;
        }
        return (result && result.structuredContent) || {};
      });
    },

    /**
     * Resolves with the mode the host actually set, which may differ from the
     * one asked for. The answer is applied at once rather than waiting for a
     * host-context-changed that a host may send late, partially, or not at all.
     */
    requestDisplayMode: function (mode) {
      return request('ui/request-display-mode', { mode: mode }).then(function (result) {
        var granted = (result && result.mode) || mode;
        applyHostContext({ displayMode: granted });
        return granted;
      });
    },

    openLink: function (url) {
      return request('ui/open-link', { url: url });
    },

    sendToChat: function (text) {
      return request('ui/message', { content: [{ type: 'text', text: text }] });
    },

    on: on,
    reportSize: reportSize,

    /** Completes the handshake. Call last, once the view is ready. */
    start: function (options) {
      options = options || {};
      return request('ui/initialize', {
        appInfo: { name: 'IoT Switch', version: '0.1.0' },
        protocolVersion: '2026-01-26',
        appCapabilities: {
          availableDisplayModes: options.displayModes || ['inline']
        }
      }, 15000).then(function (result) {
        notify('ui/notifications/initialized', {});
        hostCapabilities = (result && result.hostCapabilities) || {};
        applyHostContext(result && result.hostContext, true);
        return result || {};
      });
    }
  };

  on('ui/notifications/host-context-changed', function (params) {
    applyHostContext((params && params.hostContext) || params);
  });

  window.addEventListener('resize', reportSize);

  window.mcpApp = app;
})();
