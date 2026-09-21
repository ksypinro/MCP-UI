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

  function post(message) {
    window.parent.postMessage(message, '*');
  }

  function request(method, params, timeoutMs) {
    var id = nextId++;
    post({ jsonrpc: '2.0', id: id, method: method, params: params || {} });
    return new Promise(function (resolve, reject) {
      pending.set(id, { resolve: resolve, reject: reject });
      setTimeout(function () {
        if (!pending.has(id)) return;
        pending.delete(id);
        reject(new Error(method + ' timed out'));
      }, timeoutMs || 60000);
    });
  }

  function notify(method, params) {
    post({ jsonrpc: '2.0', method: method, params: params || {} });
  }

  /**
   * Adds a handler. Several may listen to one notification.
   *
   * This used to overwrite, which meant a view listening for
   * host-context-changed silently replaced the bridge's own handling of it —
   * so the bridge never learned the display mode had changed, and the view
   * asking for fullscreen was granted it and then rendered as if inline.
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

    var message = event.data;
    if (!message || message.jsonrpc !== '2.0') return;

    if (message.id !== undefined && (message.result !== undefined || message.error !== undefined)) {
      var waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      if (message.error) {
        var error = new Error(message.error.message || 'The host refused that request.');
        error.rpc = message.error;
        waiter.reject(error);
      } else {
        waiter.resolve(message.result);
      }
      return;
    }

    if (message.method) {
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

  function applyHostContext(context) {
    hostContext = context || {};
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
    hostCapabilities: function () { return hostCapabilities; },
    displayMode: function () { return hostContext.displayMode || 'inline'; },

    /** Calls a tool through the host. The host decides whether to forward it. */
    callTool: function (name, args) {
      return request('tools/call', { name: name, arguments: args || {} }).then(function (result) {
        if (result && result.isError) {
          var text = result.content && result.content[0] && result.content[0].text;
          var structured = result.structuredContent || {};
          var error = new Error((structured.error && structured.error.message) || text || 'That did not work.');
          // Argument validation is rejected by the server SDK before our
          // handler runs and carries no structuredContent, so the code may
          // legitimately be absent.
          error.code = structured.error && structured.error.code;
          throw error;
        }
        return (result && result.structuredContent) || {};
      });
    },

    requestDisplayMode: function (mode) {
      return request('ui/request-display-mode', { mode: mode });
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
        appCapabilities: {
          availableDisplayModes: options.displayModes || ['inline']
        }
      }, 15000).then(function (result) {
        notify('ui/notifications/initialized', {});
        hostCapabilities = (result && result.hostCapabilities) || {};
        applyHostContext(result && result.hostContext);
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
