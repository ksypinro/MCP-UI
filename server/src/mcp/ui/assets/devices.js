/**
 * The device list. Spec sections 5.3, 5.6 and 9.3.
 *
 * Inline, this renders a bounded summary rather than the whole list. On a
 * phone the conversation owns vertical scrolling: a pan starting inside an
 * inline card scrolls the chat, not the card, and the host caps inline height
 * and clips whatever overflows. A long list rendered inline is therefore
 * partly unreachable, not merely ugly.
 */
(function () {
  'use strict';
  var app = window.mcpApp;
  var $ = function (id) { return document.getElementById(id); };

  /**
   * How many rows to show inline before offering fullscreen.
   *
   * NOT MEASURED. Four is Claude's published guidance for an inline card
   * ("roughly four to five data points"), not an observation of what actually
   * fits on a device. Question 2 in spike/FINDINGS.md exists to replace this
   * with a real number; when it is answered, change this constant.
   */
  var INLINE_ROW_BUDGET = 4;

  var devices = [];
  var pending = Object.create(null);   // device id -> the state we asked for
  var loaded = false;

  function isFullscreen() { return app.displayMode() === 'fullscreen'; }
  function budget() { return isFullscreen() ? devices.length : INLINE_ROW_BUDGET; }

  function say(text, bad) {
    var el = $('status');
    el.textContent = text || '';
    el.className = 'notice' + (bad ? ' bad' : '');
    el.hidden = !text;
    app.reportSize();
  }

  function render() {
    var list = $('list');
    list.textContent = '';

    var shown = devices.slice(0, budget());
    shown.forEach(function (device) { list.appendChild(row(device)); });

    var hidden = devices.length - shown.length;
    $('more').hidden = hidden <= 0;
    $('more').textContent = hidden > 0
      ? hidden + ' more device' + (hidden === 1 ? '' : 's') + ' not shown here.'
      : '';
    // Only offer fullscreen when the host said it can do it and there is
    // something to reveal.
    $('expand').hidden = hidden <= 0 || !hostSupportsFullscreen();

    $('summary').textContent = devices.length === 0
      ? 'No devices yet. Ask to add one.'
      : devices.length + ' device' + (devices.length === 1 ? '' : 's') + '.';

    app.reportSize();
  }

  function hostSupportsFullscreen() {
    var modes = (app.hostCapabilities() || {}).availableDisplayModes;
    return !modes || modes.indexOf('fullscreen') !== -1;
  }

  function row(device) {
    var li = document.createElement('li');
    li.className = 'row';

    var icon = document.createElement('div');
    icon.className = 'icon';
    icon.textContent = '◍';
    icon.setAttribute('aria-hidden', 'true');

    var meta = document.createElement('div');
    meta.className = 'meta';

    var name = document.createElement('div');
    name.className = 'name';
    // textContent, never innerHTML: a device name is a user-supplied string
    // and this template is otherwise static.
    name.textContent = device.name;

    var intent = pending[device.id];
    var state = document.createElement('div');
    state.className = 'state';
    // Text as well as switch position: colour alone must not carry the state.
    state.textContent = intent
      ? 'Changing to ' + label(intent) + '…'
      : label(device.state);

    meta.appendChild(name);
    meta.appendChild(state);

    var hit = document.createElement('div');
    hit.className = 'sw-hit';

    var sw = document.createElement('button');
    sw.className = 'sw';
    sw.type = 'button';
    sw.setAttribute('role', 'switch');
    sw.setAttribute('aria-checked', String((intent || device.state) === 'on'));
    sw.setAttribute('aria-label', device.name);
    if (intent) sw.disabled = true;
    sw.addEventListener('click', function () { control(device); });
    hit.appendChild(sw);

    li.appendChild(icon);
    li.appendChild(meta);
    li.appendChild(hit);
    return li;
  }

  function label(state) { return state === 'on' ? 'On' : 'Off'; }

  function replace(device) {
    for (var i = 0; i < devices.length; i++) {
      if (devices[i].id === device.id) { devices[i] = device; return; }
    }
    devices.push(device);
  }

  /* ------------------------------------------------------------- control */

  function control(device) {
    if (pending[device.id]) return;          // one change at a time, per device
    var desired = device.state === 'on' ? 'off' : 'on';

    // Capture the version that was on screen. Everything below uses this
    // snapshot rather than re-reading state that may have moved.
    var expectedVersion = device.version;
    pending[device.id] = desired;
    render();

    app.callTool('control_device', {
      deviceId: device.id, state: desired, expectedVersion: expectedVersion
    }).then(function (data) {
      replace(data.device);
      say('');
    }).catch(function (error) {
      if (error.code === 'DEVICE_VERSION_CONFLICT') {
        // Refetch so the user is told what it actually is, not merely that
        // they were too late.
        say(device.name + ' changed somewhere else. Refreshing…');
        return load({ quiet: true });
      }
      if (error.code === 'DEVICE_NOT_FOUND') {
        devices = devices.filter(function (d) { return d.id !== device.id; });
        say(device.name + ' is no longer available on this account.', true);
        return;
      }
      // Never assume the write landed, and never send the inverse command:
      // that is how a switch ends up flipping itself back.
      say('Could not change ' + device.name + ': ' + (error.message || 'unknown error'), true);
    }).then(function () {
      delete pending[device.id];
      render();
    });
  }

  /* ---------------------------------------------------------------- load */

  function load(options) {
    options = options || {};
    if (!options.quiet) say('');
    return app.callTool('list_devices', {}).then(function (data) {
      devices = data.devices || [];
      loaded = true;
      render();
      if (options.quiet) say('');
    }).catch(function (error) {
      if (loaded) {
        // Keep showing what we have, labelled as old rather than as current.
        say('Could not refresh. Showing devices from an earlier update.', true);
      } else {
        $('summary').textContent = 'Could not load your devices.';
        say(error.message || 'Could not load your devices.', true);
      }
    });
  }

  /* ----------------------------------------------------------- lifecycle */

  $('refresh').addEventListener('click', function () { load(); });
  $('expand').addEventListener('click', function () {
    app.requestDisplayMode('fullscreen').then(function () {
      render();
    }).catch(function () {
      // Refused: say so rather than leaving a button that appears broken.
      $('expand').hidden = true;
      say('This host cannot show a larger view. Ask for the full list in the conversation.', true);
    });
  });

  // The host may push the result that caused this view to be rendered, which
  // saves a round trip and is the only data available if the host declines to
  // forward further calls.
  app.on('ui/notifications/tool-result', function (params) {
    var incoming = params && params.result && params.result.structuredContent;
    if (incoming && Array.isArray(incoming.devices)) {
      devices = incoming.devices;
      loaded = true;
      render();
    }
  });

  app.on('ui/notifications/host-context-changed', function () { render(); });

  app.start({ displayModes: ['inline', 'fullscreen'] }).then(function () {
    if (!loaded) return load();
  }).catch(function () {
    $('summary').textContent = 'Could not reach the host.';
  });
}());
