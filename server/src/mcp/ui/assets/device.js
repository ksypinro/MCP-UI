/**
 * One device. Spec section 5.4, mirrored for the MCP surface: the same control
 * behaviour as the list, because two copies of a state machine do not stay
 * identical.
 */
(function () {
  'use strict';
  var app = window.mcpApp;
  var $ = function (id) { return document.getElementById(id); };

  var device = null;
  var pending = null;

  function label(state) { return state === 'on' ? 'On' : 'Off'; }

  function say(text, bad) {
    var el = $('status');
    el.textContent = text || '';
    el.className = 'notice' + (bad ? ' bad' : '');
    el.hidden = !text;
    app.reportSize();
  }

  function render() {
    if (!device) return;
    $('name').textContent = device.name;
    $('state').textContent = pending ? 'Changing to ' + label(pending) + '…' : label(device.state);

    var sw = $('switch');
    sw.setAttribute('aria-checked', String((pending || device.state) === 'on'));
    sw.setAttribute('aria-label', device.name);
    sw.disabled = Boolean(pending);

    $('refresh').disabled = false;
    $('id').textContent = device.id;
    $('updated').textContent = formatTime(device.updatedAt);
    $('detail').hidden = false;
    app.reportSize();
  }

  function formatTime(value) {
    try {
      return new Date(value).toLocaleString();
    } catch (e) {
      return value;
    }
  }

  function control() {
    if (!device || pending) return;
    var desired = device.state === 'on' ? 'off' : 'on';
    var expectedVersion = device.version;

    pending = desired;
    render();

    app.callTool('control_device', {
      deviceId: device.id, state: desired, expectedVersion: expectedVersion
    }).then(function (data) {
      device = data.device;
      say('');
    }).catch(function (error) {
      if (error.code === 'DEVICE_VERSION_CONFLICT') {
        // Refetch first, then explain with what it actually is. Saying it
        // before the refresh meant the refresh cleared it again.
        return refresh({ keepMessage: true }).then(function (fresh) {
          say('This device was changed somewhere else, so your change was not applied.'
            + (fresh && device ? ' It is now ' + label(device.state) + '.' : ''), true);
        });
      }
      if (error.code === 'DEVICE_NOT_FOUND') {
        say('This device is no longer available on this account.', true);
        return;
      }
      say('Could not change it: ' + (error.message || 'unknown error'), true);
    }).then(function () {
      pending = null;
      render();
    });
  }

  /**
   * Reloads the device. Resolves true when fresh data arrived.
   *
   * `keepMessage` means leave the status alone: the caller has something to
   * say that matters more than anything reported here.
   */
  function refresh(options) {
    options = options || {};
    var keep = Boolean(options.keepMessage);
    if (!device) {
      // The Refresh control is disabled until a device arrives, so this is
      // only reachable programmatically.
      return Promise.resolve(false);
    }
    return app.callTool('get_device', { deviceId: device.id }).then(function (data) {
      device = data.device;
      render();
      return true;
    }).catch(function (error) {
      if (!keep) say(error.message || 'Could not refresh.', true);
      return false;
    });
  }

  $('switch').addEventListener('click', control);
  $('refresh').addEventListener('click', function () { refresh(); });

  app.on('ui/notifications/tool-result', function (params) {
    var incoming = params && params.result && params.result.structuredContent;
    if (incoming && incoming.device) {
      device = incoming.device;
      render();
    }
  });

  app.start({ displayModes: ['inline'] }).then(function () {
    if (!device) $('state').textContent = 'Ask for a device to see it here.';
  }).catch(function () {
    $('state').textContent = 'Could not reach the host.';
  });
}());
