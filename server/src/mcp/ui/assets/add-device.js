/**
 * The add-device form. Spec section 5.5, mirrored for the MCP surface: one
 * field, and the entered name survives every failure.
 */
(function () {
  'use strict';
  var app = window.mcpApp;
  var $ = function (id) { return document.getElementById(id); };
  var busy = false;

  function fieldError(text) {
    var el = $('name-error');
    el.textContent = text || '';
    el.hidden = !text;
    app.reportSize();
  }

  function say(text, bad) {
    var el = $('status');
    el.textContent = text || '';
    el.className = 'notice' + (bad ? ' bad' : '');
    el.hidden = !text;
    app.reportSize();
  }

  function submit() {
    if (busy) return;
    fieldError('');
    say('');

    var name = $('name').value.trim();
    if (!name) { fieldError('Enter a name for this device.'); return; }
    if (name.length > 64) { fieldError('Device names can be at most 64 characters.'); return; }

    busy = true;
    $('submit').disabled = true;
    $('submit').textContent = 'Adding…';

    app.callTool('add_device', { name: name }).then(function (data) {
      var device = data.device;
      // Cleared only on success: every failure path keeps what was typed.
      $('name').value = '';
      say('Added ' + device.name + '. It starts Off.');
    }).catch(function (error) {
      if (error.code === 'DEVICE_NAME_CONFLICT') {
        fieldError('A device with this name already exists.');
      } else if (error.code === 'DEVICE_LIMIT_REACHED') {
        say('You have reached the maximum number of devices.', true);
      } else {
        say(error.message || 'Could not add that device.', true);
      }
    }).then(function () {
      busy = false;
      $('submit').disabled = false;
      $('submit').textContent = 'Add Device';
      app.reportSize();
    });
  }

  $('submit').addEventListener('click', submit);
  $('name').addEventListener('keydown', function (event) {
    if (event.key === 'Enter') submit();
  });

  app.start({ displayModes: ['inline'] });
}());
