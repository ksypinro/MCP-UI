/**
 * The authentication entry card. Spec section 7.4.
 *
 * It contains no credential fields, and it cannot authenticate anything
 * itself. Both buttons do the same thing: ask for a protected read and let the
 * host decide how to obtain credentials. That is the MCP Apps authorization
 * model — the host intercepts the 401, runs OAuth, and retries.
 */
(function () {
  'use strict';
  var app = window.mcpApp;
  var $ = function (id) { return document.getElementById(id); };

  function say(text, bad) {
    var el = $('status');
    el.textContent = text;
    el.className = 'notice' + (bad ? ' bad' : '');
    el.hidden = !text;
    app.reportSize();
  }

  function begin() {
    $('login').disabled = true;
    $('signup').disabled = true;
    say('Waiting for the host to authorize…');

    // A protected READ, never a mutation. A host that retries the call after
    // authorizing would otherwise perform the write as a side effect of
    // signing in.
    app.callTool('list_devices', {}).then(function (data) {
      var count = (data.devices || []).length;
      $('lede').textContent = 'Signed in.';
      say(count === 0
        ? 'Signed in. You have no devices yet — ask to add one.'
        : 'Signed in. You have ' + count + ' device' + (count === 1 ? '' : 's') + '. Ask to see them.');
    }).catch(function (error) {
      say(error.message || 'Not authorized yet.', true);
    }).then(function () {
      $('login').disabled = false;
      $('signup').disabled = false;
    });
  }

  $('login').addEventListener('click', begin);
  $('signup').addEventListener('click', begin);

  app.start({ displayModes: ['inline'] }).then(function () {
    // Public, so it never triggers a challenge: it only reports whether the
    // host already holds a token.
    return app.callTool('get_auth_status', {});
  }).then(function (status) {
    if (status && status.authenticated) {
      $('lede').textContent = 'Signed in as ' + (status.username || 'this account') + '.';
      say('Ask to see your devices.');
    }
  }).catch(function () {
    /* The card is still useful signed out; nothing to report. */
  });
}());
