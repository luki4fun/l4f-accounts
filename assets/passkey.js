// Passkeys: add one, sign in with one, use one as the second step or to
// confirm it's you. Wired to buttons carrying data-passkey="add|login|mfa|step-up",
// which stay hidden where the browser cannot do this. No inline script (CSP)
// and no HTML strings (Trusted Types): text goes in with textContent only.
(function () {
  'use strict';
  var PK = window.PublicKeyCredential;
  var ok = PK && typeof PK.parseCreationOptionsFromJSON === 'function' && typeof PK.parseRequestOptionsFromJSON === 'function';

  function post(url, body, csrf) {
    var headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF'] = csrf;
    return fetch(url, { method: 'POST', headers: headers, body: JSON.stringify(body), credentials: 'same-origin' })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) throw new Error(j.error || 'Something went wrong. Please try again.');
          return j;
        });
      });
  }

  function run(b) {
    var what = b.dataset.passkey, base = b.dataset.base || '/account', csrf = b.dataset.csrf || '';
    var out = document.getElementById(b.dataset.status || '');
    var say = function (t) { if (out) out.textContent = t; };
    say('');
    b.disabled = true;
    post(base + '/passkey/options/' + what, {}, csrf)
      .then(function (o) {
        var p = what === 'add'
          ? navigator.credentials.create({ publicKey: PK.parseCreationOptionsFromJSON(o.options) })
          : navigator.credentials.get({ publicKey: PK.parseRequestOptionsFromJSON(o.options) });
        return p.then(function (cred) {
          var name = document.getElementById('passkey-name');
          return post(base + '/passkey/' + what, {
            token: o.token, credential: cred.toJSON(), name: name ? name.value : '', next: b.dataset.next || ''
          }, csrf);
        });
      })
      .then(function (r) { location.assign(r.next); })
      .catch(function (e) {
        say(e && e.name === 'NotAllowedError' ? 'Cancelled, or no passkey for this site on this device.' : (e && e.message) || 'Something went wrong.');
        b.disabled = false;
      });
  }

  document.querySelectorAll('[data-passkey]').forEach(function (b) {
    if (!ok) return;
    b.hidden = false;
    b.addEventListener('click', function () { run(b); });
  });
  document.querySelectorAll('[data-passkey-only]').forEach(function (el) { el.hidden = !ok; });
})();
