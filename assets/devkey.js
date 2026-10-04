// Remembered browsers: a non-extractable Ed25519 key kept in IndexedDB signs a
// challenge, so this browser signs its account in with one click. Buttons:
// data-devkey="add" (security page) and data-devkey="login" (sign-in page,
// shown only when this browser holds a key). No inline script, no HTML strings.
(function () {
  'use strict';
  var DB = 'l4f-account', STORE = 'devkey', SLOT = 'this';
  var enc = new TextEncoder();

  function idb(mode, fn) {
    return new Promise(function (ok, no) {
      var open = indexedDB.open(DB, 1);
      open.onupgradeneeded = function () { open.result.createObjectStore(STORE); };
      open.onerror = function () { no(open.error); };
      open.onsuccess = function () {
        var db = open.result, tx = db.transaction(STORE, mode), req = fn(tx.objectStore(STORE));
        tx.oncomplete = function () { db.close(); ok(req.result); };
        tx.onerror = function () { db.close(); no(tx.error); };
      };
    });
  }
  var load = function () { return idb('readonly', function (s) { return s.get(SLOT); }); };
  var save = function (v) { return idb('readwrite', function (s) { return s.put(v, SLOT); }); };
  var forget = function () { return idb('readwrite', function (s) { return s.delete(SLOT); }); };

  function b64u(bytes) {
    var s = '';
    new Uint8Array(bytes).forEach(function (b) { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function concat(parts) {
    var n = parts.reduce(function (a, p) { return a + p.length; }, 0), out = new Uint8Array(n), i = 0;
    parts.forEach(function (p) { out.set(p, i); i += p.length; });
    return out;
  }
  // "l4f-devkey-v1\0" || origin || "\0" || device id || "\0" || SHA-256(token)
  function sign(key, id, token) {
    return crypto.subtle.digest('SHA-256', enc.encode(token)).then(function (ch) {
      var msg = concat([enc.encode('l4f-devkey-v1\0' + location.origin + '\0'), id, new Uint8Array([0]), new Uint8Array(ch)]);
      return crypto.subtle.sign({ name: 'Ed25519' }, key, msg);
    });
  }
  function post(url, body, csrf) {
    var headers = { 'Content-Type': 'application/json' };
    if (csrf) headers['X-CSRF'] = csrf;
    return fetch(url, { method: 'POST', headers: headers, body: JSON.stringify(body), credentials: 'same-origin' })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) { var e = new Error(j.error || 'Something went wrong. Please try again.'); e.status = r.status; throw e; }
          return j;
        });
      });
  }

  function add(b) {
    var base = b.dataset.base, csrf = b.dataset.csrf, id = crypto.getRandomValues(new Uint8Array(16)), pair, token;
    return post(base + '/devkey/options/add', {}, csrf)
      .then(function (o) { token = o.token; return crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']); })
      .then(function (p) { pair = p; return save({ id: id, key: p.privateKey, user: b.dataset.user || '' }); })
      // Stored and read back before the server learns of it: some browsers
      // cannot keep a CryptoKey in IndexedDB, and a key that is gone after a
      // reload must never be enrolled.
      .then(load)
      .then(function (rec) {
        if (!rec || !rec.key) throw new Error('This browser cannot keep the key.');
        return Promise.all([crypto.subtle.exportKey('raw', pair.publicKey), sign(rec.key, id, token)]);
      })
      .then(function (r) {
        return post(base + '/devkey/add', { token: token, device_id: b64u(id), public_key: b64u(r[0]), signature: b64u(r[1]) }, csrf);
      })
      .then(function (r) { location.assign(r.next); })
      .catch(function (e) { forget(); throw e; });
  }

  function login(b, rec) {
    var base = b.dataset.base, csrf = b.dataset.csrf, token;
    return post(base + '/devkey/options/login', {}, csrf)
      .then(function (o) { token = o.token; return sign(rec.key, rec.id, token); })
      .then(function (sig) {
        return post(base + '/devkey/login', { token: token, device_id: b64u(rec.id), signature: b64u(sig), next: b.dataset.next || '' }, csrf);
      })
      .then(function (r) { location.assign(r.next); })
      .catch(function (e) {
        // Revoked or expired on the server: this key is no use any more. A
        // challenge that merely timed out is no reason to forget it.
        if (e.status === 400 && /not remembered/.test(e.message)) { forget(); b.hidden = true; }
        throw e;
      });
  }

  if (!window.indexedDB || !window.crypto || !crypto.subtle) return;
  document.querySelectorAll('[data-devkey]').forEach(function (b) {
    var out = document.getElementById(b.dataset.status || '');
    var say = function (t) { if (out) out.textContent = t; };
    var fail = function (e) { say((e && e.message) || 'Something went wrong.'); b.disabled = false; };
    if (b.dataset.devkey === 'add') {
      b.hidden = false;
      b.addEventListener('click', function () { say(''); b.disabled = true; add(b).catch(fail); });
      return;
    }
    load().then(function (rec) {
      if (!rec || !rec.key) return;
      if (rec.user) b.textContent = 'Sign in as ' + rec.user;
      b.hidden = false;
      b.addEventListener('click', function () { say(''); b.disabled = true; login(b, rec).catch(fail); });
    }).catch(function () {});
  });
})();
