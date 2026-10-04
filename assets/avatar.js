// The avatar upload: the chosen image is drawn into a canvas at most 512 by
// 512 pixels and saved as WebP (PNG where WebP encoding is missing), smaller
// until it fits 64 KiB, then sent as raw bytes. The server checks the type by
// its first bytes. No inline script, no HTML strings.
(function () {
  'use strict';
  var MAX = 512, LIMIT = 64 * 1024;
  var input = document.querySelector('[data-avatar]');
  if (!input || !window.createImageBitmap || !HTMLCanvasElement.prototype.toBlob) return;
  document.querySelectorAll('[data-avatar-only]').forEach(function (el) { el.hidden = false; });
  var out = document.getElementById(input.dataset.status || '');
  var say = function (t) { if (out) out.textContent = t; };

  function blob(canvas, type, q) {
    return new Promise(function (ok) { canvas.toBlob(ok, type, q); });
  }
  async function shrink(bmp) {
    for (var size = MAX; size >= 64; size = Math.round(size * 0.75)) {
      var scale = Math.min(1, size / Math.max(bmp.width, bmp.height));
      var c = document.createElement('canvas');
      c.width = Math.max(1, Math.round(bmp.width * scale));
      c.height = Math.max(1, Math.round(bmp.height * scale));
      c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
      for (var q = 0.9; q >= 0.5; q -= 0.1) {
        var b = await blob(c, 'image/webp', q);
        if (b && b.type !== 'image/webp') b = await blob(c, 'image/png');
        if (b && b.size <= LIMIT) return b;
        if (b && b.type === 'image/png') break;
      }
    }
    throw new Error('That image does not get small enough.');
  }

  input.addEventListener('change', function () {
    var file = input.files && input.files[0];
    if (!file) return;
    say('Resizing…');
    createImageBitmap(file)
      .then(shrink)
      .then(function (b) {
        say('Uploading…');
        return fetch(input.dataset.base + '/api/avatar', {
          method: 'PUT', credentials: 'same-origin', body: b,
          headers: { 'Content-Type': b.type, 'X-CSRF': input.dataset.csrf }
        });
      })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || 'Upload failed.'); return j; }); })
      .then(function (j) { location.assign(j.next); })
      .catch(function (e) { say(e && e.message || 'That did not work.'); });
  });
})();
