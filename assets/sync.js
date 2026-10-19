// Opt-in sync of the site's `store` settings for a signed-in account: local
// first, pulled once per page, every change pushed as one compare-and-set
// write. The host imports this only while the sync hint cookie is set, or to
// clean up after a sign-out cleared it. Turning sync off keeps the hint until
// the next pull, whose 409 clears it: this browser then keeps every value.
const API = '/account/api/kv';
// What the server last confirmed, per key: { version, json }. Lets a later
// sign-out remove exactly what came from the server and nothing changed here.
const ACKED = 'l4f-sync:acked';
// `account.epoch` of the server's copy ACKED is about. Turning sync on starts
// a new copy under a new epoch, after the old one was deleted with sync off.
const EPOCH = 'l4f-sync:epoch';

function readAcked() { try { return JSON.parse(localStorage.getItem(ACKED) || '{}') || {}; } catch { return {}; } }
function writeAcked(a) { try { localStorage.setItem(ACKED, JSON.stringify(a)); } catch { /* storage full or blocked */ } }
function readEpoch() { try { return localStorage.getItem(EPOCH) || ''; } catch { return ''; } }
function writeEpoch(e) { try { localStorage.setItem(EPOCH, e); } catch { /* storage full or blocked */ } }
function rawGet(k) { try { return localStorage.getItem(`l4f:${k}`); } catch { return null; } }
function rawSet(k, json) { try { localStorage.setItem(`l4f:${k}`, json); } catch { /* storage full or blocked */ } }
function rawDel(k) { try { localStorage.removeItem(`l4f:${k}`); } catch { /* nothing to delete */ } }
function localKeys() {
  const out = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith('l4f:')) out.push(k.slice(4));
    }
  } catch { /* storage blocked */ }
  return out;
}

/** Forget what came from the server and is unchanged since; keep the rest. */
export function cleanup() {
  const acked = readAcked();
  Object.keys(acked).forEach((k) => { if (rawGet(k) === acked[k].json) rawDel(k); });
  try { localStorage.removeItem(ACKED); localStorage.removeItem(EPOCH); } catch { /* storage blocked */ }
}

// Both sides changed: this browser wins, except My links, which become the
// union by short link and keep whichever copy has statistics.
function merge(k, local, server) {
  if (k !== 'links:v1' || !Array.isArray(local) || !Array.isArray(server)) return local;
  const by = new Map();
  [...server, ...local].forEach((e) => {
    if (!e || typeof e.short !== 'string') return;
    const old = by.get(e.short);
    by.set(e.short, old && old.stats && !e.stats ? { ...e, stats: old.stats } : e);
  });
  return [...by.values()];
}

function parse(json) { try { return JSON.parse(json); } catch { return null; } }

export function attach(store) {
  let csrf = '';
  const acked = readAcked();
  const headers = (version) => ({ 'Content-Type': 'application/json', 'X-CSRF': csrf, 'If-Match': String(version) });
  // Signed out (401) or no longer allowed to sync (403): stop, and clean up
  // what came from the server. Sync off is the pull's 409, which keeps it.
  const gone = (r) => {
    if (r.status !== 401 && r.status !== 403) return false;
    cleanup();
    return true;
  };

  function push(k, tries = 0) {
    const json = rawGet(k);
    if (json === null) return remove(k);
    const version = acked[k] ? acked[k].version : 0;
    return fetch(`${API}/${encodeURIComponent(k)}`, { method: 'PUT', credentials: 'same-origin', headers: headers(version), body: json })
      .then((r) => {
        if (gone(r)) return undefined;
        return r.json().then((j) => {
          if (r.ok) {
            acked[k] = { version: j.version, json };
            writeAcked(acked);
          } else if (r.status === 409 && tries < 2) {
            acked[k] = { version: j.version, json: JSON.stringify(j.v) };
            rawSet(k, JSON.stringify(merge(k, parse(json), j.v)));
            return push(k, tries + 1);
          }
          return undefined;
        });
      })
      .catch(() => {});
  }

  function remove(k) {
    if (!acked[k]) return undefined;
    return fetch(`${API}/${encodeURIComponent(k)}`, { method: 'DELETE', credentials: 'same-origin', headers: headers(acked[k].version) })
      .then((r) => { if (!gone(r)) { delete acked[k]; writeAcked(acked); } })
      .catch(() => {});
  }

  fetch(API, { credentials: 'same-origin' })
    .then((r) => {
      if (gone(r)) return undefined;
      // Sync is off and the server's copy deleted: keep every value here,
      // forget only what the server had confirmed, and stop.
      if (r.status === 409) {
        try { localStorage.removeItem(ACKED); } catch { /* storage blocked */ }
        return undefined;
      }
      if (!r.ok) return undefined;
      return r.json().then((j) => {
        csrf = j.csrf;
        // Not the copy ACKED is about (sync went off and on since, or no epoch
        // was kept): nothing in ACKED was deleted elsewhere then, and every
        // key here goes up as new. Another account's ACKED stays, to clear
        // what came from that account.
        const epoch = `${j.account}.${j.epoch || ''}`;
        const was = readEpoch();
        if (was !== epoch && (!was || was.startsWith(`${j.account}.`))) Object.keys(acked).forEach((k) => { delete acked[k]; });
        writeEpoch(epoch);
        const seen = new Set();
        j.items.forEach((it) => {
          seen.add(it.k);
          const json = JSON.stringify(it.v);
          const mine = rawGet(it.k);
          const unchanged = mine === null || mine === json || (acked[it.k] && mine === acked[it.k].json);
          acked[it.k] = { version: it.version, json };
          if (unchanged) {
            rawSet(it.k, json);
          } else {
            rawSet(it.k, JSON.stringify(merge(it.k, parse(mine), it.v)));
            push(it.k);
          }
        });
        // Deleted elsewhere, and unchanged here since: delete here too.
        Object.keys(acked).forEach((k) => {
          if (seen.has(k)) return;
          if (rawGet(k) === acked[k].json) rawDel(k);
          delete acked[k];
        });
        writeAcked(acked);
        localKeys().forEach((k) => { if (!seen.has(k)) push(k); });
        const set = store.set.bind(store);
        const del = store.del.bind(store);
        store.set = (k, v) => { const ok = set(k, v); if (ok) push(k); return ok; };
        store.del = (k) => { del(k); remove(k); };
        // Pages that already drew from `store` can draw again.
        window.dispatchEvent(new Event('l4f:synced'));
        return undefined;
      });
    })
    .catch(() => {});
}
