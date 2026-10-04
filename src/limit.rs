//! In-memory fixed-window rate limiter, shared by everything that counts
//! attempts (logins, sign-ups, link creation), plus a separate set of
//! single-use keys (burned challenges, spent proofs-of-work).

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Fixed-window-per-key limiter.
///
/// Every key remembers its own window, so a prune can never evict a 24-hour key
/// because a 60-second one asked (that is how one solved proof-of-work could be
/// replayed). Pruning is on a timer, not on map size, so someone parking many
/// live keys cannot make every request pay for a full scan.
///
/// ponytail: one global Mutex. Shard the map if it ever shows up in a profile.
#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    pruned: Instant,
    hits: HashMap<String, (Duration, Vec<Instant>)>,
    /// Live keys per kind, for the per-kind quota. Rebuilt on every prune.
    kinds: HashMap<String, usize>,
    /// Single-use keys and when each may be forgotten.
    spent: HashMap<String, Instant>,
}

impl Default for Inner {
    fn default() -> Self {
        Self { pruned: Instant::now(), hits: HashMap::new(), kinds: HashMap::new(), spent: HashMap::new() }
    }
}

const PRUNE_EVERY: Duration = Duration::from_secs(10);

/// Keys are `kind:source`; the kind is everything before the last `:`, so a
/// source never contains one (see `util::ip_key`). Past `PER_KIND` live keys of
/// one kind, a new source of that kind shares one spill bucket (`login:*`): a
/// flood of one kind is limited wholesale, and every other kind keeps its
/// per-source buckets. Past `MAX_KEYS` in all, every kind spills. Site-wide
/// `…:global` keys and `record`s are admitted as they are, up to
/// `MAX_KEYS + SPILL_ROOM`. Counters with `max` 1 are refused rather than
/// shared: a shared one would forget what was spent. Single-use keys belong in
/// `spend`, which no counter flood can crowd out.
/// ponytail: about 250 B a key, so 50 MB when full.
const PER_KIND: usize = 25_000;
const MAX_KEYS: usize = 200_000;
/// Room above the ceiling for spill, global and recorded keys. Past this, refuse.
const SPILL_ROOM: usize = 1_000;
/// Ceiling on live single-use keys, about 100 MB when full. Never evicted
/// early: forgetting one would let it be replayed, so a full set refuses.
const SPEND_MAX: usize = 1_000_000;

fn kind_of(key: &str) -> &str {
    key.rsplit_once(':').map_or("", |(kind, _)| kind)
}

fn prune(inner: &mut Inner, now: Instant) {
    inner.hits.retain(|_, (window, v)| v.iter().any(|t| now.duration_since(*t) < *window));
    inner.kinds.clear();
    for k in inner.hits.keys() {
        *inner.kinds.entry(kind_of(k).to_string()).or_default() += 1;
    }
    inner.spent.retain(|_, until| *until > now);
    inner.pruned = now;
}

impl RateLimiter {
    /// `true` when the call is allowed, and counts it.
    pub fn check(&self, key: &str, window: Duration, max: usize) -> bool {
        self.inner(key, window, Some(max), true)
    }

    /// Would `check` allow this, without spending an attempt?
    ///
    /// Buckets that mean "an account was created" must not be spent by someone
    /// mistyping their password, so those are peeked first and recorded only
    /// once the account actually exists.
    pub fn peek(&self, key: &str, window: Duration, max: usize) -> bool {
        self.inner(key, window, Some(max), false)
    }

    /// Count one hit without checking the limit.
    pub fn record(&self, key: &str, window: Duration) {
        self.inner(key, window, None, true);
    }

    /// `true` the first time `key` is spent within `ttl`, `false` after. An
    /// earlier spend keeps its own deadline; a later call never shortens it.
    /// For single-use tokens: a burned challenge, a solved proof-of-work.
    pub fn spend(&self, key: &str, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut g = self.lock(now);
        match g.spent.get(key) {
            Some(until) if *until > now => false,
            Some(_) => {
                g.spent.insert(key.to_string(), now + ttl);
                true
            }
            None if g.spent.len() >= SPEND_MAX => false,
            None => {
                g.spent.insert(key.to_string(), now + ttl);
                true
            }
        }
    }

    fn lock(&self, now: Instant) -> std::sync::MutexGuard<'_, Inner> {
        let mut g = self.inner.lock().unwrap();
        if now.duration_since(g.pruned) >= PRUNE_EVERY {
            prune(&mut g, now);
        }
        g
    }

    fn inner(&self, key: &str, window: Duration, max: Option<usize>, count: bool) -> bool {
        let now = Instant::now();
        let mut g = self.lock(now);
        let spill: String;
        let mut key = key;
        if !g.hits.contains_key(key) {
            // A key nobody spent: a peek says yes and leaves no entry behind.
            if !count {
                return max != Some(0);
            }
            let kind = kind_of(key);
            let full = g.hits.len() >= MAX_KEYS || g.kinds.get(kind).is_some_and(|n| *n >= PER_KIND);
            if full && !key.ends_with(":global") {
                match max {
                    Some(1) => return false,
                    Some(_) => {
                        spill = format!("{kind}:*");
                        key = &spill;
                    }
                    None => {}
                }
            }
            if !g.hits.contains_key(key) {
                if g.hits.len() >= MAX_KEYS + SPILL_ROOM {
                    return false;
                }
                *g.kinds.entry(kind.to_string()).or_default() += 1;
                g.hits.insert(key.to_string(), (window, Vec::new()));
            }
        }
        let (w, e) = g.hits.get_mut(key).unwrap();
        *w = window; // the configured window may have changed since the key was first seen
        e.retain(|t| now.duration_since(*t) < window);
        if max.is_some_and(|m| e.len() >= m) {
            return false;
        }
        if count {
            e.push(now);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_counts_then_blocks() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!(l.check("a", w, 2));
        assert!(l.check("a", w, 2));
        assert!(!l.check("a", w, 2), "third call in the window must be refused");
        assert!(l.check("b", w, 2), "a different key has its own bucket");
    }

    #[test]
    fn peek_does_not_spend_an_attempt() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!(l.peek("k", w, 1));
        assert!(l.peek("k", w, 1), "peeking twice must still be allowed");
        l.record("k", w);
        assert!(!l.peek("k", w, 1), "after record it is spent");
    }

    /// The bug this guards against: a prune triggered by a short-window key used
    /// to evict every long-window key too, which un-spent "one account per day"
    /// and let a solved proof-of-work be replayed.
    #[test]
    fn prune_honours_each_keys_own_window() {
        let l = RateLimiter::default();
        let day = Duration::from_secs(86400);
        assert!(l.check("long", day, 1));
        assert!(l.check("short", Duration::from_millis(1), 1));
        std::thread::sleep(Duration::from_millis(20));
        let mut g = l.inner.lock().unwrap();
        prune(&mut g, Instant::now());
        assert!(!g.hits.contains_key("short"), "an expired key is dropped");
        assert!(g.hits.contains_key("long"), "a live 24h key must survive a prune");
        drop(g);
        assert!(!l.peek("long", day, 1), "and it is still spent");
    }

    /// The bug this guards against: a flood of one kind filled the shared map,
    /// and then every challenge burn was refused (no passkey, SSH or device-key
    /// login for anyone) and every other kind's new sources shared one bucket.
    #[test]
    fn a_flood_of_one_kind_spills_only_that_kind() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        for i in 0..PER_KIND {
            assert!(l.check(&format!("create:{i}"), w, 5));
        }
        assert!(l.check("create:0", w, 5), "an existing key keeps working");
        assert!(l.check("create:new1", w, 2), "new sources of the flooded kind share one bucket");
        assert!(l.check("create:new2", w, 2));
        assert!(!l.check("create:new3", w, 2));
        assert!(!l.check("create:one", w, 1), "a max-1 counter is refused, not shared");
        assert!(l.check("login:1.2.3.4", w, 1), "another kind keeps per-source buckets");
        assert!(l.check("login:5.6.7.8", w, 1));
        assert!(l.check("create:global", w, 1), "a site-wide key keeps its own bucket");
        assert!(l.spend("acct-ch:abc", w), "single use still works");
        assert!(!l.spend("acct-ch:abc", w), "exactly once");
        l.record("create:rec", w);
        assert!(!l.peek("create:rec", w, 1), "a record keeps its own key");
        let g = l.inner.lock().unwrap();
        assert!(g.hits.contains_key("create:*") && !g.hits.contains_key("create:new1"));
    }

    #[test]
    fn peek_leaves_no_key_behind() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!(l.peek("nojs:1.2.3.4", w, 1));
        assert!(l.inner.lock().unwrap().hits.is_empty());
    }

    #[test]
    fn spend_is_single_use_until_its_deadline() {
        let l = RateLimiter::default();
        assert!(l.spend("k", Duration::from_secs(60)));
        assert!(!l.spend("k", Duration::from_millis(1)), "a later call does not shorten the deadline");
        std::thread::sleep(Duration::from_millis(5));
        assert!(!l.spend("k", Duration::from_secs(60)), "still spent");
        assert!(l.spend("short", Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        let mut g = l.inner.lock().unwrap();
        prune(&mut g, Instant::now());
        assert!(g.spent.contains_key("k") && !g.spent.contains_key("short"), "prune drops only expired spends");
    }
}
