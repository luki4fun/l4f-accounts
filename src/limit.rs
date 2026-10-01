//! In-memory fixed-window rate limiter, shared by everything that counts
//! attempts: logins, sign-ups, link creation, single-use challenge burns.

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
}

impl Default for Inner {
    fn default() -> Self {
        Self { pruned: Instant::now(), hits: HashMap::new() }
    }
}

const PRUNE_EVERY: Duration = Duration::from_secs(10);

/// ponytail: hard ceiling on distinct keys, about 10 MB when full. Past it, a new
/// source shares one spill bucket per kind (`login:*`, `create:*`), so a flood of
/// one kind is limited wholesale without refusing everyone at every other door.
/// Site-wide `…:global` keys and `record`s are admitted as they are, which is
/// why the admin's known devices sign in through `login-dev:global`: a full map
/// can never fold them into the spill bucket strangers are filling. Single-use
/// keys (`max` 1: a burned challenge, a no-JS slot) are refused instead: shared,
/// they would forget what was spent.
/// Keys are `kind:source`, and sources never contain `:` (see `util::ip_key`).
const MAX_KEYS: usize = 100_000;
/// Room above the ceiling for spill and global keys. Past this, refuse outright.
const SPILL_ROOM: usize = 1_000;

fn prune(inner: &mut Inner, now: Instant) {
    inner.hits.retain(|_, (window, v)| v.iter().any(|t| now.duration_since(*t) < *window));
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

    fn inner(&self, key: &str, window: Duration, max: Option<usize>, count: bool) -> bool {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        if now.duration_since(g.pruned) >= PRUNE_EVERY {
            prune(&mut g, now);
        }
        let spill: String;
        let mut key = key;
        if g.hits.len() >= MAX_KEYS && !g.hits.contains_key(key) {
            let (kind, src) = key.rsplit_once(':').unwrap_or(("", key));
            if src != "global" {
                match max {
                    Some(1) => return false,
                    Some(_) => {
                        spill = format!("{kind}:*");
                        key = &spill;
                    }
                    None => {}
                }
            }
            if g.hits.len() >= MAX_KEYS + SPILL_ROOM && !g.hits.contains_key(key) {
                return false;
            }
        }
        let (w, e) = g.hits.entry(key.to_string()).or_insert_with(|| (window, Vec::new()));
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

    /// The bug this guards against: a flood of one kind filled the map and then
    /// every new source was refused everywhere, the admin login included.
    #[test]
    fn key_ceiling_spills_new_sources_per_kind() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        for i in 0..MAX_KEYS {
            assert!(l.check(&format!("create:{i}"), w, 5));
        }
        assert!(l.check("create:0", w, 5), "an existing key keeps working");
        assert!(l.check("login:1.2.3.4", w, 2), "a new source of another kind still gets in");
        assert!(l.check("login:5.6.7.8", w, 2));
        assert!(!l.check("login:9.9.9.9", w, 2), "new sources of that kind share one bucket");
        assert!(l.check("login:global", w, 1), "a site-wide key keeps its own bucket");
        assert!(!l.check("mx:pow:abc", w, 1), "a single-use key is refused, not shared");
        l.record("mx:ok:1.2.3.4", w);
        assert!(!l.peek("mx:ok:1.2.3.4", w, 1), "a record keeps its own key");
        let g = l.inner.lock().unwrap();
        assert!(g.hits.contains_key("login:*") && !g.hits.contains_key("login:1.2.3.4"));
    }
}
