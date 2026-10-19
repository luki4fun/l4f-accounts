//! In-memory fixed-window rate limiter, shared by everything that counts
//! attempts (logins, sign-ups, link creation), plus a separate set of
//! single-use keys (burned challenges, spent proofs-of-work).
//!
//! Both live in this process's memory, so single use and every cap hold per
//! process: a second instance accepts a burned challenge or a solved
//! proof-of-work once more, and every cap counts again from zero there. Run
//! one instance, or move spends and counters to shared storage first.

use std::{
    collections::HashMap,
    sync::{Mutex, PoisonError},
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
    /// Live source keys per kind, for the per-kind quota. Rebuilt on every prune.
    kinds: HashMap<String, usize>,
    /// Per kind with `EVICT` sources or more at the last prune, its least
    /// recently hit keys then, oldest last: what a new source evicts.
    evict: HashMap<String, Vec<String>>,
    /// Single-use keys and when each may be forgotten.
    spent: HashMap<String, Instant>,
    /// Live single-use keys per kind, for `SPEND_PER_KIND`. Rebuilt on every prune.
    spent_kinds: HashMap<String, usize>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            pruned: Instant::now(),
            hits: HashMap::new(),
            kinds: HashMap::new(),
            evict: HashMap::new(),
            spent: HashMap::new(),
            spent_kinds: HashMap::new(),
        }
    }
}

const PRUNE_EVERY: Duration = Duration::from_secs(10);

/// Keys are `kind:source`; the kind is everything before the last `:`, so a
/// source never contains one (see `util::ip_key`). A kind keeps `PER_KIND`
/// sources; a new one past that evicts the kind's least recently hit key (as
/// of the last prune), so a flood forgets its own oldest sources instead of
/// refusing fresh ones, and other kinds keep theirs. A flood with more
/// sources than that escapes its per-source caps (an evicted source counts
/// afresh); the site-wide and per-account caps still hold it. A counter with
/// `max` 1 is a promise of once, so a full kind refuses a new one rather than
/// evict someone's spend. Single-use keys belong in `spend`, which no counter
/// flood can crowd out.
///
/// A counter per account is `kind-{id}:x`, one kind per account. That suits
/// only ids something else bounds: a kind per address never reaches `PER_KIND`.
/// Per-account and site-wide (`…:global`) keys are buckets of their own,
/// never evicted; they and new `record`s are admitted up to `MAX_KEYS + ROOM`,
/// as what they count is bounded elsewhere. Sources stop at `MAX_KEYS` in all
/// (sixteen full kinds): past it a new one evicts its own kind's oldest key,
/// or else the oldest of the kind with the most to spare, and is refused when
/// there is none.
/// ponytail: about 250 B a key, so 75 MB when full.
const PER_KIND: usize = MAX_KEYS / 16;
const MAX_KEYS: usize = 200_000;
/// Room above `MAX_KEYS` that sources never reach, so a flood of them cannot
/// lock out the site-wide, per-account and recorded keys. Past this, refuse.
const ROOM: usize = 50_000;
/// Eviction candidates a kind keeps from one prune to the next, once it has
/// this many sources: enough for 600 new sources a second.
const EVICT: usize = PER_KIND / 2;
/// Ceiling on live single-use keys per kind (challenge burns, each sign-up
/// gate's proofs-of-work), about 25 MB each when full. Never evicted early:
/// forgetting one would let it be replayed, so a full kind refuses. Never
/// shared, so a flood of proofs-of-work cannot refuse every challenge burn;
/// the kinds are fixed in code, which bounds them all together.
const SPEND_PER_KIND: usize = 250_000;
/// Longest a spend is kept (136 years): `Duration::MAX` means forever, and
/// `Instant + Duration` panics past its range.
const FOREVER: Duration = Duration::from_secs(u32::MAX as u64);

fn kind_of(key: &str) -> &str {
    key.rsplit_once(':').map_or("", |(kind, _)| kind)
}

/// Neither site-wide nor per-account: one of the many keys a kind tracks,
/// which the per-kind quota and `MAX_KEYS` bound.
fn source(key: &str) -> bool {
    !key.ends_with(":global") && !key.ends_with(":x")
}

/// One more live key of `kind`, allocating only for a kind not seen yet.
fn bump(counts: &mut HashMap<String, usize>, kind: &str) {
    match counts.get_mut(kind) {
        Some(n) => *n += 1,
        None => {
            counts.insert(kind.to_string(), 1);
        }
    }
}

fn prune(inner: &mut Inner, now: Instant) {
    inner.hits.retain(|_, (window, v)| v.iter().any(|t| now.duration_since(*t) < *window));
    inner.kinds.clear();
    for k in inner.hits.keys().filter(|k| source(k)) {
        bump(&mut inner.kinds, kind_of(k));
    }
    // Picked here, once per prune, so no request scans the map for them.
    let mut old: HashMap<&str, Vec<(Instant, &String)>> = HashMap::new();
    for (k, (_, v)) in &inner.hits {
        if source(k) && inner.kinds.get(kind_of(k)).is_some_and(|n| *n >= EVICT) {
            old.entry(kind_of(k)).or_default().push((v.last().copied().unwrap_or(now), k));
        }
    }
    inner.evict = old
        .into_iter()
        .map(|(kind, mut c)| {
            if c.len() > EVICT {
                c.select_nth_unstable(EVICT);
                c.truncate(EVICT);
            }
            c.sort_unstable_by(|a, b| b.cmp(a));
            (kind.to_string(), c.into_iter().map(|(_, k)| k.clone()).collect())
        })
        .collect();
    inner.spent.retain(|_, until| *until > now);
    inner.spent_kinds.clear();
    for k in inner.spent.keys() {
        bump(&mut inner.spent_kinds, kind_of(k));
    }
    inner.pruned = now;
}

/// Drops `kind`'s least recently hit key, skipping candidates hit since the
/// prune that picked them: those are not among the least recent any more.
fn evict_from(inner: &mut Inner, kind: &str) -> bool {
    let Some(c) = inner.evict.get_mut(kind) else { return false };
    while let Some(k) = c.pop() {
        if inner.hits.get(&k).is_some_and(|(_, v)| v.last().is_none_or(|t| *t < inner.pruned)) {
            inner.hits.remove(&k);
            if let Some(n) = inner.kinds.get_mut(kind) {
                *n = n.saturating_sub(1);
            }
            return true;
        }
    }
    false
}

/// Room for one more source of `kind`: its own kind's oldest, or at
/// `MAX_KEYS` the oldest of the kind with the most candidates left.
fn evict(inner: &mut Inner, kind: &str) -> bool {
    if evict_from(inner, kind) {
        return true;
    }
    if inner.hits.len() < MAX_KEYS {
        return false;
    }
    let most = inner.evict.iter().max_by_key(|(_, c)| c.len()).map(|(k, _)| k.clone());
    most.is_some_and(|k| evict_from(inner, &k))
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
        let until = now + ttl.min(FOREVER);
        let mut g = self.lock(now);
        if let Some(t) = g.spent.get_mut(key) {
            // Lapsed but not pruned yet: spendable again, still counted.
            if *t > now {
                return false;
            }
            *t = until;
            return true;
        }
        let kind = kind_of(key);
        if g.spent_kinds.get(kind).is_some_and(|n| *n >= SPEND_PER_KIND) {
            return false;
        }
        bump(&mut g.spent_kinds, kind);
        g.spent.insert(key.to_string(), until);
        true
    }

    fn lock(&self, now: Instant) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while it was held leaves nothing a prune does not rebuild,
        // so the limiter serves on instead of failing every later call.
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if now.duration_since(g.pruned) >= PRUNE_EVERY {
            prune(&mut g, now);
        }
        g
    }

    fn inner(&self, key: &str, window: Duration, max: Option<usize>, count: bool) -> bool {
        let now = Instant::now();
        let mut g = self.lock(now);
        if !g.hits.contains_key(key) {
            // A key nobody spent: a peek says yes and leaves no entry behind.
            if !count {
                return max != Some(0);
            }
            let kind = kind_of(key);
            let room = if !source(key) || max.is_none() {
                g.hits.len() < MAX_KEYS + ROOM
            } else if g.hits.len() >= MAX_KEYS || g.kinds.get(kind).is_some_and(|n| *n >= PER_KIND) {
                max.is_some_and(|m| m > 1) && evict(&mut g, kind)
            } else {
                true
            };
            if !room {
                return false;
            }
            if source(key) {
                bump(&mut g.kinds, kind);
            }
            g.hits.insert(key.to_string(), (window, Vec::new()));
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

    /// The bug this guards against: past `PER_KIND` sources, new ones shared a
    /// spill bucket the flood kept spent, so one IPv6 /48 refused every fresh
    /// visitor of that kind (GATES-1).
    #[test]
    fn a_flood_of_one_kind_evicts_its_own_oldest() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        for i in 0..PER_KIND {
            assert!(l.check(&format!("create:{i}"), w, 5));
        }
        assert!(l.check("login:1.2.3.4", w, 1));
        std::thread::sleep(Duration::from_millis(2));
        prune(&mut l.inner.lock().unwrap(), Instant::now());
        assert!(l.check("create:0", w, 5), "hit since the prune: no longer the least recent");
        for i in 0..100 {
            assert!(l.check(&format!("create:flood{i}"), w, 5), "more than PER_KIND sources");
        }
        assert!(l.check("create:fresh", w, 2), "a fresh source is not refused");
        assert!(l.check("create:fresh", w, 2));
        assert!(!l.check("create:fresh", w, 2), "and counts on its own");
        assert!(!l.check("create:once", w, 1), "a max-1 counter is refused, not given someone's place");
        assert!(l.check("login:5.6.7.8", w, 1), "another kind keeps per-source buckets");
        assert!(!l.check("login:1.2.3.4", w, 1), "and what they counted");
        assert!(l.check("create:global", w, 1), "a site-wide key keeps its own bucket");
        assert!(l.spend("acct-ch:abc", w), "single use still works");
        assert!(!l.spend("acct-ch:abc", w), "exactly once");
        l.record("create:rec", w);
        assert!(!l.peek("create:rec", w, 1), "a record keeps its own key");
        let g = l.inner.lock().unwrap();
        assert!(g.hits.contains_key("create:0") && !g.hits.contains_key("create:1"), "the least recently hit went");
        assert_eq!(g.kinds["create"], PER_KIND + 1, "the kind did not grow, but for the record");
        assert!(!g.hits.contains_key("create:*"), "no spill bucket");
    }

    /// Sources stop at `MAX_KEYS`, so they never lock out a site-wide or a
    /// per-account key, and a fresh source of a small kind takes the place of
    /// a flooded kind's oldest.
    #[test]
    fn at_the_ceiling_sources_make_room_for_themselves() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        {
            let mut g = l.inner.lock().unwrap();
            let t = Instant::now();
            for i in 0..MAX_KEYS {
                g.hits.insert(format!("k{}:{i}", i % 16), (w, vec![t]));
            }
            std::thread::sleep(Duration::from_millis(2));
            prune(&mut g, Instant::now());
        }
        assert!(l.check("acct-forgot:1.2.3.4", w, 5), "a small kind's fresh source");
        assert!(l.check("k3:fresh", w, 5), "a flooded kind's fresh source");
        assert_eq!(l.inner.lock().unwrap().hits.len(), MAX_KEYS, "each took a place");
        assert!(l.check("acct-mfa-ab12:x", w, 5), "per account");
        assert!(l.check("acct-login:global", w, 5), "site-wide");
        l.record("acct-reg:ok:1.2.3.4", w);
        assert!(!l.peek("acct-reg:ok:1.2.3.4", w, 1), "recorded");
        assert_eq!(l.inner.lock().unwrap().hits.len(), MAX_KEYS + 3);
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

    /// The bug this guards against: one ceiling for every single-use key, so
    /// a flood of solved sign-up proofs-of-work refused every challenge burn,
    /// and with it every passkey, SSH and device-key sign-in (secrets-2).
    #[test]
    fn each_kind_of_spend_has_its_own_ceiling() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        {
            let mut g = l.inner.lock().unwrap();
            let until = Instant::now() + w;
            for i in 0..SPEND_PER_KIND {
                for ns in ["acct-reg", "mx"] {
                    g.spent.insert(format!("{ns}:pow:{i}"), until);
                }
            }
            prune(&mut g, Instant::now());
        }
        assert!(!l.spend("acct-reg:pow:new", w), "a full kind fails closed");
        assert!(!l.spend("mx:pow:new", w));
        assert!(l.spend("acct-ch:abc", w), "challenge burns keep a budget of their own");
        assert!(!l.spend("acct-ch:abc", w));
        assert_eq!(l.inner.lock().unwrap().spent_kinds["acct-ch"], 1);
    }

    /// The bug this guards against: `now + Duration::MAX` panicked under the
    /// lock, and the poisoned lock then failed every later call (GATES-3).
    #[test]
    fn a_huge_ttl_or_a_poisoned_lock_breaks_nothing() {
        let l = RateLimiter::default();
        let w = Duration::from_secs(60);
        assert!(l.spend("forever", Duration::MAX));
        assert!(!l.spend("forever", w), "spent for good");
        assert!(l.check("k", w, 1));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = l.inner.lock().unwrap();
            panic!("poisoning the lock on purpose");
        }));
        assert!(l.inner.is_poisoned());
        assert!(!l.check("k", w, 1), "a poisoned lock still serves, and still counts");
        assert!(l.spend("other", w));
    }
}
