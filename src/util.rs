//! Small helpers every other module leans on: constant-time compare, the
//! truncated HMAC, clock, cookie parsing, rate-limit source keys, safe `next=`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

type H = Hmac<Sha256>;

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `now_secs` as the signed type every timestamp column uses: MySQL `BIGINT`,
/// SQLite `INTEGER`, neither with a portable unsigned flavour.
pub fn now() -> i64 {
    now_secs() as i64
}

/// Constant-time equality over two byte strings.
pub fn ct_eq(a: &str, b: &str) -> bool {
    ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |v, (x, y)| v | (x ^ y)) == 0
}

/// Truncated hex HMAC-SHA256 (16 bytes -> 32 hex chars).
pub fn mac(secret: &[u8], msg: &str) -> String {
    hex::encode(&mac_raw(secret, msg.as_bytes())[..16])
}

/// Full 32-byte HMAC-SHA256.
pub fn mac_raw(secret: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = <H>::new_from_slice(secret).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// `__Host-` requires the Secure attribute, which plain-http development lacks.
pub fn cookie_name(base: &str, secure: bool) -> String {
    if secure { format!("__Host-{base}") } else { base.to_string() }
}

/// Minimal Cookie-header parse. Not worth a crate.
pub fn cookie<'a>(header: Option<&'a str>, name: &str) -> Option<&'a str> {
    header?.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        // ASCII trim only: Unicode-aware trim would let "\u{85}__Host-x" pass as
        // the `__Host-` cookie, which a sibling subdomain can set.
        (k.trim_ascii() == name).then_some(v.trim_ascii())
    })
}

/// A `Set-Cookie` value with the attributes every cookie here shares. `max_age`
/// 0 clears it. Path is `/` because `__Host-` demands it.
pub fn set_cookie(name: &str, value: &str, max_age: u64, secure: bool, http_only: bool) -> String {
    format!(
        "{name}={value}; Path=/; SameSite=Lax; Max-Age={max_age}{}{}",
        if http_only { "; HttpOnly" } else { "" },
        if secure { "; Secure" } else { "" }
    )
}

/// Rate-limit bucket for an address: the address itself for IPv4, the /64 for
/// IPv6. One IPv6 subscriber holds 2^64 addresses, so keyed per address every
/// per-IP limit would be a fresh bucket per request. Only ever used for limiter
/// keys; what gets stored is shaped by `ip::shape_ip`.
///
/// Never contains `:`: the limiter finds a key's kind by its last colon.
pub fn ip_key(ip: IpAddr) -> String {
    // A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d, which would
    // put every one of them in the same /64.
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}-{:x}-{:x}-{:x}/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Percent-encode for a query string.
pub fn urlencode(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => out.push(b as char),
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// A `next=` value that is safe to redirect to: a path on this site, never an
/// absolute or protocol-relative URL. Anything else falls back to `fallback`.
///
/// `//host` and `/\host` are both read as protocol-relative by browsers, and a
/// control character can split a header, so all of those are refused.
pub fn safe_next<'a>(next: &'a str, fallback: &'a str) -> &'a str {
    let ok = next.starts_with('/')
        && !next[1..].starts_with(['/', '\\'])
        && !next.bytes().any(|b| b.is_ascii_control() || b == b'\\')
        && next.len() <= 512;
    if ok { next } else { fallback }
}

/// Base64url without padding: WebAuthn, PKCE and every token in a URL use it.
pub fn b64u(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_dec(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// A `b64u(payload).tag` token, split: the payload decoded and the tag as
/// sent, for the caller to check. `None` past `max` bytes, without a dot, or
/// for a payload in any spelling but the one `b64u` writes (`b64u_dec` alone
/// also takes padding).
pub(crate) fn split_token(t: &str, max: usize) -> Option<(Vec<u8>, &str)> {
    if t.len() > max {
        return None;
    }
    let (p64, tag) = t.split_once('.')?;
    let p = b64u_dec(p64)?;
    (b64u(&p) == p64).then_some((p, tag))
}

/// `n` bytes from the OS CSPRNG. Not `rand`'s thread RNG: that one is a
/// userspace generator a fork would duplicate.
///
/// # Panics
/// If the OS RNG fails.
pub fn random<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut b).expect("OS RNG failed");
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let h = Some("foo=1; __Host-sid=abc.1.def ; bar=2");
        assert_eq!(cookie(h, "__Host-sid"), Some("abc.1.def"));
        assert_eq!(cookie(h, "missing"), None);
        assert_eq!(cookie(None, "x"), None);
        assert_eq!(cookie(Some("\u{85}__Host-sid=evil"), "__Host-sid"), None, "only ASCII space is trimmed");
    }

    #[test]
    fn ip_key_buckets_ipv6_by_64() {
        let a: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let b: IpAddr = "2001:db8:abcd:1234:ffff::2".parse().unwrap();
        let c: IpAddr = "2001:db8:abcd:1235::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b), "same /64, same bucket");
        assert_ne!(ip_key(a), ip_key(c));
        assert_eq!(ip_key(a), "2001-db8-abcd-1234/64");
        assert_eq!(ip_key("203.0.113.42".parse().unwrap()), "203.0.113.42");
        assert_eq!(ip_key("::ffff:203.0.113.42".parse().unwrap()), "203.0.113.42", "a mapped IPv4 client is itself");
    }

    #[test]
    fn urlencode_is_form_encoding() {
        assert_eq!(urlencode("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
    }

    #[test]
    fn safe_next_only_allows_local_paths() {
        assert_eq!(safe_next("/admin/links?q=1", "/account"), "/admin/links?q=1");
        for bad in ["https://evil.example/", "//evil.example", "/\\evil.example", "evil", "", "/a\r\nSet-Cookie: x=1", "/a\\b"] {
            assert_eq!(safe_next(bad, "/account"), "/account", "{bad:?} must be refused");
        }
    }

    #[test]
    fn b64u_round_trips_and_tolerates_padding() {
        let raw = [0xfbu8, 0xff, 0x00, 0x10];
        let s = b64u(&raw);
        assert!(!s.contains('=') && !s.contains('+') && !s.contains('/'));
        assert_eq!(b64u_dec(&s).unwrap(), raw);
        assert_eq!(b64u_dec("-_8AEA==").unwrap(), raw);
    }

    #[test]
    fn ct_eq_checks_length_and_content() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }
}
