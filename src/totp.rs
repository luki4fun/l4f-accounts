//! RFC 6238 TOTP with the parameters every authenticator app defaults to:
//! SHA-1, 6 digits, 30 s. Anything else is ignored by some apps, so it is not
//! configurable.
//!
//! Built on the `hmac` + `sha1` already in the tree; totp-rs would add a crate
//! for forty lines. Base32 is here for the same reason.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::util::{ct_eq_bytes, random};

const PERIOD: i64 = 30;
const MODULUS: u32 = 1_000_000;
/// RFC 4226 R6: at least 128 bits.
const MIN_SECRET: usize = 16;

/// 160 bits, the length RFC 4226 recommends (one SHA-1 output).
pub fn new_secret() -> [u8; 20] {
    random::<20>()
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding: the Key URI format says to omit it, and
/// some apps refuse a secret containing `=`.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[(buf >> bits) as usize & 31] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[(buf << (5 - bits)) as usize & 31] as char);
    }
    out
}

/// Case-insensitive; whitespace anywhere and trailing `=` are ignored, because
/// apps print secrets in spaced groups of four.
///
/// A symbol count of 1, 3 or 6 (mod 8) is refused: no encoder emits it, so a
/// character was lost and the secret would silently differ from the user's app.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buf, mut bits, mut n, mut padded) = (0u32, 0u32, 0usize, false);
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padded = true;
            continue;
        }
        if padded {
            return None;
        }
        let v = match c.to_ascii_uppercase() {
            u @ b'A'..=b'Z' => u - b'A',
            u @ b'2'..=b'7' => u - b'2' + 26,
            _ => return None,
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        n += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if matches!(n % 8, 1 | 3 | 6) {
        return None;
    }
    Some(out)
}

/// RFC 4226 dynamic truncation: the 31-bit value before the decimal modulus.
/// Kept separate so the tests can check the RFC's 8-digit vectors in full.
fn truncated(secret: &[u8], step: i64) -> u32 {
    let mut m = <Hmac<Sha1>>::new_from_slice(secret).expect("hmac accepts any key length");
    m.update(&(step as u64).to_be_bytes());
    let h = m.finalize().into_bytes();
    // The offset is at most 15, so h[off + 3] <= h[18] of the 20-byte digest.
    let off = usize::from(h[19] & 0x0f);
    u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]])
}

/// RFC 6238: SHA-1, 6 digits, 30 s. `step` is `unix_secs / 30`.
pub fn code_at(secret: &[u8], step: i64) -> u32 {
    truncated(secret, step) % MODULUS
}

/// Accepts steps now-1..=now+1; returns the matched step so the caller can
/// store it and refuse replays (caller enforces `step > last_step` atomically
/// in SQL). `code`: whitespace is ignored, then exactly 6 ASCII digits.
/// Secrets under 16 bytes never verify.
///
/// If a code happens to match two steps in the window, the higher one is
/// returned: storing the lower would let the same code pass again at the
/// higher step.
pub fn verify(secret: &[u8], code: &str, now_secs: i64) -> Option<i64> {
    // A short key can be guessed outright: an empty one is public, a 1-byte
    // one (base32 "MY", a truncated `totp_enc` plaintext) has 256 values.
    if secret.len() < MIN_SECRET {
        return None;
    }
    let mut digits = [0u8; 6];
    let mut n = 0;
    for b in code.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if !b.is_ascii_digit() || n == digits.len() {
            return None;
        }
        digits[n] = b;
        n += 1;
    }
    if n != digits.len() {
        return None;
    }
    let now = now_secs.div_euclid(PERIOD);
    let mut hit = None;
    for step in now - 1..=now + 1 {
        if step >= 0 && ct_eq_bytes(format!("{:06}", code_at(secret, step)).as_bytes(), &digits) {
            hit = Some(step);
        }
    }
    hit
}

/// Google's Key URI format. Label and issuer are RFC 3986 percent-encoded:
/// apps decode `%20` but show a form-encoded `+` literally.
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let issuer = pct(issuer);
    format!(
        "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        pct(account),
        base32_encode(secret)
    )
}

/// Everything but RFC 3986 unreserved characters, so a `:`, `?` or `&` in the
/// issuer or account cannot change how the URI splits.
fn pct(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    /// RFC 6238 Appendix B, SHA-1 column: (unix time, 8-digit TOTP).
    const RFC_VECTORS: &[(i64, u32)] = &[
        (59, 94287082),
        (1111111109, 7081804),
        (1111111111, 14050471),
        (1234567890, 89005924),
        (2000000000, 69279037),
        (20000000000, 65353130),
    ];

    fn code_str(secret: &[u8], step: i64) -> String {
        format!("{:06}", code_at(secret, step))
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        for &(t, want8) in RFC_VECTORS {
            let step = t / 30;
            assert_eq!(truncated(RFC_SECRET, step) % 100_000_000, want8, "8-digit value at T={t}");
            assert_eq!(code_at(RFC_SECRET, step), want8 % 1_000_000, "6-digit code at T={t}");
            let code = format!("{:06}", want8 % 1_000_000);
            assert_eq!(verify(RFC_SECRET, &code, t), Some(step), "verify {code} at T={t}");
        }
    }

    #[test]
    fn leading_zeros_are_part_of_the_code() {
        // T=1234567890 gives 89005924, so the 6-digit code is "005924".
        assert_eq!(verify(RFC_SECRET, "005924", 1234567890), Some(41152263));
        assert_eq!(verify(RFC_SECRET, "5924", 1234567890), None, "zero padding is required");
        assert_eq!(verify(RFC_SECRET, "05924", 1234567890), None);
        assert_eq!(verify(RFC_SECRET, "081804", 1111111109), Some(37037036));
    }

    #[test]
    fn window_is_one_step_either_side() {
        let t = 1111111111;
        let s = t / 30;
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, s - 1), t), Some(s - 1), "previous step");
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, s), t), Some(s), "current step");
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, s + 1), t), Some(s + 1), "next step");
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, s - 2), t), None, "two steps old");
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, s + 2), t), None, "two steps ahead");
    }

    #[test]
    fn window_edges_in_seconds() {
        let s = 37037037i64;
        let code = code_str(RFC_SECRET, s);
        // Valid while the clock is in step s-1, s or s+1.
        assert_eq!(verify(RFC_SECRET, &code, (s - 1) * 30), Some(s), "first second of s-1");
        assert_eq!(verify(RFC_SECRET, &code, (s + 2) * 30 - 1), Some(s), "last second of s+1");
        assert_eq!(verify(RFC_SECRET, &code, (s - 1) * 30 - 1), None, "one second too early");
        assert_eq!(verify(RFC_SECRET, &code, (s + 2) * 30), None, "one second too late");
    }

    #[test]
    fn returned_step_lets_the_caller_refuse_replays() {
        // What the service does in SQL: accept only when step > last_step.
        fn accept(last: &mut i64, secret: &[u8], code: &str, now: i64) -> bool {
            match verify(secret, code, now) {
                Some(step) if step > *last => {
                    *last = step;
                    true
                }
                _ => false,
            }
        }
        let t = 1111111111;
        let s = t / 30;
        let mut last = 0;
        let code = code_str(RFC_SECRET, s);
        assert!(accept(&mut last, RFC_SECRET, &code, t), "first use");
        assert_eq!(last, s);
        assert!(!accept(&mut last, RFC_SECRET, &code, t), "same code again, same second");
        assert!(!accept(&mut last, RFC_SECRET, &code, t + 30), "same code, still inside the window");
        assert!(!accept(&mut last, RFC_SECRET, &code_str(RFC_SECRET, s - 1), t), "an older code");
        assert!(accept(&mut last, RFC_SECRET, &code_str(RFC_SECRET, s + 1), t + 30), "next code");
    }

    #[test]
    fn colliding_codes_report_the_higher_step() {
        // Found offline: the RFC secret yields 186519 at both of these steps.
        let (a, b) = (37079356i64, 37079357i64);
        assert_eq!(code_at(RFC_SECRET, a), 186519);
        assert_eq!(code_at(RFC_SECRET, b), 186519);
        assert_eq!(verify(RFC_SECRET, "186519", a * 30), Some(b), "window a-1..=a+1 holds both");
        assert_eq!(verify(RFC_SECRET, "186519", b * 30), Some(b), "window b-1..=b+1 holds both");
        assert_eq!(verify(RFC_SECRET, "186519", (a - 1) * 30), Some(a), "only a in window");
    }

    #[test]
    fn code_input_is_trimmed_but_otherwise_strict() {
        let t = 1111111111;
        let s = t / 30;
        assert_eq!(verify(RFC_SECRET, " 050471\n", t), Some(s), "surrounding whitespace");
        assert_eq!(verify(RFC_SECRET, "050 471", t), Some(s), "apps display 3+3 groups");
        assert_eq!(verify(RFC_SECRET, "050\t471", t), Some(s));
        for bad in [
            "",
            "      ",
            "50471",
            "0504711",
            "050471 1",
            "05047a",
            "+50471",
            "-50471",
            "050-471",
            "050_471",
            "0x5047",
            "050471\0",
            "０５０４７１",       // fullwidth digits
            "٠٥٠٤٧١",             // Arabic-Indic digits
            "050471050471050471", // a longer string that merely starts with the code
        ] {
            assert_eq!(verify(RFC_SECRET, bad, t), None, "{bad:?} must be refused");
        }
        let long = "0".repeat(100_000);
        assert_eq!(verify(RFC_SECRET, &long, t), None, "huge input refused");
    }

    #[test]
    fn wrong_code_and_wrong_secret_fail() {
        let t = 1111111111;
        let s = t / 30;
        let wrong = format!("{:06}", (code_at(RFC_SECRET, s) + 1) % 1_000_000);
        assert_eq!(verify(RFC_SECRET, &wrong, t), None, "off-by-one code");
        let other = b"12345678901234567891";
        assert_eq!(verify(other, &code_str(RFC_SECRET, s), t), None, "code from another secret");
    }

    #[test]
    fn short_secrets_never_verify() {
        let t = 1111111111;
        let s = t / 30;
        for n in [0, 1, 10, 15] {
            let secret = &RFC_SECRET[..n];
            assert_eq!(verify(secret, &code_str(secret, s), t), None, "{n}-byte secret, its own code");
        }
        let short = base32_decode("MY").unwrap();
        assert_eq!(verify(&short, &code_str(&short, s), t), None, "1 byte from a mistyped secret");
        let secret = &RFC_SECRET[..16];
        assert_eq!(verify(secret, &code_str(secret, s), t), Some(s), "128 bits is enough");
    }

    #[test]
    fn clock_near_epoch_skips_negative_steps() {
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, 0), 0), Some(0));
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, 1), 0), Some(1));
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, -1), 0), None, "step -1 is not a step");
        assert_eq!(verify(RFC_SECRET, &code_str(RFC_SECRET, 0), -1), Some(0), "pre-epoch clock");
    }

    #[test]
    fn new_secrets_are_random() {
        let (a, b) = (new_secret(), new_secret());
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 20]);
        assert_eq!(base32_encode(&a).len(), 32, "20 bytes is exactly 32 symbols, no padding");
        assert_eq!(base32_decode(&base32_encode(&a)).unwrap(), a);
    }

    /// RFC 4648 section 10, with the padding removed for encode.
    const B32_VECTORS: &[(&str, &str)] = &[
        ("", ""),
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ];

    #[test]
    fn base32_rfc4648_vectors() {
        for &(raw, padded) in B32_VECTORS {
            let bare = padded.trim_end_matches('=');
            assert_eq!(base32_encode(raw.as_bytes()), bare, "encode {raw:?}");
            assert_eq!(base32_decode(padded).as_deref(), Some(raw.as_bytes()), "decode {padded:?}");
            assert_eq!(base32_decode(bare).as_deref(), Some(raw.as_bytes()), "decode {bare:?}");
            let lower = bare.to_ascii_lowercase();
            assert_eq!(base32_decode(&lower).as_deref(), Some(raw.as_bytes()), "decode {lower:?}");
        }
        assert_eq!(base32_encode(RFC_SECRET), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn base32_decode_tolerates_app_formatting() {
        let want = Some(RFC_SECRET.to_vec());
        assert_eq!(base32_decode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"), want, "spaced groups");
        assert_eq!(base32_decode("gezd gnbv gy3t qojq\ngezd gnbv gy3t qojq "), want, "lowercase, newline");
        assert_eq!(base32_decode("MZXW6YQ = "), Some(b"foob".to_vec()), "space around padding");
        assert_eq!(base32_decode("MY=========="), Some(b"f".to_vec()), "excess padding");
    }

    #[test]
    fn base32_decode_refuses_garbage() {
        for bad in [
            "MZXW0", // 0, 1, 8, 9 are not in the alphabet
            "MZXW1",
            "MZXW8",
            "MZXW9",
            "MZXW6!",
            "MZXW6é",
            "MZ=XQ",     // padding in the middle
            "MY==MY==",  // data after padding
            "M",         // 1 symbol: not even one byte
            "MZX",       // 3 symbols
            "MZXW6Y",    // 6 symbols
            "MZXW6YTBO", // 9 symbols = 1 mod 8
            "MZXW-6YTB",
        ] {
            assert_eq!(base32_decode(bad), None, "{bad:?} must be refused");
        }
    }

    #[test]
    fn base32_round_trips_every_length() {
        let data: Vec<u8> = (0..=255u8).collect();
        for n in 0..=40 {
            let s = base32_encode(&data[..n]);
            assert!(!s.contains('='), "no padding emitted");
            assert_eq!(base32_decode(&s).as_deref(), Some(&data[..n]), "length {n}");
        }
    }

    #[test]
    fn otpauth_uri_layout() {
        assert_eq!(
            otpauth_uri("l4f.cc", "luki", RFC_SECRET),
            "otpauth://totp/l4f.cc:luki?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=l4f.cc&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn otpauth_uri_percent_encodes_label_and_issuer() {
        let uri = otpauth_uri("L4F & Co", "a b:c/é?x=1#y+z~_-.", b"Hello!");
        assert_eq!(
            uri,
            "otpauth://totp/L4F%20%26%20Co:a%20b%3Ac%2F%C3%A9%3Fx%3D1%23y%2Bz~_-.\
             ?secret=JBSWY3DPEE&issuer=L4F%20%26%20Co&algorithm=SHA1&digits=6&period=30"
        );
        assert!(!uri.contains('+'), "spaces must be %20, apps show a literal +");
        assert_eq!(uri.matches('?').count(), 1, "a ? in the account cannot start the query early");
        assert_eq!(uri.matches(':').count(), 2, "only the scheme and label separators stay literal");
    }
}
