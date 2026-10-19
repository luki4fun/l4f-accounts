pub mod devkey;
pub mod sshsig;
pub mod webauthn;

/// The Ed25519 points of order 1, 2, 4 and 8, sign bit cleared, plus the
/// non-canonical `p` and `p + 1` (0 and 1 unreduced): libsodium's
/// `has_small_order` list. ring accepts them all as keys.
pub(crate) const ED25519_SMALL_ORDER: [[u8; 32]; 7] = [
    le(0x00, 0x00, 0x00), // y = 0, order 4
    le(0x01, 0x00, 0x00), // the identity
    // order 8, as is the next
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, //
        0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, //
        0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
    ],
    le(0xec, 0xff, 0x7f), // p - 1, order 2
    le(0xed, 0xff, 0x7f), // p, a non-canonical 0
    le(0xee, 0xff, 0x7f), // p + 1, a non-canonical identity
];

/// 32 little-endian bytes: `low`, then 30 times `fill`, then `high`.
const fn le(low: u8, fill: u8, high: u8) -> [u8; 32] {
    let mut b = [fill; 32];
    b[0] = low;
    b[31] = high;
    b
}

/// A key of small order verifies `R || 0` for a small-order `R` whatever the
/// message (the identity verifies one fixed signature for every message), so
/// it binds nothing: it would let anyone in, and its proof of possession at
/// enrolment is just as forgeable. The sign bit is ignored: it only picks `x`
/// or `-x`, which does not change the order.
pub(crate) fn ed25519_small_order(pk: &[u8; 32]) -> bool {
    ED25519_SMALL_ORDER.iter().any(|b| b[..31] == pk[..31] && b[31] == pk[31] & 0x7f)
}

/// The magnitude of a positive integer in its one minimal encoding, which DER
/// INTEGERs and SSH mpints share: a sign byte only where the top bit needs one.
pub(crate) fn positive_int(b: &[u8]) -> Option<&[u8]> {
    match b {
        [0, rest @ ..] if rest.first().is_some_and(|x| x & 0x80 != 0) => Some(rest),
        [x, ..] if *x != 0 && *x & 0x80 == 0 => Some(b),
        // zero, negative, a needless leading zero, or nothing
        _ => None,
    }
}

/// ring refuses larger RSA exponents at every verify.
const MAX_RSA_E: u64 = (1 << 33) - 1;

/// Why `rsa_bounds` refused a key.
pub(crate) enum RsaBounds {
    /// The modulus is outside 2048..=8192 bits.
    Size,
    /// The exponent is above ring's 2^33 - 1.
    Exponent,
    /// An even modulus, or an even or tiny exponent: no RSA key at all.
    NotRsa,
}

/// The RSA keys ring verifies with, checked in this order: modulus size,
/// exponent size, oddness. `n` and `e` are `positive_int` magnitudes. Checked
/// when a key comes in, so a stored key can always be used.
pub(crate) fn rsa_bounds(n: &[u8], e: &[u8]) -> Result<(), RsaBounds> {
    if !(2048..=8192).contains(&bits(n)) {
        return Err(RsaBounds::Size);
    }
    // The length check also keeps the u64 fold below from shifting bytes out.
    if e.len() > 5 {
        return Err(RsaBounds::Exponent);
    }
    let ev = e.iter().fold(0u64, |a, b| a << 8 | u64::from(*b));
    if ev > MAX_RSA_E {
        return Err(RsaBounds::Exponent);
    }
    if ev < 3 || ev & 1 == 0 || n.last().is_some_and(|b| b & 1 == 0) {
        return Err(RsaBounds::NotRsa);
    }
    Ok(())
}

fn bits(n: &[u8]) -> usize {
    n.first().map_or(0, |b| n.len() * 8 - b.leading_zeros() as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_count_from_the_top_set_bit() {
        assert_eq!(bits(&[0x01, 0, 0]), 17);
        assert_eq!(bits(&[0x80; 256]), 2048);
        assert_eq!(bits(&[]), 0);
    }
}
