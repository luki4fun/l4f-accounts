//! What of a client address may be stored. Applied before anything reaches the
//! database: session rows, the audit log, and the host app's own logs.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::net::IpAddr;

/// A closed set, so a typo in the config is a parse error instead of silently
/// falling through to the least private option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpMode {
    /// YOURLS parity.
    #[default]
    Full,
    Truncate,
    Hash,
    None,
}

pub fn shape_ip(ip: IpAddr, mode: IpMode, salt: &[u8]) -> String {
    let ip = ip.to_canonical(); // ::ffff:a.b.c.d is an IPv4 client
    match mode {
        IpMode::None => String::new(),
        // The mode can be hot-reloaded while the salt is only checked at boot.
        // An unsalted hash of an IPv4 address is reversible, so store nothing.
        IpMode::Hash if salt.len() < 32 => {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| tracing::error!("ip_mode is \"hash\" but the IP salt is under 32 characters: storing no addresses"));
            String::new()
        }
        IpMode::Hash => {
            let mut m = <Hmac<Sha256>>::new_from_slice(salt).expect("hmac accepts any key length");
            m.update(ip.to_string().as_bytes());
            hex::encode(&m.finalize().into_bytes()[..8])
        }
        IpMode::Truncate => match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.0", o[0], o[1], o[2])
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                // keep the /48
                std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0).to_string()
            }
        },
        IpMode::Full => ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_shaping() {
        let v4: IpAddr = "203.0.113.42".parse().unwrap();
        assert_eq!(shape_ip(v4, IpMode::Full, b""), "203.0.113.42");
        assert_eq!(shape_ip(v4, IpMode::Truncate, b""), "203.0.113.0");
        assert_eq!(shape_ip(v4, IpMode::None, b""), "");
        assert_eq!(shape_ip(v4, IpMode::Hash, &[7; 32]).len(), 16);
        assert_eq!(shape_ip(v4, IpMode::Hash, b"short"), "", "a short salt stores nothing");
        let v6: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        assert_eq!(shape_ip(v6, IpMode::Truncate, b""), "2001:db8:abcd::");
        let mapped: IpAddr = "::ffff:203.0.113.42".parse().unwrap();
        assert_eq!(shape_ip(mapped, IpMode::Truncate, b""), "203.0.113.0");
        assert_eq!(shape_ip(mapped, IpMode::Hash, &[7; 32]), shape_ip(v4, IpMode::Hash, &[7; 32]));
    }

    #[test]
    fn mode_names_are_the_config_spellings() {
        #[derive(Deserialize)]
        struct C {
            m: IpMode,
        }
        for (s, m) in [("full", IpMode::Full), ("truncate", IpMode::Truncate), ("hash", IpMode::Hash), ("none", IpMode::None)] {
            let c: C = serde_json::from_str(&format!("{{\"m\":\"{s}\"}}")).unwrap();
            assert_eq!(c.m, m);
        }
        assert!(serde_json::from_str::<C>("{\"m\":\"Full\"}").is_err(), "a typo must not parse");
    }
}
