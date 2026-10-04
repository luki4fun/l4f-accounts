//! One-line messages after a redirect (post/redirect/get), carried in the
//! query string and signed, so a link cannot make the site say anything else.

use axum::response::Response;
use serde::Deserialize;

use super::see_other;
use crate::keys::Keys;
use crate::util;

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct Query {
    ok: Option<String>,
    err: Option<String>,
    sig: Option<String>,
}

pub(super) struct Flash {
    pub good: bool,
    pub msg: String,
}

fn sig(keys: &Keys, kind: &str, msg: &str) -> String {
    keys.sign("notice", format!("{kind}\0{msg}").as_bytes())
}

/// `path` with the message attached.
pub(super) fn url(keys: &Keys, path: &str, good: bool, msg: &str) -> String {
    let kind = if good { "ok" } else { "err" };
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}{kind}={}&sig={}", util::urlencode(msg), sig(keys, kind, msg))
}

/// 303 to `path` with the message, plus cookies.
pub(super) fn to(keys: &Keys, path: &str, good: bool, msg: &str, cookies: &[String]) -> Response {
    see_other(&url(keys, path, good, msg), cookies)
}

/// The message in the query, if its signature holds.
pub(super) fn read(keys: &Keys, q: &Query) -> Option<Flash> {
    let (good, msg) = match (&q.ok, &q.err) {
        (Some(m), None) => (true, m),
        (None, Some(m)) => (false, m),
        _ => return None,
    };
    let kind = if good { "ok" } else { "err" };
    keys.verify("notice", format!("{kind}\0{msg}").as_bytes(), q.sig.as_deref()?).then(|| Flash { good, msg: msg.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_signed_messages_show() {
        let k = Keys::new(&[5; 32], None).unwrap();
        let s = sig(&k, "ok", "Saved.");
        let q = |ok: Option<&str>, err: Option<&str>, sig: &str| Query {
            ok: ok.map(String::from),
            err: err.map(String::from),
            sig: Some(sig.to_string()),
        };
        assert!(read(&k, &q(Some("Saved."), None, &s)).is_some_and(|f| f.good && f.msg == "Saved."));
        assert!(read(&k, &q(Some("Pay here."), None, &s)).is_none(), "another text");
        assert!(read(&k, &q(None, Some("Saved."), &s)).is_none(), "another kind");
        assert!(read(&k, &q(Some("Saved."), Some("x"), &s)).is_none());
        assert!(read(&k, &Query::default()).is_none());
    }
}
