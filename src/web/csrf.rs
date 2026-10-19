//! One CSRF check in front of every route of the crate router.
//!
//! - GET and HEAD never change state and pass.
//! - Any other method from another site (`Sec-Fetch-Site` cross-site, or
//!   same-site, which covers sibling `*.l4f.cc` hosts) is refused. A browser
//!   without Fetch Metadata still sends `Origin`: without the header, a
//!   request whose `Origin` is not one of `Config::origins`, or is `null`, is
//!   refused too.
//! - With a session cookie, the request must also carry that session's token:
//!   the `X-CSRF` header, or the `csrf` field of an urlencoded form. The body
//!   is read here (72 KiB at most) and handed on unchanged. Raw bodies never
//!   are; they must send the header.
//! - Without a session cookie there is no session to ride on, and the handler
//!   (login, sign-up) has its own `Sec-Fetch-Site` check.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::Response,
};

use super::{WebHost, error_page, header_str, session_token};
use crate::keys::Keys;
use crate::service::{Accounts, Config, token_hash};
use crate::util;

const FORM_LIMIT: usize = 72 * 1024;

/// The form token of the session whose token hashes to `hash`.
pub(super) fn token(keys: &Keys, hash: &[u8; 32]) -> String {
    keys.sign("csrf", hex::encode(hash).as_bytes())
}

/// The raw value of `name` in an urlencoded body. Tokens are base64url, which
/// needs no percent-decoding; an encoded one simply does not match.
fn form_field<'a>(body: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(body).ok()?.split('&').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k == name).then_some(v)
    })
}

/// An `Origin` header naming one of the site's own origins. `null` never
/// does: any page can make its own origin `null`.
fn our_origin(cfg: &Config, origin: &[u8]) -> bool {
    origin != b"null" && cfg.origins().iter().any(|o| o.trim_end_matches('/').as_bytes().eq_ignore_ascii_case(origin))
}

const EXPIRED: &str = "This form expired or came from another site. Go back, reload and try again.";

fn refuse<H: WebHost>(status: StatusCode, a: &Accounts<H>, h: &axum::http::HeaderMap) -> Response {
    let msg = if status == StatusCode::PAYLOAD_TOO_LARGE { "That form is too large." } else { EXPIRED };
    error_page(a, h, status, msg)
}

pub(super) async fn layer<H: WebHost>(State(a): State<Arc<Accounts<H>>>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD) {
        return next.run(req).await;
    }
    let h = req.headers();
    let cfg = a.host.config();
    let foreign = match header_str(h, "sec-fetch-site") {
        "cross-site" | "same-site" => true,
        "" => h.get(header::ORIGIN).is_some_and(|o| !our_origin(&cfg, o.as_bytes())),
        _ => false,
    };
    if foreign {
        return refuse(StatusCode::FORBIDDEN, &a, h);
    }
    let Some(hash) = session_token(&cfg, h).and_then(token_hash) else {
        return next.run(req).await;
    };
    let want = token(&a.keys, &hash);
    if let Some(got) = h.get("x-csrf") {
        if util::ct_eq(got.to_str().unwrap_or(""), &want) {
            return next.run(req).await;
        }
        return refuse(StatusCode::FORBIDDEN, &a, h);
    }
    if !header_str(h, header::CONTENT_TYPE).starts_with("application/x-www-form-urlencoded") {
        return refuse(StatusCode::FORBIDDEN, &a, h);
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, FORM_LIMIT).await else {
        return refuse(StatusCode::PAYLOAD_TOO_LARGE, &a, &parts.headers);
    };
    if !form_field(&bytes, "csrf").is_some_and(|got| util::ct_eq(got, &want)) {
        return refuse(StatusCode::FORBIDDEN, &a, &parts.headers);
    }
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

#[cfg(test)]
mod tests {
    use super::form_field;

    #[test]
    fn form_field_finds_the_raw_value() {
        assert_eq!(form_field(b"a=1&csrf=abc_-9&b=2", "csrf"), Some("abc_-9"));
        assert_eq!(form_field(b"xcsrf=1&csrfx=2", "csrf"), None);
        assert_eq!(form_field(b"csrf", "csrf"), None);
        assert_eq!(form_field(b"\xff=1", "csrf"), None);
    }
}
