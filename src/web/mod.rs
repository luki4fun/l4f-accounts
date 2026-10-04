//! The axum layer: thin handlers that turn a request into one service call
//! and render a body fragment, which the host wraps in its own page shell
//! (`WebHost::page`). Every page works without JavaScript.
//!
//! The host must:
//! - nest `router()` at [`BASE`];
//! - insert [`ClientIp`] into every request after its own proxy check;
//! - serve `/static/js/pow.js` (the ALTCHA solver the sign-up form loads).

mod account;
mod admin;
mod auth;
mod csrf;
mod extract;
mod flash;
mod mfa;
mod passkey;
#[cfg(test)]
mod tests;

pub use extract::{Authed, PendingMfa, Viewer};

use std::{net::IpAddr, sync::Arc};

use askama::Template;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};

use crate::model::AccountId;
use crate::service::{Accounts, Config, Error, Host};
use crate::util;

/// Where the host nests the router. Redirects and form actions use it.
pub const BASE: &str = "/account";

const DAY: u64 = 86_400;
const DEVICE_DAYS: u64 = 365;

/// What the web layer needs from the host beyond `Host`.
pub trait WebHost: Host {
    /// Wraps a body fragment (rendered and escaped by the crate) in the site's
    /// page. Account pages are noindex and carry no canonical link.
    fn page(&self, headers: &HeaderMap, title: &str, body: String) -> Response;

    /// The host's own pages a signed-in account can use, as (label, href),
    /// listed on the dashboard. `scopes` are the session's.
    fn dashboard_links(&self, scopes: &[String]) -> Vec<(String, String)> {
        let _ = scopes;
        Vec::new()
    }
}

/// The client address as the host's proxy check established it, inserted as
/// a request extension before the router runs. Without it, every handler that
/// needs a `Ctx` answers 500: failing closed beats rate-limiting the proxy.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

/// How the extractors reach the service from the router state: the crate's
/// own `Arc<Accounts<H>>`, or a host's state holding one.
pub trait AccountsState: Clone + Send + Sync + 'static {
    type Host: WebHost;
    fn accounts(&self) -> &Accounts<Self::Host>;
}

impl<H: WebHost> AccountsState for Arc<Accounts<H>> {
    type Host = H;
    fn accounts(&self) -> &Accounts<H> {
        self
    }
}

/// The `/account` pages, for any host state `S`.
pub fn router<H: WebHost, S: Clone + Send + Sync + 'static>(a: Arc<Accounts<H>>) -> Router<S> {
    Router::new()
        .route("/", get(account::dashboard::<H>))
        .route("/sessions/{id}/revoke", post(account::revoke::<H>))
        .route("/display-name", post(account::display_name::<H>))
        .route("/data", get(account::export::<H>))
        .route("/delete", get(account::delete_form::<H>).post(account::delete::<H>))
        .route("/admin/users", get(admin::users::<H>))
        .route("/admin/users/{id}", get(admin::user::<H>).post(admin::user_action::<H>))
        .route("/admin/roles", get(admin::roles::<H>).post(admin::role_create::<H>))
        .route("/admin/roles/{name}", get(admin::role::<H>).post(admin::role_action::<H>))
        .route("/mfa", get(mfa::mfa_form::<H>).post(mfa::mfa::<H>))
        .route("/security", get(mfa::security::<H>))
        .route("/totp", get(mfa::totp_form::<H>).post(mfa::totp::<H>))
        .route("/recovery", post(mfa::recovery::<H>))
        .route("/passkey/options/login", post(passkey::options_login::<H>))
        .route("/passkey/options/add", post(passkey::options_add::<H>))
        .route("/passkey/options/mfa", post(passkey::options_mfa::<H>))
        .route("/passkey/options/step-up", post(passkey::options_step_up::<H>))
        .route("/passkey/login", post(passkey::login::<H>))
        .route("/passkey/add", post(passkey::add::<H>))
        .route("/passkey/mfa", post(passkey::mfa::<H>))
        .route("/passkey/step-up", post(passkey::step_up::<H>))
        .route("/passkey/{id}/delete", post(passkey::remove::<H>))
        .route("/assets/passkey.js", get(passkey::script))
        .route("/login", get(auth::login_form::<H>).post(auth::login::<H>))
        .route("/logout", post(auth::logout::<H>))
        .route("/logout-all", post(auth::logout_all::<H>))
        .route("/register", get(auth::register_form::<H>).post(auth::register::<H>))
        .route("/reauth", get(auth::reauth_form::<H>).post(auth::reauth::<H>))
        .route_layer(middleware::from_fn_with_state(a.clone(), csrf::layer::<H>))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::map_response(no_store))
        .with_state(a)
}

/// Account pages are per person: never cached, never shared. A handler that
/// set its own Cache-Control keeps it.
async fn no_store(mut r: Response) -> Response {
    if !r.headers().contains_key(header::CACHE_CONTROL) {
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    }
    r
}

type St<H> = axum::extract::State<Arc<Accounts<H>>>;

fn header_str(h: &HeaderMap, name: impl header::AsHeaderName) -> &str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

// ---- cookies

fn session_name(cfg: &Config) -> String {
    util::cookie_name("acct", cfg.cookie_secure)
}

fn device_name(cfg: &Config) -> String {
    util::cookie_name("acct-dev", cfg.cookie_secure)
}

/// The session cookie's value, if any. Not checked against the database.
fn session_token<'a>(cfg: &Config, h: &'a HeaderMap) -> Option<&'a str> {
    util::cookie(h.get(header::COOKIE).and_then(|v| v.to_str().ok()), &session_name(cfg))
}

fn set_session(cfg: &Config, token: &str) -> String {
    let age = u64::try_from(cfg.session_max_days).unwrap_or(0) * DAY;
    util::set_cookie(&session_name(cfg), token, age, cfg.cookie_secure, true)
}

fn clear_session(cfg: &Config) -> String {
    util::set_cookie(&session_name(cfg), "", 0, cfg.cookie_secure, true)
}

/// The known-device cookie: this browser signed in to that account before, so
/// it gets a sign-in bucket of its own that strangers cannot spend.
fn set_device<H: Host>(a: &Accounts<H>, cfg: &Config, user: AccountId) -> String {
    let hex = user.hex();
    let v = format!("{hex}.{}", a.keys.sign("device", hex.as_bytes()));
    util::set_cookie(&device_name(cfg), &v, DEVICE_DAYS * DAY, cfg.cookie_secure, true)
}

fn clear_device(cfg: &Config) -> String {
    util::set_cookie(&device_name(cfg), "", 0, cfg.cookie_secure, true)
}

/// The browser nonce a passkey challenge is bound to: a cookie only this
/// browser sends, so a challenge cannot be completed somewhere else.
fn new_nonce(cfg: &Config) -> (Vec<u8>, String) {
    let n = util::random::<16>();
    let cookie = util::set_cookie(&util::cookie_name("acct-ch", cfg.cookie_secure), &util::b64u(&n), 600, cfg.cookie_secure, true);
    (n.to_vec(), cookie)
}

fn nonce_of(cfg: &Config, h: &HeaderMap) -> Vec<u8> {
    util::cookie(h.get(header::COOKIE).and_then(|v| v.to_str().ok()), &util::cookie_name("acct-ch", cfg.cookie_secure))
        .and_then(util::b64u_dec)
        .unwrap_or_default()
}

fn known_device<H: Host>(a: &Accounts<H>, cfg: &Config, h: &HeaderMap) -> Option<AccountId> {
    let v = util::cookie(h.get(header::COOKIE).and_then(|v| v.to_str().ok()), &device_name(cfg))?;
    let (hex, sig) = v.split_once('.')?;
    a.keys.verify("device", hex.as_bytes(), sig).then(|| AccountId::parse_hex(hex)).flatten()
}

/// The form token for whatever session cookie the request carries, valid or
/// not: the CSRF layer checks every POST that comes with one.
fn csrf_for_cookie<H: Host>(a: &Accounts<H>, h: &HeaderMap) -> Option<String> {
    let cfg = a.host.config();
    let hash = crate::service::token_hash(session_token(&cfg, h)?)?;
    Some(csrf::token(&a.keys, &hash))
}

// ---- responses

/// 303 to `to`, with cookies.
fn see_other(to: &str, cookies: &[String]) -> Response {
    let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

fn page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, title: &str, status: StatusCode, t: &impl Template) -> Response {
    match t.render() {
        Ok(body) => {
            let mut r = a.host.page(h, title, body);
            *r.status_mut() = status;
            r
        }
        Err(e) => {
            tracing::error!(target: "accounts", error = %e, "template error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTpl<'a> {
    msg: &'a str,
    base: &'static str,
}

/// A page with one sentence and a way back, inside the host's shell. Public so
/// the host's own scope-guarded pages refuse the same way.
pub fn error_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, msg: &str) -> Response {
    page(a, h, "Something went wrong", status, &ErrorTpl { msg, base: BASE })
}

/// A JSON answer for the scripts, with cookies.
fn json_ok(v: serde_json::Value, cookies: &[String]) -> Response {
    let mut r = axum::Json(v).into_response();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

/// A refusal for the scripts: never a 2xx, and the sentence to show.
fn json_refused(e: &Error) -> Response {
    if let Error::Db(err) = e {
        tracing::error!(target: "accounts", error = %err, "database error");
    }
    let status = match status_of(e) {
        StatusCode::OK => StatusCode::BAD_REQUEST,
        s => s,
    };
    (status, axum::Json(serde_json::json!({ "error": e.message() }))).into_response()
}

/// The status a refused service call answers with when its page is shown again.
fn status_of(e: &Error) -> StatusCode {
    match e {
        Error::Gate(d) if matches!(d.outcome, "rate_limited" | "global_cap") => StatusCode::TOO_MANY_REQUESTS,
        Error::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        Error::Busy => StatusCode::SERVICE_UNAVAILABLE,
        Error::Forbidden | Error::CrossSite | Error::Closed | Error::SignupClosed => StatusCode::FORBIDDEN,
        Error::NotFound => StatusCode::NOT_FOUND,
        Error::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Gate(_)
        | Error::Invalid(_)
        | Error::UsernameTaken
        | Error::RoleTaken
        | Error::BadLogin
        | Error::LastAdmin
        | Error::Builtin => StatusCode::OK,
    }
}

/// The error page for a refused call, with `Retry-After` when busy. A database
/// error is logged here, once.
fn refused<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, e: &Error) -> Response {
    if let Error::Db(err) = e {
        tracing::error!(target: "accounts", error = %err, "database error");
    }
    let mut r = error_page(a, h, status_of(e), e.message());
    if matches!(e, Error::Busy) {
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    }
    r
}

/// `2026-10-04 17:30 UTC`, for timestamps shown to people. No date crate for one
/// format: days to civil date after Howard Hinnant's `civil_from_days`.
pub(crate) fn when(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", secs / 3600, secs % 3600 / 60)
}
