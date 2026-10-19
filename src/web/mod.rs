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
mod keylogin;
mod mail;
mod mfa;
mod passkey;
mod profile;
#[cfg(feature = "oauth")]
mod social;
mod storage;
#[cfg(test)]
mod tests;

pub use extract::{Authed, PendingMfa, Viewer};
pub use profile::profile_router;

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
use crate::service::{Accounts, Config, Error, Host, NewSession};
use crate::util;

/// Where the host nests the router. Redirects and form actions use it.
pub const BASE: &str = crate::service::ACCOUNT_PATH;
/// The pages most redirects lead to. Spelled out, as `concat!` cannot take
/// `BASE`; a test holds them under it.
const LOGIN_PAGE: &str = "/account/login";
const SECURITY_PAGE: &str = "/account/security";

const DAY: u64 = 86_400;
const DEVICE_DAYS: u64 = 365;

/// What the web layer needs from the host beyond `Host`.
pub trait WebHost: Host {
    /// Wraps a body fragment (rendered and escaped by the crate) in the site's
    /// page. `title` is plain text: the host escapes it like any value it puts
    /// in HTML. Account pages are noindex and carry no canonical link.
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
    let r = Router::new();
    #[cfg(feature = "email")]
    let r = r
        .route("/email", get(mail::email_form::<H>).post(mail::email::<H>))
        .route("/verify-email", get(mail::verify_form::<H>).post(mail::verify::<H>))
        .route("/forgot", get(mail::forgot_form::<H>).post(mail::forgot::<H>))
        .route("/reset", get(mail::reset_form::<H>).post(mail::reset::<H>));
    #[cfg(feature = "oauth")]
    let r = r
        .route("/oauth/signup", get(social::signup_form::<H>).post(social::signup::<H>))
        .route("/oauth/{p}", get(social::start::<H>))
        .route("/oauth/{p}/cb", get(social::callback::<H>))
        .route("/oauth/{p}/unlink", post(social::unlink::<H>));
    r.route("/password", get(mail::password_form::<H>).post(mail::password::<H>))
        .route("/api/kv", get(storage::kv_list::<H>))
        .route("/api/kv/{k}", axum::routing::put(storage::kv_put::<H>).delete(storage::kv_delete::<H>))
        .route("/sync", post(storage::sync::<H>))
        .route("/api/vault", get(storage::vault_list::<H>))
        .route(
            "/api/vault/items/{k}",
            // An item is up to 72 KiB of ciphertext, past the router's 64 KiB.
            axum::routing::put(storage::vault_put_item::<H>).delete(storage::vault_delete_item::<H>).layer(DefaultBodyLimit::max(80 * 1024)),
        )
        .route("/api/vault/slots/{k}", axum::routing::put(storage::vault_put_slot::<H>).delete(storage::vault_delete_slot::<H>))
        .route("/vault", get(storage::vault_page::<H>))
        .route("/vault/wipe", post(storage::vault_wipe::<H>))
        .route("/profile", get(profile::settings::<H>).post(profile::save::<H>))
        .route("/api/avatar", axum::routing::put(profile::avatar_put::<H>))
        .route("/assets/avatar.js", get(profile::avatar_script))
        .route("/assets/sync.js", get(storage::sync_script))
        .route("/assets/vault.js", get(storage::vault_script))
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
        .route("/assets/passkey.js", get(passkey::script))
        .route("/login/ssh", get(keylogin::ssh_login_form::<H>).post(keylogin::ssh_login::<H>))
        .route("/ssh", get(keylogin::ssh_add_form::<H>).post(keylogin::ssh_add::<H>))
        .route("/devkey/options/add", post(keylogin::devkey_options_add::<H>))
        .route("/devkey/options/login", post(keylogin::devkey_options_login::<H>))
        .route("/devkey/add", post(keylogin::devkey_add::<H>))
        .route("/devkey/login", post(keylogin::devkey_login::<H>))
        .route("/assets/devkey.js", get(keylogin::devkey_script))
        .route("/credentials/{kind}/{id}/delete", post(keylogin::remove::<H>))
        .route("/login", get(auth::login_form::<H>).post(auth::login::<H>))
        .route("/logout", post(auth::logout::<H>))
        .route("/logout-all", post(auth::logout_all::<H>))
        .route("/register", get(auth::register_form::<H>).post(auth::register::<H>))
        .route("/reauth", get(auth::reauth_form::<H>).post(auth::reauth::<H>))
        .route_layer(middleware::from_fn_with_state(a.clone(), csrf::layer::<H>))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::map_response(account_headers))
        .with_state(a)
}

/// Account pages are per person: never cached, never shared. Never framed
/// either, or a sibling host could lay them under its own page and have a
/// click land on a security button. A handler, or the host's page, that set
/// its own Cache-Control or X-Frame-Options keeps it.
async fn account_headers(mut r: Response) -> Response {
    let h = r.headers_mut();
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    }
    if !h.contains_key(header::X_FRAME_OPTIONS) {
        h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    r
}

type St<H> = axum::extract::State<Arc<Accounts<H>>>;

fn header_str(h: &HeaderMap, name: impl header::AsHeaderName) -> &str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

// ---- cookies

const SESSION_COOKIE: &str = "acct";
const DEVICE_COOKIE: &str = "acct-dev";
const CHALLENGE_COOKIE: &str = "acct-ch";
const SYNC_COOKIE: &str = "acct-sync";

/// A crate cookie named `base`: the `__Host-` prefix and Secure both follow
/// `cookie_secure`, from one place. A prefixed cookie without Secure is one
/// the browser drops.
fn cookie_out(cfg: &Config, base: &str, value: &str, max_age: u64, http_only: bool) -> String {
    util::set_cookie(&util::cookie_name(base, cfg.cookie_secure), value, max_age, cfg.cookie_secure, http_only)
}

/// The request's crate cookie named `base`, if any.
fn cookie_in<'a>(cfg: &Config, h: &'a HeaderMap, base: &str) -> Option<&'a str> {
    util::cookie(h.get(header::COOKIE).and_then(|v| v.to_str().ok()), &util::cookie_name(base, cfg.cookie_secure))
}

/// The session cookie's value, if any. Not checked against the database.
fn session_token<'a>(cfg: &Config, h: &'a HeaderMap) -> Option<&'a str> {
    cookie_in(cfg, h, SESSION_COOKIE)
}

fn set_session(cfg: &Config, token: &str) -> String {
    let age = u64::try_from(cfg.session_max_days).unwrap_or(0) * DAY;
    cookie_out(cfg, SESSION_COOKIE, token, age, true)
}

/// The hint `lib.js` reads to load the sync script. Not HttpOnly on purpose:
/// it only says that sync is on, and a script has to see it.
fn sync_hint(cfg: &Config, on: bool) -> String {
    let age = if on { u64::try_from(cfg.session_max_days).unwrap_or(0) * DAY } else { 0 };
    cookie_out(cfg, SYNC_COOKIE, if on { "1" } else { "" }, age, false)
}

/// The cookies of a completed sign-in: the session, the known device, and the
/// sync hint as the account has it.
async fn signed_in<H: Host>(a: &Accounts<H>, s: &NewSession) -> Vec<String> {
    let cfg = a.host.config();
    let sync = a.store.user_by_id(s.info.user_id).await.ok().flatten().is_some_and(|u| u.sync_enabled);
    vec![set_session(&cfg, &s.token), set_device(a, &cfg, s.info.user_id), sync_hint(&cfg, sync)]
}

fn clear_session(cfg: &Config) -> String {
    cookie_out(cfg, SESSION_COOKIE, "", 0, true)
}

/// The known-device cookie: this browser signed in to that account before, so
/// it gets a sign-in bucket of its own that strangers cannot spend.
fn set_device<H: Host>(a: &Accounts<H>, cfg: &Config, user: AccountId) -> String {
    let hex = user.hex();
    let v = format!("{hex}.{}", a.keys.sign("device", hex.as_bytes()));
    cookie_out(cfg, DEVICE_COOKIE, &v, DEVICE_DAYS * DAY, true)
}

fn clear_device(cfg: &Config) -> String {
    cookie_out(cfg, DEVICE_COOKIE, "", 0, true)
}

/// The browser nonce a passkey challenge is bound to: a cookie only this
/// browser sends, so a challenge cannot be completed somewhere else.
fn new_nonce(cfg: &Config) -> (Vec<u8>, String) {
    let n = util::random::<16>();
    (n.to_vec(), cookie_out(cfg, CHALLENGE_COOKIE, &util::b64u(&n), 600, true))
}

fn nonce_of(cfg: &Config, h: &HeaderMap) -> Vec<u8> {
    cookie_in(cfg, h, CHALLENGE_COOKIE).and_then(util::b64u_dec).unwrap_or_default()
}

fn known_device<H: Host>(a: &Accounts<H>, cfg: &Config, h: &HeaderMap) -> Option<AccountId> {
    let v = cookie_in(cfg, h, DEVICE_COOKIE)?;
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

/// `r` with a Set-Cookie for each of `cookies`.
fn with_cookies(mut r: Response, cookies: &[String]) -> Response {
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

/// 303 to `to`, with cookies.
fn see_other(to: &str, cookies: &[String]) -> Response {
    with_cookies((StatusCode::SEE_OTHER, [(header::LOCATION, to)]).into_response(), cookies)
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

/// The configured social providers as (slug, label); none without the feature.
fn providers<H: Host>(a: &Accounts<H>) -> Vec<(&'static str, &'static str)> {
    #[cfg(feature = "oauth")]
    return a.oauth_kinds().into_iter().map(|k| (k.slug(), k.label())).collect();
    #[cfg(not(feature = "oauth"))]
    {
        let _ = a;
        Vec::new()
    }
}

/// A JSON answer for the scripts, with cookies.
fn json_ok(v: serde_json::Value, cookies: &[String]) -> Response {
    with_cookies(axum::Json(v).into_response(), cookies)
}

/// A refusal for the scripts: never a 2xx, and the sentence to show.
fn json_refused(e: &Error) -> Response {
    let status = match status_of(e) {
        StatusCode::OK => StatusCode::BAD_REQUEST,
        s => s,
    };
    (status, axum::Json(serde_json::json!({ "error": e.message() }))).into_response()
}

/// The JSON answer to a sign-in: its cookies and where to go next.
async fn json_signed_in<H: Host>(a: &Accounts<H>, r: Result<NewSession, Error>, next: &str) -> Response {
    match r {
        Ok(s) => json_ok(serde_json::json!({ "next": util::safe_next(next, BASE) }), &signed_in(a, &s).await),
        Err(e) => json_refused(&e),
    }
}

/// The status a refused service call answers with when its page is shown
/// again. Every refusal comes through here once, so a database error is
/// logged here.
fn status_of(e: &Error) -> StatusCode {
    if let Error::Db(err) = e {
        tracing::error!(target: "accounts", error = %err, "database error");
    }
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

/// The error page for a refused call, with `Retry-After` when busy.
fn refused<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, e: &Error) -> Response {
    let mut r = error_page(a, h, status_of(e), e.message());
    if matches!(e, Error::Busy) {
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
    }
    r
}

/// After a change: back to `back` with what happened, or why not. Refusals a
/// person can act on become a message; the rest an error page.
fn done<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, back: &str, r: Result<&str, Error>) -> Response {
    match r {
        Ok(msg) => flash::to(&a.keys, back, true, msg, &[]),
        Err(e @ (Error::Invalid(_) | Error::LastAdmin | Error::Builtin | Error::RoleTaken | Error::NotFound)) => {
            flash::to(&a.keys, back, false, e.message(), &[])
        }
        Err(e) => refused(a, h, &e),
    }
}

/// One of the crate's scripts, served from the binary like the templates.
/// `no-cache`: the browser asks every time and keeps nothing stale after an
/// upgrade. `nosniff`: it runs as the JavaScript it says it is, or not at all.
fn script(body: &'static str) -> Response {
    let headers = [
        (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
        (header::CACHE_CONTROL, "no-cache"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    ];
    (headers, body).into_response()
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
