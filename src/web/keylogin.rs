//! SSH key and device key sign-in on the web, and removing any credential.

use askama::Template;
use axum::{
    Form, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::auth::{NextQuery, need_fresh};
use super::flash;
use super::{
    Authed, BASE, St, WebHost, error_page, json_ok, json_refused, new_nonce, nonce_of, page, refused, see_other, set_session,
    status_of,
};
use crate::service::{Accounts, Ctx, Error, LoginStep, NewDeviceKey};
use crate::util;

/// The command the page shows: signs the challenge from stdin, prints the
/// signature. The token is base64url and a dot, safe inside single quotes.
fn command(token: &str, namespace: &str) -> String {
    format!("printf '%s' '{token}' | ssh-keygen -Y sign -n {namespace} -f ~/.ssh/id_ed25519")
}

// ---- SSH sign-in

#[derive(Template)]
#[template(path = "ssh_login.html")]
struct SshLoginTpl<'a> {
    base: &'static str,
    token: &'a str,
    command: &'a str,
    next: &'a str,
    csrf: Option<String>,
    error: Option<&'a str>,
}

fn ssh_login_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, next: &str, error: Option<&str>) -> Response {
    let cfg = a.host.config();
    let (nonce, cookie) = new_nonce(&cfg);
    let token = a.ssh_challenge(None, &nonce);
    let cmd = command(&token, &cfg.ssh_namespace());
    let t = SshLoginTpl { base: BASE, token: &token, command: &cmd, next, csrf: super::csrf_for_cookie(a, h), error };
    let mut r = page(a, h, "Sign in with an SSH key", status, &t);
    if let Ok(v) = cookie.parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

pub(super) async fn ssh_login_form<H: WebHost>(State(a): St<H>, h: HeaderMap, Query(q): Query<NextQuery>) -> Response {
    ssh_login_page(&a, &h, StatusCode::OK, &q.next, None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct SshLoginForm {
    token: String,
    signature: String,
    next: String,
}

pub(super) async fn ssh_login<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<SshLoginForm>) -> Response {
    let cfg = a.host.config();
    match a.ssh_login(&ctx, &f.token, &nonce_of(&cfg, &h), &f.signature).await {
        Ok(LoginStep::Done(s)) => {
            let cookies = super::signed_in(&a, &s).await;
            see_other(util::safe_next(&f.next, BASE), &cookies)
        }
        Ok(LoginStep::NeedMfa(s)) => {
            let to = format!("{BASE}/mfa?next={}", util::urlencode(util::safe_next(&f.next, BASE)));
            see_other(&to, &[set_session(&cfg, &s.token)])
        }
        // A fresh challenge: the old one may be burned, and the command changes.
        Err(e) => ssh_login_page(&a, &h, status_of(&e), &f.next, Some(e.message())),
    }
}

// ---- adding an SSH key

#[derive(Template)]
#[template(path = "ssh_add.html")]
struct SshAddTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    token: &'a str,
    command: &'a str,
    key: &'a str,
    error: Option<&'a str>,
}

const SSH_PAGE: &str = "/account/ssh";
const SECURITY_PAGE: &str = "/account/security";

fn ssh_add_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, me: &Authed, key: &str, error: Option<&str>) -> Response {
    let cfg = a.host.config();
    let (nonce, cookie) = new_nonce(&cfg);
    let token = a.ssh_challenge(Some(&me.user), &nonce);
    let cmd = command(&token, &cfg.ssh_namespace());
    let t = SshAddTpl { base: BASE, csrf: me.csrf(), token: &token, command: &cmd, key, error };
    let mut r = page(a, h, "Add an SSH key", status, &t);
    if let Ok(v) = cookie.parse() {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

pub(super) async fn ssh_add_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    if let Some(r) = need_fresh(&a, &me, SSH_PAGE) {
        return r;
    }
    ssh_add_page(&a, &h, StatusCode::OK, &me, "", None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct SshAddForm {
    token: String,
    key: String,
    signature: String,
}

pub(super) async fn ssh_add<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<SshAddForm>) -> Response {
    if let Some(r) = need_fresh(&a, &me, SSH_PAGE) {
        return r;
    }
    match a.ssh_add(&ctx, &me.user, &f.token, &nonce_of(&a.host.config(), &h), &f.key, &f.signature).await {
        Ok(()) => flash::to(&a.keys, SECURITY_PAGE, true, "SSH key added.", &[]),
        Err(e @ (Error::Invalid(_) | Error::RateLimited)) => ssh_add_page(&a, &h, status_of(&e), &me, &f.key, Some(e.message())),
        Err(e) => refused(&a, &h, &e),
    }
}

// ---- device keys

fn b64(s: &str) -> Vec<u8> {
    util::b64u_dec(s).unwrap_or_default()
}

pub(super) async fn devkey_options_add<H: WebHost>(State(a): St<H>, me: Authed) -> Response {
    if !a.fresh(&me.session, util::now()) {
        return json_refused(&Error::Invalid("Confirm it's you first: reload the page."));
    }
    let (nonce, cookie) = new_nonce(&a.host.config());
    json_ok(json!({ "token": a.devkey_challenge(Some(&me.user), &nonce) }), &[cookie])
}

pub(super) async fn devkey_options_login<H: WebHost>(State(a): St<H>) -> Response {
    let (nonce, cookie) = new_nonce(&a.host.config());
    json_ok(json!({ "token": a.devkey_challenge(None, &nonce) }), &[cookie])
}

#[derive(Deserialize)]
pub(super) struct DevkeyFinish {
    token: String,
    device_id: String,
    #[serde(default)]
    public_key: String,
    signature: String,
    #[serde(default)]
    next: String,
}

pub(super) async fn devkey_add<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Json(f): Json<DevkeyFinish>) -> Response {
    if !a.fresh(&me.session, util::now()) {
        return json_refused(&Error::Invalid("Confirm it's you first: reload the page."));
    }
    let (id, pk, sig) = (b64(&f.device_id), b64(&f.public_key), b64(&f.signature));
    let key = NewDeviceKey { device_id: &id, public_key: &pk, signature: &sig };
    match a.devkey_add(&ctx, &me.user, &f.token, &nonce_of(&a.host.config(), &h), key).await {
        Ok(()) => json_ok(json!({ "next": flash::url(&a.keys, SECURITY_PAGE, true, "This browser is remembered.") }), &[]),
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn devkey_login<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Json(f): Json<DevkeyFinish>) -> Response {
    let cfg = a.host.config();
    match a.devkey_login(&ctx, &f.token, &nonce_of(&cfg, &h), &b64(&f.device_id), &b64(&f.signature)).await {
        Ok(s) => {
            let cookies = super::signed_in(&a, &s).await;
            json_ok(json!({ "next": util::safe_next(&f.next, BASE) }), &cookies)
        }
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn devkey_script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
        include_str!("../../assets/devkey.js"),
    )
        .into_response()
}

// ---- removing a credential

#[derive(Deserialize, Default)]
pub(super) struct Empty {}

/// One form for every kind: passkeys, SSH keys, remembered browsers.
pub(super) async fn remove<H: WebHost>(
    State(a): St<H>,
    me: Authed,
    ctx: Ctx,
    h: HeaderMap,
    Path((kind, id)): Path<(String, String)>,
    _f: Form<Empty>,
) -> Response {
    if let Some(r) = need_fresh(&a, &me, SECURITY_PAGE) {
        return r;
    }
    let (kind, done) = match kind.as_str() {
        "passkey" => ("passkey", "Passkey removed."),
        "ssh" => ("ssh", "SSH key removed."),
        "devkey" => ("devkey", "That browser is forgotten."),
        _ => return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found."),
    };
    let Some(ext_id) = util::b64u_dec(&id) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    match a.remove_credential(&ctx, &me.user, kind, &ext_id).await {
        Ok(()) => flash::to(&a.keys, SECURITY_PAGE, true, done, &[]),
        Err(e @ (Error::Invalid(_) | Error::NotFound)) => flash::to(&a.keys, SECURITY_PAGE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}
