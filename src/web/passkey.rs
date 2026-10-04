//! Passkey ceremonies for `assets/passkey.js`: JSON in, JSON out. Options set
//! the browser nonce cookie the challenge is bound to; the finishing call
//! reads it back. With a session cookie the CSRF layer wants `X-CSRF`.

use axum::{
    Form, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::flash;
use super::{
    Authed, BASE, PendingMfa, St, WebHost, error_page, json_ok, json_refused, new_nonce, nonce_of, refused, set_device, set_session,
};
use crate::service::{Ctx, Error, PasskeyFor};
use crate::util;

const RECENT: Error = Error::Invalid("Confirm it's you first: reload the page.");

fn options_response(r: Result<(serde_json::Value, String), Error>, cookie: String) -> Response {
    match r {
        Ok((options, token)) => json_ok(json!({ "options": options, "token": token }), &[cookie]),
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn options_login<H: WebHost>(State(a): St<H>) -> Response {
    let (nonce, cookie) = new_nonce(&a.host.config());
    options_response(a.passkey_options(PasskeyFor::Login, None, &nonce).await, cookie)
}

pub(super) async fn options_add<H: WebHost>(State(a): St<H>, me: Authed) -> Response {
    if !a.fresh(&me.session, util::now()) {
        return json_refused(&RECENT);
    }
    let (nonce, cookie) = new_nonce(&a.host.config());
    options_response(a.passkey_options(PasskeyFor::Add, Some(&me.user), &nonce).await, cookie)
}

pub(super) async fn options_mfa<H: WebHost>(State(a): St<H>, p: PendingMfa) -> Response {
    let (nonce, cookie) = new_nonce(&a.host.config());
    options_response(a.passkey_options(PasskeyFor::Mfa, Some(&p.user), &nonce).await, cookie)
}

pub(super) async fn options_step_up<H: WebHost>(State(a): St<H>, me: Authed) -> Response {
    let (nonce, cookie) = new_nonce(&a.host.config());
    options_response(a.passkey_options(PasskeyFor::StepUp, Some(&me.user), &nonce).await, cookie)
}

#[derive(Deserialize)]
pub(super) struct Finish {
    token: String,
    /// The browser's `credential.toJSON()`, passed through as it came.
    credential: serde_json::Value,
    #[serde(default)]
    name: String,
    #[serde(default)]
    next: String,
}

pub(super) async fn add<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Json(f): Json<Finish>) -> Response {
    if !a.fresh(&me.session, util::now()) {
        return json_refused(&RECENT);
    }
    let nonce = nonce_of(&a.host.config(), &h);
    match a.passkey_add(&ctx, &me.user, &f.token, &nonce, &f.credential.to_string(), &f.name).await {
        Ok(()) => json_ok(json!({ "next": flash::url(&a.keys, &format!("{BASE}/security"), true, "Passkey added.") }), &[]),
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn login<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Json(f): Json<Finish>) -> Response {
    let cfg = a.host.config();
    let nonce = nonce_of(&cfg, &h);
    match a.passkey_login(&ctx, &f.token, &nonce, &f.credential.to_string()).await {
        Ok(s) => {
            let cookies = [set_session(&cfg, &s.token), set_device(&a, &cfg, s.info.user_id)];
            json_ok(json!({ "next": util::safe_next(&f.next, BASE) }), &cookies)
        }
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn mfa<H: WebHost>(State(a): St<H>, p: PendingMfa, ctx: Ctx, h: HeaderMap, Json(f): Json<Finish>) -> Response {
    let cfg = a.host.config();
    let nonce = nonce_of(&cfg, &h);
    match a.passkey_mfa(&ctx, &p.user, &p.session, &f.token, &nonce, &f.credential.to_string()).await {
        Ok(s) => {
            let cookies = [set_session(&cfg, &s.token), set_device(&a, &cfg, p.user.id)];
            json_ok(json!({ "next": util::safe_next(&f.next, BASE) }), &cookies)
        }
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn step_up<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Json(f): Json<Finish>) -> Response {
    let cfg = a.host.config();
    let nonce = nonce_of(&cfg, &h);
    match a.passkey_step_up(&ctx, &me.user, &me.session, &f.token, &nonce, &f.credential.to_string()).await {
        Ok(s) => json_ok(json!({ "next": util::safe_next(&f.next, BASE) }), &[set_session(&cfg, &s.token)]),
        Err(e) => json_refused(&e),
    }
}

#[derive(Deserialize, Default)]
pub(super) struct Empty {}

/// A form post, not JSON: removing works without the script.
pub(super) async fn remove<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Path(id): Path<String>, _f: Form<Empty>) -> Response {
    let back = format!("{BASE}/security");
    if let Some(r) = super::auth::need_fresh(&a, &me, &back) {
        return r;
    }
    let Some(ext_id) = util::b64u_dec(&id) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    match a.passkey_remove(&ctx, &me.user, &ext_id).await {
        Ok(()) => flash::to(&a.keys, &back, true, "Passkey removed.", &[]),
        Err(e @ (Error::Invalid(_) | Error::NotFound)) => flash::to(&a.keys, &back, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}

/// Served from the binary, like the templates. `no-cache`: the browser asks
/// every time and keeps nothing stale after an upgrade.
pub(super) async fn script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")],
        include_str!("../../assets/passkey.js"),
    )
        .into_response()
}
