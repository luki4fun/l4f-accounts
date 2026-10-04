//! The storage API under `/api` (JSON in and out, raw bytes for vault
//! items), the sync switch, and the vault page. Every write is
//! compare-and-set: `If-Match` carries the version the client read, 0 to
//! create. A conflict answers 409 with what is there now.

use askama::Template;
use axum::{
    Form,
    body::Bytes,
    extract::{FromRequestParts, Path, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use super::auth::need_fresh;
use super::flash;
use super::{AccountsState, Authed, BASE, St, WebHost, json_ok, json_refused, page, refused};
use crate::service::{Ctx, Error, Put};
use crate::store::Blob;
use crate::util;

/// `Authed` for scripts: no session is a 401 the script can act on (forget
/// what it holds), not a redirect to a page it cannot show.
pub struct Api(pub Authed);

impl<S: AccountsState> FromRequestParts<S> for Api {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &S) -> Result<Self, Response> {
        match st.accounts().viewer(&parts.headers).await {
            Ok(Some(me)) => Ok(Api(me)),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "Signed out." }))).into_response()),
            Err(e) => {
                tracing::error!(target: "accounts", error = %e, "session lookup failed");
                Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
            }
        }
    }
}

fn expect(h: &HeaderMap) -> i64 {
    h.get(header::IF_MATCH).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().trim_matches('"').parse().ok()).unwrap_or(0)
}

/// 200 with the new version, or 409 with what is there now. `json` says how
/// to show a conflicting value: as JSON, or base64url bytes.
fn put_answer(r: Result<Put, Error>, json_value: bool) -> Response {
    match r {
        Ok(Put::Done(v)) => json_ok(json!({ "version": v }), &[]),
        Ok(Put::Conflict(now)) => {
            let body = match now {
                Some(b) => json!({ "version": b.version, "v": value(&b, json_value) }),
                None => json!({ "version": 0, "v": null }),
            };
            (StatusCode::CONFLICT, axum::Json(body)).into_response()
        }
        Err(e) => json_refused(&e),
    }
}

fn value(b: &Blob, json_value: bool) -> serde_json::Value {
    if json_value {
        serde_json::from_slice(&b.v).unwrap_or(serde_json::Value::Null)
    } else {
        util::b64u(&b.v).into()
    }
}

fn deleted(r: Result<bool, Error>) -> Response {
    match r {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::CONFLICT, axum::Json(json!({ "error": "It changed or is gone." }))).into_response(),
        Err(e) => json_refused(&e),
    }
}

// ---- synced settings

pub(super) async fn kv_list<H: WebHost>(State(a): St<H>, Api(me): Api) -> Response {
    match a.kv_list(&me.user, &me.scopes).await {
        Ok(items) => {
            let items: Vec<_> = items.iter().map(|b| json!({ "k": b.k, "v": value(b, true), "version": b.version })).collect();
            // The form token rides along: the script runs on pages that have none.
            json_ok(json!({ "csrf": me.csrf(), "items": items }), &[])
        }
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn kv_put<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>, body: Bytes) -> Response {
    put_answer(a.kv_put(&me.user, &me.scopes, &k, &body, expect(&h)).await, true)
}

pub(super) async fn kv_delete<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>) -> Response {
    deleted(a.kv_delete(&me.user, &me.scopes, &k, expect(&h)).await)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct SyncForm {
    #[serde(rename = "_action")]
    action: String,
}

pub(super) async fn sync<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<SyncForm>) -> Response {
    let on = f.action == "on";
    match a.sync_set(&ctx, &me.user, &me.scopes, on).await {
        Ok(()) => {
            let msg = if on { "Sync is on." } else { "Sync is off; the copy here is deleted. This browser keeps its own." };
            flash::to(&a.keys, BASE, true, msg, &[super::sync_hint(&a.host.config(), on)])
        }
        Err(e) => refused(&a, &h, &e),
    }
}

// ---- the vault

pub(super) async fn vault_list<H: WebHost>(State(a): St<H>, Api(me): Api) -> Response {
    match a.vault_list(&me.user, &me.scopes).await {
        Ok((slots, items)) => {
            let slots: Vec<_> = slots.iter().map(|b| json!({ "k": b.k, "v": value(b, true), "version": b.version })).collect();
            let items: Vec<_> = items.iter().map(|b| json!({ "k": b.k, "v": value(b, false), "version": b.version })).collect();
            // The account id is part of every AAD (docs/vault-format.md).
            json_ok(json!({ "csrf": me.csrf(), "account": me.user.id.hex(), "slots": slots, "items": items }), &[])
        }
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn vault_put_item<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>, body: Bytes) -> Response {
    put_answer(a.vault_put(&me.user, &me.scopes, false, &k, &body, expect(&h)).await, false)
}

pub(super) async fn vault_put_slot<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>, body: Bytes) -> Response {
    put_answer(a.vault_put(&me.user, &me.scopes, true, &k, &body, expect(&h)).await, true)
}

pub(super) async fn vault_delete_item<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>) -> Response {
    deleted(a.vault_delete(&me.user, &me.scopes, false, &k, expect(&h)).await)
}

pub(super) async fn vault_delete_slot<H: WebHost>(State(a): St<H>, Api(me): Api, h: HeaderMap, Path(k): Path<String>) -> Response {
    deleted(a.vault_delete(&me.user, &me.scopes, true, &k, expect(&h)).await)
}

#[derive(Template)]
#[template(path = "vault.html")]
struct VaultTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    allowed: bool,
}

pub(super) async fn vault_page<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    let t = VaultTpl { base: BASE, csrf: me.csrf(), allowed: me.can("vault:use") };
    page(&a, &h, "Vault", StatusCode::OK, &t)
}

#[derive(Deserialize, Default)]
pub(super) struct Empty {}

pub(super) async fn vault_wipe<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, _f: Form<Empty>) -> Response {
    if let Some(r) = need_fresh(&a, &me, "/account/vault") {
        return r;
    }
    match a.vault_wipe(&ctx, &me.user, &me.scopes).await {
        Ok(()) => flash::to(&a.keys, BASE, true, "The vault is empty.", &[]),
        Err(e) => refused(&a, &h, &e),
    }
}

fn script(body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

pub(super) async fn sync_script() -> Response {
    script(include_str!("../../assets/sync.js"))
}

pub(super) async fn vault_script() -> Response {
    script(include_str!("../../assets/vault.js"))
}
