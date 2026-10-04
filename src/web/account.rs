//! The dashboard and what a person does to their own account.

use std::time::Duration;

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use super::auth::need_fresh;
use super::flash::{self, Flash};
use super::{Authed, BASE, St, WebHost, clear_device, clear_session, error_page, page, refused, when};
use crate::model::{Role, User};
use crate::service::{Ctx, Error};
use crate::util;

struct SessionRow {
    /// Hex of the token hash: names the session in its revoke URL.
    id: String,
    created: String,
    seen: String,
    ip: String,
    ua: String,
    current: bool,
    pending: bool,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    user: &'a User,
    roles: Vec<Role>,
    sessions: Vec<SessionRow>,
    links: Vec<(String, String)>,
    can_users: bool,
    can_roles: bool,
    flash: Option<Flash>,
}

pub(super) async fn dashboard<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, Query(fq): Query<flash::Query>) -> Response {
    let now = util::now();
    let (roles, sessions) = match tokio::try_join!(a.store.user_roles(me.user.id), a.sessions(me.user.id, now)) {
        Ok(v) => v,
        Err(e) => return refused(&a, &h, &Error::Db(e)),
    };
    let sessions = sessions
        .into_iter()
        .map(|s| SessionRow {
            id: hex::encode(s.token_hash),
            created: when(s.created_at),
            seen: when(s.seen_at),
            current: s.token_hash == me.session.token_hash,
            pending: !s.mfa_ok,
            ip: s.ip,
            ua: s.ua,
        })
        .collect();
    let t = DashboardTpl {
        base: BASE,
        csrf: me.csrf(),
        user: &me.user,
        roles,
        sessions,
        links: a.host.dashboard_links(&me.scopes),
        can_users: me.can("users:read"),
        can_roles: me.can("roles:admin"),
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "Your account", StatusCode::OK, &t)
}

pub(super) async fn revoke<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Path(id): Path<String>) -> Response {
    let Some(hash) = hex::decode(&id).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) else {
        return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.");
    };
    match a.revoke_session(&ctx, me.user.id, &hash).await {
        Ok(true) if hash == me.session.token_hash => {
            flash::to(&a.keys, &format!("{BASE}/login"), true, "Signed out.", &[clear_session(&a.host.config())])
        }
        Ok(true) => flash::to(&a.keys, BASE, true, "That session is signed out.", &[]),
        Ok(false) => flash::to(&a.keys, BASE, false, "That session was already gone.", &[]),
        Err(e) => refused(&a, &h, &Error::Db(e)),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct NameForm {
    display_name: String,
}

pub(super) async fn display_name<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<NameForm>) -> Response {
    match a.set_display_name(&ctx, me.user.id, &f.display_name).await {
        Ok(_) => flash::to(&a.keys, BASE, true, "Display name saved.", &[]),
        Err(e @ Error::Invalid(_)) => flash::to(&a.keys, BASE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}

/// Everything stored about the account, as a JSON download.
pub(super) async fn export<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    if !a.limiter.check(&format!("acct-export-{}:x", me.user.id.hex()), Duration::from_secs(3600), 10) {
        return refused(&a, &h, &Error::RateLimited);
    }
    let v = match a.export(me.user.id).await {
        Ok(v) => v,
        Err(e) => return refused(&a, &h, &e),
    };
    let body = serde_json::to_vec_pretty(&v).unwrap_or_default();
    let mut r = body.into_response();
    let hs = r.headers_mut();
    hs.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    // Usernames are [a-z0-9_-], so the name needs no quoting rules.
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"account-{}.json\"", me.user.username)) {
        hs.insert(header::CONTENT_DISPOSITION, v);
    }
    r
}

#[derive(Template)]
#[template(path = "delete.html")]
struct DeleteTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    username: &'a str,
}

const DELETE_PAGE: &str = "/account/delete";

pub(super) async fn delete_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    if let Some(r) = need_fresh(&a, &me, DELETE_PAGE) {
        return r;
    }
    page(&a, &h, "Delete your account", StatusCode::OK, &DeleteTpl { base: BASE, csrf: me.csrf(), username: &me.user.username })
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct DeleteForm {
    delete_owned: Option<String>,
}

pub(super) async fn delete<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<DeleteForm>) -> Response {
    if let Some(r) = need_fresh(&a, &me, DELETE_PAGE) {
        return r;
    }
    match a.delete_account(&ctx, me.actor(), me.user.id, f.delete_owned.is_some()).await {
        Ok(()) => {
            let cfg = a.host.config();
            flash::to(&a.keys, &format!("{BASE}/login"), true, "Your account is deleted.", &[clear_session(&cfg), clear_device(&cfg)])
        }
        Err(e @ (Error::LastAdmin | Error::Invalid(_))) => flash::to(&a.keys, BASE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}
