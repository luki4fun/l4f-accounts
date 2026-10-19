//! User and role administration. The service checks every scope; these pages
//! add the step-up every change needs and turn refusals into messages.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::auth::need_fresh;
use super::flash::{self, Flash};
use super::{Authed, BASE, St, WebHost, done, error_page, page, refused, when};
use crate::model::{AccountId, Role, User, UserStatus};
use crate::scope::ScopeDef;
use crate::service::{Ctx, RoleForm};
use crate::util;

const PAGE: u32 = 50;

fn parse_id(id: &str) -> Option<AccountId> {
    AccountId::parse_hex(id)
}

// ---- users

struct UserRow {
    id: String,
    username: String,
    display_name: String,
    disabled: bool,
    created: String,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct UsersTpl {
    base: &'static str,
    q: String,
    q_enc: String,
    rows: Vec<UserRow>,
    total: i64,
    offset: u32,
    shown_to: u32,
    prev: Option<u32>,
    next: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct ListQuery {
    q: String,
    offset: u32,
}

pub(super) async fn users<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, Query(lq): Query<ListQuery>) -> Response {
    let q = lq.q.trim();
    let (list, total) = match a.list_users(me.actor(), Some(q).filter(|s| !s.is_empty()), PAGE, lq.offset).await {
        Ok(v) => v,
        Err(e) => return refused(&a, &h, &e),
    };
    let shown_to = lq.offset + list.len() as u32;
    let t = UsersTpl {
        base: BASE,
        q: q.to_string(),
        q_enc: util::urlencode(q),
        rows: list
            .into_iter()
            .map(|u| UserRow {
                id: u.id.hex(),
                disabled: u.status == UserStatus::Disabled,
                created: when(u.created_at),
                username: u.username,
                display_name: u.display_name,
            })
            .collect(),
        total,
        offset: lq.offset,
        shown_to,
        prev: (lq.offset > 0).then(|| lq.offset.saturating_sub(PAGE)),
        next: (i64::from(shown_to) < total).then_some(shown_to),
    };
    page(&a, &h, "Users", StatusCode::OK, &t)
}

struct AuditRow {
    at: String,
    event: String,
    detail: String,
    ip: String,
    by: String,
}

#[derive(Template)]
#[template(path = "admin_user.html")]
struct UserTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    u: User,
    created: String,
    roles: Vec<Role>,
    grantable: Vec<String>,
    audit: Vec<AuditRow>,
    can_admin: bool,
    is_self: bool,
    flash: Option<Flash>,
}

pub(super) async fn user<H: WebHost>(
    State(a): St<H>,
    me: Authed,
    h: HeaderMap,
    Path(id): Path<String>,
    Query(fq): Query<flash::Query>,
) -> Response {
    let Some(id) = parse_id(&id) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    let detail = match a.user_detail(me.actor(), id).await {
        Ok(d) => d,
        Err(e) => return refused(&a, &h, &e),
    };
    let all = a.roles(me.actor()).await.unwrap_or_default();
    let grantable = all.into_iter().filter(|r| !detail.roles.iter().any(|h| h.id == r.id)).map(|r| r.name).collect();
    let audit = detail
        .audit
        .into_iter()
        .map(|e| AuditRow {
            at: when(e.at),
            by: match e.actor_id {
                Some(x) if Some(x) == e.user_id => String::new(),
                Some(x) => x.hex(),
                None => String::new(),
            },
            event: e.event,
            detail: e.detail,
            ip: e.ip,
        })
        .collect();
    let t = UserTpl {
        base: BASE,
        csrf: me.csrf(),
        created: when(detail.user.created_at),
        is_self: detail.user.id == me.user.id,
        u: detail.user,
        roles: detail.roles,
        grantable,
        audit,
        can_admin: me.can("users:admin"),
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "User", StatusCode::OK, &t)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct UserAction {
    #[serde(rename = "_action")]
    action: String,
    role: String,
    delete_owned: Option<String>,
}

pub(super) async fn user_action<H: WebHost>(
    State(a): St<H>,
    me: Authed,
    ctx: Ctx,
    h: HeaderMap,
    Path(raw): Path<String>,
    Form(f): Form<UserAction>,
) -> Response {
    let Some(id) = parse_id(&raw) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    let back = format!("{BASE}/admin/users/{}", id.hex());
    if let Some(r) = need_fresh(&a, &me, &back) {
        return r;
    }
    let actor = me.actor();
    let r = match f.action.as_str() {
        "grant" => a.grant_role(&ctx, actor, id, &f.role).await.map(|new| if new { "Role granted." } else { "They already had that role." }),
        "revoke" => a
            .revoke_role(&ctx, actor, id, &f.role)
            .await
            .map(|gone| if gone { "Role taken away; their sessions are signed out." } else { "They did not have that role." }),
        "disable" => a
            .set_user_status(&ctx, actor, id, UserStatus::Disabled)
            .await
            .map(|c| if c { "Account suspended; its sessions are signed out." } else { "It was already suspended." }),
        "enable" => a
            .set_user_status(&ctx, actor, id, UserStatus::Active)
            .await
            .map(|c| if c { "Account active again." } else { "It was already active." }),
        "delete" => {
            return match a.delete_account(&ctx, actor, id, f.delete_owned.is_some()).await {
                Ok(()) => flash::to(&a.keys, &format!("{BASE}/admin/users"), true, "Account deleted.", &[]),
                Err(e) => done(&a, &h, &back, Err(e)),
            };
        }
        _ => return error_page(&a, &h, StatusCode::BAD_REQUEST, "Unknown action."),
    };
    done(&a, &h, &back, r)
}

// ---- roles

#[derive(Template)]
#[template(path = "admin_roles.html")]
struct RolesTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    roles: Vec<Role>,
    registry: &'a [ScopeDef],
    can_admin: bool,
    flash: Option<Flash>,
}

pub(super) async fn roles<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, Query(fq): Query<flash::Query>) -> Response {
    let roles = match a.roles(me.actor()).await {
        Ok(r) => r,
        Err(e) => return refused(&a, &h, &e),
    };
    let t = RolesTpl {
        base: BASE,
        csrf: me.csrf(),
        roles,
        registry: &a.scopes,
        can_admin: me.can("roles:admin"),
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "Roles", StatusCode::OK, &t)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RoleFields {
    #[serde(rename = "_action")]
    action: String,
    name: String,
    description: String,
    badge: String,
    /// One grant per line or space: a textarea also takes `links:*` and `*`.
    scopes: String,
}

impl RoleFields {
    fn grants(&self) -> Vec<String> {
        self.scopes.split_whitespace().map(String::from).collect()
    }
}

pub(super) async fn role_create<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<RoleFields>) -> Response {
    let back = format!("{BASE}/admin/roles");
    if let Some(r) = need_fresh(&a, &me, &back) {
        return r;
    }
    let grants = f.grants();
    let form = RoleForm { name: &f.name, description: &f.description, badge: &f.badge, scopes: &grants };
    done(&a, &h, &back, a.create_role(&ctx, me.actor(), form).await.map(|_| "Role created."))
}

#[derive(Template)]
#[template(path = "admin_role.html")]
struct RoleTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    role: Role,
    scopes_text: String,
    registry: &'a [ScopeDef],
    can_admin: bool,
    flash: Option<Flash>,
}

pub(super) async fn role<H: WebHost>(
    State(a): St<H>,
    me: Authed,
    h: HeaderMap,
    Path(name): Path<String>,
    Query(fq): Query<flash::Query>,
) -> Response {
    let role = match a.roles(me.actor()).await {
        Ok(all) => all.into_iter().find(|r| r.name == name),
        Err(e) => return refused(&a, &h, &e),
    };
    let Some(role) = role else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    let t = RoleTpl {
        base: BASE,
        csrf: me.csrf(),
        scopes_text: role.scopes.join("\n"),
        role,
        registry: &a.scopes,
        can_admin: me.can("roles:admin"),
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "Role", StatusCode::OK, &t)
}

pub(super) async fn role_action<H: WebHost>(
    State(a): St<H>,
    me: Authed,
    ctx: Ctx,
    h: HeaderMap,
    Path(name): Path<String>,
    Form(f): Form<RoleFields>,
) -> Response {
    let back = role_url(&name);
    if let Some(r) = need_fresh(&a, &me, &back) {
        return r;
    }
    match f.action.as_str() {
        "save" => {
            let grants = f.grants();
            let form = RoleForm { name: &name, description: &f.description, badge: &f.badge, scopes: &grants };
            done(&a, &h, &back, a.update_role(&ctx, me.actor(), form).await.map(|()| "Role saved."))
        }
        "delete" => match a.delete_role(&ctx, me.actor(), &name).await {
            Ok(()) => flash::to(&a.keys, &format!("{BASE}/admin/roles"), true, "Role deleted.", &[]),
            Err(e) => done(&a, &h, &back, Err(e)),
        },
        _ => error_page(&a, &h, StatusCode::BAD_REQUEST, "Unknown action."),
    }
}

/// Role names are `[a-z0-9_-]`, but the path segment is whatever was asked
/// for; encoded, it can't leave the role pages.
fn role_url(name: &str) -> String {
    format!("{BASE}/admin/roles/{}", util::urlencode(name))
}
