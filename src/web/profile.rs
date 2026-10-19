//! The profile settings page, the avatar upload, and the public profile with
//! its avatar, which the host nests where it likes (`profile_router`).

use std::sync::Arc;

use askama::Template;
use axum::{
    Form, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;

use super::flash::{self, Flash};
use super::storage::Api;
use super::{Authed, BASE, St, WebHost, json_ok, json_refused, page, refused};
use crate::service::{Accounts, Ctx, Error, provider_label, uuid_of};
use crate::util;

const PROFILE_PAGE: &str = "/account/profile";

struct IdentityRow {
    kind: String,
    id: String,
    label: String,
    name: String,
    public: bool,
}

#[derive(Template)]
#[template(path = "profile.html")]
struct SettingsTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    allowed: bool,
    link: Option<String>,
    bio: String,
    show_badges: bool,
    identities: Vec<IdentityRow>,
    avatar: bool,
    flash: Option<Flash>,
}

pub(super) async fn settings<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, axum::extract::Query(fq): axum::extract::Query<flash::Query>) -> Response {
    let p = match a.profile_settings(me.user.id).await {
        Ok(p) => p,
        Err(e) => return refused(&a, &h, &Error::Db(e)),
    };
    let mut identities = Vec::new();
    for kind in ["oauth:discord", "oauth:google", "oauth:facebook"] {
        let Ok(creds) = a.store.credentials_of(me.user.id, kind).await else { continue };
        for c in creds {
            identities.push(IdentityRow { kind: kind.into(), id: util::b64u(&c.ext_id), label: provider_label(kind), name: c.name, public: c.public });
        }
    }
    let avatar = a.avatar(me.user.id).await.ok().flatten().is_some();
    let base_url = a.host.config().base_url.clone();
    let t = SettingsTpl {
        base: BASE,
        csrf: me.csrf(),
        allowed: me.can("profile:public"),
        link: p.public_id.map(|id| format!("{base_url}/profile/{}", uuid_of(&id))),
        bio: p.bio,
        show_badges: p.show_badges,
        identities,
        avatar,
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "Profile", StatusCode::OK, &t)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct SettingsForm {
    #[serde(rename = "_action")]
    action: String,
    on: Option<String>,
    bio: String,
    show_badges: Option<String>,
    kind: String,
    id: String,
    public: Option<String>,
}

pub(super) async fn save<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<SettingsForm>) -> Response {
    let r = match f.action.as_str() {
        "save" => a.profile_save(&ctx, &me.user, &me.scopes, f.on.is_some(), &f.bio, f.show_badges.is_some()).await.map(|()| "Profile saved."),
        "rotate" => a.profile_rotate(&ctx, &me.user).await.map(|()| "New link made; the old one stopped working."),
        "identity" => match util::b64u_dec(&f.id) {
            Some(ext) => a.identity_public(&me.user, &f.kind, &ext, f.public.is_some()).await.map(|()| "Saved."),
            None => Err(Error::NotFound),
        },
        "avatar_remove" => a.avatar_remove(&me.user).await.map(|()| "Avatar removed.").map_err(Error::Db),
        _ => Err(Error::Invalid("Unknown action.")),
    };
    match r {
        Ok(msg) => flash::to(&a.keys, PROFILE_PAGE, true, msg, &[]),
        Err(e @ (Error::Invalid(_) | Error::NotFound | Error::Forbidden)) => flash::to(&a.keys, PROFILE_PAGE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}

/// The avatar as the browser resized it: raw PNG or WebP bytes.
pub(super) async fn avatar_put<H: WebHost>(State(a): St<H>, Api(me): Api, ctx: Ctx, body: Bytes) -> Response {
    match a.avatar_put(&ctx, &me.user, &me.scopes, &body).await {
        Ok(()) => json_ok(serde_json::json!({ "next": flash::url(&a.keys, PROFILE_PAGE, true, "Avatar saved.") }), &[]),
        Err(e) => json_refused(&e),
    }
}

pub(super) async fn avatar_script() -> Response {
    super::script(include_str!("../../assets/avatar.js"))
}

// ---- the public profile

#[derive(Template)]
#[template(path = "public_profile.html")]
struct PublicTpl<'a> {
    link: &'a str,
    name: &'a str,
    bio: &'a str,
    badges: &'a [String],
    identities: &'a [(String, String)],
    links: &'a [(String, String)],
    avatar: bool,
}

/// The public profile and its avatar, for the host to nest (l4f: `/profile`).
pub fn profile_router<H: WebHost, S: Clone + Send + Sync + 'static>(a: Arc<Accounts<H>>) -> Router<S> {
    Router::new().route("/{id}", get(public_page::<H>)).route("/{id}/avatar", get(public_avatar::<H>)).with_state(a)
}

/// Kept out of search engines and caches: the link is the only way in.
fn private(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow"));
    r
}

async fn public_page<H: WebHost>(State(a): St<H>, h: HeaderMap, Path(id): Path<String>) -> Response {
    let p = match a.public_profile(&id).await {
        Ok(Some(p)) => p,
        Ok(None) => return private(super::error_page(&a, &h, StatusCode::NOT_FOUND, "No such profile.")),
        Err(e) => return refused(&a, &h, &e),
    };
    let links: Vec<_> = a.host.profile_links(p.user).await.into_iter().filter(|(_, url)| web_link(url)).collect();
    let t = PublicTpl {
        link: &id,
        name: &p.display_name,
        bio: &p.bio,
        badges: &p.badges,
        identities: &p.identities,
        links: &links,
        avatar: p.avatar,
    };
    // A fixed title: the name is the owner's to choose, and a host that put
    // the title in its page unescaped would run the owner's markup.
    private(page(&a, &h, "Profile", StatusCode::OK, &t))
}

/// `https://`, `http://` or a path on this site. Escaping keeps a link inside
/// its `href`, but a `javascript:` or `data:` one would still run when clicked.
fn web_link(url: &str) -> bool {
    ["https://", "http://", "/"].iter().any(|p| url.starts_with(p))
}

/// The image alone in a sandbox: it can run nothing and be embedded nowhere else.
async fn public_avatar<H: WebHost>(State(a): St<H>, Path(id): Path<String>) -> Response {
    let found = match a.public_profile(&id).await {
        Ok(Some(p)) if p.avatar => a.avatar(p.user).await.ok().flatten(),
        _ => None,
    };
    let Some((bytes, ctype)) = found else { return private(StatusCode::NOT_FOUND.into_response()) };
    let mut r = private(bytes.into_response());
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}
