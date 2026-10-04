//! Second factors on the web: the second sign-in step, the security page,
//! TOTP setup and recovery codes.

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::auth::{NextQuery, need_fresh};
use super::flash::{self, Flash};
use super::{Authed, BASE, PendingMfa, St, WebHost, error_page, page, refused, see_other, set_device, set_session, status_of, when};
use crate::qr::qr_svg;
use crate::service::{Accounts, Ctx, Error, TotpSetup};
use crate::util;

// ---- the second sign-in step

#[derive(Template)]
#[template(path = "mfa.html")]
struct MfaTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    next: &'a str,
    totp: bool,
    passkey: bool,
    error: Option<&'a str>,
}

fn mfa_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, p: &PendingMfa, next: &str, error: Option<&str>) -> Response {
    let t = MfaTpl { base: BASE, csrf: p.csrf(), next, totp: p.user.totp_enabled, passkey: p.user.has_passkey, error };
    page(a, h, "Second step", status, &t)
}

pub(super) async fn mfa_form<H: WebHost>(State(a): St<H>, p: PendingMfa, h: HeaderMap, Query(q): Query<NextQuery>) -> Response {
    mfa_page(&a, &h, StatusCode::OK, &p, &q.next, None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct MfaForm {
    #[serde(rename = "_action")]
    action: String,
    code: String,
    next: String,
}

pub(super) async fn mfa<H: WebHost>(State(a): St<H>, p: PendingMfa, ctx: Ctx, h: HeaderMap, Form(f): Form<MfaForm>) -> Response {
    let cfg = a.host.config();
    let done = match f.action.as_str() {
        "totp" => a.mfa_totp(&ctx, &p.user, &p.session, &f.code).await.map(|s| (s, None)),
        "recovery" => a.mfa_recovery(&ctx, &p.user, &p.session, &f.code).await.map(|(s, left)| (s, Some(left))),
        _ => return error_page(&a, &h, StatusCode::BAD_REQUEST, "Unknown action."),
    };
    match done {
        Ok((s, recovery_left)) => {
            let cookies = [set_session(&cfg, &s.token), set_device(&a, &cfg, p.user.id)];
            match recovery_left {
                // Straight to where a new set is made, saying how many are left.
                Some(left) => {
                    let msg = format!("Signed in with a recovery code. {left} left: make a new set if that is few.");
                    flash::to(&a.keys, &format!("{BASE}/security"), true, &msg, &cookies)
                }
                None => see_other(util::safe_next(&f.next, BASE), &cookies),
            }
        }
        Err(e) => {
            if let Error::Db(err) = &e {
                tracing::error!(target: "accounts", error = %err, "database error");
            }
            mfa_page(&a, &h, status_of(&e), &p, &f.next, Some(e.message()))
        }
    }
}

// ---- the security page

struct KeyRow {
    /// base64url of the credential id: names it in its delete URL.
    id: String,
    name: String,
    created: String,
    used: String,
}

fn rows(creds: Vec<crate::model::Credential>) -> Vec<KeyRow> {
    creds
        .into_iter()
        .map(|c| KeyRow {
            id: util::b64u(&c.ext_id),
            created: when(c.created_at),
            used: c.last_used_at.map(when).unwrap_or_else(|| "never".into()),
            name: c.name,
        })
        .collect()
}

#[derive(Template)]
#[template(path = "security.html")]
struct SecurityTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    fresh: bool,
    totp: bool,
    recovery_left: i64,
    passkeys: Vec<KeyRow>,
    ssh: Vec<KeyRow>,
    devkeys: Vec<KeyRow>,
    username: &'a str,
    flash: Option<Flash>,
}

pub(super) async fn security<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, Query(fq): Query<flash::Query>) -> Response {
    let id = me.user.id;
    let (left, passkeys, ssh, devkeys) = match tokio::try_join!(a.recovery_left(id), a.passkeys(id), a.ssh_keys(id), a.devkeys(id)) {
        Ok(v) => v,
        Err(e) => return refused(&a, &h, &Error::Db(e)),
    };
    let t = SecurityTpl {
        base: BASE,
        csrf: me.csrf(),
        fresh: a.fresh(&me.session, util::now()),
        totp: me.user.totp_enabled,
        recovery_left: left,
        passkeys: rows(passkeys),
        ssh: rows(ssh),
        devkeys: rows(devkeys),
        username: &me.user.username,
        flash: flash::read(&a.keys, &fq),
    };
    page(&a, &h, "Security", StatusCode::OK, &t)
}

// ---- TOTP

#[derive(Template)]
#[template(path = "totp.html")]
struct TotpTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    /// The base32 secret in groups of four, for typing in.
    secret: String,
    qr: String,
    sealed: &'a str,
    error: Option<&'a str>,
}

fn totp_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, me: &Authed, s: &TotpSetup, error: Option<&str>) -> Response {
    let grouped = s.secret.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ");
    let t = TotpTpl { base: BASE, csrf: me.csrf(), secret: grouped, qr: qr_svg(&s.uri), sealed: &s.sealed, error };
    page(a, h, "Two-factor codes", status, &t)
}

const TOTP_PAGE: &str = "/account/totp";
const SECURITY_PAGE: &str = "/account/security";

pub(super) async fn totp_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    if let Some(r) = need_fresh(&a, &me, TOTP_PAGE) {
        return r;
    }
    if me.user.totp_enabled {
        return see_other(SECURITY_PAGE, &[]);
    }
    let setup = a.totp_setup(&me.user);
    totp_page(&a, &h, StatusCode::OK, &me, &setup, None)
}

#[derive(Template)]
#[template(path = "codes.html")]
struct CodesTpl<'a> {
    base: &'static str,
    codes: &'a [String],
}

fn codes_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, codes: &[String]) -> Response {
    page(a, h, "Recovery codes", StatusCode::OK, &CodesTpl { base: BASE, codes })
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct TotpForm {
    #[serde(rename = "_action")]
    action: String,
    setup: String,
    code: String,
}

pub(super) async fn totp<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<TotpForm>) -> Response {
    if let Some(r) = need_fresh(&a, &me, SECURITY_PAGE) {
        return r;
    }
    match f.action.as_str() {
        "enable" => match a.totp_enable(&ctx, &me.user, &f.setup, &f.code).await {
            Ok(codes) if codes.is_empty() => flash::to(&a.keys, SECURITY_PAGE, true, "Two-factor codes are on.", &[]),
            Ok(codes) => codes_page(&a, &h, &codes),
            Err(e @ (Error::Invalid(_) | Error::RateLimited)) => match a.totp_setup_again(&me.user, &f.setup) {
                Some(s) => totp_page(&a, &h, status_of(&e), &me, &s, Some(e.message())),
                None => flash::to(&a.keys, SECURITY_PAGE, false, e.message(), &[]),
            },
            Err(e) => refused(&a, &h, &e),
        },
        "disable" => match a.totp_disable(&ctx, &me.user).await {
            Ok(()) => flash::to(&a.keys, SECURITY_PAGE, true, "Two-factor codes are off.", &[]),
            Err(e @ Error::Invalid(_)) => flash::to(&a.keys, SECURITY_PAGE, false, e.message(), &[]),
            Err(e) => refused(&a, &h, &e),
        },
        _ => error_page(&a, &h, StatusCode::BAD_REQUEST, "Unknown action."),
    }
}

pub(super) async fn recovery<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap) -> Response {
    if let Some(r) = need_fresh(&a, &me, SECURITY_PAGE) {
        return r;
    }
    match a.recovery_regenerate(&ctx, &me.user).await {
        Ok(codes) => codes_page(&a, &h, &codes),
        Err(e @ Error::Invalid(_)) => flash::to(&a.keys, SECURITY_PAGE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}
