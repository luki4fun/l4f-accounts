//! Sign-in, sign-up, sign-out and step-up.

use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::flash::{self, Flash};
use super::{
    Authed, BASE, St, Viewer, WebHost, clear_session, csrf_for_cookie, known_device, page, refused, see_other,
    session_token, set_session, status_of,
};
use crate::password::MAX_LEN;
use crate::service::{Accounts, Ctx, Error, LoginStep};
use crate::{pow, util};

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct NextQuery {
    pub(super) next: String,
}

#[cfg(feature = "email")]
fn mail_ready<H: WebHost>(a: &Accounts<H>) -> bool {
    a.mail_ready()
}

#[cfg(not(feature = "email"))]
fn mail_ready<H: WebHost>(_: &Accounts<H>) -> bool {
    false
}

// ---- sign in

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTpl<'a> {
    base: &'static str,
    next: &'a str,
    username: &'a str,
    csrf: Option<String>,
    flash: Option<Flash>,
    error: Option<&'a str>,
    signup_open: bool,
    forgot: bool,
    providers: Vec<(&'static str, &'static str)>,
    max_len: usize,
}

fn login_page<H: WebHost>(
    a: &Accounts<H>,
    h: &HeaderMap,
    status: StatusCode,
    next: &str,
    username: &str,
    flash: Option<Flash>,
    error: Option<&str>,
) -> Response {
    let cfg = a.host.config();
    let t = LoginTpl {
        base: BASE,
        next,
        username,
        csrf: csrf_for_cookie(a, h),
        flash,
        error,
        signup_open: cfg.enabled && cfg.registration_open && a.pow_key.is_some(),
        forgot: mail_ready(a),
        providers: super::providers(a),
        max_len: MAX_LEN,
    };
    page(a, h, "Sign in", status, &t)
}

pub(super) async fn login_form<H: WebHost>(
    State(a): St<H>,
    Viewer(me): Viewer,
    h: HeaderMap,
    Query(q): Query<NextQuery>,
    Query(fq): Query<flash::Query>,
) -> Response {
    if me.is_some() {
        return see_other(util::safe_next(&q.next, BASE), &[]);
    }
    login_page(&a, &h, StatusCode::OK, &q.next, "", flash::read(&a.keys, &fq), None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct LoginForm {
    username: String,
    password: String,
    next: String,
}

pub(super) async fn login<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<LoginForm>) -> Response {
    let cfg = a.host.config();
    let known = known_device(&a, &cfg, &h);
    match a.login_password(&ctx, &f.username, &f.password, known).await {
        Ok(LoginStep::Done(s)) => {
            let cookies = super::signed_in(&a, &s).await;
            see_other(util::safe_next(&f.next, BASE), &cookies)
        }
        Ok(LoginStep::NeedMfa(s)) => {
            // A session that grants nothing until the second step completes it.
            let to = format!("{BASE}/mfa?next={}", util::urlencode(util::safe_next(&f.next, BASE)));
            see_other(&to, &[set_session(&cfg, &s.token)])
        }
        Err(e) => {
            if let Error::Db(err) = &e {
                tracing::error!(target: "accounts", error = %err, "database error");
            }
            login_page(&a, &h, status_of(&e), &f.next, &f.username, None, Some(e.message()))
        }
    }
}

pub(super) async fn logout<H: WebHost>(State(a): St<H>, h: HeaderMap) -> Response {
    let cfg = a.host.config();
    if let Some(t) = session_token(&cfg, &h)
        && let Err(e) = a.logout(t).await
    {
        tracing::warn!(target: "accounts", error = %e, "session row not removed at sign-out");
    }
    flash::to(&a.keys, &format!("{BASE}/login"), true, "Signed out.", &[clear_session(&cfg), super::sync_hint(&cfg, false)])
}

pub(super) async fn logout_all<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap) -> Response {
    match a.logout_all(&ctx, me.user.id, Some(&me.session.token_hash)).await {
        Ok(n) => {
            let msg = if n == 1 { "Signed out of 1 other session.".to_string() } else { format!("Signed out of {n} other sessions.") };
            flash::to(&a.keys, BASE, true, &msg, &[])
        }
        Err(e) => refused(&a, &h, &Error::Db(e)),
    }
}

// ---- sign up

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTpl<'a> {
    base: &'static str,
    open: bool,
    challenge_json: String,
    stamp: String,
    min_len: usize,
    max_len: usize,
    min_form_seconds: u64,
    username: &'a str,
    email: &'a str,
    display_name: &'a str,
    csrf: Option<String>,
    error: Option<&'a str>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct RegisterForm {
    username: String,
    password: String,
    email: String,
    display_name: String,
    website: String,
    ts: String,
    altcha: String,
}

fn register_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, f: &RegisterForm, error: Option<&str>) -> Response {
    let cfg = a.host.config();
    let key = a.pow_key.as_deref().filter(|_| cfg.enabled && cfg.registration_open);
    // A fresh challenge every time: the last one may already be burned.
    let (challenge_json, stamp) = match key {
        Some(k) => (
            serde_json::to_string(&pow::issue(k, cfg.signup.pow_maxnumber, cfg.signup.pow_ttl_minutes * 60)).unwrap_or_default(),
            pow::stamp(k, util::now_secs()),
        ),
        None => (String::new(), String::new()),
    };
    let t = RegisterTpl {
        base: BASE,
        open: key.is_some(),
        challenge_json,
        stamp,
        min_len: cfg.min_password_len,
        max_len: MAX_LEN,
        min_form_seconds: cfg.signup.min_form_seconds,
        username: &f.username,
        email: &f.email,
        display_name: &f.display_name,
        csrf: csrf_for_cookie(a, h),
        error,
    };
    page(a, h, "Create an account", status, &t)
}

pub(super) async fn register_form<H: WebHost>(State(a): St<H>, Viewer(me): Viewer, h: HeaderMap) -> Response {
    if me.is_some() {
        return see_other(BASE, &[]);
    }
    register_page(&a, &h, StatusCode::OK, &RegisterForm::default(), None)
}

pub(super) async fn register<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<RegisterForm>) -> Response {
    let proof = pow::Proof { altcha: &f.altcha, ts: &f.ts, honeypot: &f.website, sec_fetch_site: "" };
    let form = crate::service::RegisterForm {
        username: &f.username,
        password: &f.password,
        email: Some(&f.email),
        display_name: Some(&f.display_name),
        proof,
    };
    match a.register(&ctx, form).await {
        Ok(s) => {
            let cookies = super::signed_in(&a, &s).await;
            flash::to(&a.keys, BASE, true, "Welcome! Your account is ready.", &cookies)
        }
        Err(e) => {
            if let Error::Db(err) = &e {
                tracing::error!(target: "accounts", error = %err, "database error");
            }
            register_page(&a, &h, status_of(&e), &f, Some(e.message()))
        }
    }
}

// ---- step-up

#[derive(Template)]
#[template(path = "reauth.html")]
struct ReauthTpl<'a> {
    base: &'static str,
    next: &'a str,
    username: &'a str,
    csrf: &'a str,
    minutes: i64,
    totp: bool,
    passkey: bool,
    password: bool,
    /// Providers to confirm with, for accounts with nothing else to offer.
    social: Vec<(&'static str, &'static str)>,
    max_len: usize,
    error: Option<&'a str>,
}

fn reauth_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, me: &Authed, next: &str, error: Option<&str>) -> Response {
    let t = ReauthTpl {
        base: BASE,
        next,
        username: &me.user.username,
        csrf: me.csrf(),
        minutes: a.host.config().step_up_minutes,
        totp: me.user.totp_enabled,
        passkey: me.user.has_passkey,
        password: me.user.has_password,
        social: if me.user.totp_enabled || me.user.has_passkey || me.user.has_password { Vec::new() } else { super::providers(a) },
        max_len: MAX_LEN,
        error,
    };
    page(a, h, "Confirm it's you", status, &t)
}

pub(super) async fn reauth_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap, Query(q): Query<NextQuery>) -> Response {
    reauth_page(&a, &h, StatusCode::OK, &me, &q.next, None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct ReauthForm {
    #[serde(rename = "_action")]
    action: String,
    password: String,
    code: String,
    next: String,
}

pub(super) async fn reauth<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<ReauthForm>) -> Response {
    let r = if f.action == "totp" {
        a.step_up_totp(&ctx, &me.user, &me.session, &f.code).await
    } else {
        a.step_up(&ctx, &me.user, &me.session, &f.password).await
    };
    match r {
        Ok(s) => see_other(util::safe_next(&f.next, BASE), &[set_session(&a.host.config(), &s.token)]),
        Err(e) => {
            if let Error::Db(err) = &e {
                tracing::error!(target: "accounts", error = %err, "database error");
            }
            reauth_page(&a, &h, status_of(&e), &me, &f.next, Some(e.message()))
        }
    }
}

/// For a handler that needs a recent sign-in: `None` when the session has one,
/// else the redirect to the step-up page, which comes back to `back`.
pub(super) fn need_fresh<H: WebHost>(a: &Accounts<H>, me: &Authed, back: &str) -> Option<Response> {
    if a.fresh(&me.session, util::now()) {
        return None;
    }
    Some(see_other(&format!("{BASE}/reauth?next={}", util::urlencode(back)), &[]))
}
