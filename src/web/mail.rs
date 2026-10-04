//! The password page, and with mail: the address, its confirmation link,
//! and resetting a forgotten password. Link pages show a button whose POST
//! uses the token, so a mail scanner opening the link changes nothing.

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::auth::need_fresh;
use super::flash;
use super::{Authed, BASE, St, WebHost, page, refused, status_of};
use crate::password::MAX_LEN;
use crate::service::{Accounts, Ctx, Error};

const SECURITY_PAGE: &str = "/account/security";

// ---- changing the password while signed in

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordTpl<'a> {
    base: &'static str,
    csrf: &'a str,
    username: &'a str,
    has_password: bool,
    min_len: usize,
    max_len: usize,
    error: Option<&'a str>,
}

fn password_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, me: &Authed, error: Option<&str>) -> Response {
    let t = PasswordTpl {
        base: BASE,
        csrf: me.csrf(),
        username: &me.user.username,
        has_password: me.user.has_password,
        min_len: a.host.config().min_password_len,
        max_len: MAX_LEN,
        error,
    };
    page(a, h, "Password", status, &t)
}

const PASSWORD_PAGE: &str = "/account/password";

pub(super) async fn password_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
    if let Some(r) = need_fresh(&a, &me, PASSWORD_PAGE) {
        return r;
    }
    password_page(&a, &h, StatusCode::OK, &me, None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct PasswordForm {
    password: String,
}

pub(super) async fn password<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<PasswordForm>) -> Response {
    if let Some(r) = need_fresh(&a, &me, PASSWORD_PAGE) {
        return r;
    }
    match a.password_change(&ctx, &me.user, &me.session, &f.password).await {
        Ok(()) => flash::to(&a.keys, SECURITY_PAGE, true, "Password changed. Every other session is signed out.", &[]),
        Err(e @ (Error::Invalid(_) | Error::Busy)) => password_page(&a, &h, status_of(&e), &me, Some(e.message())),
        Err(e) => refused(&a, &h, &e),
    }
}

// ---- the address

#[cfg(feature = "email")]
pub(super) use with_mail::*;

#[cfg(feature = "email")]
mod with_mail {
    use super::*;
    use axum::extract::Query;

    #[derive(Template)]
    #[template(path = "email.html")]
    struct EmailTpl<'a> {
        base: &'static str,
        csrf: &'a str,
        email: Option<&'a str>,
        pending: Option<&'a str>,
        ready: bool,
        value: &'a str,
        error: Option<&'a str>,
    }

    const EMAIL_PAGE: &str = "/account/email";

    fn email_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, me: &Authed, value: &str, error: Option<&str>) -> Response {
        let t = EmailTpl {
            base: BASE,
            csrf: me.csrf(),
            email: me.user.email.as_deref(),
            pending: me.user.email_pending.as_deref(),
            ready: a.mail_ready(),
            value,
            error,
        };
        page(a, h, "Email", status, &t)
    }

    pub(in super::super) async fn email_form<H: WebHost>(State(a): St<H>, me: Authed, h: HeaderMap) -> Response {
        if let Some(r) = need_fresh(&a, &me, EMAIL_PAGE) {
            return r;
        }
        email_page(&a, &h, StatusCode::OK, &me, "", None)
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    pub(in super::super) struct EmailForm {
        #[serde(rename = "_action")]
        action: String,
        email: String,
    }

    pub(in super::super) async fn email<H: WebHost>(State(a): St<H>, me: Authed, ctx: Ctx, h: HeaderMap, Form(f): Form<EmailForm>) -> Response {
        if let Some(r) = need_fresh(&a, &me, EMAIL_PAGE) {
            return r;
        }
        let r = match f.action.as_str() {
            "remove" => a.email_remove(&ctx, &me.user).await.map(|()| "Address removed."),
            _ => a.email_set(&ctx, &me.user, &f.email).await.map(|()| "A link is on its way. Open it to confirm the address."),
        };
        match r {
            Ok(msg) => flash::to(&a.keys, SECURITY_PAGE, true, msg, &[]),
            Err(e @ (Error::Invalid(_) | Error::RateLimited)) => email_page(&a, &h, status_of(&e), &me, &f.email, Some(e.message())),
            Err(e) => refused(&a, &h, &e),
        }
    }

    // ---- link pages

    #[derive(Deserialize, Default)]
    #[serde(default)]
    pub(in super::super) struct TokenQuery {
        t: String,
    }

    #[derive(Template)]
    #[template(path = "verify_email.html")]
    struct VerifyTpl<'a> {
        base: &'static str,
        t: &'a str,
        csrf: Option<String>,
    }

    pub(in super::super) async fn verify_form<H: WebHost>(State(a): St<H>, h: HeaderMap, Query(q): Query<TokenQuery>) -> Response {
        let t = VerifyTpl { base: BASE, t: &q.t, csrf: super::super::csrf_for_cookie(&a, &h) };
        page(&a, &h, "Confirm your address", StatusCode::OK, &t)
    }

    pub(in super::super) async fn verify<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(q): Form<TokenQuery>) -> Response {
        match a.email_confirm(&ctx, &q.t).await {
            Ok(()) => flash::to(&a.keys, BASE, true, "Your address is confirmed.", &[]),
            Err(e @ Error::Invalid(_)) => flash::to(&a.keys, &format!("{BASE}/login"), false, e.message(), &[]),
            Err(e) => refused(&a, &h, &e),
        }
    }

    #[derive(Template)]
    #[template(path = "forgot.html")]
    struct ForgotTpl {
        base: &'static str,
        ready: bool,
        csrf: Option<String>,
    }

    pub(in super::super) async fn forgot_form<H: WebHost>(State(a): St<H>, h: HeaderMap) -> Response {
        let t = ForgotTpl { base: BASE, ready: a.mail_ready(), csrf: super::super::csrf_for_cookie(&a, &h) };
        page(&a, &h, "Forgot your password", StatusCode::OK, &t)
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    pub(in super::super) struct ForgotForm {
        who: String,
    }

    pub(in super::super) async fn forgot<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<ForgotForm>) -> Response {
        match a.password_forgot(&ctx, &f.who).await {
            Ok(()) => {
                let msg = "If that account has a confirmed address, a link is on its way. It works for an hour.";
                flash::to(&a.keys, &format!("{BASE}/login"), true, msg, &[])
            }
            Err(e) => refused(&a, &h, &e),
        }
    }

    #[derive(Template)]
    #[template(path = "reset.html")]
    struct ResetTpl<'a> {
        base: &'static str,
        t: &'a str,
        csrf: Option<String>,
        min_len: usize,
        max_len: usize,
        error: Option<&'a str>,
    }

    fn reset_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, t: &str, error: Option<&str>) -> Response {
        let tpl = ResetTpl {
            base: BASE,
            t,
            csrf: super::super::csrf_for_cookie(a, h),
            min_len: a.host.config().min_password_len,
            max_len: MAX_LEN,
            error,
        };
        page(a, h, "Choose a new password", status, &tpl)
    }

    pub(in super::super) async fn reset_form<H: WebHost>(State(a): St<H>, h: HeaderMap, Query(q): Query<TokenQuery>) -> Response {
        reset_page(&a, &h, StatusCode::OK, &q.t, None)
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    pub(in super::super) struct ResetForm {
        t: String,
        password: String,
    }

    pub(in super::super) async fn reset<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<ResetForm>) -> Response {
        match a.password_reset(&ctx, &f.t, &f.password).await {
            Ok(()) => flash::to(&a.keys, &format!("{BASE}/login"), true, "Password changed. Sign in with it.", &[]),
            Err(e @ (Error::Invalid(_) | Error::Busy)) => reset_page(&a, &h, status_of(&e), &f.t, Some(e.message())),
            Err(e) => refused(&a, &h, &e),
        }
    }
}
