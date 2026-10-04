//! Social sign-in pages. Starting is a GET link (a POST that answers with a
//! redirect to another site trips `form-action 'self'`), so it changes
//! nothing but the flow cookie; the callback does the work.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;

use super::auth::need_fresh;
use super::flash;
use super::{BASE, St, Viewer, WebHost, error_page, page, refused, see_other, set_device, set_session, status_of};
use crate::oauth::Kind;
use crate::service::{Accounts, Ctx, Error, Intent, LoginStep, SocialOutcome};
use crate::{pow, util};

const FLOW_COOKIE: &str = "acct-oauth";
const SIGNUP_COOKIE: &str = "acct-oauth-signup";
const SECURITY_PAGE: &str = "/account/security";

fn cookie_set<H: WebHost>(a: &Accounts<H>, base: &str, value: &str, max_age: u64) -> String {
    let cfg = a.host.config();
    util::set_cookie(&util::cookie_name(base, cfg.cookie_secure), value, max_age, cfg.cookie_secure, true)
}

fn cookie_get<'a, H: WebHost>(a: &Accounts<H>, h: &'a HeaderMap, base: &str) -> &'a str {
    let name = util::cookie_name(base, a.host.config().cookie_secure);
    util::cookie(h.get(axum::http::header::COOKIE).and_then(|v| v.to_str().ok()), &name).unwrap_or("")
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct StartQuery {
    intent: String,
    next: String,
}

pub(super) async fn start<H: WebHost>(
    State(a): St<H>,
    Viewer(me): Viewer,
    h: HeaderMap,
    Path(p): Path<String>,
    Query(q): Query<StartQuery>,
) -> Response {
    let Some(kind) = Kind::from_slug(&p) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    let intent = match q.intent.as_str() {
        "link" => Intent::Link,
        "reauth" => Intent::Reauth,
        _ => Intent::Login,
    };
    if intent != Intent::Login {
        let Some(me) = &me else { return see_other(&format!("{BASE}/login"), &[]) };
        if intent == Intent::Link
            && let Some(r) = need_fresh(&a, me, SECURITY_PAGE)
        {
            return r;
        }
    }
    match a.oauth_begin(kind, intent, me.as_ref().map(|m| &m.user), &q.next) {
        Ok((url, cookie)) => see_other(&url, &[cookie_set(&a, FLOW_COOKIE, &cookie, 600)]),
        Err(e) => refused(&a, &h, &e),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct Callback {
    code: String,
    state: String,
    error: String,
}

pub(super) async fn callback<H: WebHost>(
    State(a): St<H>,
    Viewer(me): Viewer,
    ctx: Ctx,
    h: HeaderMap,
    Path(p): Path<String>,
    Query(q): Query<Callback>,
) -> Response {
    let cfg = a.host.config();
    let clear = cookie_set(&a, FLOW_COOKIE, "", 0);
    let back = if me.is_some() { SECURITY_PAGE.to_string() } else { format!("{BASE}/login") };
    let Some(kind) = Kind::from_slug(&p) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    if !q.error.is_empty() || q.code.is_empty() {
        return flash::to(&a.keys, &back, false, "Signing in there was cancelled.", &[clear]);
    }
    let flow = cookie_get(&a, &h, FLOW_COOKIE);
    let r = a.oauth_finish(&ctx, kind, flow, &q.state, &q.code, me.as_ref().map(|m| (&m.user, &m.session))).await;
    match r {
        Ok((SocialOutcome::Signed(LoginStep::Done(s)), next)) => {
            let cookies = [clear, set_session(&cfg, &s.token), set_device(&a, &cfg, s.info.user_id)];
            see_other(util::safe_next(&next, BASE), &cookies)
        }
        Ok((SocialOutcome::Signed(LoginStep::NeedMfa(s)), next)) => {
            let to = format!("{BASE}/mfa?next={}", util::urlencode(util::safe_next(&next, BASE)));
            see_other(&to, &[clear, set_session(&cfg, &s.token)])
        }
        Ok((SocialOutcome::Signup { cookie }, _)) => {
            see_other(&format!("{BASE}/oauth/signup"), &[clear, cookie_set(&a, SIGNUP_COOKIE, &cookie, 600)])
        }
        Ok((SocialOutcome::Linked, _)) => flash::to(&a.keys, SECURITY_PAGE, true, "Linked.", &[clear]),
        Ok((SocialOutcome::SteppedUp(s), next)) => see_other(util::safe_next(&next, BASE), &[clear, set_session(&cfg, &s.token)]),
        Err(e @ (Error::Invalid(_) | Error::Forbidden | Error::RateLimited | Error::BadLogin | Error::Closed)) => {
            flash::to(&a.keys, &back, false, e.message(), &[clear])
        }
        Err(e) => {
            let mut r = refused(&a, &h, &e);
            if let Ok(v) = clear.parse() {
                r.headers_mut().append(axum::http::header::SET_COOKIE, v);
            }
            r
        }
    }
}

// ---- choosing a username for a new account

#[derive(Template)]
#[template(path = "oauth_signup.html")]
struct SignupTpl<'a> {
    base: &'static str,
    username: &'a str,
    challenge_json: String,
    stamp: String,
    min_form_seconds: u64,
    csrf: Option<String>,
    error: Option<&'a str>,
}

fn signup_page<H: WebHost>(a: &Accounts<H>, h: &HeaderMap, status: StatusCode, username: &str, error: Option<&str>) -> Response {
    let cfg = a.host.config();
    let Some(key) = a.pow_key.as_deref() else { return error_page(a, h, StatusCode::FORBIDDEN, "Sign-up is closed.") };
    let t = SignupTpl {
        base: BASE,
        username,
        challenge_json: serde_json::to_string(&pow::issue(key, cfg.signup.pow_maxnumber, cfg.signup.pow_ttl_minutes * 60)).unwrap_or_default(),
        stamp: pow::stamp(key, util::now_secs()),
        min_form_seconds: cfg.signup.min_form_seconds,
        csrf: super::csrf_for_cookie(a, h),
        error,
    };
    page(a, h, "Choose a username", status, &t)
}

pub(super) async fn signup_form<H: WebHost>(State(a): St<H>, h: HeaderMap) -> Response {
    let Some(suggested) = a.oauth_signup_suggestion(cookie_get(&a, &h, SIGNUP_COOKIE)) else {
        return flash::to(&a.keys, &format!("{BASE}/login"), false, "That sign-in took too long. Try again.", &[]);
    };
    signup_page(&a, &h, StatusCode::OK, &suggested, None)
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(super) struct SignupForm {
    username: String,
    website: String,
    ts: String,
    altcha: String,
}

pub(super) async fn signup<H: WebHost>(State(a): St<H>, ctx: Ctx, h: HeaderMap, Form(f): Form<SignupForm>) -> Response {
    let proof = pow::Proof { altcha: &f.altcha, ts: &f.ts, honeypot: &f.website, sec_fetch_site: "" };
    match a.oauth_signup(&ctx, cookie_get(&a, &h, SIGNUP_COOKIE), &f.username, proof).await {
        Ok(s) => {
            let cfg = a.host.config();
            let cookies = [cookie_set(&a, SIGNUP_COOKIE, "", 0), set_session(&cfg, &s.token), set_device(&a, &cfg, s.info.user_id)];
            flash::to(&a.keys, BASE, true, "Welcome! Your account is ready.", &cookies)
        }
        Err(e @ Error::Db(_)) => refused(&a, &h, &e),
        Err(e) => signup_page(&a, &h, status_of(&e), &f.username, Some(e.message())),
    }
}

// ---- unlinking

#[derive(Deserialize, Default)]
pub(super) struct Empty {}

pub(super) async fn unlink<H: WebHost>(
    State(a): St<H>,
    me: super::Authed,
    ctx: Ctx,
    h: HeaderMap,
    Path(p): Path<String>,
    _f: Form<Empty>,
) -> Response {
    if let Some(r) = need_fresh(&a, &me, SECURITY_PAGE) {
        return r;
    }
    let Some(kind) = Kind::from_slug(&p) else { return error_page(&a, &h, StatusCode::NOT_FOUND, "Not found.") };
    let linked = match a.oauth_linked(me.user.id).await {
        Ok(l) => l,
        Err(e) => return refused(&a, &h, &Error::Db(e)),
    };
    let Some((_, cred)) = linked.into_iter().find(|(k, _)| *k == kind) else {
        return flash::to(&a.keys, SECURITY_PAGE, false, "That is not linked.", &[]);
    };
    match a.remove_credential(&ctx, &me.user, &kind.credential_kind(), &cred.ext_id).await {
        Ok(()) => flash::to(&a.keys, SECURITY_PAGE, true, "Unlinked.", &[]),
        Err(e @ (Error::Invalid(_) | Error::NotFound)) => flash::to(&a.keys, SECURITY_PAGE, false, e.message(), &[]),
        Err(e) => refused(&a, &h, &e),
    }
}
