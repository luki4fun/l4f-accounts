//! Router tests: the crate router nested at `/account` under a stub host whose
//! page is the bare fragment. The first group never reaches the database (its
//! pool points nowhere); the second needs `L4F_TEST_DATABASE_URL`.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use sha2::Digest;
use sqlx::mysql::MySqlPoolOptions;
use tower::ServiceExt;

use super::*;
use crate::keys::Keys;
use crate::model::{AccountId, NewUser};
use crate::service::{Accounts, Config, Host};
use crate::store::Store;
use crate::{password, util};

const POW: &[u8] = b"web-test-pow-key-0123456789abcdef";
const PW: &str = "correct horse battery";

struct T {
    cfg: Arc<Config>,
}

impl Host for T {
    fn config(&self) -> Arc<Config> {
        self.cfg.clone()
    }

    async fn export(&self, _: AccountId) -> Vec<(String, serde_json::Value)> {
        Vec::new()
    }

    async fn delete_user(&self, _: crate::store::StoreConn<'_>, _: AccountId, _: bool) -> sqlx::Result<()> {
        Ok(())
    }
}

impl WebHost for T {
    fn page(&self, _: &HeaderMap, title: &str, body: String) -> Response {
        Html(format!("<title>{title}</title>{body}")).into_response()
    }
}

fn cfg() -> Config {
    let mut c = Config {
        login_per_15min: 100,
        login_per_15min_global: 1000,
        login_per_user_15min: 100,
        require_2fa_for_privileged: false,
        ..Config::default()
    };
    c.signup.min_form_seconds = 0;
    c.signup.pow_maxnumber = 1000;
    c.signup.max_accounts_per_ip_day = 1000;
    c.signup.max_accounts_per_hour = 1000;
    c.signup.max_attempts_per_ip_hour = 1000;
    c
}

fn nowhere() -> Store {
    Store::from(MySqlPoolOptions::new().acquire_timeout(Duration::from_millis(200)).connect_lazy("mysql://x:x@127.0.0.1:9/x").unwrap())
}

fn app(store: Store, cfg: Config) -> (Router, Arc<Accounts<T>>) {
    let keys = Keys::new(&[9; 32], None).unwrap();
    let a = Arc::new(Accounts::new(store, keys, Arc::default(), T { cfg: Arc::new(cfg) }, &[], Some(POW.to_vec()), Vec::new()).unwrap());
    (Router::new().nest(BASE, router(a.clone())), a)
}

async fn send(app: &Router, mut req: Request<Body>) -> Response {
    req.extensions_mut().insert(ClientIp("203.0.113.99".parse().unwrap()));
    app.clone().oneshot(req).await.unwrap()
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(uri);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn post(uri: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "same-origin");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn text(r: Response) -> String {
    String::from_utf8(axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap()
}

fn location(r: &Response) -> &str {
    r.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// `name=value` of the Set-Cookie for `name`, if any.
fn set_cookie(r: &Response, name: &str) -> Option<String> {
    r.headers().get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|c| {
        let pair = c.split(';').next()?;
        pair.starts_with(&format!("{name}=")).then(|| pair.to_string())
    })
}

/// The value of the first `name="<name>" value="…"` in a page.
fn field(page: &str, name: &str) -> String {
    let at = page.find(&format!("name=\"{name}\" value=\"")).unwrap_or_else(|| panic!("no {name} field")) + name.len() + 15;
    page[at..at + page[at..].find('"').unwrap()].to_string()
}

fn challenge_json(page: &str) -> &str {
    const OPEN: &str = r#"id="pow-challenge">"#;
    let at = page.find(OPEN).unwrap() + OPEN.len();
    &page[at..at + page[at..].find("</script>").unwrap()]
}

fn token_cookie() -> (String, [u8; 32]) {
    let raw: [u8; 32] = util::random();
    let t = util::b64u(&raw);
    (format!("__Host-acct={t}"), sha2::Sha256::digest(raw).into())
}

#[tokio::test]
async fn login_form_renders_without_session() {
    let (app, _) = app(nowhere(), cfg());
    let r = send(&app, get("/account/login", None)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CACHE_CONTROL], "private, no-store");
    let page = text(r).await;
    assert!(page.contains(r#"action="/account/login""#) && page.contains("<title>Sign in</title>"));
    assert!(!page.contains(r#"name="csrf""#), "no cookie, no token");
    assert!(!page.contains("/account/register"), "sign-up closed: no link");
}

#[tokio::test]
async fn a_stale_cookie_gets_a_form_token_so_signing_in_again_works() {
    let (app, a) = app(nowhere(), cfg());
    let (cookie, hash) = token_cookie();
    let page = text(send(&app, get("/account/login", Some(&cookie))).await).await;
    assert_eq!(field(&page, "csrf"), csrf::token(&a.keys, &hash));
}

#[tokio::test]
async fn anonymous_pages_redirect_to_login_with_next() {
    let (app, _) = app(nowhere(), cfg());
    let r = send(&app, get("/account/reauth?next=/account/delete", None)).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&r), "/account/login?next=%2Faccount%2Freauth%3Fnext%3D%2Faccount%2Fdelete");
    let r = send(&app, post("/account/logout-all", "", None)).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/login?next=%2Faccount"), "a POST comes back to the dashboard");
}

#[tokio::test]
async fn cross_and_same_site_posts_are_refused() {
    let (app, _) = app(nowhere(), cfg());
    for site in ["cross-site", "same-site"] {
        let mut req = post("/account/login", "username=a&password=b", None);
        req.headers_mut().insert("sec-fetch-site", site.parse().unwrap());
        assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN, "{site}");
    }
    let mut req = post("/account/logout", "", None);
    req.headers_mut().remove("sec-fetch-site");
    let r = send(&app, req).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "no header and no cookie: nothing to protect");
    assert!(location(&r).starts_with("/account/login?ok=Signed+out."));
}

/// A browser without Fetch Metadata still names a form's origin (AUTH-7).
#[tokio::test]
async fn without_fetch_metadata_a_foreign_origin_is_refused() {
    let (app, _) = app(nowhere(), Config { base_url: "https://l4f.cc".into(), ..cfg() });
    let logout = |site: Option<&str>, origin: Option<&str>| {
        let mut req = post("/account/logout", "", None);
        req.headers_mut().remove("sec-fetch-site");
        if let Some(s) = site {
            req.headers_mut().insert("sec-fetch-site", s.parse().unwrap());
        }
        if let Some(o) = origin {
            req.headers_mut().insert(header::ORIGIN, o.parse().unwrap());
        }
        req
    };
    for bad in ["https://evil.example", "null", "http://l4f.cc", "https://l4f.cc.evil.example"] {
        assert_eq!(send(&app, logout(None, Some(bad))).await.status(), StatusCode::FORBIDDEN, "{bad}");
    }
    for ok in [Some("https://l4f.cc"), None] {
        assert_eq!(send(&app, logout(None, ok)).await.status(), StatusCode::SEE_OTHER, "{ok:?}");
    }
    let r = send(&app, logout(Some("same-origin"), Some("null"))).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "where the browser sends Fetch Metadata, that decides");
}

/// Never framed, unless a handler or the host's page set its own policy (FAC-3).
#[tokio::test]
async fn account_pages_are_never_framed_unless_the_host_says_so() {
    let (app, _) = app(nowhere(), cfg());
    assert_eq!(send(&app, get("/account/login", None)).await.headers()[header::X_FRAME_OPTIONS], "DENY");
    let own = ([(header::X_FRAME_OPTIONS, "SAMEORIGIN")], "x").into_response();
    assert_eq!(account_headers(own).await.headers()[header::X_FRAME_OPTIONS], "SAMEORIGIN");
}

#[tokio::test]
async fn post_with_session_cookie_needs_its_token() {
    let (app, a) = app(nowhere(), cfg());
    let (cookie, hash) = token_cookie();
    let good = csrf::token(&a.keys, &hash);
    let other = csrf::token(&a.keys, &[1; 32]);
    assert_eq!(send(&app, post("/account/logout", "", Some(&cookie))).await.status(), StatusCode::FORBIDDEN);
    let r = send(&app, post("/account/logout", &format!("csrf={other}"), Some(&cookie))).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "another session's token");
    let mut req = post("/account/logout", "", Some(&cookie));
    req.headers_mut().insert("x-csrf", good.parse().unwrap());
    let r = send(&app, req).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "the header");
    assert_eq!(set_cookie(&r, "__Host-acct").as_deref(), Some("__Host-acct="), "cleared");
    let r = send(&app, post("/account/logout", &format!("a=1&csrf={good}"), Some(&cookie))).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "the form field");
    let mut req = post("/account/logout", "{}", Some(&cookie));
    req.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN, "a body the layer cannot read needs the header");
}

#[tokio::test]
async fn oversized_form_body_with_cookie_is_413() {
    let (app, a) = app(nowhere(), cfg());
    let (cookie, hash) = token_cookie();
    let body = format!("csrf={}&x={}", csrf::token(&a.keys, &hash), "a".repeat(80 * 1024));
    assert_eq!(send(&app, post("/account/logout", &body, Some(&cookie))).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn missing_client_ip_fails_closed() {
    let (app, _) = app(nowhere(), cfg());
    let r = app.clone().oneshot(post("/account/login", "username=a&password=b", None)).await.unwrap();
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn register_is_closed_by_default() {
    let (app, _) = app(nowhere(), Config::default());
    let page = text(send(&app, get("/account/register", None)).await).await;
    assert!(page.contains("Sign-up is closed"));
    assert!(!page.contains("pow-challenge") && !page.contains("pow.js"));
}

#[tokio::test]
async fn register_form_carries_the_pow_markup_when_open() {
    let (app, _) = app(nowhere(), Config { registration_open: true, ..cfg() });
    let page = text(send(&app, get("/account/register", None)).await).await;
    for want in [r#"id="pow-challenge""#, r#"name="ts""#, r#"name="website""#, r#"id="altcha""#, "/static/js/pow.js", r#"id="username""#] {
        assert!(page.contains(want), "{want}");
    }
    assert!(!page.contains(r#"id="u""#), "pow.js wires the Matrix availability check to #u");
    let json = challenge_json(&page);
    assert!(serde_json::from_str::<serde_json::Value>(json).is_ok(), "{json}");
    let login = text(send(&app, get("/account/login", None)).await).await;
    assert!(login.contains("/account/register"), "open sign-up is linked");
}

#[test]
fn page_paths_sit_under_base() {
    for p in [LOGIN_PAGE, SECURITY_PAGE] {
        assert!(p.strip_prefix(BASE).is_some_and(|rest| rest.starts_with('/')), "{p}");
    }
}

/// The `__Host-` prefix and Secure go together, or the browser drops the cookie.
#[test]
fn crate_cookies_take_prefix_and_secure_together() {
    let (on, off) = (cfg(), Config { cookie_secure: false, ..cfg() });
    assert_eq!(cookie_out(&on, SESSION_COOKIE, "v", 60, true), "__Host-acct=v; Path=/; SameSite=Lax; Max-Age=60; HttpOnly; Secure");
    assert_eq!(cookie_out(&off, SYNC_COOKIE, "1", 60, false), "acct-sync=1; Path=/; SameSite=Lax; Max-Age=60");
    let h: HeaderMap = [(header::COOKIE, "acct-ch=plain; __Host-acct-ch=host".parse().unwrap())].into_iter().collect();
    assert_eq!((cookie_in(&on, &h, CHALLENGE_COOKIE), cookie_in(&off, &h, CHALLENGE_COOKIE)), (Some("host"), Some("plain")));
}

/// Every refusal shown goes through `status_of` once: a database error is
/// logged once, also where a handler shows its own form again.
#[tokio::test]
async fn a_database_error_is_logged_once() {
    let (_, a) = app(nowhere(), cfg());
    let db = || Error::Db(sqlx::Error::PoolTimedOut);
    let logs = |f: &dyn Fn()| crate::testkit::logged(f).iter().filter(|l| l.contains("database error")).count();
    assert_eq!(logs(&|| _ = status_of(&db())), 1, "a form shown again");
    assert_eq!(logs(&|| _ = refused(&a, &HeaderMap::new(), &db())), 1, "the error page");
    assert_eq!(logs(&|| _ = json_refused(&db())), 1, "a script's refusal");
    assert_eq!(logs(&|| _ = status_of(&Error::NotFound)), 0);
}

// ---- against the test database

async fn shared(cfg: Config) -> Option<(Router, Arc<Accounts<T>>)> {
    let store = crate::store::tests::shared().await?;
    Some(app(store, cfg))
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(util::random::<6>()))
}

async fn make_user(a: &Accounts<T>) -> NewUser {
    let u = NewUser {
        id: AccountId::new(),
        username: unique("w"),
        display_name: "W".into(),
        email_pending: None,
        password_hash: Some(password::hash(PW)),
        created_at: util::now(),
    };
    a.store.create_user(&u, Some("user")).await.unwrap();
    u
}

async fn drop_user(a: &Accounts<T>, id: AccountId) {
    crate::store::tests::delete(&a.store, id).await.unwrap();
}

/// Brute-force the page's challenge the way pow.js does.
fn solve(page: &str) -> String {
    let c: serde_json::Value = serde_json::from_str(challenge_json(page)).unwrap();
    let (salt, want) = (c["salt"].as_str().unwrap(), c["challenge"].as_str().unwrap());
    for n in 0..=c["maxnumber"].as_u64().unwrap() {
        if hex::encode(sha2::Sha256::digest(format!("{salt}{n}").as_bytes())) == want {
            return serde_json::json!({
                "algorithm": c["algorithm"], "challenge": want, "number": n, "salt": salt, "signature": c["signature"]
            })
            .to_string();
        }
    }
    panic!("unsolvable");
}

#[tokio::test]
async fn register_then_reauth_page_then_sign_out() {
    let Some((app, a)) = shared(Config { registration_open: true, ..cfg() }).await else { return };
    let page = text(send(&app, get("/account/register", None)).await).await;
    let name = unique("w");
    let body = format!(
        "username={name}&password={}&display_name=&email=&website=&ts={}&altcha={}",
        util::urlencode(PW),
        util::urlencode(&field(&page, "ts")),
        util::urlencode(&solve(&page))
    );
    let r = send(&app, post("/account/register", &body, None)).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(location(&r).starts_with("/account?ok=Welcome"));
    let cookie = set_cookie(&r, "__Host-acct").unwrap();
    assert!(set_cookie(&r, "__Host-acct-dev").is_some());

    let r = send(&app, get("/account/reauth?next=/account", Some(&cookie))).await;
    assert_eq!(r.status(), StatusCode::OK);
    let page = text(r).await;
    assert!(page.contains(&format!(r#"value="{name}""#)), "the username, for password managers");
    let csrf = field(&page, "csrf");
    let r = send(&app, post("/account/logout", &format!("csrf={csrf}"), Some(&cookie))).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let r = send(&app, get("/account/reauth", Some(&cookie))).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER, "signed out");
    assert_eq!(set_cookie(&r, "__Host-acct").as_deref(), Some("__Host-acct="), "the dead cookie is cleared");
    let u = a.store.user_by_username(&name).await.unwrap().unwrap();
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn wrong_password_and_unknown_user_get_the_same_answer() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let mut seen = Vec::new();
    for (name, pw) in [(u.username.as_str(), "wrong password!"), ("nobody-here", PW)] {
        let r = send(&app, post("/account/login", &format!("username={name}&password={}", util::urlencode(pw)), None)).await;
        assert!(set_cookie(&r, "__Host-acct").is_none());
        let status = r.status();
        let page = text(r).await;
        assert!(page.contains("Wrong username or password."));
        assert!(page.contains(&format!(r#"value="{name}""#)), "the name stays filled in");
        seen.push(status);
    }
    assert_eq!(seen, [StatusCode::OK, StatusCode::OK]);
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn sign_in_sets_the_device_cookie_and_returns_to_next() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let body = format!("username={}&password={}&next=%2Faccount%2Freauth", u.username, util::urlencode(PW));
    let r = send(&app, post("/account/login", &body, None)).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/reauth"));
    let dev = set_cookie(&r, "__Host-acct-dev").unwrap();
    assert!(dev.starts_with(&format!("__Host-acct-dev={}.", u.id.hex())));
    let h: HeaderMap = [(header::COOKIE, dev.parse().unwrap())].into_iter().collect();
    assert_eq!(known_device(&a, &a.host.config(), &h), Some(u.id));
    let forged: HeaderMap = [(header::COOKIE, format!("__Host-acct-dev={}.AAAA", u.id.hex()).parse().unwrap())].into_iter().collect();
    assert_eq!(known_device(&a, &a.host.config(), &forged), None);

    let evil = format!("username={}&password={}&next=%2F%2Fevil.example", u.username, util::urlencode(PW));
    assert_eq!(location(&send(&app, post("/account/login", &evil, None)).await), "/account", "next stays on this site");
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn step_up_takes_the_password_and_rotates_the_cookie() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let ctx = crate::service::Ctx { ip: "203.0.113.99".parse().unwrap(), ua: String::new(), sec_fetch_site: String::new() };
    let s = a.create_session(u.id, "password", true, util::now() - 3600, &ctx).await.unwrap();
    let cookie = format!("__Host-acct={}", s.token);
    let csrf = csrf::token(&a.keys, &s.info.token_hash);
    let r = send(&app, post("/account/reauth", &format!("csrf={csrf}&password=nope&next=%2Fx"), Some(&cookie))).await;
    assert!(text(r).await.contains("Wrong password."));
    let r = send(&app, post("/account/reauth", &format!("csrf={csrf}&password={}&next=%2Fx", util::urlencode(PW)), Some(&cookie))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/x"));
    let fresh = set_cookie(&r, "__Host-acct").unwrap();
    assert_ne!(fresh, cookie);
    let me = a.viewer(&[(header::COOKIE, fresh.parse().unwrap())].into_iter().collect()).await.unwrap().unwrap();
    assert!(a.fresh(&me.session, util::now()));
    assert!(a.viewer(&[(header::COOKIE, cookie.parse().unwrap())].into_iter().collect()).await.unwrap().is_none(), "old cookie dead");
    drop_user(&a, u.id).await;
}

#[test]
fn when_formats_utc() {
    assert_eq!(when(0), "1970-01-01 00:00 UTC");
    assert_eq!(when(1_791_129_600), "2026-10-04 16:00 UTC");
    assert_eq!(when(951_825_600), "2000-02-29 12:00 UTC");
    assert_eq!(when(-1), "1969-12-31 23:59 UTC");
}

#[tokio::test]
async fn the_dashboard_needs_a_session() {
    let (app, _) = app(nowhere(), cfg());
    let r = send(&app, get("/account", None)).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/login?next=%2Faccount"));
}

/// A signed-in browser: its cookie header and form token. `auth_at` decides
/// whether it counts as a recent sign-in.
async fn browser(a: &Accounts<T>, user: AccountId, auth_at: i64) -> (String, String, [u8; 32]) {
    let ctx = crate::service::Ctx { ip: "203.0.113.99".parse().unwrap(), ua: "Test/1".into(), sec_fetch_site: String::new() };
    let s = a.create_session(user, "password", true, auth_at, &ctx).await.unwrap();
    (format!("__Host-acct={}", s.token), csrf::token(&a.keys, &s.info.token_hash), s.info.token_hash)
}

#[tokio::test]
async fn dashboard_sessions_and_sign_out_everywhere() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let (c1, t1, h1) = browser(&a, u.id, util::now()).await;
    let (c2, _, h2) = browser(&a, u.id, util::now()).await;
    let (c3, _, _) = browser(&a, u.id, util::now()).await;
    let r = send(&app, get("/account", Some(&c1))).await;
    assert_eq!(r.status(), StatusCode::OK);
    let page = text(r).await;
    assert!(page.contains(&format!("@{}", u.username)) && page.contains("this browser") && page.contains("Test/1"));
    assert_eq!(page.matches("/revoke\"").count(), 3);
    assert!(page.contains(&hex::encode(h2)));

    let r = send(&app, post(&format!("/account/sessions/{}/revoke", hex::encode(h2)), &format!("csrf={t1}"), Some(&c1))).await;
    assert!(location(&r).starts_with("/account?ok=That+session"));
    assert_eq!(send(&app, get("/account", Some(&c2))).await.status(), StatusCode::SEE_OTHER, "revoked");
    let r = send(&app, post("/account/sessions/zz/revoke", &format!("csrf={t1}"), Some(&c1))).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    let r = send(&app, post("/account/logout-all", &format!("csrf={t1}"), Some(&c1))).await;
    assert!(location(&r).starts_with("/account?ok=Signed+out+of+1+other+session."), "{}", location(&r));
    assert_eq!(send(&app, get("/account", Some(&c3))).await.status(), StatusCode::SEE_OTHER);
    assert_eq!(send(&app, get("/account", Some(&c1))).await.status(), StatusCode::OK, "this one stays");

    let r = send(&app, post(&format!("/account/sessions/{}/revoke", hex::encode(h1)), &format!("csrf={t1}"), Some(&c1))).await;
    assert!(location(&r).starts_with("/account/login?ok=Signed+out."), "revoking this browser signs it out");
    assert_eq!(set_cookie(&r, "__Host-acct").as_deref(), Some("__Host-acct="));
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn display_name_is_cleaned() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let r = send(&app, post("/account/display-name", &format!("csrf={t}&display_name=+Dee+"), Some(&c))).await;
    assert!(location(&r).starts_with("/account?ok="));
    let r = send(&app, post("/account/display-name", &format!("csrf={t}&display_name=a%E2%80%AEb"), Some(&c))).await;
    assert!(location(&r).starts_with("/account?err="), "bidi override refused");
    let page = text(send(&app, get(location(&r), Some(&c))).await).await;
    assert!(page.contains("text-direction") && page.contains("<h1>Dee</h1>"));
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn deleting_needs_a_recent_sign_in() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let (stale, st, _) = browser(&a, u.id, util::now() - 3600).await;
    let r = send(&app, get("/account/delete", Some(&stale))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/reauth?next=%2Faccount%2Fdelete"));
    let r = send(&app, post("/account/delete", &format!("csrf={st}"), Some(&stale))).await;
    assert_eq!(location(&r), "/account/reauth?next=%2Faccount%2Fdelete", "the post too");
    assert!(a.store.user_by_id(u.id).await.unwrap().is_some());

    let (fresh, ft, _) = browser(&a, u.id, util::now()).await;
    assert_eq!(send(&app, get("/account/delete", Some(&fresh))).await.status(), StatusCode::OK);
    let r = send(&app, post("/account/delete", &format!("csrf={ft}&delete_owned=1"), Some(&fresh))).await;
    assert!(location(&r).starts_with("/account/login?ok=Your+account+is+deleted."));
    assert_eq!(set_cookie(&r, "__Host-acct-dev").as_deref(), Some("__Host-acct-dev="));
    assert!(a.store.user_by_id(u.id).await.unwrap().is_none());
}

#[tokio::test]
async fn export_is_a_json_attachment_without_secrets() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, _, h) = browser(&a, u.id, util::now()).await;
    let r = send(&app, get("/account/data", Some(&c))).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
    assert_eq!(r.headers()[header::CONTENT_DISPOSITION], format!("attachment; filename=\"account-{}.json\"", u.username).as_str());
    let body = text(r).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.is_object());
    assert!(!body.contains("$argon2") && !body.contains(&hex::encode(h)), "no hash, no session id");
    drop_user(&a, u.id).await;
}

async fn role_with(a: &Accounts<T>, scopes: &[&str]) -> String {
    let name = unique("r");
    let id = a.store.create_role(&name, "", None).await.unwrap().unwrap();
    a.store.set_role_scopes(id, &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>()).await.unwrap();
    name
}

async fn give(a: &Accounts<T>, user: AccountId, role: &str) {
    let r = a.store.role_by_name(role).await.unwrap().unwrap();
    a.store.grant_role(user, r.id, None).await.unwrap();
}

async fn drop_role(a: &Accounts<T>, name: &str) {
    if let Some(r) = a.store.role_by_name(name).await.unwrap() {
        a.store.delete_role(r.id).await.unwrap();
    }
}

#[tokio::test]
async fn admin_pages_need_their_scope_and_changes_need_step_up() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let nobody = make_user(&a).await;
    let (c0, _, _) = browser(&a, nobody.id, util::now()).await;
    assert_eq!(send(&app, get("/account/admin/users", Some(&c0))).await.status(), StatusCode::FORBIDDEN);
    assert_eq!(send(&app, get("/account/admin/roles", Some(&c0))).await.status(), StatusCode::FORBIDDEN);

    let reader = role_with(&a, &["users:read"]).await;
    let viewer = make_user(&a).await;
    give(&a, viewer.id, &reader).await;
    let (c1, t1, _) = browser(&a, viewer.id, util::now()).await;
    let r = send(&app, get(&format!("/account/admin/users?q={}", nobody.username), Some(&c1))).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(text(r).await.contains(&nobody.username));
    let page = text(send(&app, get("/account", Some(&c1))).await).await;
    assert!(page.contains("/account/admin/users") && !page.contains("/account/admin/roles\""), "only what it may open");
    let target = format!("/account/admin/users/{}", nobody.id.hex());
    use crate::store::tests::{Arg, exec};
    let sql = "INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) VALUES ('passkey', ?, ?, 1)";
    exec(&a.store, sql, vec![Arg::B(util::random::<16>().to_vec()), Arg::B(nobody.id.0.to_vec())]).await;
    let r = send(&app, get(&target, Some(&c1))).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert!(text(r).await.contains("<dt>Two-factor</dt><dd>passkey</dd>"), "a passkey alone is a second factor too");
    let r = send(&app, post(&target, &format!("csrf={t1}&_action=grant&role={reader}"), Some(&c1))).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "reading is not granting");

    let admin_role = role_with(&a, &["users:admin", "users:read", "roles:admin"]).await;
    let admin = make_user(&a).await;
    give(&a, admin.id, &admin_role).await;
    let (stale, st, _) = browser(&a, admin.id, util::now() - 3600).await;
    let r = send(&app, post(&target, &format!("csrf={st}&_action=grant&role={reader}"), Some(&stale))).await;
    assert_eq!(location(&r), format!("/account/reauth?next={}", util::urlencode(&target)), "a change needs a recent sign-in");

    let (c2, t2, _) = browser(&a, admin.id, util::now()).await;
    let (victim, _, _) = browser(&a, nobody.id, util::now()).await;
    let r = send(&app, post(&target, &format!("csrf={t2}&_action=grant&role={reader}"), Some(&c2))).await;
    assert!(location(&r).starts_with(&format!("{target}?ok=Role+granted.")), "{}", location(&r));
    let r = send(&app, post(&target, &format!("csrf={t2}&_action=revoke&role={reader}"), Some(&c2))).await;
    assert!(location(&r).contains("ok=Role+taken+away"));
    assert_eq!(send(&app, get("/account", Some(&victim))).await.status(), StatusCode::SEE_OTHER, "signed out by the revoke");
    let r = send(&app, post(&target, &format!("csrf={t2}&_action=disable"), Some(&c2))).await;
    assert!(location(&r).contains("ok=Account+suspended"));
    let r = send(&app, post(&target, &format!("csrf={t2}&_action=nonsense"), Some(&c2))).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = send(&app, post(&target, &format!("csrf={t2}&_action=delete"), Some(&c2))).await;
    assert!(location(&r).starts_with("/account/admin/users?ok=Account+deleted."));
    assert!(a.store.user_by_id(nobody.id).await.unwrap().is_none());

    drop_user(&a, viewer.id).await;
    drop_user(&a, admin.id).await;
    drop_role(&a, &reader).await;
    drop_role(&a, &admin_role).await;
}

#[tokio::test]
async fn roles_are_created_edited_and_deleted() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let admin_role = role_with(&a, &["roles:admin", "users:read"]).await;
    let admin = make_user(&a).await;
    give(&a, admin.id, &admin_role).await;
    let (c, t, _) = browser(&a, admin.id, util::now()).await;
    let name = unique("r");
    let r = send(&app, post("/account/admin/roles", &format!("csrf={t}&name={name}&description=Test&badge=&scopes=users%3Aread"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/admin/roles?ok=Role+created."), "{}", location(&r));
    let second = unique("r");
    let r = send(&app, post("/account/admin/roles", &format!("csrf={t}&name={}&scopes=users%3Aread", second.to_uppercase()), Some(&c))).await;
    assert!(location(&r).starts_with("/account/admin/roles?ok="), "names are lowercased");
    assert!(a.store.role_by_name(&second).await.unwrap().is_some());
    let r = send(&app, post("/account/admin/roles", &format!("csrf={t}&name={}&scopes=users%3Areed", unique("r")), Some(&c))).await;
    assert!(location(&r).contains("err=That+is+not+a+scope"), "a typo is refused");
    let r = send(&app, post("/account/admin/roles", &format!("csrf={t}&name={}&scopes=users%3Aadmin", unique("r")), Some(&c))).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "no handing out what you do not hold");

    let page_url = format!("/account/admin/roles/{name}");
    let page = text(send(&app, get(&page_url, Some(&c))).await).await;
    assert!(page.contains(">users:read</textarea>"));
    let r = send(&app, post(&page_url, &format!("csrf={t}&_action=save&description=New&badge=Mod&scopes=users%3Aread%0Aroles%3Aadmin"), Some(&c))).await;
    assert!(location(&r).starts_with(&format!("{page_url}?ok=Role+saved.")));
    let role = a.store.role_by_name(&name).await.unwrap().unwrap();
    assert_eq!((role.description.as_str(), role.badge.as_deref(), role.scopes.len()), ("New", Some("Mod"), 2));
    let r = send(&app, post(&page_url, &format!("csrf={t}&_action=delete"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/admin/roles?ok=Role+deleted."));
    let r = send(&app, post("/account/admin/roles/user", &format!("csrf={t}&_action=delete"), Some(&c))).await;
    assert!(location(&r).contains("err=Built-in"), "{}", location(&r));
    assert_eq!(send(&app, get("/account/admin/roles/nope-nope", Some(&c))).await.status(), StatusCode::NOT_FOUND);

    drop_user(&a, admin.id).await;
    drop_role(&a, &admin_role).await;
    drop_role(&a, &second).await;
}

// ---- second factors

fn pk_cfg() -> Config {
    Config { base_url: "https://l4f.cc".into(), ..cfg() }
}

fn post_json(uri: &str, body: &serde_json::Value, cookie: Option<&str>, csrf: Option<&str>) -> Request<Body> {
    let mut b = Request::post(uri).header(header::CONTENT_TYPE, "application/json").header("sec-fetch-site", "same-origin");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(t) = csrf {
        b = b.header("x-csrf", t);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn json_of(r: Response) -> serde_json::Value {
    serde_json::from_str(&text(r).await).unwrap()
}

#[tokio::test]
async fn totp_setup_then_sign_in_through_the_second_step() {
    let Some((app, a)) = shared(pk_cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let page = text(send(&app, get("/account/totp", Some(&c))).await).await;
    assert!(page.contains("<svg") || page.contains("<?xml"), "a QR code");
    let sealed = field(&page, "setup");
    let secret = crate::totp::base32_decode(&page[page.find(r#"<p class="mono anywhere">"#).unwrap() + 25..].split('<').next().unwrap().replace(' ', "")).unwrap();
    let step = util::now() / 30;
    let code = |s: i64| format!("{:06}", crate::totp::code_at(&secret, s));
    let r = send(&app, post("/account/totp", &format!("csrf={t}&_action=enable&setup={sealed}&code=000000"), Some(&c))).await;
    assert!(text(r).await.contains("That code is not right."), "a wrong code shows the same setup again");
    let r = send(&app, post("/account/totp", &format!("csrf={t}&_action=enable&setup={sealed}&code={}", code(step)), Some(&c))).await;
    let rotated = set_cookie(&r, "__Host-acct").expect("the first second factor gives this browser a new token");
    assert!(rotated != "__Host-acct=" && rotated != c);
    let codes_page = text(r).await;
    assert!(codes_page.contains("Your recovery codes") && codes_page.contains("Every other session"));
    let code_at = |i: usize| codes_page.split("<li>").nth(i).unwrap().split('<').next().unwrap().to_string();
    let first_code = code_at(1);
    assert_eq!(location(&send(&app, get("/account", Some(&c))).await), "/account/login?next=%2Faccount", "the old token is dead");
    assert_eq!(send(&app, get("/account", Some(&rotated))).await.status(), StatusCode::OK, "the new one signs in");

    // Signing in again stops at the second step.
    let body = format!("username={}&password={}&next=%2Faccount%2Fsecurity", u.username, util::urlencode(PW));
    let r = send(&app, post("/account/login", &body, None)).await;
    assert_eq!(location(&r), "/account/mfa?next=%2Faccount%2Fsecurity");
    let pending = set_cookie(&r, "__Host-acct").unwrap();
    assert!(set_cookie(&r, "__Host-acct-dev").is_none(), "not a known device before the second step");
    // A pending session is nobody: an account page sends it to its second step, cookie kept.
    let r = send(&app, get("/account/security", Some(&pending))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/mfa?next=%2Faccount%2Fsecurity"));
    assert!(set_cookie(&r, "__Host-acct").is_none(), "a live pending cookie stays");
    let page = text(send(&app, get("/account/mfa?next=%2Faccount%2Fsecurity", Some(&pending))).await).await;
    assert!(page.contains("authenticator app") && !page.contains(r#"data-passkey="mfa""#));
    let pt = field(&page, "csrf");
    let r = send(&app, post("/account/mfa", &format!("csrf={pt}&_action=totp&next=%2Faccount%2Fsecurity&code={}", code(step + 1)), Some(&pending))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/security"));
    let full = set_cookie(&r, "__Host-acct").unwrap();
    assert!(set_cookie(&r, "__Host-acct-dev").is_some());
    assert_eq!(send(&app, get("/account", Some(&full))).await.status(), StatusCode::OK);
    let reauth = text(send(&app, get("/account/reauth", Some(&full))).await).await;
    assert!(reauth.contains("authenticator app") && !reauth.contains(r#"name="password""#), "step-up takes the code");

    // A recovery code finishes another sign-in and lands on the security page.
    let r = send(&app, post("/account/login", &body, None)).await;
    let pending = set_cookie(&r, "__Host-acct").unwrap();
    let pt = field(&text(send(&app, get("/account/mfa", Some(&pending))).await).await, "csrf");
    let r = send(&app, post("/account/mfa", &format!("csrf={pt}&_action=recovery&code={first_code}"), Some(&pending))).await;
    assert!(location(&r).starts_with("/account/security?ok=Signed+in+with+a+recovery+code.+9+left"), "{}", location(&r));

    // That sign-in is not recent; another code steps it up (FAC-2).
    let rec = set_cookie(&r, "__Host-acct").unwrap();
    assert!(text(send(&app, get("/account/security", Some(&rec))).await).await.contains("Changes here need a recent sign-in"));
    let page = text(send(&app, get("/account/reauth?next=%2Faccount%2Fsecurity", Some(&rec))).await).await;
    assert!(page.contains(r#"name="_action" value="recovery""#), "offered while codes are left");
    let body = format!("csrf={}&_action=recovery&next=%2Faccount%2Fsecurity&code={}", field(&page, "csrf"), code_at(2));
    let r = send(&app, post("/account/reauth", &body, Some(&rec))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/security"));
    let up = set_cookie(&r, "__Host-acct").unwrap();
    assert!(!text(send(&app, get("/account/security", Some(&up))).await).await.contains("Changes here need a recent sign-in"));
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn passkeys_are_added_and_used_through_the_json_endpoints() {
    let Some((app, a)) = shared(pk_cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let r = send(&app, post_json("/account/passkey/options/add", &serde_json::json!({}), Some(&c), None)).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "JSON with a session cookie needs X-CSRF");
    let r = send(&app, post_json("/account/passkey/options/add", &serde_json::json!({}), Some(&c), Some(&t))).await;
    assert_eq!(r.status(), StatusCode::OK);
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let o = json_of(r).await;
    let token = o["token"].as_str().unwrap().to_string();
    let ch = crate::challenge::challenge_bytes(&token);
    let mut auth = crate::testkit::Authenticator::new();
    let cred: serde_json::Value = serde_json::from_str(&auth.create(&ch, "https://l4f.cc", "l4f.cc")).unwrap();
    let both = format!("{c}; {nonce}");
    let r = send(&app, post_json("/account/passkey/add", &serde_json::json!({ "token": token, "credential": cred, "name": "Phone" }), Some(&both), Some(&t))).await;
    assert_eq!(r.status(), StatusCode::OK);
    let rotated = set_cookie(&r, "__Host-acct").expect("the first second factor gives this browser a new token");
    assert!(rotated != "__Host-acct=" && rotated != c);
    assert!(json_of(r).await["next"].as_str().unwrap().starts_with("/account/security?ok=Passkey+added"));
    assert_eq!(send(&app, get("/account/security", Some(&c))).await.status(), StatusCode::SEE_OTHER, "the old token is dead");
    let page = text(send(&app, get("/account/security", Some(&rotated))).await).await;
    assert!(page.contains("<td>Phone</td>"));
    let (c, t, _) = browser(&a, u.id, util::now()).await;

    // Signing in with it, no session yet: no CSRF token needed.
    let r = send(&app, post_json("/account/passkey/options/login", &serde_json::json!({}), None, None)).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let token = json_of(r).await["token"].as_str().unwrap().to_string();
    let get_json = auth.get(&crate::challenge::challenge_bytes(&token), "https://l4f.cc", "l4f.cc", Some(&u.id.0), true);
    let body = serde_json::json!({ "token": token, "credential": serde_json::from_str::<serde_json::Value>(&get_json).unwrap(), "next": "/account" });
    let r = send(&app, post_json("/account/passkey/login", &body, None, None)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "without the browser nonce cookie");
    let r = send(&app, post_json("/account/passkey/login", &body, Some(&nonce), None)).await;
    assert_eq!(r.status(), StatusCode::OK, "the refusal above did not spend the challenge");
    assert!(set_cookie(&r, "__Host-acct").is_some());
    assert_eq!(json_of(r).await["next"], "/account");
    let r = send(&app, post_json("/account/passkey/login", &body, Some(&nonce), None)).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "a replay is refused (here by the counter, before the burn)");

    let r = send(&app, post_json("/account/passkey/options/login", &serde_json::json!({}), None, None)).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let token = json_of(r).await["token"].as_str().unwrap().to_string();
    let get_json = auth.get(&crate::challenge::challenge_bytes(&token), "https://l4f.cc", "l4f.cc", Some(&u.id.0), true);
    let body = serde_json::json!({ "token": token, "credential": serde_json::from_str::<serde_json::Value>(&get_json).unwrap(), "next": "//evil" });
    let r = send(&app, post_json("/account/passkey/login", &body, Some(&nonce), None)).await;
    assert_eq!(json_of(r).await["next"], "/account", "next stays on this site");

    // Removing it, with a recent sign-in, from the security page's form.
    let id = util::b64u(&auth.id);
    let r = send(&app, post(&format!("/account/credentials/passkey/{id}/delete"), &format!("csrf={t}"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/security?ok=Passkey+removed."));
    assert!(!a.store.user_by_id(u.id).await.unwrap().unwrap().has_passkey);
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn the_passkey_script_is_served_and_privileged_accounts_are_told_about_2fa() {
    let Some((app, a)) = shared(Config { require_2fa_for_privileged: true, ..pk_cfg() }).await else { return };
    let r = send(&app, get("/account/assets/passkey.js", None)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
    assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
    assert!(text(r).await.contains("parseCreationOptionsFromJSON"));

    let admin_role = role_with(&a, &["users:read"]).await;
    let u = make_user(&a).await;
    give(&a, u.id, &admin_role).await;
    let (c, _, _) = browser(&a, u.id, util::now()).await;
    let page = text(send(&app, get("/account", Some(&c))).await).await;
    assert!(page.contains("work only with two-factor sign-in"));
    assert_eq!(send(&app, get("/account/admin/users", Some(&c))).await.status(), StatusCode::FORBIDDEN, "held, not granted");
    drop_user(&a, u.id).await;
    drop_role(&a, &admin_role).await;
}

// ---- key sign-in

fn token_on(page: &str) -> String {
    field(page, "token")
}

#[tokio::test]
async fn ssh_keys_are_added_and_sign_in_through_the_pages() {
    let Some((app, a)) = shared(pk_cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let key = crate::testkit::EdKey::new();
    let r = send(&app, get("/account/ssh", Some(&c))).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let page = text(r).await;
    assert!(page.contains("ssh-keygen -Y sign -n login@l4f.cc"));
    let token = token_on(&page);
    let sig = key.ssh_sign("login@l4f.cc", token.as_bytes());
    let body = format!(
        "csrf={t}&token={token}&key={}&signature={}",
        util::urlencode(&key.ssh_public("me@box")),
        util::urlencode(&sig)
    );
    let r = send(&app, post("/account/ssh", &body, Some(&format!("{c}; {nonce}")))).await;
    assert!(location(&r).starts_with("/account/security?ok=SSH+key+added."), "{}", location(&r));
    assert!(text(send(&app, get("/account/security", Some(&c))).await).await.contains("<td>me@box</td>"));

    let r = send(&app, get("/account/login/ssh?next=%2Faccount%2Fsecurity", None)).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let page = text(r).await;
    let token = token_on(&page);
    let sig = key.ssh_sign("login@l4f.cc", token.as_bytes());
    let body = format!("token={token}&next=%2Faccount%2Fsecurity&signature={}", util::urlencode(&sig));
    let r = send(&app, post("/account/login/ssh", &body, Some(&nonce))).await;
    assert_eq!((r.status(), location(&r)), (StatusCode::SEE_OTHER, "/account/security"));
    assert!(set_cookie(&r, "__Host-acct").is_some());
    let r = send(&app, post("/account/login/ssh", &body, Some(&nonce))).await;
    assert!(text(r).await.contains("That took too long"), "a replay gets a fresh page and an error");

    let id = util::b64u(&a.ssh_keys(u.id).await.unwrap()[0].ext_id);
    let r = send(&app, post(&format!("/account/credentials/ssh/{id}/delete"), &format!("csrf={t}"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/security?ok=SSH+key+removed."));
    let r = send(&app, post(&format!("/account/credentials/nonsense/{id}/delete"), &format!("csrf={t}"), Some(&c))).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    drop_user(&a, u.id).await;
}

#[tokio::test]
async fn a_remembered_browser_signs_in_through_the_json_endpoints() {
    let Some((app, a)) = shared(pk_cfg()).await else { return };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let key = crate::testkit::EdKey::new();
    let device = util::random::<16>();
    let r = send(&app, post_json("/account/devkey/options/add", &serde_json::json!({}), Some(&c), Some(&t))).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let token = json_of(r).await["token"].as_str().unwrap().to_string();
    let sig = key.devkey_sign("https://l4f.cc", &device, &crate::challenge::challenge_bytes(&token));
    let body = serde_json::json!({ "token": token, "device_id": util::b64u(&device), "public_key": util::b64u(&key.raw_public()), "signature": util::b64u(&sig) });
    let r = send(&app, post_json("/account/devkey/add", &body, Some(&format!("{c}; {nonce}")), Some(&t))).await;
    assert_eq!(r.status(), StatusCode::OK);

    let r = send(&app, post_json("/account/devkey/options/login", &serde_json::json!({}), None, None)).await;
    let nonce = set_cookie(&r, "__Host-acct-ch").unwrap();
    let token = json_of(r).await["token"].as_str().unwrap().to_string();
    let sig = key.devkey_sign("https://l4f.cc", &device, &crate::challenge::challenge_bytes(&token));
    let body = serde_json::json!({ "token": token, "device_id": util::b64u(&device), "signature": util::b64u(&sig), "next": "/account" });
    let r = send(&app, post_json("/account/devkey/login", &body, Some(&nonce), None)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let full = set_cookie(&r, "__Host-acct").unwrap();
    let page = text(send(&app, get("/account/security", Some(&full))).await).await;
    assert!(page.contains("Confirm it's you"), "a remembered browser is never a recent sign-in");

    let r = send(&app, get("/account/assets/devkey.js", None)).await;
    assert_eq!(r.headers()[header::CACHE_CONTROL], "no-cache");
    assert!(text(r).await.contains("l4f-devkey-v1"));
    drop_user(&a, u.id).await;
}

// ---- password and mail

#[tokio::test]
async fn the_password_page_needs_a_recent_sign_in_and_changes_it() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let (stale, _, _) = browser(&a, u.id, util::now() - 3600).await;
    assert_eq!(location(&send(&app, get("/account/password", Some(&stale))).await), "/account/reauth?next=%2Faccount%2Fpassword");
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    assert_eq!(send(&app, get("/account/password", Some(&c))).await.status(), StatusCode::OK);
    let r = send(&app, post("/account/password", &format!("csrf={t}&password=short"), Some(&c))).await;
    assert!(text(r).await.contains("That password is too short."), "the policy, on the page");
    let r = send(&app, post("/account/password", &format!("csrf={t}&password=a+much+better+password"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/security?ok=Password+changed."));
    assert_eq!(send(&app, get("/account", Some(&stale))).await.status(), StatusCode::SEE_OTHER, "the other session went");
    assert_eq!(send(&app, get("/account", Some(&c))).await.status(), StatusCode::OK, "this one stays");
    drop_user(&a, u.id).await;
}

#[cfg(feature = "email")]
#[tokio::test]
async fn confirm_and_reset_links_work_through_their_pages() {
    let Some(store) = crate::store::tests::shared().await else { return };
    let (m, sent) = crate::email::Mailer::capture();
    let keys = Keys::new(&[9; 32], None).unwrap();
    let host = T { cfg: Arc::new(pk_cfg()) };
    let a = Arc::new(Accounts::new(store, keys, Arc::default(), host, &[], Some(POW.to_vec()), Vec::new()).unwrap().with_mailer(m));
    let app = Router::new().nest(BASE, router(a.clone()));
    let link_token = |n: usize| {
        let sent = sent.clone();
        async move {
            for _ in 0..100 {
                if let Some(m) = sent.lock().unwrap().get(n) {
                    return m.body.split("?t=").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("no mail {n}");
        }
    };
    let u = make_user(&a).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let addr = format!("{}@example.org", unique("w"));
    let r = send(&app, post("/account/email", &format!("csrf={t}&_action=set&email={addr}"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/security?ok=A+link"));
    let vt = link_token(0).await;
    let page = text(send(&app, get(&format!("/account/verify-email?t={vt}"), None)).await).await;
    assert!(page.contains(">Confirm</button>"), "opening the link changes nothing");
    assert!(a.store.user_by_id(u.id).await.unwrap().unwrap().email.is_none());
    let r = send(&app, post("/account/verify-email", &format!("t={vt}"), None)).await;
    assert!(location(&r).starts_with("/account?ok=Your+address+is+confirmed."));

    assert!(text(send(&app, get("/account/login", None)).await).await.contains("/account/forgot"));
    let r = send(&app, post("/account/forgot", &format!("who={}", u.username), None)).await;
    assert!(location(&r).starts_with("/account/login?ok=If+that+account"));
    let rt = link_token(1).await;
    assert!(text(send(&app, get(&format!("/account/reset?t={rt}"), None)).await).await.contains(r#"name="password""#));
    let r = send(&app, post("/account/reset", &format!("t={rt}&password=reset+by+link+now"), None)).await;
    assert!(location(&r).starts_with("/account/login?ok=Password+changed."));
    let r = send(&app, post("/account/reset", &format!("t={rt}&password=and+again+please"), None)).await;
    assert!(text(r).await.contains("not valid any more"));
    assert_eq!(send(&app, get("/account", Some(&c))).await.status(), StatusCode::SEE_OTHER, "signed out by the reset");
    drop_user(&a, u.id).await;
}

// ---- social sign-in

#[cfg(feature = "oauth")]
#[tokio::test]
async fn social_sign_in_runs_through_start_and_callback() {
    use crate::oauth::{Kind, Provider};
    use axum::routing::{get as aget, post as apost};
    let Some(store) = crate::store::tests::shared().await else { return };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let subject = unique("d");
    let sub = subject.clone();
    let fake = Router::new()
        .route("/d/token", apost(|| async { axum::Json(serde_json::json!({ "access_token": "at" })) }))
        .route("/d/profile", aget(move || {
            let s = sub.clone();
            async move { axum::Json(serde_json::json!({ "id": s, "username": "pat" })) }
        }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, fake).await.unwrap() });
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let oauth = crate::service::OAuth::new(http, vec![Provider::at(Kind::Discord, &format!("{base}/d"))]);
    let host = T { cfg: Arc::new(pk_cfg()) };
    let a = Arc::new(
        Accounts::new(store, Keys::new(&[9; 32], None).unwrap(), Arc::default(), host, &[], Some(POW.to_vec()), Vec::new())
            .unwrap()
            .with_oauth(oauth),
    );
    let app = Router::new().nest(BASE, router(a.clone()));

    let u = make_user(&a).await;
    let (c, _, _) = browser(&a, u.id, util::now()).await;
    let r = send(&app, get("/account/oauth/discord?intent=link", Some(&c))).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(location(&r).starts_with(&format!("{base}/d/authorize?")));
    let flow = set_cookie(&r, "__Host-acct-oauth").unwrap();
    let state = location(&r).split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let both = format!("{c}; {flow}");
    let r = send(&app, get(&format!("/account/oauth/discord/cb?state={state}&error=access_denied"), Some(&both))).await;
    assert!(location(&r).starts_with("/account/security?err=Signing+in+there+was+cancelled."));
    assert_eq!(set_cookie(&r, "__Host-acct-oauth").as_deref(), Some("__Host-acct-oauth="), "the flow cookie goes every time");
    let r = send(&app, get(&format!("/account/oauth/discord/cb?state={state}&code=abc"), Some(&both))).await;
    assert!(location(&r).starts_with("/account/security?ok=Linked."), "{}", location(&r));

    // Now it signs in, and the login page offers it.
    assert!(text(send(&app, get("/account/login", None)).await).await.contains("/account/oauth/discord"));
    let r = send(&app, get("/account/oauth/discord?next=%2Faccount%2Fsecurity", None)).await;
    let flow = set_cookie(&r, "__Host-acct-oauth").unwrap();
    let state = location(&r).split("state=").nth(1).unwrap().split('&').next().unwrap().to_string();
    let r = send(&app, get(&format!("/account/oauth/discord/cb?state={state}&code=abc"), Some(&flow))).await;
    assert_eq!(location(&r), "/account/security");
    assert!(set_cookie(&r, "__Host-acct").is_some());
    let r = send(&app, get(&format!("/account/oauth/discord/cb?state={state}&code=abc"), None)).await;
    assert!(location(&r).starts_with("/account/login?err="), "without the flow cookie: refused");

    // An account with nothing but the identity confirms it there.
    crate::store::tests::exec(&a.store, "UPDATE acct_users SET password_hash = NULL WHERE id = ?", vec![crate::store::tests::Arg::B(u.id.0.to_vec())]).await;
    let page = text(send(&app, get("/account/reauth?next=%2Faccount%2Fdelete", Some(&c))).await).await;
    assert!(page.contains("/account/oauth/discord?intent=reauth") && !page.contains(r#"name="password""#));
    drop_user(&a, u.id).await;
}

// ---- storage

fn put_raw(uri: &str, body: Vec<u8>, ctype: &str, cookie: &str, csrf: Option<&str>, version: i64) -> Request<Body> {
    let mut b = Request::put(uri)
        .header(header::CONTENT_TYPE, ctype)
        .header(header::COOKIE, cookie)
        .header(header::IF_MATCH, version.to_string())
        .header("sec-fetch-site", "same-origin");
    if let Some(t) = csrf {
        b = b.header("x-csrf", t);
    }
    b.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn sync_api_is_compare_and_set_behind_the_switch() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let role = role_with(&a, &["storage:sync", "vault:use"]).await;
    give(&a, u.id, &role).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    assert_eq!(send(&app, get("/account/api/kv", None)).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, get("/account/api/kv", Some(&c))).await.status(), StatusCode::CONFLICT, "sync is off");
    let r = send(&app, post("/account/sync", &format!("csrf={t}&_action=on"), Some(&c))).await;
    let hint = r.headers().get_all(header::SET_COOKIE).iter().map(|v| v.to_str().unwrap().to_string()).find(|c| c.starts_with("__Host-acct-sync=1")).unwrap();
    assert!(!hint.contains("HttpOnly"), "the script reads it");
    let j = json_of(send(&app, get("/account/api/kv", Some(&c))).await).await;
    assert_eq!((j["csrf"].as_str(), j["items"].as_array().map(Vec::len)), (Some(t.as_str()), Some(0)));
    assert_eq!((j["account"].as_str(), j["epoch"].as_str().map(str::len)), (Some(u.id.hex().as_str()), Some(22)), "the copy's epoch");
    for bad in ["", "&_action=Off", "&_action=nonsense"] {
        let r = send(&app, post("/account/sync", &format!("csrf={t}{bad}"), Some(&c))).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad:?} must not turn sync off");
    }
    assert!(a.store.user_by_id(u.id).await.unwrap().unwrap().sync_enabled);
    let body = br#"[{"short":"https://l4f.cc/abc"}]"#.to_vec();
    assert_eq!(send(&app, put_raw("/account/api/kv/links:v1", body.clone(), "application/json", &c, None, 0)).await.status(), StatusCode::FORBIDDEN, "X-CSRF");
    let r = send(&app, put_raw("/account/api/kv/links:v1", body.clone(), "application/json", &c, Some(&t), 0)).await;
    assert_eq!((r.status(), json_of(r).await["version"].as_i64()), (StatusCode::OK, Some(1)));
    let r = send(&app, put_raw("/account/api/kv/links:v1", b"[]".to_vec(), "application/json", &c, Some(&t), 0)).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let j = json_of(r).await;
    assert_eq!((j["version"].as_i64(), j["v"][0]["short"].as_str()), (Some(1), Some("https://l4f.cc/abc")), "what is there now");
    let mut del = Request::delete("/account/api/kv/links:v1").header(header::COOKIE, &c).header("x-csrf", &t).header(header::IF_MATCH, "1");
    del = del.header("sec-fetch-site", "same-origin");
    assert_eq!(send(&app, del.body(Body::empty()).unwrap()).await.status(), StatusCode::NO_CONTENT);
    // Off keeps the hint; the next pull is a 409 that clears it, so the
    // script keeps this browser's values instead of cleaning up (ADMIN-2).
    let r = send(&app, post("/account/sync", &format!("csrf={t}&_action=off"), Some(&c))).await;
    assert!(location(&r).starts_with("/account?ok=Sync+is+off"));
    assert_eq!(set_cookie(&r, "__Host-acct-sync"), None, "the hint stays");
    let r = send(&app, get("/account/api/kv", Some(&c))).await;
    assert_eq!((r.status(), set_cookie(&r, "__Host-acct-sync").as_deref()), (StatusCode::CONFLICT, Some("__Host-acct-sync=")));
    assert_eq!(json_of(r).await["error"], "Sync is off.");
    drop_user(&a, u.id).await;
    drop_role(&a, &role).await;
}

#[tokio::test]
async fn the_vault_api_takes_up_to_72_kib_of_ciphertext_per_item() {
    let Some((app, a)) = shared(cfg()).await else { return };
    let u = make_user(&a).await;
    let role = role_with(&a, &["vault:use"]).await;
    give(&a, u.id, &role).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let j = json_of(send(&app, get("/account/api/vault", Some(&c))).await).await;
    assert_eq!(j["account"].as_str(), Some(u.id.hex().as_str()), "the AAD needs it");
    let k = format!("note.{}", util::b64u(&util::random::<16>()));
    let mut item = vec![1u8];
    item.extend(vec![7u8; 70 * 1024]);
    let r = send(&app, put_raw(&format!("/account/api/vault/items/{k}"), item, "application/octet-stream", &c, Some(&t), 0)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = send(&app, put_raw(&format!("/account/api/vault/items/{k}"), vec![1u8; 100 * 1024], "application/octet-stream", &c, Some(&t), 1)).await;
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let page = text(send(&app, get("/account/vault", Some(&c))).await).await;
    assert!(page.contains(r#"id="vault""#) && page.contains(r#"type="module" src="/account/assets/vault.js""#));
    assert!(text(send(&app, get("/account/assets/vault.js", None)).await).await.contains("l4f-vault-item/v1"));
    assert!(text(send(&app, get("/account/assets/sync.js", None)).await).await.contains("export function attach"));
    let r = send(&app, post("/account/vault/wipe", &format!("csrf={t}"), Some(&c))).await;
    assert!(location(&r).starts_with("/account?ok=The+vault+is+empty."));
    drop_user(&a, u.id).await;
    drop_role(&a, &role).await;
}

// ---- profile

#[tokio::test]
async fn the_public_profile_is_private_noindex_and_its_avatar_sandboxed() {
    let Some((_, a)) = shared(cfg()).await else { return };
    let app = Router::new().nest(BASE, router(a.clone())).nest("/profile", profile_router(a.clone()));
    let role = role_with(&a, &["profile:public"]).await;
    let u = make_user(&a).await;
    give(&a, u.id, &role).await;
    let (c, t, _) = browser(&a, u.id, util::now()).await;
    let page = text(send(&app, get("/account/profile", Some(&c))).await).await;
    assert!(page.contains("Your profile is off."));
    let r = send(&app, post("/account/profile", &format!("csrf={t}&_action=save&on=1&bio=Hi+there&show_badges=1"), Some(&c))).await;
    assert!(location(&r).starts_with("/account/profile?ok=Profile+saved."));
    let id = crate::service::uuid_of(&a.store.profile(u.id).await.unwrap().public_id.unwrap());
    let r = send(&app, get(&format!("/profile/{id}"), None)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!((r.headers()["x-robots-tag"].to_str().unwrap(), r.headers()[header::CACHE_CONTROL].to_str().unwrap()), ("noindex, nofollow", "private, no-store"));
    assert!(text(r).await.contains("Hi there"));
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend([0u8; 32]);
    let r = send(&app, put_raw("/account/api/avatar", png, "image/png", &c, Some(&t), 0)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = send(&app, get(&format!("/profile/{id}/avatar"), None)).await;
    assert_eq!(r.headers()[header::CONTENT_TYPE], "image/png");
    assert_eq!(r.headers()[header::CONTENT_SECURITY_POLICY], "default-src 'none'; sandbox");
    assert_eq!(r.headers()["cross-origin-resource-policy"], "same-origin");
    assert_eq!(send(&app, get("/profile/00000000-0000-4000-8000-000000000000", None)).await.status(), StatusCode::NOT_FOUND);
    assert_eq!(send(&app, get("/profile/garbage/avatar", None)).await.status(), StatusCode::NOT_FOUND);
    drop_user(&a, u.id).await;
    drop_role(&a, &role).await;
}
