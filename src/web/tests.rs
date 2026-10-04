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

    async fn delete_user(&self, _: &mut sqlx::MySqlConnection, _: AccountId, _: bool) -> sqlx::Result<()> {
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
    Store(MySqlPoolOptions::new().acquire_timeout(Duration::from_millis(200)).connect_lazy("mysql://x:x@127.0.0.1:9/x").unwrap())
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
    Store::delete_user(&mut a.store.0.acquire().await.unwrap(), id).await.unwrap();
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
    assert_eq!(send(&app, get(&target, Some(&c1))).await.status(), StatusCode::OK);
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
    let codes_page = text(r).await;
    assert!(codes_page.contains("Your recovery codes"));
    let first_code = codes_page.split("<li>").nth(1).unwrap().split('<').next().unwrap().to_string();

    // Signing in again stops at the second step.
    let body = format!("username={}&password={}&next=%2Faccount%2Fsecurity", u.username, util::urlencode(PW));
    let r = send(&app, post("/account/login", &body, None)).await;
    assert_eq!(location(&r), "/account/mfa?next=%2Faccount%2Fsecurity");
    let pending = set_cookie(&r, "__Host-acct").unwrap();
    assert!(set_cookie(&r, "__Host-acct-dev").is_none(), "not a known device before the second step");
    assert_eq!(send(&app, get("/account", Some(&pending))).await.status(), StatusCode::SEE_OTHER, "a pending session is nobody");
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
    assert!(json_of(r).await["next"].as_str().unwrap().starts_with("/account/security?ok=Passkey+added."));
    let page = text(send(&app, get("/account/security", Some(&c))).await).await;
    assert!(page.contains("<td>Phone</td>"));

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
    let r = send(&app, post(&format!("/account/passkey/{id}/delete"), &format!("csrf={t}"), Some(&c))).await;
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
