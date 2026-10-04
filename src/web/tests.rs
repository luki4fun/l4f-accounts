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
    let mut c = Config { login_per_15min: 100, login_per_15min_global: 1000, login_per_user_15min: 100, ..Config::default() };
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
