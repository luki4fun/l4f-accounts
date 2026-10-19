//! Service tests against the throwaway MariaDB (`L4F_TEST_DATABASE_URL`); they
//! pass vacuously without it. On the shared database every name is unique and
//! nothing grants `*`; tests about `*` or row counts get a database of their own.

use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use sha2::Digest;

use super::admin::role_name;
use super::storage::KV_MAX_BYTES;
use super::profile::uuid_of;
use super::auth::{WINDOW, clean_email, new_token, token_hash};
use super::*;
use crate::model::{Credential, SessionInfo, UserStatus};
use crate::store::tests::{Arg, delete, exec, exec_conn, fresh, scalar, shared as shared_store};

const APP: &[ScopeDef] = &[ScopeDef { name: "t:one", description: "test" }, ScopeDef { name: "t:two", description: "test" }];
const POW_KEY: &[u8] = b"service-test-pow-key-0123456789ab";
const PW: &str = "correct horse battery";

struct Stub {
    cfg: Arc<Config>,
    deleted: StdMutex<Vec<(AccountId, bool)>>,
}

impl Host for Stub {
    fn config(&self) -> Arc<Config> {
        self.cfg.clone()
    }

    async fn export(&self, user: AccountId) -> Vec<(String, serde_json::Value)> {
        vec![("links".into(), serde_json::json!([user.hex()]))]
    }

    async fn delete_user(&self, tx: StoreConn<'_>, user: AccountId, delete_owned: bool) -> sqlx::Result<()> {
        self.deleted.lock().unwrap().push((user, delete_owned));
        // A write in the caller's transaction, to see it go back with a refusal.
        exec_conn(tx, "UPDATE acct_users SET display_name = 'host was here' WHERE id = ?", vec![Arg::B(user.0.to_vec())]).await;
        Ok(())
    }
}

fn cfg() -> Config {
    let generous = pow::Limits {
        min_form_seconds: 0,
        max_attempts_per_ip_hour: 1000,
        max_attempts_per_hour: 1000,
        max_accounts_per_hour: 1000,
        max_accounts_per_ip_day: 1000,
        ..pow::Limits::default()
    };
    Config {
        registration_open: true,
        signup: generous,
        login_per_15min: 100,
        login_per_15min_global: 1000,
        login_per_user_15min: 100,
        // Tests about the 2FA rule turn it on; the rest test one thing at a time.
        require_2fa_for_privileged: false,
        ..Config::default()
    }
}

/// Own limiter per instance, so tests never spend each other's caps.
async fn on(store: Store, cfg: Config) -> Accounts<Stub> {
    on_keys(store, cfg, Keys::new(&[7; 32], None).unwrap()).await
}

async fn on_keys(store: Store, cfg: Config, keys: Keys) -> Accounts<Stub> {
    let host = Stub { cfg: Arc::new(cfg), deleted: StdMutex::default() };
    Accounts::build(store, keys, Arc::default(), host, APP, Some(POW_KEY.to_vec()), Vec::new()).await.unwrap()
}

async fn shared(cfg: Config) -> Option<Accounts<Stub>> {
    Some(on(shared_store().await?, cfg).await)
}

fn ctx(ip: &str) -> Ctx {
    Ctx { ip: ip.parse().unwrap(), ua: "test agent".into(), sec_fetch_site: "same-origin".into() }
}

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", hex::encode(util::random::<6>()))
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// One Argon2 hash shared by every account that only needs to sign in.
fn pw_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| password::hash(PW))
}

fn err<T>(r: Result<T, Error>) -> Error {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

fn signed_in(r: Result<LoginStep, Error>) -> NewSession {
    match r {
        Ok(LoginStep::Done(s)) => s,
        Ok(LoginStep::NeedMfa(_)) => panic!("expected a full sign-in, got NeedMfa"),
        Err(e) => panic!("expected a full sign-in, got {e:?}"),
    }
}

/// Brute-force the challenge the way the browser does.
fn solve(c: &pow::Challenge) -> String {
    for n in 0..=c.maxnumber as u64 {
        if hex::encode(sha2::Sha256::digest(format!("{}{}", c.salt, n).as_bytes())) == c.challenge {
            return serde_json::json!({
                "algorithm": c.algorithm, "challenge": c.challenge,
                "number": n, "salt": c.salt, "signature": c.signature
            })
            .to_string();
        }
    }
    panic!("unsolvable challenge");
}

async fn register_with(a: &Accounts<Stub>, c: &Ctx, name: &str, pw: &str, email: Option<&str>) -> Result<NewSession, Error> {
    let ts = pow::stamp(POW_KEY, util::now_secs() - 5);
    let altcha = solve(&pow::issue(POW_KEY, 1000, 600));
    let proof = pow::Proof { altcha: &altcha, ts: &ts, ..pow::Proof::default() };
    a.register(c, RegisterForm { username: name, password: pw, email, display_name: None, proof }).await
}

async fn register(a: &Accounts<Stub>, c: &Ctx, name: &str, pw: &str) -> Result<NewSession, Error> {
    register_with(a, c, name, pw, None).await
}

/// A full session of `u`: what an enrolment asks of its caller.
async fn full_session(a: &Accounts<Stub>, c: &Ctx, u: &User) -> SessionInfo {
    a.create_session(u.id, "password", true, util::now(), c).await.unwrap().info
}

async fn make_user(a: &Accounts<Stub>, roles: &[&str]) -> User {
    let u = NewUser {
        id: AccountId::new(),
        username: unique("u"),
        display_name: "T".into(),
        email_pending: None,
        password_hash: Some(pw_hash().into()),
        created_at: util::now(),
    };
    a.store.create_user(&u, None).await.unwrap();
    for r in roles {
        let role = a.store.role_by_name(r).await.unwrap().unwrap();
        a.store.grant_role(u.id, role.id, None).await.unwrap();
    }
    a.store.user_by_id(u.id).await.unwrap().unwrap()
}

/// No password, as after a social sign-up: nothing in the crate removes one.
async fn drop_password(a: &Accounts<Stub>, id: AccountId) {
    exec(&a.store, "UPDATE acct_users SET password_hash = NULL WHERE id = ?", vec![Arg::B(id.0.to_vec())]).await;
}

async fn make_role(a: &Accounts<Stub>, scopes: &[&str]) -> String {
    let name = unique("r");
    let id = a.store.create_role(&name, "", None).await.unwrap().unwrap();
    a.store.set_role_scopes(id, &strings(scopes)).await.unwrap();
    name
}

async fn cleanup(a: &Accounts<Stub>, users: &[AccountId], roles: &[&str]) {
    for u in users {
        delete(&a.store, *u).await.unwrap();
    }
    for r in roles {
        let role = a.store.role_by_name(r).await.unwrap().unwrap();
        a.store.delete_role(role.id).await.unwrap();
    }
}

fn sess(user: AccountId, seen: i64, expires: i64) -> SessionInfo {
    SessionInfo {
        token_hash: util::random(),
        user_id: user,
        created_at: seen,
        seen_at: seen,
        expires_at: expires,
        auth_at: 0,
        mfa_ok: true,
        method: "password".into(),
        ip: String::new(),
        ua: String::new(),
    }
}

async fn audit_events(a: &Accounts<Stub>, user: AccountId) -> Vec<String> {
    a.store.audit_of(user, 50).await.unwrap().into_iter().map(|e| e.event).collect()
}

/// Handlers run these on a multi-thread runtime; checked at compile time.
#[allow(dead_code)]
fn service_futures_are_send(a: &Accounts<Stub>, c: &Ctx, actor: Actor<'_>) {
    fn send<T: Send>(_: T) {}
    let form = RegisterForm { username: "", password: "", email: None, display_name: None, proof: pow::Proof::default() };
    send(a.register(c, form));
    send(a.login_password(c, "", "", None));
    send(a.session_from_token("", 0));
    send(a.rotate(""));
    send(a.logout(""));
    send(a.logout_all(c, actor.user.id, None));
    send(a.export(actor.user.id));
    send(a.delete_account(c, actor, actor.user.id, false));
    send(a.update_role(c, actor, RoleForm { name: "", description: "", badge: "", scopes: &[] }));
    send(a.grant_role(c, actor, actor.user.id, ""));
    send(a.set_user_status(c, actor, actor.user.id, UserStatus::Disabled));
    send(a.bootstrap_admin("", ""));
    send(a.sweep(0));
    send(a.confirm_password(c, actor.user, ""));
    send(a.set_display_name(c, actor.user.id, ""));
    send(a.sessions(actor.user.id, 0));
    send(a.revoke_session(c, actor.user.id, &[0; 32]));
}

#[allow(dead_code)]
fn step_up_is_send(a: &Accounts<Stub>, c: &Ctx, u: &User, s: &SessionInfo) {
    fn send<T: Send>(_: T) {}
    send(a.step_up(c, u, s, ""));
}

#[test]
fn defaults_keep_signup_closed_and_privileged_scopes_behind_2fa() {
    let c = Config::default();
    assert!(c.enabled && !c.registration_open && c.require_2fa_for_privileged);
    assert_eq!((c.min_password_len, c.session_idle_days, c.session_max_days, c.step_up_minutes), (10, 7, 30, 15));
    assert_eq!((c.login_per_15min, c.login_per_15min_global, c.login_per_user_15min), (10, 1000, 10));
    assert_eq!(c.audit_retention_days, 180);
    let parsed: Config = serde_json::from_str(r#"{"registration_open": true, "signup": {"max_accounts_per_ip_day": 1}}"#).unwrap();
    assert!(parsed.registration_open);
    assert_eq!(parsed.signup.max_accounts_per_ip_day, 1);
    assert_eq!(parsed.signup.max_attempts_per_hour, 60, "unset limits keep their defaults");
    assert_eq!(parsed.min_password_len, 10);
    for bad in [r#"{"ip_salt": [1, 2]}"#, r#"{"registraton_open": true}"#, r#"{"signup": {"max_acounts_per_hour": 1}}"#] {
        assert!(serde_json::from_str::<Config>(bad).is_err(), "{bad}: unknown keys, secrets included, are refused");
    }
}

/// What a browser sends as its origin: never a path or a trailing slash (FAC-14).
#[test]
fn origins_are_the_scheme_and_authority_of_base_url() {
    let bases = [
        ("https://l4f.cc", "https://l4f.cc"),
        ("https://l4f.cc/", "https://l4f.cc"),
        ("http://127.0.0.1:8080/app/?x#y", "http://127.0.0.1:8080"),
        ("voipc://00ff", "voipc://00ff"),
    ];
    for (base, want) in bases {
        assert_eq!(Config { base_url: base.into(), ..Config::default() }.origins(), [want], "{base}");
    }
    let listed = Config { base_url: "https://l4f.cc/".into(), webauthn_origins: vec!["https://a.example".into()], ..Config::default() };
    assert_eq!(listed.origins(), ["https://a.example"], "a configured list, as it is");
}

#[test]
fn only_issued_tokens_hash() {
    let (t, h) = new_token();
    assert_eq!(t.len(), 43);
    assert_eq!(token_hash(&t), Some(h));
    assert_ne!(new_token().1, h);
    for bad in [format!("{t}="), t[..42].to_string(), format!("{t}A"), "!".repeat(43), String::new()] {
        assert_eq!(token_hash(&bad), None, "{bad:?}");
    }
}

#[test]
fn email_and_role_name_rules() {
    assert_eq!(clean_email("  Dee@Example.COM "), Ok(Some("dee@example.com".into())));
    assert_eq!(clean_email("   "), Ok(None));
    let bad = ["dee", "@example.com", "dee@", "dee@example", "dee@.com", "dee@example.com.", "a@b@c.de", "d ee@x.com", "d@x\u{200b}y.com"];
    for b in bad {
        assert!(clean_email(b).is_err(), "{b:?}");
    }
    assert!(clean_email(&format!("{}@example.com", "a".repeat(250))).is_err());
    assert_eq!(role_name(" Mods "), Ok("mods".into()));
    for b in ["m", "_mods", "mo ds", "mods/x", &"m".repeat(33), "módś"] {
        assert!(role_name(b).is_err(), "{b:?}");
    }
}

#[tokio::test]
async fn register_then_sign_in_rotate_and_sign_out() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.10");
    let name = unique("u");
    let now = util::now();
    let s1 = register_with(&a, &c, &name.to_uppercase(), PW, Some("Dee@Example.com")).await.unwrap();
    let (user, info, _) = a.session_from_token(&s1.token, now).await.unwrap().expect("a fresh session");
    assert_eq!((user.username.as_str(), user.display_name.as_str()), (name.as_str(), name.as_str()), "lowercased; display name defaults");
    assert_eq!(user.email_pending.as_deref(), Some("dee@example.com"));
    assert_eq!(user.email, None, "unverified");
    assert!(info.mfa_ok && info.auth_at >= now && info.method == "password");
    assert_eq!((info.ip.as_str(), info.ua.as_str()), ("203.0.113.10", "test agent"));
    assert!(info.expires_at >= now + 30 * DAY);
    let roles: Vec<_> = a.store.user_roles(user.id).await.unwrap().into_iter().map(|r| r.name).collect();
    assert_eq!(roles, ["user"]);
    assert!(a.store.password_hash_of(user.id).await.unwrap().unwrap().starts_with("$argon2id$"));

    assert!(matches!(register(&a, &c, &name, PW).await, Err(Error::UsernameTaken)));
    assert!(matches!(register(&a, &c, "admin", PW).await, Err(Error::Invalid(_))), "reserved");
    assert!(matches!(register(&a, &c, &unique("u"), "short").await, Err(Error::Invalid(_))));
    assert!(matches!(register_with(&a, &c, &unique("u"), PW, Some("nope")).await, Err(Error::Invalid(_))));

    let s2 = signed_in(a.login_password(&c, &format!("  {}  ", name.to_uppercase()), PW, None).await);
    assert!(a.session_from_token(&s2.token, now).await.unwrap().is_some());
    let s3 = a.rotate(&s2.token).await.unwrap().expect("a live session rotates");
    assert!(a.session_from_token(&s2.token, now).await.unwrap().is_none(), "the old token is dead");
    let (_, rotated, _) = a.session_from_token(&s3.token, now).await.unwrap().unwrap();
    assert_eq!(rotated.created_at, s2.info.created_at, "same session, new token");
    assert!(a.rotate(&s2.token).await.unwrap().is_none());

    a.logout(&s3.token).await.unwrap();
    assert!(a.session_from_token(&s3.token, now).await.unwrap().is_none());
    a.logout("not a token").await.unwrap();
    assert!(a.session_from_token(&s1.token, now).await.unwrap().is_some(), "other sessions stay");
    // From the session's own times: `now` was taken before it existed, and
    // on a slow run the two are seconds apart.
    assert!(a.session_from_token(&s1.token, s1.info.seen_at + 7 * DAY).await.unwrap().is_none(), "idle for a week");
    assert!(a.session_from_token(&s1.token, s1.info.expires_at).await.unwrap().is_none(), "past the absolute limit");
    assert!(a.session_from_token("garbage", now).await.unwrap().is_none());

    assert_eq!(a.logout_all(&c, user.id, None).await.unwrap(), 1);
    assert!(a.session_from_token(&s1.token, now).await.unwrap().is_none());
    assert_eq!(audit_events(&a, user.id).await, ["logout_all", "login_ok", "register"]);
    cleanup(&a, &[user.id], &[]).await;
}

#[tokio::test]
async fn sign_up_is_closed_by_default_and_gated() {
    let Some(closed) = shared(Config { registration_open: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.11");
    assert!(matches!(register(&closed, &c, &unique("u"), PW).await, Err(Error::SignupClosed)));
    let Some(mut a) = shared(cfg()).await else { return };
    let cross = Ctx { sec_fetch_site: "same-site".into(), ..ctx("203.0.113.11") };
    assert_eq!(err(register(&a, &cross, &unique("u"), PW).await).outcome(), "cross_site", "the Ctx header wins over the form's");
    a.pow_key = None;
    assert!(matches!(register(&a, &c, &unique("u"), PW).await, Err(Error::SignupClosed)), "no PoW key, no sign-up");
}

#[tokio::test]
async fn wrong_password_unknown_and_disabled_accounts_look_alike() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.20");
    let u = make_user(&a, &[]).await;
    let off = make_user(&a, &[]).await;
    a.store.set_status(off.id, UserStatus::Disabled).await.unwrap();
    let nopw = NewUser {
        id: AccountId::new(),
        username: unique("u"),
        display_name: String::new(),
        email_pending: None,
        password_hash: None,
        created_at: util::now(),
    };
    a.store.create_user(&nopw, None).await.unwrap();
    let nobody = unique("nobody");
    let tries = [
        (u.username.as_str(), "wrong password!"),
        (nobody.as_str(), PW),
        (off.username.as_str(), PW),
        (nopw.username.as_str(), PW),
        ("x", PW),
    ];
    for (name, pw) in tries {
        let e = err(a.login_password(&c, name, pw, None).await);
        assert!(matches!(e, Error::BadLogin), "{name}: {e:?}");
        assert_eq!(e.message(), "Wrong username or password.");
    }
    // Each one reaches Argon2: with both slots taken, each is Busy instead of
    // being answered before the hash.
    let hold = a.hash_permits.clone().try_acquire_many_owned(2).unwrap();
    for (name, pw) in tries {
        assert!(matches!(a.login_password(&c, name, pw, None).await, Err(Error::Busy)), "{name}");
    }
    drop(hold);

    // Failures are audited for real accounts only, off the response path.
    let fail = "login_fail".to_string();
    let mut logged = false;
    for _ in 0..50 {
        if audit_events(&a, u.id).await.contains(&fail) && audit_events(&a, off.id).await.contains(&fail) {
            logged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(logged, "login_fail audited for the real and the disabled account");

    // A disabled account gets no new session, and one that survived the
    // disable stops working.
    assert!(matches!(a.create_session(off.id, "password", true, 1, &c).await, Err(sqlx::Error::RowNotFound)));
    a.store.set_status(off.id, UserStatus::Active).await.unwrap();
    let s = a.create_session(off.id, "password", true, 1, &c).await.unwrap();
    a.store.set_status(off.id, UserStatus::Disabled).await.unwrap();
    assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none());
    cleanup(&a, &[u.id, off.id, nopw.id], &[]).await;
}

#[tokio::test]
async fn login_caps_per_address_per_account_and_known_device() {
    let Some(a) = shared(Config { login_per_15min: 2, login_per_user_15min: 3, ..cfg() }).await else { return };
    let u = make_user(&a, &[]).await;
    let login = |ip: &'static str, pw: &'static str, dev: Option<AccountId>| {
        let a = &a;
        let name = u.username.clone();
        async move { a.login_password(&ctx(ip), &name, pw, dev).await }
    };
    assert!(matches!(login("198.51.100.1", "wrong password", None).await, Err(Error::BadLogin)));
    assert!(matches!(login("198.51.100.1", "wrong password", None).await, Err(Error::BadLogin)));
    assert!(matches!(login("198.51.100.1", PW, None).await, Err(Error::RateLimited)), "per address");
    assert!(matches!(login("198.51.100.2", "wrong password", None).await, Err(Error::BadLogin)));
    assert!(matches!(login("198.51.100.3", PW, None).await, Err(Error::RateLimited)), "per account, any address");
    signed_in(login("198.51.100.1", PW, Some(u.id)).await);
    assert!(
        matches!(login("198.51.100.4", PW, Some(AccountId::new())).await, Err(Error::RateLimited)),
        "another account's device cookie is no pass"
    );
    // Unknown names are capped the same way, so the cap does not tell them apart.
    let nobody = unique("nobody");
    for (i, ip) in ["198.51.100.5", "198.51.100.5", "198.51.100.6"].iter().enumerate() {
        assert!(matches!(a.login_password(&ctx(ip), &nobody, PW, None).await, Err(Error::BadLogin)), "try {i}");
    }
    assert!(matches!(a.login_password(&ctx("198.51.100.7"), &nobody, PW, None).await, Err(Error::RateLimited)));

    let Some(g) = shared(Config { login_per_15min_global: 1, ..cfg() }).await else { return };
    assert!(matches!(g.login_password(&ctx("198.51.100.8"), &u.username, "wrong password", None).await, Err(Error::BadLogin)));
    let site_wide = g.login_password(&ctx("198.51.100.9"), &u.username, PW, None).await;
    assert!(matches!(site_wide, Err(Error::RateLimited)), "site-wide");
    signed_in(g.login_password(&ctx("198.51.100.9"), &u.username, PW, Some(u.id)).await);
    for site in ["cross-site", "same-site"] {
        let c = Ctx { sec_fetch_site: site.into(), ..ctx("198.51.100.10") };
        assert!(matches!(g.login_password(&c, &u.username, PW, Some(u.id)).await, Err(Error::CrossSite)));
    }

    let Some(off) = shared(Config { enabled: false, ..cfg() }).await else { return };
    assert!(matches!(off.login_password(&ctx("198.51.100.11"), &u.username, PW, None).await, Err(Error::Closed)));
    cleanup(&a, &[u.id], &[]).await;
}

#[cfg(feature = "legacy-bcrypt")]
#[tokio::test]
async fn a_bcrypt_hash_becomes_argon2_at_the_first_login() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.30");
    let u = make_user(&a, &[]).await;
    let bc = bcrypt::hash(PW, 4).unwrap();
    assert!(a.store.rehash_password(u.id, pw_hash(), &bc).await.unwrap());
    assert!(matches!(a.login_password(&c, &u.username, "wrong password", None).await, Err(Error::BadLogin)));
    assert_eq!(a.store.password_hash_of(u.id).await.unwrap().as_deref(), Some(bc.as_str()), "no rehash on failure");
    signed_in(a.login_password(&c, &u.username, PW, None).await);
    let now = a.store.password_hash_of(u.id).await.unwrap().unwrap();
    assert!(now.starts_with("$argon2id$"), "{now}");
    signed_in(a.login_password(&c, &u.username, PW, None).await);
    assert_eq!(a.store.password_hash_of(u.id).await.unwrap().unwrap(), now, "a current hash stays");
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn role_admin_needs_cover_and_known_scopes() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.40");
    let boss_role = make_role(&a, &["roles:admin", "users:admin", "users:read", "t:one"]).await;
    let boss = make_user(&a, &[&boss_role]).await;
    let scopes = a.effective_scopes(&boss).await.unwrap();
    let actor = Actor { user: &boss, scopes: &scopes };
    let new = unique("r");
    for (scopes, want) in [
        (&["t:two"][..], "forbidden"),
        (&["t:*"], "forbidden"),
        (&["*"], "forbidden"),
        (&["t:nope"], "invalid"),
        (&["zz:*"], "invalid"),
        (&["T:one"], "invalid"),
    ] {
        let s = strings(scopes);
        let e = err(a.create_role(&c, actor, RoleForm { name: &new, description: "", badge: "", scopes: &s }).await);
        assert_eq!(e.outcome(), want, "{scopes:?}");
    }
    let one = strings(&["t:one", " t:one ", ""]);
    a.create_role(&c, actor, RoleForm { name: &new.to_uppercase(), description: "Mods", badge: "Mod", scopes: &one }).await.unwrap();
    let r = a.store.role_by_name(&new).await.unwrap().unwrap();
    assert_eq!((r.scopes.clone(), r.description.as_str(), r.badge.as_deref()), (strings(&["t:one"]), "Mods", Some("Mod")));
    let again = a.create_role(&c, actor, RoleForm { name: &new, description: "", badge: "", scopes: &one }).await;
    assert!(matches!(again, Err(Error::RoleTaken)));
    let bad_badge = a.create_role(&c, actor, RoleForm { name: &unique("r"), description: "", badge: "a\u{202e}b", scopes: &one }).await;
    assert!(matches!(bad_badge, Err(Error::Invalid(_))));
    let bad_name = a.create_role(&c, actor, RoleForm { name: "Bad Name", description: "", badge: "", scopes: &one }).await;
    assert!(matches!(bad_name, Err(Error::Invalid(_))));

    let target = make_user(&a, &[]).await;
    assert!(a.grant_role(&c, actor, target.id, &new).await.unwrap());
    assert!(!a.grant_role(&c, actor, target.id, &new).await.unwrap(), "already held");
    assert!(matches!(a.grant_role(&c, actor, AccountId::new(), &new).await, Err(Error::NotFound)));
    assert!(matches!(a.grant_role(&c, actor, target.id, "no-such-role").await, Err(Error::NotFound)));
    let two = make_role(&a, &["t:two"]).await;
    assert!(matches!(a.grant_role(&c, actor, target.id, &two).await, Err(Error::Forbidden)));
    a.store.grant_role(target.id, a.store.role_by_name(&two).await.unwrap().unwrap().id, None).await.unwrap();
    assert!(matches!(a.revoke_role(&c, actor, target.id, &two).await, Err(Error::Forbidden)), "taking away needs it too");
    let to_one = RoleForm { name: &two, description: "", badge: "", scopes: &one };
    assert!(matches!(a.update_role(&c, actor, to_one).await, Err(Error::Forbidden)), "the old set must be covered too");
    assert!(matches!(a.delete_role(&c, actor, &two).await, Err(Error::Forbidden)));
    // Someone holding more than the actor cannot be suspended or deleted by them.
    assert!(matches!(a.set_user_status(&c, actor, target.id, UserStatus::Disabled).await, Err(Error::Forbidden)));
    assert!(matches!(a.delete_account(&c, actor, target.id, false).await, Err(Error::Forbidden)));

    let none: Vec<String> = Vec::new();
    a.update_role(&c, actor, RoleForm { name: &new, description: "Now empty", badge: "", scopes: &none }).await.unwrap();
    let r = a.store.role_by_name(&new).await.unwrap().unwrap();
    assert_eq!((r.scopes.len(), r.description.as_str(), r.badge), (0, "Now empty", None));
    assert!(a.roles(actor).await.unwrap().iter().any(|r| r.name == new));
    assert_eq!(a.user_detail(actor, target.id).await.unwrap().roles.len(), 2);

    // Without the admin scopes nothing passes.
    let plain_scopes = strings(&["t:one", "t:two"]);
    let plain = Actor { user: &target, scopes: &plain_scopes };
    let f = RoleForm { name: &unique("r"), description: "", badge: "", scopes: &one };
    assert!(matches!(a.create_role(&c, plain, f).await, Err(Error::Forbidden)));
    assert!(matches!(a.grant_role(&c, plain, boss.id, &new).await, Err(Error::Forbidden)));
    assert!(matches!(a.roles(plain).await, Err(Error::Forbidden)));
    assert!(matches!(a.list_users(plain, None, 10, 0).await, Err(Error::Forbidden)));
    assert!(matches!(a.user_detail(plain, boss.id).await, Err(Error::Forbidden)));
    assert!(matches!(a.delete_account(&c, plain, boss.id, false).await, Err(Error::Forbidden)));

    a.delete_role(&c, actor, &new).await.unwrap();
    assert!(a.store.role_by_name(&new).await.unwrap().is_none());
    assert!(matches!(a.delete_role(&c, actor, &new).await, Err(Error::NotFound)));
    cleanup(&a, &[boss.id, target.id], &[&boss_role, &two]).await;
}

/// A role the actor covers still changes only on an account the actor
/// covers: a moderator cannot sign a stronger admin out over and over by
/// taking a role away and handing it back (ADMIN-5). The host's shell can.
#[tokio::test]
async fn roles_change_only_on_accounts_the_actor_covers() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.41");
    let mod_role = make_role(&a, &["users:admin", "t:one"]).await;
    let one = make_role(&a, &["t:one"]).await;
    let more = make_role(&a, &["t:two"]).await;
    let moderator = make_user(&a, &[&mod_role]).await;
    let scopes = a.effective_scopes(&moderator).await.unwrap();
    let actor = Actor { user: &moderator, scopes: &scopes };
    let owner = make_user(&a, &[&one, &more]).await;
    a.store.insert_session(&sess(owner.id, util::now(), util::now() + 100)).await.unwrap();
    assert!(matches!(a.revoke_role(&c, actor, owner.id, &one).await, Err(Error::Forbidden)));
    assert_eq!(a.store.sessions_of(owner.id).await.unwrap().len(), 1, "nobody signed out");
    assert!(a.revoke_role_as_host(&c, owner.id, &one).await.unwrap());
    assert!(matches!(a.grant_role(&c, actor, owner.id, &one).await, Err(Error::Forbidden)));
    assert!(a.grant_role_as_host(&c, owner.id, &one).await.unwrap());
    let peer = make_user(&a, &[&one]).await;
    assert!(a.revoke_role(&c, actor, peer.id, &one).await.unwrap(), "an account it covers");
    cleanup(&a, &[moderator.id, owner.id, peer.id], &[&mod_role, &one, &more]).await;
}

#[tokio::test]
async fn revoke_and_disable_end_the_targets_sessions() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.50");
    let mod_role = make_role(&a, &["users:admin", "users:read", "t:one"]).await;
    let one = make_role(&a, &["t:one"]).await;
    let boss = make_user(&a, &[&mod_role]).await;
    let scopes = a.effective_scopes(&boss).await.unwrap();
    let actor = Actor { user: &boss, scopes: &scopes };
    let target = make_user(&a, &[&one]).await;
    let now = util::now();

    let s = signed_in(a.login_password(&c, &target.username, PW, None).await);
    assert_eq!(a.session_from_token(&s.token, now).await.unwrap().unwrap().2, ["t:one"]);
    assert!(a.revoke_role(&c, actor, target.id, &one).await.unwrap());
    assert!(a.session_from_token(&s.token, now).await.unwrap().is_none(), "revoke ends the sessions");
    assert!(!a.revoke_role(&c, actor, target.id, &one).await.unwrap(), "not held any more");

    let s = signed_in(a.login_password(&c, &target.username, PW, None).await);
    assert!(a.grant_role(&c, actor, target.id, &one).await.unwrap());
    assert_eq!(a.session_from_token(&s.token, now).await.unwrap().unwrap().2, ["t:one"], "a grant applies live, sessions stay");

    assert!(a.set_user_status(&c, actor, target.id, UserStatus::Disabled).await.unwrap());
    assert!(a.session_from_token(&s.token, now).await.unwrap().is_none(), "disable ends the sessions");
    assert!(!a.set_user_status(&c, actor, target.id, UserStatus::Disabled).await.unwrap());
    assert!(matches!(a.login_password(&c, &target.username, PW, None).await, Err(Error::BadLogin)));
    assert!(a.set_user_status(&c, actor, target.id, UserStatus::Active).await.unwrap());
    signed_in(a.login_password(&c, &target.username, PW, None).await);

    let detail = a.user_detail(actor, target.id).await.unwrap();
    let events: Vec<_> = detail.audit.iter().map(|e| e.event.as_str()).collect();
    for want in ["role_revoke", "role_grant", "disable", "enable"] {
        assert!(events.contains(&want), "{want} in {events:?}");
    }
    let (found, total) = a.list_users(actor, Some(&target.username), 500, 0).await.unwrap();
    assert_eq!((found.len(), total), (1, 1));
    cleanup(&a, &[boss.id, target.id], &[&mod_role, &one]).await;
}

#[tokio::test]
async fn privileged_scopes_wait_for_a_second_factor() {
    let narrow = Config { require_2fa_for_privileged: true, default_user_scopes: strings(&["t:one"]), ..cfg() };
    let Some(a) = shared(narrow).await else { return };
    let c = ctx("203.0.113.60");
    let role = make_role(&a, &["t:one", "t:two", "users:read"]).await;
    let u = make_user(&a, &[&role]).await;
    assert_eq!(a.effective_scopes(&u).await.unwrap(), ["t:one"]);
    let wide = Config { require_2fa_for_privileged: true, default_user_scopes: strings(&["t:*"]), ..cfg() };
    let Some(w) = shared(wide).await else { return };
    assert_eq!(w.effective_scopes(&u).await.unwrap(), ["t:one", "t:two"], "a default wildcard covers its scopes");
    // What Phase 2's TOTP enrolment writes.
    exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(u.id.0.to_vec())]).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert_eq!(a.effective_scopes(&u).await.unwrap(), ["t:one", "t:two", "users:read"]);

    let Ok(LoginStep::NeedMfa(s)) = a.login_password(&c, &u.username, PW, None).await else {
        panic!("a password alone only half signs in once 2FA is enrolled");
    };
    assert!(!s.info.mfa_ok && s.info.auth_at == 0 && s.info.expires_at <= util::now() + 600);
    let (_, info, scopes) = a.session_from_token(&s.token, util::now()).await.unwrap().unwrap();
    assert!(!info.mfa_ok && scopes.is_empty(), "a half session grants nothing");
    assert!(audit_events(&a, u.id).await.contains(&"login_need_mfa".to_string()));
    cleanup(&a, &[u.id], &[&role]).await;
}

#[tokio::test]
async fn delete_account_takes_the_app_rows_in_one_transaction() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.70");
    let u = make_user(&a, &[]).await;
    let s = signed_in(a.login_password(&c, &u.username, PW, None).await);
    let v = a.export(u.id).await.unwrap();
    assert_eq!(v["user"]["username"], u.username.as_str());
    assert_eq!(v["app"]["links"][0], u.id.hex().as_str(), "the host's entries ride along");
    assert!(!v.to_string().contains("argon2"));

    let me = Actor { user: &u, scopes: &[] };
    a.delete_account(&c, me, u.id, true).await.unwrap();
    assert_eq!(a.host.deleted.lock().unwrap().last(), Some(&(u.id, true)));
    assert!(a.store.user_by_id(u.id).await.unwrap().is_none());
    assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none());
    assert!(matches!(a.delete_account(&c, me, u.id, true).await, Err(Error::NotFound)));
    assert!(matches!(a.export(u.id).await, Err(Error::NotFound)));

    let mod_role = make_role(&a, &["users:admin", "t:one"]).await;
    let one = make_role(&a, &["t:one"]).await;
    let boss = make_user(&a, &[&mod_role]).await;
    let target = make_user(&a, &[&one]).await;
    let scopes = a.effective_scopes(&boss).await.unwrap();
    a.delete_account(&c, Actor { user: &boss, scopes: &scopes }, target.id, false).await.unwrap();
    assert_eq!(a.host.deleted.lock().unwrap().last(), Some(&(target.id, false)));
    let logged = scalar(
        &a.store,
        "SELECT COUNT(*) FROM acct_audit WHERE actor_id = ? AND event = 'account_delete' AND detail = ?",
        vec![Arg::B(boss.id.0.to_vec()), Arg::S(target.id.hex())],
    )
    .await;
    assert_eq!(logged, 1, "an admin's deletion stays on the record");
    cleanup(&a, &[boss.id], &[&mod_role, &one]).await;
}

#[tokio::test]
async fn bootstrap_creates_the_first_admin_once() {
    let Some(f) = fresh().await else { return };
    let a = on(f.store.clone(), cfg()).await;
    let taken = make_user(&a, &[]).await;
    assert!(matches!(a.bootstrap_admin(&taken.username, pw_hash()).await, Err(BootstrapError::NameTaken)));
    assert!(matches!(a.bootstrap_admin("ab", pw_hash()).await, Err(BootstrapError::BadName(_))));
    let costly = pw_hash().replace("m=19456", "m=999999");
    for bad in ["", "not a hash", costly.as_str(), "$2y$99$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"] {
        assert!(matches!(a.bootstrap_admin("boss", bad).await, Err(BootstrapError::BadHash)), "{bad:?}");
    }
    assert_eq!(a.store.holders_of_scope_star().await.unwrap(), 0, "every refusal created nothing");

    // The site's own name is reserved for sign-up, which is what lets this create it.
    let id = a.bootstrap_admin("  Luki4Fun ", &format!("{}\n", pw_hash())).await.unwrap().expect("created");
    let admin = a.store.user_by_id(id).await.unwrap().unwrap();
    assert_eq!(admin.username, "luki4fun");
    assert_eq!(a.store.holders_of_scope_star().await.unwrap(), 1);
    assert_eq!(a.bootstrap_admin("luki4fun", pw_hash()).await.unwrap(), None, "idempotent");
    assert_eq!(a.bootstrap_admin("someone-else", "garbage").await.unwrap(), None, "nothing to do while someone holds *");
    let s = signed_in(a.login_password(&ctx("203.0.113.80"), "LUKI4FUN", PW, None).await);
    assert_eq!(a.session_from_token(&s.token, util::now()).await.unwrap().unwrap().2, ["*"]);
    assert!(audit_events(&a, id).await.contains(&"bootstrap".to_string()));
    drop(a);
    f.done().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn racing_boots_create_one_admin() {
    let Some(f) = fresh().await else { return };
    let a = Arc::new(on(f.store.clone(), cfg()).await);
    let boot = || {
        let a = a.clone();
        tokio::spawn(async move { a.bootstrap_admin("boss", pw_hash()).await })
    };
    let (r1, r2) = (boot(), boot());
    let mut got = [r1.await.unwrap().unwrap(), r2.await.unwrap().unwrap()];
    got.sort_by_key(|r| r.is_some());
    assert!(matches!(got, [None, Some(_)]), "one creates, the other finds it done: {got:?}");
    assert_eq!(a.store.holders_of_scope_star().await.unwrap(), 1);
    drop(a);
    f.done().await;
}

#[cfg(feature = "legacy-bcrypt")]
#[tokio::test]
async fn bootstrap_takes_the_yourls_hash_and_login_upgrades_it() {
    let Some(f) = fresh().await else { return };
    let a = on(f.store.clone(), cfg()).await;
    let bc = bcrypt::hash(PW, 4).unwrap();
    let yourls = format!("phpass:{}", bc.replace('$', "!"));
    let id = a.bootstrap_admin("luki4fun", &yourls).await.unwrap().unwrap();
    assert_eq!(a.store.password_hash_of(id).await.unwrap().as_deref(), Some(bc.as_str()), "stored unmangled");
    signed_in(a.login_password(&ctx("203.0.113.81"), "luki4fun", PW, None).await);
    assert!(a.store.password_hash_of(id).await.unwrap().unwrap().starts_with("$argon2id$"));
    drop(a);
    f.done().await;
}

/// Two admins removing each other at the same moment, for each kind of
/// removal: the store's guard lets exactly one through, and the refused
/// deletion takes the host's write in its transaction back with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_star_holder_survives_racing_admins() {
    let Some(f) = fresh().await else { return };
    let a = Arc::new(on(f.store.clone(), cfg()).await);
    let first = a.bootstrap_admin("boss", pw_hash()).await.unwrap().unwrap();
    let star = strings(&["*"]);
    let mut keep = a.store.user_by_id(first).await.unwrap().unwrap();
    for round in 0..6 {
        let other = make_user(&a, &["admin"]).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let go = |actor: User, target: AccountId| {
            let (a, b, star) = (a.clone(), barrier.clone(), star.clone());
            tokio::spawn(async move {
                let (c, act) = (ctx("203.0.113.90"), Actor { user: &actor, scopes: &star });
                b.wait().await;
                match round % 3 {
                    0 => a.revoke_role(&c, act, target, "admin").await.map(|_| ()),
                    1 => a.set_user_status(&c, act, target, UserStatus::Disabled).await.map(|_| ()),
                    _ => a.delete_account(&c, act, target, false).await,
                }
            })
        };
        let (j1, j2) = (go(keep.clone(), other.id), go(other.clone(), keep.id));
        keep = match (j1.await.unwrap(), j2.await.unwrap()) {
            (Ok(()), Err(Error::LastAdmin)) => keep,
            (Err(Error::LastAdmin), Ok(())) => other,
            x => panic!("round {round}: expected one removal and one LastAdmin, got {x:?}"),
        };
        assert_eq!(a.store.holders_of_scope_star().await.unwrap(), 1, "round {round}");
        let survivor = a.store.user_by_id(keep.id).await.unwrap().unwrap();
        assert_ne!(survivor.display_name, "host was here", "round {round}: the host's write rolled back");
    }

    let c = ctx("203.0.113.91");
    let act = Actor { user: &keep, scopes: &star };
    assert!(matches!(a.set_user_status(&c, act, keep.id, UserStatus::Disabled).await, Err(Error::LastAdmin)));
    assert!(matches!(a.delete_account(&c, act, keep.id, true).await, Err(Error::LastAdmin)));
    let none: Vec<String> = Vec::new();
    let strip = RoleForm { name: "admin", description: "Full access", badge: "", scopes: &none };
    assert!(matches!(a.update_role(&c, act, strip).await, Err(Error::LastAdmin)));
    assert!(matches!(a.delete_role(&c, act, "admin").await, Err(Error::Builtin)));
    assert_eq!(a.store.role_by_name("admin").await.unwrap().unwrap().scopes, ["*"]);
    drop(a);
    f.done().await;
}

#[tokio::test]
async fn sweep_removes_dead_sessions_and_old_audit_rows() {
    let Some(f) = fresh().await else { return };
    let a = on(f.store.clone(), Config { session_idle_days: 7, audit_retention_days: 180, ..cfg() }).await;
    let u = make_user(&a, &[]).await;
    let now = util::now();
    let live = sess(u.id, now - 6 * DAY, now + DAY);
    for s in [sess(u.id, now - 10, now - 1), sess(u.id, now - 8 * DAY, now + DAY), live.clone()] {
        a.store.insert_session(&s).await.unwrap();
    }
    for at in [now - 181 * DAY, now - 200 * DAY] {
        exec(&a.store, "INSERT INTO acct_audit (user_id, event, at) VALUES (?, 'old', ?)", vec![Arg::B(u.id.0.to_vec()), Arg::I(at)]).await;
    }
    a.store.audit(Some(u.id), None, "recent", "", "").await.unwrap();
    assert_eq!(a.sweep(now).await.unwrap(), Swept { sessions: 2, audit: 2, devkeys: 0, invites: 0, resealed: 0 });
    let left: Vec<_> = a.store.sessions_of(u.id).await.unwrap().into_iter().map(|s| s.token_hash).collect();
    assert_eq!(left, [live.token_hash]);
    assert_eq!(audit_events(&a, u.id).await, ["recent"]);
    assert_eq!(a.sweep(now).await.unwrap(), Swept::default());

    let keep_all = on(f.store.clone(), Config { audit_retention_days: 0, ..cfg() }).await;
    exec(&a.store, "INSERT INTO acct_audit (user_id, event, at) VALUES (?, 'ancient', 1)", vec![Arg::B(u.id.0.to_vec())]).await;
    assert_eq!(keep_all.sweep(now).await.unwrap().audit, 0, "retention 0 keeps the log");
    drop((a, keep_all));
    f.done().await;
}

/// A rotation: the sweep moves every TOTP secret off the old master, used or
/// not, so the old master can go; recovery codes from before match only while
/// it stays (secrets-1). A database of its own: the sweep reads every row.
#[tokio::test]
async fn the_sweep_reseals_totp_secrets_for_a_key_rotation() {
    let Some(f) = fresh().await else { return };
    let (old, new) = ([0x5a; 32], [0x5b; 32]);
    let a = on_keys(f.store.clone(), cfg(), Keys::new(&old, None).unwrap()).await;
    let c = ctx("203.0.113.96");
    let u = make_user(&a, &[]).await;
    let setup = a.totp_setup(&u);
    let secret = totp_secret(&setup);
    let (codes, _) = a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &format!("{:06}", crate::totp::code_at(&secret, step_now()))).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();

    let rotating = on_keys(f.store.clone(), cfg(), Keys::new(&new, Some(&old)).unwrap()).await;
    assert_eq!(rotating.sweep(util::now()).await.unwrap().resealed, 1);
    assert_eq!(rotating.sweep(util::now()).await.unwrap().resealed, 0, "none left under the old master");
    let pending = pending_of(rotating.login_password(&c, &u.username, PW, None).await);
    let (_, left) = rotating.mfa_recovery(&c, &u, &pending.info, &codes[0]).await.unwrap();
    assert_eq!(left, 9, "a code from before the rotation, while the old master stays");

    let after = on_keys(f.store.clone(), cfg(), Keys::new(&new, None).unwrap()).await;
    let pending = pending_of(after.login_password(&c, &u.username, PW, None).await);
    assert!(matches!(after.mfa_recovery(&c, &u, &pending.info, &codes[1]).await, Err(Error::Invalid(_))), "not once it is gone");
    let next = format!("{:06}", crate::totp::code_at(&secret, step_now() + 1));
    assert!(after.mfa_totp(&c, &u, &pending.info, &next).await.unwrap().info.mfa_ok, "the code was never used during the rotation");
    assert_eq!(after.sweep(util::now()).await.unwrap().resealed, 0);
    drop((a, rotating, after));
    f.done().await;
}

/// Step-up with the password counts per account like the login form, in a
/// bucket of its own: strangers failing to sign in as the owner cannot lock
/// the signed-in owner out of step-up (AUTH-4).
#[tokio::test]
async fn confirm_password_has_its_own_account_bucket() {
    let Some(a) = shared(Config { login_per_user_15min: 3, ..cfg() }).await else { return };
    let c = ctx("203.0.113.60");
    let u = make_user(&a, &[]).await;
    a.confirm_password(&c, &u, PW).await.unwrap();
    assert!(matches!(a.confirm_password(&c, &u, "wrong password").await, Err(Error::Invalid("Wrong password."))));
    let cross = Ctx { sec_fetch_site: "same-site".into(), ..ctx("203.0.113.60") };
    assert!(matches!(a.confirm_password(&cross, &u, PW).await, Err(Error::CrossSite)));
    a.confirm_password(&c, &u, PW).await.unwrap();
    assert!(matches!(a.confirm_password(&c, &u, PW).await, Err(Error::RateLimited)), "3 per account, right or wrong");
    signed_in(a.login_password(&ctx("203.0.113.61"), &u.username, PW, None).await);
    let v = make_user(&a, &[]).await;
    for _ in 0..3 {
        assert!(matches!(a.login_password(&ctx("203.0.113.61"), &v.username, "wrong password", None).await, Err(Error::BadLogin)));
    }
    assert!(matches!(a.login_password(&ctx("203.0.113.61"), &v.username, PW, None).await, Err(Error::RateLimited)));
    a.confirm_password(&c, &v, PW).await.unwrap();
    let mut logged = false;
    for _ in 0..50 {
        if audit_events(&a, u.id).await.contains(&"reauth_fail".to_string()) {
            logged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(logged, "a wrong password is audited");
    cleanup(&a, &[u.id, v.id], &[]).await;
}

#[tokio::test]
async fn step_up_refreshes_auth_at_and_rotates_the_token() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.62");
    let u = make_user(&a, &[]).await;
    let now = util::now();
    // A login long ago: the session is live but not fresh.
    let old = a.create_session(u.id, "password", true, now - 3600, &c).await.unwrap();
    let (_, info, _) = a.session_from_token(&old.token, now).await.unwrap().unwrap();
    assert!(!a.fresh(&info, now), "an hour-old sign-in is stale");
    assert!(matches!(a.step_up(&c, &u, &info, "wrong password").await, Err(Error::Invalid(_))));
    let new = a.step_up(&c, &u, &info, PW).await.unwrap();
    assert!(a.session_from_token(&old.token, now).await.unwrap().is_none(), "the old token is dead");
    let (_, fresh, _) = a.session_from_token(&new.token, now).await.unwrap().unwrap();
    assert!(a.fresh(&fresh, util::now()));
    assert!(!a.fresh(&fresh, fresh.auth_at + 15 * 60), "15 minutes by default");
    assert_eq!(fresh.created_at, info.created_at, "same session");
    assert!(audit_events(&a, u.id).await.contains(&"step_up".to_string()));

    // Someone else's session, a pending one, and a 2FA account are refused.
    let other = make_user(&a, &[]).await;
    assert!(matches!(a.step_up(&c, &other, &fresh, PW).await, Err(Error::Forbidden)));
    let pending = a.create_session(u.id, "password", false, 0, &c).await.unwrap();
    assert!(matches!(a.step_up(&c, &u, &pending.info, PW).await, Err(Error::Forbidden)));
    assert!(!a.fresh(&pending.info, now));
    exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(u.id.0.to_vec())]).await;
    let u2 = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(matches!(a.step_up(&c, &u2, &fresh, PW).await, Err(Error::Invalid(_))), "a password alone is not enough with 2FA");
    cleanup(&a, &[u.id, other.id], &[]).await;
}

/// A password change asks for no old password and ends every other session:
/// only from a recent sign-in (AUTH-10). Each is an Argon2 hash, so they are
/// capped per account once the policy passed (AUTH-3).
#[tokio::test]
async fn a_password_change_needs_a_recent_sign_in_and_is_capped() {
    let Some(a) = shared(Config { login_per_user_15min: 2, ..cfg() }).await else { return };
    let c = ctx("203.0.113.64");
    let u = make_user(&a, &[]).await;
    let now = util::now();
    let stale = a.create_session(u.id, "password", true, now - 3600, &c).await.unwrap();
    assert!(matches!(a.password_change(&c, &u, &stale.info, "a brand new password").await, Err(Error::Forbidden)), "an hour-old sign-in");
    let here = a.create_session(u.id, "password", true, now, &c).await.unwrap();
    for _ in 0..3 {
        assert!(matches!(a.password_change(&c, &u, &here.info, "tiny").await, Err(Error::Invalid(_))), "the policy spends nothing");
    }
    a.password_change(&c, &u, &here.info, "a brand new password").await.unwrap();
    a.password_change(&c, &u, &here.info, "another new password").await.unwrap();
    assert!(matches!(a.password_change(&c, &u, &here.info, "a third new password").await, Err(Error::RateLimited)), "2 per 15 minutes");
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn display_name_sessions_and_revoke() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.63");
    let u = make_user(&a, &[]).await;
    let other = make_user(&a, &[]).await;
    assert_eq!(a.set_display_name(&c, u.id, "  Dee  ").await.unwrap(), "Dee");
    assert!(matches!(a.set_display_name(&c, u.id, "a\u{202e}b").await, Err(Error::Invalid(_))));
    assert_eq!(a.store.user_by_id(u.id).await.unwrap().unwrap().display_name, "Dee", "a refused name changes nothing");

    let now = util::now();
    let live = sess(u.id, now - 10, now + DAY);
    let expired = sess(u.id, now - 10, now - 1);
    let idle = sess(u.id, now - 8 * DAY, now + DAY);
    for s in [&live, &expired, &idle] {
        a.store.insert_session(s).await.unwrap();
    }
    let listed: Vec<_> = a.sessions(u.id, now).await.unwrap().into_iter().map(|s| s.token_hash).collect();
    assert_eq!(listed, [live.token_hash], "expired and idle rows are left out");

    assert!(!a.revoke_session(&c, other.id, &live.token_hash).await.unwrap(), "someone else's hash deletes nothing");
    assert_eq!(a.sessions(u.id, now).await.unwrap().len(), 1);
    assert!(a.revoke_session(&c, u.id, &live.token_hash).await.unwrap());
    assert!(a.sessions(u.id, now).await.unwrap().is_empty());
    assert!(!a.revoke_session(&c, u.id, &live.token_hash).await.unwrap());
    let ev = audit_events(&a, u.id).await;
    assert!(ev.contains(&"session_revoke".to_string()) && ev.contains(&"display_name".to_string()));
    cleanup(&a, &[u.id, other.id], &[]).await;
}

// ---- second factors

fn totp_secret(setup: &TotpSetup) -> Vec<u8> {
    crate::totp::base32_decode(&setup.secret).unwrap()
}

fn step_now() -> i64 {
    util::now() / 30
}

fn pending_of(r: Result<LoginStep, Error>) -> NewSession {
    match r {
        Ok(LoginStep::NeedMfa(s)) => s,
        Ok(LoginStep::Done(_)) => panic!("expected the second step, got a full sign-in"),
        Err(e) => panic!("expected the second step, got {e:?}"),
    }
}

#[tokio::test]
async fn totp_turns_on_gates_sign_in_and_refuses_replays() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.70");
    let u = make_user(&a, &[]).await;
    let setup = a.totp_setup(&u);
    assert!(setup.uri.starts_with("otpauth://totp/") && setup.uri.contains(&u.username));
    let secret = totp_secret(&setup);
    assert!(matches!(a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, "000000").await, Err(Error::Invalid(_))), "a wrong code enables nothing");
    let other = make_user(&a, &[]).await;
    let code = format!("{:06}", crate::totp::code_at(&secret, step_now()));
    assert!(matches!(a.totp_enable(&c, &other, &full_session(&a, &c, &other).await, &setup.sealed, &code).await, Err(Error::Invalid(_))), "sealed to its account");
    let (codes, _) = a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &code).await.unwrap();
    assert_eq!(codes.len(), 10, "recovery codes come with it");
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(u.totp_enabled && has_second_factor(&u));
    assert!(matches!(a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &code).await, Err(Error::Invalid(_))), "already on");

    // A password alone now opens a pending session that grants nothing.
    let pending = pending_of(a.login_password(&c, &u.username, PW, None).await);
    let (_, info, scopes) = a.session_from_token(&pending.token, util::now()).await.unwrap().unwrap();
    assert!(!info.mfa_ok && scopes.is_empty() && info.expires_at <= util::now() + 600);
    assert!(matches!(a.mfa_totp(&c, &u, &pending.info, &code).await, Err(Error::Invalid(_))), "the setup's code was spent");
    let next = format!("{:06}", crate::totp::code_at(&secret, step_now() + 1));
    let done = a.mfa_totp(&c, &u, &pending.info, &next).await.unwrap();
    assert!(done.info.mfa_ok && done.info.auth_at > 0 && done.info.expires_at > util::now() + 29 * DAY);
    assert!(a.session_from_token(&pending.token, util::now()).await.unwrap().is_none(), "the pending token is dead");
    assert!(matches!(a.mfa_totp(&c, &u, &done.info, &next).await, Err(Error::Invalid(_)) | Err(Error::Forbidden)));

    // Step-up takes a code, not the password, and counts apart from the
    // second step: whoever has the password and spends that bucket cannot
    // lock the owner out of step-up (FAC-1). Each takes 5 codes per 15
    // minutes, right or wrong; two of each went above.
    assert!(matches!(a.step_up(&c, &u, &done.info, PW).await, Err(Error::Invalid(_))));
    let stranger = pending_of(a.login_password(&c, &u.username, PW, None).await);
    for _ in 0..3 {
        assert!(matches!(a.mfa_totp(&c, &u, &stranger.info, "000000").await, Err(Error::Invalid(_))));
    }
    assert!(matches!(a.mfa_totp(&c, &u, &stranger.info, &next).await, Err(Error::RateLimited)), "the second step");
    exec(&a.store, "UPDATE acct_users SET totp_last_step = 0 WHERE id = ?", vec![Arg::B(u.id.0.to_vec())]).await;
    let up = a.step_up_totp(&c, &u, &done.info, &code).await.unwrap();
    assert!(a.fresh(&up.info, util::now()));
    for _ in 0..2 {
        assert!(matches!(a.step_up_totp(&c, &u, &up.info, "000000").await, Err(Error::Invalid(_))));
    }
    assert!(matches!(a.step_up_totp(&c, &u, &up.info, &code).await, Err(Error::RateLimited)), "step-up and setup");

    a.totp_disable(&c, &u).await.unwrap();
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 0, "no second factor left, no recovery codes");
    signed_in(a.login_password(&c, &u.username, PW, None).await);
    cleanup(&a, &[u.id, other.id], &[]).await;
}

#[tokio::test]
async fn recovery_codes_work_once_and_wrong_codes_are_capped() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.71");
    let u = make_user(&a, &[]).await;
    let setup = a.totp_setup(&u);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    let (codes, _) = a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &code).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let pending = pending_of(a.login_password(&c, &u.username, PW, None).await);
    let typed = codes[0].to_uppercase().replace('-', " ");
    let (s, left) = a.mfa_recovery(&c, &u, &pending.info, &typed).await.unwrap();
    assert_eq!(left, 9);
    assert!(s.info.mfa_ok && s.info.auth_at == 0, "a recovery code is never a recent sign-in");
    let again = pending_of(a.login_password(&c, &u.username, PW, None).await);
    assert!(matches!(a.mfa_recovery(&c, &u, &again.info, &codes[0]).await, Err(Error::Invalid(_))), "spent");
    let fresh_codes = a.recovery_regenerate(&c, &u).await.unwrap();
    assert!(matches!(a.mfa_recovery(&c, &u, &again.info, &codes[1]).await, Err(Error::Invalid(_))), "the old set is gone");
    for _ in 0..2 {
        let _ = a.mfa_totp(&c, &u, &again.info, "000000").await;
    }
    assert!(matches!(a.mfa_recovery(&c, &u, &again.info, &fresh_codes[0]).await, Err(Error::RateLimited)), "5 tries per 15 minutes");
    cleanup(&a, &[u.id], &[]).await;
}

/// Signed in with a recovery code after losing the phone, the session is not
/// recent; a second code steps it up, so the owner can set up a new factor
/// and make a new set (FAC-2). It counts in the step-up bucket.
#[tokio::test]
async fn a_recovery_code_steps_up() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.76");
    let u = make_user(&a, &[]).await;
    let setup = a.totp_setup(&u);
    let (codes, _) = a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()))).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let pending = pending_of(a.login_password(&c, &u.username, PW, None).await);
    let (s, _) = a.mfa_recovery(&c, &u, &pending.info, &codes[0]).await.unwrap();
    assert!(!a.fresh(&s.info, util::now()));
    assert!(matches!(a.step_up_recovery(&c, &u, &pending.info, &codes[1]).await, Err(Error::Forbidden)), "a pending session");
    assert!(matches!(a.step_up_recovery(&c, &u, &s.info, &codes[0]).await, Err(Error::Invalid(_))), "spent");
    let up = a.step_up_recovery(&c, &u, &s.info, &codes[1]).await.unwrap();
    assert!(a.fresh(&up.info, util::now()) && up.info.created_at == s.info.created_at);
    assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none(), "a new token");
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 8);
    let ev = a.store.audit_of(u.id, 50).await.unwrap();
    assert!(ev.iter().any(|e| e.event == "step_up" && e.detail == "recovery"));
    // Setup took one, the spent code one, the step-up one.
    for _ in 0..2 {
        assert!(matches!(a.step_up_recovery(&c, &u, &up.info, "nope").await, Err(Error::Invalid(_))));
    }
    assert!(matches!(a.step_up_recovery(&c, &u, &up.info, &codes[2]).await, Err(Error::RateLimited)));
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 8, "refused before the code is spent");
    cleanup(&a, &[u.id], &[]).await;
}

/// A second step that may not finish is refused before its factor is spent:
/// a session of someone else, an expired one, or any while accounts are off
/// (FAC-8).
#[tokio::test]
async fn the_second_step_checks_its_session_before_the_code() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.77");
    let u = make_user(&a, &[]).await;
    let setup = a.totp_setup(&u);
    let (codes, _) = a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()))).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let pending = pending_of(a.login_password(&c, &u.username, PW, None).await);
    let others = SessionInfo { user_id: AccountId::new(), ..pending.info.clone() };
    assert!(matches!(a.mfa_recovery(&c, &u, &others, &codes[0]).await, Err(Error::Forbidden)));
    let expired = SessionInfo { expires_at: util::now() - 1, ..pending.info.clone() };
    assert!(matches!(a.mfa_recovery(&c, &u, &expired, &codes[0]).await, Err(Error::Forbidden)));
    let off = on(a.store.clone(), Config { enabled: false, ..cfg() }).await;
    assert!(matches!(off.mfa_recovery(&c, &u, &pending.info, &codes[0]).await, Err(Error::Closed)));
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 10, "no code was spent");
    a.mfa_recovery(&c, &u, &pending.info, &codes[0]).await.unwrap();
    cleanup(&a, &[u.id], &[]).await;
}

fn pk_cfg() -> Config {
    Config { base_url: "https://l4f.cc".into(), ..cfg() }
}

const ORIGIN: &str = "https://l4f.cc";
const NONCE: &[u8] = b"browser-nonce-0123456789";

async fn add_passkey(a: &Accounts<Stub>, c: &Ctx, u: &User) -> crate::testkit::Authenticator {
    let auth = crate::testkit::Authenticator::new();
    let (opts, token) = a.passkey_options(PasskeyFor::Add, Some(u), NONCE).await.unwrap();
    assert_eq!(opts["rp"]["id"], "l4f.cc");
    let json = auth.create(&crate::challenge::challenge_bytes(&token), ORIGIN, "l4f.cc");
    a.passkey_add(c, u, &full_session(a, c, u).await, &token, NONCE, &json, "Laptop").await.unwrap();
    assert!(matches!(a.passkey_add(c, u, &full_session(a, c, u).await, &token, NONCE, &json, "Laptop").await, Err(Error::Invalid(_))), "a token works once");
    auth
}

#[tokio::test]
async fn a_passkey_signs_in_alone_with_user_verification() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.72");
    let u = make_user(&a, &[]).await;
    let mut auth = add_passkey(&a, &c, &u).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(u.has_passkey && has_second_factor(&u));
    let (opts, _) = a.passkey_options(PasskeyFor::Add, Some(&u), NONCE).await.unwrap();
    assert_eq!(opts["excludeCredentials"][0]["id"], util::b64u(&auth.id), "no second registration of the same key");

    let (opts, token) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    assert_eq!(opts["userVerification"], "required");
    let named = a.passkey_options(PasskeyFor::Login, Some(&u), NONCE).await;
    assert!(matches!(named, Err(Error::Forbidden)), "a sign-in token names no account: one that did could never verify");
    let ch = crate::challenge::challenge_bytes(&token);
    let no_uv = auth.get(&ch, ORIGIN, "l4f.cc", Some(&u.id.0), false);
    assert!(matches!(a.passkey_login(&c, &token, NONCE, &no_uv).await, Err(Error::Invalid(_))), "alone, it must verify the user");
    let (_, token) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    let ch = crate::challenge::challenge_bytes(&token);
    let json = auth.get(&ch, ORIGIN, "l4f.cc", Some(&u.id.0), true);
    assert!(matches!(a.passkey_login(&c, &token, b"another-browser-nonce", &json).await, Err(Error::Invalid(_))), "bound to the browser");
    let s = a.passkey_login(&c, &token, NONCE, &json).await.unwrap();
    assert!(s.info.mfa_ok && s.info.method == "passkey" && a.fresh(&s.info, util::now()));
    assert!(matches!(a.passkey_login(&c, &token, NONCE, &json).await, Err(Error::Invalid(_))), "a replay is refused");
    let (_, token) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    let wrong = auth.get(&crate::challenge::challenge_bytes(&token), ORIGIN, "l4f.cc", Some(&[9; 16]), true);
    assert!(matches!(a.passkey_login(&c, &token, NONCE, &wrong).await, Err(Error::Invalid(_))), "the handle must be the owner");
    let (_, token) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    let evil = auth.get(&crate::challenge::challenge_bytes(&token), "https://evil.example", "l4f.cc", Some(&u.id.0), true);
    assert!(matches!(a.passkey_login(&c, &token, NONCE, &evil).await, Err(Error::Invalid(_))), "another origin");
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn a_passkey_is_a_second_factor_and_a_step_up() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.73");
    let u = make_user(&a, &[]).await;
    let mut auth = add_passkey(&a, &c, &u).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let pending = pending_of(a.login_password(&c, &u.username, PW, None).await);
    let (opts, token) = a.passkey_options(PasskeyFor::Mfa, Some(&u), NONCE).await.unwrap();
    assert_eq!(opts["allowCredentials"][0]["id"], util::b64u(&auth.id));
    let json = auth.get(&crate::challenge::challenge_bytes(&token), ORIGIN, "l4f.cc", None, false);
    let other = make_user(&a, &[]).await;
    let others = SessionInfo { user_id: other.id, ..pending.info.clone() };
    assert!(matches!(a.passkey_mfa(&c, &other, &others, &token, NONCE, &json).await, Err(Error::Invalid(_))), "bound to its account");
    assert!(matches!(a.passkey_mfa(&c, &other, &pending.info, &token, NONCE, &json).await, Err(Error::Forbidden)), "someone else's session");
    let s = a.passkey_mfa(&c, &u, &pending.info, &token, NONCE, &json).await.unwrap();
    assert!(s.info.mfa_ok && a.fresh(&s.info, util::now()));

    exec(&a.store, "UPDATE acct_sessions SET auth_at = 1 WHERE token_hash = ?", vec![Arg::B(s.info.token_hash.to_vec())]).await;
    let (_, info, _) = a.session_from_token(&s.token, util::now()).await.unwrap().unwrap();
    let (_, token) = a.passkey_options(PasskeyFor::StepUp, Some(&u), NONCE).await.unwrap();
    let ch = crate::challenge::challenge_bytes(&token);
    assert!(a.passkey_step_up(&c, &u, &info, &token, NONCE, &auth.get(&ch, ORIGIN, "l4f.cc", None, false)).await.is_err(), "step-up needs UV");
    let (_, token) = a.passkey_options(PasskeyFor::StepUp, Some(&u), NONCE).await.unwrap();
    let ch = crate::challenge::challenge_bytes(&token);
    let up = a.passkey_step_up(&c, &u, &info, &token, NONCE, &auth.get(&ch, ORIGIN, "l4f.cc", None, true)).await.unwrap();
    assert!(a.fresh(&up.info, util::now()));

    // A counter that goes backwards means a cloned key.
    auth.count = 0;
    let (_, token) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    let json = auth.get(&crate::challenge::challenge_bytes(&token), ORIGIN, "l4f.cc", Some(&u.id.0), true);
    assert!(a.passkey_login(&c, &token, NONCE, &json).await.is_err());
    cleanup(&a, &[u.id, other.id], &[]).await;
}

#[tokio::test]
async fn removing_passkeys_keeps_a_way_in() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.74");
    let u = make_user(&a, &[]).await;
    let auth = add_passkey(&a, &c, &u).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let codes = a.recovery_regenerate(&c, &u).await.unwrap();
    assert_eq!(codes.len(), 10);
    drop_password(&a, u.id).await;
    assert!(matches!(a.passkey_remove(&c, &u, &auth.id).await, Err(Error::Invalid(_))), "the only way in stays");
    assert!(matches!(a.passkey_remove(&c, &u, &[1, 2, 3]).await, Err(Error::NotFound)));
    assert!(a.store.set_password_hash(u.id, pw_hash()).await.unwrap());
    a.passkey_remove(&c, &u, &auth.id).await.unwrap();
    assert!(!a.store.user_by_id(u.id).await.unwrap().unwrap().has_passkey);
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 0, "recovery codes went with the last second factor");
    cleanup(&a, &[u.id], &[]).await;
}

/// The name comes after the authenticator stored the key: one the site
/// cannot keep falls back instead of leaving that key unknown here (FAC-5).
#[tokio::test]
async fn a_passkey_with_a_name_that_cannot_be_kept_is_still_added() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.78");
    let u = make_user(&a, &[]).await;
    let auth = crate::testkit::Authenticator::new();
    let (_, token) = a.passkey_options(PasskeyFor::Add, Some(&u), NONCE).await.unwrap();
    let json = auth.create(&crate::challenge::challenge_bytes(&token), ORIGIN, "l4f.cc");
    a.passkey_add(&c, &u, &full_session(&a, &c, &u).await, &token, NONCE, &json, "\u{200f}Phone").await.unwrap();
    assert_eq!(a.passkeys(u.id).await.unwrap()[0].name, "Passkey");
    cleanup(&a, &[u.id], &[]).await;
}

/// A session opened before the account's first second factor never showed
/// one, yet would get the privileged scopes that wait for it: the first one
/// ends every other session and gives the enrolling one a new token, so a
/// copied cookie of it dies too. Another one ends none (AUTH-1).
#[tokio::test]
async fn the_first_second_factor_keeps_only_the_enrolling_session() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.75");
    let u = make_user(&a, &[]).await;
    let before = signed_in(a.login_password(&c, &u.username, PW, None).await);
    let mine = a.create_session(u.id, "password", true, util::now(), &c).await.unwrap();
    let setup = a.totp_setup(&u);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    let (_, new) = a.totp_enable(&c, &u, &mine.info, &setup.sealed, &code).await.unwrap();
    let new = new.expect("the first second factor gives the caller a new token");
    assert!(a.session_from_token(&before.token, util::now()).await.unwrap().is_none(), "codes first: the others end");
    assert!(a.session_from_token(&mine.token, util::now()).await.unwrap().is_none(), "and the caller's old token");
    assert!(a.session_from_token(&new.token, util::now()).await.unwrap().is_some(), "the caller stays signed in");
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let after = a.create_session(u.id, "password", true, util::now(), &c).await.unwrap();
    add_passkey(&a, &c, &u).await;
    assert!(a.session_from_token(&after.token, util::now()).await.unwrap().is_some(), "a passkey next to codes ends none");

    let v = make_user(&a, &[]).await;
    let before = signed_in(a.login_password(&c, &v.username, PW, None).await);
    add_passkey(&a, &c, &v).await;
    assert!(a.session_from_token(&before.token, util::now()).await.unwrap().is_none(), "a passkey first");
    let w = make_user(&a, &[]).await;
    let theirs = a.create_session(v.id, "password", true, util::now(), &c).await.unwrap();
    let setup = a.totp_setup(&w);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    assert!(matches!(a.totp_enable(&c, &w, &theirs.info, &setup.sealed, &code).await, Err(Error::Forbidden)), "only with one's own session");
    let x = make_user(&a, &[]).await;
    let gone = a.create_session(x.id, "password", true, util::now(), &c).await.unwrap();
    a.logout(&gone.token).await.unwrap();
    let setup = a.totp_setup(&x);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    let (codes, new) = a.totp_enable(&c, &x, &gone.info, &setup.sealed, &code).await.unwrap();
    assert!(!codes.is_empty() && new.is_none(), "signed out meanwhile: the codes still come back, with no session to keep");
    cleanup(&a, &[u.id, v.id, w.id, x.id], &[]).await;
}

// ---- key sign-in

#[tokio::test]
async fn an_ssh_key_signs_in_once_it_signed_its_own_enrolment() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.80");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let ns = a.host.config().ssh_namespace();
    assert_eq!(ns, "login@l4f.cc");
    let token = a.ssh_challenge(Some(&u), NONCE);
    let line = key.ssh_public("dee@laptop");
    let other = crate::testkit::EdKey::new();
    assert!(matches!(a.ssh_add(&c, &u, &token, NONCE, &line, &other.ssh_sign(&ns, token.as_bytes())).await, Err(Error::Invalid(_))), "signed by another key");
    assert!(matches!(a.ssh_add(&c, &u, &token, NONCE, &line, &key.ssh_sign("git", token.as_bytes())).await, Err(Error::Invalid(_))), "another namespace");
    a.ssh_add(&c, &u, &token, NONCE, &line, &key.ssh_sign(&ns, token.as_bytes())).await.unwrap();
    assert_eq!(a.ssh_keys(u.id).await.unwrap()[0].name, "dee@laptop");
    let v = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let t2 = a.ssh_challenge(Some(&v), NONCE);
    assert!(matches!(a.ssh_add(&c, &v, &t2, NONCE, &line, &key.ssh_sign(&ns, t2.as_bytes())).await, Err(Error::Invalid(_))), "registered once");

    let login = a.ssh_challenge(None, NONCE);
    let sig = key.ssh_sign(&ns, login.as_bytes());
    assert!(matches!(a.ssh_login(&c, &login, b"some-other-browser!", &sig).await, Err(Error::Invalid(_))));
    let s = signed_in(a.ssh_login(&c, &login, NONCE, &sig).await);
    assert!(s.info.mfa_ok && s.info.method == "ssh" && !a.fresh(&s.info, util::now()), "never a recent sign-in");
    assert!(a.ssh_login(&c, &login, NONCE, &sig).await.is_err(), "a replay is refused");
    let stranger = a.ssh_challenge(None, NONCE);
    assert!(a.ssh_login(&c, &stranger, NONCE, &other.ssh_sign(&ns, stranger.as_bytes())).await.is_err(), "an unknown key");

    // With a second factor, an SSH key is only the first one, and the audit
    // says so: not "password+recovery" (FAC-9).
    exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(u.id.0.to_vec())]).await;
    let login = a.ssh_challenge(None, NONCE);
    let pending = pending_of(a.ssh_login(&c, &login, NONCE, &key.ssh_sign(&ns, login.as_bytes())).await);
    assert!(!pending.info.mfa_ok);
    let v = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let codes = a.recovery_regenerate(&c, &v).await.unwrap();
    a.mfa_recovery(&c, &v, &pending.info, &codes[0]).await.unwrap();
    let audit = a.store.audit_of(u.id, 50).await.unwrap();
    assert!(audit.iter().any(|e| e.event == "login_ok" && e.detail == "ssh+recovery"));
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn a_device_key_signs_in_this_browser_until_it_is_revoked() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.81");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let device = util::random::<16>();
    let token = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&token);
    let bad = key.devkey_sign("https://evil.example", &device, &ch);
    assert!(a.devkey_add(&c, &u, &token, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &bad }).await.is_err(), "signed for another origin");
    a.devkey_add(&c, &u, &token, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();

    let sign_in = |t: &str| key.devkey_sign(ORIGIN, &device, &crate::challenge::challenge_bytes(t));
    let t = a.devkey_challenge(None, NONCE);
    let s = a.devkey_login(&c, &t, NONCE, &device, &sign_in(&t)).await.unwrap();
    assert!(s.info.mfa_ok && s.info.method == "devkey" && !a.fresh(&s.info, util::now()));
    assert!(a.devkey_login(&c, &t, NONCE, &device, &sign_in(&t)).await.is_err(), "a replay is refused");
    let t = a.devkey_challenge(None, NONCE);
    assert!(a.devkey_login(&c, &t, NONCE, &util::random::<16>(), &sign_in(&t)).await.is_err(), "another device id");

    // Unused for 90 days: gone.
    exec(&a.store, "UPDATE acct_credentials SET last_used_at = 1 WHERE kind = 'devkey' AND ext_id = ?", vec![Arg::B(device.to_vec())]).await;
    let t = a.devkey_challenge(None, NONCE);
    assert!(a.devkey_login(&c, &t, NONCE, &device, &sign_in(&t)).await.is_err());
    assert!(a.devkeys(u.id).await.unwrap().is_empty(), "and deleted");

    // Sign-out everywhere and any second-factor change revoke them.
    let token = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&token);
    a.devkey_add(&c, &u, &token, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();
    a.logout_all(&c, u.id, None).await.unwrap();
    assert!(a.devkeys(u.id).await.unwrap().is_empty(), "sign-out everywhere");
    let token = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&token);
    a.devkey_add(&c, &u, &token, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();
    add_passkey(&a, &c, &u).await;
    assert!(a.devkeys(u.id).await.unwrap().is_empty(), "a new passkey");
    cleanup(&a, &[u.id], &[]).await;
}

/// A refused device-key sign-in leaves its journal line, as an SSH one does
/// (FAC-10). Refused at the door, before any query: one poll runs it.
#[tokio::test]
async fn a_refused_device_key_sign_in_is_logged() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let cross = Ctx { sec_fetch_site: "cross-site".into(), ..ctx("203.0.113.79") };
    let lines = crate::testkit::logged(|| {
        let mut f = std::pin::pin!(a.devkey_login(&cross, "", NONCE, &[0; 16], &[]));
        let r = f.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(matches!(r, std::task::Poll::Ready(Err(Error::CrossSite))));
    });
    assert!(lines.iter().any(|l| l.contains("devkey login refused") && l.contains(r#"outcome="cross_site""#)), "{lines:?}");
}

/// SSH, device-key and passkey sign-ins share one bucket per account, charged
/// once the signature checked out and before the burn: one account signing
/// from many addresses cannot fill the burn set (GATES-6).
#[tokio::test]
async fn key_sign_ins_count_per_account() {
    let Some(a) = shared(Config { login_per_user_15min: 1, ..pk_cfg() }).await else { return };
    let c = ctx("203.0.113.84");
    let u = make_user(&a, &[]).await;
    let mut auth = add_passkey(&a, &c, &u).await;
    let key = crate::testkit::EdKey::new();
    let ns = a.host.config().ssh_namespace();
    let t = a.ssh_challenge(Some(&u), NONCE);
    a.ssh_add(&c, &u, &t, NONCE, &key.ssh_public(""), &key.ssh_sign(&ns, t.as_bytes())).await.unwrap();
    let device = util::random::<16>();
    let t = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&t);
    a.devkey_add(&c, &u, &t, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();
    let dk = |t: &str| key.devkey_sign(ORIGIN, &device, &crate::challenge::challenge_bytes(t));

    for _ in 0..3 {
        let (t, other) = (a.devkey_challenge(None, NONCE), a.devkey_challenge(None, NONCE));
        assert!(a.devkey_login(&c, &t, NONCE, &device, &dk(&other)).await.is_err(), "unverified: not charged");
    }
    let t = a.ssh_challenge(None, NONCE);
    pending_of(a.ssh_login(&ctx("198.51.100.31"), &t, NONCE, &key.ssh_sign(&ns, t.as_bytes())).await);
    let t = a.devkey_challenge(None, NONCE);
    a.devkey_login(&ctx("198.51.100.32"), &t, NONCE, &device, &dk(&t)).await.unwrap();
    let (_, t) = a.passkey_options(PasskeyFor::Login, None, NONCE).await.unwrap();
    let json = auth.get(&crate::challenge::challenge_bytes(&t), ORIGIN, "l4f.cc", Some(&u.id.0), true);
    a.passkey_login(&ctx("198.51.100.33"), &t, NONCE, &json).await.unwrap();
    let t = a.devkey_challenge(None, NONCE);
    assert!(matches!(a.devkey_login(&ctx("198.51.100.34"), &t, NONCE, &device, &dk(&t)).await, Err(Error::RateLimited)), "3 per 15 minutes");
    let n = crate::challenge::check(&a.keys, &t, crate::challenge::Purpose::Login, None, NONCE, util::now()).unwrap();
    assert!(crate::challenge::burn(&a.limiter, &n), "refused before its burn");
    cleanup(&a, &[u.id], &[]).await;
}

/// A key removed while its sign-in was under way signs nobody in: the use is
/// recorded on no row then (FAC-7). A counter these kinds never have stands
/// in for the missing row, as the UPDATE misses it the same way.
#[tokio::test]
async fn a_key_gone_mid_sign_in_signs_nobody_in() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.85");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let ns = a.host.config().ssh_namespace();
    let t = a.ssh_challenge(Some(&u), NONCE);
    a.ssh_add(&c, &u, &t, NONCE, &key.ssh_public(""), &key.ssh_sign(&ns, t.as_bytes())).await.unwrap();
    let device = util::random::<16>();
    let t = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&t);
    a.devkey_add(&c, &u, &t, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();
    exec(&a.store, "UPDATE acct_credentials SET sign_count = 1 WHERE user_id = ?", vec![Arg::B(u.id.0.to_vec())]).await;
    let t = a.ssh_challenge(None, NONCE);
    assert!(matches!(a.ssh_login(&c, &t, NONCE, &key.ssh_sign(&ns, t.as_bytes())).await, Err(Error::Invalid(_))), "ssh");
    let t = a.devkey_challenge(None, NONCE);
    let sig = key.devkey_sign(ORIGIN, &device, &crate::challenge::challenge_bytes(&t));
    assert!(matches!(a.devkey_login(&c, &t, NONCE, &device, &sig).await, Err(Error::Invalid(_))), "device key");
    assert!(a.sessions(u.id, util::now()).await.unwrap().is_empty());
    cleanup(&a, &[u.id], &[]).await;
}

/// A sign-in racing a revocation keeps no session, whichever runs first: the
/// revocation removes the credential before the sessions, and the sign-in
/// checks its device key or password hash again once its session is in
/// (store-data-1).
#[tokio::test]
async fn a_sign_in_racing_a_revocation_keeps_no_session() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.86");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let device = util::random::<16>();
    let t = a.devkey_challenge(Some(&u), NONCE);
    let ch = crate::challenge::challenge_bytes(&t);
    a.devkey_add(&c, &u, &t, NONCE, NewDeviceKey { device_id: &device, public_key: &key.raw_public(), signature: &key.devkey_sign(ORIGIN, &device, &ch) }).await.unwrap();
    let t = a.devkey_challenge(None, NONCE);
    let sig = key.devkey_sign(ORIGIN, &device, &crate::challenge::challenge_bytes(&t));
    let (login, out) = tokio::join!(a.devkey_login(&c, &t, NONCE, &device, &sig), a.logout_all(&c, u.id, None));
    out.unwrap();
    if let Ok(s) = login {
        assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none(), "sign-out everywhere");
    }

    let here = a.create_session(u.id, "password", true, util::now(), &c).await.unwrap();
    let (login, changed) = tokio::join!(a.login_password(&c, &u.username, PW, None), a.password_change(&c, &u, &here.info, "a brand new password"));
    changed.unwrap();
    if let Ok(LoginStep::Done(s)) = login {
        assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none(), "a password change");
    }
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn an_account_without_a_password_keeps_one_way_in() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.82");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let ns = a.host.config().ssh_namespace();
    let token = a.ssh_challenge(Some(&u), NONCE);
    a.ssh_add(&c, &u, &token, NONCE, &key.ssh_public(""), &key.ssh_sign(&ns, token.as_bytes())).await.unwrap();
    let fp = a.ssh_keys(u.id).await.unwrap()[0].ext_id.clone();
    drop_password(&a, u.id).await;
    assert!(matches!(a.remove_credential(&c, &u, "ssh", &fp).await, Err(Error::Invalid(_))));
    let other = make_user(&a, &[]).await;
    assert!(matches!(a.remove_credential(&c, &other, "ssh", &fp).await, Err(Error::NotFound)), "someone else's key");
    assert!(a.store.set_password_hash(u.id, pw_hash()).await.unwrap());
    a.remove_credential(&c, &u, "ssh", &fp).await.unwrap();
    assert!(a.ssh_keys(u.id).await.unwrap().is_empty());
    cleanup(&a, &[u.id, other.id], &[]).await;
}

/// An SSH sign-in is never recent, so an account without a password keeps a
/// passkey or a linked account: with SSH keys alone it could sign in but
/// never confirm it's you again. Turning codes off keeps to it too (FAC-4).
#[tokio::test]
async fn an_account_without_a_password_keeps_a_way_to_step_up() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.83");
    let u = make_user(&a, &[]).await;
    let key = crate::testkit::EdKey::new();
    let ns = a.host.config().ssh_namespace();
    let token = a.ssh_challenge(Some(&u), NONCE);
    a.ssh_add(&c, &u, &token, NONCE, &key.ssh_public(""), &key.ssh_sign(&ns, token.as_bytes())).await.unwrap();
    let ssh = a.ssh_keys(u.id).await.unwrap()[0].ext_id.clone();
    // As if it signed up through Google.
    let google = || Credential {
        kind: "oauth:google".into(),
        ext_id: unique("g").into_bytes(),
        user_id: u.id,
        public_key: None,
        alg: 0,
        sign_count: 0,
        flags: 0,
        name: "Dee G".into(),
        created_at: util::now(),
        last_used_at: None,
        public: false,
    };
    let g = google();
    assert!(a.store.insert_credential(&g).await.unwrap());
    drop_password(&a, u.id).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(matches!(a.remove_credential(&c, &u, &g.kind, &g.ext_id).await, Err(Error::Invalid(_))), "SSH alone would be left");

    // With codes on, an older account could get to SSH alone: the codes stay.
    assert!(a.store.delete_credential(u.id, &g.kind, &g.ext_id).await.unwrap());
    exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(u.id.0.to_vec())]).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(matches!(a.totp_disable(&c, &u).await, Err(Error::Invalid(_))));
    assert!(matches!(a.remove_credential(&c, &u, "ssh", &ssh).await, Err(Error::Invalid(_))), "nor its only way in");
    let g = google();
    assert!(a.store.insert_credential(&g).await.unwrap());
    a.totp_disable(&c, &u).await.unwrap();
    a.remove_credential(&c, &u, "ssh", &ssh).await.unwrap();
    assert!(matches!(a.remove_credential(&c, &u, &g.kind, &g.ext_id).await, Err(Error::Invalid(_))), "the last way in");
    cleanup(&a, &[u.id], &[]).await;
}

// ---- mail

#[cfg(feature = "email")]
mod mail_flows {
    use super::*;
    use crate::email::{Mailer, Sent};
    use std::sync::{Arc, Mutex};

    async fn with_mail(cfg: Config) -> Option<(Accounts<Stub>, Arc<Mutex<Vec<Sent>>>)> {
        let (m, sent) = Mailer::capture();
        Some((on(shared_store().await?, cfg).await.with_mailer(m), sent))
    }

    /// Mail goes out on a spawned task: wait for message number `n`.
    async fn nth(sent: &Arc<Mutex<Vec<Sent>>>, n: usize) -> Sent {
        for _ in 0..100 {
            if let Some(m) = sent.lock().unwrap().get(n) {
                return m.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("no mail number {n}");
    }

    fn token_in(body: &str) -> String {
        body.split("?t=").nth(1).unwrap().split_whitespace().next().unwrap().to_string()
    }

    fn mail_cfg() -> Config {
        Config { base_url: "https://l4f.cc".into(), ..cfg() }
    }

    #[tokio::test]
    async fn an_address_is_confirmed_by_its_link_and_belongs_to_one_account() {
        let Some((a, sent)) = with_mail(mail_cfg()).await else { return };
        let c = ctx("203.0.113.90");
        let u = make_user(&a, &[]).await;
        let addr = format!("{}@example.org", unique("m"));
        a.email_set(&c, &u, &format!(" {} ", addr.to_uppercase())).await.unwrap();
        let m = nth(&sent, 0).await;
        assert_eq!(m.to, addr);
        assert!(m.body.contains("https://l4f.cc/account/verify-email?t=") && m.body.contains(&u.username));
        let t = token_in(&m.body);
        assert_eq!(a.store.user_by_id(u.id).await.unwrap().unwrap().email_pending.as_deref(), Some(addr.as_str()));
        assert!(matches!(a.email_confirm(&c, &format!("{t}x")).await, Err(Error::Invalid(_))), "a forged link");
        a.email_confirm(&c, &t).await.unwrap();
        let v = a.store.user_by_id(u.id).await.unwrap().unwrap();
        assert_eq!((v.email.as_deref(), v.email_pending.as_deref()), (Some(addr.as_str()), None));
        assert!(matches!(a.email_confirm(&c, &t).await, Err(Error::Invalid(_))), "used up: nothing pending");

        let other = make_user(&a, &[]).await;
        a.email_set(&c, &other, &addr).await.unwrap();
        let t2 = token_in(&nth(&sent, 1).await.body);
        assert!(matches!(a.email_confirm(&c, &t2).await, Err(Error::Invalid("That address belongs to another account."))));
        assert!(matches!(a.email_set(&c, &other, &addr).await, Err(Error::RateLimited) | Ok(())));
        cleanup(&a, &[u.id, other.id], &[]).await;
    }

    #[tokio::test]
    async fn a_reset_link_sets_a_password_once_and_signs_everything_out() {
        let Some((a, sent)) = with_mail(mail_cfg()).await else { return };
        let c = ctx("203.0.113.91");
        let u = make_user(&a, &[]).await;
        let addr = format!("{}@example.org", unique("r"));
        a.email_set(&c, &u, &addr).await.unwrap();
        a.email_confirm(&c, &token_in(&nth(&sent, 0).await.body)).await.unwrap();
        let s = signed_in(a.login_password(&c, &u.username, PW, None).await);

        a.password_forgot(&c, "nobody-at-all").await.unwrap();
        a.password_forgot(&c, &addr.to_uppercase()).await.unwrap();
        let m = nth(&sent, 1).await;
        assert!(m.body.contains("/account/reset?t="));
        assert_eq!(sent.lock().unwrap().len(), 2, "nothing for a name nobody has");
        let t = token_in(&m.body);
        assert!(matches!(a.password_reset(&c, &t, "short").await, Err(Error::Invalid(_))));
        a.password_reset(&c, &t, "a whole new password").await.unwrap();
        assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_none(), "every session went");
        assert!(matches!(a.password_reset(&c, &t, "yet another password").await, Err(Error::Invalid(_))), "once");
        assert!(matches!(a.login_password(&c, &u.username, PW, None).await, Err(Error::BadLogin)));
        signed_in(a.login_password(&c, &u.username, "a whole new password", None).await);
        assert!(nth(&sent, 2).await.body.contains("with a reset link"), "the owner is told");
        cleanup(&a, &[u.id], &[]).await;
    }

    #[tokio::test]
    async fn changing_the_password_keeps_this_session_only() {
        let Some((a, _)) = with_mail(mail_cfg()).await else { return };
        let c = ctx("203.0.113.92");
        let u = make_user(&a, &[]).await;
        let here = signed_in(a.login_password(&c, &u.username, PW, None).await);
        let there = signed_in(a.login_password(&c, &u.username, PW, None).await);
        assert!(matches!(a.password_change(&c, &u, &here.info, "tiny").await, Err(Error::Invalid(_))));
        a.password_change(&c, &u, &here.info, "brand new password").await.unwrap();
        assert!(a.session_from_token(&here.token, util::now()).await.unwrap().is_some());
        assert!(a.session_from_token(&there.token, util::now()).await.unwrap().is_none());
        signed_in(a.login_password(&c, &u.username, "brand new password", None).await);
        cleanup(&a, &[u.id], &[]).await;
    }
}

// ---- social sign-in

// The stand-in provider is an axum app.
#[cfg(all(feature = "oauth", feature = "axum"))]
mod social_flows {
    use super::*;
    use crate::oauth::{Kind, Provider};
    use axum::{Json, Router, extract::State as AxState, routing::{get, post}};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Fake {
        subject: String,
        nonce: String,
        auth_time: i64,
    }

    type Shared = Arc<Mutex<Fake>>;

    async fn d_token() -> Json<serde_json::Value> {
        Json(serde_json::json!({ "access_token": "at", "token_type": "Bearer" }))
    }

    async fn d_profile(AxState(f): AxState<Shared>) -> Json<serde_json::Value> {
        let s = f.lock().unwrap().subject.clone();
        Json(serde_json::json!({ "id": s, "username": "dee_d", "global_name": "Dee D" }))
    }

    async fn g_token(AxState(f): AxState<Shared>) -> Json<serde_json::Value> {
        let f = f.lock().unwrap();
        let claims = serde_json::json!({ "iss": "https://accounts.google.com", "aud": "client", "exp": util::now() + 600,
            "sub": f.subject, "nonce": f.nonce, "name": "Dee G", "auth_time": f.auth_time });
        Json(serde_json::json!({ "id_token": format!("e30.{}.sig", util::b64u(claims.to_string().as_bytes())) }))
    }

    /// A stand-in provider on a local port, and accounts that talk to it over
    /// plain HTTP (the real client is HTTPS-only).
    async fn setup() -> Option<(Accounts<Stub>, Shared)> {
        // reqwest is built without a crypto provider: the host installs one.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let fake: Shared = Arc::default();
        let app = Router::new()
            .route("/d/token", post(d_token))
            .route("/d/profile", get(d_profile))
            .route("/g/token", post(g_token))
            .with_state(fake.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let providers = vec![Provider::at(Kind::Discord, &format!("{base}/d")), Provider::at(Kind::Google, &format!("{base}/g"))];
        let a = on(shared_store().await?, pk_cfg()).await.with_oauth(super::super::OAuth::new(http, providers));
        Some((a, fake))
    }

    fn param(url: &str, name: &str) -> String {
        url.split(['?', '&']).find_map(|kv| kv.strip_prefix(&format!("{name}="))).unwrap().to_string()
    }

    #[tokio::test]
    async fn a_new_identity_signs_up_then_signs_in() {
        let Some((a, fake)) = setup().await else { return };
        let c = ctx("203.0.113.100");
        fake.lock().unwrap().subject = unique("d");
        let (url, cookie) = a.oauth_begin(Kind::Discord, Intent::Login, None, "/account/security").unwrap();
        let state = param(&url, "state");
        assert!(url.contains("code_challenge="));
        assert!(matches!(a.oauth_finish(&c, Kind::Discord, &cookie, "wrong", "code", None).await, Err(Error::Invalid(_))), "state");
        assert!(matches!(a.oauth_finish(&c, Kind::Google, &cookie, &state, "code", None).await, Err(Error::Invalid(_))), "provider");
        let (out, next) = a.oauth_finish(&c, Kind::Discord, &cookie, &state, "code", None).await.unwrap();
        assert_eq!(next, "/account/security");
        let SocialOutcome::Signup { cookie: signup } = out else { panic!("expected the username page") };
        assert_eq!(a.oauth_signup_suggestion(&signup).as_deref(), Some("deed"), "the display name, in the username alphabet");
        let ts = pow::stamp(POW_KEY, util::now_secs() - 5);
        let altcha = solve(&pow::issue(POW_KEY, 1000, 600));
        let name = unique("o");
        let s = a.oauth_signup(&c, &signup, &name, pow::Proof { altcha: &altcha, ts: &ts, ..pow::Proof::default() }).await.unwrap();
        assert!(s.info.mfa_ok && s.info.auth_at == 0 && s.info.method == "oauth");
        let u = a.store.user_by_username(&name).await.unwrap().unwrap();
        assert!(!u.has_password && u.display_name == "Dee D");

        let (url, cookie) = a.oauth_begin(Kind::Discord, Intent::Login, None, "").unwrap();
        let (out, _) = a.oauth_finish(&c, Kind::Discord, &cookie, &param(&url, "state"), "code", None).await.unwrap();
        assert!(matches!(out, SocialOutcome::Signed(LoginStep::Done(_))), "the same identity signs in now");

        exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(u.id.0.to_vec())]).await;
        let (url, cookie) = a.oauth_begin(Kind::Discord, Intent::Login, None, "").unwrap();
        let (out, _) = a.oauth_finish(&c, Kind::Discord, &cookie, &param(&url, "state"), "code", None).await.unwrap();
        assert!(matches!(out, SocialOutcome::Signed(LoginStep::NeedMfa(_))), "a first factor only, with 2FA on");
        cleanup(&a, &[u.id], &[]).await;
    }

    #[tokio::test]
    async fn linking_needs_a_recent_sign_in_and_an_identity_has_one_account() {
        let Some((a, fake)) = setup().await else { return };
        let c = ctx("203.0.113.101");
        fake.lock().unwrap().subject = unique("d");
        let u = make_user(&a, &[]).await;
        let now = util::now();
        let fresh = a.create_session(u.id, "password", true, now, &c).await.unwrap();
        let stale = a.create_session(u.id, "password", true, now - 3600, &c).await.unwrap();
        let (url, cookie) = a.oauth_begin(Kind::Discord, Intent::Link, Some(&u), "").unwrap();
        let st = param(&url, "state");
        assert!(matches!(a.oauth_finish(&c, Kind::Discord, &cookie, &st, "code", Some((&u, &stale.info))).await, Err(Error::Invalid(_))));
        let other = make_user(&a, &[]).await;
        assert!(matches!(a.oauth_finish(&c, Kind::Discord, &cookie, &st, "code", Some((&other, &fresh.info))).await, Err(Error::Forbidden)), "started by u");
        let (out, _) = a.oauth_finish(&c, Kind::Discord, &cookie, &st, "code", Some((&u, &fresh.info))).await.unwrap();
        assert!(matches!(out, SocialOutcome::Linked));
        assert_eq!(a.oauth_linked(u.id).await.unwrap()[0].1.name, "Dee D");
        let other_s = a.create_session(other.id, "password", true, now, &c).await.unwrap();
        let (url, cookie) = a.oauth_begin(Kind::Discord, Intent::Link, Some(&other), "").unwrap();
        assert!(
            matches!(a.oauth_finish(&c, Kind::Discord, &cookie, &param(&url, "state"), "code", Some((&other, &other_s.info))).await, Err(Error::Invalid(_))),
            "one identity, one account"
        );
        cleanup(&a, &[u.id, other.id], &[]).await;
    }

    #[tokio::test]
    async fn a_google_step_up_needs_a_fresh_sign_in_there() {
        let Some((a, fake)) = setup().await else { return };
        let c = ctx("203.0.113.102");
        let sub = unique("g");
        fake.lock().unwrap().subject = sub.clone();
        let u = make_user(&a, &[]).await;
        let s = a.create_session(u.id, "password", true, util::now(), &c).await.unwrap();
        let (url, cookie) = a.oauth_begin(Kind::Google, Intent::Link, Some(&u), "").unwrap();
        fake.lock().unwrap().nonce = param(&url, "nonce");
        a.oauth_finish(&c, Kind::Google, &cookie, &param(&url, "state"), "code", Some((&u, &s.info))).await.unwrap();

        let (url, cookie) = a.oauth_begin(Kind::Google, Intent::Reauth, Some(&u), "/account/delete").unwrap();
        assert!(url.contains("max_age=0"));
        {
            let mut f = fake.lock().unwrap();
            f.nonce = param(&url, "nonce");
            f.auth_time = util::now() - 3600;
        }
        let st = param(&url, "state");
        assert!(matches!(a.oauth_finish(&c, Kind::Google, &cookie, &st, "code", Some((&u, &s.info))).await, Err(Error::Invalid(_))), "an old sign-in");
        fake.lock().unwrap().auth_time = util::now();
        let (out, next) = a.oauth_finish(&c, Kind::Google, &cookie, &st, "code", Some((&u, &s.info))).await.unwrap();
        let SocialOutcome::SteppedUp(up) = out else { panic!("expected a step-up") };
        assert!(a.fresh(&up.info, util::now()) && next == "/account/delete");
        cleanup(&a, &[u.id], &[]).await;
    }
}

// ---- storage

#[tokio::test]
async fn synced_settings_are_compare_and_set_and_go_with_sync() {
    let Some(a) = shared(Config { storage_quota_bytes: 40 * 1024, ..cfg() }).await else { return };
    let c = ctx("203.0.113.110");
    let u = make_user(&a, &[]).await;
    // The built-in user role carries these on a fresh install; the shared test
    // database seeded it long ago, so the scopes are given here.
    assert!(Config::default().default_user_scopes.contains(&"storage:sync".to_string()));
    let scopes = strings(&["storage:sync"]);
    assert!(matches!(a.kv_put(&u, &scopes, "links:v1", b"[]", 0).await, Err(Error::Invalid("Sync is off."))));
    a.sync_set(&c, &u, &scopes, true).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    let Put::Done(v1) = a.kv_put(&u, &scopes, "links:v1", b"[1]", 0).await.unwrap() else { panic!("created") };
    assert!(matches!(a.kv_put(&u, &scopes, "links:v1", b"[2]", 0).await.unwrap(), Put::Conflict(Some(b)) if b.v == b"[1]"), "create finds it");
    let Put::Done(v2) = a.kv_put(&u, &scopes, "links:v1", b"[2]", v1).await.unwrap() else { panic!("replaced") };
    assert!(matches!(a.kv_put(&u, &scopes, "links:v1", b"[3]", v1).await.unwrap(), Put::Conflict(Some(b)) if b.version == v2), "stale version");
    assert!(matches!(a.kv_put(&u, &scopes, "links:v1", b"not json", v2).await, Err(Error::Invalid(_))));
    assert!(matches!(a.kv_put(&u, &scopes, "Bad Key", b"1", 0).await, Err(Error::Invalid(_))));
    let big = format!("\"{}\"", "x".repeat(KV_MAX_BYTES));
    assert!(matches!(a.kv_put(&u, &scopes, "big", big.as_bytes(), 0).await, Err(Error::Invalid(_))), "32 KiB a key");
    let half = format!("\"{}\"", "x".repeat(30 * 1024));
    assert!(matches!(a.kv_put(&u, &scopes, "a", half.as_bytes(), 0).await.unwrap(), Put::Done(_)));
    assert!(matches!(a.kv_put(&u, &scopes, "b", half.as_bytes(), 0).await, Err(Error::Invalid("Your storage is full."))), "the quota");
    assert_eq!(a.kv_list(&u, &scopes).await.unwrap().len(), 2);
    assert!(a.kv_delete(&u, &scopes, "a", 0).await.unwrap());
    a.sync_set(&c, &u, &scopes, false).await.unwrap();
    assert_eq!(a.store.blob_count(u.id, "kv").await.unwrap(), 0, "the server's copy goes with sync");
    assert!(matches!(a.kv_list(&u, &[]).await, Err(Error::Forbidden)), "needs storage:sync");
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn the_vault_takes_ciphertext_shaped_entries_only() {
    let Some(a) = shared(cfg()).await else { return };
    let c = ctx("203.0.113.111");
    let u = make_user(&a, &[]).await;
    let scopes = strings(&["vault:use"]);
    let slot_id = util::b64u(&util::random::<16>());
    let slot = serde_json::json!({ "v": 1, "id": slot_id, "kind": "pass", "kdf": { "alg": "PBKDF2-SHA256", "iter": 600000 } }).to_string();
    assert!(matches!(a.vault_put(&u, &scopes, true, &slot_id, slot.as_bytes(), 0).await.unwrap(), Put::Done(1)));
    let weak = slot.replace("600000", "1000");
    assert!(matches!(a.vault_put(&u, &scopes, true, &slot_id, weak.as_bytes(), 1).await, Err(Error::Invalid(_))));
    let item_k = format!("totp.{}", util::b64u(&util::random::<16>()));
    let mut item = vec![1u8];
    item.extend(util::random::<40>());
    assert!(matches!(a.vault_put(&u, &scopes, false, &item_k, &item, 0).await.unwrap(), Put::Done(1)));
    assert!(matches!(a.vault_put(&u, &scopes, false, "evil.AAAAAAAAAAAAAAAAAAAAAA", &item, 0).await, Err(Error::Invalid(_))));
    assert!(matches!(a.vault_put(&u, &scopes, false, &item_k, &[2u8; 40], 1).await, Err(Error::Invalid(_))), "version byte");
    let (slots, items) = a.vault_list(&u, &scopes).await.unwrap();
    assert_eq!((slots.len(), items.len()), (1, 1));
    a.vault_wipe(&c, &u, &scopes).await.unwrap();
    let (slots, items) = a.vault_list(&u, &scopes).await.unwrap();
    assert!(slots.is_empty() && items.is_empty());
    assert!(matches!(a.vault_list(&u, &["storage:sync".to_string()]).await, Err(Error::Forbidden)), "needs vault:use");
    cleanup(&a, &[u.id], &[]).await;
}

// ---- profile

fn png() -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    b.extend([0u8; 64]);
    b
}

#[tokio::test]
async fn a_profile_shows_what_its_owner_chose_behind_a_rotatable_link() {
    let Some(a) = shared(Config { require_2fa_for_privileged: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.120");
    let role = make_role(&a, &["profile:public"]).await;
    a.store.update_role(a.store.role_by_name(&role).await.unwrap().unwrap().id, "", Some("Helper")).await.unwrap();
    let u = make_user(&a, &[&role]).await;
    let scopes = a.effective_scopes(&u).await.unwrap();
    assert!(matches!(a.profile_save(&c, &u, &[], true, "", true).await, Err(Error::Forbidden)), "needs profile:public");
    a.profile_save(&c, &u, &scopes, true, "Hello\r\nthere", true).await.unwrap();
    let id = a.profile_settings(u.id).await.unwrap().public_id.unwrap();
    let link = uuid_of(&id);
    let p = a.public_profile(&link).await.unwrap().unwrap();
    assert_eq!((p.display_name.as_str(), p.bio.as_str(), p.badges.clone()), ("T", "Hello\nthere", vec!["Helper".to_string()]));
    assert!(!p.avatar);
    a.profile_save(&c, &u, &scopes, true, "Hello", false).await.unwrap();
    assert!(a.public_profile(&link).await.unwrap().unwrap().badges.is_empty(), "badges hidden");
    assert_eq!(a.profile_settings(u.id).await.unwrap().public_id, Some(id), "saving keeps the link");

    a.profile_rotate(&c, &u).await.unwrap();
    assert!(a.public_profile(&link).await.unwrap().is_none(), "the old link is dead");
    let new = uuid_of(&a.profile_settings(u.id).await.unwrap().public_id.unwrap());
    assert!(a.public_profile(&new).await.unwrap().is_some());

    a.avatar_put(&c, &u, &scopes, &png()).await.unwrap();
    assert_eq!(a.avatar(u.id).await.unwrap().unwrap().1, "image/png");
    assert!(a.public_profile(&new).await.unwrap().unwrap().avatar);
    assert!(matches!(a.avatar_put(&c, &u, &scopes, b"<svg/>").await, Err(Error::Invalid(_))));
    assert!(matches!(a.avatar_put(&c, &u, &scopes, &[png(), vec![0; 70_000]].concat()).await, Err(Error::Invalid(_))));

    // Losing the scope hides the profile; switching it off drops the link.
    a.store.revoke_role(u.id, a.store.role_by_name(&role).await.unwrap().unwrap().id).await.unwrap();
    assert!(a.public_profile(&new).await.unwrap().is_none());
    a.profile_save(&c, &u, &scopes, false, "", true).await.unwrap();
    assert!(a.profile_settings(u.id).await.unwrap().public_id.is_none());
    cleanup(&a, &[u.id], &[&role]).await;
}

async fn invite_signup(a: &Accounts<Stub>, c: &Ctx, code: &str, name: &str) -> Result<NewSession, Error> {
    a.register_invite(c, InviteForm { code, username: name, password: PW, email: None, display_name: None }).await
}

fn invite_id(code: &str) -> String {
    hex::encode(sha2::Sha256::digest(util::b64u_dec(code).unwrap()))
}

#[tokio::test]
async fn invites_open_closed_sign_up_once_and_bind_names() {
    let Some(a) = shared(Config { registration_open: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.90");
    let role = make_role(&a, &["users:admin"]).await;
    let boss = make_user(&a, &[&role, "user"]).await;
    let scopes = a.effective_scopes(&boss).await.unwrap();
    let actor = Actor { user: &boss, scopes: &scopes };
    let nobody = make_user(&a, &[]).await;
    let none: Vec<String> = Vec::new();
    assert!(matches!(a.invite_create(&c, Actor { user: &nobody, scopes: &none }, None, 7).await, Err(Error::Forbidden)));
    // Each invite makes an account with the `user` role: the inviter covers
    // it, as `grant_role` would ask (ADMIN-7).
    let admin_only = strings(&["users:admin"]);
    assert!(matches!(a.invite_create(&c, Actor { user: &boss, scopes: &admin_only }, None, 7).await, Err(Error::Forbidden)));

    let code = a.invite_create(&c, actor, None, 7).await.unwrap();
    assert_eq!(code.len(), 22);
    assert!(matches!(err(invite_signup(&a, &c, "AAAAAAAAAAAAAAAAAAAAAA", &unique("i")).await), Error::Invalid(_)), "an unknown code");
    assert!(matches!(err(invite_signup(&a, &c, "short", &unique("i")).await), Error::Invalid(_)));
    // A taken name refuses and leaves the code for another try.
    assert!(matches!(err(invite_signup(&a, &c, &code, &nobody.username).await), Error::UsernameTaken));
    let name = unique("i");
    let s = invite_signup(&a, &c, &code, &name).await.expect("sign-up is closed, the invite opens it");
    let (user, _, granted) = a.session_from_token(&s.token, util::now()).await.unwrap().unwrap();
    assert_eq!(user.username, name);
    let mut plain = a.host.cfg.default_user_scopes.clone();
    plain.sort();
    assert_eq!(granted, plain, "the plain user role");
    assert!(matches!(err(invite_signup(&a, &c, &code, &unique("i")).await), Error::Invalid(_)), "single use");
    let listed = a.invites(actor).await.unwrap();
    let mine = listed.iter().find(|i| i.id == invite_id(&code)).expect("listed");
    assert_eq!((mine.used_by, mine.created_by), (Some(user.id), Some(boss.id)));

    let bound_name = unique("b");
    let bound = a.invite_create(&c, actor, Some(&bound_name.to_uppercase()), 7).await.unwrap();
    assert!(matches!(err(invite_signup(&a, &c, &bound, &unique("x")).await), Error::Invalid(_)), "bound to one name");
    let b = invite_signup(&a, &c, &bound, &bound_name).await.unwrap();
    assert!(matches!(a.invite_create(&c, actor, Some(&bound_name), 7).await, Err(Error::UsernameTaken)), "a name in use");

    let revoked = a.invite_create(&c, actor, None, 7).await.unwrap();
    assert!(a.invite_revoke(&c, actor, &invite_id(&revoked)).await.unwrap());
    assert!(!a.invite_revoke(&c, actor, &invite_id(&revoked)).await.unwrap());
    assert!(matches!(err(invite_signup(&a, &c, &revoked, &unique("r")).await), Error::Invalid(_)));
    let b_id = a.session_from_token(&b.token, util::now()).await.unwrap().unwrap().0.id;
    cleanup(&a, &[boss.id, nobody.id, user.id, b_id], &[&role]).await;
}

#[tokio::test]
async fn the_host_issues_invites_without_an_admin() {
    let Some(a) = shared(Config { registration_open: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.93");
    let name = unique("h");
    let code = a.invite_create_as_host(&c, Some(&name), 7).await.unwrap();
    let s = invite_signup(&a, &c, &code, &name).await.expect("a host invite opens sign-up");
    let user = a.session_from_token(&s.token, util::now()).await.unwrap().unwrap().0;
    assert!(matches!(err(invite_signup(&a, &c, &code, &name).await), Error::Invalid(_)), "single use");
    let sql = "SELECT COUNT(*) FROM acct_audit WHERE event = 'invite_create' AND actor_id IS NULL AND detail = ?";
    assert_eq!(scalar(&a.store, sql, vec![Arg::S(format!("{name} (host)"))]).await, 1, "marked as the host's (ADMIN-12)");
    cleanup(&a, &[user.id], &[]).await;
}

#[tokio::test]
async fn invite_codes_expire() {
    let Some(a) = shared(Config { registration_open: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.91");
    let role = make_role(&a, &["users:admin"]).await;
    let boss = make_user(&a, &[&role, "user"]).await;
    let scopes = a.effective_scopes(&boss).await.unwrap();
    let code = a.invite_create(&c, Actor { user: &boss, scopes: &scopes }, None, 1).await.unwrap();
    exec(&a.store, "UPDATE acct_invites SET expires_at = 1 WHERE code_hash = ?", vec![Arg::B(hex::decode(invite_id(&code)).unwrap())]).await;
    assert!(matches!(err(invite_signup(&a, &c, &code, &unique("e")).await), Error::Invalid(_)));
    cleanup(&a, &[boss.id], &[&role]).await;
}

/// A wrong code or a taken name is refused before the password is hashed:
/// with both Argon2 slots held they still get their own answer, and only a
/// good code for a free name gets as far as the hash (ADMIN-4, AUTH-6).
#[tokio::test]
async fn an_invite_is_checked_before_its_password_is_hashed() {
    let Some(a) = shared(Config { registration_open: false, ..cfg() }).await else { return };
    let c = ctx("203.0.113.98");
    let taken = make_user(&a, &[]).await;
    let code = a.invite_create_as_host(&c, None, 7).await.unwrap();
    let held = a.hash_permits.clone().try_acquire_many_owned(2).unwrap();
    assert!(matches!(err(invite_signup(&a, &c, "AAAAAAAAAAAAAAAAAAAAAA", &unique("i")).await), Error::Invalid(_)), "a wrong code");
    assert!(matches!(err(invite_signup(&a, &c, &code, &taken.username).await), Error::UsernameTaken), "a taken name");
    assert!(matches!(err(invite_signup(&a, &c, &code, &unique("i")).await), Error::Busy), "a good one reaches the hash");
    drop(held);
    let s = invite_signup(&a, &c, &code, &unique("i")).await.expect("none of that spent the code");
    let user = a.session_from_token(&s.token, util::now()).await.unwrap().unwrap().0;
    cleanup(&a, &[taken.id, user.id], &[]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_grant_makes_one_admin_of_an_empty_site() {
    let Some(f) = fresh().await else { return };
    let a = Arc::new(on(f.store.clone(), cfg()).await);
    let c = ctx("203.0.113.92");
    let off = make_user(&a, &[]).await;
    a.store.set_status(off.id, UserStatus::Disabled).await.unwrap();
    assert!(!a.bootstrap_grant(&c, off.id).await.unwrap(), "a disabled account cannot become the admin");
    let (u1, u2) = (make_user(&a, &[]).await, make_user(&a, &[]).await);
    let grant = |id| {
        let a = a.clone();
        tokio::spawn(async move { a.bootstrap_grant(&ctx("203.0.113.92"), id).await.unwrap() })
    };
    let (r1, r2) = (grant(u1.id), grant(u2.id));
    let mut got = [r1.await.unwrap(), r2.await.unwrap()];
    got.sort();
    assert_eq!(got, [false, true], "racing grants make one admin");
    assert_eq!(a.store.holders_of_scope_star().await.unwrap(), 1);
    let third = make_user(&a, &[]).await;
    assert!(!a.bootstrap_grant(&c, third.id).await.unwrap(), "nothing to do once someone holds *");
    drop(a);
    f.done().await;
}

#[tokio::test]
async fn reset_2fa_clears_codes_device_keys_and_sessions() {
    let narrow = Config { require_2fa_for_privileged: true, default_user_scopes: strings(&["t:one"]), ..cfg() };
    let Some(a) = shared(narrow).await else { return };
    let c = ctx("203.0.113.93");
    let role = make_role(&a, &["t:one", "t:two"]).await;
    let u = make_user(&a, &[&role]).await;
    assert!(a.needs_2fa(&u).await.unwrap(), "a privileged scope without a second factor");
    let plain = make_user(&a, &[]).await;
    assert!(!a.needs_2fa(&plain).await.unwrap());

    let setup = a.totp_setup(&u);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &code).await.unwrap();
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(!a.needs_2fa(&u).await.unwrap());
    a.store.insert_session(&sess(u.id, util::now(), util::now() + 100)).await.unwrap();

    let admin_role = make_role(&a, &["users:admin", "t:*"]).await;
    let boss = make_user(&a, &[&admin_role]).await;
    exec(&a.store, "UPDATE acct_users SET totp_enc = ? WHERE id = ?", vec![Arg::B(vec![0]), Arg::B(boss.id.0.to_vec())]).await;
    let boss = a.store.user_by_id(boss.id).await.unwrap().unwrap();
    let scopes = a.effective_scopes(&boss).await.unwrap();
    let weak: Vec<String> = strings(&["users:admin"]);
    assert!(matches!(a.reset_2fa(&c, Actor { user: &boss, scopes: &weak }, u.id).await, Err(Error::Forbidden)), "must cover the target");
    let sql = "INSERT INTO acct_credentials (kind, ext_id, user_id, created_at) VALUES ('devkey', ?, ?, 1)";
    exec(&a.store, sql, vec![Arg::B(util::random::<16>().to_vec()), Arg::B(u.id.0.to_vec())]).await;
    assert!(a.reset_2fa(&c, Actor { user: &boss, scopes: &scopes }, u.id).await.unwrap());
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(!u.totp_enabled && a.needs_2fa(&u).await.unwrap(), "back to needing one");
    assert_eq!(a.store.recovery_left(u.id).await.unwrap(), 0);
    assert!(a.store.sessions_of(u.id).await.unwrap().is_empty() && a.devkeys(u.id).await.unwrap().is_empty());
    assert!(!a.reset_2fa(&c, Actor { user: &boss, scopes: &scopes }, u.id).await.unwrap(), "already off");
    let log = a.store.audit_of(u.id, 50).await.unwrap();
    assert!(log.iter().any(|e| e.event == "totp_reset" && e.actor_id == Some(boss.id)));
    // The admin forgot the device keys, not the account: its history shows
    // no address of the admin's (ADMIN-6).
    let forgot = log.iter().find(|e| e.event == "devkey_revoke").expect("the device key went");
    assert_eq!((forgot.actor_id, forgot.ip.as_str()), (Some(boss.id), ""));
    cleanup(&a, &[u.id, plain.id, boss.id], &[&role, &admin_role]).await;
}

/// The lost second factor may be a passkey alone: the reset goes on with
/// codes off, takes the passkey and the recovery codes, and the next
/// sign-in is by password (ADMIN-11).
#[tokio::test]
async fn reset_2fa_takes_a_passkey_too() {
    let Some(a) = shared(pk_cfg()).await else { return };
    let c = ctx("203.0.113.99");
    let u = make_user(&a, &[]).await;
    add_passkey(&a, &c, &u).await;
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    a.recovery_regenerate(&c, &u).await.unwrap();
    assert!(!u.totp_enabled && u.has_passkey);
    assert!(matches!(a.login_password(&c, &u.username, PW, None).await, Ok(LoginStep::NeedMfa(_))));
    assert!(a.reset_2fa_as_host(&c, u.id).await.unwrap(), "codes were off, a passkey was there");
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(!has_second_factor(&u) && a.passkeys(u.id).await.unwrap().is_empty());
    assert_eq!(a.recovery_left(u.id).await.unwrap(), 0);
    assert!(a.store.sessions_of(u.id).await.unwrap().is_empty(), "the pending sign-in went too");
    assert!(!a.reset_2fa_as_host(&c, u.id).await.unwrap(), "nothing left to remove");
    signed_in(a.login_password(&c, &u.username, PW, None).await);
    cleanup(&a, &[u.id], &[]).await;
}

#[tokio::test]
async fn the_host_grants_resets_and_revokes_without_an_admin() {
    let narrow = Config { require_2fa_for_privileged: true, default_user_scopes: strings(&["t:one"]), ..cfg() };
    let Some(a) = shared(narrow).await else { return };
    let c = ctx("203.0.113.94");
    let role = make_role(&a, &["t:one", "t:two"]).await;
    let u = make_user(&a, &[]).await;
    assert!(a.grant_role_as_host(&c, u.id, &role).await.unwrap());
    assert!(!a.grant_role_as_host(&c, u.id, &role).await.unwrap(), "held already");
    assert!(a.store.user_scopes(u.id).await.unwrap().contains(&"t:two".to_string()));
    // Codes on, then off again from the shell: the way back in after a lost phone.
    let setup = a.totp_setup(&u);
    let code = format!("{:06}", crate::totp::code_at(&totp_secret(&setup), step_now()));
    a.totp_enable(&c, &u, &full_session(&a, &c, &u).await, &setup.sealed, &code).await.unwrap();
    a.store.insert_session(&sess(u.id, util::now(), util::now() + 100)).await.unwrap();
    assert!(a.reset_2fa_as_host(&c, u.id).await.unwrap());
    let u = a.store.user_by_id(u.id).await.unwrap().unwrap();
    assert!(!u.totp_enabled);
    assert!(a.store.sessions_of(u.id).await.unwrap().is_empty(), "signed out everywhere");
    assert!(!a.reset_2fa_as_host(&c, u.id).await.unwrap(), "already off");
    a.store.insert_session(&sess(u.id, util::now(), util::now() + 100)).await.unwrap();
    assert!(a.revoke_role_as_host(&c, u.id, &role).await.unwrap());
    assert!(a.store.sessions_of(u.id).await.unwrap().is_empty(), "the loss counts at once");
    assert!(!a.revoke_role_as_host(&c, u.id, &role).await.unwrap(), "gone already");
    // No actor, and the detail says who instead (ADMIN-12).
    let log = a.store.audit_of(u.id, 50).await.unwrap();
    for e in ["role_grant", "totp_reset", "role_revoke"] {
        let row = log.iter().find(|r| r.event == e).unwrap_or_else(|| panic!("no {e}: {log:?}"));
        assert!(row.actor_id.is_none() && row.detail.ends_with("(host)"), "{e}: {:?}", row.detail);
    }
    assert!(matches!(a.grant_role_as_host(&c, u.id, "no-such-role").await, Err(Error::NotFound)));
    cleanup(&a, &[u.id], &[&role]).await;
}

/// What fail2ban and journal greps read: `ip=` bare, `outcome=` the event.
/// The actor shows only when it is someone else, the detail only when set.
#[test]
fn the_journal_line_keeps_ip_and_outcome() {
    let (u, boss) = (AccountId([1; 16]), AccountId([2; 16]));
    let lines = crate::testkit::logged(|| {
        event_line("203.0.113.9", Some(u), Some(u), "session_revoke", "");
        event_line("203.0.113.9", Some(u), Some(boss), "role_grant", "mod");
    });
    let (u, boss) = (u.hex(), boss.hex());
    assert_eq!(lines, [
        format!(r#"ip=203.0.113.9 outcome="session_revoke" user={u}"#),
        format!(r#"ip=203.0.113.9 outcome="role_grant" actor={boss} user={u} detail="mod""#),
    ]);
}

/// Per address the key is `kind:address`, per account `kind-id:x`. An invite
/// try counts under the one kind `acct-inv`, not under a kind of its own per
/// address that no per-kind cap ever reaches (GATES-2).
#[tokio::test]
async fn gates_count_per_address_or_per_account() {
    let Some(a) = shared(cfg()).await else { return };
    assert!(matches!(err(invite_signup(&a, &ctx("198.51.100.17"), "short", &unique("i")).await), Error::Invalid(_)));
    assert!(!a.limiter.peek("acct-inv:198.51.100.17", WINDOW, 1), "counted per address");
    assert!(a.limiter.peek("acct-inv-198.51.100.17:x", WINDOW, 1));
    let id = AccountId::new();
    assert!(a.per_account("acct-t", id, WINDOW, 1).is_ok());
    assert!(matches!(a.per_account("acct-t", id, WINDOW, 1), Err(Error::RateLimited)));
    assert!(!a.limiter.peek(&format!("acct-t-{}:x", id.hex()), WINDOW, 1));
}

fn built(store: Store, app: &[ScopeDef], pow_key: &[u8]) -> sqlx::Result<Accounts<Stub>> {
    let host = Stub { cfg: Arc::new(cfg()), deleted: StdMutex::default() };
    Accounts::new(store, Keys::new(&[7; 32], None).unwrap(), Arc::default(), host, app, Some(pow_key.to_vec()), Vec::new())
}

/// A short ALTCHA key boots, with sign-up closed: under it anyone could forge
/// the proof-of-work (GATES-4).
#[tokio::test]
async fn a_short_pow_key_keeps_sign_up_closed() {
    let Some(store) = shared_store().await else { return };
    let short = &POW_KEY[..31];
    let a = built(store, APP, short).unwrap();
    assert!(a.pow_key.is_none());
    let ts = pow::stamp(short, util::now_secs() - 5);
    let altcha = solve(&pow::issue(short, 1000, 600));
    let proof = pow::Proof { altcha: &altcha, ts: &ts, ..pow::Proof::default() };
    let form = RegisterForm { username: &unique("s"), password: PW, email: None, display_name: None, proof };
    assert!(matches!(a.register(&ctx("203.0.113.97"), form).await, Err(Error::SignupClosed)));
}

/// Grants match by name, so a second entry for a name would grant the first
/// one's power under its own description (GATES-10).
#[tokio::test]
async fn a_scope_registered_twice_is_refused() {
    let Some(store) = shared_store().await else { return };
    let crate_dup = [ScopeDef { name: "users:admin", description: "Manage the app's user list" }];
    let app_dup = [APP[0], APP[0]];
    for app in [&crate_dup[..], &app_dup[..]] {
        let e = built(store.clone(), app, POW_KEY).err().expect("refused");
        assert!(matches!(&e, sqlx::Error::InvalidArgument(m) if m.contains("registered twice")), "{e}");
    }
    assert!(built(store, APP, POW_KEY).is_ok());
}

/// A lost audit row after a commit is logged, not returned: the change
/// happened (AUTH-13). Before the change, as for a sign-in, it still refuses.
#[tokio::test]
async fn a_lost_audit_row_does_not_undo_a_committed_change() {
    let Some(f) = fresh().await else { return };
    let a = on(f.store.clone(), cfg()).await;
    let c = ctx("203.0.113.95");
    let u = make_user(&a, &[]).await;
    exec(&a.store, "DROP TABLE acct_audit", vec![]).await;
    assert!(a.bootstrap_grant(&c, u.id).await.unwrap(), "granted, and it says so");
    let name = unique("l");
    let s = register(&a, &c, &name, PW).await.expect("the account exists, so its session comes with it");
    assert!(a.session_from_token(&s.token, util::now()).await.unwrap().is_some());
    assert!(matches!(a.login_password(&c, &name, PW, None).await, Err(Error::Db(_))), "a sign-in still needs its row");
    drop(a);
    f.done().await;
}
