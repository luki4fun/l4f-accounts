//! Social sign-in: the authorization code flow with PKCE against Discord,
//! Google and Facebook, one table-driven file. What comes back is an
//! `Identity` keyed by (provider, subject); tokens are dropped right after.
//!
//! Every call goes out through a dedicated client that may reach only
//! `EGRESS_HOSTS` (through the host's SNI forwarder when one is configured),
//! never follows redirects and speaks HTTPS only. Google's identity comes
//! from the id_token in the token response alone: received from the token
//! endpoint over TLS, its signature need not be checked (OIDC Core 3.1.3.7),
//! but issuer, audience, expiry and nonce are.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::util::{self, b64u};

/// Every host a provider call may reach; the nginx egress allow-list lists
/// the same. A test checks every endpoint below is in here.
pub const EGRESS_HOSTS: &[&str] = &["discord.com", "oauth2.googleapis.com", "graph.facebook.com"];

/// Bodies larger than this are not a token or a profile.
const MAX_BODY: usize = 64 * 1024;
const FB_VERSION: &str = "v21.0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Discord,
    Google,
    Facebook,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Discord, Kind::Google, Kind::Facebook];

    pub fn slug(self) -> &'static str {
        match self {
            Kind::Discord => "discord",
            Kind::Google => "google",
            Kind::Facebook => "facebook",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Discord => "Discord",
            Kind::Google => "Google",
            Kind::Facebook => "Facebook",
        }
    }

    pub fn from_slug(s: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.slug() == s)
    }

    /// The credential kind its identities are stored under.
    pub fn credential_kind(self) -> String {
        format!("oauth:{}", self.slug())
    }
}

/// One configured provider. The endpoints are fields so tests can point
/// them at a local stand-in; production uses the constructors.
pub struct Provider {
    pub kind: Kind,
    pub client_id: String,
    client_secret: String,
    pub authorize_url: String,
    pub token_url: String,
    pub profile_url: String,
}

impl Provider {
    pub fn new(kind: Kind, client_id: String, client_secret: String) -> Provider {
        let (authorize_url, token_url, profile_url) = match kind {
            Kind::Discord => (
                "https://discord.com/oauth2/authorize".to_string(),
                "https://discord.com/api/oauth2/token".to_string(),
                "https://discord.com/api/users/@me".to_string(),
            ),
            Kind::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                "https://oauth2.googleapis.com/token".to_string(),
                String::new(),
            ),
            Kind::Facebook => (
                format!("https://www.facebook.com/{FB_VERSION}/dialog/oauth"),
                format!("https://graph.facebook.com/{FB_VERSION}/oauth/access_token"),
                format!("https://graph.facebook.com/{FB_VERSION}/me"),
            ),
        };
        Provider { kind, client_id, client_secret, authorize_url, token_url, profile_url }
    }

    /// For tests: the same provider against other endpoints.
    #[cfg(test)]
    pub fn at(kind: Kind, base: &str) -> Provider {
        Provider {
            kind,
            client_id: "client".into(),
            client_secret: "secret".into(),
            authorize_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            profile_url: format!("{base}/profile"),
        }
    }
}

/// Who the provider says signed in. `auth_time` only from Google, and only
/// meaningful after a forced prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub handle: String,
    pub email: Option<String>,
    pub auth_time: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OAuthError {
    /// Network, TLS or timeout.
    Http(String),
    /// The provider answered with an error status.
    Status(u16),
    /// Not the JSON or JWT it should be.
    Malformed,
    /// An id_token claim failed: issuer, audience, expiry or nonce.
    Claim(&'static str),
}

/// The client every provider call goes through.
pub fn client(egress: Option<SocketAddr>) -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .timeout(Duration::from_secs(10))
        .user_agent("l4f-accounts");
    if let Some(addr) = egress {
        for h in EGRESS_HOSTS {
            b = b.resolve(h, addr);
        }
    }
    b.build()
}

/// The per-sign-in secrets, kept in the sealed flow cookie.
pub struct Flow {
    pub state: String,
    pub verifier: String,
    pub nonce: String,
}

impl Flow {
    pub fn new() -> Flow {
        Flow { state: b64u(&util::random::<16>()), verifier: b64u(&util::random::<32>()), nonce: b64u(&util::random::<16>()) }
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

/// PKCE S256.
pub fn pkce_challenge(verifier: &str) -> String {
    b64u(&Sha256::digest(verifier.as_bytes()))
}

/// Where to send the browser. `reauth` forces the provider to ask again.
pub fn authorize_url(p: &Provider, redirect_uri: &str, f: &Flow, reauth: bool) -> String {
    let enc = util::urlencode;
    let mut q = vec![
        ("response_type", "code".to_string()),
        ("client_id", p.client_id.clone()),
        ("redirect_uri", redirect_uri.to_string()),
        ("state", f.state.clone()),
        ("code_challenge", pkce_challenge(&f.verifier)),
        ("code_challenge_method", "S256".to_string()),
    ];
    match p.kind {
        Kind::Discord => {
            q.push(("scope", "identify".into()));
            if reauth {
                q.push(("prompt", "consent".into()));
            }
        }
        Kind::Google => {
            q.push(("scope", "openid profile".into()));
            q.push(("nonce", f.nonce.clone()));
            if reauth {
                q.push(("prompt", "login".into()));
                q.push(("max_age", "0".into()));
            }
        }
        Kind::Facebook => {
            q.push(("scope", "public_profile".into()));
            if reauth {
                q.push(("auth_type", "reauthenticate".into()));
            }
        }
    }
    let qs: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect();
    format!("{}?{}", p.authorize_url, qs.join("&"))
}

/// A transport error without the URL reqwest prints with it: Facebook's
/// calls carry the app secret, the code and the access token in the query.
fn net(e: reqwest::Error) -> OAuthError {
    OAuthError::Http(e.without_url().to_string())
}

async fn body(r: reqwest::Response) -> Result<Vec<u8>, OAuthError> {
    if !r.status().is_success() {
        return Err(OAuthError::Status(r.status().as_u16()));
    }
    let mut r = r;
    let mut out = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(net)? {
        out.extend_from_slice(&chunk);
        if out.len() > MAX_BODY {
            return Err(OAuthError::Malformed);
        }
    }
    Ok(out)
}

fn json<T: for<'de> Deserialize<'de>>(b: &[u8]) -> Result<T, OAuthError> {
    serde_json::from_slice(b).map_err(|_| OAuthError::Malformed)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
}

#[derive(Deserialize)]
struct FacebookUser {
    id: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GoogleClaims {
    iss: String,
    aud: String,
    exp: i64,
    sub: String,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    auth_time: Option<i64>,
}

/// The id_token's claims, checked. No signature check: it came straight from
/// the token endpoint over TLS (OIDC Core 3.1.3.7).
fn google_identity(p: &Provider, id_token: &str, nonce: &str, now: i64) -> Result<Identity, OAuthError> {
    let payload = id_token.split('.').nth(1).ok_or(OAuthError::Malformed)?;
    let c: GoogleClaims = json(&util::b64u_dec(payload).ok_or(OAuthError::Malformed)?)?;
    if c.iss != "https://accounts.google.com" && c.iss != "accounts.google.com" {
        return Err(OAuthError::Claim("iss"));
    }
    if c.aud != p.client_id {
        return Err(OAuthError::Claim("aud"));
    }
    if c.exp <= now {
        return Err(OAuthError::Claim("exp"));
    }
    if !c.nonce.as_deref().is_some_and(|n| util::ct_eq(n, nonce)) {
        return Err(OAuthError::Claim("nonce"));
    }
    let email = c.email.filter(|_| c.email_verified == Some(true));
    // The name only: a handle may become a public display name, which an
    // address must never be.
    Ok(Identity { handle: c.name.unwrap_or_default(), subject: c.sub, email, auth_time: c.auth_time })
}

/// The code for an identity: token endpoint, then the profile where the
/// provider needs one. The tokens go out of scope here.
pub async fn exchange(http: &reqwest::Client, p: &Provider, code: &str, redirect_uri: &str, f: &Flow) -> Result<Identity, OAuthError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &p.client_id),
        ("client_secret", &p.client_secret),
        ("code_verifier", &f.verifier),
    ];
    let token: TokenResponse = match p.kind {
        // Facebook's token endpoint takes a GET with the same parameters.
        Kind::Facebook => json(&body(http.get(&p.token_url).query(&form[1..]).send().await.map_err(net)?).await?)?,
        _ => json(&body(http.post(&p.token_url).form(&form).send().await.map_err(net)?).await?)?,
    };
    match p.kind {
        Kind::Google => google_identity(p, token.id_token.as_deref().ok_or(OAuthError::Malformed)?, &f.nonce, util::now()),
        Kind::Discord => {
            let at = token.access_token.ok_or(OAuthError::Malformed)?;
            let u: DiscordUser = json(&body(http.get(&p.profile_url).bearer_auth(at).send().await.map_err(net)?).await?)?;
            Ok(Identity { handle: u.global_name.unwrap_or(u.username), subject: u.id, email: None, auth_time: None })
        }
        Kind::Facebook => {
            let at = token.access_token.ok_or(OAuthError::Malformed)?;
            // appsecret_proof: a leaked access token alone cannot call the API.
            let proof = hex::encode(util::mac_raw(p.client_secret.as_bytes(), at.as_bytes()));
            let q = [("fields", "id,name"), ("access_token", at.as_str()), ("appsecret_proof", proof.as_str())];
            let u: FacebookUser = json(&body(http.get(&p.profile_url).query(&q).send().await.map_err(net)?).await?)?;
            Ok(Identity { handle: u.name.unwrap_or_default(), subject: u.id, email: None, auth_time: None })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_of(url: &str) -> &str {
        url.split("://").nth(1).unwrap().split('/').next().unwrap()
    }

    #[test]
    fn every_endpoint_host_is_on_the_egress_list() {
        for k in Kind::ALL {
            let p = Provider::new(k, "id".into(), "s".into());
            for url in [&p.token_url, &p.profile_url] {
                if !url.is_empty() {
                    assert!(EGRESS_HOSTS.contains(&host_of(url)), "{url} is not on the egress list");
                }
            }
        }
    }

    #[test]
    fn authorize_urls_carry_state_pkce_and_the_reauth_prompt() {
        let f = Flow::new();
        let g = Provider::new(Kind::Google, "gid".into(), "s".into());
        let u = authorize_url(&g, "https://l4f.cc/account/oauth/google/cb", &f, true);
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        for want in ["client_id=gid", "code_challenge_method=S256", "max_age=0", "prompt=login", &format!("state={}", f.state), &format!("nonce={}", f.nonce)] {
            assert!(u.contains(want), "{want} in {u}");
        }
        assert!(u.contains(&format!("code_challenge={}", pkce_challenge(&f.verifier))));
        assert!(!u.contains(&f.verifier), "the verifier never leaves");
        assert!(u.contains("&scope=openid+profile&"), "no address asked for: {u}");
        let d = authorize_url(&Provider::new(Kind::Discord, "d".into(), "s".into()), "x", &f, false);
        assert!(!d.contains("prompt="));
        let fb = authorize_url(&Provider::new(Kind::Facebook, "f".into(), "s".into()), "x", &f, true);
        assert!(fb.contains("auth_type=reauthenticate"));
    }

    #[test]
    fn pkce_matches_rfc_7636_appendix_b() {
        assert_eq!(pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    fn jwt(claims: serde_json::Value) -> String {
        format!("e30.{}.sig", b64u(claims.to_string().as_bytes()))
    }

    #[test]
    fn google_id_token_claims_are_checked() {
        let p = Provider::new(Kind::Google, "gid".into(), "s".into());
        let good = serde_json::json!({ "iss": "https://accounts.google.com", "aud": "gid", "exp": 2000, "sub": "123", "nonce": "n",
            "email": "a@b.c", "email_verified": true, "name": "Dee", "auth_time": 999 });
        let id = google_identity(&p, &jwt(good.clone()), "n", 1000).unwrap();
        assert_eq!(id, Identity { subject: "123".into(), handle: "Dee".into(), email: Some("a@b.c".into()), auth_time: Some(999) });
        for (field, value, claim) in [("iss", "https://evil", "iss"), ("aud", "other", "aud"), ("nonce", "m", "nonce")] {
            let mut bad = good.clone();
            bad[field] = value.into();
            assert_eq!(google_identity(&p, &jwt(bad), "n", 1000), Err(OAuthError::Claim(claim)));
        }
        assert_eq!(google_identity(&p, &jwt(good.clone()), "n", 2000), Err(OAuthError::Claim("exp")));
        let mut nameless = good.clone();
        nameless.as_object_mut().unwrap().remove("name");
        assert_eq!(google_identity(&p, &jwt(nameless), "n", 1000).unwrap().handle, "", "never the address");
        let mut unverified = good;
        unverified["email_verified"] = false.into();
        assert_eq!(google_identity(&p, &jwt(unverified), "n", 1000).unwrap().email, None, "an unverified address is dropped");
        assert_eq!(google_identity(&p, "garbage", "n", 1000), Err(OAuthError::Malformed));
    }

    /// reqwest prints the URL with a transport error, and Facebook's calls
    /// carry their secrets in the query.
    #[tokio::test]
    async fn a_transport_error_leaves_the_url_out() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // A port nobody listens on any more.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = client(None).unwrap().get(format!("https://127.0.0.1:{port}/token?client_secret=hush")).send().await.unwrap_err();
        assert!(e.to_string().contains("hush"), "the URL, as reqwest prints it");
        let OAuthError::Http(s) = net(e) else { panic!("a transport error") };
        assert!(!s.contains("hush") && !s.contains("127.0.0.1"), "{s}");
    }
}
