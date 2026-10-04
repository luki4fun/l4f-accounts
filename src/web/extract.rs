//! Extractors: who is asking (`Ctx`), and who is signed in (`Authed`, `Viewer`).

use std::convert::Infallible;

use axum::{
    extract::{FromRequestParts, OriginalUri},
    http::{HeaderMap, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};

use super::{AccountsState, BASE, ClientIp, clear_session, csrf, error_page, header_str, see_other, session_token};
use crate::model::{SessionInfo, User};
use crate::service::{Accounts, Actor, Ctx, Host, require, token_hash};
use crate::util;

impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Response> {
        let Some(ClientIp(ip)) = parts.extensions.get::<ClientIp>().copied() else {
            tracing::error!(target: "accounts", "request without a ClientIp extension: the host must insert one");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        };
        Ok(Ctx {
            ip,
            ua: header_str(&parts.headers, header::USER_AGENT).chars().take(256).collect(),
            sec_fetch_site: header_str(&parts.headers, "sec-fetch-site").to_string(),
        })
    }
}

/// A full session (second factor done, if any): the account, the session row,
/// the scopes it grants now, and its form token. Rejects with a 303 to the
/// sign-in page, which comes back here afterwards.
pub struct Authed {
    pub user: User,
    pub session: SessionInfo,
    pub scopes: Vec<String>,
    csrf: String,
}

impl Authed {
    /// The value forms carry as `csrf` (or scripts as `X-CSRF`).
    pub fn csrf(&self) -> &str {
        &self.csrf
    }

    /// For the host's own forms, which sit outside the crate's CSRF layer.
    pub fn check_csrf(&self, token: &str) -> bool {
        util::ct_eq(&self.csrf, token)
    }

    pub fn can(&self, scope: &str) -> bool {
        require(&self.scopes, scope)
    }

    pub fn actor(&self) -> Actor<'_> {
        Actor { user: &self.user, scopes: &self.scopes }
    }
}

impl<H: Host> Accounts<H> {
    /// The signed-in account behind the request's cookie, if its session is
    /// live and complete. For host pages that are not behind `Authed`.
    pub async fn viewer(&self, h: &HeaderMap) -> sqlx::Result<Option<Authed>> {
        let Some(token) = session_token(&self.host.config(), h) else { return Ok(None) };
        let Some(hash) = token_hash(token) else { return Ok(None) };
        let Some((user, session, scopes)) = self.session_from_token(token, util::now()).await? else { return Ok(None) };
        // A session still waiting for its second factor is not signed in yet.
        if !session.mfa_ok {
            return Ok(None);
        }
        let csrf = csrf::token(&self.keys, &hash);
        Ok(Some(Authed { user, session, scopes, csrf }))
    }
}

/// Where to come back to after signing in: this page for a GET, the dashboard
/// for anything else (posting again would need the form).
fn next_of(parts: &Parts) -> String {
    if !matches!(parts.method, Method::GET | Method::HEAD) {
        return BASE.to_string();
    }
    // Nested routers see their path with the prefix stripped.
    let uri = parts.extensions.get::<OriginalUri>().map_or(&parts.uri, |o| &o.0);
    uri.path_and_query().map_or(BASE, |p| p.as_str()).to_string()
}

impl<S: AccountsState> FromRequestParts<S> for Authed {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, st: &S) -> Result<Self, Response> {
        let a = st.accounts();
        match a.viewer(&parts.headers).await {
            Ok(Some(me)) => Ok(me),
            Ok(None) => {
                let to = format!("{BASE}/login?next={}", util::urlencode(&next_of(parts)));
                let cfg = a.host.config();
                // A cookie that names no session is cleared, so the next form
                // doesn't carry a token for it.
                let clear = session_token(&cfg, &parts.headers).map(|_| clear_session(&cfg));
                Err(see_other(&to, clear.as_slice()))
            }
            Err(e) => {
                tracing::error!(target: "accounts", error = %e, "session lookup failed");
                Err(error_page(a, &parts.headers, StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong. Please try again."))
            }
        }
    }
}

/// Whoever is signed in, or nobody. A database error counts as nobody, which
/// grants nothing.
pub struct Viewer(pub Option<Authed>);

impl<S: AccountsState> FromRequestParts<S> for Viewer {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &S) -> Result<Self, Infallible> {
        Ok(Viewer(st.accounts().viewer(&parts.headers).await.unwrap_or_else(|e| {
            tracing::warn!(target: "accounts", error = %e, "session lookup failed");
            None
        })))
    }
}
