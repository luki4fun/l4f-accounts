//! Users, roles, scopes and authentication for l4f.cc, built so another server
//! (voipc) can embed the same foundation later.
//!
//! The default feature set is the pure core: synchronous helpers with no tokio,
//! sqlx, axum or HTTP client. `mysql` adds the store, migrations and the service
//! layer; `axum` the web handlers and templates; `oauth` and `email` the outbound
//! integrations. See `docs/embedding.md`.

pub mod challenge;
pub mod ip;
pub mod keys;
pub mod limit;
#[cfg(feature = "mysql")]
pub mod migrate;
pub mod model;
pub mod password;
pub mod pow;
pub mod qr;
pub mod recovery;
pub mod scope;
#[cfg(feature = "mysql")]
pub mod store;
pub mod totp;
pub mod util;
pub mod verify;

pub use ip::IpMode;
pub use limit::RateLimiter;
