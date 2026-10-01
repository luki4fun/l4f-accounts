//! Users, roles, scopes and authentication for l4f.cc, built so another server
//! (voipc) can embed the same foundation later.
//!
//! The default feature set is the pure core: synchronous helpers with no tokio,
//! sqlx, axum or HTTP client. `mysql` adds the store, migrations and the service
//! layer; `axum` the web handlers and templates; `oauth` and `email` the outbound
//! integrations. See `docs/embedding.md`.

pub mod ip;
pub mod limit;
pub mod pow;
pub mod qr;
pub mod util;

pub use ip::IpMode;
pub use limit::RateLimiter;
