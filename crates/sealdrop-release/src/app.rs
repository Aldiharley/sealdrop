use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;

use crate::clock::Clock;
use crate::db::Db;
use crate::ratelimit::Limiter;

pub const DEFAULT_REFILL_PER_SEC: f64 = 0.5;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub clock: Arc<dyn Clock>,
    pub signer: Arc<minisign::KeyPair>,
    pub limiter: Arc<Limiter>,
    /// Key the rate limiter on the first `X-Forwarded-For` address instead of the TCP peer.
    /// Only for a deployment behind a reverse proxy that sets that header itself.
    pub trust_proxy: bool,
}

impl AppState {
    /// State with the default rate-limit refill of one request per two seconds.
    pub fn new(
        db: Db,
        clock: Arc<dyn Clock>,
        signer: minisign::KeyPair,
        rate_capacity: u32,
    ) -> Self {
        Self::with_rate(db, clock, signer, rate_capacity, DEFAULT_REFILL_PER_SEC)
    }

    pub fn with_rate(
        db: Db,
        clock: Arc<dyn Clock>,
        signer: minisign::KeyPair,
        rate_capacity: u32,
        refill_per_sec: f64,
    ) -> Self {
        Self {
            db: Arc::new(db),
            clock,
            signer: Arc::new(signer),
            limiter: Arc::new(Limiter::new(rate_capacity, refill_per_sec)),
            trust_proxy: false,
        }
    }

    /// Behind a reverse proxy (`serve --trust-proxy`): rate-limit per client address taken
    /// from `X-Forwarded-For`, not per proxy connection.
    pub fn trusting_proxy(mut self, yes: bool) -> Self {
        self.trust_proxy = yes;
        self
    }
}

pub fn build(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(crate::routes::healthz))
        .route("/v1/releases/{id}", put(crate::routes::deposit))
        .route("/v1/releases/{id}/unlock", post(crate::routes::unlock))
        .route("/v1/releases/{id}/receipt", get(crate::routes::receipt))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::routes::rate_limit,
        ))
        .with_state(state)
}
