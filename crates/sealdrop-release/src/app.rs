use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use axum::Router;

use crate::clock::Clock;
use crate::db::Db;
use crate::ratelimit::Limiter;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub clock: Arc<dyn Clock>,
    pub signer: Arc<minisign::KeyPair>,
    pub limiter: Arc<Limiter>,
}

impl AppState {
    pub fn new(
        db: Db,
        clock: Arc<dyn Clock>,
        signer: minisign::KeyPair,
        rate_capacity: u32,
    ) -> Self {
        Self {
            db: Arc::new(db),
            clock,
            signer: Arc::new(signer),
            limiter: Arc::new(Limiter::new(rate_capacity, 0.5)),
        }
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
