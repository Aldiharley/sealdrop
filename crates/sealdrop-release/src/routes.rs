use std::net::{IpAddr, SocketAddr};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::clock::fmt_unix;

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn rate_limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let ip: IpAddr = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]));
    if !st.limiter.allow(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    next.run(req).await
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Deserialize)]
pub struct DepositBody {
    k_release: String,
    window_secs: u64,
    unlock_token_hash: String,
    package_sha256: String,
}

pub async fn deposit(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(tok) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !st.db.token_valid(&tok).unwrap_or(false) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    // Parsed only after authentication so unauthenticated callers always get 401.
    let Ok(b) = serde_json::from_slice::<DepositBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid body").into_response();
    };
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return (StatusCode::BAD_REQUEST, "bad id").into_response();
    }
    let key_ok = base64::Engine::decode(&base64::prelude::BASE64_STANDARD_NO_PAD, &b.k_release)
        .map(|k| k.len() == 32)
        .unwrap_or(false);
    if !key_ok {
        return (
            StatusCode::BAD_REQUEST,
            "k_release must be 32 bytes, base64 without padding",
        )
            .into_response();
    }
    if !is_hex64(&b.unlock_token_hash) || !is_hex64(&b.package_sha256) {
        return (
            StatusCode::BAD_REQUEST,
            "unlock_token_hash and package_sha256 must be 64 lowercase hex characters",
        )
            .into_response();
    }
    if b.window_secs == 0 || b.window_secs > 366 * 86_400 {
        return (StatusCode::BAD_REQUEST, "bad window_secs").into_response();
    }
    match st.db.insert_release(
        &id,
        &b.k_release,
        b.window_secs as i64,
        &b.unlock_token_hash,
        &b.package_sha256,
        st.clock.now_unix(),
    ) {
        // The sender records this key in the manifest and pins receipts to it.
        Ok(true) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "service_key": st.signer.pk.to_base64() })),
        )
            .into_response(),
        Ok(false) => (StatusCode::CONFLICT, "release exists").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
pub struct UnlockBody {
    unlock_token: String,
}

#[derive(Serialize)]
pub struct UnlockResponse {
    k_release: String,
    first_unlock: String,
    expires_at: String,
}

pub async fn unlock(State(st): State<AppState>, Path(id): Path<String>, body: Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<UnlockBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid body").into_response();
    };
    let Ok(Some(row)) = st.db.get_release(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let raw =
        match base64::Engine::decode(&base64::prelude::BASE64_STANDARD_NO_PAD, &b.unlock_token) {
            Ok(r) => r,
            Err(_) => return StatusCode::FORBIDDEN.into_response(),
        };
    if sealdrop_core::hashing::sha256_hex(&raw) != row.unlock_token_hash {
        return StatusCode::FORBIDDEN.into_response();
    }
    let now = st.clock.now_unix();
    let (first, expires_at, expires_unix) =
        match (&row.first_unlock, &row.expires_at, row.expires_unix) {
            (Some(f), Some(e), Some(eu)) => (f.clone(), e.clone(), eu),
            _ => {
                let eu = now + row.window_secs;
                let f = fmt_unix(now);
                let e = fmt_unix(eu);
                let _ = st.db.mark_first_unlock(&id, &f, &e, eu);
                // A concurrent first unlock may have won; report what was actually stored.
                match st.db.get_release(&id) {
                    Ok(Some(r)) => match (r.first_unlock, r.expires_at, r.expires_unix) {
                        (Some(f), Some(e), Some(eu)) => (f, e, eu),
                        _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    },
                    _ => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            }
        };
    if now >= expires_unix {
        let _ = st.db.delete_key(&id);
        return (StatusCode::GONE, "release window has passed").into_response();
    }
    let Some(k) = row.k_release else {
        return (StatusCode::GONE, "release window has passed").into_response();
    };
    let _ = st.db.bump_unlock_count(&id);
    Json(UnlockResponse {
        k_release: k,
        first_unlock: first,
        expires_at,
    })
    .into_response()
}

pub async fn receipt(
    State(st): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(tok) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !st.db.token_valid(&tok).unwrap_or(false) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(Some(row)) = st.db.get_release(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let r = sealdrop_core::release::Receipt {
        release_id: row.release_id,
        package_sha256: row.package_sha256,
        first_unlock: row.first_unlock,
        expires_at: row.expires_at,
        unlock_count: row.unlock_count as u64,
        service_key: st.signer.pk.to_base64(),
    };
    match sealdrop_core::release::sign_receipt(&r, &st.signer.sk, &st.signer.pk) {
        Ok(s) => Json(s).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
