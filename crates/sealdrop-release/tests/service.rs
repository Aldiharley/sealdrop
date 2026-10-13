use axum_test::TestServer;
use sealdrop_release::app::{build, AppState};
use sealdrop_release::clock::FixedClock;
use sealdrop_release::db::Db;
use serde_json::{json, Value};
use std::sync::Arc;

fn server() -> (TestServer, AppState, Arc<FixedClock>, String) {
    let clock = Arc::new(FixedClock::new("2026-10-13T09:00:00Z"));
    let db = Db::open_memory().unwrap();
    let token = db.create_token("tests").unwrap();
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let state = AppState::new(db, clock.clone(), kp, 1000);
    (TestServer::new(build(state.clone())), state, clock, token)
}

async fn deposit(s: &TestServer, token: &str) {
    let r = s
        .put("/v1/releases/r1")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "k_release": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "window_secs": 600,
            "unlock_token_hash": sealdrop_core::hashing::sha256_hex(b"tok"),
            "package_sha256": "ab"
        }))
        .await;
    assert_eq!(r.status_code(), 201, "{}", r.text());
    let v: Value = r.json();
    assert!(
        v["service_key"].as_str().unwrap().starts_with("RW"),
        "deposit must return the service key"
    );
}

#[tokio::test]
async fn deposit_requires_token() {
    let (s, _, _, _) = server();
    let r = s.put("/v1/releases/r1").json(&json!({})).await;
    assert_eq!(r.status_code(), 401);
    let r = s
        .put("/v1/releases/r1")
        .add_header("authorization", "Bearer nope")
        .json(&json!({}))
        .await;
    assert_eq!(r.status_code(), 401);
}

#[tokio::test]
async fn second_deposit_for_same_id_conflicts() {
    let (s, _, _, token) = server();
    deposit(&s, &token).await;
    let r = s
        .put("/v1/releases/r1")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "k_release": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "window_secs": 600,
            "unlock_token_hash": sealdrop_core::hashing::sha256_hex(b"tok"),
            "package_sha256": "ab"
        }))
        .await;
    assert_eq!(r.status_code(), 409);
}

#[tokio::test]
async fn unlock_window_is_enforced_on_service_clock() {
    let (s, _, clock, token) = server();
    deposit(&s, &token).await;
    let unlock_b64 = base64::Engine::encode(&base64::prelude::BASE64_STANDARD_NO_PAD, b"tok");

    let r = s
        .post("/v1/releases/r1/unlock")
        .json(&json!({"unlock_token": "wrong"}))
        .await;
    assert_eq!(r.status_code(), 403);
    let r = s
        .post("/v1/releases/nope/unlock")
        .json(&json!({"unlock_token": unlock_b64}))
        .await;
    assert_eq!(r.status_code(), 404);

    let r = s
        .post("/v1/releases/r1/unlock")
        .json(&json!({"unlock_token": unlock_b64}))
        .await;
    assert_eq!(r.status_code(), 200, "{}", r.text());
    let v: Value = r.json();
    assert_eq!(v["first_unlock"], "2026-10-13T09:00:00Z");
    assert_eq!(v["expires_at"], "2026-10-13T09:10:00Z");
    assert_eq!(
        v["k_release"],
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    clock.advance_secs(599);
    let r = s
        .post("/v1/releases/r1/unlock")
        .json(&json!({"unlock_token": unlock_b64}))
        .await;
    assert_eq!(r.status_code(), 200);
    assert_eq!(r.json::<Value>()["first_unlock"], "2026-10-13T09:00:00Z");

    clock.advance_secs(2);
    let r = s
        .post("/v1/releases/r1/unlock")
        .json(&json!({"unlock_token": unlock_b64}))
        .await;
    assert_eq!(r.status_code(), 410);

    // Receipt still available to the sender, key is gone.
    let r = s
        .get("/v1/releases/r1/receipt")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(r.status_code(), 200);
    let text = r.text();
    assert!(
        !text.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        "the release key must never appear in a receipt"
    );
    let signed: sealdrop_core::release::SignedReceipt = serde_json::from_str(&text).unwrap();
    let rec = sealdrop_core::release::verify_receipt(&signed, None).unwrap();
    assert_eq!(rec.unlock_count, 2);
    assert_eq!(rec.first_unlock.as_deref(), Some("2026-10-13T09:00:00Z"));
}

#[tokio::test]
async fn sweeper_deletes_expired_keys() {
    let (s, state, clock, token) = server();
    deposit(&s, &token).await;
    let unlock_b64 = base64::Engine::encode(&base64::prelude::BASE64_STANDARD_NO_PAD, b"tok");
    s.post("/v1/releases/r1/unlock")
        .json(&json!({"unlock_token": unlock_b64}))
        .await
        .assert_status_ok();
    clock.advance_secs(601);
    let n = state.db.sweep_expired(state.clock.now_unix()).unwrap();
    assert_eq!(n, 1);
    assert!(state
        .db
        .get_release("r1")
        .unwrap()
        .unwrap()
        .k_release
        .is_none());
}

#[tokio::test]
async fn rate_limit_returns_429() {
    let (s, state, _, _) = server();
    state.limiter.set_capacity(3);
    for _ in 0..3 {
        let r = s.get("/healthz").await;
        assert_eq!(r.status_code(), 200);
    }
    let r = s.get("/healthz").await;
    assert_eq!(r.status_code(), 429);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let (s, _, _, token) = server();
    let r = s
        .put("/v1/releases/r1")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({"k_release": "x".repeat(20_000), "window_secs": 600, "unlock_token_hash": "", "package_sha256": ""}))
        .await;
    assert_eq!(r.status_code(), 413);
}
