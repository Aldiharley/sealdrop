use axum_test::TestServer;
use sealdrop_release::app::{build, AppState};
use sealdrop_release::clock::FixedClock;
use sealdrop_release::db::Db;
use serde_json::{json, Value};
use std::sync::Arc;

const PKG: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

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
            "package_sha256": PKG
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
            "k_release": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA",
            "window_secs": 600,
            "unlock_token_hash": sealdrop_core::hashing::sha256_hex(b"tok"),
            "package_sha256": PKG
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
    assert_eq!(v["now"], "2026-10-13T09:00:00Z");
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
    let v: Value = r.json();
    assert_eq!(v["first_unlock"], "2026-10-13T09:00:00Z");
    // Service clock advances; remaining = expires_at - now.
    assert_eq!(v["now"], "2026-10-13T09:09:59Z");
    let now = chrono::DateTime::parse_from_rfc3339(v["now"].as_str().unwrap()).unwrap();
    let exp = chrono::DateTime::parse_from_rfc3339(v["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!((exp - now).num_seconds(), 1);

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
    // The receipt carries the service clock at issue time (09:00:00 + 599 + 2).
    assert_eq!(rec.now, "2026-10-13T09:10:01Z");
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
async fn trust_proxy_rate_limits_per_forwarded_client() {
    let clock = Arc::new(FixedClock::new("2026-10-13T09:00:00Z"));
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let state = AppState::new(Db::open_memory().unwrap(), clock, kp, 2).trusting_proxy(true);
    let s = TestServer::new(build(state));
    let get = |xff: &'static str| {
        let s = &s;
        async move {
            s.get("/healthz")
                .add_header("x-forwarded-for", xff)
                .await
                .status_code()
        }
    };
    // Every request arrives from the same peer (the proxy); each client gets its own bucket.
    assert_eq!(get("203.0.113.7").await, 200);
    assert_eq!(get("203.0.113.7, 10.0.0.1").await, 200);
    assert_eq!(get("203.0.113.7").await, 429);
    assert_eq!(get("198.51.100.9").await, 200);
    assert_eq!(get("2001:db8::1").await, 200);
    // An absent or invalid header falls back to the peer address.
    assert_eq!(get("not-an-ip").await, 200);
    assert_eq!(s.get("/healthz").await.status_code(), 200);
    assert_eq!(s.get("/healthz").await.status_code(), 429);
}

#[tokio::test]
async fn without_trust_proxy_forwarded_for_is_ignored() {
    let clock = Arc::new(FixedClock::new("2026-10-13T09:00:00Z"));
    let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let s = TestServer::new(build(AppState::new(
        Db::open_memory().unwrap(),
        clock,
        kp,
        2,
    )));
    for (xff, want) in [
        ("203.0.113.7", 200),
        ("198.51.100.9", 200),
        ("192.0.2.1", 429),
    ] {
        let r = s.get("/healthz").add_header("x-forwarded-for", xff).await;
        assert_eq!(r.status_code(), want, "{xff}");
    }
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

fn good() -> Value {
    json!({
        "k_release": KEY,
        "window_secs": 600,
        "unlock_token_hash": sealdrop_core::hashing::sha256_hex(b"tok"),
        "package_sha256": PKG
    })
}

async fn put_with(s: &TestServer, token: &str, id: &str, body: &Value) -> u16 {
    s.put(&format!("/v1/releases/{id}"))
        .add_header("authorization", format!("Bearer {token}"))
        .json(body)
        .await
        .status_code()
        .as_u16()
}

#[tokio::test]
async fn deposit_validates_k_release() {
    let (s, _, _, token) = server();
    for (i, bad) in [
        "",
        "AAAA",
        // 33 bytes
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        // 32 bytes but padded
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "not base64 !!!not base64 !!!not base64 !!!!!",
    ]
    .iter()
    .enumerate()
    {
        let mut b = good();
        b["k_release"] = json!(bad);
        assert_eq!(
            put_with(&s, &token, &format!("k{i}"), &b).await,
            400,
            "{bad:?}"
        );
    }
    assert_eq!(put_with(&s, &token, "ok", &good()).await, 201);
}

#[tokio::test]
async fn deposit_validates_hashes() {
    let (s, _, _, token) = server();
    let up = sealdrop_core::hashing::sha256_hex(b"tok").to_uppercase();
    for (field, bad) in [
        ("unlock_token_hash", json!("ab")),
        ("unlock_token_hash", json!(up)),
        ("unlock_token_hash", json!("g".repeat(64))),
        ("unlock_token_hash", json!("a".repeat(65))),
        ("package_sha256", json!("ab")),
        ("package_sha256", json!("")),
        ("package_sha256", json!(PKG.to_uppercase())),
        ("package_sha256", json!("z".repeat(64))),
    ] {
        let mut b = good();
        b[field] = bad.clone();
        assert_eq!(put_with(&s, &token, "h1", &b).await, 400, "{field}={bad}");
    }
    assert_eq!(put_with(&s, &token, "h1", &good()).await, 201);
}

#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let (s, _, _, token) = server();
    deposit(&s, &token).await;
    for scheme in ["bearer", "BEARER", "Bearer"] {
        let r = s
            .get("/v1/releases/r1/receipt")
            .add_header("authorization", format!("{scheme} {token}"))
            .await;
        assert_eq!(r.status_code(), 200, "{scheme}");
    }
    let r = s
        .get("/v1/releases/r1/receipt")
        .add_header("authorization", format!("Basic {token}"))
        .await;
    assert_eq!(r.status_code(), 401);
}

#[tokio::test]
async fn never_unlocked_deposits_are_purged_after_retention() {
    let (s, state, clock, token) = server();
    deposit(&s, &token).await;
    // Not yet 90 days: untouched.
    clock.advance_secs(89 * 86_400);
    assert_eq!(state.db.sweep_expired(clock_now(&state)).unwrap(), 0);
    assert!(state
        .db
        .get_release("r1")
        .unwrap()
        .unwrap()
        .k_release
        .is_some());
    // Past 90 days since creation, never unlocked: key and row gone.
    clock.advance_secs(2 * 86_400);
    assert_eq!(state.db.sweep_expired(clock_now(&state)).unwrap(), 1);
    assert!(state.db.get_release("r1").unwrap().is_none());
}

fn clock_now(state: &AppState) -> i64 {
    state.clock.now_unix()
}
