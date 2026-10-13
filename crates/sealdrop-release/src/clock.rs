use std::sync::atomic::{AtomicI64, Ordering};

/// Source of time for the service. The window is enforced against this clock only; no
/// client-supplied time is ever trusted.
pub trait Clock: Send + Sync {
    fn now_rfc3339(&self) -> String;
    fn now_unix(&self) -> i64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        fmt_unix(self.now_unix())
    }
    fn now_unix(&self) -> i64 {
        chrono::Utc::now().timestamp()
    }
}

/// A manually advanced clock for tests.
pub struct FixedClock(AtomicI64);

impl FixedClock {
    pub fn new(rfc3339: &str) -> Self {
        let t = chrono::DateTime::parse_from_rfc3339(rfc3339)
            .expect("valid RFC 3339 timestamp")
            .timestamp();
        Self(AtomicI64::new(t))
    }
    pub fn advance_secs(&self, s: i64) {
        self.0.fetch_add(s, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        fmt_unix(self.now_unix())
    }
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub fn fmt_unix(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .expect("timestamp in range")
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}
