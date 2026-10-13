//! Per-IP token bucket, in memory.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Above this many tracked addresses, buckets idle for longer than `IDLE_EVICT` are dropped.
const MAX_BUCKETS: usize = 10_000;
const IDLE_EVICT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

pub struct Limiter {
    capacity: AtomicU32,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: AtomicU32::new(capacity),
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn set_capacity(&self, c: u32) {
        self.capacity.store(c, Ordering::SeqCst);
        self.buckets.lock().unwrap().clear();
    }

    /// Returns true if the request is allowed.
    pub fn allow(&self, ip: IpAddr) -> bool {
        let cap = self.capacity.load(Ordering::SeqCst) as f64;
        let mut b = self.buckets.lock().unwrap();
        let now = Instant::now();
        if b.len() > MAX_BUCKETS {
            b.retain(|_, (_, last)| now.duration_since(*last) <= IDLE_EVICT);
        }
        let (tokens, last) = b.entry(ip).or_insert((cap, now));
        *tokens =
            (*tokens + now.duration_since(*last).as_secs_f64() * self.refill_per_sec).min(cap);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
