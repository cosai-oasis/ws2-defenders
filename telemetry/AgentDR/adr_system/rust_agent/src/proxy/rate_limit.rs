//! Per-key sliding-window rate limiting for the LLM Guard, built on
//! [`governor`].
//!
//! `governor` implements the GCRA (Generic Cell Rate Algorithm) which gives
//! a smooth sliding-window limiter rather than the bursty fixed-window kind:
//! the configured `requests_per_minute` is the sustained rate and `burst`
//! the instantaneous allowance. We use the *keyed* variant so each
//! authenticated subject (API-key fingerprint / JWT `sub` / peer address in
//! observe-only mode) gets its own independent quota.

use crate::config::RateLimitConfig;
use governor::{
    clock::DefaultClock,
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};
use std::num::NonZeroU32;

type KeyedLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// A keyed sliding-window limiter. When disabled, [`check`](RateLimiter::check)
/// always allows.
pub struct KeyedRateLimiter {
    inner: Option<KeyedLimiter>,
    per_minute: u32,
}

impl KeyedRateLimiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        if !cfg.enabled {
            return Self { inner: None, per_minute: cfg.requests_per_minute };
        }
        // Sustained rate: requests_per_minute. Burst: configured burst, or
        // the per-minute rate when unset. Both floored at 1 to satisfy
        // governor's NonZero requirements.
        let per_minute = cfg.requests_per_minute.max(1);
        let burst = if cfg.burst == 0 { per_minute } else { cfg.burst }.max(1);

        let quota = Quota::per_minute(NonZeroU32::new(per_minute).unwrap())
            .allow_burst(NonZeroU32::new(burst).unwrap());

        Self { inner: Some(RateLimiter::keyed(quota)), per_minute }
    }

    /// Returns `true` if the request for `key` is permitted, `false` if it
    /// should be rejected (HTTP 429).
    pub fn check(&self, key: &str) -> bool {
        match &self.inner {
            Some(limiter) => limiter.check_key(&key.to_string()).is_ok(),
            None => true,
        }
    }

    /// Whether limiting is active (for logging / health output).
    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Configured sustained per-minute rate (for event context).
    pub fn per_minute(&self) -> u32 {
        self.per_minute
    }

    /// Opportunistically drop rate-limiter state for keys that have fully
    /// recovered their quota, bounding memory for long-running guards.
    pub fn retain_recent(&self) {
        if let Some(limiter) = &self.inner {
            limiter.retain_recent();
        }
    }
}
