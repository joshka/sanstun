//! Measures how long each poll of a driver's tasks runs, to find work that goes too long
//! without reaching an `.await`.
//!
//! Recording is off unless [`enable`]d, so benchmarks pay one relaxed load per poll.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
/// Polls by duration: bucket `i` counts polls of `[2^i, 2^(i+1))` nanoseconds.
static BUCKETS: [AtomicU64; 40] = [const { AtomicU64::new(0) }; 40];
static MAX_NANOS: AtomicU64 = AtomicU64::new(0);
/// Polls of at least 10µs, 100µs and 1ms.
static OVER: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
const THRESHOLDS: [u64; 3] = [10_000, 100_000, 1_000_000];

pub fn enable() {
    reset();
    ENABLED.store(true, Ordering::Relaxed);
}

pub fn disable() {
    ENABLED.store(false, Ordering::Relaxed);
}

pub fn reset() {
    for bucket in &BUCKETS {
        bucket.store(0, Ordering::Relaxed);
    }
    MAX_NANOS.store(0, Ordering::Relaxed);
    for over in &OVER {
        over.store(0, Ordering::Relaxed);
    }
}

/// A summary of the polls recorded since [`enable`].
#[derive(Debug)]
pub struct Stats {
    pub polls: u64,
    /// Upper bounds of the bucket holding the median and the 99th and 99.9th percentiles.
    pub p50_nanos: u64,
    pub p99_nanos: u64,
    pub p999_nanos: u64,
    pub max_nanos: u64,
    pub over_10us: u64,
    pub over_100us: u64,
    pub over_1ms: u64,
}

pub fn stats() -> Stats {
    let counts = BUCKETS.each_ref().map(|b| b.load(Ordering::Relaxed));
    let polls = counts.iter().sum::<u64>();
    let percentile = |p: f64| {
        let target = (polls as f64 * p).ceil() as u64;
        let mut seen = 0;
        for (i, count) in counts.iter().enumerate() {
            seen += count;
            if seen >= target.max(1) {
                return 1 << (i + 1);
            }
        }
        0
    };
    Stats {
        polls,
        p50_nanos: percentile(0.5),
        p99_nanos: percentile(0.99),
        p999_nanos: percentile(0.999),
        max_nanos: MAX_NANOS.load(Ordering::Relaxed),
        over_10us: OVER[0].load(Ordering::Relaxed),
        over_100us: OVER[1].load(Ordering::Relaxed),
        over_1ms: OVER[2].load(Ordering::Relaxed),
    }
}

/// Wraps a driver task so its polls are recorded.
pub(crate) fn timed<F: Future>(future: F) -> Timed<F> {
    Timed { future }
}

pin_project_lite::pin_project! {
    pub(crate) struct Timed<F> {
        #[pin]
        future: F,
    }
}

impl<F: Future> Future for Timed<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let future = self.project().future;
        if !ENABLED.load(Ordering::Relaxed) {
            return future.poll(cx);
        }

        let start = Instant::now();
        let poll = future.poll(cx);
        let nanos = start.elapsed().as_nanos() as u64;
        BUCKETS[(63 - nanos.max(1).leading_zeros()) as usize].fetch_add(1, Ordering::Relaxed);
        MAX_NANOS.fetch_max(nanos, Ordering::Relaxed);
        for (over, threshold) in OVER.iter().zip(THRESHOLDS) {
            if nanos >= threshold {
                over.fetch_add(1, Ordering::Relaxed);
            }
        }

        poll
    }
}
