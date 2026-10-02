//! The counter a stamp is actually read from.
//!
//! A stamp is a read of this and nothing else. There is no network call, no system call to a time
//! service and no lock. That is the whole design: the network work happens continuously in the
//! background, away from the event, so that the event itself costs one instruction.
//!
//! It is behind a trait so a test can drive time by hand. A clock model whose time cannot be
//! controlled cannot be tested for what it does over an hour of holdover, and that behaviour is one
//! of the two things this product has to get right.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use timewitness_core::{MonotonicNanos, Nanos};

/// Something that reports a counter that only ever goes forward.
pub trait MonotonicClock: Send + Sync {
    /// Read the counter.
    fn now(&self) -> MonotonicNanos;
}

/// The machine's own monotonic counter.
///
/// The origin is the moment this was constructed, so the values mean nothing on their own and
/// everything as differences, which is all the model asks of them.
#[derive(Debug)]
pub struct SystemMonotonic {
    origin: Instant,
}

impl SystemMonotonic {
    /// Start a counter from now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    /// Measure how finely this machine's counter actually ticks.
    ///
    /// Reads the counter repeatedly and takes the smallest step it ever sees. A counter that reports
    /// nanoseconds but moves in hundred nanosecond jumps has a hundred nanosecond granularity, and
    /// the bound has to carry that rather than the number of digits in the reading.
    #[must_use]
    pub fn measure_granularity(&self, reads: usize) -> Nanos {
        let mut smallest: Option<Nanos> = None;
        let mut previous = self.now();
        for _ in 0..reads.max(2) {
            let current = self.now();
            let step = current.since(previous);
            if step > 0 {
                smallest = Some(smallest.map_or(step, |s: Nanos| s.min(step)));
            }
            previous = current;
        }
        smallest.unwrap_or(0)
    }
}

impl Default for SystemMonotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonic {
    fn now(&self) -> MonotonicNanos {
        let elapsed = self.origin.elapsed().as_nanos();
        MonotonicNanos(u64::try_from(elapsed).unwrap_or(u64::MAX))
    }
}

/// A counter a test moves by hand.
#[derive(Debug, Default)]
pub struct TestClock {
    now: AtomicU64,
}

impl TestClock {
    /// A counter starting at `start` nanoseconds.
    #[must_use]
    pub fn starting_at(start: u64) -> Self {
        Self {
            now: AtomicU64::new(start),
        }
    }

    /// Move the counter forward by `delta` nanoseconds.
    pub fn advance(&self, delta: u64) {
        self.now.fetch_add(delta, Ordering::SeqCst);
    }

    /// Move the counter forward by `seconds`.
    pub fn advance_seconds(&self, seconds: u64) {
        self.advance(seconds.saturating_mul(1_000_000_000));
    }
}

impl MonotonicClock for TestClock {
    fn now(&self) -> MonotonicNanos {
        MonotonicNanos(self.now.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_counter_goes_forward() {
        let c = SystemMonotonic::new();
        let a = c.now();
        let b = c.now();
        assert!(b >= a);
    }

    #[test]
    fn granularity_is_measured_rather_than_assumed() {
        let c = SystemMonotonic::new();
        let g = c.measure_granularity(2_000);
        assert!(g >= 0, "granularity should never be negative, got {g}");
    }

    #[test]
    fn the_test_counter_moves_only_when_told() {
        let c = TestClock::starting_at(1_000);
        assert_eq!(c.now(), MonotonicNanos(1_000));
        assert_eq!(c.now(), MonotonicNanos(1_000));
        c.advance_seconds(5);
        assert_eq!(c.now(), MonotonicNanos(5_000_001_000));
    }
}
