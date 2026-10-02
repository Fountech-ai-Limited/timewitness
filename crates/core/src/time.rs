//! The two clocks, kept apart on purpose.
//!
//! A monotonic counter only ever goes forward and has no relationship to UTC. A UTC value is a
//! position on the civil timescale. The agent measures elapsed time on the first and estimates the
//! second from it, so mixing the two types up would be the easiest way to write a wrong stamp.

use core::fmt;
use core::ops::{Add, Sub};

/// A signed nanosecond quantity, wide enough that intermediate arithmetic cannot overflow.
///
/// Durations, offsets and interval widths are all this type. It is 128 bits because a bound
/// calculation multiplies a frequency error by an elapsed time, and a 64-bit product of two
/// realistic values gets close enough to the ceiling to be worth not thinking about.
pub type Nanos = i128;

/// One nanosecond, as a count of nanoseconds. Present so arithmetic reads as arithmetic.
pub const NANOS_PER_MICRO: Nanos = 1_000;
/// Nanoseconds in a millisecond.
pub const NANOS_PER_MILLI: Nanos = 1_000_000;
/// Nanoseconds in a second.
pub const NANOS_PER_SEC: Nanos = 1_000_000_000;

/// A reading of the machine's monotonic counter, in nanoseconds from an arbitrary origin.
///
/// The origin is whatever the platform picked, usually the last boot. It is meaningless on its own
/// and only differences between two of these mean anything.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MonotonicNanos(pub u64);

impl MonotonicNanos {
    /// The counter value as a plain number of nanoseconds.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Nanoseconds elapsed from `earlier` to `self`, saturating at zero.
    ///
    /// Saturating rather than wrapping because a monotonic counter that appears to go backwards is
    /// a platform fault, and returning a negative elapsed time would push that fault into the
    /// bound arithmetic where it would be invisible.
    #[must_use]
    pub const fn since(self, earlier: MonotonicNanos) -> Nanos {
        if self.0 >= earlier.0 {
            (self.0 - earlier.0) as Nanos
        } else {
            0
        }
    }

    /// The counter advanced by `delta` nanoseconds. Used by tests that drive a fake counter.
    #[must_use]
    pub fn advanced(self, delta: Nanos) -> MonotonicNanos {
        let d = if delta < 0 { 0 } else { delta as u128 };
        MonotonicNanos(self.0.saturating_add(u64::try_from(d).unwrap_or(u64::MAX)))
    }
}

impl fmt::Debug for MonotonicNanos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mono({} ns)", self.0)
    }
}

/// A position on UTC, in nanoseconds from the Unix epoch.
///
/// Held as 128 bits internally so the arithmetic never overflows. It narrows to 64 bits at the
/// wire, which covers the years 1678 to 2262, and the narrowing is checked rather than silent.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct UnixNanos(pub Nanos);

impl UnixNanos {
    /// The value as a plain nanosecond count from the Unix epoch.
    #[must_use]
    pub const fn as_nanos(self) -> Nanos {
        self.0
    }

    /// The value as a 64-bit nanosecond count, or `None` if it does not fit.
    ///
    /// The wire format uses 64 bits. A receipt carrying a time outside that range would be
    /// unreadable by a verifier, so the conversion refuses rather than truncating.
    #[must_use]
    pub fn as_i64_nanos(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }

    /// The value in whole milliseconds from the epoch, rounding towards negative infinity.
    #[must_use]
    pub fn as_millis(self) -> Nanos {
        self.0.div_euclid(NANOS_PER_MILLI)
    }
}

impl fmt::Debug for UnixNanos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "utc({} ns)", self.0)
    }
}

impl Add<Nanos> for UnixNanos {
    type Output = UnixNanos;
    fn add(self, rhs: Nanos) -> UnixNanos {
        UnixNanos(self.0 + rhs)
    }
}

impl Sub<Nanos> for UnixNanos {
    type Output = UnixNanos;
    fn sub(self, rhs: Nanos) -> UnixNanos {
        UnixNanos(self.0 - rhs)
    }
}

impl Sub<UnixNanos> for UnixNanos {
    type Output = Nanos;
    fn sub(self, rhs: UnixNanos) -> Nanos {
        self.0 - rhs.0
    }
}

/// Nanoseconds rendered as a millisecond figure for a person to read.
///
/// Bounds are quoted in milliseconds because that is the scale they live at. This is a display
/// helper and nothing in the arithmetic uses it.
#[must_use]
pub fn nanos_as_millis_f64(n: Nanos) -> f64 {
    n as f64 / NANOS_PER_MILLI as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_never_goes_negative() {
        let early = MonotonicNanos(1_000);
        let late = MonotonicNanos(3_000);
        assert_eq!(late.since(early), 2_000);
        assert_eq!(early.since(late), 0);
    }

    #[test]
    fn utc_narrowing_refuses_out_of_range() {
        let ok = UnixNanos(1_757_000_000_000_000_000);
        assert!(ok.as_i64_nanos().is_some());
        let too_far = UnixNanos(i128::from(i64::MAX) + 1);
        assert!(too_far.as_i64_nanos().is_none());
    }

    #[test]
    fn millis_round_towards_negative_infinity() {
        assert_eq!(UnixNanos(-1).as_millis(), -1);
        assert_eq!(UnixNanos(0).as_millis(), 0);
        assert_eq!(UnixNanos(NANOS_PER_MILLI - 1).as_millis(), 0);
    }
}
