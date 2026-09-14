//! An interval of clock offset.
//!
//! Every source answers with one of these rather than with a point. A point would be a claim we
//! cannot support, because the network path the answer arrived over was not measured in each
//! direction separately and cannot be.

use crate::time::{nanos_as_millis_f64, Nanos};
use core::fmt;

/// A closed interval of possible offsets, in nanoseconds.
///
/// Offset here means the correction to add to the machine's own reading to reach UTC. A source
/// saying the machine is 3 ms slow, give or take 8 ms, contributes `[-5_000_000, 11_000_000]`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OffsetInterval {
    /// The smallest offset the source considers possible.
    pub lo: Nanos,
    /// The largest offset the source considers possible.
    pub hi: Nanos,
}

impl OffsetInterval {
    /// An interval from its two ends, ordered so `lo` is never above `hi`.
    #[must_use]
    pub fn new(lo: Nanos, hi: Nanos) -> Self {
        if lo <= hi {
            Self { lo, hi }
        } else {
            Self { lo: hi, hi: lo }
        }
    }

    /// An interval centred on `centre` and reaching `half_width` either side.
    ///
    /// `half_width` is taken as its magnitude, so a caller cannot build an inverted interval by
    /// passing a negative width.
    #[must_use]
    pub fn centred(centre: Nanos, half_width: Nanos) -> Self {
        let h = half_width.abs();
        Self {
            lo: centre - h,
            hi: centre + h,
        }
    }

    /// The distance between the two ends.
    #[must_use]
    pub const fn width(&self) -> Nanos {
        self.hi - self.lo
    }

    /// The point half way between the ends.
    ///
    /// This is a display value and not an answer. The product's claim is the interval; the midpoint
    /// is where a person's eye goes and it carries no more weight than either end.
    #[must_use]
    pub const fn midpoint(&self) -> Nanos {
        // Written as lo + half the width rather than (lo + hi) / 2 so the sum cannot overflow and
        // so the rounding goes the same way for negative offsets as for positive ones.
        self.lo + (self.hi - self.lo) / 2
    }

    /// Whether the interval holds `point`.
    #[must_use]
    pub const fn contains(&self, point: Nanos) -> bool {
        point >= self.lo && point <= self.hi
    }

    /// Whether the two intervals share at least one point. Touching at an end counts.
    #[must_use]
    pub const fn overlaps(&self, other: &OffsetInterval) -> bool {
        self.lo <= other.hi && other.lo <= self.hi
    }

    /// The interval shifted by `delta` nanoseconds.
    #[must_use]
    pub const fn shifted(&self, delta: Nanos) -> Self {
        Self {
            lo: self.lo + delta,
            hi: self.hi + delta,
        }
    }

    /// The interval widened by `amount` at each end.
    ///
    /// Widening is the only direction a bound may be moved after the fact. Narrowing one would be
    /// claiming to know something that was never measured.
    #[must_use]
    pub fn widened(&self, amount: Nanos) -> Self {
        let a = amount.abs();
        Self {
            lo: self.lo - a,
            hi: self.hi + a,
        }
    }

    /// The part the two intervals share, or `None` when they share nothing.
    #[must_use]
    pub fn intersect(&self, other: &OffsetInterval) -> Option<Self> {
        if self.overlaps(other) {
            Some(Self {
                lo: self.lo.max(other.lo),
                hi: self.hi.min(other.hi),
            })
        } else {
            None
        }
    }
}

impl fmt::Debug for OffsetInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:.3} ms, {:.3} ms]",
            nanos_as_millis_f64(self.lo),
            nanos_as_millis_f64(self.hi)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_orders_its_ends() {
        let i = OffsetInterval::new(10, -10);
        assert_eq!(i.lo, -10);
        assert_eq!(i.hi, 10);
    }

    #[test]
    fn centred_ignores_the_sign_of_the_width() {
        assert_eq!(OffsetInterval::centred(0, -5), OffsetInterval::new(-5, 5));
    }

    #[test]
    fn touching_intervals_overlap() {
        let a = OffsetInterval::new(0, 10);
        let b = OffsetInterval::new(10, 20);
        assert!(a.overlaps(&b));
        assert_eq!(a.intersect(&b), Some(OffsetInterval::new(10, 10)));
    }

    #[test]
    fn disjoint_intervals_do_not_intersect() {
        let a = OffsetInterval::new(0, 10);
        let b = OffsetInterval::new(11, 20);
        assert!(!a.overlaps(&b));
        assert_eq!(a.intersect(&b), None);
    }

    #[test]
    fn midpoint_of_a_negative_interval_stays_inside_it() {
        let i = OffsetInterval::new(-9, -1);
        assert!(i.contains(i.midpoint()));
        assert_eq!(i.midpoint(), -5);
    }

    #[test]
    fn widening_never_narrows() {
        let i = OffsetInterval::new(-5, 5);
        let w = i.widened(-3);
        assert_eq!(w, OffsetInterval::new(-8, 8));
        assert!(w.width() >= i.width());
    }
}
