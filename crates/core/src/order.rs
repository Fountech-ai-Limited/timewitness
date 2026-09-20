//! Which of two moments came first, where the honest answer is often that nobody can say.
//!
//! This is the arithmetic behind the product's second claim. The first is bounded time, which is
//! one moment and a width around it. The second is unbroken order, which is two moments and a
//! question about them, and it is answered here in one place so that every surface that answers it
//! answers it the same way.
//!
//! ## The rule, and it is one line
//!
//! Two moments are in a known order when every moment one of them could have been is before every
//! moment the other could have been. Anything else is undecided.
//!
//! That is interval disjointness and nothing cleverer. It is the same statement as "the two
//! readings are further apart than the two bounds added together", which is how the claim is
//! usually said in words, except that the disjointness version stays correct when an interval is
//! not centred on its reading, and an interval here is never promised to be.
//!
//! ## What is deliberately not done
//!
//! **The two intervals are never averaged, intersected, or combined into a narrower one.** Two
//! agents each disciplined their own clock against their own sources, and neither one's bound is
//! evidence about the other's. Narrowing one with the other would be inventing accuracy out of two
//! claims, which is the single thing this product exists not to do.
//!
//! **Overlap is never resolved by a tie-break.** Where the intervals touch or overlap, the two
//! moments could have happened in either order or at the same instant, and the answer is that
//! nobody can say. A midpoint comparison would answer every question and would be wrong a share of
//! the time nobody could measure afterwards, which is worse than no answer.
//!
//! **Touching at a point is undecided, not ordered.** Where one ends exactly where the other
//! begins, the two could be the same instant. The comparison is therefore strict.

use crate::time::{Nanos, UnixNanos};
use core::fmt;

/// A closed interval of UTC that one moment could have been in.
///
/// It is the pair of edges and nothing else. A reading inside it is a display value and takes no
/// part in this arithmetic, which is why it is not here: a comparison that could reach for the
/// reading is a comparison somebody will one day make with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MomentInterval {
    /// The earliest UTC the moment could have been.
    pub earliest: UnixNanos,
    /// The latest UTC the moment could have been.
    pub latest: UnixNanos,
}

impl MomentInterval {
    /// An interval from its two edges, in the order they are given.
    ///
    /// It does not quietly swap them. An inverted interval means the thing that produced it is
    /// wrong, and hiding that here would turn a fault into a narrower answer.
    #[must_use]
    pub const fn new(earliest: UnixNanos, latest: UnixNanos) -> Self {
        Self { earliest, latest }
    }

    /// Whether the edges are the right way round.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        self.earliest <= self.latest
    }

    /// How wide it is.
    #[must_use]
    pub fn width_ns(&self) -> Nanos {
        self.latest.as_nanos() - self.earliest.as_nanos()
    }
}

/// What can be said about the order of two moments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// The first moment is before the second, and every possible pair of readings agrees.
    ///
    /// `gap_ns` is the distance between the end of the first interval and the start of the second,
    /// which is how much room the answer had. It is reported because an order established by a
    /// nanosecond and one established by a second are the same verdict and not the same evidence.
    Before {
        /// The clear space between the two intervals.
        gap_ns: Nanos,
    },
    /// The second moment is before the first, on the same rule.
    After {
        /// The clear space between the two intervals.
        gap_ns: Nanos,
    },
    /// The two intervals touch or overlap, so the order is not established by them.
    ///
    /// `overlap_ns` is how much they share, and it is zero where they meet at exactly one point.
    /// **This is an answer and not a failure.** The two moments could have happened either way
    /// round or at the same instant, and the pair of claims does not say which.
    Undecided {
        /// How much of the two intervals is common to both.
        overlap_ns: Nanos,
    },
    /// One of the two intervals is not an interval, so nothing can be said.
    ///
    /// Kept apart from `Undecided` because they mean different things to whoever reads them. An
    /// undecided answer is a sound pair of claims that does not settle the question; this is a
    /// claim that cannot be true, and the thing to do about it is look at what produced it.
    Incoherent,
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Order::Before { gap_ns } => {
                write!(
                    f,
                    "the first is before the second, by {gap_ns} ns of clear space"
                )
            }
            Order::After { gap_ns } => {
                write!(
                    f,
                    "the second is before the first, by {gap_ns} ns of clear space"
                )
            }
            Order::Undecided { overlap_ns } => write!(
                f,
                "undecided: the two intervals overlap by {overlap_ns} ns, so either order is \
                 possible and so is the same instant"
            ),
            Order::Incoherent => write!(
                f,
                "one of the two intervals has its edges the wrong way round, so nothing follows \
                 from either"
            ),
        }
    }
}

impl Order {
    /// Whether an order was established at all.
    #[must_use]
    pub const fn is_decided(&self) -> bool {
        matches!(self, Order::Before { .. } | Order::After { .. })
    }
}

/// Which of two moments came first, or that nobody can say.
///
/// The whole of the rule is in the two comparisons below. Everything else in this module is saying
/// what they mean.
#[must_use]
pub fn order_of(first: &MomentInterval, second: &MomentInterval) -> Order {
    if !first.is_coherent() || !second.is_coherent() {
        return Order::Incoherent;
    }
    // Strict, because touching at a point leaves the same instant possible.
    if first.latest < second.earliest {
        return Order::Before {
            gap_ns: second.earliest.as_nanos() - first.latest.as_nanos(),
        };
    }
    if second.latest < first.earliest {
        return Order::After {
            gap_ns: first.earliest.as_nanos() - second.latest.as_nanos(),
        };
    }
    let shared_start = first.earliest.max(second.earliest);
    let shared_end = first.latest.min(second.latest);
    Order::Undecided {
        overlap_ns: shared_end.as_nanos() - shared_start.as_nanos(),
    }
}
