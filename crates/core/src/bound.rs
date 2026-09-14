//! The reading, the bound and the stamp they make together.
//!
//! Three separate things, and the product falls over if any two of them get mixed up.
//!
//! The reading is a counter read. It has nanosecond resolution because that is what the hardware
//! offers, and its resolution says nothing at all about how close to UTC it is.
//!
//! The bound is how far from UTC that reading could be. It is millisecond scale over the public
//! internet because the network path is not symmetric and no amount of arithmetic can see the
//! asymmetry from timestamps alone.
//!
//! The stamp is the two of them together with the evidence for the second, and it is what a receipt
//! carries.

use crate::interval::OffsetInterval;
use crate::source::{Generations, SourceState};
use crate::time::{nanos_as_millis_f64, MonotonicNanos, Nanos, UnixNanos};
use core::fmt;

/// A local read of the machine's clock.
///
/// `utc_estimate` is a display value. The claim this product makes is the interval in [`Bound`],
/// and a reader who takes the estimate as the answer has read the receipt wrongly. The receipt
/// format carries a flag saying so, because several independent reviews of this design landed on
/// the midpoint being the field most likely to be misread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    /// The raw monotonic counter value at the moment of the read.
    pub monotonic: MonotonicNanos,
    /// Where the model thinks that moment sits on UTC. Display only.
    pub utc_estimate: UnixNanos,
}

/// Whether the interval rests on third-party signatures or on our own model alone.
///
/// The two are not the same strength of claim and the receipt never blurs them. A local model is
/// the tighter number and it is the one that rests on trusting us.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EpsilonBasis {
    /// The interval is pinned between third-party signed evidence on both sides.
    ThirdPartySandwich,
    /// The interval comes from the agent's own disciplined model and nothing else.
    LocalModelOnly,
}

/// How the surviving source intervals were combined into one.
///
/// Named in the receipt so a reader does not have to guess, and so that anything that ever
/// combined sources by averaging them would have to say so out loud. Averaging clocks is not a
/// measurement and this product does not do it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FusionRule {
    /// Marzullo intersection over the source intervals, taken at a majority rather than at the
    /// largest overlap, then inverse-square weighting of the survivors by interval width, then
    /// linear regression for offset and frequency.
    ///
    /// The selection carries one rule the textbook does not, decided 2026-09-09: a majority that
    /// exists only because of sources that could not have been put in the minority is refused. It
    /// only ever refuses, so no receipt naming this rule was signed under a weaker one. See
    /// `timewitness_clock::marzullo`.
    MarzulloThenInverseSquare {
        /// How many sources answered.
        offered: usize,
        /// How many overlapped the region a majority allowed, and were kept.
        kept: usize,
    },
}

/// Where each part of the bound's width came from.
///
/// The parts do not simply add up, and pretending they do would hide the one that matters. The
/// intersection term already carries each source's stated uncertainty and half of its round trip,
/// because that is what a source interval is built from. The four terms after it are widenings
/// applied on top. `widest_source_network_half` is reported for a reader who wants to see how much
/// of the width is the network, and it is deliberately not part of the sum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundBreakdown {
    /// How the source intervals were combined.
    pub fusion: FusionRule,
    /// Half the width of the Marzullo intersection at the last good synchronisation.
    pub intersection_half: Nanos,
    /// The largest half round trip among the surviving sources. Diagnostic, not part of the sum.
    pub widest_source_network_half: Nanos,
    /// Allowance for the cost and jitter of the local read itself.
    pub scheduling: Nanos,
    /// Growth since the last synchronisation, from the frequency uncertainty times elapsed time.
    pub oscillator_holdover: Nanos,
    /// The regression's own standard errors, carried through as width.
    pub model_residual: Nanos,
    /// A fixed allowance for what the model does not attempt to describe.
    pub safety_margin: Nanos,
}

impl BoundBreakdown {
    /// Half the total width of the reported interval.
    ///
    /// The intersection term plus the four widenings. The network figure is excluded on purpose,
    /// because it is already inside the intersection term and counting it twice would make the
    /// bound look more careful than it is.
    #[must_use]
    pub const fn half_width(&self) -> Nanos {
        self.intersection_half
            + self.scheduling
            + self.oscillator_holdover
            + self.model_residual
            + self.safety_margin
    }
}

/// How wrong the reading could be, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The earliest UTC the reading could correspond to.
    pub earliest: UnixNanos,
    /// The latest UTC the reading could correspond to.
    pub latest: UnixNanos,
    /// Whether this rests on third-party signatures or on our own model.
    pub basis: EpsilonBasis,
    /// Where the width came from.
    pub breakdown: BoundBreakdown,
}

impl Bound {
    /// The width of the interval, in nanoseconds.
    #[must_use]
    pub fn width(&self) -> Nanos {
        self.latest - self.earliest
    }

    /// The width of the interval in milliseconds, which is the scale bounds are quoted at.
    #[must_use]
    pub fn width_millis(&self) -> f64 {
        nanos_as_millis_f64(self.width())
    }

    /// Whether a given UTC value falls inside the interval.
    #[must_use]
    pub fn contains(&self, t: UnixNanos) -> bool {
        t >= self.earliest && t <= self.latest
    }

    /// The interval expressed as offsets from `reference`.
    #[must_use]
    pub fn as_offset_interval(&self, reference: UnixNanos) -> OffsetInterval {
        OffsetInterval::new(self.earliest - reference, self.latest - reference)
    }
}

impl fmt::Display for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3} ms wide", self.width_millis())
    }
}

/// A reading, its bound, and the state of the model that produced them.
///
/// This is what the clock model hands out and what the receipt issuer turns into a receipt. It
/// carries no evidence of its own: the agent's bound is the agent's claim, and the third-party
/// evidence is attached later, separately, by the code that fetched it.
#[derive(Clone, Debug, PartialEq)]
pub struct Stamp {
    /// The local read.
    pub reading: Reading,
    /// How wrong that read could be.
    pub bound: Bound,
    /// What each source was doing at the time.
    pub sources: Vec<SourceState>,
    /// Which boot and which resume the machine was on.
    pub generations: Generations,
    /// The age of the newest exchange the bound rests on, in nanoseconds.
    ///
    /// This is how long the model has been extrapolating, and it is measured from the exchange
    /// rather than from the selection round that used it. The two are the same on a healthy poll
    /// and they come apart the moment the sources go quiet, because a selection round takes
    /// whatever is already in the window: a poller calling it on a schedule kept resetting this to
    /// nought while nothing had been heard for hours.
    pub since_last_sync: Nanos,
    /// The model's measured frequency error, in parts per million, where it has one.
    ///
    /// `None` means no rate is claimed, and it is the honest answer twice over: before the model
    /// has fitted anything, and after a fit its own baseline could not support. A fit taken over
    /// two seconds of wall time against sources whose midpoints move by seconds produces a slope in
    /// the thousands of parts per million, which is the sources' jitter divided by a short baseline
    /// rather than anything about this machine's oscillator. Reporting that as a measured frequency
    /// error would quote a figure nobody measured, so the model does not.
    ///
    /// Nothing is lost by refusing it. Where a rate is not claimed it is not corrected for either,
    /// and the whole of what the fit allowed goes into the width instead, so the interval is wider
    /// than it would have been rather than narrower.
    pub frequency_ppm: Option<f64>,
}

impl Stamp {
    /// Whether the reading's own estimate sits inside its bound.
    ///
    /// It always should. The check exists so a test can assert it rather than assume it, because a
    /// point estimate outside its own interval is the shape of a bug that would otherwise ship.
    #[must_use]
    pub fn estimate_within_bound(&self) -> bool {
        self.bound.contains(self.reading.utc_estimate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SmearPolicy;
    use crate::time::NANOS_PER_MILLI;

    fn breakdown() -> BoundBreakdown {
        BoundBreakdown {
            fusion: FusionRule::MarzulloThenInverseSquare {
                offered: 5,
                kept: 4,
            },
            intersection_half: 4 * NANOS_PER_MILLI,
            widest_source_network_half: 3 * NANOS_PER_MILLI,
            scheduling: 50_000,
            oscillator_holdover: NANOS_PER_MILLI,
            model_residual: 200_000,
            safety_margin: 250_000,
        }
    }

    #[test]
    fn the_network_term_is_not_counted_twice() {
        let b = breakdown();
        let expected = b.intersection_half
            + b.scheduling
            + b.oscillator_holdover
            + b.model_residual
            + b.safety_margin;
        assert_eq!(b.half_width(), expected);
        assert!(b.half_width() < expected + b.widest_source_network_half);
    }

    #[test]
    fn width_is_quoted_in_milliseconds() {
        let bound = Bound {
            earliest: UnixNanos(1_000_000_000_000_000_000),
            latest: UnixNanos(1_000_000_000_012_000_000),
            basis: EpsilonBasis::LocalModelOnly,
            breakdown: breakdown(),
        };
        assert!((bound.width_millis() - 12.0).abs() < 1e-9);
    }

    #[test]
    fn smear_default_is_no_smear() {
        assert_eq!(SmearPolicy::default(), SmearPolicy::None);
    }
}
