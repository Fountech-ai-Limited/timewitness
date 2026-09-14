//! One exchange, turned into an interval.
//!
//! This is where the four timestamps become arithmetic. Two formulas do the work and both come
//! straight from NTP, which has used them since the 1980s.
//!
//! The offset of the source's clock against ours is `((t2 - t1) + (t3 - t4)) / 2`, and the round
//! trip is `(t4 - t1) - (t3 - t2)`. Subtracting the source's own processing time inside the round
//! trip is the whole reason the arithmetic uses four timestamps rather than two: whatever the
//! source spent thinking about the request cancels.
//!
//! Two of the four are the source's and arrive on the exchange. The other two are ours and do not:
//! they are stamped by the model off its own anchor, and passed in here, so that this file can only
//! ever measure an offset against the clock the bound is anchored to.
//!
//! What does not cancel is how unevenly the round trip was split between the way out and the way
//! back. Nothing in the timestamps can see it. The worst case is that all of the asymmetry sits on
//! one leg, which puts the true offset up to half the round trip away from the computed one. That
//! residual is why the bound is milliseconds while the reading is nanoseconds, and it is not
//! approximated away anywhere in this file.

use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, OffsetInterval, Operator, SmearPolicy, SourceId, SourceKind,
    Timescale, UnixNanos,
};
use timewitness_sources::Exchange;

/// One exchange reduced to what the model needs from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    /// Which source it came from.
    pub source: SourceId,
    /// Who runs that source.
    pub operator: Operator,
    /// What that source speaks.
    pub kind: SourceKind,
    /// The offset of the source's clock against ours, in nanoseconds.
    pub offset: Nanos,
    /// The measured round trip, in nanoseconds, never negative.
    pub round_trip: Nanos,
    /// What the source said about its own uncertainty, in nanoseconds.
    pub stated_uncertainty: Nanos,
    /// The monotonic counter at the moment the reply arrived, for ageing the sample later.
    pub taken_at: MonotonicNanos,
    /// The timescale the source answered on, before any conversion.
    pub timescale: Timescale,
    /// What the source does with a leap second.
    pub smear: SmearPolicy,
    /// What the source said about an upcoming leap second.
    pub leap: LeapIndicator,
}

impl Sample {
    /// Reduce an exchange to a sample.
    ///
    /// `local_t1` and `local_t4` are the two ends of the round trip as the model's own anchor puts
    /// them, and they are passed in rather than read off the exchange because the exchange has no
    /// local time on it. Only one clock on the machine may appear in this arithmetic, and it is the
    /// one the bound is anchored to; see `Exchange` for why the alternative is not merely untidy.
    ///
    /// A source answering on TAI is converted to UTC here using the offset it stated, so everything
    /// downstream is on one timescale. The original timescale is kept on the sample, because the
    /// receipt has to be able to say what the source actually spoke.
    ///
    /// Returns nothing where the source's own two timestamps cannot both be true, which is the one
    /// thing an exchange can say that no amount of arithmetic afterwards can repair. See the
    /// round-trip comment below.
    ///
    /// Visible inside this crate only. The model is the one thing that holds the anchor, so it is
    /// the one thing allowed to say where the local ends of a round trip were, and a dependant
    /// reaching for the system clock to fill these in is the bug this signature exists to prevent.
    #[must_use]
    pub(crate) fn from_exchange(
        e: &Exchange,
        local_t1: UnixNanos,
        local_t4: UnixNanos,
    ) -> Option<Self> {
        let t1 = local_t1.as_nanos();
        let t2 = e.t2.as_nanos();
        let t3 = e.t3.as_nanos();
        let t4 = local_t4.as_nanos();

        let timescale_correction = match e.timescale {
            Timescale::Tai { offset_seconds } => Nanos::from(offset_seconds) * NANOS_PER_SEC,
            Timescale::Utc | Timescale::Unknown => 0,
        };

        let offset = ((t2 - t1) + (t3 - t4)) / 2 - timescale_correction;

        // The source's own processing time is subtracted out of the round trip, and the source is
        // the only party who says what that time was. A reply claiming to have taken longer to
        // produce than the whole exchange took is a reply whose two timestamps cannot both be
        // true, and there is no honest number to put in its place: zero is the narrowest answer
        // there is, and clamping to it hands the source the tightest interval on the strength of
        // the one thing it said that is provably wrong.
        //
        // So the sample is dropped. The cost is one exchange from a source whose clock is too
        // coarse to measure a round trip this short, and a source that cannot measure the round
        // trip cannot support an interval either, so the window is better off without it.
        let round_trip = (t4 - t1) - (t3 - t2);
        if round_trip < 0 {
            return None;
        }

        Some(Self {
            source: e.source.clone(),
            operator: e.operator.clone(),
            kind: e.kind,
            offset,
            round_trip,
            stated_uncertainty: e.stated_uncertainty(),
            taken_at: e.mono_t4,
            timescale: e.timescale,
            smear: e.smear,
            leap: e.leap,
        })
    }

    /// Half the round trip, which is the largest error the split between the two legs can cause.
    #[must_use]
    pub const fn split_direction_residual(&self) -> Nanos {
        self.round_trip / 2
    }

    /// The interval this sample supports, aged forward to `now`.
    ///
    /// Three terms, and none of them is optional. Half the round trip is the split-direction
    /// residual. The stated uncertainty is what the source said about its own distance from its
    /// reference. The dispersion term grows with the age of the sample at the assumed drift rate,
    /// because a sample taken a minute ago describes a clock that has moved since.
    ///
    /// The first two are both the source's to choose, and a source willing to state that it spent
    /// the whole round trip thinking and that it knows its own time exactly makes both of them
    /// zero. `source_floor` is the width below which no source's answer is taken, whatever it says
    /// about itself, and it is applied to those two before the ageing term is added, because the
    /// ageing term is the model's own arithmetic and not a claim of the source's. See
    /// `Policy::source_interval_floor` for where the figure comes from.
    #[must_use]
    pub fn interval_at(
        &self,
        now: MonotonicNanos,
        drift_floor_ppm: f64,
        source_floor: Nanos,
    ) -> OffsetInterval {
        let age = now.since(self.taken_at);
        let dispersion = crate::policy::ppm_over(drift_floor_ppm, age);
        let stated = self.split_direction_residual() + self.stated_uncertainty;
        let half = stated.max(source_floor.max(0)) + dispersion;
        OffsetInterval::centred(self.offset, half)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
    use timewitness_core::UnixNanos;

    /// Where the model's own anchor puts the start of the round trip in these tests.
    const LOCAL_T1: Nanos = 1_000_000_000_000_000_000;

    /// Build an exchange for a source whose clock is `true_offset` ahead of ours, where the request
    /// took `out` on the way there and `back` on the way home.
    ///
    /// The exchange holds only what the source said. The local end of it is `local_t1` and
    /// `local_t4` below, which stand in for what the model's anchor would have stamped.
    fn exchange(true_offset: Nanos, out: Nanos, back: Nanos, server_think: Nanos) -> Exchange {
        let t2 = LOCAL_T1 + out + true_offset;
        let t3 = t2 + server_think;
        Exchange {
            source: SourceId::new("s"),
            operator: Operator::new("s"),
            kind: SourceKind::Ntp,
            t2: UnixNanos(t2),
            t3: UnixNanos(t3),
            mono_t1: MonotonicNanos(0),
            mono_t4: MonotonicNanos((out + server_think + back) as u64),
            root_delay: 0,
            root_dispersion: 0,
            timescale: Timescale::Utc,
            smear: SmearPolicy::None,
            leap: LeapIndicator::None,
            attestation: None,
        }
    }

    /// The two local stamps the model would take for `e`, off one clock.
    fn local_ends(e: &Exchange) -> (UnixNanos, UnixNanos) {
        (
            UnixNanos(LOCAL_T1),
            UnixNanos(LOCAL_T1 + e.mono_t4.since(e.mono_t1)),
        )
    }

    /// Reduce an exchange the way the model does, where the model would take it at all.
    fn sample_of(e: &Exchange) -> Sample {
        let (t1, t4) = local_ends(e);
        Sample::from_exchange(e, t1, t4).expect("this exchange is one the model accepts")
    }

    #[test]
    fn a_symmetric_path_recovers_the_offset_exactly() {
        let e = exchange(
            7 * NANOS_PER_MILLI,
            4 * NANOS_PER_MILLI,
            4 * NANOS_PER_MILLI,
            0,
        );
        let s = sample_of(&e);
        assert_eq!(s.offset, 7 * NANOS_PER_MILLI);
        assert_eq!(s.round_trip, 8 * NANOS_PER_MILLI);
    }

    #[test]
    fn the_sources_own_thinking_time_cancels_out_of_the_round_trip() {
        let quick = exchange(0, 3 * NANOS_PER_MILLI, 3 * NANOS_PER_MILLI, 0);
        let slow = exchange(
            0,
            3 * NANOS_PER_MILLI,
            3 * NANOS_PER_MILLI,
            40 * NANOS_PER_MILLI,
        );
        assert_eq!(sample_of(&quick).round_trip, sample_of(&slow).round_trip);
        assert_eq!(sample_of(&quick).offset, sample_of(&slow).offset);
    }

    #[test]
    fn worst_case_asymmetry_still_lands_inside_the_interval() {
        // All ten milliseconds of the round trip sit on the outbound leg. The computed offset is
        // then five milliseconds out, and half the round trip is exactly five milliseconds, so the
        // true offset sits on the edge of the interval rather than outside it.
        let true_offset = 20 * NANOS_PER_MILLI;
        let e = exchange(true_offset, 10 * NANOS_PER_MILLI, 0, 0);
        let s = sample_of(&e);
        assert_eq!(s.round_trip, 10 * NANOS_PER_MILLI);
        assert_eq!(s.split_direction_residual(), 5 * NANOS_PER_MILLI);
        let interval = s.interval_at(s.taken_at, 0.0, 0);
        assert!(
            interval.contains(true_offset),
            "the interval {interval:?} must hold the true offset {true_offset}"
        );
    }

    #[test]
    fn a_negative_round_trip_is_refused_rather_than_clamped_to_the_narrowest_answer() {
        let mut e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        // Force the source's two timestamps further apart than the whole exchange took.
        e.t3 = UnixNanos(e.t3.as_nanos() + 10 * NANOS_PER_MILLI);
        let (t1, t4) = local_ends(&e);
        assert!(
            Sample::from_exchange(&e, t1, t4).is_none(),
            "clamping this to zero hands the source the narrowest interval there is on the              strength of the one thing it said that is provably wrong"
        );
    }

    #[test]
    fn a_source_stating_nothing_is_floored_rather_than_taken_at_its_word() {
        // Zero round trip and zero stated uncertainty, which is what a hostile server sends.
        let mut e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        e.t3 = UnixNanos(e.t3.as_nanos() + 2 * NANOS_PER_MILLI);
        e.root_delay = 0;
        e.root_dispersion = 0;
        let s = sample_of(&e);
        assert_eq!(s.round_trip, 0);
        assert_eq!(s.interval_at(s.taken_at, 0.0, 0).width(), 0);
        assert_eq!(
            s.interval_at(s.taken_at, 0.0, NANOS_PER_MILLI).width(),
            2 * NANOS_PER_MILLI
        );
    }

    #[test]
    fn a_tai_source_is_brought_onto_utc() {
        let mut e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        e.timescale = Timescale::Tai { offset_seconds: 37 };
        e.t2 = UnixNanos(e.t2.as_nanos() + 37 * NANOS_PER_SEC);
        e.t3 = UnixNanos(e.t3.as_nanos() + 37 * NANOS_PER_SEC);
        let s = sample_of(&e);
        assert_eq!(s.offset, 0);
        assert_eq!(s.timescale, Timescale::Tai { offset_seconds: 37 });
    }

    #[test]
    fn an_older_sample_supports_a_wider_interval() {
        let e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        let s = sample_of(&e);
        let fresh = s.interval_at(s.taken_at, 15.0, 0);
        let stale = s.interval_at(s.taken_at.advanced(600 * NANOS_PER_SEC), 15.0, 0);
        assert!(stale.width() > fresh.width());
        assert_eq!(
            stale.width() - fresh.width(),
            2 * crate::policy::ppm_over(15.0, 600 * NANOS_PER_SEC)
        );
    }
}
