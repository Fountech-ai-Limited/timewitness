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

use crate::model::CounterAgeing;
use crate::policy::WIDEST;

/// Why an exchange was not taken into the model.
///
/// Each of these is something the exchange said that the arithmetic cannot carry, named so that a
/// poller counting bad answers can say which kind it counted. Every one of them is refused before
/// the exchange becomes a sample, so nothing here ever reaches a window, a selection round or a
/// width. Until 2026-09-17 only the first existed and the others were an overflow, a panic or a
/// sample that aged by nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectedExchange {
    /// The source claims to have spent longer thinking than the whole exchange took, so its two
    /// timestamps cannot both be true.
    ImpossibleReply,
    /// A timestamp the source wrote, or the offset or round trip it gives, is further from the
    /// local clock than the arithmetic carries any one term.
    TimestampOutOfRange,
    /// The source states an uncertainty of its own, or a negative one, that no clock can have.
    StatedUncertaintyOutOfRange,
    /// The reply is stamped as having come home before the request left.
    HomeBeforeItLeft,
    /// The request is stamped as having left before this model started, so there is no anchor to
    /// measure it against.
    BeforeTheModelStarted,
}

impl core::fmt::Display for RejectedExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ImpossibleReply => {
                "the source's two timestamps cannot both be true: it claims more processing time \
                 than the whole exchange took"
            }
            Self::TimestampOutOfRange => {
                "a timestamp the source wrote puts its clock further from ours than the arithmetic \
                 carries"
            }
            Self::StatedUncertaintyOutOfRange => {
                "the source states an uncertainty of its own that no clock can have"
            }
            Self::HomeBeforeItLeft => "the reply is stamped as arriving before the request left",
            Self::BeforeTheModelStarted => {
                "the request is stamped as leaving before this model started"
            }
        })
    }
}

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
    /// The monotonic counter as the request went out.
    ///
    /// Kept beside `taken_at` because a reading taken between the two is inside the exchange, and
    /// one taken before this is a reading the counter went backwards to: the model measures its
    /// holdover from here in that one case and from `taken_at` otherwise.
    pub sent_at: MonotonicNanos,
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
    /// Refuses, naming why, where the exchange says something the arithmetic cannot carry: the
    /// source's own two timestamps cannot both be true, which no amount of arithmetic afterwards
    /// can repair (see the round-trip comment below); or a timestamp, the offset or the round trip
    /// is further from the local clock than any one term of a bound is carried, which until
    /// 2026-09-17 was an overflow inside this function rather than a refusal at its door; or the
    /// source states an uncertainty no clock can have.
    ///
    /// Visible inside this crate only. The model is the one thing that holds the anchor, so it is
    /// the one thing allowed to say where the local ends of a round trip were, and a dependant
    /// reaching for the system clock to fill these in is the bug this signature exists to prevent.
    pub(crate) fn from_exchange(
        e: &Exchange,
        local_t1: UnixNanos,
        local_t4: UnixNanos,
    ) -> Result<Self, RejectedExchange> {
        let t1 = local_t1.as_nanos();
        let t2 = e.t2.as_nanos();
        let t3 = e.t3.as_nanos();
        let t4 = local_t4.as_nanos();

        // The two timestamps the source wrote are held to the range every other term is carried in
        // before any arithmetic is done on them. Inside it, no sum or difference of a handful of
        // terms can overflow the integer; outside it, the offset would be one nothing downstream
        // could hold, so the exchange is refused rather than reduced.
        let within = |value: Nanos| (-WIDEST..=WIDEST).contains(&value);
        if !within(t2) || !within(t3) || !within(t1) || !within(t4) {
            return Err(RejectedExchange::TimestampOutOfRange);
        }

        let timescale_correction = match e.timescale {
            Timescale::Tai { offset_seconds } => Nanos::from(offset_seconds) * NANOS_PER_SEC,
            Timescale::Utc | Timescale::Unknown => 0,
        };

        let offset = ((t2 - t1) + (t3 - t4)) / 2 - timescale_correction;
        if !within(offset) {
            return Err(RejectedExchange::TimestampOutOfRange);
        }

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
            return Err(RejectedExchange::ImpossibleReply);
        }
        if round_trip > WIDEST {
            return Err(RejectedExchange::TimestampOutOfRange);
        }

        // A negative uncertainty is not a small one. `stated_uncertainty` floors each half at
        // nought for callers that only want a width; here the claim itself is what is being judged,
        // and a source that wrote a minus sign wrote something no clock can have.
        if e.root_delay < 0 || e.root_dispersion < 0 {
            return Err(RejectedExchange::StatedUncertaintyOutOfRange);
        }
        let stated_uncertainty = e.stated_uncertainty();
        if stated_uncertainty > WIDEST {
            return Err(RejectedExchange::StatedUncertaintyOutOfRange);
        }

        Ok(Self {
            source: e.source.clone(),
            operator: e.operator.clone(),
            kind: e.kind,
            offset,
            round_trip,
            stated_uncertainty,
            sent_at: e.mono_t1,
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
    /// reference. The dispersion term grows with the age of the sample at everything the model
    /// knows about the local counter's rate, because a sample taken a minute ago describes a clock
    /// that has moved since.
    ///
    /// That third term was the frequency floor alone until 2026-09-18, and the floor bounds how
    /// wrong a fitted rate was rather than how fast a raw counter runs. [`CounterAgeing`] is the
    /// whole of what replaced it and carries the reasoning, including why this widens and never
    /// corrects.
    ///
    /// The first two are both the source's to choose, and a source willing to state that it spent
    /// the whole round trip thinking and that it knows its own time exactly makes both of them
    /// zero. `source_floor` is the width below which no source's answer is taken, whatever it says
    /// about itself, and it is applied to those two before the ageing term is added, because the
    /// ageing term is the model's own arithmetic and not a claim of the source's. See
    /// `Policy::source_interval_floor` for where the figure comes from.
    ///
    /// A sample stamped after `now` ages by nothing here. What it can hide is its own round trip's
    /// worth of ageing, because the model's holdover term is measured from the moment the exchange
    /// went out whenever a reading falls before the moment it came home.
    #[must_use]
    pub fn interval_at(
        &self,
        now: MonotonicNanos,
        ageing: &CounterAgeing,
        source_floor: Nanos,
    ) -> OffsetInterval {
        let age = now.since(self.taken_at);
        let dispersion = ageing.dispersion(age);
        let stated = self.split_direction_residual() + self.stated_uncertainty;
        // Saturating, because the dispersion is carried at `WIDEST` whenever a term of it could not
        // be read, and a bound holding that is refused by the ceiling rather than wrapping on the
        // way to it.
        let half = stated.max(source_floor.max(0)).saturating_add(dispersion);
        OffsetInterval::centred(self.offset, half)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BandReading, RateKnowledge};
    use crate::policy::Policy;
    use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
    use timewitness_core::UnixNanos;

    /// An ageing that widens at exactly `ppm` over an age and at nothing else, for arithmetic a
    /// test writes down rather than arithmetic a world produced.
    fn ageing_at(ppm: f64) -> CounterAgeing {
        let policy = Policy {
            frequency_floor_ppm: ppm,
            frequency_slew_ppm_per_second: 0.0,
            ..Policy::default()
        };
        let rate = RateKnowledge {
            frequency_ppm: None,
            frequency_stderr_ppm: 0.0,
            unclaimed_frequency_ppm: 0.0,
            band: BandReading::NotRead,
        };
        CounterAgeing::new(&policy, &rate)
    }

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
        let interval = s.interval_at(s.taken_at, &ageing_at(0.0), 0);
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
            Sample::from_exchange(&e, t1, t4) == Err(RejectedExchange::ImpossibleReply),
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
        assert_eq!(s.interval_at(s.taken_at, &ageing_at(0.0), 0).width(), 0);
        assert_eq!(
            s.interval_at(s.taken_at, &ageing_at(0.0), NANOS_PER_MILLI)
                .width(),
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
    fn a_timestamp_at_the_integer_extremes_is_refused_and_never_overflows() {
        // Every combination of the two source timestamps at i128::MIN and i128::MAX, and each on its
        // own. Until 2026-09-17 each of these was a subtract or add with overflow inside this
        // function, which the release profile turns into a panic in the shipped binary.
        let honest = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        let (t1, t4) = local_ends(&honest);
        let extremes = [None, Some(i128::MIN), Some(i128::MAX)];
        for t2 in extremes {
            for t3 in extremes {
                if t2.is_none() && t3.is_none() {
                    continue;
                }
                let mut e = honest.clone();
                if let Some(v) = t2 {
                    e.t2 = UnixNanos(v);
                }
                if let Some(v) = t3 {
                    e.t3 = UnixNanos(v);
                }
                assert_eq!(
                    Sample::from_exchange(&e, t1, t4),
                    Err(RejectedExchange::TimestampOutOfRange),
                    "t2 {t2:?} t3 {t3:?}"
                );
            }
        }
        // One past the widest term either way is refused too.
        let mut e = honest.clone();
        e.t2 = UnixNanos(crate::policy::WIDEST + 1);
        e.t3 = e.t2;
        assert_eq!(
            Sample::from_exchange(&e, t1, t4),
            Err(RejectedExchange::TimestampOutOfRange)
        );
        // Four timestamps each inside the range whose offset is past it: the source at the far end
        // of the range and the local clock at the near end.
        let mut e = honest.clone();
        e.t2 = UnixNanos(crate::policy::WIDEST);
        e.t3 = e.t2;
        let far = UnixNanos(-crate::policy::WIDEST);
        assert_eq!(
            Sample::from_exchange(&e, far, far),
            Err(RejectedExchange::TimestampOutOfRange)
        );
        // And four inside the range whose round trip is past it: the source claims to have
        // answered the whole width of the range before it was asked.
        let mut e = honest.clone();
        e.t2 = UnixNanos(crate::policy::WIDEST);
        e.t3 = UnixNanos(-crate::policy::WIDEST);
        assert_eq!(
            Sample::from_exchange(&e, t1, t4),
            Err(RejectedExchange::TimestampOutOfRange)
        );
    }

    #[test]
    fn a_stated_uncertainty_no_clock_can_have_is_refused() {
        let (t1, t4) = local_ends(&exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0));
        for (delay, dispersion) in [
            (-1, 0),
            (0, -1),
            (i128::MIN, i128::MIN),
            (i128::MAX, 0),
            (0, i128::MAX),
            (i128::MAX, i128::MAX),
            (crate::policy::WIDEST, crate::policy::WIDEST),
        ] {
            let mut e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
            e.root_delay = delay;
            e.root_dispersion = dispersion;
            assert_eq!(
                Sample::from_exchange(&e, t1, t4),
                Err(RejectedExchange::StatedUncertaintyOutOfRange),
                "delay {delay} dispersion {dispersion}"
            );
        }
    }

    #[test]
    fn an_older_sample_supports_a_wider_interval() {
        let e = exchange(0, NANOS_PER_MILLI, NANOS_PER_MILLI, 0);
        let s = sample_of(&e);
        let fresh = s.interval_at(s.taken_at, &ageing_at(15.0), 0);
        let stale = s.interval_at(
            s.taken_at.advanced(600 * NANOS_PER_SEC),
            &ageing_at(15.0),
            0,
        );
        assert!(stale.width() > fresh.width());
        assert_eq!(
            stale.width() - fresh.width(),
            2 * crate::policy::ppm_over(15.0, 600 * NANOS_PER_SEC)
        );
    }
}
