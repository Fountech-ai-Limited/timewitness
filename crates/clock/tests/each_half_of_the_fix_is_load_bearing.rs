//! The two changes of 2026-09-18 evening, each held by a test that fails when it alone is reverted.
//!
//! The P0 of that afternoon was fixed by two things: the band caps the ageing widening, and a
//! window picks the sample a round is built from by narrowest aged interval rather than by shortest
//! round trip. The regression case for it, `a_fresh_agent_at_the_shipped_cadence.rs`, is a
//! simulated curve over twelve minutes, and on 2026-09-19 it was measured going green with either
//! change reverted on its own. It only goes red on both. A rig that cannot tell a half-reverted fix
//! from a whole one is not holding either half in, and a later run reading it green would take that
//! as licence to take one of them out.
//!
//! So the two halves are held here, as arithmetic rather than as a longer curve. That is the right
//! shape for a second reason, measured on the same day: a binary with the cap removed and nothing
//! else changed is indistinguishable from the head over twenty minutes against the nine published
//! servers, so the curve going green on that revert is not hiding a live convergence break. There
//! is not one. What the cap does is keep the widening inside the assumption the rest of the
//! arithmetic rests on, and that is a statement about the arithmetic, so it is tested as one.
//!
//! Neither test here is a measurement of a path. Both are values written down and read back.

use timewitness_clock::{BandReading, CounterAgeing, Policy, RateKnowledge, Sample, SourceWindow};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
};

/// Half the band `Policy::default` states, which is the largest magnitude a part may honestly show.
fn half_band(policy: &Policy) -> f64 {
    policy.frequency_span_ppm / 2.0
}

/// A rate the model has fitted and will stand behind, with an error bar sharp enough to separate
/// one rate in the band from another.
fn a_claimed_rate(ppm: f64) -> RateKnowledge {
    RateKnowledge {
        frequency_ppm: Some(ppm),
        frequency_stderr_ppm: 1.0,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::Inside {
            magnitude_ppm: ppm.abs(),
        },
    }
}

/// A fit that puts this machine inside the band widens by no more than half the band over any age.
///
/// This is the first assumption of the whole ageing arithmetic said back to it: on a machine whose
/// true rate magnitude never passes half the band, half the band over the age is a widening that
/// holds whatever a fit says, so a fit can narrow that and never needs to widen it. The terms are
/// added rather than maximised because they are independent facts, and added they run past the
/// figure they are all bounded by.
///
/// The arithmetic on `Policy::default`, at a claimed 40.0 ppm with a standard error of 1.0: the
/// measurement term is the floor at 15.0, the claimed magnitude is 40.0, nothing is unclaimed, and
/// the rate may have moved by the slew over the age. The sum passes half the band, 50.0, at every
/// age here. Remove the cap and this reads 56.0 ppm at a second and 65.0 at ten.
#[test]
fn a_fit_inside_the_band_widens_by_no_more_than_half_the_band() {
    let policy = Policy::default();
    let half = half_band(&policy);
    let ageing = CounterAgeing::new(&policy, &a_claimed_rate(40.0));

    for seconds in [1 as Nanos, 2, 5, 10, 60] {
        let age = seconds * NANOS_PER_SEC;
        let ppm = ageing.ppm(age);
        assert!(
            ppm <= half,
            "a fit claiming 40.0 ppm inside a band of {} widened at {ppm} ppm over {seconds} s, \
             which is past the half band of {half} the rest of this arithmetic assumes",
            policy.frequency_span_ppm
        );
    }

    // And the cap is not a ceiling on everything, which is the other way this could be wrong. A
    // magnitude past half the band is the machine saying the band is wrong about it, and there the
    // sum is carried whole.
    let outside = CounterAgeing::new(&policy, &a_claimed_rate(60.0));
    let ppm = outside.ppm(NANOS_PER_SEC);
    assert!(
        ppm > half,
        "a fit claiming 60.0 ppm, which is past half the band, widened at {ppm} ppm, so the cap \
         was applied to a machine that has said the band is wrong about it"
    );
}

/// An ageing that widens at exactly `ppm` over an age and at nothing else.
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

fn sample(offset: Nanos, round_trip: Nanos, taken_at: u64) -> Sample {
    Sample {
        source: SourceId::new("s"),
        operator: Operator::new("s"),
        kind: SourceKind::Ntp,
        offset,
        round_trip,
        stated_uncertainty: 0,
        sent_at: MonotonicNanos(taken_at),
        taken_at: MonotonicNanos(taken_at),
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
    }
}

/// The interval a source supports now is the narrowest one it supports now, not the one it knew
/// best when it was taken and not the newest one it has.
///
/// The window here separates the three rules. The oldest sample has the shortest round trip, so a
/// rule reading what the sample knew when it was taken picks it; the newest has the longest, so a
/// rule reading recency picks it; and the middle one is neither, and is the narrowest once each has
/// been aged forward to now. At a thousand parts per million a second of age costs a millisecond,
/// so the arithmetic is written here rather than derived: 2 ms of round trip and 10 s of age is
/// 22 ms wide, 20 ms of round trip and half a second of age is 21 ms, and 6 ms of round trip and
/// 2 s of age is 10 ms.
///
/// Reverting `best_within` to the shortest round trip reads 22 ms here, and reverting `interval_at`
/// to the newest sample reads 21 ms. Both are the selection change of 2026-09-18 taken back out on
/// its own, which the twelve-minute curve does not notice.
#[test]
fn a_window_offers_the_narrowest_interval_after_ageing_and_not_before_it() {
    let now = MonotonicNanos(10 * NANOS_PER_SEC as u64);
    let ageing = ageing_at(1000.0);

    let mut window = SourceWindow::new(SourceId::new("s"), 8);
    // Oldest, quickest: 1 ms of its own plus 10 ms of ageing.
    window.push(sample(1, 2 * NANOS_PER_MILLI, 0));
    // Neither quickest nor newest, and narrowest once aged: 3 ms of its own plus 2 ms of ageing.
    window.push(sample(2, 6 * NANOS_PER_MILLI, 8 * NANOS_PER_SEC as u64));
    // Newest, slowest: 10 ms of its own plus half a millisecond of ageing.
    window.push(sample(
        3,
        20 * NANOS_PER_MILLI,
        9_500 * NANOS_PER_MILLI as u64,
    ));

    let chosen = window
        .best_within(now, Nanos::MAX, &ageing, 0)
        .expect("the window holds three samples");
    assert_eq!(
        chosen.offset, 2,
        "the window picked the sample at offset {}, which is the quickest or the newest rather \
         than the narrowest once aged",
        chosen.offset
    );

    let interval = window
        .interval_at(now, &ageing, 0)
        .expect("the window holds three samples");
    assert_eq!(
        interval.width(),
        10 * NANOS_PER_MILLI,
        "the interval the window offers is {} ms wide, and the narrowest its samples support at \
         this instant is 10 ms",
        interval.width() as f64 / NANOS_PER_MILLI as f64
    );
}
