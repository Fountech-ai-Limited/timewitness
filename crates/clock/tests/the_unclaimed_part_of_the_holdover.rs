//! The part of the oscillator allowance that covers a rate the model is not correcting for.
//!
//! A receipt carries the whole holdover and, from receipt format version 1, this part of it beside
//! the whole. Before 2026-09-21 the part was inside the whole and nothing said how much, so a reader
//! could not tell the oscillator's own uncertainty from a rate the agent measured and declined to
//! stand behind. These tests hold the part to the term `oscillator_holdover` adds for it, to the
//! whole it is part of, and to nought wherever a rate is claimed.

use timewitness_clock::policy::{ppm_over, WIDEST};
use timewitness_clock::{oscillator_holdover, unclaimed_rate, BandReading, Policy, RateKnowledge};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};

const ELAPSED: [Nanos; 6] = [
    0,
    1,
    NANOS_PER_MILLI,
    NANOS_PER_SEC,
    64 * NANOS_PER_SEC,
    3_600 * NANOS_PER_SEC,
];

#[test]
fn before_a_fit_the_part_is_half_the_band_over_the_elapsed_time() {
    let policy = Policy::default();
    let rate = RateKnowledge::before_a_fit(&policy);
    for elapsed in ELAPSED {
        let holdover = oscillator_holdover(&policy, &rate, elapsed);
        let part = unclaimed_rate(&rate, elapsed, holdover);
        assert_eq!(
            part,
            ppm_over(policy.frequency_span_ppm / 2.0, elapsed),
            "over {elapsed} ns before any fit"
        );
        assert!(part <= holdover, "a part is never more than its whole");
    }
    assert!(
        unclaimed_rate(
            &rate,
            64 * NANOS_PER_SEC,
            oscillator_holdover(&policy, &rate, 64 * NANOS_PER_SEC)
        ) > 0,
        "over a minute before any fit the unclaimed part is not nought, which is the whole reason \
         it is worth stating"
    );
}

#[test]
fn a_rate_the_model_claims_leaves_nothing_unclaimed() {
    let policy = Policy::default();
    let rate = RateKnowledge {
        frequency_ppm: Some(4.25),
        frequency_stderr_ppm: 0.1,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::NotRead,
    };
    for elapsed in ELAPSED {
        let holdover = oscillator_holdover(&policy, &rate, elapsed);
        assert_eq!(unclaimed_rate(&rate, elapsed, holdover), 0);
    }
}

#[test]
fn a_refused_fit_outside_the_band_is_carried_at_the_magnitude_it_found() {
    let policy = Policy::default();
    // A fit of 400 ppm against a band of 100: the model refuses it and carries the larger figure.
    let rate = RateKnowledge {
        frequency_ppm: None,
        frequency_stderr_ppm: policy.frequency_floor_ppm,
        unclaimed_frequency_ppm: 400.0,
        band: BandReading::NotRead,
    };
    let elapsed = 10 * NANOS_PER_SEC;
    let holdover = oscillator_holdover(&policy, &rate, elapsed);
    let part = unclaimed_rate(&rate, elapsed, holdover);
    assert_eq!(part, ppm_over(400.0, elapsed));
    assert!(part <= holdover);
}

#[test]
fn a_rate_nobody_can_read_is_the_whole_holdover_and_never_nought() {
    let policy = Policy::default();
    let rate = RateKnowledge {
        frequency_ppm: None,
        frequency_stderr_ppm: policy.frequency_floor_ppm,
        unclaimed_frequency_ppm: f64::NAN,
        band: BandReading::NotRead,
    };
    let elapsed = NANOS_PER_SEC;
    let holdover = oscillator_holdover(&policy, &rate, elapsed);
    assert_eq!(holdover, WIDEST);
    assert_eq!(unclaimed_rate(&rate, elapsed, holdover), WIDEST);
}
