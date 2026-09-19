//! The band before a fit, proved on the arithmetic with no world in the test.
//!
//! The invariant: wherever the model corrects for no rate, and before anything
//! has been fitted is the first such place, the allowance it carries for the oscillator is at least
//! half the band the policy states, times the elapsed time. Half the band is the largest magnitude a
//! part may honestly show, so under the assumption that the machine's true rate never passes it, an
//! allowance of that size over the elapsed time holds a truth that started inside the sources'
//! intersection, whatever the rate inside the band actually is.
//!
//! This file asserts that on the width composition itself, over a generated set of legal policies
//! with every field that enters the allowance at its floor, at its default and above it, in
//! combination, and over a ladder of elapsed times from one nanosecond to the policy's own holdover
//! ceiling. No world, no sources, no rounds. `a_read_before_a_fit.rs` then confirms it on worlds.
//! Three fixes in one day each passed a sample of worlds and lost to the next member of the
//! class, which is why the grade is the proof and the grid is the confirmation.
//!
//! Frozen and hashed before the diff was opened, 2026-09-18. It names the two things the diff has to
//! provide: `RateKnowledge`, what the width knows about the oscillator's rate, with `before_a_fit`
//! and `from_fit`; and `oscillator_holdover`, the composition `read()` puts in the breakdown under
//! that name. Until the diff exists this file does not compile, which is the point: the bar is
//! written down before the thing it measures.
//!
//! The second half is the second net. No branch of the composition answers with a permitting
//! value where it could not read its input: a rate that is not a finite number no less than nought
//! is an infinite allowance, which `ppm_over` carries as `WIDEST` and the ceiling refuses. Each of
//! those tests is named for the guard it holds, and each goes red when that guard is reverted.

use timewitness_clock::policy::{
    ppm_over, FREQUENCY_FLOOR_PPM, SLEW_FLOOR_PPM_PER_SECOND, SPAN_FLOOR_PPM, WIDEST,
    WIDEST_RATE_PPM,
};
use timewitness_clock::regression::Fit;
use timewitness_clock::{oscillator_holdover, BandReading, Policy, RateKnowledge};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};

fn d() -> Policy {
    Policy::default()
}

/// Every field that enters the pre-fit allowance, at its floor, its default and above it, in
/// combination. The other fields do not enter it and stay at the default.
fn legal_policies() -> Vec<Policy> {
    let floors = [
        FREQUENCY_FLOOR_PPM,
        2.0 * FREQUENCY_FLOOR_PPM,
        WIDEST_RATE_PPM,
    ];
    let slews = [SLEW_FLOOR_PPM_PER_SECOND, 5.0, WIDEST_RATE_PPM];
    let spans = [SPAN_FLOOR_PPM, 1_000.0, WIDEST_RATE_PPM];
    let coverages = [1.0, 2.0, 10.0, f64::MAX];
    let allowances = [0, 500 * NANOS_PER_MICRO, WIDEST];
    let holdovers = [1, 3_600 * NANOS_PER_SEC, WIDEST];
    let mut out = Vec::new();
    for floor in floors {
        for slew in slews {
            for span in spans {
                for coverage in coverages {
                    for allowance in allowances {
                        for holdover in holdovers {
                            let policy = Policy {
                                frequency_floor_ppm: floor,
                                frequency_slew_ppm_per_second: slew,
                                frequency_span_ppm: span,
                                coverage_factor: coverage,
                                holdover_allowance: allowance,
                                max_holdover: holdover,
                                ..d()
                            };
                            // A floor past half the band has been refused since 2026-09-19: the
                            // floor says the rate could be out by at least that much and the band
                            // says its magnitude never passes half the band, so a policy saying
                            // both cannot be honoured. This sweep crosses every rate with every
                            // other, so it builds those combinations, and what it must not do is
                            // quietly drop a policy for some other reason. So the refusal is
                            // matched rather than skipped.
                            match policy.fault() {
                                None => out.push(policy),
                                Some(why) => assert!(
                                    why.contains("past half the band"),
                                    "{policy:?} is refused for something other than the floor \
                                     passing half the band: {why}"
                                ),
                            }
                        }
                    }
                }
            }
        }
    }
    // The sweep is worth nothing if the refusal above has swallowed most of it, and a count that
    // only ever goes down is the way that happens without anybody noticing. Three of the nine
    // floor and band pairs are refused, the three whose floor is the widest rate, so six ninths of
    // 972 stand. The number is written out rather than computed, because computing it from the
    // same lists that built it would agree with anything.
    assert_eq!(
        out.len(),
        648,
        "the sweep is meant to cross six of its nine floor and band pairs over everything else"
    );
    out
}

/// One nanosecond doubling to the holdover ceiling, the ceiling itself, and the three reads the
/// arithmetic below is worked at by hand.
fn elapsed_ladder(max_holdover: Nanos) -> Vec<Nanos> {
    let mut out = Vec::new();
    let mut e: Nanos = 1;
    while e < max_holdover {
        out.push(e);
        e = e.saturating_mul(2);
    }
    out.push(max_holdover);
    for s in [9, 32, 900] {
        let e = s * NANOS_PER_SEC;
        if e <= max_holdover {
            out.push(e);
        }
    }
    out
}

#[test]
fn before_a_fit_the_allowance_is_at_least_half_the_band_over_every_elapsed_on_every_legal_policy() {
    let mut cells = 0usize;
    for policy in legal_policies() {
        let rate = RateKnowledge::before_a_fit(&policy);
        assert!(
            rate.frequency_ppm.is_none(),
            "nothing is fitted before a fit"
        );
        for elapsed in elapsed_ladder(policy.max_holdover) {
            let allowance = oscillator_holdover(&policy, &rate, elapsed);
            let half_band = ppm_over(policy.frequency_span_ppm / 2.0, elapsed);
            assert!(
                allowance >= half_band,
                "before a fit, over {elapsed} ns, the allowance is {allowance} ns and half the band \
                 comes to {half_band} ns: {policy:?}"
            );
            cells += 1;
        }
    }
    // 24624 from 2026-09-19, where it was 36936 before. Three of the nine floor and band pairs are
    // now refused by `Policy::fault`, so two thirds of the policies stand and the ladder over each
    // is unchanged. The floor is written out rather than computed, because a count computed from
    // the lists that built it agrees with anything.
    assert!(
        cells >= 24_624,
        "{cells} cells is not the grid this file describes"
    );
}

/// The fits `regression::fit` can hand back, at the edges the model decides on.
fn fits() -> Vec<Fit> {
    let rates = [
        0.0,
        3.0,
        -3.0,
        49.9,
        -49.9,
        50.1,
        -50.1,
        80.0,
        -80.0,
        1e4,
        -1e4,
        1e9,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    let errors = [0.0, 1.0, 40.0, 51.0, 200.0, 1e6, f64::NAN, f64::INFINITY];
    let mut out = Vec::new();
    for rate in rates {
        for error in errors {
            out.push(Fit {
                offset: 0,
                offset_stderr: 0,
                frequency_ppm: rate,
                frequency_stderr_ppm: error,
                points: 3,
            });
        }
    }
    out
}

#[test]
fn a_fit_the_model_will_not_stand_behind_carries_at_least_half_the_band_too() {
    // Wherever the model corrects for no rate, the same invariant holds. A fit is refused for
    // sitting outside the band or for an error bar wider than the band, and either way the
    // magnitude carried is at least half the band, so a third reason for refusing added later
    // cannot narrow it by accident.
    for policy in legal_policies().into_iter().step_by(7) {
        for fit in fits() {
            let rate = RateKnowledge::from_fit(&fit, &policy);
            match rate.frequency_ppm {
                Some(claimed) => {
                    assert!(claimed.is_finite());
                    assert_eq!(claimed.to_bits(), fit.frequency_ppm.to_bits());
                    assert!(claimed.abs() <= policy.frequency_span_ppm / 2.0, "{fit:?}");
                    assert!(
                        fit.frequency_stderr_ppm * policy.coverage_factor
                            <= policy.frequency_span_ppm,
                        "{fit:?}"
                    );
                    assert_eq!(rate.unclaimed_frequency_ppm.to_bits(), 0.0_f64.to_bits());
                }
                None => {
                    for elapsed in [1, NANOS_PER_SEC, 9 * NANOS_PER_SEC, 3_600 * NANOS_PER_SEC] {
                        let allowance = oscillator_holdover(&policy, &rate, elapsed);
                        let half_band = ppm_over(policy.frequency_span_ppm / 2.0, elapsed);
                        assert!(
                            allowance >= half_band,
                            "a refused fit {fit:?} over {elapsed} ns carries {allowance} ns against \
                             half the band at {half_band} ns: {policy:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn the_arithmetic_at_n28_and_at_the_default_by_hand() {
    // N28's policy: coverage one, every allowance nought, the rates at the shipped figures. Before
    // a fit the allowance is the floor, plus half the band, plus the slew over the elapsed time,
    // over that elapsed time. On a machine drifting forty parts per million the truth moves 360 us
    // in nine seconds and the interval used to widen by 216 us.
    let n28 = Policy {
        coverage_factor: 1.0,
        holdover_allowance: 0,
        safety_margin: 0,
        scheduling_floor: 0,
        ..d()
    };
    let before = RateKnowledge::before_a_fit(&n28);
    assert_eq!(
        oscillator_holdover(&n28, &before, 9 * NANOS_PER_SEC),
        666 * NANOS_PER_MICRO
    );
    assert_eq!(
        oscillator_holdover(&n28, &before, 32 * NANOS_PER_SEC),
        3_104 * NANOS_PER_MICRO
    );
    assert_eq!(
        oscillator_holdover(&n28, &before, 900 * NANOS_PER_SEC),
        148_500 * NANOS_PER_MICRO
    );
    // The default at nine seconds: thirty, plus fifty, plus nine, over nine seconds, and the fixed
    // holdover allowance on top.
    let shipped = RateKnowledge::before_a_fit(&d());
    assert_eq!(
        oscillator_holdover(&d(), &shipped, 9 * NANOS_PER_SEC),
        801 * NANOS_PER_MICRO + d().holdover_allowance
    );
    // And nothing over no elapsed time, because nothing has moved.
    assert_eq!(oscillator_holdover(&d(), &shipped, 0), 0);
    assert_eq!(oscillator_holdover(&n28, &before, 0), 0);
}

// -------------------------------------------------------------------------------------------------
// The second net. Each test below is named for one guard and goes red when that guard alone is reverted.
// -------------------------------------------------------------------------------------------------

#[test]
fn a_band_nobody_can_read_is_an_infinite_magnitude_before_a_fit() {
    // The validator refuses each of these first; this is the second net, and it widens.
    for span in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -100.0,
        0.0,
        -0.0,
    ] {
        let policy = Policy {
            frequency_span_ppm: span,
            ..d()
        };
        let rate = RateKnowledge::before_a_fit(&policy);
        assert!(
            rate.unclaimed_frequency_ppm.is_infinite() && rate.unclaimed_frequency_ppm > 0.0,
            "a band of {span} gave an unclaimed magnitude of {}",
            rate.unclaimed_frequency_ppm
        );
        assert_eq!(
            oscillator_holdover(&policy, &rate, NANOS_PER_SEC),
            WIDEST,
            "band {span}"
        );
    }
}

#[test]
fn a_measurement_nobody_can_read_widens_and_never_falls_to_the_floor() {
    // `f64::max` answers with the other operand when one is not a number, so a standard error that
    // was not a number used to come out as the floor: the permitting value on exactly the input
    // that says the measurement cannot be known.
    for error in [f64::NAN, -1.0, f64::NEG_INFINITY, f64::INFINITY] {
        let rate = RateKnowledge {
            frequency_ppm: Some(0.0),
            frequency_stderr_ppm: error,
            unclaimed_frequency_ppm: 0.0,
            band: BandReading::NotRead,
        };
        assert_eq!(
            oscillator_holdover(&d(), &rate, NANOS_PER_SEC),
            WIDEST,
            "error {error}"
        );
    }
    let sound = RateKnowledge {
        frequency_ppm: Some(0.0),
        frequency_stderr_ppm: 1.0,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::NotRead,
    };
    for coverage in [f64::NAN, f64::INFINITY, -1.0] {
        let policy = Policy {
            coverage_factor: coverage,
            ..d()
        };
        assert_eq!(
            oscillator_holdover(&policy, &sound, NANOS_PER_SEC),
            WIDEST,
            "coverage {coverage}"
        );
    }
    for floor in [f64::NAN, f64::NEG_INFINITY, -15.0] {
        let policy = Policy {
            frequency_floor_ppm: floor,
            ..d()
        };
        assert_eq!(
            oscillator_holdover(&policy, &sound, NANOS_PER_SEC),
            WIDEST,
            "floor {floor}"
        );
    }
}

#[test]
fn an_unclaimed_magnitude_nobody_can_read_widens() {
    for unclaimed in [f64::NAN, -1.0, f64::NEG_INFINITY, f64::INFINITY] {
        let rate = RateKnowledge {
            frequency_ppm: None,
            frequency_stderr_ppm: FREQUENCY_FLOOR_PPM,
            unclaimed_frequency_ppm: unclaimed,
            band: BandReading::NotRead,
        };
        assert_eq!(
            oscillator_holdover(&d(), &rate, NANOS_PER_SEC),
            WIDEST,
            "unclaimed {unclaimed}"
        );
    }
}

#[test]
fn a_rate_movement_nobody_can_read_is_an_infinite_allowance() {
    // A claimed rate with no error, so the movement term is the only thing that can widen this.
    let claimed = RateKnowledge {
        frequency_ppm: Some(0.0),
        frequency_stderr_ppm: 0.0,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::NotRead,
    };
    for slew in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let policy = Policy {
            frequency_slew_ppm_per_second: slew,
            ..d()
        };
        assert_eq!(
            oscillator_holdover(&policy, &claimed, NANOS_PER_SEC),
            WIDEST,
            "slew {slew}"
        );
    }
    for span in [0.0, -0.0, -100.0, f64::NAN, f64::NEG_INFINITY] {
        let policy = Policy {
            frequency_span_ppm: span,
            ..d()
        };
        assert_eq!(
            oscillator_holdover(&policy, &claimed, NANOS_PER_SEC),
            WIDEST,
            "span {span}"
        );
    }
    // A finite, positive slew and band still give a finite allowance, so the net is only the net.
    assert!(oscillator_holdover(&d(), &claimed, NANOS_PER_SEC) < WIDEST);
}
