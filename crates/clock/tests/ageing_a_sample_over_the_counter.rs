//! Ageing a source's interval over the local counter, proved on the arithmetic with no world.
//!
//! The invariant: a sample aged over the local counter widens by at least everything the model does
//! not know about that counter's rate. Before a fit that is half the band the policy states, which
//! is the largest magnitude a part may honestly show; after one it is the whole magnitude of the
//! rate the model fitted, because this arithmetic widens and never corrects, and `read` is the one
//! place a rate is claimed. `timewitness_clock::CounterAgeing` carries the reasoning for both.
//!
//! What it stands against. Until 2026-09-18 a sample aged at `Policy::frequency_floor_ppm` alone,
//! fifteen parts per million at the default against a band of a hundred, so a machine drifting
//! legally at fifty was displaced by `(50 - 15) x age` more than it was widened for. Where such
//! samples were the majority clique, Marzullo took their intersection and the bound was signed with
//! the truth outside it: 412 of 17280 cells of `a_round_spread_out_in_time.rs`, worst 140.001 us.
//! This file is the proof and that one is the confirmation, the same way round as
//! `the_band_before_a_fit.rs` and `a_read_before_a_fit.rs`, because three fixes on 2026-09-17 each
//! passed a sample of worlds and lost to the next member of the same class.
//!
//! The second half is the second net, and it is the class named on 2026-09-18: a
//! guard that answers "no finding" where it means "cannot tell", because "no finding" permits. No
//! input to this arithmetic that cannot be read comes out as nought or as the floor. Each of those
//! tests is named for the guard it holds and goes red when that guard is reverted.
//!
//! The last part reads a fitted rate back against the band the policy assumes about the machine,
//! which is what nothing in the tree did until this file was written. Four answers and not two: not
//! read at all is its own answer and is not the same as read and found inside.

use timewitness_clock::policy::{
    ppm_over, FREQUENCY_FLOOR_PPM, SLEW_FLOOR_PPM_PER_SECOND, SPAN_FLOOR_PPM, WIDEST,
    WIDEST_RATE_PPM,
};
use timewitness_clock::regression::Fit;
use timewitness_clock::{BandReading, CounterAgeing, Policy, RateKnowledge};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};

fn d() -> Policy {
    Policy::default()
}

/// A ladder of ages, from one nanosecond to an hour, which is the shipped holdover ceiling and so
/// the oldest sample `candidates_at` will offer.
fn ages() -> Vec<Nanos> {
    vec![
        1,
        1_000,
        NANOS_PER_MICRO,
        NANOS_PER_SEC,
        32 * NANOS_PER_SEC,
        600 * NANOS_PER_SEC,
        3_600 * NANOS_PER_SEC,
    ]
}

/// Every field that enters the ageing, at its floor, its default and above it, in combination.
fn legal_policies() -> Vec<Policy> {
    let mut out = Vec::new();
    for floor in [FREQUENCY_FLOOR_PPM, 2.0 * FREQUENCY_FLOOR_PPM, 1_000.0] {
        for slew in [SLEW_FLOOR_PPM_PER_SECOND, 5.0, 1_000.0] {
            for span in [SPAN_FLOOR_PPM, 1_000.0, WIDEST_RATE_PPM] {
                for coverage in [1.0, 2.0, 10.0] {
                    out.push(Policy {
                        frequency_floor_ppm: floor,
                        frequency_slew_ppm_per_second: slew,
                        frequency_span_ppm: span,
                        coverage_factor: coverage,
                        ..d()
                    });
                }
            }
        }
    }
    out
}

/// A rate the model is standing behind, with no measurement error, so the only thing that can widen
/// the ageing is the magnitude itself and the movement.
fn claiming(ppm: f64) -> RateKnowledge {
    RateKnowledge {
        frequency_ppm: Some(ppm),
        frequency_stderr_ppm: 0.0,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::Inside {
            magnitude_ppm: ppm.abs(),
        },
    }
}

#[test]
fn before_a_fit_a_sample_ages_at_no_less_than_half_the_band() {
    for policy in legal_policies() {
        let half = policy.frequency_span_ppm / 2.0;
        let ageing = CounterAgeing::before_a_fit(&policy);
        for age in ages() {
            assert!(
                ageing.ppm(age) >= half,
                "band {} floor {} coverage {} age {age}: aged at {} parts per million, under half \
                 the band at {half}",
                policy.frequency_span_ppm,
                policy.frequency_floor_ppm,
                policy.coverage_factor,
                ageing.ppm(age)
            );
            assert!(
                ageing.dispersion(age) >= ppm_over(half, age),
                "band {} age {age}",
                policy.frequency_span_ppm
            );
        }
    }
}

#[test]
fn a_claimed_rate_is_carried_as_width_and_never_corrected_away() {
    // The one thing this arithmetic must not do is what `read` does. `read` corrects for a rate it
    // will stand behind, once, from the moment the newest exchange went out. Correcting here as
    // well would be a second correction from a second reference instant, and the two come apart the
    // moment a poller synchronises later than the round it is synchronising over.
    for policy in legal_policies() {
        for ppm in [0.0, 1.0, 15.0, 50.0, -50.0, 499.0] {
            let ageing = CounterAgeing::new(&policy, &claiming(ppm));
            for age in ages() {
                assert!(
                    ageing.ppm(age) >= ppm.abs(),
                    "a rate of {ppm} parts per million aged at {} at age {age}",
                    ageing.ppm(age)
                );
            }
        }
    }
}

#[test]
fn an_older_sample_never_supports_a_narrower_interval() {
    for policy in legal_policies() {
        for rate in [RateKnowledge::before_a_fit(&policy), claiming(12.0)] {
            let ageing = CounterAgeing::new(&policy, &rate);
            let mut last = 0;
            for age in ages() {
                let now = ageing.dispersion(age);
                assert!(now >= last, "age {age}: {now} after {last}");
                last = now;
            }
        }
    }
}

#[test]
fn a_sample_stamped_after_the_instant_it_is_used_at_ages_by_nothing() {
    let ageing = CounterAgeing::before_a_fit(&d());
    assert_eq!(ageing.dispersion(0), 0);
    assert_eq!(ageing.dispersion(-1), 0);
    assert_eq!(ageing.dispersion(-NANOS_PER_SEC), 0);
}

#[test]
fn a_measurement_nobody_can_read_widens_and_never_falls_to_the_floor() {
    for error in [f64::NAN, -1.0, f64::NEG_INFINITY, f64::INFINITY] {
        let rate = RateKnowledge {
            frequency_stderr_ppm: error,
            ..claiming(0.0)
        };
        assert_eq!(
            CounterAgeing::new(&d(), &rate).dispersion(NANOS_PER_SEC),
            WIDEST,
            "error {error}"
        );
    }
    for coverage in [f64::NAN, f64::INFINITY, -1.0] {
        let policy = Policy {
            coverage_factor: coverage,
            ..d()
        };
        let rate = RateKnowledge {
            frequency_stderr_ppm: 1.0,
            ..claiming(0.0)
        };
        assert_eq!(
            CounterAgeing::new(&policy, &rate).dispersion(NANOS_PER_SEC),
            WIDEST,
            "coverage {coverage}"
        );
    }
}

#[test]
fn a_floor_nobody_can_read_widens() {
    for floor in [f64::NAN, f64::NEG_INFINITY, -15.0] {
        let policy = Policy {
            frequency_floor_ppm: floor,
            ..d()
        };
        assert_eq!(
            CounterAgeing::new(&policy, &claiming(0.0)).dispersion(NANOS_PER_SEC),
            WIDEST,
            "floor {floor}"
        );
    }
}

#[test]
fn a_claimed_rate_nobody_can_read_widens_rather_than_being_carried_as_nought() {
    // The model says it will stand behind this rate and then hands over something that is not one.
    // Not correcting for it is right; saying nothing about its magnitude is the permitting answer
    // on exactly the input that says the magnitude is unknown.
    for ppm in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let rate = RateKnowledge {
            frequency_ppm: Some(ppm),
            frequency_stderr_ppm: 0.0,
            unclaimed_frequency_ppm: 0.0,
            band: BandReading::Unreadable,
        };
        assert_eq!(
            CounterAgeing::new(&d(), &rate).dispersion(NANOS_PER_SEC),
            WIDEST,
            "claimed rate {ppm}"
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
            CounterAgeing::new(&d(), &rate).dispersion(NANOS_PER_SEC),
            WIDEST,
            "unclaimed {unclaimed}"
        );
    }
}

#[test]
fn a_band_nobody_can_read_widens_a_sample_before_a_fit() {
    for band in [f64::NAN, 0.0, -1.0, f64::INFINITY, f64::NEG_INFINITY] {
        let policy = Policy {
            frequency_span_ppm: band,
            ..d()
        };
        assert_eq!(
            CounterAgeing::before_a_fit(&policy).dispersion(NANOS_PER_SEC),
            WIDEST,
            "band {band}"
        );
    }
}

#[test]
fn a_rate_movement_nobody_can_read_widens_a_sample() {
    for slew in [-1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let policy = Policy {
            frequency_slew_ppm_per_second: slew,
            ..d()
        };
        assert_eq!(
            CounterAgeing::new(&policy, &claiming(0.0)).dispersion(NANOS_PER_SEC),
            WIDEST,
            "slew {slew}"
        );
    }
}

fn fit_at(ppm: f64) -> Fit {
    Fit {
        offset: 0,
        offset_stderr: 0,
        frequency_ppm: ppm,
        frequency_stderr_ppm: 0.1,
        points: 3,
    }
}

#[test]
fn nothing_fitted_is_its_own_answer_and_not_a_rate_inside_the_band() {
    // A boolean here would have said the two were the same thing, and "inside" permits.
    assert_eq!(RateKnowledge::before_a_fit(&d()).band, BandReading::NotRead);
}

#[test]
fn a_fitted_rate_is_read_back_against_the_band() {
    // Half the band at the default is fifty parts per million.
    for ppm in [0.0, 1.0, 49.9, 50.0, -50.0] {
        assert_eq!(
            RateKnowledge::from_fit(&fit_at(ppm), &d()).band,
            BandReading::Inside {
                magnitude_ppm: ppm.abs()
            },
            "rate {ppm}"
        );
    }
    for (ppm, by) in [(50.1_f64, 0.1_f64), (100.0, 50.0), (-120.0, 70.0)] {
        match RateKnowledge::from_fit(&fit_at(ppm), &d()).band {
            BandReading::Outside { by_ppm } => assert!(
                (by_ppm - by).abs() < 1e-9,
                "rate {ppm}: read as {by_ppm} past the band, expected {by}"
            ),
            other => panic!("rate {ppm} read as {other:?}"),
        }
    }
}

#[test]
fn a_rate_or_a_band_nobody_can_read_is_read_as_unreadable_and_never_as_inside() {
    for ppm in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            RateKnowledge::from_fit(&fit_at(ppm), &d()).band,
            BandReading::Unreadable,
            "rate {ppm}"
        );
    }
    for band in [f64::NAN, 0.0, -1.0, f64::INFINITY] {
        let policy = Policy {
            frequency_span_ppm: band,
            ..d()
        };
        assert_eq!(
            RateKnowledge::from_fit(&fit_at(1.0), &policy).band,
            BandReading::Unreadable,
            "band {band}"
        );
    }
}

#[test]
fn a_machine_outside_the_band_is_still_widened_by_what_was_measured() {
    // The reading reports and never gates, so the widening has to be there on its own. A fit past
    // half the band stops being claimed and its magnitude is carried instead, so the bound holds
    // what was measured even though the assumption the band stands for has been broken.
    let rate = RateKnowledge::from_fit(&fit_at(120.0), &d());
    assert_eq!(rate.frequency_ppm, None);
    assert!(rate.unclaimed_frequency_ppm >= 120.0);
    let ageing = CounterAgeing::new(&d(), &rate);
    assert!(ageing.ppm(NANOS_PER_SEC) >= 120.0);
}
