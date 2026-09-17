//! A policy the arithmetic cannot stand behind is refused, and never narrows the bound.
//!
//! Every field of `Policy` is public, so a caller can build one by struct update from the default
//! and go round anything a constructor would check. Until 2026-09-17 a coverage factor of nought, a
//! negative one or not a number made the model's own residual vanish, and a rate in parts per
//! million that was not a number made the allowance for the oscillator vanish. Those are the two
//! largest terms in a real receipt's width, and each went to zero at the moment the input was known
//! to be wrong.
//!
//! Each case here is one attack from a set written down before the fix was opened, and kept under the
//! name it had there. The test for every attack is the same: the model refuses, or the interval it states is no narrower than the one the same
//! model states on the same exchanges under the shipped policy. A panic fails.

mod common;

use common::{Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Validity};

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The shipped policy with the independence floor lowered, because the four simulated sources are
/// four operators and the floor has tests of its own elsewhere.
fn shipped() -> Policy {
    Policy {
        min_operators: 2,
        ..Policy::default()
    }
}

/// Sixteen rounds on paths whose delays move, then a reading nine seconds into the gap.
///
/// The paths move so the fit has scatter to measure. With none, the fitted errors are nought and a
/// coverage factor multiplies nothing, which is how an attack on it would pass without being tested.
fn width_under(policy: Policy) -> Result<Nanos, Validity> {
    let world = World::drifting(0, 12.0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
    let paths = [
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 40, 3),
    ];
    for round in 0..16_i128 {
        if round > 0 {
            clock.advance_seconds(32);
        }
        let jitter_us = 120 + (round % 5) * 90;
        let now = clock.now();
        for (n, path) in paths.iter().enumerate() {
            let lean = ((n as i128 % 2) * 2 - 1) * jitter_us * NANOS_PER_MICRO;
            let mut path = path.clone();
            path.out += lean;
            path.back -= lean;
            model.ingest(&world.exchange(&path, now));
        }
        model.synchronise();
    }
    clock.advance_seconds(9);
    model
        .read()
        .map(|stamp| stamp.bound.width())
        .map_err(|refusal| refusal.validity)
}

/// The one question every attack is asked.
fn refused_or_no_narrower(attack: &str, policy: Policy) {
    let honest = width_under(shipped()).expect("the shipped policy reads on this fixture");
    match width_under(policy) {
        Err(validity) => assert!(
            !validity.is_valid(),
            "{attack}: a refusal has to carry a reason other than valid"
        ),
        Ok(width) => assert!(
            width >= honest,
            "{attack}: the model signed {width} ns where the shipped policy gives {honest} ns"
        ),
    }
}

fn coverage(factor: f64) -> Policy {
    Policy {
        coverage_factor: factor,
        ..shipped()
    }
}

#[test]
fn a1_a_coverage_factor_of_nought() {
    refused_or_no_narrower("A1", coverage(0.0));
}

#[test]
fn a2_a_negative_coverage_factor() {
    refused_or_no_narrower("A2", coverage(-1.0));
}

#[test]
fn a3_a_coverage_factor_that_is_not_a_number() {
    refused_or_no_narrower("A3", coverage(f64::NAN));
}

#[test]
fn a4_a_coverage_factor_of_a_half() {
    refused_or_no_narrower("A4", coverage(0.5));
}

#[test]
fn a5_a_coverage_factor_of_negative_nought() {
    refused_or_no_narrower("A5", coverage(-0.0));
}

#[test]
fn a6_the_smallest_positive_coverage_factor() {
    refused_or_no_narrower("A6", coverage(f64::MIN_POSITIVE));
}

#[test]
fn a7_a_subnormal_coverage_factor() {
    refused_or_no_narrower("A7", coverage(5e-324));
}

#[test]
fn a8_a_coverage_factor_just_under_one() {
    refused_or_no_narrower("A8", coverage(0.999_999_999));
}

#[test]
fn a9_an_infinite_coverage_factor() {
    refused_or_no_narrower("A9", coverage(f64::INFINITY));
}

#[test]
fn a10_a_negative_infinite_coverage_factor() {
    refused_or_no_narrower("A10", coverage(f64::NEG_INFINITY));
}

/// Every rate in parts per million the policy carries, set to one bad value in turn.
fn every_rate(attack: &str, value: f64) {
    let fields: [(&str, Policy); 3] = [
        (
            "frequency_floor_ppm",
            Policy {
                frequency_floor_ppm: value,
                ..shipped()
            },
        ),
        (
            "frequency_slew_ppm_per_second",
            Policy {
                frequency_slew_ppm_per_second: value,
                ..shipped()
            },
        ),
        (
            "frequency_span_ppm",
            Policy {
                frequency_span_ppm: value,
                ..shipped()
            },
        ),
    ];
    for (field, policy) in fields {
        refused_or_no_narrower(&format!("{attack} on {field}"), policy);
    }
}

#[test]
fn b1_a_rate_that_is_not_a_number() {
    every_rate("B1", f64::NAN);
}

#[test]
fn b2_an_infinite_rate() {
    every_rate("B2", f64::INFINITY);
}

#[test]
fn b3_a_negative_infinite_rate() {
    every_rate("B3", f64::NEG_INFINITY);
}

#[test]
fn b4_a_negative_rate() {
    every_rate("B4", -5.0);
}

#[test]
fn b5_a_rate_of_ten_to_the_three_hundred() {
    every_rate("B5", 1e300);
}

#[test]
fn b6_a_rate_of_negative_nought() {
    every_rate("B6", -0.0);
}

/// Each rate one float below the figure this product ships, and at nought and a subnormal.
///
/// Refused by name rather than only no narrower, because these were legal until the evening of
/// 2026-09-17 and a cold set (`tests/build-checks/2026-09-17-181-3/attacks.tsv` under the product
/// root, D02 to D07 and R20) found that with the rates at nought, and with the slew or the band
/// alone at nought or subnormal, a policy the validator accepted signed a bound with the truth
/// outside it from fifteen minutes into holdover. A rate below the shipped figure is a claim about
/// hardware nobody measured.
#[test]
fn b7_a_rate_below_the_figure_this_product_ships() {
    let below = |floor: f64| f64::from_bits(floor.to_bits() - 1);
    for value in [0.0, 5e-324, f64::MIN_POSITIVE] {
        refused_naming(
            "B7",
            "frequency_floor_ppm",
            Policy {
                frequency_floor_ppm: value,
                ..shipped()
            },
        );
        refused_naming(
            "B7",
            "frequency_slew_ppm_per_second",
            Policy {
                frequency_slew_ppm_per_second: value,
                ..shipped()
            },
        );
        refused_naming(
            "B7",
            "frequency_span_ppm",
            Policy {
                frequency_span_ppm: value,
                ..shipped()
            },
        );
    }
    let d = Policy::default();
    refused_naming(
        "B7",
        "frequency_floor_ppm",
        Policy {
            frequency_floor_ppm: below(d.frequency_floor_ppm),
            ..shipped()
        },
    );
    refused_naming(
        "B7",
        "frequency_slew_ppm_per_second",
        Policy {
            frequency_slew_ppm_per_second: below(d.frequency_slew_ppm_per_second),
            ..shipped()
        },
    );
    refused_naming(
        "B7",
        "frequency_span_ppm",
        Policy {
            frequency_span_ppm: below(d.frequency_span_ppm),
            ..shipped()
        },
    );
    // All three at nought together, which is R20 of the afternoon's frozen set and signed 15.520 ms at 900 s
    // with the truth outside at 3399099.
    refused_naming(
        "B7",
        "frequency_floor_ppm",
        Policy {
            frequency_floor_ppm: 0.0,
            frequency_slew_ppm_per_second: 0.0,
            frequency_span_ppm: 0.0,
            ..shipped()
        },
    );
}

// Every other field, one test each, from the cold set frozen on the afternoon of 2026-09-17 at
// `tests/build-checks/2026-09-17-181-2/attacks.tsv` under the product root, after the morning's fix
// held on the coverage factor and the rates and a set written without sight of it found five sibling
// fields still narrowing and one panicking. The ids are that set's. Each value is the wrong side of
// the field's own range: a minus sign, nought where nought is not a floor, the integer's floor and
// ceiling, and one past the widest any term is carried as. A value the validator refuses is asserted
// refused by name, because "no narrower" was already true of half these fields and a test that
// passed before the guard went in is not watching it.

const WIDEST: Nanos = i64::MAX as Nanos;

/// The policy is refused before anything is read, and the refusal names the field.
fn refused_naming(attack: &str, field: &str, policy: Policy) {
    match width_under(policy) {
        Err(Validity::PolicyRefused { detail }) => {
            assert!(
                detail.contains(field),
                "{attack}: refused for something else: {detail}"
            );
        }
        Err(other) => {
            panic!("{attack}: refused as {other:?} rather than as a policy fault naming {field}")
        }
        Ok(width) => {
            panic!("{attack}: the model signed {width} ns under a policy it should have refused")
        }
    }
}

/// The bound is refused, by the ceiling or by the policy, and nothing panics.
fn refused(attack: &str, policy: Policy) {
    match width_under(policy) {
        Err(validity) => assert!(
            !validity.is_valid(),
            "{attack}: a refusal has to carry a reason"
        ),
        Ok(width) => panic!("{attack}: the model signed {width} ns where a refusal was due"),
    }
}

fn nanos_field(attack: &str, field: &str, set: impl Fn(Nanos) -> Policy, values: &[Nanos]) {
    for value in values {
        refused_naming(&format!("{attack} at {value}"), field, set(*value));
    }
}

#[test]
fn c1_holdover_allowance_outside_its_range() {
    nanos_field(
        "B01 to B04",
        "holdover_allowance",
        |v| Policy {
            holdover_allowance: v,
            ..shipped()
        },
        &[-1, i128::MIN, WIDEST + 1, i128::MAX],
    );
    // B05: at the cap it is legal, and the first reading in holdover is refused as too wide.
    refused_or_no_narrower(
        "B05",
        Policy {
            holdover_allowance: WIDEST,
            ..shipped()
        },
    );
}

#[test]
fn c2_safety_margin_outside_its_range() {
    nanos_field(
        "B06 to B08",
        "safety_margin",
        |v| Policy {
            safety_margin: v,
            ..shipped()
        },
        &[-1, i128::MIN + 1, i128::MIN, WIDEST + 1],
    );
    // B09: at the cap it is legal, and every reading is refused as too wide.
    refused(
        "B09",
        Policy {
            safety_margin: WIDEST,
            ..shipped()
        },
    );
}

#[test]
fn c3_scheduling_floor_outside_its_range() {
    nanos_field(
        "B10 to B12",
        "scheduling_floor",
        |v| Policy {
            scheduling_floor: v,
            ..shipped()
        },
        &[-1, i128::MIN, WIDEST + 1],
    );
}

#[test]
fn c4_source_interval_floor_outside_its_range() {
    nanos_field(
        "B13 to B16",
        "source_interval_floor",
        |v| Policy {
            source_interval_floor: v,
            ..shipped()
        },
        &[-1, 0, i128::MIN, WIDEST + 1],
    );
}

#[test]
fn c5_weight_floor_outside_its_range() {
    nanos_field(
        "B17 to B19",
        "weight_floor",
        |v| Policy {
            weight_floor: v,
            ..shipped()
        },
        &[0, -1, i128::MIN],
    );
}

#[test]
fn c6_max_bound_width_outside_its_range() {
    nanos_field(
        "B20 to B23",
        "max_bound_width",
        |v| Policy {
            max_bound_width: v,
            ..shipped()
        },
        &[0, -1, i128::MIN, WIDEST + 1],
    );
    // B24: the ceiling at the integer's own ceiling with three margins at the cap signed a bound of
    // thirty-six billion seconds until 2026-09-17, and overflowed on placing the ends one step past.
    refused_naming(
        "B24",
        "max_bound_width",
        Policy {
            max_bound_width: i128::MAX,
            safety_margin: WIDEST,
            holdover_allowance: WIDEST,
            scheduling_floor: WIDEST,
            ..shipped()
        },
    );
    // B78: a ceiling of a nanosecond is legal and refuses every real bound as too wide.
    refused(
        "B78",
        Policy {
            max_bound_width: 1,
            ..shipped()
        },
    );
}

#[test]
fn c7_max_holdover_outside_its_range() {
    nanos_field(
        "B25 to B28",
        "max_holdover",
        |v| Policy {
            max_holdover: v,
            ..shipped()
        },
        &[0, -1, i128::MIN, WIDEST + 1],
    );
    // B76, B77: a short but legal holdover ceiling refuses late readings and narrows none.
    refused_or_no_narrower(
        "B76",
        Policy {
            max_holdover: 10 * NANOS_PER_SEC,
            ..shipped()
        },
    );
    refused_or_no_narrower(
        "B77",
        Policy {
            max_holdover: 31 * NANOS_PER_SEC,
            ..shipped()
        },
    );
}

#[test]
fn c8_leap_smear_window_outside_its_range() {
    nanos_field(
        "B29 to B31",
        "leap_smear_window",
        |v| Policy {
            leap_smear_window: v,
            ..shipped()
        },
        &[-1, i128::MIN, WIDEST + 1],
    );
}

#[test]
fn c9_leap_divergence_ceiling_outside_its_range() {
    nanos_field(
        "B32 to B34",
        "leap_divergence_ceiling",
        |v| Policy {
            leap_divergence_ceiling: v,
            ..shipped()
        },
        &[0, -1, WIDEST + 1],
    );
}

#[test]
fn c10_regression_window_outside_its_range_or_shorter_than_a_poll() {
    nanos_field(
        "B35 to B38",
        "regression_window",
        |v| Policy {
            regression_window: v,
            ..shipped()
        },
        &[0, -1, i128::MIN, WIDEST + 1],
    );
    // B39 to B41: a legal window shorter than the fit needs at the cadence. The fit keeps its minimum
    // points rather than emptying, so the residual stays in the width and nothing narrows.
    for seconds in [31, 40, 100] {
        refused_or_no_narrower(
            &format!("B39 to B41 at {seconds} s"),
            Policy {
                regression_window: seconds * NANOS_PER_SEC,
                ..shipped()
            },
        );
    }
}

#[test]
fn c11_regression_min_points_outside_its_range() {
    for value in [0, 1, 2] {
        refused_naming(
            &format!("B42 to B44 at {value}"),
            "regression_min_points",
            Policy {
                regression_min_points: value,
                ..shipped()
            },
        );
    }
    // B45, B46: more points than the history can hold is refused on the capacity.
    for value in [257, usize::MAX] {
        refused_naming(
            &format!("B45, B46 at {value}"),
            "history_capacity",
            Policy {
                regression_min_points: value,
                ..shipped()
            },
        );
    }
}

#[test]
fn c12_history_capacity_under_the_regression_minimum() {
    for value in [0, 1, 2] {
        refused_naming(
            &format!("B47 to B49 at {value}"),
            "history_capacity",
            Policy {
                history_capacity: value,
                ..shipped()
            },
        );
    }
    // B50 to B52: at the minimum and above it, legal, and no narrower.
    for value in [3, 4, usize::MAX] {
        refused_or_no_narrower(
            &format!("B50 to B52 at {value}"),
            Policy {
                history_capacity: value,
                ..shipped()
            },
        );
    }
    // B73 to B75: the capacity exactly at the minimum, under it, and beside a short window.
    refused_or_no_narrower(
        "B73",
        Policy {
            history_capacity: 3,
            regression_min_points: 3,
            ..shipped()
        },
    );
    refused_naming(
        "B74",
        "history_capacity",
        Policy {
            history_capacity: 3,
            regression_min_points: 4,
            ..shipped()
        },
    );
    refused_or_no_narrower(
        "B75",
        Policy {
            history_capacity: 3,
            regression_window: 31 * NANOS_PER_SEC,
            ..shipped()
        },
    );
}

#[test]
fn c13_counts_of_nought() {
    refused_naming(
        "B53",
        "samples_per_source",
        Policy {
            samples_per_source: 0,
            ..shipped()
        },
    );
    refused_or_no_narrower(
        "B54",
        Policy {
            samples_per_source: usize::MAX,
            ..shipped()
        },
    );
    refused_naming(
        "B55",
        "min_sources",
        Policy {
            min_sources: 0,
            ..shipped()
        },
    );
    refused_or_no_narrower(
        "B56",
        Policy {
            min_sources: 1,
            ..shipped()
        },
    );
    refused_naming(
        "B57",
        "min_operators",
        Policy {
            min_operators: 0,
            ..shipped()
        },
    );
    refused(
        "B58",
        Policy {
            min_operators: usize::MAX,
            ..shipped()
        },
    );
}

#[test]
fn c14_a_rate_past_the_whole_clock() {
    for (attack, value) in [("B62, B65, B67", 1e6 + 1.0), ("B63", f64::MAX)] {
        refused_naming(
            attack,
            "frequency_floor_ppm",
            Policy {
                frequency_floor_ppm: value,
                ..shipped()
            },
        );
        refused_naming(
            attack,
            "frequency_slew_ppm_per_second",
            Policy {
                frequency_slew_ppm_per_second: value,
                ..shipped()
            },
        );
        refused_naming(
            attack,
            "frequency_span_ppm",
            Policy {
                frequency_span_ppm: value,
                ..shipped()
            },
        );
    }
    refused_naming(
        "B68",
        "frequency_span_ppm",
        Policy {
            frequency_span_ppm: 1e300,
            ..shipped()
        },
    );
    // B64: at the cap it is legal and only ever wider.
    every_rate("B64", 1e6);
    // B59, B60: a coverage factor that scales the residual past the ceiling is refused as too wide.
    refused(
        "B59",
        Policy {
            coverage_factor: 1e300,
            ..shipped()
        },
    );
    refused(
        "B60",
        Policy {
            coverage_factor: f64::MAX,
            ..shipped()
        },
    );
}

#[test]
fn c15_two_legal_terms_whose_sum_is_past_the_ceiling() {
    refused(
        "B70",
        Policy {
            holdover_allowance: WIDEST,
            safety_margin: WIDEST,
            ..shipped()
        },
    );
    refused(
        "B71",
        Policy {
            holdover_allowance: WIDEST,
            safety_margin: WIDEST,
            scheduling_floor: WIDEST,
            coverage_factor: 1e300,
            ..shipped()
        },
    );
    refused_naming(
        "B72",
        "safety_margin",
        Policy {
            safety_margin: -1,
            holdover_allowance: 500_001,
            ..shipped()
        },
    );
    refused(
        "B79",
        Policy {
            max_bound_width: WIDEST,
            safety_margin: WIDEST,
            ..shipped()
        },
    );
}

/// The same rig as `width_under`, with the read allowance the platform hands in set by the test.
fn width_with_granularity(granularity: Nanos) -> Result<Nanos, Validity> {
    let world = World::drifting(0, 12.0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(
        shipped(),
        Box::new(ClockHandle(clock.clone())),
        wall,
        granularity,
    );
    let paths = [
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 40, 3),
    ];
    for round in 0..16_i128 {
        if round > 0 {
            clock.advance_seconds(32);
        }
        let now = clock.now();
        for path in &paths {
            model.ingest(&world.exchange(path, now));
        }
        model.synchronise();
    }
    clock.advance_seconds(9);
    model
        .read()
        .map(|stamp| stamp.bound.width())
        .map_err(|refusal| refusal.validity)
}

#[test]
fn c16_the_read_allowance_from_the_platform_is_held_to_the_same_range() {
    let honest = width_with_granularity(0).expect("the shipped policy reads on this fixture");
    // B80: past the cap it is refused as too wide rather than overflowing.
    assert!(matches!(
        width_with_granularity(i128::MAX),
        Err(Validity::BoundTooWide { .. })
    ));
    // B81, B82: below the floor it is the floor, and the width is the shipped width.
    assert_eq!(width_with_granularity(-1), Ok(honest));
    assert_eq!(width_with_granularity(i128::MIN), Ok(honest));
    // And the allowance the model settled on is the cap itself, not the integer's ceiling: the
    // ceiling check would refuse either, so this is what pins the cap.
    let world = World::drifting(0, 12.0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let model = ClockModel::new(shipped(), Box::new(ClockHandle(clock)), wall, i128::MAX);
    assert_eq!(model.scheduling_allowance(), WIDEST);
}

#[test]
fn c17_a_bad_policy_refuses_every_method_and_the_callers_copy_reaches_nothing() {
    // B84: built with a policy the validator refuses, nothing signs and nothing panics.
    let world = World::drifting(0, 12.0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let bad = Policy {
        coverage_factor: f64::NAN,
        ..shipped()
    };
    let mut model = ClockModel::new(bad, Box::new(ClockHandle(clock.clone())), wall, 0);
    let now = clock.now();
    assert_eq!(
        model.ingest(&world.exchange(&Path::honest("alpha", 12, 1), now)),
        None
    );
    assert!(matches!(
        model.synchronise(),
        Validity::PolicyRefused { .. }
    ));
    assert!(matches!(model.validity(), Validity::PolicyRefused { .. }));
    assert!(matches!(
        model.read().map_err(|r| r.validity),
        Err(Validity::PolicyRefused { .. })
    ));

    // B83: the model holds its own copy, so a caller editing theirs afterwards changes no width.
    let honest = width_under(shipped()).expect("the shipped policy reads on this fixture");
    let mut callers = shipped();
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let mut model = ClockModel::new(callers, Box::new(ClockHandle(clock.clone())), wall, 0);
    callers.safety_margin = i128::MIN;
    let paths = [
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 40, 3),
    ];
    for round in 0..16_i128 {
        if round > 0 {
            clock.advance_seconds(32);
        }
        let now = clock.now();
        for path in &paths {
            model.ingest(&world.exchange(path, now));
        }
        model.synchronise();
    }
    clock.advance_seconds(9);
    assert_eq!(
        model
            .read()
            .map(|s| s.bound.width())
            .map_err(|r| r.validity),
        Ok(honest)
    );
    assert_eq!(model.policy().safety_margin, shipped().safety_margin);
    assert_eq!(callers.safety_margin, i128::MIN);
}
