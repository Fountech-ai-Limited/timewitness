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
use timewitness_core::time::{Nanos, NANOS_PER_MICRO};
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
