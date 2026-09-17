//! The width, worked out here and compared with the model's.
//!
//! `bound_battery.rs` next door attacks the bound: it asks whether the interval still holds a truth
//! the test wrote down, under asymmetry, holdover, a lying source and a rate that moves. Every one
//! of those questions is about whether the bound is wide enough, and none of them is about how wide
//! it is. So the whole of `crates/clock` stayed green through a mutation that halved the coverage
//! factor on the largest term in the width. Five hundred and seventy-six tests, and the one thing
//! that is fatal, a bound quietly too narrow, is the one direction none of them could see.
//!
//! This file computes the width by hand from the policy and the numbers the last synchronisation
//! fitted, and asserts the model's answer term by term. The arithmetic below is written out
//! longhand on purpose: calling the model's own helpers would make this a test that the code agrees
//! with itself, which is what was already there.
//!
//! The two mutations it was watched failing against, both on `crates/clock/src/model.rs`:
//!
//! - halving the coverage factor where `measurement_ppm` is built, which was found to leave
//!   every other test binary green;
//! - quartering the whole `widen` term, which before this file turned exactly one test red, and
//!   that one was about a refusal rather than about a width.

mod common;

use common::{Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy, SyncFit};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Stamp};

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The five terms of a half width, each one worked out here.
#[derive(Debug)]
struct ByHand {
    intersection_half: Nanos,
    oscillator_holdover: Nanos,
    model_residual: Nanos,
    scheduling: Nanos,
    safety_margin: Nanos,
    /// How long the model had been extrapolating when the reading was taken.
    elapsed: Nanos,
    /// The rate uncertainty the model had measured, before the allowance for the rate moving.
    measurement_ppm: f64,
    /// What that would have been if the floor were doing the work instead of the measurement.
    floor_ppm: f64,
}

impl ByHand {
    fn half_width(&self) -> Nanos {
        self.intersection_half
            + self.oscillator_holdover
            + self.model_residual
            + self.scheduling
            + self.safety_margin
    }
}

/// The width the model ought to report, from the policy, the fit and the counter it is read at.
///
/// Every line of this is the arithmetic written out rather than the model's own functions called.
/// `ppm_over` and `scaled` both round away from zero, so the rounding is written out too: a term
/// that rounded the other way would be a bound a fraction of a nanosecond too narrow, and the point
/// of this file is that nothing about the width goes unchecked because it looks too small to matter.
fn by_hand(policy: &Policy, fit: &SyncFit, scheduling: Nanos, at: MonotonicNanos) -> ByHand {
    // From the moment the newest exchange went out, whichever way the counter went since.
    let elapsed = at.signed_since(fit.newest_exchange_sent).abs();

    // How wrong the fitted rate was when it was fitted, floored at what the hardware can support,
    // plus the magnitude of any rate the model refused to stand behind.
    let measured = fit.frequency_stderr_ppm * policy.coverage_factor;
    let measurement_ppm = if measured > policy.frequency_floor_ppm {
        measured
    } else {
        policy.frequency_floor_ppm
    } + fit.unclaimed_frequency_ppm;

    // How far the rate may have moved since, at the slew rate and capped at the whole band.
    let movement_ppm = if elapsed <= 0 {
        0.0
    } else {
        let seconds = elapsed as f64 / NANOS_PER_SEC as f64;
        let slewed = policy.frequency_slew_ppm_per_second * seconds;
        if slewed > policy.frequency_span_ppm {
            policy.frequency_span_ppm
        } else {
            slewed
        }
    };

    let ppm = measurement_ppm + movement_ppm;
    let oscillator_holdover = if elapsed <= 0 {
        0
    } else {
        (ppm * elapsed as f64 / 1_000_000.0).ceil() as Nanos + policy.holdover_allowance
    };

    let model_residual = (fit.offset_stderr as f64 * policy.coverage_factor).ceil() as Nanos;

    // Half the Marzullo region, rounded up so the parts never add to less than the whole.
    let width = fit.intersection.hi - fit.intersection.lo;
    let intersection_half = (width + 1).div_euclid(2);

    ByHand {
        intersection_half,
        oscillator_holdover,
        model_residual,
        scheduling,
        safety_margin: policy.safety_margin,
        elapsed,
        measurement_ppm,
        floor_ppm: policy.frequency_floor_ppm + fit.unclaimed_frequency_ppm,
    }
}

/// Compares a reading with the arithmetic, one term at a time and then the whole.
fn agrees(stamp: &Stamp, hand: &ByHand) {
    let parts = &stamp.bound.breakdown;
    assert_eq!(
        parts.intersection_half, hand.intersection_half,
        "the sources overlapping"
    );
    assert_eq!(
        parts.oscillator_holdover, hand.oscillator_holdover,
        "the oscillator since the last exchange"
    );
    assert_eq!(
        parts.model_residual, hand.model_residual,
        "the model's own residual"
    );
    assert_eq!(parts.scheduling, hand.scheduling, "the local read");
    assert_eq!(parts.safety_margin, hand.safety_margin, "the safety margin");
    assert_eq!(parts.half_width(), hand.half_width(), "the five together");

    // The reported interval is the intersection plus the widening on each side, so the width is
    // twice the half width and not the half width plus something.
    assert_eq!(
        stamp.bound.width(),
        2 * hand.half_width(),
        "the interval on the reading against the parts it says it is made of"
    );
}

struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    policy: Policy,
}

impl Rig {
    fn new(world: World, policy: Policy) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
            policy,
        }
    }

    /// One round against paths whose delays are not the same as last time.
    ///
    /// A path with a fixed delay produces the same offset every round, the line through those
    /// points is perfect, and the fitted standard errors come out at nothing. A model whose
    /// measured uncertainty is zero has the policy floor doing all the work, and a mutation to the
    /// measured term is then invisible: that is why the halving survived the suite. So the round
    /// trips move round to round, the way a real path does.
    fn round(&mut self, jitter_us: i128) {
        let now = self.clock.now();
        let paths = [
            Path::honest("alpha", 12, 1),
            Path::honest("bravo", 24, 2),
            Path::honest("charlie", 8, 1),
            Path::honest("delta", 40, 3),
        ];
        for (n, path) in paths.iter().enumerate() {
            let lean = ((n as i128 % 2) * 2 - 1) * jitter_us * NANOS_PER_MICRO;
            let mut path = path.clone();
            path.out += lean;
            path.back -= lean;
            let exchange = self.world.exchange(&path, now);
            self.model.ingest(&exchange);
        }
        self.model.synchronise();
    }

    fn now(&self) -> MonotonicNanos {
        self.clock.now()
    }
}

/// A model that has been running long enough to have fitted a rate, on a path that moves.
fn settled(policy: Policy) -> Rig {
    let mut rig = Rig::new(World::drifting(0, 12.0), policy);
    // Sixteen rounds is the shipped default and a fit needs at least three.
    for round in 0..16 {
        if round > 0 {
            rig.clock.advance_seconds(32);
        }
        // The lean walks so the residuals scatter rather than repeating.
        rig.round(120 + (round as i128 % 5) * 90);
    }
    rig
}

/// The policy the arithmetic cases run on: the shipped one with the independence floor lowered.
///
/// Four simulated sources, each its own operator, against a shipped floor of four operators. The
/// floor has its own tests and none of them is here.
fn policy() -> Policy {
    Policy {
        min_operators: 2,
        ..Policy::default()
    }
}

#[test]
fn every_term_of_the_width_is_the_arithmetic_and_not_whatever_the_model_says() {
    let rig = settled(policy());
    // Read part way into the gap, so the model is extrapolating and the oscillator term is real.
    rig.clock.advance_seconds(9);

    let at = rig.now();
    let fit = rig.model.fit().expect("a settled model has a fit");
    let hand = by_hand(&rig.policy, &fit, rig.model.scheduling_allowance(), at);
    let stamp = rig.model.read().expect("a settled model reads");

    assert!(
        hand.elapsed > 0,
        "this case is about the terms that grow with time, so it has to be extrapolating"
    );
    agrees(&stamp, &hand);
}

#[test]
fn the_coverage_factor_on_the_measured_rate_is_what_the_policy_says() {
    // The floor is what hides a change to the measured term, and since the evening of 2026-09-17
    // it cannot be lowered below the shipped figure, so the measured term is raised above it
    // instead, by a coverage factor large enough that the fit's own error times it clears fifteen
    // parts per million. The case asserts that it did: with the floor above the measurement,
    // halving the coverage factor changes nothing and this file would pass over the mutation it
    // exists to catch.
    let rig = settled(Policy {
        coverage_factor: 12.0,
        max_bound_width: NANOS_PER_SEC,
        ..policy()
    });
    rig.clock.advance_seconds(9);

    let at = rig.now();
    let fit = rig.model.fit().expect("a settled model has a fit");
    let hand = by_hand(&rig.policy, &fit, rig.model.scheduling_allowance(), at);
    let stamp = rig.model.read().expect("a settled model reads");

    assert!(
        hand.measurement_ppm > hand.floor_ppm,
        "the measured rate uncertainty is {} ppm and the floor is {} ppm, so the floor is doing \
         the work and a change to the measured term would not show. Either the fixture stopped \
         producing scatter or the floor moved.",
        hand.measurement_ppm,
        hand.floor_ppm
    );
    assert!(
        fit.frequency_stderr_ppm > 0.0,
        "with no measured uncertainty at all, doubling or halving it is the same number"
    );
    agrees(&stamp, &hand);
}

#[test]
fn the_width_at_the_moment_of_synchronisation_carries_no_holdover() {
    let rig = settled(policy());

    // Read at the same counter as the newest exchange: nothing has elapsed, so the two terms that
    // grow with time are nought and the rest are not. Without this the oscillator term could be
    // anything at all at zero elapsed and every other case would still pass.
    let at = rig.now();
    let fit = rig.model.fit().expect("a settled model has a fit");
    let hand = by_hand(&rig.policy, &fit, rig.model.scheduling_allowance(), at);
    let stamp = rig.model.read().expect("a settled model reads");

    assert_eq!(hand.elapsed, 0, "the fixture reads at the newest exchange");
    assert_eq!(
        stamp.bound.breakdown.oscillator_holdover, 0,
        "nothing has elapsed, so nothing is owed for the oscillator or the holdover allowance"
    );
    agrees(&stamp, &hand);
}

#[test]
fn the_terms_that_grow_with_time_grow_by_the_arithmetic_and_not_by_a_habit() {
    let rig = settled(policy());

    // Three readings across a gap. Each is checked against the arithmetic at its own counter, so a
    // term that grew at the wrong rate fails at the reading where it first disagrees rather than
    // being averaged away.
    let mut last = 0;
    for seconds in [1_u64, 20, 300] {
        rig.clock.advance_seconds(seconds);
        let at = rig.now();
        let fit = rig.model.fit().expect("a settled model has a fit");
        let hand = by_hand(&rig.policy, &fit, rig.model.scheduling_allowance(), at);
        let stamp = rig.model.read().expect("this is inside the ceiling");
        agrees(&stamp, &hand);
        assert!(
            stamp.bound.width() > last,
            "a bound that has been extrapolating longer is never narrower"
        );
        last = stamp.bound.width();
    }
}

#[test]
fn the_fixed_allowances_are_the_policy_and_nothing_else() {
    // A policy whose fixed terms are all different from the shipped ones, so a term that reads a
    // constant instead of the policy fails here rather than agreeing by luck.
    let rig = settled(Policy {
        safety_margin: 731 * NANOS_PER_MICRO,
        holdover_allowance: 379 * NANOS_PER_MICRO,
        scheduling_floor: 43 * NANOS_PER_MICRO,
        ..policy()
    });
    rig.clock.advance_seconds(9);

    let at = rig.now();
    let fit = rig.model.fit().expect("a settled model has a fit");
    let hand = by_hand(&rig.policy, &fit, rig.model.scheduling_allowance(), at);
    let stamp = rig.model.read().expect("a settled model reads");

    assert_eq!(stamp.bound.breakdown.safety_margin, 731 * NANOS_PER_MICRO);
    assert_eq!(stamp.bound.breakdown.scheduling, 43 * NANOS_PER_MICRO);
    agrees(&stamp, &hand);
}

/// The reading a receipt is anchored to sits inside the interval reported with it.
///
/// Not the same question as the width, and it is here because the two are computed from the same
/// three lines and a mutation to either shows in only one of them.
#[test]
fn the_reading_is_inside_the_interval_it_is_reported_with() {
    let rig = settled(policy());
    rig.clock.advance_seconds(9);
    let stamp = rig.model.read().expect("a settled model reads");
    let reading = stamp.reading.utc_estimate;
    assert!(
        stamp.bound.earliest <= reading && reading <= stamp.bound.latest,
        "the reading is outside its own bound"
    );
}
