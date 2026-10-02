//! How long a baseline buys anything, and where it stops.
//!
//! The model's own residual is the largest single part of the bound on the resident agent's path.
//! It falls as more synchronisations pile up, because the regression has more points, so the obvious
//! thing to try is to leave an agent running for hours. This file is the answer to whether that
//! works, and the answer is that it stops working after thirty minutes.
//!
//! `Policy::regression_window` is 1800 seconds and `ClockModel` drops every point older than that
//! before `history_capacity` can bind. At the agent's shipped thirty-two second cadence that is
//! about fifty-six points, reached after half an hour, and never more however long the agent runs.
//!
//! **This is a simulated network with a known true offset, per `common/mod.rs`, so the numbers here
//! are the arithmetic of the model rather than a reading from a real path.** What it establishes is
//! the shape: that the fall stops, and that where it stops is set by the window rather than by how
//! long anything ran. The measurement on a real path was taken separately and it agrees.

mod common;

use common::{Path, World};

use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::MonotonicNanos;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The agent's own cadence, which is what makes the point count a function of the window.
const CADENCE_S: u64 = 32;

/// Run a model for `rounds` synchronisations at the agent's cadence and hand back the residual
/// after each one, in nanoseconds of half width.
///
/// The width ceiling is raised because these are simulated paths and the quantity under test is the
/// residual rather than the width. Nothing else about the policy is touched, so the window and the
/// history capacity are the shipped ones and this measures them as they ship.
fn residual_after_each_round(rounds: usize, window: Nanos) -> Vec<Nanos> {
    let policy = Policy {
        max_bound_width: 30_000 * NANOS_PER_MILLI,
        regression_window: window,
        ..Policy::default()
    };
    let paths: Vec<Path> = vec![
        Path::honest("alpha", 20, 1).operated_by("one.example"),
        Path::honest("bravo", 24, 2).operated_by("two.example"),
        Path::honest("charlie", 16, 1).operated_by("three.example"),
        Path::honest("delta", 28, 2).operated_by("four.example"),
    ];

    // A clock running a little fast, so there is a real slope for the line to find and the residual
    // is the scatter about it rather than an artefact of a perfectly flat series.
    let world = World::drifting(0, 3.0).with_residual(NANOS_PER_MILLI / 2);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);

    let mut residuals = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let now = clock.now();
        for path in &paths {
            model.ingest(&world.exchange(path, now));
        }
        if model.synchronise().is_valid() {
            if let Ok(stamp) = model.read() {
                residuals.push(stamp.bound.breakdown.model_residual);
            }
        }
        clock.advance_seconds(CADENCE_S);
    }
    residuals
}

#[test]
fn the_residual_falls_while_the_window_fills_and_then_stops() {
    // Two hours at the agent's cadence, which is four times the window. If the fall were a function
    // of how long the agent has been up, the last half hour would be meaningfully better than the
    // hour before it. It is not.
    let window = Policy::default().regression_window;
    let rounds = (2 * 3_600 / CADENCE_S) as usize;
    let residuals = residual_after_each_round(rounds, window);
    assert!(
        residuals.len() > rounds / 2,
        "the fixture has to keep producing bounds for two simulated hours, and it produced {}",
        residuals.len()
    );

    let at = |seconds: u64| residuals[(seconds / CADENCE_S) as usize - 1];

    // While the window fills, the residual falls and it falls a long way.
    assert!(
        at(300) > at(1_500) * 2,
        "five minutes in it was {} and twenty-five minutes in it was {}, which is not the fall a \
         filling window is supposed to produce",
        at(300),
        at(1_500)
    );

    // Past the window it does not. Half an hour, one hour and two hours are the same number to
    // within a tenth, and the fixture has no noise in it that would explain them apart.
    let plateau = at(1_800);
    for hours_in in [3_600u64, 5_400, 7_000] {
        let later = at(hours_in);
        let apart = (later - plateau).abs();
        assert!(
            apart * 10 <= plateau,
            "at {hours_in} s the residual is {later} against {plateau} at the window, which is more \
             than a tenth apart: the window is not what is binding"
        );
    }
}

#[test]
fn a_window_twice_as_long_plateaus_lower_and_that_is_what_makes_it_the_window() {
    // The other half of the claim, and the half that says it is the window rather than something
    // else about the fixture. Twice the window is twice the points, so the plateau should be lower
    // by about the square root of two. Both runs are otherwise identical.
    let shipped = Policy::default().regression_window;
    let rounds = (2 * 3_600 / CADENCE_S) as usize;

    let at_hour = |window: Nanos| {
        let residuals = residual_after_each_round(rounds, window);
        residuals[(3_600 / CADENCE_S) as usize - 1]
    };

    let narrow = at_hour(shipped);
    let wide = at_hour(2 * shipped);
    assert!(
        wide < narrow,
        "twice the window did not lower the plateau: {wide} against {narrow}"
    );
    // Somewhere near the square root of two, and stated as a range because the scatter of the
    // fixture is real and the point is the shape rather than a coefficient.
    let ratio = narrow as f64 / wide as f64;
    assert!(
        (1.15..=1.75).contains(&ratio),
        "the plateau moved by {ratio}, and the square root of two is what doubling the points buys"
    );
}

#[test]
fn the_window_is_what_the_policy_says_it_is() {
    // The number the two tests above are about, asserted where somebody looking for it will find it,
    // so a change to it turns this red rather than quietly changing what they measure.
    assert_eq!(Policy::default().regression_window, 1_800 * NANOS_PER_SEC);
    assert_eq!(Policy::default().history_capacity, 256);
    // And the capacity is not what binds at the shipped cadence: half an hour at thirty-two seconds
    // is about fifty-six points, which is a long way under it.
    let points_in_a_window = 1_800 / CADENCE_S;
    assert!(points_in_a_window < Policy::default().history_capacity as u64);
}

#[test]
#[ignore = "prints the curve rather than asserting anything; run it with --ignored to read it"]
fn the_curve_itself() {
    let window = Policy::default().regression_window;
    let residuals = residual_after_each_round((2 * 3_600 / CADENCE_S) as usize, window);
    for seconds in [
        300u64, 600, 900, 1_200, 1_500, 1_800, 2_400, 3_600, 5_400, 7_000,
    ] {
        let i = (seconds / CADENCE_S) as usize - 1;
        if i < residuals.len() {
            println!("{seconds} s\t{} ns", residuals[i]);
        }
    }
}
