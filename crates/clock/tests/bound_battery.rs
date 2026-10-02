//! The bound arithmetic's own battery.
//!
//! The clock model builds the arithmetic. This file is the discipline that stops it being
//! trusted on the strength of a green suite alone, because the bound is the one number in the
//! whole product that a stranger has to take on faith about our own claim. So it gets attacked
//! rather than exercised.
//!
//! Every test in here was watched failing against the specific mutation it exists to catch before
//! it was allowed to pass. A test that has never been red is a test nobody has checked, and on this
//! particular file that matters more than usual, because a bound that is quietly too narrow looks
//! exactly like a bound that is right.

mod common;

use common::{four_honest_sources, Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, UnixNanos, Validity};

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn new(world: World, paths: Vec<Path>, policy: Policy) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
            paths,
        }
    }

    fn now(&self) -> MonotonicNanos {
        self.clock.now()
    }

    fn poll_and_synchronise(&mut self) -> Validity {
        let now = self.now();
        for p in &self.paths {
            let e = self.world.exchange(p, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }

    fn run_for(&mut self, rounds: usize, spacing_s: u64) -> Validity {
        let mut last = Validity::NeverSynchronised;
        for i in 0..rounds {
            if i > 0 {
                self.clock.advance_seconds(spacing_s);
            }
            last = self.poll_and_synchronise();
        }
        last
    }

    fn truth(&self) -> UnixNanos {
        self.world.utc(self.now())
    }
}

// ---------------------------------------------------------------------------
// The residual: what the split between the two legs can do, and what it cannot
// ---------------------------------------------------------------------------

#[test]
fn the_bound_holds_the_truth_at_every_split_of_the_round_trip() {
    // The whole of the round trip is pushed onto one leg and then the other, and everywhere in
    // between. Every source is skewed the same way, which is the worst case, because a systematic
    // bias shared by every source is the one thing intersecting them cannot see.
    let splits = [0.0, 0.05, 0.2, 0.35, 0.5, 0.65, 0.8, 0.95, 1.0];

    for split in splits {
        let paths: Vec<Path> = four_honest_sources()
            .into_iter()
            .map(|p| p.with_split(split))
            .collect();

        let mut rig = Rig::new(World::still(7), paths, common::arithmetic_policy());
        assert_eq!(rig.run_for(6, 64), Validity::Valid, "split {split}");

        let stamp = rig.model.read().unwrap();
        assert!(
            stamp.bound.contains(rig.truth()),
            "at a split of {split} the bound {:?} does not hold the true time; the reading was {} ns out",
            stamp.bound,
            (stamp.reading.utc_estimate - rig.truth()).abs()
        );
    }
}

#[test]
fn the_worst_case_split_is_the_widest_error_and_the_bound_still_holds() {
    // One source, repeated three times so a majority exists, with every millisecond of a forty
    // millisecond round trip on the outbound leg. The computed offset is then twenty milliseconds
    // wrong, which is exactly half the round trip and exactly what the interval is built to absorb.
    let rtt_ms = 40;
    let paths = vec![
        Path::honest("a", rtt_ms, 0).with_split(1.0),
        Path::honest("b", rtt_ms, 0).with_split(1.0),
        Path::honest("c", rtt_ms, 0).with_split(1.0),
    ];

    let mut rig = Rig::new(World::still(0), paths, common::arithmetic_policy());
    assert_eq!(rig.run_for(6, 64), Validity::Valid);

    let stamp = rig.model.read().unwrap();
    let error = (stamp.reading.utc_estimate - rig.truth()).abs();

    assert!(
        error > 15 * NANOS_PER_MILLI,
        "the point estimate should be badly wrong here, and it is only {error} ns out"
    );
    assert!(
        stamp.bound.contains(rig.truth()),
        "the bound {:?} has to hold the truth even when the point estimate is {error} ns out",
        stamp.bound
    );
}

#[test]
fn the_bound_is_never_narrower_than_half_the_round_trip_plus_what_the_source_stated() {
    // Three identical sources, so the intersection is exactly one source's own interval and the
    // reported width can be compared against the theory directly.
    for (rtt_ms, stated_ms) in [(4, 0), (12, 1), (40, 3), (120, 10)] {
        let paths = vec![
            Path::honest("a", rtt_ms, stated_ms),
            Path::honest("b", rtt_ms, stated_ms),
            Path::honest("c", rtt_ms, stated_ms),
        ];
        let theory = paths[0].expected_half_width();

        let policy = Policy {
            max_bound_width: NANOS_PER_SEC,
            ..common::arithmetic_policy()
        };

        let mut rig = Rig::new(World::still(0), paths, policy);
        assert_eq!(rig.run_for(4, 64), Validity::Valid);

        let stamp = rig.model.read().unwrap();
        let reported_half = stamp.bound.width() / 2;

        assert!(
            reported_half >= theory,
            "a {rtt_ms} ms round trip with {stated_ms} ms of stated uncertainty needs at least \
             {theory} ns of half width and the model reported {reported_half} ns"
        );
    }
}

#[test]
fn a_source_that_states_no_uncertainty_still_carries_half_its_round_trip() {
    let paths = vec![
        Path::honest("a", 30, 0),
        Path::honest("b", 30, 0),
        Path::honest("c", 30, 0),
    ];
    let mut rig = Rig::new(World::still(0), paths, common::arithmetic_policy());
    rig.run_for(4, 64);
    let stamp = rig.model.read().unwrap();
    assert!(stamp.bound.width() / 2 >= 15 * NANOS_PER_MILLI);
}

// ---------------------------------------------------------------------------
// Holdover: the bound grows, and it grows by the right amount
// ---------------------------------------------------------------------------

#[test]
fn the_bound_grows_every_second_the_sources_are_unreachable() {
    let mut rig = Rig::new(
        World::still(2),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(10, 64);

    let mut previous = rig.model.read().unwrap().bound.width();
    let mut samples = 0;

    for _ in 0..50 {
        rig.clock.advance_seconds(60);
        // The outage ends at a refusal rather than at a very wide number, which is its own test.
        // Everything up to that point has to grow.
        let Ok(stamp) = rig.model.read() else { break };
        let width = stamp.bound.width();
        assert!(
            width >= previous,
            "the bound shrank during an outage, from {previous} ns to {width} ns"
        );
        assert!(
            width > previous,
            "the bound stayed flat during an outage, at {width} ns, which is the dishonest answer"
        );
        previous = width;
        samples += 1;
    }

    assert!(
        samples >= 5,
        "only {samples} readings came back at all, so nothing was measured about how the bound grows"
    );
}

#[test]
fn the_bound_grows_by_at_least_the_whole_oscillator_allowance() {
    // Two terms, and the model has to carry both. Fifteen parts per million is the floor under how
    // wrong the fitted frequency was when it was fitted. The allowance for the rate having moved
    // since is separate and larger, and it reaches its whole band well inside twenty minutes.
    //
    // The width ceiling is lifted here because at the default policy it refuses long before this,
    // which is `the_model_refuses_rather_than_extrapolating_through_a_rate_it_cannot_bound` in
    // `rate_change.rs` and is not what this test is about.
    let policy = Policy {
        max_bound_width: NANOS_PER_SEC,
        ..common::arithmetic_policy()
    };
    let mut rig = Rig::new(World::still(0), four_honest_sources(), policy);
    rig.run_for(10, 64);

    let before = rig.model.read().unwrap().bound.width();
    let outage_s = 1_200u64;
    rig.clock.advance_seconds(outage_s);
    let after = rig.model.read().unwrap().bound.width();

    let elapsed: Nanos = (outage_s as Nanos) * NANOS_PER_SEC;
    let allowance_ppm = policy.frequency_floor_ppm
        + (policy.frequency_slew_ppm_per_second * outage_s as f64).min(policy.frequency_span_ppm);
    let least_growth = 2 * ((allowance_ppm * elapsed as f64 / 1_000_000.0) as Nanos);

    assert!(
        after - before >= least_growth,
        "twenty minutes of holdover grew the bound by {} ns and the two allowances alone come to \
         {least_growth} ns",
        after - before
    );
}

#[test]
fn holdover_still_holds_the_truth_on_a_machine_that_is_actually_drifting() {
    // The machine's oscillator is genuinely eight parts per million out. The model measures that,
    // extrapolates with it, and widens for the uncertainty in its own measurement.
    let mut rig = Rig::new(
        World::drifting(0, 8.0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    assert_eq!(rig.run_for(20, 64), Validity::Valid);

    let mut answered = 0;
    for minutes in [1u64, 5, 15, 30, 55] {
        let mut probe = Rig::new(
            World::drifting(0, 8.0),
            four_honest_sources(),
            common::arithmetic_policy(),
        );
        probe.run_for(20, 64);
        probe.clock.advance_seconds(minutes * 60);

        // The longer holdovers end at a refusal, because the allowance for the rate moving reaches
        // its whole band and the width ceiling then bites. Refusing is a correct answer; an
        // interval that does not hold the truth is not.
        let Ok(stamp) = probe.model.read() else {
            continue;
        };
        answered += 1;
        assert!(
            stamp.bound.contains(probe.truth()),
            "after {minutes} minutes of holdover the bound {:?} does not hold the truth",
            stamp.bound
        );
    }
    assert!(answered >= 3, "only {answered} of five holdovers answered");
}

#[test]
fn the_point_estimate_never_leaves_its_own_bound() {
    let mut rig = Rig::new(
        World::drifting(11, -6.0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(15, 64);

    let mut samples = 0;
    for _ in 0..40 {
        rig.clock.advance_seconds(45);
        // Once the holdover is long enough the answer is a refusal, and a refusal has no reading
        // to sit outside anything.
        let Ok(stamp) = rig.model.read() else { break };
        assert!(
            stamp.estimate_within_bound(),
            "the reading {:?} sits outside its own bound {:?}",
            stamp.reading,
            stamp.bound
        );
        samples += 1;
    }
    assert!(samples >= 5, "only {samples} readings came back at all");
}

// ---------------------------------------------------------------------------
// Refusal: what makes the bound invalid, and what the model does about it
// ---------------------------------------------------------------------------

#[test]
fn a_model_that_has_never_synchronised_refuses() {
    let rig = Rig::new(
        World::still(0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    let refusal = rig.model.read().expect_err("nothing has been measured yet");
    assert_eq!(refusal.validity, Validity::NeverSynchronised);
}

#[test]
fn a_resume_from_sleep_refuses_and_does_not_return_the_last_good_bound() {
    let mut rig = Rig::new(
        World::still(5),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(8, 64);
    let good = rig.model.read().unwrap();

    rig.model.note_resume();

    let refusal = rig
        .model
        .read()
        .expect_err("a bound says nothing across a suspend");
    assert_eq!(
        refusal.validity,
        Validity::SuspendedSinceLastSync {
            resume_generation: 1
        }
    );
    assert_eq!(rig.model.generations().resume, 1);

    // The refusal is a refusal and not a wider version of the old answer.
    drop(good);

    // And it clears only on a real synchronisation.
    rig.clock.advance_seconds(64);
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
    assert!(rig.model.read().is_ok());
}

#[test]
fn holdover_past_the_ceiling_refuses_rather_than_extrapolating_further() {
    let policy = Policy {
        max_holdover: 600 * NANOS_PER_SEC,
        ..common::arithmetic_policy()
    };

    let mut rig = Rig::new(World::still(0), four_honest_sources(), policy);
    rig.run_for(8, 64);
    assert!(rig.model.read().is_ok());

    rig.clock.advance_seconds(601);
    let refusal = rig
        .model
        .read()
        .expect_err("past the ceiling this is arithmetic, not measurement");
    match refusal.validity {
        Validity::HoldoverExceeded { elapsed, ceiling } => {
            assert!(elapsed > ceiling);
            assert_eq!(ceiling, 600 * NANOS_PER_SEC);
        }
        other => panic!("expected a holdover refusal and got {other:?}"),
    }
}

#[test]
fn a_timescale_conflict_refuses_once_the_model_is_told() {
    let mut rig = Rig::new(
        World::still(0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(8, 64);
    assert!(rig.model.read().is_ok());

    rig.model.force_invalid(Validity::TimescaleConflict {
        detail: "alpha smears a leap second and bravo steps it".to_string(),
    });

    let refusal = rig
        .model
        .read()
        .expect_err("an ambiguous interval near a leap event is refused");
    assert!(matches!(
        refusal.validity,
        Validity::TimescaleConflict { .. }
    ));
    assert!(refusal.to_string().contains("leap second"));

    rig.model.clear_forced();
    assert!(rig.model.read().is_ok());
}

#[test]
fn every_refusal_says_why_in_words_a_person_can_act_on() {
    let cases = [
        Validity::NeverSynchronised,
        Validity::SuspendedSinceLastSync {
            resume_generation: 3,
        },
        Validity::HoldoverExceeded {
            elapsed: 2 * NANOS_PER_SEC,
            ceiling: NANOS_PER_SEC,
        },
        Validity::InsufficientSources {
            present: 1,
            required: 3,
        },
        Validity::NoMajority {
            present: 4,
            agreeing: 2,
        },
        Validity::FreeMajority {
            present: 3,
            informative: 2,
        },
        Validity::TimescaleConflict {
            detail: "alpha and bravo".to_string(),
        },
        Validity::BoundTooWide {
            width: 2 * NANOS_PER_SEC,
            ceiling: NANOS_PER_SEC,
        },
    ];

    for case in cases {
        let said = timewitness_core::Refusal::new(case.clone()).to_string();
        assert!(said.len() > 20, "{case:?} explains itself as {said:?}");
        assert!(!said.contains("error"), "a refusal is not an error message");
    }
}

#[test]
fn a_refusal_is_never_a_very_wide_bound() {
    // The three invalidating conditions, one after another, each checked for the same thing: the
    // caller gets nothing rather than something it might use.
    let mut rig = Rig::new(
        World::still(0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(8, 64);

    rig.model.note_resume();
    assert!(rig.model.read().is_err());

    rig.clock.advance_seconds(64);
    rig.poll_and_synchronise();
    rig.model.force_invalid(Validity::TimescaleConflict {
        detail: "mixed smear".to_string(),
    });
    assert!(rig.model.read().is_err());
    rig.model.clear_forced();

    let tight = Policy {
        max_holdover: 10 * NANOS_PER_SEC,
        ..common::arithmetic_policy()
    };
    let mut short = Rig::new(World::still(0), four_honest_sources(), tight);
    short.run_for(4, 1);
    short.clock.advance_seconds(11);
    assert!(short.model.read().is_err());
}

// ---------------------------------------------------------------------------
// The arithmetic reports itself honestly
// ---------------------------------------------------------------------------

#[test]
fn the_breakdown_never_adds_to_less_than_the_bound_it_describes() {
    let mut rig = Rig::new(
        World::drifting(3, 5.0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(12, 64);

    for step in 0..30 {
        // Read at a spread of holdover ages, then synchronise again so the run never walks past
        // the holdover ceiling, which is its own refusal and is tested on its own.
        rig.clock.advance_seconds(30 + step * 7);
        let stamp = rig.model.read().unwrap();
        let b = stamp.bound.breakdown;
        assert!(
            2 * b.half_width() >= stamp.bound.width(),
            "the parts add to {} and the whole is {}",
            2 * b.half_width(),
            stamp.bound.width()
        );
        rig.poll_and_synchronise();
    }
}

#[test]
fn the_network_term_is_reported_and_is_not_added_twice() {
    let mut rig = Rig::new(
        World::still(0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.run_for(8, 64);
    let stamp = rig.model.read().unwrap();
    let b = stamp.bound.breakdown;

    assert!(
        b.widest_source_network_half > 0,
        "the network figure should be reported"
    );
    let sum_with_network = b.half_width() + b.widest_source_network_half;
    assert!(
        2 * b.half_width() <= stamp.bound.width() + 1,
        "the network figure has been counted into the width as well as reported"
    );
    assert!(sum_with_network > b.half_width());
}

#[test]
fn a_stamp_carries_the_boot_and_resume_generations_a_verifier_needs() {
    let mut rig = Rig::new(
        World::still(0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    rig.model.set_boot_generation(42);
    rig.run_for(4, 64);

    let stamp = rig.model.read().unwrap();
    assert_eq!(stamp.generations.boot, 42);
    assert_eq!(stamp.generations.resume, 0);

    rig.model.note_resume();
    rig.clock.advance_seconds(64);
    rig.poll_and_synchronise();
    let after = rig.model.read().unwrap();
    assert_eq!(after.generations.resume, 1);
}
