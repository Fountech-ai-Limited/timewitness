//! What the machine does to the model without asking it.
//!
//! Two of the three faults that make a bound a lie are outside the model's reach: the machine sleeps
//! and comes back with no idea how long it was away, and another time service moves the clock. The
//! model cannot see either. What it can do is refuse once told, and refuse in the same way it
//! refuses everything else, so that a caller has one thing to handle rather than three.
//!
//! That is what these test. Detecting the faults belongs to the platform crate and is tested there,
//! including against the counters of the machine the tests run on.

mod common;

use common::World;
use timewitness_clock::model::ClockModel;
use timewitness_clock::monotonic::TestClock;
use timewitness_clock::MonotonicClock;
use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Validity};

struct Handle(std::sync::Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// A model that has just synchronised against four honest sources.
fn synchronised() -> (ClockModel, std::sync::Arc<TestClock>, World) {
    let world = World::still(0);
    let clock = std::sync::Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let mut model = ClockModel::new(
        common::arithmetic_policy(),
        Box::new(Handle(clock.clone())),
        world.wall0,
        100,
    );
    poll_and_synchronise(&mut model, &world, &clock);
    (model, clock, world)
}

fn poll_and_synchronise(model: &mut ClockModel, world: &World, clock: &TestClock) -> Validity {
    for (i, path) in common::four_honest_sources().iter().enumerate() {
        clock.advance((i as u64 + 1) * 1_000_000);
        model.ingest(&world.exchange(path, clock.now()));
    }
    model.synchronise()
}

#[test]
fn a_machine_that_slept_refuses_until_it_has_measured_again() {
    let (mut model, clock, world) = synchronised();
    assert!(model.read().is_ok(), "a synchronised model reads");
    let before = model.generations().resume;

    model.note_resume();

    let refusal = model.read().expect_err("a machine that slept has no bound");
    assert_eq!(
        refusal.validity,
        Validity::SuspendedSinceLastSync {
            resume_generation: before + 1
        }
    );
    assert_eq!(
        model.generations().resume,
        before + 1,
        "the receipt carries a counter a reader can compare across two receipts"
    );

    // And it comes back, which is the half a guard that only ever refuses would fail.
    clock.advance_seconds(1);
    assert_eq!(
        poll_and_synchronise(&mut model, &world, &clock),
        Validity::Valid
    );
    assert!(
        model.read().is_ok(),
        "once it has measured the clock again it can answer again"
    );
}

#[test]
fn a_sleep_throws_away_everything_measured_before_it() {
    // Not the same property as refusing. A model that refused but kept its samples would answer
    // again from measurements taken before a gap it cannot measure.
    let (mut model, clock, world) = synchronised();
    let one_source_short = common::arithmetic_policy().min_sources - 1;

    model.note_resume();
    clock.advance_seconds(1);

    // Poll two sources rather than four. If the windows had survived the sleep there would be
    // enough to synchronise on; there is not, because they did not.
    for (i, path) in common::four_honest_sources().iter().take(2).enumerate() {
        clock.advance((i as u64 + 1) * 1_000_000);
        model.ingest(&world.exchange(path, clock.now()));
    }
    assert_eq!(
        model.synchronise(),
        Validity::InsufficientSources {
            present: 2,
            required: one_source_short + 1
        },
        "the samples taken before the sleep have to be gone, not merely ignored"
    );
}

#[test]
fn a_clock_moved_by_something_else_refuses_until_it_has_measured_again() {
    let (mut model, clock, world) = synchronised();
    assert!(model.read().is_ok());

    let moved: Nanos = 4 * NANOS_PER_SEC;
    model.note_system_clock_step(moved);

    let refusal = model
        .read()
        .expect_err("a clock something else has just stepped has no bound worth signing");
    assert_eq!(refusal.validity, Validity::SystemClockStepped { by: moved });
    assert!(
        refusal.to_string().contains("other than this agent"),
        "the refusal says who moved it, or it is not actionable: {refusal}"
    );

    clock.advance_seconds(1);
    assert_eq!(
        poll_and_synchronise(&mut model, &world, &clock),
        Validity::Valid
    );
    assert!(model.read().is_ok());
}

#[test]
fn a_step_does_not_raise_the_resume_generation() {
    // The two are told apart in the receipt, so telling them apart has to survive the wiring. A
    // machine whose clock was set is not a machine that slept, and a verifier reading a raised
    // resume generation would take it as one.
    let (mut model, _clock, _world) = synchronised();
    let before = model.generations();
    model.note_system_clock_step(NANOS_PER_SEC);
    assert_eq!(model.generations(), before);
}

#[test]
fn every_environment_fault_refuses_through_the_same_door() {
    // Three detectors and one refusal. A caller handles `Err(Refusal)` and nothing else, which is
    // what stops the third fault arriving with a fourth way of failing that nobody handles.
    let (mut model, _clock, _world) = synchronised();
    model.note_resume();
    let slept = model.read().expect_err("refuses");

    let (mut model, _clock, _world) = synchronised();
    model.note_system_clock_step(NANOS_PER_SEC);
    let stepped = model.read().expect_err("refuses");

    let (mut model, _clock, _world) = synchronised();
    model.force_invalid(Validity::TimescaleConflict {
        detail: "a source spreading a leap second against one that inserted it".to_string(),
    });
    let leaping = model.read().expect_err("refuses");

    for refusal in [&slept, &stepped, &leaping] {
        assert!(!refusal.validity.is_valid());
        assert!(
            !refusal.to_string().is_empty(),
            "a refusal a person cannot read is a refusal nobody acts on"
        );
    }
    assert_ne!(slept.validity, stepped.validity);
    assert_ne!(stepped.validity, leaping.validity);
}
