//! What happens when the sources stop answering and the poller does not.
//!
//! The property under test is the one this suite is worded about: a bound that loses UTC must widen
//! or refuse, whatever caused it. Losing contact with the sources is one of the ways, and it is the
//! one an ordinary polling loop reaches without doing anything wrong. A loop that calls
//! `synchronise()` on a schedule cannot see that the window under it has stopped moving, so if the
//! model measures its own age from the selection round rather than from the newest exchange, the
//! loop keeps the model looking fresh for as long as it keeps running.
//!
//! Every test here works against the simulated network, so the truth is a number the test wrote
//! down and an assertion about the bound is a question about whether the interval holds it.

mod common;

use common::{Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::Validity;

use std::sync::Arc;

/// A model wired to a clock the test drives.
struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn with_policy(world: World, paths: Vec<Path>, policy: Policy) -> Self {
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

    /// Poll every source once and run a selection round.
    fn poll_and_synchronise(&mut self) -> Validity {
        let now = self.clock.now_value();
        for p in &self.paths {
            let e = self.world.exchange(p, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }

    /// Run a selection round over whatever is already in the window, polling nothing.
    ///
    /// This is the polling loop with the sources gone. The call is identical to the healthy one
    /// from the model's side, which is the whole difficulty: nothing in the API distinguishes them.
    fn synchronise_only(&mut self) -> Validity {
        self.model.synchronise()
    }

    fn advance_seconds(&self, s: u64) {
        self.clock.advance_seconds(s);
    }

    /// True UTC right now, which is what any bound the model signs has to contain.
    fn truth(&self) -> timewitness_core::UnixNanos {
        self.world.utc(self.clock.now_value())
    }
}

/// A handle so the test and the model share one counter.
struct ClockHandle(Arc<TestClock>);

impl timewitness_clock::MonotonicClock for ClockHandle {
    fn now(&self) -> timewitness_core::MonotonicNanos {
        self.0.now()
    }
}

trait TestClockExt {
    fn now_value(&self) -> timewitness_core::MonotonicNanos;
}

impl TestClockExt for TestClock {
    fn now_value(&self) -> timewitness_core::MonotonicNanos {
        use timewitness_clock::MonotonicClock;
        self.now()
    }
}

/// Three honest sources on ordinary paths.
fn three_sources() -> Vec<Path> {
    vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
    ]
}

/// A policy that will not refuse on width before the holdover ceiling is reached.
///
/// The default `max_bound_width` bites somewhere under twenty minutes, so under it the holdover
/// ceiling is never the thing that answers. Widening the width ceiling is what lets these tests ask
/// about the ceiling they are about; nothing else is changed.
fn a_policy_that_reaches_the_ceiling() -> Policy {
    Policy {
        max_bound_width: 600 * NANOS_PER_SEC,
        ..common::arithmetic_policy()
    }
}

#[test]
fn a_poller_over_frozen_samples_refuses_at_the_stated_ceiling() {
    let mut rig = Rig::with_policy(
        World::still(0),
        three_sources(),
        a_policy_that_reaches_the_ceiling(),
    );
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);

    let ceiling = rig.model.policy().max_holdover;
    // The sources answered once and then went quiet. The loop carries on calling `synchronise` on
    // its own schedule, which is what a poller does and what it has no way to know is now pointless.
    let step_s = 60;
    let mut elapsed: Nanos = 0;
    let mut refused_at: Option<Nanos> = None;
    for _ in 0..180 {
        rig.advance_seconds(step_s);
        elapsed += (step_s as Nanos) * NANOS_PER_SEC;
        rig.synchronise_only();
        let state = rig.model.validity();
        if refused_at.is_none() && !state.is_valid() {
            refused_at = Some(elapsed);
            assert!(
                matches!(state, Validity::HoldoverExceeded { .. }),
                "the first refusal after the sources went quiet is a holdover refusal, got {state:?}"
            );
        }
    }

    let refused_at = refused_at.expect(
        "a model whose sources went quiet three hours ago must refuse, whatever the poller does",
    );
    assert!(
        refused_at <= ceiling + (step_s as Nanos) * NANOS_PER_SEC,
        "the refusal must arrive at the stated ceiling of {ceiling} ns, and it arrived at \
         {refused_at} ns"
    );
    assert!(
        refused_at > ceiling - (step_s as Nanos) * NANOS_PER_SEC,
        "the refusal must not arrive before the ceiling either, and it arrived at {refused_at} ns \
         against a ceiling of {ceiling} ns"
    );
}

#[test]
fn since_last_sync_reports_the_age_of_the_newest_exchange() {
    let mut rig = Rig::with_policy(
        World::still(0),
        three_sources(),
        a_policy_that_reaches_the_ceiling(),
    );
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);

    // The sources were all polled at the same instant and their replies came home at the ends of
    // their own round trips, so the newest exchange is the slowest source's reply.
    let slowest = three_sources()
        .iter()
        .map(Path::round_trip)
        .max()
        .expect("three sources");

    // Ten minutes of a polling loop with nothing answering it.
    let quiet_for = 600 * NANOS_PER_SEC;
    for _ in 0..10 {
        rig.advance_seconds(60);
        rig.synchronise_only();
    }

    let stamp = rig
        .model
        .read()
        .expect("ten minutes is inside the holdover ceiling");
    let expected = quiet_for - slowest;
    assert_eq!(
        stamp.since_last_sync, expected,
        "the age reported has to be the age of the newest exchange, which came home {slowest} ns \
         after the poll, and not the age of the last selection round"
    );
}

#[test]
fn a_bound_over_frozen_samples_still_holds_the_truth() {
    // Forty parts per million is an ordinary temperature change on an ordinary crystal.
    let mut rig = Rig::with_policy(
        World::drifting(0, 40.0),
        three_sources(),
        a_policy_that_reaches_the_ceiling(),
    );
    // Enough rounds for the model to fit a rate, then silence.
    for i in 0..6 {
        if i > 0 {
            rig.advance_seconds(60);
        }
        assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
    }

    for _ in 0..10 {
        rig.advance_seconds(60);
        rig.synchronise_only();
        let truth = rig.truth();
        if let Ok(stamp) = rig.model.read() {
            assert!(
                stamp.bound.contains(truth),
                "a bound signed while the sources are unreachable still has to hold true UTC; \
                 the interval is [{}, {}] and the truth is {}",
                stamp.bound.earliest.as_nanos(),
                stamp.bound.latest.as_nanos(),
                truth.as_nanos()
            );
        }
    }
}

#[test]
fn a_stale_source_stops_being_a_candidate() {
    let mut rig = Rig::with_policy(
        World::still(0),
        three_sources(),
        a_policy_that_reaches_the_ceiling(),
    );
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);

    // Past the ceiling, the samples in the window describe a clock nobody has measured for longer
    // than this model will extrapolate, so they are not candidates any more and a round over them
    // has nothing to select from.
    rig.advance_seconds(3_601);
    let state = rig.synchronise_only();
    assert!(
        matches!(state, Validity::InsufficientSources { present: 0, .. }),
        "samples older than the holdover ceiling are not candidates, so the round has nothing to \
         select from, and it returned {state:?}"
    );
}

#[test]
fn a_round_that_learned_nothing_does_not_narrow_the_bound() {
    let mut rig = Rig::with_policy(
        World::still(0),
        three_sources(),
        a_policy_that_reaches_the_ceiling(),
    );
    for i in 0..4 {
        if i > 0 {
            rig.advance_seconds(60);
        }
        assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
    }
    let before = rig
        .model
        .read()
        .expect("the model has just synchronised")
        .bound
        .width();

    // Repeating the same samples at later and later counter values fits a line through points the
    // model has already used. The line gets flatter and its residual smaller, and none of it is
    // measurement: nothing new has been heard from any source.
    for _ in 0..20 {
        rig.advance_seconds(60);
        rig.synchronise_only();
    }
    let after = rig
        .model
        .read()
        .expect("twenty minutes is inside the holdover ceiling")
        .bound
        .width();

    assert!(
        after >= before,
        "twenty minutes with nothing heard from any source cannot make the bound narrower; it \
         went from {before} ns to {after} ns"
    );
    assert!(
        after > before + NANOS_PER_MILLI,
        "twenty minutes of silence has to show in the width; it went from {before} ns to {after} ns"
    );
}
