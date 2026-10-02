//! The bound on a machine where somebody else is moving the clock.
//!
//! Every other test in this suite runs on a machine that is doing nothing but running the agent.
//! That machine barely exists. The ordinary machine has a time service of its own already holding
//! the system clock near UTC: a stock Windows box, a stock Linux under chrony or
//! systemd-timesyncd, and every cloud instance with a hypervisor clock.
//!
//! On that machine there are two local clocks and they disagree by more every minute. The system
//! clock is being steered, so it stays right. Anything projected forward over the monotonic counter
//! from a single reading is not being steered, so it walks away at the oscillator's own rate. Both
//! look perfectly healthy on their own, which is the whole difficulty: the divergence is only
//! visible if the arithmetic uses one of them and the answer is checked against the other.
//!
//! So these tests do not ask whether the model agrees with itself. They write the truth down, let
//! the machine's two clocks come apart underneath it, and ask whether the interval the model signed
//! still holds the number the test wrote down.

mod common;

use common::{four_honest_sources, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock};
use timewitness_core::time::{nanos_as_millis_f64, NANOS_PER_MILLI};
use timewitness_core::{MonotonicNanos, UnixNanos, Validity};

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// An agent started on `world`, polling four honest sources every `spacing_s` seconds.
struct Agent {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
}

impl Agent {
    fn started_on(world: World) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        // What every agent does at startup, and the only local time it is ever given: one reading
        // of whatever clock the operating system offers.
        let wall = world.system(world.mono0);
        let model = ClockModel::new(
            common::arithmetic_policy(),
            Box::new(ClockHandle(clock.clone())),
            wall,
            0,
        );
        Self {
            clock,
            world,
            model,
        }
    }

    fn now(&self) -> MonotonicNanos {
        self.clock.now()
    }

    /// Poll every source and run a selection round.
    fn poll_and_synchronise(&mut self) -> Validity {
        let now = self.now();
        for p in four_honest_sources() {
            let e = self.world.exchange(&p, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }

    /// Run for `rounds` rounds `spacing_s` seconds apart, as a background discipliner would.
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

    /// True UTC now, which the test wrote down and the model has never seen.
    fn truth(&self) -> UnixNanos {
        self.world.utc(self.now())
    }
}

/// How far the centre of the bound sits from the truth, in milliseconds, for a failure message.
fn centre_error_ms(bound: &timewitness_core::Bound, truth: UnixNanos) -> f64 {
    let centre = (bound.earliest.as_nanos() + bound.latest.as_nanos()) / 2;
    nanos_as_millis_f64(centre - truth.as_nanos())
}

#[test]
fn the_bound_holds_the_truth_while_another_service_steers_the_system_clock() {
    // Twenty parts per million is an ordinary laptop oscillator on a warm day. The operating
    // system's own time service is holding the system clock at UTC throughout, so nothing the
    // agent can see is behaving badly, and the sources are all honest.
    let mut agent = Agent::started_on(World::disciplined_elsewhere(20.0));
    assert_eq!(agent.run_for(20, 64), Validity::Valid);

    let stamp = agent.model.read().expect("a synchronised model reads");
    let truth = agent.truth();
    assert!(
        stamp.bound.contains(truth),
        "after twenty minutes the bound {:?} does not hold the truth {truth:?}. \
         Its centre is {:.3} ms from UTC and it is {:.3} ms wide, and the model reports {:.1} ppm \
         of drift on a machine truly drifting at 20.0 ppm",
        stamp.bound,
        centre_error_ms(&stamp.bound, truth),
        nanos_as_millis_f64(stamp.bound.width()),
        stamp.frequency_ppm.unwrap_or(0.0),
    );
}

#[test]
fn the_error_does_not_grow_with_the_time_the_agent_has_been_running() {
    // The failure this catches is unbounded rather than large. A fixed error would show up in the
    // first minute; this one is nothing at startup and grows for as long as the agent runs, so a
    // short test is the one thing that cannot see it.
    let mut agent = Agent::started_on(World::disciplined_elsewhere(20.0));
    agent.run_for(4, 64);

    let early = {
        let stamp = agent.model.read().unwrap();
        centre_error_ms(&stamp.bound, agent.truth()).abs()
    };

    agent.run_for(40, 64);

    let late = {
        let stamp = agent.model.read().unwrap();
        centre_error_ms(&stamp.bound, agent.truth()).abs()
    };

    assert!(
        late < early + 1.0,
        "the centre of the bound was {early:.3} ms from UTC after four minutes and {late:.3} ms \
         after forty-four, so the error is growing with the time the agent has been running"
    );
}

#[test]
fn the_drift_the_model_reports_is_the_drift_the_machine_has() {
    // The machine is genuinely twenty parts per million slow and the operating system is hiding it
    // from every reading of the system clock. The model has to see it anyway, because it is what
    // the bound widens by during holdover.
    let mut agent = Agent::started_on(World::disciplined_elsewhere(20.0));
    assert_eq!(agent.run_for(20, 64), Validity::Valid);

    let stamp = agent.model.read().unwrap();
    let rate = stamp
        .frequency_ppm
        .expect("a twenty minute baseline supports a rate");
    assert!(
        (rate - 20.0).abs() < 2.0,
        "the machine is drifting at 20.0 ppm and the model reports {rate:.2} ppm"
    );
}

#[test]
fn a_holdover_on_a_steered_machine_still_holds_the_truth() {
    // Synchronisation stops and the agent carries the bound forward on its own frequency estimate.
    // Everything that keeps the interval honest here rests on that estimate being the machine's
    // real drift rather than the drift the system clock is being made to show.
    let mut agent = Agent::started_on(World::disciplined_elsewhere(-14.0));
    assert_eq!(agent.run_for(20, 64), Validity::Valid);

    // Past the point where the allowance for the rate moving outgrows the width ceiling the model
    // refuses, and a refusal is a correct answer. What is never correct is an interval without the
    // truth in it, so both are checked and neither stands in for the other.
    let mut answered = 0;
    for minutes in [1u64, 5, 15, 30, 55] {
        let mut probe = Agent::started_on(World::disciplined_elsewhere(-14.0));
        probe.run_for(20, 64);
        probe.clock.advance_seconds(minutes * 60);

        let truth = probe.truth();
        match probe.model.read() {
            Ok(stamp) => {
                answered += 1;
                assert!(
                    stamp.bound.contains(truth),
                    "after {minutes} minutes of holdover on a steered machine the bound {:?} does \
                     not hold the truth {truth:?}, its centre being {:.3} ms out",
                    stamp.bound,
                    centre_error_ms(&stamp.bound, truth),
                );
            }
            Err(refusal) => assert!(
                matches!(refusal.validity, Validity::BoundTooWide { .. }),
                "the only thing that should stop a holdover this long is the width ceiling, and \
                 after {minutes} minutes it was {:?}",
                refusal.validity
            ),
        }
    }
    assert!(
        answered >= 3,
        "only {answered} of the five holdover points produced a bound at all, which is a model \
         that has stopped working rather than one that is being careful"
    );
}

#[test]
fn a_system_clock_left_a_few_milliseconds_out_by_its_own_service_changes_nothing() {
    // The other service is not perfect either. It leaves the system clock three milliseconds fast
    // and holds it there. That is an ordinary constant error, the sources still see the truth, and
    // the bound has to hold the truth rather than the system clock's version of it.
    let world = World::disciplined_elsewhere(9.0).with_residual(3 * NANOS_PER_MILLI);
    let mut agent = Agent::started_on(world);
    assert_eq!(agent.run_for(20, 64), Validity::Valid);

    let stamp = agent.model.read().unwrap();
    let truth = agent.truth();
    assert!(
        stamp.bound.contains(truth),
        "the bound {:?} does not hold the truth {truth:?}, its centre being {:.3} ms out",
        stamp.bound,
        centre_error_ms(&stamp.bound, truth),
    );
}
