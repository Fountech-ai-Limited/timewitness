//! One clock model, held between stamps, and the two things that can go wrong while it is held.
//!
//! A one-shot command builds a model, polls, reads and exits, so nothing can happen to the machine
//! between the synchronisation and the reading except the microseconds in between. A resident agent
//! synchronises on a schedule and is read whenever somebody asks, so the gap between those two is
//! whatever the schedule is, and the machine gets to do things in it.
//!
//! Two of those things make the bound a lie, and neither is visible to the counter the model stamps
//! from.
//!
//! **The machine sleeps.** The counter the model reads is the counter that stopped, so asking it is
//! asking the thing that failed.
//!
//! **Another time service moves the clock.** On Windows the built-in one contends with any other
//! discipliner by design, and on Linux there is usually a daemon doing the same job.
//!
//! The platform crate can see both, by comparing counters the agent does not stamp from. What this
//! module decides is *when* to look, and the answer is the point of the file: **on the read path, on
//! every single reading, and not only on the poll schedule.** Looking only when polling leaves a
//! window the length of the poll interval in which a lid closes and the model answers anyway. A
//! resident agent that does that is worse than the command it replaces, because it is confidently
//! wrong where the command was honestly narrow.
//!
//! The look costs two calls into the operating system. It is on the read path, so it is paid at
//! every stamp, and the caller is already paying for the whole crossing in the bound's `scheduling`
//! term, which is where it is charged.
//!
//! Nothing here stops a machine sleeping or stops another service setting the clock. It records that
//! either happened and declines to sign until the model has measured the clock again.

use std::sync::Arc;

use timewitness_clock::monotonic::MonotonicClock;
use timewitness_clock::{ClockModel, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Refusal, Stamp, UnixNanos, Validity};
use timewitness_platform::continuous::SystemContinuous;
use timewitness_platform::{ContinuousClock, EnvironmentWatch, Interruptions, Marks};
use timewitness_receipt::schema::PolicyRecord;
use timewitness_sources::Exchange;

/// What the machine's own clocks said at one moment.
///
/// The platform crate reads them itself and this trait exists so a test does not have to. A test
/// that cannot hand the agent a machine which slept cannot test the one property this module is
/// for, and a property nobody can test is a property nobody has.
pub trait Surroundings: Send {
    /// Take one look, with the agent's own counter passed in so both are talking about the same one.
    fn marks(&mut self, monotonic: MonotonicNanos) -> Marks;
}

/// The machine this is actually running on.
#[derive(Debug, Default)]
pub struct SystemSurroundings;

impl Surroundings for SystemSurroundings {
    fn marks(&mut self, monotonic: MonotonicNanos) -> Marks {
        use std::time::{SystemTime, UNIX_EPOCH};
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i128::try_from(d.as_nanos()).ok())
            .map_or(UnixNanos(0), UnixNanos);
        Marks {
            wall,
            monotonic,
            elapsed: SystemContinuous.elapsed(),
        }
    }
}

/// The agent's counter, shared between the model and the code around it.
struct Shared(Arc<dyn MonotonicClock>);

impl MonotonicClock for Shared {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// A clock model that outlives the reading taken from it.
pub struct Resident {
    model: ClockModel,
    clock: Arc<dyn MonotonicClock>,
    watch: EnvironmentWatch,
    surroundings: Box<dyn Surroundings>,
    notes: Vec<String>,
}

impl Resident {
    /// Start one.
    ///
    /// `wall` is the machine's idea of UTC, read once by the caller and never again by the model.
    /// The first look at the surroundings is taken here, so the watch has something to compare
    /// against before anything is polled or read.
    pub fn new(
        policy: Policy,
        clock: Arc<dyn MonotonicClock>,
        wall: UnixNanos,
        granularity: Nanos,
        mut surroundings: Box<dyn Surroundings>,
    ) -> Self {
        let model = ClockModel::new(policy, Box::new(Shared(clock.clone())), wall, granularity);
        let mut watch = EnvironmentWatch::new();
        watch.observe(surroundings.marks(clock.now()));
        Self {
            model,
            clock,
            watch,
            surroundings,
            notes: Vec::new(),
        }
    }

    /// The counter this agent reads, so a caller can hand the same one to a source client.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn MonotonicClock> {
        self.clock.clone()
    }

    /// The agent's own limits, in the shape a receipt carries them.
    ///
    /// The policy that governed a bound is the policy of the process that held the model, so this is
    /// what crosses the boundary with a reading. A caller recording its own would be putting limits
    /// in the receipt that nothing was ever held to.
    #[must_use]
    pub fn policy_record(&self) -> PolicyRecord {
        let policy = self.model.policy();
        PolicyRecord {
            max_bound_width: policy.max_bound_width,
            min_sources: policy.min_sources as u32,
            min_operators: Some(policy.min_operators as u32),
            max_holdover: Some(policy.max_holdover),
        }
    }

    /// Take a round of exchanges and run a selection over them.
    ///
    /// The polling itself happens outside, and outside the lock this is called under, because a poll
    /// is network work measured in seconds and a reading must never wait behind one.
    pub fn take(&mut self, exchanges: &[Exchange]) -> Validity {
        self.look();
        for exchange in exchanges {
            self.model.ingest(exchange);
        }
        self.model.synchronise()
    }

    /// Take a reading.
    ///
    /// The look comes first and that ordering is the whole property. A machine that suspended since
    /// the last poll is caught here rather than at the next poll, so there is no span of time in
    /// which this answers from a model whose clock went away.
    pub fn read(&mut self) -> Result<Stamp, Refusal> {
        self.look();
        self.model.read()
    }

    /// What the model would say about itself right now, having looked first.
    pub fn validity(&mut self) -> Validity {
        self.look();
        self.model.validity()
    }

    /// What has happened to this machine since the agent started, newest last.
    #[must_use]
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Look at the machine, and tell the model what it finds.
    fn look(&mut self) {
        let seen = self.surroundings.marks(self.clock.now());
        let seen = self.watch.observe(seen);
        note_interruptions(&mut self.model, seen, &mut self.notes);
    }
}

/// Tell the model what happened to the machine, and keep a line about it for whoever asks.
///
/// Neither of these stops anything. A machine that suspended has already suspended and a clock
/// another service stepped has already been stepped; what the agent decides is whether it puts its
/// name to a reading taken afterwards, and it does not until it has measured the clock again.
///
/// A platform that keeps only one counter cannot tell the two apart. The jump is real either way, so
/// the model refuses either way, and the resume generation is not raised, because saying the machine
/// resumed would be saying something that was not measured.
pub fn note_interruptions(model: &mut ClockModel, seen: Interruptions, notes: &mut Vec<String>) {
    if let Some(away) = seen.suspended {
        model.note_resume();
        notes.push(format!(
            "this machine was suspended for {:.3} s, so everything measured before it was thrown \
             away",
            away as f64 / NANOS_PER_SEC as f64
        ));
    }
    if let Some(moved) = seen.clock_moved {
        model.note_system_clock_step(moved);
        let by = moved as f64 / 1_000_000.0;
        notes.push(if seen.attributed {
            format!("something other than this agent moved this machine's clock by {by:.3} ms")
        } else {
            format!(
                "this machine's timekeeping jumped by {by:.3} ms and this platform keeps no second \
                 counter to say whether it slept or was set"
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use timewitness_clock::monotonic::TestClock;
    use timewitness_platform::continuous::Elapsed;

    /// A counter a test moves by hand.
    struct Held(Arc<TestClock>);

    impl MonotonicClock for Held {
        fn now(&self) -> MonotonicNanos {
            self.0.now()
        }
    }

    const ANCHOR: Nanos = 1_757_000_000 * NANOS_PER_SEC;

    fn a_model() -> ClockModel {
        let clock = Arc::new(TestClock::starting_at(0));
        ClockModel::new(
            Policy::default(),
            Box::new(Held(clock)),
            UnixNanos(ANCHOR),
            0,
        )
    }

    #[test]
    fn a_machine_that_slept_is_driven_into_the_model_and_says_so() {
        // The wiring rather than the arithmetic. Both halves worked on their own before this: the
        // model refused when told, and the counters were there to be read. Nothing joined them, so
        // a real machine ran the shadow model and nothing anywhere called any of these doors.
        let mut model = a_model();
        let before = model.generations().resume;

        let mut watch = EnvironmentWatch::new();
        let hour = 3_600 * NANOS_PER_SEC;
        let marks = |wall: Nanos, running: Nanos, including: Nanos| Marks {
            wall: UnixNanos(ANCHOR + wall),
            monotonic: MonotonicNanos(u64::try_from(running).unwrap_or(0)),
            elapsed: Some(Elapsed {
                including_suspend: including,
                excluding_suspend: running,
            }),
        };
        watch.observe(marks(0, 0, 0));

        let mut notes = Vec::new();
        let slept = watch.observe(marks(hour, NANOS_PER_SEC, hour));
        note_interruptions(&mut model, slept, &mut notes);

        assert_eq!(model.generations().resume, before + 1);
        assert!(!model.validity().is_valid(), "{:?}", model.validity());
        assert!(
            notes.iter().any(|n| n.contains("suspended")),
            "the run has to say what happened to the machine: {notes:?}"
        );
    }

    #[test]
    fn a_clock_moved_by_something_else_is_driven_into_the_model_without_claiming_a_resume() {
        let mut model = a_model();
        let before = model.generations();

        let mut notes = Vec::new();
        note_interruptions(
            &mut model,
            Interruptions {
                suspended: None,
                clock_moved: Some(4 * NANOS_PER_SEC),
                attributed: true,
            },
            &mut notes,
        );

        assert_eq!(model.generations(), before, "a step is not a resume");
        assert!(matches!(
            model.validity(),
            Validity::SystemClockStepped { .. }
        ));
        assert!(notes
            .iter()
            .any(|n| n.contains("moved this machine's clock")));
    }
}
