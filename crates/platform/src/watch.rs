//! Watching for the two things that happen to a machine's timekeeping without anybody asking.
//!
//! The machine goes to sleep, and comes back with no idea how long it was away. Or another time
//! service moves the clock, which on a Windows box is the ordinary case rather than an unusual one,
//! because the built-in time service contends with anything else that disciplines the same clock.
//!
//! Neither of these is detected by the counter the agent stamps from, and that is the trap. A
//! counter that stops while the machine sleeps cannot report that the machine slept: the thing being
//! asked is the thing that failed. So this watch reads counters the agent does not stamp from, and
//! compares them with each other rather than with itself.
//!
//! What it does about what it finds is not here. It reports; the clock model refuses. Nothing in
//! this file stops a sleep, prevents a clock being moved, or claims to: a machine that suspends does
//! so whether the agent likes it or not, and a second time service that steps the clock has already
//! stepped it by the time this sees anything. The whole of the agent's answer is that it declines to
//! put its name to a reading afterwards until it has measured the clock again.

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI};
use timewitness_core::{MonotonicNanos, UnixNanos};

use crate::continuous::{ContinuousClock, Elapsed, SystemContinuous};

/// The shortest sleep this watch will call a sleep.
///
/// A quarter of a second. The two counters it compares are read one after the other rather than at
/// the same instant, and on Windows the one that counts sleep moves in fifteen millisecond steps, so
/// a few tens of milliseconds of difference is the reading rather than the machine. Anything shorter
/// than this is invisible here, which is a limitation of the measurement and is written down as one.
pub const SHORTEST_VISIBLE_SLEEP: Nanos = 250 * NANOS_PER_MILLI;

/// The smallest movement of the system clock this watch will call a step.
///
/// A hundred and twenty-eight milliseconds, which is the threshold the ordinary time daemons use
/// themselves to decide between slewing a clock and stepping it. Below it they slew, and a slew
/// shows up here as the two counters drifting slowly apart rather than jumping, which the allowance
/// below covers. Above it they step, and a step is what this is looking for.
pub const SMALLEST_VISIBLE_STEP: Nanos = 128 * NANOS_PER_MILLI;

/// How fast the system clock may be slewed against a counter no clock adjustment reaches.
///
/// Five hundred parts per million, which is the largest rate correction the interfaces on both
/// platforms accept. A slew at the maximum for a whole minute is thirty milliseconds, well under the
/// step threshold, so the allowance only matters where a watch has not been polled for a long time.
const MAXIMUM_SLEW_PPM: f64 = 500.0;

/// What happened to this machine's timekeeping since the last look.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interruptions {
    /// How long the machine spent suspended, where the platform keeps a counter that can say.
    pub suspended: Option<Nanos>,
    /// How far the system clock moved against a counter that no clock adjustment reaches.
    pub clock_moved: Option<Nanos>,
    /// Whether the two could be told apart.
    ///
    /// False where this platform keeps only one counter. The machine's timekeeping jumped, the jump
    /// is in `clock_moved`, and whether it was a sleep or a clock being set is not something this
    /// build can answer. The agent refuses either way and does not raise its resume generation,
    /// because it cannot say that a resume is what happened.
    pub attributed: bool,
}

impl Interruptions {
    /// Whether nothing happened.
    #[must_use]
    pub fn quiet(&self) -> bool {
        self.suspended.is_none() && self.clock_moved.is_none()
    }
}

/// One look at the machine's clocks.
#[derive(Clone, Copy, Debug)]
pub struct Marks {
    /// What the system clock said.
    pub wall: UnixNanos,
    /// What the counter the agent stamps from said. Used only where the platform offers no pair.
    pub monotonic: MonotonicNanos,
    /// What the platform's own pair of counters said, where it keeps one.
    pub elapsed: Option<Elapsed>,
}

/// Compares one look at the clocks with the one before it.
#[derive(Debug, Default)]
pub struct EnvironmentWatch {
    last: Option<Marks>,
}

impl EnvironmentWatch {
    /// A watch that has not looked yet.
    #[must_use]
    pub fn new() -> Self {
        Self { last: None }
    }

    /// Look at this machine's clocks now.
    ///
    /// `monotonic` is the agent's own counter, passed in rather than read here, so the watch and the
    /// clock model are talking about the same one on a platform where it is all there is.
    pub fn look(&mut self, monotonic: MonotonicNanos) -> Interruptions {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i128::try_from(d.as_nanos()).ok())
            .map_or(UnixNanos(0), UnixNanos);
        self.observe(Marks {
            wall,
            monotonic,
            elapsed: SystemContinuous.elapsed(),
        })
    }

    /// The same, over marks the caller took, so a test can hand over a machine that slept.
    pub fn observe(&mut self, marks: Marks) -> Interruptions {
        let Some(previous) = self.last else {
            // The first look establishes where things were. Nothing before it to compare with, and
            // reporting an interruption from a single reading would be inventing one.
            self.last = Some(marks);
            return Interruptions::default();
        };
        self.last = Some(marks);

        match (previous.elapsed, marks.elapsed) {
            (Some(before), Some(now)) => Self::with_both_counters(&previous, &marks, before, now),
            _ => Self::with_one_counter(&previous, &marks),
        }
    }

    /// Where the platform keeps both counters, a sleep and a clock being set are different things.
    fn with_both_counters(
        previous: &Marks,
        marks: &Marks,
        before: Elapsed,
        now: Elapsed,
    ) -> Interruptions {
        let running = now.excluding_suspend - before.excluding_suspend;
        let wall_clock_time = now.including_suspend - before.including_suspend;
        let away = wall_clock_time - running;

        let moved = (marks.wall - previous.wall) - wall_clock_time;
        let allowance = SMALLEST_VISIBLE_STEP + slew_allowance(wall_clock_time);

        Interruptions {
            suspended: (away > SHORTEST_VISIBLE_SLEEP).then_some(away),
            clock_moved: (moved.abs() > allowance).then_some(moved),
            attributed: true,
        }
    }

    /// Where it keeps one, the jump is real and its cause is not something this can name.
    fn with_one_counter(previous: &Marks, marks: &Marks) -> Interruptions {
        let running = marks.monotonic.since(previous.monotonic);
        let moved = (marks.wall - previous.wall) - running;
        let allowance = SMALLEST_VISIBLE_STEP + slew_allowance(running);
        Interruptions {
            suspended: None,
            clock_moved: (moved.abs() > allowance).then_some(moved),
            attributed: false,
        }
    }
}

/// How far a slew at the maximum rate could have moved the system clock over `elapsed`.
fn slew_allowance(elapsed: Nanos) -> Nanos {
    if elapsed <= 0 {
        return 0;
    }
    let moved = MAXIMUM_SLEW_PPM * (elapsed as f64) / 1_000_000.0;
    if !moved.is_finite() {
        return 0;
    }
    moved.ceil() as Nanos
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_core::time::NANOS_PER_SEC;

    fn marks(wall: Nanos, running: Nanos, including: Nanos) -> Marks {
        Marks {
            wall: UnixNanos(1_757_000_000 * NANOS_PER_SEC + wall),
            monotonic: MonotonicNanos(u64::try_from(running).unwrap_or(0)),
            elapsed: Some(Elapsed {
                including_suspend: including,
                excluding_suspend: running,
            }),
        }
    }

    #[test]
    fn the_first_look_reports_nothing() {
        let mut watch = EnvironmentWatch::new();
        assert!(watch.observe(marks(0, 0, 0)).quiet());
    }

    #[test]
    fn an_ordinary_second_is_quiet() {
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));
        assert!(watch
            .observe(marks(NANOS_PER_SEC, NANOS_PER_SEC, NANOS_PER_SEC))
            .quiet());
    }

    #[test]
    fn a_machine_that_slept_for_ten_hours_is_seen() {
        let ten_hours = 36_000 * NANOS_PER_SEC;
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));

        // The counter the agent stamps from advanced by a second, because that is all the running
        // the machine did. The counter that keeps going advanced by ten hours and a second, and so
        // did the wall clock, because the world carried on.
        let seen = watch.observe(marks(
            ten_hours + NANOS_PER_SEC,
            NANOS_PER_SEC,
            ten_hours + NANOS_PER_SEC,
        ));
        assert_eq!(seen.suspended, Some(ten_hours));
        assert_eq!(seen.clock_moved, None);
        assert!(seen.attributed);
    }

    #[test]
    fn a_clock_stepped_a_second_forward_is_seen_and_is_not_a_sleep() {
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));
        let seen = watch.observe(marks(2 * NANOS_PER_SEC, NANOS_PER_SEC, NANOS_PER_SEC));
        assert_eq!(seen.suspended, None);
        assert_eq!(seen.clock_moved, Some(NANOS_PER_SEC));
    }

    #[test]
    fn a_clock_stepped_backwards_is_seen_too() {
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));
        let seen = watch.observe(marks(0, NANOS_PER_SEC, NANOS_PER_SEC));
        assert_eq!(seen.clock_moved, Some(-NANOS_PER_SEC));
    }

    #[test]
    fn a_slew_at_the_maximum_rate_is_not_a_step() {
        let minute = 60 * NANOS_PER_SEC;
        // Five hundred parts per million for a minute is thirty milliseconds of movement.
        let slewed = minute + 30 * NANOS_PER_MILLI;
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));
        assert!(watch.observe(marks(slewed, minute, minute)).quiet());
    }

    #[test]
    fn a_sleep_and_a_step_together_are_both_reported() {
        // A minute rather than an hour, because the allowance for a slew is a rate: over an hour a
        // clock slewed at the maximum could have moved nearly two seconds and a one second step is
        // inside that. Over a minute the allowance is thirty milliseconds and the step is plain.
        let minute = 60 * NANOS_PER_SEC;
        let mut watch = EnvironmentWatch::new();
        watch.observe(marks(0, 0, 0));
        let seen = watch.observe(marks(minute + NANOS_PER_SEC, NANOS_PER_SEC, minute));
        assert_eq!(seen.suspended, Some(minute - NANOS_PER_SEC));
        assert_eq!(seen.clock_moved, Some(NANOS_PER_SEC));
    }

    #[test]
    fn one_counter_sees_the_jump_and_will_not_say_what_caused_it() {
        let mut watch = EnvironmentWatch::new();
        let bare = |wall: Nanos, mono: u64| Marks {
            wall: UnixNanos(1_757_000_000 * NANOS_PER_SEC + wall),
            monotonic: MonotonicNanos(mono),
            elapsed: None,
        };
        watch.observe(bare(0, 0));
        let seen = watch.observe(bare(10 * NANOS_PER_SEC, 1_000_000_000));
        assert!(!seen.attributed);
        assert_eq!(seen.suspended, None);
        assert_eq!(seen.clock_moved, Some(9 * NANOS_PER_SEC));
    }
}
