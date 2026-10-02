//! The two counters the operating system keeps, and the difference between them.
//!
//! Every platform that can suspend keeps time twice. One counter stops while the machine is asleep
//! and one carries on. Their difference is how long the machine was away, and it is the only place
//! that number exists: nothing inside the process can measure an interval it was not running for.
//!
//! Both counters here come from the same family on each platform, so there is no second oscillator
//! and no rate to reconcile. That matters more than it looks. Comparing a counter from one hardware
//! source against a counter from another leaves the two drifting apart at the difference of their
//! rates, and after a few hours that drift is larger than a short suspend, so a watch built that way
//! reports sleeps that never happened.
//!
//! Windows and Linux answer. Anything else does not, and says so rather than guessing: the caller
//! then has one counter instead of two and can see that the machine's timekeeping jumped without
//! being able to say which of the two things did it. That is a worse answer and it is an honest one.

// `NANOS_PER_MILLI` is imported by the two modules below that use it rather than here. Both are
// behind a `cfg`, one on Windows and one on `test`, so an import at this level is unused on a Linux
// release build and `-D warnings` turns that into a failed build. That is what had continuous
// integration red on `main` from 2026-09-08 while every clippy run on the Windows desktop was
// silent.
use timewitness_core::time::Nanos;

/// What the operating system says about time the machine spent not running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed {
    /// Nanoseconds since the machine started, counting time it spent suspended.
    pub including_suspend: Nanos,
    /// Nanoseconds since the machine started, not counting time it spent suspended.
    pub excluding_suspend: Nanos,
}

impl Elapsed {
    /// How long this machine has spent suspended since it started.
    ///
    /// Floored at zero. A negative answer would mean the two counters disagree about which of them
    /// is which, and reporting a negative sleep would push that into the arithmetic above.
    #[must_use]
    pub fn suspended(&self) -> Nanos {
        (self.including_suspend - self.excluding_suspend).max(0)
    }
}

/// Something that can read both of the machine's counters.
pub trait ContinuousClock: Send + Sync {
    /// Read them, or say that this platform does not offer the pair.
    fn elapsed(&self) -> Option<Elapsed>;
}

/// The counters this machine actually keeps.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemContinuous;

impl ContinuousClock for SystemContinuous {
    fn elapsed(&self) -> Option<Elapsed> {
        read()
    }
}

/// Whether this build has a pair of counters at all.
///
/// Reported so a caller can say what it could not measure, rather than reporting nothing and
/// leaving a reader to assume it measured nothing worth mentioning.
#[must_use]
pub fn pair_available() -> bool {
    read().is_some()
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{Elapsed, Nanos};
    use timewitness_core::time::NANOS_PER_MILLI;

    // Both live in kernel32 and both have since Windows 7. They are the biased and the unbiased
    // interrupt time: biased counts the time the machine spent in sleep, unbiased does not, and
    // neither of them moves when the time of day is set. The tick count is milliseconds, which is
    // coarse against the hundred nanoseconds the other reports, and coarse is not a problem here
    // because the quantity being measured is a machine asleep, which is seconds at the least.
    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount64() -> u64;
        fn QueryUnbiasedInterruptTime(unbiased: *mut u64) -> i32;
    }

    pub fn read() -> Option<Elapsed> {
        let mut unbiased: u64 = 0;
        // Safety: the call writes one `u64` through the pointer and reads nothing. The local it
        // points at outlives the call, is correctly aligned, and is initialised before it.
        let ok = unsafe { QueryUnbiasedInterruptTime(&mut unbiased) };
        if ok == 0 {
            return None;
        }
        // Safety: no arguments and no pointers. It returns a count.
        let ticks = unsafe { GetTickCount64() };
        Some(Elapsed {
            including_suspend: Nanos::from(ticks) * NANOS_PER_MILLI,
            // Hundred nanosecond units, which is what every interrupt time on this platform is in.
            excluding_suspend: Nanos::from(unbiased) * 100,
        })
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Elapsed, Nanos};

    /// The clock that carries on across a suspend.
    const CLOCK_BOOTTIME: i32 = 7;
    /// The clock that does not.
    const CLOCK_MONOTONIC: i32 = 1;

    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }

    extern "C" {
        fn clock_gettime(clock: i32, out: *mut Timespec) -> i32;
    }

    fn read_one(clock: i32) -> Option<Nanos> {
        let mut ts = Timespec {
            seconds: 0,
            nanoseconds: 0,
        };
        // Safety: the call writes one `Timespec` through the pointer and reads nothing. The local it
        // points at outlives the call, is correctly aligned, and is initialised before it.
        let ok = unsafe { clock_gettime(clock, &mut ts) };
        if ok != 0 {
            return None;
        }
        Some(Nanos::from(ts.seconds) * 1_000_000_000 + Nanos::from(ts.nanoseconds))
    }

    pub fn read() -> Option<Elapsed> {
        Some(Elapsed {
            including_suspend: read_one(CLOCK_BOOTTIME)?,
            excluding_suspend: read_one(CLOCK_MONOTONIC)?,
        })
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod platform {
    use super::Elapsed;

    /// No pair on this platform, and none guessed at.
    ///
    /// Other systems do keep both counters. They are not written here because none of the machines
    /// this is developed on runs one, and a platform read nobody has watched working is worse than
    /// an absence:
    /// the absence is visible in the receipt and a wrong reading is not.
    pub fn read() -> Option<Elapsed> {
        None
    }
}

use platform::read;

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_core::time::NANOS_PER_MILLI;

    /// How coarsely the counter that includes sleep is allowed to be reported.
    ///
    /// Windows reports it in milliseconds off the timer interrupt, which moves in steps of about
    /// fifteen and a half. So on a machine that has never slept the two counters do not read equal;
    /// the one that includes sleep reads up to one step behind. Measured on the machine this was
    /// written on, 2026-09-08, at 75 hours of uptime and no sleep: 6.771 ms behind.
    ///
    /// This is the reason `watch::SHORTEST_VISIBLE_SLEEP` is a quarter of a second rather than
    /// nothing.
    const COARSEST_STEP: Nanos = 20 * NANOS_PER_MILLI;

    #[test]
    fn the_two_counters_agree_about_which_is_which() {
        let Some(elapsed) = read() else {
            // A platform with no pair is a supported outcome. The watch reports what it could not
            // measure rather than measuring it wrongly.
            return;
        };
        assert!(
            elapsed.excluding_suspend - elapsed.including_suspend <= COARSEST_STEP,
            "the counter that includes sleep may lag the other by its own resolution and no more: \
             {elapsed:?}"
        );
        assert!(elapsed.suspended() >= 0);
    }

    #[test]
    fn both_counters_go_forward() {
        let Some(first) = read() else { return };
        let mut second = read().expect("a platform that answered once answers twice");
        for _ in 0..1_000 {
            second = read().expect("a platform that answered once answers twice");
            if second.excluding_suspend > first.excluding_suspend {
                break;
            }
        }
        assert!(second.excluding_suspend >= first.excluding_suspend);
        assert!(second.including_suspend >= first.including_suspend);
    }
}
