//! The platform reads, run against the machine the test is running on.
//!
//! Everything else about this crate can be driven by hand: the watch is arithmetic over four
//! numbers and a test can hand it a machine that slept for ten hours without any machine sleeping.
//! What a test cannot fake is whether the two counters exist on this platform, whether they read
//! what this crate says they read, and whether an ordinary quiet minute on a real desktop comes
//! back quiet. Those are the questions here, and they are the ones that decide whether the watch is
//! a real detector or a well-tested opinion.
//!
//! One thing is deliberately not here, and it is the obvious one. Nothing in this file suspends the
//! machine. Watching a real resume means putting a real computer to sleep, which is not something a
//! test suite does to the machine it is running on, so the resume arithmetic is proved against
//! counters a test wrote down and the platform read underneath it is proved here. The limitation
//! list says exactly that rather than implying a sleep was watched.
//!
//! Run with `cargo test -p timewitness-platform --test on_this_machine -- --nocapture` to see the
//! readings rather than only the verdict.

use std::thread::sleep;
use std::time::Duration;

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::MonotonicNanos;
use timewitness_platform::continuous::pair_available;
use timewitness_platform::{ContinuousClock, EnvironmentWatch, SystemContinuous};

/// Seconds, for a number a person reads.
fn seconds(n: Nanos) -> f64 {
    n as f64 / NANOS_PER_SEC as f64
}

#[test]
fn this_platform_answers_about_time_it_spent_asleep() {
    let expected = cfg!(any(target_os = "windows", target_os = "linux"));
    assert_eq!(
        pair_available(),
        expected,
        "Windows and Linux keep both counters and this build says otherwise"
    );
}

#[test]
fn the_counters_on_this_machine_read_what_this_crate_says_they_read() {
    let Some(elapsed) = SystemContinuous.elapsed() else {
        println!("this platform keeps no pair of counters, so there is nothing to read");
        return;
    };

    println!(
        "uptime including sleep {:.3} s, uptime excluding sleep {:.3} s, spent asleep {:.3} s",
        seconds(elapsed.including_suspend),
        seconds(elapsed.excluding_suspend),
        seconds(elapsed.suspended())
    );

    assert!(
        elapsed.excluding_suspend > 0,
        "a running machine has been running for some time"
    );
    assert!(
        elapsed.suspended() >= 0,
        "a machine cannot have spent a negative time asleep"
    );
    assert!(
        elapsed.suspended() <= elapsed.including_suspend,
        "a machine cannot have spent longer asleep than it has existed"
    );
}

#[test]
fn a_quiet_second_on_this_machine_is_reported_as_quiet() {
    // The false-positive half, and it is the half that decides whether this can ship. A watch that
    // reports an interruption on an ordinary machine doing nothing would make the agent refuse for
    // ever, which is a worse failure than the one it was built to catch.
    let mut watch = EnvironmentWatch::new();
    let start = std::time::Instant::now();
    watch.look(MonotonicNanos(0));

    for step in 1..=10 {
        sleep(Duration::from_millis(100));
        let running = Nanos::try_from(start.elapsed().as_nanos()).unwrap_or(0);
        let seen = watch.look(MonotonicNanos(u64::try_from(running).unwrap_or(0)));
        assert!(
            seen.quiet(),
            "look {step} on an undisturbed machine reported {seen:?}"
        );
    }
    println!("ten looks over a second on this machine, all quiet");
}

#[test]
fn the_system_clock_and_the_counter_keep_step_on_this_machine() {
    // What this measures is the ordinary condition the step detector has to sit above: how far the
    // system clock and a counter no clock adjustment reaches drift apart on a real machine, over a
    // real second, with whatever time service this machine runs doing whatever it does. On a Windows
    // desktop that time service is the built-in one, so this is the contention case at rest.
    let Some(before) = SystemContinuous.elapsed() else {
        println!("this platform keeps no pair of counters, so there is nothing to compare");
        return;
    };
    let wall_before = std::time::SystemTime::now();
    sleep(Duration::from_secs(1));
    let after = SystemContinuous
        .elapsed()
        .expect("it answered a moment ago");
    let wall_after = std::time::SystemTime::now();

    let counted = after.including_suspend - before.including_suspend;
    let walled = Nanos::try_from(
        wall_after
            .duration_since(wall_before)
            .expect("the clock went backwards during the test, which is itself the finding")
            .as_nanos(),
    )
    .unwrap_or(0);
    let apart = walled - counted;

    println!(
        "over {:.3} s the system clock and the interrupt counter moved {:.3} ms apart",
        seconds(counted),
        apart as f64 / NANOS_PER_MILLI as f64
    );
    assert!(
        apart.abs() < 128 * NANOS_PER_MILLI,
        "an undisturbed second moved the two {apart} ns apart, which is over the step threshold"
    );
}
