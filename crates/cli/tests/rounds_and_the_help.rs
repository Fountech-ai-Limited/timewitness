//! What `--rounds` does to the width, and whether the shipped help says it.
//!
//! The help shipped a sentence saying more rounds is a narrower bound. Measured on this desktop at
//! 12:54 and 12:56 on 2026-09-08 against the three public Roughtime servers, two passes at each
//! setting, it is the other way round at the settings a build would use:
//!
//! | rounds | width | the model's own residual |
//! |---|---|---|
//! | 1 | 6.155 s, 6.154 s | 0 |
//! | 2 | 6.150 s, 6.151 s | 0 |
//! | 3 | 17.378 s, 17.383 s | 5.613 s |
//! | 4 | 16.433 s, 13.763 s | 5.143 s |
//! | 8 | 14.092 s, 14.104 s | 3.9 s |
//! | 12 | 12.807 s, 12.821 s | 3.330 s |
//! | 16 | 12.021 s, 12.019 s | 2.936 s |
//! | 24 | 11.020 s, 11.008 s | 2.433 s |
//! | 32 | 10.398 s, 10.397 s | 2.125 s |
//!
//! The whole of the difference is one term. Below three rounds the model has too few points to fit
//! a line, so the scatter of its own measurements is never measured and never enters the width. At
//! three it is measured and it is at its largest, and from there it falls roughly as one over the
//! square root of the number of rounds. So a one-round bound is narrower because less was measured,
//! not because the clock is better known, which is the overclaim this product exists to refuse.
//!
//! This test is what keeps the sentence and the arithmetic together. It measures the shape against
//! a simulated network rather than quoting the table above, and then reads the help out of the
//! shipped binary and asks whether it says the same thing. Change either half on its own and this
//! fails.

use std::process::Command;
use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
    UnixNanos,
};
use timewitness_sources::Exchange;

/// Where the counter and the machine's own clock both start.
const COUNTER_ORIGIN: u64 = 1_000_000_000;
const WALL_ORIGIN: Nanos = 1_757_000_000 * NANOS_PER_SEC;

/// A source that answers honestly and jitters, which is what makes this test about anything.
///
/// A source with no jitter at all fits a line with no scatter, so the residual is nought at every
/// round count and the shape this test is about does not exist. A Roughtime server states its own
/// uncertainty as a radius in whole seconds and its midpoints move by hundreds of milliseconds
/// between answers, so the jitter is the ordinary case rather than an awkward one.
struct Source {
    id: &'static str,
    round_trip: Nanos,
    stated: Nanos,
    /// How far this source's answers move about, either side of the truth.
    jitter: Nanos,
}

/// A repeatable jitter, so a failure is the same failure on the next run.
///
/// A test that fails one run in twenty teaches nobody anything, and the shape being measured here
/// does not need real randomness: it needs scatter that is the same every time.
fn wobble(seed: u64) -> f64 {
    let mixed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    let unit = ((mixed >> 33) as f64) / f64::from(u32::MAX >> 1);
    unit * 2.0 - 1.0
}

/// One exchange with `source`, sent at `send_at`, on a machine whose clock is right.
fn exchange(source: &Source, send_at: MonotonicNanos, round: usize) -> Exchange {
    let home = send_at.advanced(source.round_trip);
    let wall_at_arrival = UnixNanos(WALL_ORIGIN)
        + send_at.since(MonotonicNanos(COUNTER_ORIGIN))
        + source.round_trip / 2;
    let scatter =
        (wobble(round as u64 * 31 + source.id.len() as u64) * source.jitter as f64) as Nanos;

    Exchange {
        source: SourceId::new(source.id),
        operator: Operator::new(source.id),
        kind: SourceKind::Roughtime,
        t2: wall_at_arrival + scatter,
        t3: wall_at_arrival + scatter,
        mono_t1: send_at,
        mono_t4: home,
        root_delay: 0,
        root_dispersion: source.stated,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        attestation: None,
    }
}

/// A handle so the test and the model share one counter.
struct Handle(Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The width and the model's own residual after `rounds` polls of three honest sources.
///
/// The polls sit a second apart, which is the shape of a run that does not wait: a build stamping
/// its own output polls as fast as the servers answer.
fn after(rounds: usize) -> (Nanos, Nanos) {
    let sources = [
        Source {
            id: "alpha",
            round_trip: 12 * NANOS_PER_MILLI,
            stated: NANOS_PER_SEC,
            jitter: 400 * NANOS_PER_MILLI,
        },
        Source {
            id: "bravo",
            round_trip: 24 * NANOS_PER_MILLI,
            stated: NANOS_PER_SEC,
            jitter: 300 * NANOS_PER_MILLI,
        },
        Source {
            id: "charlie",
            round_trip: 8 * NANOS_PER_MILLI,
            stated: NANOS_PER_SEC,
            jitter: 500 * NANOS_PER_MILLI,
        },
    ];

    // The shipped agent policy refuses anything wider than 250 ms, which is a machine with real
    // time sources. Three public Roughtime servers are seconds wide before anything else happens,
    // so this is the ceiling the Action runs on and the one the shape being measured lives under.
    //
    // The independence floor is lowered here for the same reason and it is the same admission. The
    // shipped floor is four operators and three Roughtime servers are three, so a deployment that
    // can reach nothing else has to state that it will sign on three parties rather than four. It is
    // written here rather than defaulted so that it shows up as a decision somebody took: the whole
    // point of the floor is that being short of independent parties is visible.
    let policy = Policy {
        max_bound_width: 30 * NANOS_PER_SEC,
        min_operators: 3,
        ..Policy::default()
    };

    let clock = Arc::new(TestClock::starting_at(COUNTER_ORIGIN));
    let mut model = ClockModel::new(
        policy,
        Box::new(Handle(clock.clone())),
        UnixNanos(WALL_ORIGIN),
        0,
    );

    for round in 0..rounds {
        if round > 0 {
            clock.advance_seconds(1);
        }
        let now = clock.now();
        for source in &sources {
            model.ingest(&exchange(source, now, round));
        }
        model.synchronise();
    }

    let stamp = model
        .read()
        .expect("three honest sources support a reading");
    (
        stamp.bound.latest - stamp.bound.earliest,
        stamp.bound.breakdown.model_residual,
    )
}

#[test]
fn below_three_rounds_the_model_measures_no_residual_of_its_own() {
    for rounds in [1, 2] {
        let (_, residual) = after(rounds);
        assert_eq!(
            residual, 0,
            "at {rounds} rounds the model has too few points to fit a line, so it has no residual \
             to report"
        );
    }
}

#[test]
fn the_first_rounds_that_fit_a_line_widen_the_bound_rather_than_narrowing_it() {
    let (one, _) = after(1);
    let (three, residual) = after(3);

    assert!(
        residual > 0,
        "three points is enough to fit a line, so the scatter of the measurements is measured"
    );
    assert!(
        three > one,
        "three rounds came out {three} ns wide and one round {one} ns. The bound at one round is \
         narrower because a term was never measured, not because the clock is better known"
    );
}

#[test]
fn past_that_the_residual_falls_as_the_rounds_pile_up() {
    let (three, three_residual) = after(3);
    let (sixteen, sixteen_residual) = after(16);

    assert!(
        sixteen_residual < three_residual,
        "the residual is the standard error of the fit, so more points pin the offset down: \
         {sixteen_residual} ns at sixteen rounds against {three_residual} ns at three"
    );
    assert!(
        sixteen < three,
        "sixteen rounds came out {sixteen} ns wide and three rounds {three} ns"
    );
}

/// The sentence and the arithmetic, held together.
///
/// The help said "More is a narrower bound and a longer wait" until 2026-09-08, and the three tests
/// above are what it was saying the opposite of. This one reads the shipped binary's own output, so
/// a future edit that puts the old claim back fails here rather than on somebody's build.
#[test]
fn the_shipped_help_says_what_the_rounds_actually_do() {
    let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .output()
        .expect("the binary this test was built alongside runs");
    let help = String::from_utf8(out.stdout).expect("the help is text");

    assert!(
        help.contains("--rounds"),
        "the help still documents the option"
    );
    assert!(
        !help.contains("narrower bound"),
        "the help claims more rounds is a narrower bound, and the tests above measure the opposite"
    );
    assert!(
        help.contains("widens the bound"),
        "the help has to say that the first rounds to fit a line widen the bound, because they do"
    );
    assert!(
        help.contains("narrows again"),
        "and that it comes back down as the rounds pile up, because it does"
    );
}

/// The resident agent has to be findable from the help, and it has to be described for what it is.
///
/// `timewitness agent` is in the tree. The thing a reader will assume, and the thing the limitation
/// list says on all three surfaces, is that it installs itself and comes back after a restart. It
/// does not, so the help says so where somebody looking for it will read it, rather than only in a
/// document they have to go and find.
#[test]
fn the_shipped_help_describes_the_agent_without_overclaiming_it() {
    let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .output()
        .expect("the binary this test was built alongside runs");
    let help = String::from_utf8(out.stdout).expect("the help is text");

    assert!(
        help.contains("timewitness agent --endpoint"),
        "the subcommand is not in the help at all"
    );
    assert!(
        help.contains("--agent <file>"),
        "nothing tells a reader how a stamp reaches the agent"
    );
    assert!(
        help.contains("installs no service"),
        "the help has to say the agent installs nothing, because a reader will assume it does"
    );
    assert!(
        help.contains("never sets the clock"),
        "and that it measures and vouches rather than disciplining the system clock"
    );
}

/// An option that belongs to the other path is refused rather than dropped.
///
/// `--rounds` and `--gap` describe polling that `--agent` is not doing. An option silently ignored
/// is how somebody comes to believe the number they gave was applied, which is the same fault as
/// reporting held for a check that was never run.
///
/// **`--max-width` was on this list until 2026-09-10 and was taken off**, because the reasoning for
/// it being here was the defect. It said the ceiling is the agent's own and is set where the agent
/// is started, which left the caller with no ceiling of its own and the answering party choosing
/// the one it was judged by. On this path the option now means the widest interval this run will
/// accept, and `a_caller_states_its_own_ceiling_on_the_agent_path` below is what holds that.
#[test]
fn an_option_that_belongs_to_the_other_path_is_refused_rather_than_ignored() {
    for option in ["--rounds", "--gap"] {
        let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
            .args([
                "stamp",
                "--subject",
                "Cargo.toml",
                "--key",
                "no-such-key",
                "--out",
                "no-such-receipt",
                "--agent",
                "no-such-endpoint",
                option,
                "4",
            ])
            .current_dir(std::env::temp_dir())
            .output()
            .expect("the binary runs");
        let said = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{said}");
        assert!(
            said.contains(option) && said.contains("the polling is the agent's"),
            "{option} should be refused by name and was not: {said}"
        );
        // And refused before anything was written. The key file is made where there is not one
        // already, so a run turned down after that point would leave a private key behind for a
        // stamp that never happened.
        assert!(
            !std::env::temp_dir().join("no-such-key").exists(),
            "{option} was refused after a key had already been written"
        );
    }
}

/// `--gap` is seconds, the help says so, and a gap past the ceiling is refused before a key exists.
///
/// Until 2026-09-15 the help said `--gap <ns>` and the code slept for that many seconds, with no
/// ceiling: a reader who followed the help and asked for thirty seconds got a run that was still
/// asleep when it was killed at 502 s. The help, the refusal and the constant now say one unit,
/// and this is what keeps the three together.
#[test]
fn a_gap_is_seconds_and_one_past_the_ceiling_is_refused_before_anything_is_written() {
    let help = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("--help")
        .output()
        .expect("the binary runs");
    let help = String::from_utf8_lossy(&help.stdout).into_owned();
    assert!(
        help.contains("--gap <s>") && help.contains("seconds to wait between polling rounds"),
        "the help has to give --gap in seconds: {help}"
    );
    assert!(
        help.contains("at most 300"),
        "the help has to state the ceiling beside the option: {help}"
    );

    let key = std::env::temp_dir().join("no-such-key-for-a-gap");
    let _ = std::fs::remove_file(&key);
    let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args([
            "stamp",
            "--subject",
            "Cargo.toml",
            "--key",
            "no-such-key-for-a-gap",
            "--out",
            "no-such-receipt",
            "--gap",
            "301",
        ])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("the binary runs");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(
        said.contains("--gap") && said.contains("at most 300 seconds"),
        "a gap past the ceiling should be refused by name, in seconds: {said}"
    );
    assert!(
        !key.exists(),
        "the gap was refused after a key had already been written"
    );
}

/// `--max-width` reaches the agent path instead of being turned away at the door.
///
/// What the option means there is checked in `timewitness-agent`, over a real socket, because that
/// is where the two ceilings are compared. What is checked here is the thing only the command line
/// can say: that the option is taken rather than refused by name, which it was until 2026-09-10.
/// The run still fails, on the endpoint file that is not there, and the endpoint is read before the
/// ceiling is, so reaching that message is the evidence the option was accepted.
#[test]
fn a_caller_states_its_own_ceiling_on_the_agent_path() {
    // A subject that is really there, because this run gets further than the one above: that one is
    // turned down before anything is read and this one has to reach the endpoint.
    let subject = std::env::temp_dir().join("timewitness-ceiling-subject");
    std::fs::write(&subject, b"a subject").expect("a temporary subject");

    // A key name of this test's own. The run gets as far as making one, and the test above asserts
    // that `no-such-key` was never written, so sharing the name would make one test fail the other.
    let key = std::env::temp_dir().join("timewitness-ceiling-key");
    let _ = std::fs::remove_file(&key);

    let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args([
            "stamp",
            "--subject",
            subject.to_str().expect("a path"),
            "--key",
            key.to_str().expect("a path"),
            "--out",
            "no-such-receipt",
            "--agent",
            "no-such-endpoint",
            "--max-width",
            "250000000",
        ])
        .current_dir(std::env::temp_dir())
        .output()
        .expect("the binary runs");
    let said = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(
        !said.contains("the polling is the agent's"),
        "--max-width was refused as belonging to the other path: {said}"
    );
    assert!(
        said.contains("no-such-endpoint"),
        "the run should have got as far as the endpoint file: {said}"
    );
    let _ = std::fs::remove_file(&key);
    let _ = std::fs::remove_file(&subject);
}

/// The help text says what `--max-width` means on the agent path, and what the check there is not.
///
/// The caller's own ceiling added a refusal a person can meet, so a person has to be able to find
/// out what it is before they meet it. The two things that have to be findable are that the option
/// is a ceiling of this caller's own, and that the comparison against the local clock is a sanity
/// check rather than evidence: a reader who takes it for evidence has the trust model backwards.
#[test]
fn the_help_says_what_the_agent_path_checks_and_what_it_does_not_prove() {
    let out = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .output()
        .expect("the binary runs");
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        said.contains("the widest this run will accept from"),
        "the help does not say what --max-width means with --agent: {said}"
    );
    assert!(
        said.contains("sanity check") && said.contains("not evidence"),
        "the help does not say the local clock check is not evidence: {said}"
    );
}
