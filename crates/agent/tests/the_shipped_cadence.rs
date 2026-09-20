//! The schedule the agent ships, stated once and held to two places at the same time.
//!
//! Three figures decide what a resident agent costs other people's servers and what a fresh one has
//! to extrapolate across. The reasoning for each is on `Cadence` itself. They are also what the
//! regression case for the 2026-09-18 P0 simulates, in
//! `crates/clock/tests/a_fresh_agent_at_the_shipped_cadence.rs`, which writes them down again
//! because the crate that ships the cadence depends on the clock model and not the other way round.
//!
//! Two copies of a figure with nothing between them is the fault this file exists to stop. Until
//! 2026-09-20 the rig held its own three literals with an assertion of each against itself, which
//! could not fail, so a cadence change left the rig simulating a schedule the agent no longer kept,
//! green, and the only regression case for the P0 was measuring the wrong world. Nothing anywhere
//! read both copies.
//!
//! This does. It states the three figures, checks `Cadence::default` against them, and then reads
//! the rig's own source and checks its three constants against the same figures. Moving either copy
//! alone turns this red and names which one moved. Moving the cadence deliberately means editing
//! all three in one act, which is the point: the three paragraphs on `Cadence` say what each figure
//! costs, and a schedule is not something to change by touching one number.
//!
//! Reading the rig's source rather than its values is the only way across: an integration test in
//! this crate cannot reach another crate's test binary, and a dev-dependency back on this crate
//! from the clock crate is an edge `crates/architecture/tests/module_boundaries.rs` refuses, on the
//! layout rule that the clock model sits below the agent. A constant this parser cannot find is a
//! failure rather than a pass, for the same reason that guard fails on a manifest heading it does
//! not recognise.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use timewitness_agent::Cadence;

/// How many rounds the agent runs back to back before settling into its schedule.
const SETTLING_ROUNDS: u64 = 4;
/// How long it waits between those rounds, in milliseconds.
const SETTLING_GAP_MS: u64 = 250;
/// How long it waits between every round after them, in seconds.
const INTERVAL_S: u64 = 32;

#[test]
fn the_agent_polls_four_times_a_quarter_second_apart_and_then_every_thirty_two_seconds() {
    let cadence = Cadence::default();

    assert_eq!(
        cadence.settling_rounds as u64, SETTLING_ROUNDS,
        "the settling rounds decide whether a fresh agent has anything to fit at all"
    );
    assert_eq!(
        cadence.settling_gap,
        Duration::from_millis(SETTLING_GAP_MS),
        "the settling gap decides the baseline the first fit is made across"
    );
    assert_eq!(
        cadence.interval,
        Duration::from_secs(INTERVAL_S),
        "the interval is one step inside what RFC 5905 permits a client to poll at, and it is what \
         the width the agent reaches is extrapolated over"
    );

    // And the gap is long enough for the rig to probe across. It reads three times at ten second
    // spacing and then advances by whatever is left, and on the unsigned count it is written on a
    // remainder below nought is a panic rather than a shorter schedule. Said here rather than left
    // for a later cadence change to find in the arithmetic.
    assert!(
        cadence.interval >= Duration::from_secs(30),
        "the regression rig probes three times at ten second spacing across the gap, and the gap \
         is now {:?}, so those readings no longer fit inside it",
        cadence.interval
    );
}

/// Where the regression case for the 2026-09-18 P0 lives, from this crate's manifest directory.
fn the_rig() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the agent crate sits inside crates/")
        .join("clock")
        .join("tests")
        .join("a_fresh_agent_at_the_shipped_cadence.rs")
}

/// The value of a `const NAME: TYPE = VALUE;` line, or nothing where the file has no such line.
///
/// Small and strict on purpose. It takes the one shape these three constants are written in, and
/// anything else, including the constant having been renamed or moved into a function, is nothing
/// rather than a guess. The caller treats nothing as a failure.
fn constant(source: &str, name: &str) -> Option<u64> {
    source
        .lines()
        .map(str::trim)
        .find_map(|line| {
            let rest = line.strip_prefix("const ")?;
            let (declared, value) = rest.split_once('=')?;
            let declared = declared.split(':').next()?.trim();
            (declared == name).then(|| value.trim().trim_end_matches(';').trim().to_string())
        })
        .and_then(|value| value.replace('_', "").parse().ok())
}

#[test]
fn the_regression_rig_simulates_the_schedule_the_agent_ships() {
    let path = the_rig();
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read the rig at {}: {e}", path.display()));

    for (name, expected) in [
        ("SETTLING_ROUNDS", SETTLING_ROUNDS),
        ("SETTLING_GAP_MS", SETTLING_GAP_MS),
        ("INTERVAL_S", INTERVAL_S),
    ] {
        let found = constant(&source, name).unwrap_or_else(|| {
            panic!(
                "the rig at {} no longer declares `const {name}` as a plain number, so nothing is \
                 holding it to the cadence the agent ships",
                path.display()
            )
        });
        assert_eq!(
            found, expected,
            "the rig simulates {name} at {found} and the agent ships {expected}, so the \
             regression case for the 2026-09-18 P0 is measuring a schedule the agent does not keep"
        );
    }
}

#[test]
fn a_renamed_or_rewritten_constant_is_a_failure_and_not_a_pass() {
    // The parser itself, on the shapes that matter: the one it is meant to read, a rename, and a
    // constant turned into something computed. Only the first is an answer.
    assert_eq!(
        constant("const INTERVAL_S: u64 = 32;", "INTERVAL_S"),
        Some(32)
    );
    assert_eq!(
        constant("const SETTLING_GAP_MS: u64 = 1_250;", "SETTLING_GAP_MS"),
        Some(1250)
    );
    assert_eq!(constant("const GAP_S: u64 = 32;", "INTERVAL_S"), None);
    assert_eq!(
        constant("const INTERVAL_S: u64 = other() * 2;", "INTERVAL_S"),
        None
    );
    assert_eq!(constant("let INTERVAL_S: u64 = 32;", "INTERVAL_S"), None);
}
