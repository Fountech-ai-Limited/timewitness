//! `stamp` answers by refusing rather than by running long.
//!
//! Every call the command makes carries its own timeout, five seconds for NTP, NTS and Roughtime,
//! eight for drand, fifteen for the timestamp authority and two for the agent socket, and there is
//! no retry loop. What none of it bounded until 2026-09-20 was the command. Sixteen rounds by nine
//! sources by five seconds is 720 seconds of polling before the evidence calls, on a network that
//! drops the packets rather than refusing them, which is the ordinary shape of a locked-down build
//! environment rather than an exotic one. The one line this product asks a stranger to put in a
//! workflow runs this command, on somebody else's build minutes.
//!
//! These run the shipped binary and touch no network: each one is refused before a packet goes out,
//! or is refused by a deadline short enough to pass while the first round is still being set up.
//! `--no-evidence` keeps the third-party calls out of it either way.

use std::process::Command;
use std::time::Instant;

fn timewitness() -> Command {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
}

fn stamp(extra: &[&str]) -> (bool, String) {
    let subject = std::env::temp_dir().join("tw-deadline-subject");
    std::fs::write(&subject, b"a file to stamp").expect("the temp directory takes a file");
    let key = std::env::temp_dir().join("tw-deadline.key");
    let out = std::env::temp_dir().join("tw-deadline-receipt.cbor");

    let mut command = timewitness();
    command.args([
        "stamp",
        "--subject",
        subject.to_str().expect("a path this test wrote"),
        "--key",
        key.to_str().expect("a path this test wrote"),
        "--out",
        out.to_str().expect("a path this test wrote"),
        "--no-evidence",
    ]);
    command.args(extra);
    let done = command.output().expect("the shipped binary runs");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    );
    (done.status.success(), said)
}

#[test]
fn the_help_says_what_the_deadline_is_and_why() {
    let done = timewitness().output().expect("the shipped binary runs");
    let help = String::from_utf8_lossy(&done.stdout).to_string();

    assert!(
        help.contains("--deadline <s>"),
        "the flag is not in the help a reader is handed: {help}"
    );
    assert!(
        help.contains("300 by default"),
        "the help does not say what the default is: {help}"
    );
    assert!(
        help.contains("twelve\n                          minutes"),
        "the help does not say what it costs without one: {help}"
    );
}

#[test]
fn a_deadline_that_is_not_a_number_of_seconds_is_refused_before_anything_is_polled() {
    for bad in ["0", "-1", "3601", "soon"] {
        let started = Instant::now();
        let (ok, said) = stamp(&["--deadline", bad]);
        assert!(!ok, "--deadline {bad} was accepted: {said}");
        assert!(
            said.contains("--deadline"),
            "--deadline {bad} was refused for something else: {said}"
        );
        assert!(
            started.elapsed().as_secs() < 5,
            "--deadline {bad} was refused after polling something"
        );
    }
}

/// A run whose own deliberate waiting already passes its deadline is refused before it starts.
///
/// `--rounds 16 --gap 60` is fifteen minutes of sleeping the caller asked for, and under the
/// default deadline it would be refused a quarter of the way through, having spent the build's time
/// and produced nothing. The two settings disagreeing is visible before the first packet.
#[test]
fn a_gap_and_a_round_count_that_cannot_finish_are_refused_before_the_first_packet() {
    let started = Instant::now();
    let (ok, said) = stamp(&["--rounds", "16", "--gap", "60"]);

    assert!(
        !ok,
        "a run that could not finish was started anyway: {said}"
    );
    assert!(
        said.contains("waiting on purpose"),
        "it was refused for something other than the waiting: {said}"
    );
    assert!(
        said.contains("900"),
        "the refusal does not say how much waiting was asked for: {said}"
    );
    assert!(
        started.elapsed().as_secs() < 5,
        "it slept before refusing, which is the fault rather than the fix"
    );
}

/// The same run with a deadline that fits is not refused for this reason.
///
/// It may well be refused for another, since this machine may have no network, and that is the
/// point of reading the sentence rather than the exit code: a check that only reads failure would
/// pass with the refusal above still firing.
#[test]
fn raising_the_deadline_past_the_waiting_takes_the_refusal_away() {
    let (_, said) = stamp(&["--rounds", "2", "--gap", "1", "--deadline", "30"]);
    assert!(
        !said.contains("waiting on purpose"),
        "one second of waiting inside thirty seconds was refused as too much: {said}"
    );
}
