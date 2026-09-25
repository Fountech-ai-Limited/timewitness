//! `stamp` answers by refusing rather than by running long.
//!
//! Every call the command makes carries its own timeout, five seconds for NTP and Roughtime and for
//! each of NTS's two steps, eight for drand, fifteen for the timestamp authority and two for the
//! agent socket, and there is no retry loop. What none of it bounded until 2026-09-20 was the command. Sixteen rounds by nine
//! sources by five seconds is 720 seconds of polling before the evidence calls, on a network that
//! drops the packets rather than refusing them, which is the ordinary shape of a locked-down build
//! environment rather than an exotic one. The one line this product asks a stranger to put in a
//! workflow runs this command, on somebody else's build minutes.
//!
//! These run the shipped binary and touch no network: each one is refused before a packet goes out,
//! or is refused by a deadline short enough to pass while the first round is still being set up.
//! `--no-evidence` keeps the third-party calls out of it either way.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

fn timewitness() -> Command {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
}

/// Each call gets a folder of its own. The tests in this file run in parallel, and when they shared
/// one key path two of them could both find it missing and both try to create it, so the second was
/// refused with "could not be written" rather than for the waiting it was there to prove. That
/// failed `main` at `201abed` on 2026-09-21 with nothing else changed.
fn scratch() -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let folder = std::env::temp_dir().join(format!(
        "tw-deadline-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&folder).expect("the temp directory takes a folder");
    folder
}

fn stamp(extra: &[&str]) -> (bool, String) {
    let folder = scratch();
    let subject = folder.join("subject");
    std::fs::write(&subject, b"a file to stamp").expect("the temp directory takes a file");
    let key = folder.join("stamp.key");
    let out = folder.join("receipt.cbor");

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
    let _ = std::fs::remove_dir_all(&folder);
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
    // Read with the layout's line breaks taken out. Until 2026-09-25 the help said the shipped
    // settings poll for twelve minutes, which was the cost before this flag existed, and a reader
    // took it as the cost now; it now says what the bound saves.
    let flat = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("would poll for twelve minutes; this answers by refusing at five"),
        "the help does not say what it costs without one and what it answers with: {help}"
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
