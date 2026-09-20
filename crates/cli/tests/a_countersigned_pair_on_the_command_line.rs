//! A stranger holding both halves of an exchange, checking them with the shipped binary.
//!
//! This is the acceptance for slice three of the countersign protocol, run the way a stranger meets
//! it: hand the two header values to the binary and read what it says. The crate's own tests prove
//! the pairing; this proves the tool says so, and refuses when it should, because a library that
//! refuses and a tool that does not is a tool nobody can use to refuse.

use std::fs;
use std::process::{Command, Output};

use timewitness_countersign::{Countersigned, Exchange, Interval, Role, Signed};
use timewitness_receipt::AgentKey;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        // Nothing in this path asks the network. There is no switch to take it away here, so this
        // says it rather than proving it; the proof is
        // `crates/architecture/tests/verify_path_needs_nothing_of_ours.rs` and the offline run CI
        // makes in a namespace with no network at all.
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn digest(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn sender() -> AgentKey {
    AgentKey::from_seed(&digest(42))
}

fn receiver() -> AgentKey {
    AgentKey::from_seed(&digest(77))
}

fn a_signed_request() -> Signed {
    let request = Exchange {
        role: Role::Request,
        payload: digest(1),
        sequence: 7,
        interval: Interval {
            earliest_ns: 1_788_979_278_845_210_129,
            reading_ns: 1_788_979_278_918_450_302,
            latest_ns: 1_788_979_278_999_084_899,
        },
        receipt: digest(100),
        key: sender().public_key_bytes(),
        answers: None,
    };
    Signed::new(&request, &sender()).expect("our own request signs")
}

fn a_pair() -> Countersigned {
    Countersigned::answer(
        a_signed_request().to_bytes(),
        digest(2),
        1,
        Interval {
            earliest_ns: 1_788_979_279_045_210_129,
            reading_ns: 1_788_979_279_118_450_302,
            latest_ns: 1_788_979_279_199_084_899,
        },
        digest(150),
        &receiver(),
    )
    .expect("our own pair is a pair")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_binary_reads_a_pair_and_says_what_it_establishes() {
    let pair = a_pair();
    let out = run(&[
        "countersign",
        &pair.request().to_wire(),
        &pair.response().to_wire(),
    ]);
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    assert!(
        said.contains("one countersigned exchange"),
        "it did not say these two are one exchange: {said}"
    );
    assert!(
        said.contains("The sender's half.") && said.contains("The receiver's half."),
        "it did not show both halves: {said}"
    );
    // Both keys in full, so a reader can compare each with one they hold.
    assert!(
        said.contains(&hex(&sender().public_key_bytes())),
        "the sender's key is not in what it said: {said}"
    );
    assert!(
        said.contains(&hex(&receiver().public_key_bytes())),
        "the receiver's key is not in what it said: {said}"
    );
    // And the limit, in the same breath as the claim, per the rule that binds every surface.
    assert!(
        said.contains("Neither interval is evidence for the other party"),
        "it did not say what the pair is not: {said}"
    );
}

#[test]
fn the_binary_refuses_two_halves_that_are_not_one_exchange() {
    let pair = a_pair();

    // A second request, differing only in where it sits in the sender's own chain, so the response
    // is about the first one and not this one.
    let mut other = a_signed_request().exchange.clone();
    other.sequence += 1;
    let other = Signed::new(&other, &sender()).expect("the other request signs");

    let out = run(&["countersign", &other.to_wire(), &pair.response().to_wire()]);
    // A refusal goes to standard error, the same as every other refusal this tool gives.
    let said = text(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a pair that is not a pair is a non-zero exit: {}",
        text(&out.stdout)
    );
    assert!(
        said.contains("not one exchange"),
        "it did not say why: {said}"
    );
    // And what a receiver does about it, which is nothing.
    assert!(
        said.contains("carry on as though no exchange happened"),
        "it did not say a receiver carries on: {said}"
    );
}

#[test]
fn the_binary_reads_a_pair_out_of_a_file_one_to_a_line() {
    let pair = a_pair();
    let dir = std::env::temp_dir().join(format!("tw-pair-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to write into");
    let path = dir.join("exchange.txt");
    fs::write(
        &path,
        format!(
            "{}\n{}\n",
            pair.request().to_wire(),
            pair.response().to_wire()
        ),
    )
    .expect("the file is written");

    let out = run(&["countersign", "--from", &path.display().to_string()]);
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        said.contains("one countersigned exchange"),
        "reading two lines is reading a pair: {said}"
    );

    // One line in the same file is still one half, so the two routes have not come apart.
    fs::write(&path, format!("{}\n", pair.request().to_wire())).expect("the file is rewritten");
    let out = run(&["countersign", "--from", &path.display().to_string()]);
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        said.contains("the sender's half"),
        "one line is one half: {said}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_binary_refuses_more_than_two() {
    let pair = a_pair();
    let out = run(&[
        "countersign",
        &pair.request().to_wire(),
        &pair.response().to_wire(),
        &pair.response().to_wire(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "three halves is a usage error: {}",
        text(&out.stdout)
    );
}
