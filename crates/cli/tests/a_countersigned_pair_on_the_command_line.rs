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

// The ordering answer, through the tool. The verdict a reader sees has to be the verdict the crate
// gives, and the undecided case has to read as an answer rather than as the tool having failed.

/// A pair whose receive interval is put wherever a case needs it, signed straight over the
/// receiver's key.
///
/// Our own receiver refuses to answer with an interval wholly before the request, so the
/// contradicted case can only reach a reader from somebody else's, and that is how it is built.
fn pair_with(received: Interval) -> Countersigned {
    let request = a_signed_request();
    let response = Exchange {
        role: Role::Response,
        payload: digest(2),
        sequence: 1,
        interval: received,
        receipt: digest(150),
        key: receiver().public_key_bytes(),
        answers: Some(request.envelope_hash()),
    };
    let response = Signed::new(&response, &receiver()).expect("the response signs");
    Countersigned::read(&request.to_wire(), &response.to_wire())
        .expect("the pair is a pair whatever the clocks say")
}

fn sent() -> Interval {
    a_signed_request().exchange.interval
}

fn shifted(by_ns: i128) -> Interval {
    let sent = sent();
    Interval {
        earliest_ns: sent.earliest_ns + by_ns,
        reading_ns: sent.reading_ns + by_ns,
        latest_ns: sent.latest_ns + by_ns,
    }
}

/// What the binary says about a pair, and the exit it gives.
///
/// The exit follows the verdict the way `order`'s does: nought where the pair can be relied on,
/// one where it is contradicted. A script reading the exit code alone must not take a pair its
/// own reader calls impossible as a good one.
fn said_about(pair: &Countersigned, extra: &[&str]) -> String {
    let mut args = vec![
        "countersign".to_string(),
        pair.request().to_wire(),
        pair.response().to_wire(),
    ];
    args.extend(extra.iter().map(ToString::to_string));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run(&borrowed);
    // A non-zero exit goes to standard error, the same as every other refusal the binary gives.
    let said = format!("{}{}", text(&out.stdout), text(&out.stderr));
    let wanted = if pair.ordering().word() == "contradicted" {
        1
    } else {
        0
    };
    assert_eq!(
        out.status.code(),
        Some(wanted),
        "the exit does not follow the verdict {}: {said}",
        pair.ordering().word()
    );
    said
}

#[test]
fn the_binary_says_which_came_first_where_the_two_claims_settle_it() {
    let width = sent().latest_ns - sent().earliest_ns;
    let said = said_about(&pair_with(shifted(width + 1_000_000)), &[]);
    assert!(
        said.contains("Which came first."),
        "it did not answer the question: {said}"
    );
    assert!(
        said.contains("the request was made before the response"),
        "it did not give the verdict: {said}"
    );
    assert!(
        said.contains("1000000 ns of clear space"),
        "it did not say how much room the answer had: {said}"
    );
}

#[test]
fn the_binary_says_undecided_out_loud_and_does_not_pick_one() {
    // The case the product exists to be willing to say. A reader must be able to tell this from the
    // tool having failed, so the exit is zero and the words say what is and is not established.
    let width = sent().latest_ns - sent().earliest_ns;
    let said = said_about(&pair_with(shifted(width - 1_000_000)), &[]);
    assert!(
        said.contains("undecided"),
        "it did not say undecided: {said}"
    );
    assert!(
        said.contains("do not establish"),
        "it did not say what is not established: {said}"
    );
    assert!(
        !said.contains("the request was made before the response,"),
        "it picked an order it does not have: {said}"
    );
    assert!(
        said.contains("Nothing here narrows one bound with the other"),
        "it did not say what it refuses to do to get an answer: {said}"
    );
}

#[test]
fn the_binary_says_a_receive_moment_before_a_send_moment_cannot_be_true() {
    let width = sent().latest_ns - sent().earliest_ns;
    let said = said_about(&pair_with(shifted(-(width + 5_000))), &[]);
    assert!(
        said.contains("contradicted"),
        "it did not name the contradiction: {said}"
    );
    assert!(
        said.contains("cannot be true"),
        "it did not say the two claims cannot both hold: {said}"
    );
    assert!(
        said.contains("this does not guess"),
        "it guessed which of the two is wrong: {said}"
    );
}

#[test]
fn the_fields_a_script_reads_carry_the_verdict_and_the_number_beside_it() {
    let width = sent().latest_ns - sent().earliest_ns;

    let ordered = said_about(&pair_with(shifted(width + 7)), &["--fields"]);
    assert!(
        ordered.contains("order=established\n"),
        "the verdict is one word: {ordered}"
    );
    assert!(ordered.contains("gap_ns=7\n"), "with its gap: {ordered}");
    assert!(
        !ordered.contains("overlap_ns="),
        "an order has no overlap to report: {ordered}"
    );

    let undecided = said_about(&pair_with(shifted(width - 7)), &["--fields"]);
    assert!(
        undecided.contains("order=undecided\n"),
        "the verdict is one word: {undecided}"
    );
    assert!(
        undecided.contains("overlap_ns=7\n"),
        "with its overlap: {undecided}"
    );
    assert!(
        !undecided.contains("gap_ns="),
        "an overlap is not a gap and a script must not read one as the other: {undecided}"
    );

    // Each half is named by the hash of what travelled, so a script can tie the pair to a log.
    assert!(
        undecided.contains(&format!(
            "request_sha256={}",
            hex(&a_signed_request().envelope_hash())
        )),
        "the request is named by what travelled: {undecided}"
    );
}

#[test]
fn the_fields_verdict_is_the_one_the_words_give() {
    // Two surfaces over one answer is two answers waiting to disagree. Every case is asked both
    // ways and the two must line up.
    let width = sent().latest_ns - sent().earliest_ns;
    for (shift, word) in [
        (width + 1, "established"),
        (width, "undecided"),
        (width - 1, "undecided"),
        (-(width + 1), "contradicted"),
    ] {
        let pair = pair_with(shifted(shift));
        let fields = said_about(&pair, &["--fields"]);
        let words = said_about(&pair, &[]);
        assert!(
            fields.contains(&format!("order={word}\n")),
            "the fields say {word}: {fields}"
        );
        assert!(
            words.contains(word),
            "and so do the words, at a shift of {shift}: {words}"
        );
    }
}
