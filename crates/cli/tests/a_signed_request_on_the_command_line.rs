//! A stranger holding one half of an exchange, checking it with the shipped binary and no network.
//!
//! This is the acceptance for slice two of the countersign protocol, run the way a stranger would
//! meet it: build a signed request, hand the header value to the binary, and read what it says. The
//! same properties the crate's own tests establish are established again here through the tool,
//! because a library that refuses and a tool that does not is a tool nobody can use to refuse.

use std::process::{Command, Output};

use timewitness_countersign::{Exchange, Interval, Role, Signed};
use timewitness_receipt::AgentKey;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        // Nothing in this path asks the network, and a test that let it would not notice. There is
        // no switch to take it away here, so this says it rather than proving it; the proof is
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

fn a_signed_request() -> (Signed, AgentKey) {
    let key = AgentKey::from_seed(&digest(42));
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
        key: key.public_key_bytes(),
        answers: None,
    };
    let signed = Signed::new(&request, &key).expect("our own request signs");
    (signed, key)
}

#[test]
fn the_binary_reads_a_signed_request_and_says_what_it_establishes() {
    let (signed, key) = a_signed_request();
    let wire = signed.to_wire();
    let out = run(&["countersign", &wire]);
    let said = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    assert!(
        said.contains("the sender's half"),
        "it did not say which half this is: {said}"
    );
    // The key it was signed by, in full, so a reader can compare it with one they hold.
    let hex: String = key
        .public_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        said.contains(&hex),
        "it did not name the signing key: {said}"
    );
    assert!(
        said.contains("1788979278845210129") && said.contains("1788979278999084899"),
        "it did not print both edges of the interval: {said}"
    );

    // And the sentence that keeps the limit in front of the reader. A signature is not evidence
    // about a clock, and this is the surface where somebody would most easily assume it was.
    assert!(
        said.contains("about its own clock"),
        "it did not say what the signature is a statement about: {said}"
    );
    assert!(
        said.contains("not evidence that the clock was right"),
        "it did not say what the signature is not: {said}"
    );
    assert!(
        said.contains("third-party evidence"),
        "it did not say the interval's evidence is elsewhere: {said}"
    );
}

#[test]
fn the_binary_refuses_a_body_nobody_signed() {
    let (signed, _) = a_signed_request();
    // The body on its own, which is what the wire carried before anything signed it.
    let body = signed.exchange.to_cbor();
    let wire = format!("tw1.{}", timewitness_countersign::base64url::encode(&body));
    let out = run(&["countersign", &wire]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    let said = text(&out.stderr);
    assert!(
        said.contains("not a signed exchange"),
        "it did not say why: {said}"
    );
    // And it says what a receiver does about it, which is nothing, because this product does not
    // enforce.
    assert!(
        said.contains("carry on as though no exchange happened"),
        "it did not say what follows from a refusal: {said}"
    );
}

#[test]
fn the_binary_refuses_one_altered_after_it_was_signed() {
    let (signed, _) = a_signed_request();
    let wire = signed.to_wire();
    // One character of the encoded value changed, which is the crudest tamper there is and the one
    // a reader will try first.
    let mut bytes: Vec<char> = wire.chars().collect();
    let at = bytes.len() - 5;
    bytes[at] = if bytes[at] == 'A' { 'B' } else { 'A' };
    let altered: String = bytes.into_iter().collect();
    assert_ne!(altered, wire);

    let out = run(&["countersign", &altered]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("not an exchange this can read"),
        "it did not refuse an altered value: {}",
        text(&out.stderr)
    );
}

#[test]
fn the_usage_names_it_and_asking_for_it_wrong_says_so() {
    let out = run(&["countersign"]);
    assert_eq!(out.status.code(), Some(2));
    let said = text(&out.stderr);
    assert!(
        said.contains("countersign needs the header value"),
        "it did not say what it needed: {said}"
    );
    assert!(
        said.contains("timewitness countersign"),
        "it did not print the usage beside the refusal: {said}"
    );

    // An option this subcommand does not have is refused by name rather than ignored.
    let out = run(&["countersign", "tw1.AQ", "--min-width", "9"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("countersign has no --min-width"),
        "an option it does not have was not refused: {}",
        text(&out.stderr)
    );
}
