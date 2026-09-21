//! A receiver making its own half of an exchange, with the shipped binary and nothing else.
//!
//! This is receiver-only mode as a person meets it. The receiver holds no account, has no
//! relationship with us, and is not asked for one. What it holds is a receipt its own agent signed
//! for whatever it is sending back, and that receipt is where every number in its half comes from.
//!
//! The property worth the test is the one that cannot be seen by reading the output: there is no
//! way, on this command line, for a receiver to state an interval its own clock never read. The
//! library call takes an interval, a sequence and a receipt hash; the command takes none of the
//! three. So the tests below check what it refuses at least as hard as what it produces.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_countersign::{Exchange, Interval, Role, Signed};
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Payload, PolicyRecord, Receipt, SourceRecord,
};
use timewitness_receipt::AgentKey;

/// When the receiver's receipt says it read its clock.
const ARRIVED: Nanos = 1_788_800_001 * NANOS_PER_SEC;

/// Half the width of the bound that receipt claims.
const HALF: Nanos = 60 * NANOS_PER_MILLI;

/// The seed of the key that signs the receiver's receipt, and the receiver's half with it.
const RECEIVER_SEED: [u8; 32] = [0x31u8; 32];

/// Somebody else's key, for the halves that have to be refused.
const A_STRANGERS_SEED: [u8; 32] = [0x32u8; 32];

/// The sender, who is not this machine.
const SENDER_SEED: [u8; 32] = [0x33u8; 32];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn digest(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i % 256).unwrap_or(0));
    }
    out
}

/// A request from somebody else, signed by a key that is not this machine's.
fn a_request() -> String {
    a_request_made_at(ARRIVED - NANOS_PER_SEC)
}

/// The same request, made at a moment a case chooses.
fn a_request_made_at(earliest_ns: Nanos) -> String {
    let sender = AgentKey::from_seed(&SENDER_SEED);
    let request = Exchange {
        role: Role::Request,
        payload: digest(1),
        sequence: 9,
        interval: Interval {
            earliest_ns,
            reading_ns: earliest_ns + 10,
            latest_ns: earliest_ns + 20,
        },
        receipt: digest(200),
        key: sender.public_key_bytes(),
        answers: None,
    };
    Signed::new(&request, &sender)
        .expect("the sender signs its own request")
        .to_wire()
}

/// The receipt the receiver's own agent signed for what it is sending back.
fn a_receipt(key: &AgentKey, payload: [u8; 32]) -> Vec<u8> {
    let breakdown = BreakdownRecord {
        intersection_half: HALF - 3,
        network_half: 0,
        scheduling: 1,
        oscillator_holdover: 1,
        model_residual: 1,
        safety_margin: 0,
        unclaimed_rate: None,
    };
    let receipt = Receipt {
        version: 0,
        sequence: 12,
        chain_previous: None,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash: payload.to_vec(),
        },
        monotonic: 4_000_000_000,
        utc_estimate: UnixNanos(ARRIVED),
        claim: AgentClaim {
            earliest: UnixNanos(ARRIVED - HALF),
            latest: UnixNanos(ARRIVED + HALF),
            basis: EpsilonBasis::LocalModelOnly,
            fusion: "marzullo-then-inverse-square".to_string(),
            sources_offered: 3,
            sources_kept: 3,
            breakdown,
            since_last_sync: 30 * NANOS_PER_SEC,
            frequency_ppb: 900,
            boot_generation: 1,
            resume_generation: 0,
            sources: (0..3)
                .map(|i| SourceRecord {
                    id: format!("source-{i}"),
                    operator: Some(format!("operator-{i}.example")),
                    kind: "ntp".to_string(),
                    timescale: "utc".to_string(),
                    smear: "none".to_string(),
                    leap: "none".to_string(),
                    kept: true,
                    first_party: false,
                })
                .collect(),
            policy: PolicyRecord {
                max_bound_width: 5 * NANOS_PER_SEC,
                min_sources: 3,
                min_operators: Some(3),
                max_holdover: Some(3_600 * NANOS_PER_SEC),
                source_interval_floor: None,
                frequency_slew_ppb_per_s: None,
                frequency_span_ppb: None,
            },
            taken_by: None,
        },
        evidence: Vec::new(),
        agent_public_key: key.public_key_bytes(),
    };
    key.sign(&receipt).expect("the agent signs its own receipt")
}

/// The receiver's own files: a private key, and a receipt that key signed.
fn the_receivers_machine(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tw-answer-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to work in");
    let key_path = dir.join("agent.key");
    let receipt_path = dir.join("what-we-sent-back.cbor");
    fs::write(&key_path, RECEIVER_SEED).expect("the key is written");
    fs::write(
        &receipt_path,
        a_receipt(&AgentKey::from_seed(&RECEIVER_SEED), digest(7)),
    )
    .expect("the receipt is written");
    (key_path, receipt_path)
}

fn as_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The response value out of what the command printed.
fn the_response(said: &str) -> String {
    said.lines()
        .map(str::trim)
        .find(|line| line.starts_with("tw1."))
        .unwrap_or_else(|| panic!("no response value in {said}"))
        .to_string()
}

#[test]
fn a_receiver_answers_a_request_and_the_pair_reads_back() {
    let (key, receipt) = the_receivers_machine("answers");
    let request = a_request();

    let out = run(&[
        "countersign",
        &request,
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    let said = text(&out.stdout);
    assert!(out.status.success(), "{said}{}", text(&out.stderr));

    let response = the_response(&said);
    assert!(said.contains("X-Bounded-Time"), "{said}");
    assert!(
        said.contains("one countersigned exchange"),
        "the writer reads its own output back before printing it: {said}"
    );

    // And a stranger holding the two values reads the same pair, with the shipped binary, offline.
    let read = run(&["countersign", &request, &response]);
    assert!(
        read.status.success(),
        "{}{}",
        text(&read.stdout),
        text(&read.stderr)
    );
    assert!(
        text(&read.stdout).contains("Both signatures hold"),
        "{}",
        text(&read.stdout)
    );
}

#[test]
fn everything_the_response_says_about_the_clock_comes_out_of_the_receipt() {
    let (key, receipt) = the_receivers_machine("fields");
    let request = a_request();

    let fields = text(
        &run(&[
            "countersign",
            &request,
            "--answer",
            "--receipt",
            &as_str(&receipt),
            "--key",
            &as_str(&key),
            "--fields",
        ])
        .stdout,
    );
    let read = |name: &str| -> String {
        fields
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {fields}"))
            .to_string()
    };

    // The three numbers a command line could otherwise have been asked for, each read off the
    // receipt rather than off an argument.
    assert_eq!(read("response_earliest_ns"), (ARRIVED - HALF).to_string());
    assert_eq!(read("response_latest_ns"), (ARRIVED + HALF).to_string());
    assert_eq!(read("response_sequence"), "12");
    assert_eq!(
        read("response_key"),
        AgentKey::from_seed(&RECEIVER_SEED)
            .public_key_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert!(fields.contains("response="), "{fields}");
}

#[test]
fn a_key_that_did_not_sign_the_receipt_is_refused_rather_than_signed() {
    // The fault this catches: a response naming a receipt somebody else's key signed. A reader who
    // fetched that receipt would find two parties where they were told there was one, and nothing
    // on the wire says so, because the wire carries the receipt by hash and not by content.
    let (_, receipt) = the_receivers_machine("wrong-key");
    let dir = std::env::temp_dir().join(format!("tw-answer-{}-wrong-key", std::process::id()));
    let stranger = dir.join("somebody-elses.key");
    fs::write(&stranger, A_STRANGERS_SEED).expect("the key is written");

    let out = run(&[
        "countersign",
        &a_request(),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&stranger),
    ]);
    assert_eq!(out.status.code(), Some(2));
    let said = text(&out.stderr);
    assert!(said.contains("did not sign the receipt"), "{said}");

    // And the control: the same command with the key that did sign it goes through, so the refusal
    // above is about the key rather than about anything else in the line.
    let (key, receipt) = the_receivers_machine("wrong-key");
    assert!(run(&[
        "countersign",
        &a_request(),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ])
    .status
    .success());
}

#[test]
fn a_key_that_is_not_there_is_refused_and_never_made() {
    // `stamp` makes a key where there is none, because a build runner has nobody to ask. Here that
    // would be the one key certain not to have signed the receipt, so this reads and never writes.
    let (_, receipt) = the_receivers_machine("no-key");
    let missing = std::env::temp_dir()
        .join(format!("tw-answer-{}-no-key", std::process::id()))
        .join("not-here.key");

    let out = run(&[
        "countersign",
        &a_request(),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&missing),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("is not there"),
        "{}",
        text(&out.stderr)
    );
    assert!(
        !missing.exists(),
        "a key was made for a run that was refused"
    );
}

#[test]
fn a_request_that_cannot_be_read_is_not_answered_and_nothing_is_signed() {
    let (key, receipt) = the_receivers_machine("bad-request");
    let out = run(&[
        "countersign",
        "tw1.not-a-request",
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(said.contains("was not answered"), "{said}");
    assert!(
        said.contains("carries on as though no exchange happened"),
        "a receiver that will not countersign does not stop the request: {said}"
    );
}

#[test]
fn answering_two_requests_at_once_is_refused_rather_than_picking_one() {
    let (key, receipt) = the_receivers_machine("two");
    let request = a_request();
    let out = run(&[
        "countersign",
        &request,
        &request,
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("one request"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_receipt_that_is_not_a_receipt_is_said_rather_than_guessed_at() {
    let (key, _) = the_receivers_machine("rubbish");
    let dir = std::env::temp_dir().join(format!("tw-answer-{}-rubbish", std::process::id()));
    let rubbish = dir.join("not-a-receipt.cbor");
    fs::write(&rubbish, b"nothing of the kind").expect("the file is written");

    let out = run(&[
        "countersign",
        &a_request(),
        "--answer",
        "--receipt",
        &as_str(&rubbish),
        "--key",
        &as_str(&key),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("is not a receipt this can read"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_receipt_older_than_the_request_is_not_answered_and_nothing_is_signed() {
    // The receiver's receipt says its clock read a moment wholly before the request was made. A
    // response names its request by bytes that had to exist first, so a pair built from these two
    // is one our own reader calls contradicted. Found 2026-09-21: this signed it and exited 0.
    let (key, receipt) = the_receivers_machine("older");
    let later = ARRIVED + HALF + 1;
    let out = run(&[
        "countersign",
        &a_request_made_at(later),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    let said = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{said}");
    assert!(said.contains("was not answered"), "{said}");
    assert!(said.contains("before the request"), "{said}");
    assert!(
        !said.lines().any(|line| line.trim().starts_with("tw1.")),
        "a response was printed for a request that was not answered: {said}"
    );

    // The same with --fields, which a script reads.
    let fields = run(&[
        "countersign",
        &a_request_made_at(later),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
        "--fields",
    ]);
    assert_eq!(fields.status.code(), Some(1));
    assert!(!text(&fields.stdout).contains("response="));

    // And the control: a request made one nanosecond earlier touches the receipt's interval, which
    // is undecided rather than contradicted, and is answered.
    let answered = run(&[
        "countersign",
        &a_request_made_at(later - 1),
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert!(
        answered.status.success(),
        "{}{}",
        text(&answered.stdout),
        text(&answered.stderr)
    );
}
