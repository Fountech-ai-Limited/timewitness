//! A stranger holding two receipts, asking the shipped binary which came first.
//!
//! The crate under `crates/verify` proves the reading. This proves the tool says it, in words a
//! person reads and in fields a script reads, and that the two never disagree: the sentence opens
//! with the word the field carries.
//!
//! The pair a reader most often has is the undecided one, because two stamps a program takes in the
//! ordinary course of its work are closer together than the bound on either of them. So that case
//! is here twice: once for the words it prints, and once for the fields, where `stands` is what a
//! script reads to find out whether it may rely on an order.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Payload, PolicyRecord, Receipt, SourceRecord,
};
use timewitness_receipt::{chain_link, AgentKey};

/// The moment the first receipt of every pair here is about.
const NOON: Nanos = 1_788_800_000 * NANOS_PER_SEC;

/// Half the width of the bound each receipt claims.
const HALF: Nanos = 60 * NANOS_PER_MILLI;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn key(seed: u8) -> AgentKey {
    AgentKey::from_seed(&[seed; 32])
}

/// A signed receipt claiming a bound around `at`, at `sequence` and behind `previous`.
fn a_receipt(key: &AgentKey, sequence: u64, previous: Option<Vec<u8>>, at: Nanos) -> Vec<u8> {
    let breakdown = BreakdownRecord {
        intersection_half: HALF - 3,
        network_half: 0,
        scheduling: 1,
        oscillator_holdover: 1,
        model_residual: 1,
        safety_margin: 0,
    };
    let receipt = Receipt {
        version: 0,
        sequence,
        chain_previous: previous,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash: vec![0x5au8; 32],
        },
        monotonic: 1_000_000_000 + u64::try_from(at - NOON).unwrap_or(0),
        utc_estimate: UnixNanos(at),
        claim: AgentClaim {
            earliest: UnixNanos(at - HALF),
            latest: UnixNanos(at + HALF),
            basis: EpsilonBasis::LocalModelOnly,
            fusion: "marzullo-then-inverse-square".to_string(),
            sources_offered: 3,
            sources_kept: 3,
            breakdown,
            since_last_sync: 30 * NANOS_PER_SEC,
            frequency_ppb: 1_200,
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
            },
        },
        evidence: Vec::new(),
        agent_public_key: key.public_key_bytes(),
    };
    key.sign(&receipt).expect("the agent signs its own receipt")
}

/// Two receipts of one chain on disk, the second `apart` nanoseconds after the first.
fn a_pair_on_disk(name: &str, apart: Nanos) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tw-order-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to write the pair into");
    let agent = key(0x11);
    let first = a_receipt(&agent, 4, None, NOON);
    let second = a_receipt(&agent, 5, Some(chain_link(&first)), NOON + apart);
    let first_path = dir.join("first.cbor");
    let second_path = dir.join("second.cbor");
    fs::write(&first_path, &first).expect("the first receipt is written");
    fs::write(&second_path, &second).expect("the second receipt is written");
    (first_path, second_path)
}

fn as_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn two_stamps_a_second_apart_come_back_in_order_and_exit_zero() {
    let (first, second) = a_pair_on_disk("clear", NANOS_PER_SEC);
    let out = run(&["order", &as_str(&first), &as_str(&second)]);
    let said = text(&out.stdout);

    assert!(out.status.success(), "{}{}", said, text(&out.stderr));
    assert!(said.contains("established:"), "{said}");
    assert!(
        said.contains("the first of the two moments came first"),
        "{said}"
    );
    // The chain is said as its own statement, about signing rather than about UTC.
    assert!(said.contains("one chain"), "{said}");
    assert!(
        said.contains("run `timewitness verify` on each one"),
        "a reader is told where the evidence for each interval is: {said}"
    );
}

#[test]
fn two_stamps_closer_together_than_their_own_bounds_answer_that_nobody_can_say() {
    // The answer this product exists to be willing to give, through the shipped binary.
    let (first, second) = a_pair_on_disk("overlapping", 10 * NANOS_PER_MILLI);
    let out = run(&["order", &as_str(&first), &as_str(&second)]);
    let said = text(&out.stdout);

    assert!(said.contains("undecided:"), "{said}");
    assert!(said.contains("Nobody can say"), "{said}");
    assert!(
        said.contains("rather than a failure"),
        "the answer says it is an answer: {said}"
    );
    // Zero, because the pair was read and answered. What a script reads to find out whether it
    // may rely on an order is the field below, not the exit status.
    assert!(out.status.success(), "{said}{}", text(&out.stderr));
    // And the chain's own answer survives beside it rather than being lost with the verdict.
    assert!(said.contains("one chain"), "{said}");
}

#[test]
fn the_fields_a_script_reads_say_the_same_thing_as_the_words() {
    let (first, second) = a_pair_on_disk("fields", NANOS_PER_SEC);
    let fields = text(&run(&["order", &as_str(&first), &as_str(&second), "--fields"]).stdout);
    let words = text(&run(&["order", &as_str(&first), &as_str(&second)]).stdout);

    let read = |name: &str| -> String {
        fields
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {fields}"))
            .to_string()
    };

    assert_eq!(read("order"), "established");
    assert_eq!(read("earlier"), "first");
    assert_eq!(read("stands"), "true");
    assert_eq!(read("chain"), "names");
    assert_eq!(read("chain_rests_on_a_hash"), "true");
    assert_eq!(read("first_held"), "true");
    assert_eq!(read("second_held"), "true");
    assert_eq!(read("first_sequence"), "4");
    assert_eq!(read("second_sequence"), "5");
    assert_eq!(read("gap_ns"), (NANOS_PER_SEC - 2 * HALF).to_string());

    // The sentence a person reads opens with the word the script reads. Two surfaces answering one
    // question differently is the fault this holds shut.
    assert!(words.contains(&format!("  {}:", read("order"))), "{words}");

    let undecided = a_pair_on_disk("fields-undecided", 10 * NANOS_PER_MILLI);
    // Undecided is an answer, so it is on stdout like any other.
    let fields = text(
        &run(&[
            "order",
            &as_str(&undecided.0),
            &as_str(&undecided.1),
            "--fields",
        ])
        .stdout,
    );
    assert!(fields.contains("order=undecided"), "{fields}");
    assert!(fields.contains("stands=false"), "{fields}");
    // The number beside an undecided verdict is the overlap and is never named as a gap, because a
    // script that read one as the other would have the two cases exactly backwards.
    assert!(fields.contains("overlap_ns="), "{fields}");
    assert!(!fields.contains("gap_ns="), "{fields}");
}

#[test]
fn one_receipt_is_refused_rather_than_answered_and_so_is_a_third() {
    let (first, second) = a_pair_on_disk("count", NANOS_PER_SEC);
    let one = run(&["order", &as_str(&first)]);
    assert_eq!(one.status.code(), Some(2));
    assert!(
        text(&one.stderr).contains("two receipts"),
        "{}",
        text(&one.stderr)
    );

    let three = run(&["order", &as_str(&first), &as_str(&second), &as_str(&first)]);
    assert_eq!(three.status.code(), Some(2));
}

#[test]
fn a_file_that_is_not_a_receipt_is_said_rather_than_guessed_at() {
    let (first, _) = a_pair_on_disk("rubbish", NANOS_PER_SEC);
    let dir = std::env::temp_dir().join(format!("tw-order-{}-rubbish", std::process::id()));
    let rubbish = dir.join("not-a-receipt.cbor");
    fs::write(&rubbish, b"this is not a receipt").expect("the file is written");

    let out = run(&["order", &as_str(&first), &as_str(&rubbish)]);
    assert_eq!(out.status.code(), Some(1));
    // A refusal prints as a refusal, which is stderr, the same as a receipt verify refuses.
    let said = text(&out.stderr);
    assert!(
        said.contains("not-sayable") || said.contains("not sayable"),
        "{said}"
    );
    assert!(said.contains("refused at"), "{said}");
}

#[test]
fn the_help_says_what_the_command_does_and_that_nobody_can_say_is_an_answer() {
    let usage = text(&run(&["--help"]).stdout);
    assert!(
        usage.contains("timewitness order <receipt> <receipt>"),
        "{usage}"
    );
    assert!(usage.contains("nobody"), "{usage}");

    // An option the command does not have is refused by name rather than read as a flag nobody
    // looks at, which is how a reader ends up believing a number of theirs was applied.
    let (first, second) = a_pair_on_disk("options", NANOS_PER_SEC);
    let out = run(&[
        "order",
        &as_str(&first),
        &as_str(&second),
        "--subject",
        "anything",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("--subject"),
        "{}",
        text(&out.stderr)
    );
}
