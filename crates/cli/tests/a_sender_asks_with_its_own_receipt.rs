//! A machine starting an exchange, with the shipped binary and nothing else.
//!
//! `--answer` let a receiver make its half. Until this, nothing on the command line made the other
//! one, so two machines could countersign each other only through a program somebody wrote against
//! the library. That gap matters more than it sounds: a fleet that countersigns its own heartbeats
//! is the claim, and a claim that rests on code nobody has written is not a claim.
//!
//! The property worth the test is the same one the answering side has, and it cannot be seen by
//! reading the output: there is no way here for a sender to state an interval its own clock never
//! read. The interval, the sequence, the receipt hash and the payload all come out of a receipt its
//! agent signed, and none of the four is an argument. So what this checks hardest is what the
//! command refuses.
//!
//! The last test is the one a fleet turns on: two machines, two keys, two receipts, one exchange,
//! and no third party anywhere in it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Payload, PolicyRecord, Receipt, SourceRecord,
};
use timewitness_receipt::AgentKey;

/// When the sender's receipt says it read its clock.
const SENT: Nanos = 1_788_800_000 * NANOS_PER_SEC;

/// Half the width of the bound that receipt claims.
const HALF: Nanos = 40 * NANOS_PER_MILLI;

/// The first machine in the domain, which asks.
const ASKING_SEED: [u8; 32] = [0x41u8; 32];

/// The second, which answers.
const ANSWERING_SEED: [u8; 32] = [0x42u8; 32];

/// A third key, for the halves that have to be refused.
const A_STRANGERS_SEED: [u8; 32] = [0x43u8; 32];

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

/// A receipt this machine's own agent signed, for whatever it is about to send.
fn a_receipt(key: &AgentKey, payload: [u8; 32], read_at: Nanos, sequence: u64) -> Vec<u8> {
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
        sequence,
        chain_previous: None,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash: payload.to_vec(),
        },
        monotonic: 4_000_000_000,
        utc_estimate: UnixNanos(read_at),
        claim: AgentClaim {
            earliest: UnixNanos(read_at - HALF),
            latest: UnixNanos(read_at + HALF),
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

/// One machine's own files: a private key, and a receipt that key signed.
fn a_machine(name: &str, seed: [u8; 32], read_at: Nanos, sequence: u64) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("tw-ask-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to work in");
    let key_path = dir.join("agent.key");
    let receipt_path = dir.join("what-we-are-sending.cbor");
    fs::write(&key_path, seed).expect("the key is written");
    fs::write(
        &receipt_path,
        a_receipt(&AgentKey::from_seed(&seed), digest(7), read_at, sequence),
    )
    .expect("the receipt is written");
    (key_path, receipt_path)
}

fn as_str(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The wire value out of what the command printed.
fn the_value(said: &str) -> String {
    said.lines()
        .map(str::trim)
        .find(|line| line.starts_with("tw1."))
        .unwrap_or_else(|| panic!("no wire value in {said}"))
        .to_string()
}

/// One field off the `--fields` surface.
fn field(said: &str, name: &str) -> String {
    said.lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} in {said}"))
        .to_string()
}

#[test]
fn a_sender_makes_its_half_and_our_own_reader_reads_it_back() {
    let (key, receipt) = a_machine("asks", ASKING_SEED, SENT, 12);

    let out = run(&[
        "countersign",
        "--ask",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    let said = text(&out.stdout);
    assert!(out.status.success(), "{said}{}", text(&out.stderr));

    assert!(said.contains("X-Bounded-Time"), "{said}");
    assert!(
        said.contains("sender's half"),
        "it says which half it made: {said}"
    );
    assert!(
        said.contains("Nothing here obliges anybody to countersign"),
        "a request is not an instruction, and the words say so: {said}"
    );

    // A stranger reads the half back with the same binary and no network.
    let request = the_value(&said);
    let read = run(&["countersign", &request]);
    assert!(
        read.status.success(),
        "{}{}",
        text(&read.stdout),
        text(&read.stderr)
    );
    assert!(
        text(&read.stdout).contains("its signature holds"),
        "{}",
        text(&read.stdout)
    );
}

#[test]
fn every_number_in_the_half_comes_out_of_the_receipt() {
    let (key, receipt) = a_machine("numbers", ASKING_SEED, SENT, 12);

    let out = run(&[
        "countersign",
        "--ask",
        "--fields",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    let said = text(&out.stdout);
    assert!(out.status.success(), "{said}{}", text(&out.stderr));

    assert_eq!(
        field(&said, "request_earliest_ns"),
        (SENT - HALF).to_string()
    );
    assert_eq!(field(&said, "request_latest_ns"), (SENT + HALF).to_string());
    assert_eq!(field(&said, "request_width_ns"), (2 * HALF).to_string());
    assert_eq!(field(&said, "request_sequence"), "12");
    assert_eq!(
        field(&said, "request_payload"),
        digest(7)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert!(field(&said, "request").starts_with("tw1."));
}

#[test]
fn a_key_that_did_not_sign_the_receipt_is_refused() {
    let (_, receipt) = a_machine("stranger", ASKING_SEED, SENT, 12);
    let dir = std::env::temp_dir().join(format!("tw-ask-{}-stranger-key", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to work in");
    let key = dir.join("somebody-elses.key");
    fs::write(&key, A_STRANGERS_SEED).expect("the key is written");

    let out = run(&[
        "countersign",
        "--ask",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("a receipt of somebody else's"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_key_that_is_not_there_is_never_made() {
    let (_, receipt) = a_machine("nokey", ASKING_SEED, SENT, 12);
    let missing = std::env::temp_dir()
        .join(format!("tw-ask-{}-nokey", std::process::id()))
        .join("not-here.key");

    let out = run(&[
        "countersign",
        "--ask",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&missing),
    ]);
    assert!(!out.status.success());
    let said = text(&out.stderr);
    assert!(said.contains("reads a key and never makes one"), "{said}");
    assert!(!missing.exists(), "a refusal made a key: {said}");
}

#[test]
fn the_two_halves_are_one_or_the_other_and_neither_reads_a_value() {
    let (key, receipt) = a_machine("both", ASKING_SEED, SENT, 12);
    let both = run(&[
        "countersign",
        "--ask",
        "--answer",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert!(!both.status.success());
    assert!(
        text(&both.stderr).contains("one or the other"),
        "{}",
        text(&both.stderr)
    );

    // `--ask` makes a half rather than reading one, so a value handed to it is a person expecting
    // the other command.
    let with_a_value = run(&[
        "countersign",
        "tw1.something",
        "--ask",
        "--receipt",
        &as_str(&receipt),
        "--key",
        &as_str(&key),
    ]);
    assert!(!with_a_value.status.success());
    assert!(
        text(&with_a_value.stderr).contains("takes no exchange value"),
        "{}",
        text(&with_a_value.stderr)
    );
}

#[test]
fn asking_needs_a_receipt_and_a_key_and_says_which_is_missing() {
    let (key, receipt) = a_machine("needs", ASKING_SEED, SENT, 12);

    let no_receipt = run(&["countersign", "--ask", "--key", &as_str(&key)]);
    assert!(!no_receipt.status.success());
    assert!(
        text(&no_receipt.stderr).contains("--receipt"),
        "{}",
        text(&no_receipt.stderr)
    );

    let no_key = run(&["countersign", "--ask", "--receipt", &as_str(&receipt)]);
    assert!(!no_key.status.success());
    assert!(
        text(&no_key.stderr).contains("--key"),
        "{}",
        text(&no_key.stderr)
    );
}

/// Two machines countersign a heartbeat with the shipped binary, and nothing else is in it.
///
/// This is what a shared time domain rests on, run the way a stranger would. Machine one makes its
/// half from its own receipt, machine two answers from its own, and a third party reads the pair.
/// No account exists, no host of ours is named, and neither machine was asked for anything by
/// anybody.
#[test]
fn two_machines_countersign_a_heartbeat_with_nothing_of_ours_in_it() {
    let (first_key, first_receipt) = a_machine("fleet-one", ASKING_SEED, SENT, 12);
    let (second_key, second_receipt) =
        a_machine("fleet-two", ANSWERING_SEED, SENT + NANOS_PER_SEC, 5);

    let asked = run(&[
        "countersign",
        "--ask",
        "--receipt",
        &as_str(&first_receipt),
        "--key",
        &as_str(&first_key),
    ]);
    assert!(
        asked.status.success(),
        "{}{}",
        text(&asked.stdout),
        text(&asked.stderr)
    );
    let request = the_value(&text(&asked.stdout));

    let answered = run(&[
        "countersign",
        &request,
        "--answer",
        "--receipt",
        &as_str(&second_receipt),
        "--key",
        &as_str(&second_key),
    ]);
    assert!(
        answered.status.success(),
        "{}{}",
        text(&answered.stdout),
        text(&answered.stderr)
    );
    let response = the_value(&text(&answered.stdout));

    let read = run(&["countersign", &request, &response]);
    let said = text(&read.stdout);
    assert!(read.status.success(), "{said}{}", text(&read.stderr));
    assert!(said.contains("Both signatures hold"), "{said}");
    assert!(
        said.contains("two different keys"),
        "a heartbeat is two parties: {said}"
    );

    // The two bounds are a second apart and each is 80 ms wide, so the order is established. What
    // the words must not do is turn that into an agreement between the two clocks.
    assert!(
        said.contains("It is a claim about order and not about"),
        "{said}"
    );
    assert!(
        !said.to_lowercase().contains("accurate"),
        "a pair of bounds is never an accuracy: {said}"
    );
    assert!(
        said.contains("Neither interval is evidence for the other party"),
        "{said}"
    );

    // And nothing of ours is anywhere in what the two machines made or read.
    for value in [&request, &response, &said] {
        assert!(
            !value.contains("timewitness.dev"),
            "a host of ours is in the exchange: {value}"
        );
    }
}
