//! The shipped binary tells a reader what receipt format version 1 states, and says when a receipt
//! is version 0 and could not state it.
//!
//! The terms that set a receipt's width were the point of version 1, and a term nobody prints is a
//! term nobody reads. So the words, the fields and the JSON all carry them, from one list, and a
//! version 0 receipt is named as one rather than shown with noughts that would read as the agent
//! having stated nought.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Payload, PolicyRecord, Receipt, SourceRecord, TakenBy,
};
use timewitness_receipt::AgentKey;

const NOON: Nanos = 1_788_800_000 * NANOS_PER_SEC;
const HALF: Nanos = 60 * NANOS_PER_MILLI;

const THE_COMMITTED_RECEIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../verify/tests/data/a-real-stamp/receipt.cbor"
);

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn version_1(taken_by: TakenBy) -> Vec<u8> {
    let key = AgentKey::from_seed(&[0x31; 32]);
    let receipt = Receipt {
        version: 1,
        sequence: 1,
        chain_previous: None,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash: vec![0x5a; 32],
        },
        monotonic: 1_000_000_000,
        utc_estimate: UnixNanos(NOON),
        claim: AgentClaim {
            earliest: UnixNanos(NOON - HALF),
            latest: UnixNanos(NOON + HALF),
            basis: EpsilonBasis::LocalModelOnly,
            fusion: "marzullo-then-inverse-square".to_string(),
            sources_offered: 3,
            sources_kept: 3,
            breakdown: BreakdownRecord {
                intersection_half: HALF - 30 * NANOS_PER_MILLI,
                network_half: 0,
                scheduling: 0,
                oscillator_holdover: 30 * NANOS_PER_MILLI,
                model_residual: 0,
                safety_margin: 0,
                unclaimed_rate: Some(12 * NANOS_PER_MILLI),
            },
            since_last_sync: 30 * NANOS_PER_SEC,
            frequency_ppb: 0,
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
                source_interval_floor: Some(100_000),
                frequency_slew_ppb_per_s: Some(1_000),
                frequency_span_ppb: Some(100_000),
            },
            taken_by: Some(taken_by),
        },
        evidence: Vec::new(),
        agent_public_key: key.public_key_bytes(),
    };
    key.sign(&receipt).expect("a whole version 1 receipt signs")
}

fn on_disk(name: &str, bytes: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tw-v1-report-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to write into");
    let path = dir.join(name);
    fs::write(&path, bytes).expect("the receipt is written");
    path
}

#[test]
fn the_fields_carry_every_term_version_1_states() {
    let path = on_disk("one-shot.cbor", &version_1(TakenBy::OneShot));
    let out = run(&[
        "verify",
        &path.to_string_lossy(),
        "--fields",
        "--no-anchors",
    ]);
    let said = text(&out.stdout);
    for line in [
        "format_version=1",
        "taken_by=one-shot",
        "unclaimed_rate_ns=12000000",
        "source_interval_floor_ns=100000",
        "frequency_slew_ppb_per_s=1000",
        "frequency_span_ppb=100000",
    ] {
        assert!(said.lines().any(|l| l == line), "no {line} in: {said}");
    }
}

#[test]
fn the_words_say_which_path_the_reading_came_by_and_the_terms_it_rests_on() {
    let path = on_disk("resident.cbor", &version_1(TakenBy::ResidentAgent));
    let said = text(&run(&["verify", &path.to_string_lossy(), "--no-anchors"]).stdout);
    assert!(said.contains("The terms that set the width"), "{said}");
    assert!(said.contains("read from a resident agent"), "{said}");
    assert!(
        said.contains("a rate the agent is not correcting for"),
        "{said}"
    );
    assert!(said.contains("100000 parts per billion wide"), "{said}");
}

#[test]
fn the_json_carries_the_same_list() {
    let path = on_disk("json.cbor", &version_1(TakenBy::OneShot));
    let said = text(&run(&["verify", &path.to_string_lossy(), "--json", "--no-anchors"]).stdout);
    assert!(said.contains("\"version_1\""), "{said}");
    assert!(said.contains("\"taken_by\": \"one-shot\""), "{said}");
}

#[test]
fn a_version_0_receipt_is_named_as_one_and_shows_no_invented_nought() {
    let fields = text(&run(&["verify", THE_COMMITTED_RECEIPT, "--fields", "--no-anchors"]).stdout);
    for line in [
        "format_version=0",
        "taken_by=none",
        "unclaimed_rate_ns=none",
        "frequency_span_ppb=none",
    ] {
        assert!(fields.lines().any(|l| l == line), "no {line} in: {fields}");
    }
    let words = text(&run(&["verify", THE_COMMITTED_RECEIPT, "--no-anchors"]).stdout);
    assert!(words.contains("format version 0"), "{words}");
}
