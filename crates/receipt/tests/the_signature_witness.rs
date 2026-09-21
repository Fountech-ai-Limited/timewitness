//! The witness over a receipt's own signature, which receipt format version 1 carries outside the
//! signed body.
//!
//! Every other outside signature is about the subject, so it places the thing stamped and not the
//! signing. These tests hold the witness to being about this receipt's signature and no other, to the
//! one place version 1 allows it, and to version 0 allowing it nowhere. The live half, a real token
//! over a real signature checked against a pinned authority, is `crates/verify/tests/a_version_1_stamp.rs`.

use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState, Stamp, Timescale, UnixNanos,
};
use timewitness_receipt::value::Value;
use timewitness_receipt::{
    cbor, open, sha256_payload, signature_of, with_signature_witness, AgentKey, PolicyRecord,
    Receipt, ReceiptError, TakenBy, SIGNATURE_WITNESS,
};

const MS: i128 = 1_000_000;
const NOW: i128 = 1_788_806_207 * 1_000 * MS;

/// A real RFC 3161 token, captured 2026-09-07 over thirty-two bytes of 0x5a. Genuine, signed, and
/// about something other than any signature in this file.
const A_TOKEN_ABOUT_SOMETHING_ELSE: &str = include_str!("data/sandwich/rfc3161.hex");

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

fn key() -> AgentKey {
    AgentKey::from_seed(&[41u8; 32])
}

fn stamp() -> Stamp {
    let source = |id: &str| SourceState {
        id: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        kept: true,
    };
    Stamp {
        reading: Reading {
            monotonic: MonotonicNanos(4_200_000_000),
            utc_estimate: UnixNanos(NOW),
        },
        bound: Bound {
            earliest: UnixNanos(NOW - 16 * MS),
            latest: UnixNanos(NOW + 16 * MS),
            basis: EpsilonBasis::LocalModelOnly,
            breakdown: BoundBreakdown {
                fusion: FusionRule::MarzulloThenInverseSquare {
                    offered: 4,
                    kept: 4,
                },
                intersection_half: 5 * MS,
                widest_source_network_half: 3 * MS,
                scheduling: 500_000,
                oscillator_holdover: 10 * MS,
                unclaimed_rate: 6_400_000,
                model_residual: 250_000,
                safety_margin: 250_000,
            },
        },
        sources: ["alpha", "bravo", "charlie", "delta"]
            .into_iter()
            .map(source)
            .collect(),
        generations: Generations { boot: 1, resume: 0 },
        since_last_sync: 64_000_000_000,
        frequency_ppm: None,
    }
}

fn receipt() -> Receipt {
    Receipt::from_stamp(
        &stamp(),
        1,
        None,
        sha256_payload(b"what is being stamped"),
        key().public_key_bytes(),
        PolicyRecord {
            max_bound_width: 250 * MS,
            min_sources: 3,
            min_operators: Some(4),
            max_holdover: Some(3_600 * 1_000 * MS),
            source_interval_floor: Some(100_000),
            frequency_slew_ppb_per_s: Some(1_000),
            frequency_span_ppb: Some(100_000),
        },
        TakenBy::OneShot,
    )
}

/// A signed receipt with its unprotected header replaced by `header`.
fn with_header(signed: &[u8], header: Vec<(Value, Value)>) -> Vec<u8> {
    let envelope = cbor::decode(signed).unwrap();
    let mut parts = envelope.as_array().unwrap().to_vec();
    let mut header = header;
    header.sort_by_cached_key(|(k, _)| cbor::encode(k));
    parts[1] = Value::Map(header);
    cbor::encode(&Value::Array(parts))
}

fn kid() -> (Value, Value) {
    (Value::Int(4), Value::Bytes(key().public_key_bytes()))
}

#[test]
fn a_receipt_with_no_witness_opens_and_is_reported_as_placing_only_its_subject() {
    let signed = key().sign(&receipt()).unwrap();
    let (_, report) =
        timewitness_receipt::open_with(&signed, &timewitness_receipt::TrustAnchors::none())
            .unwrap();
    assert_eq!(report.signature_witness, None);
    assert!(
        report
            .lines()
            .iter()
            .any(|l| l.contains("carries no witness")),
        "{:?}",
        report.lines()
    );
}

#[test]
fn putting_a_witness_in_changes_nothing_the_signature_covers() {
    let signed = key().sign(&receipt()).unwrap();
    let witnessed = with_signature_witness(&signed, &unhex(A_TOKEN_ABOUT_SOMETHING_ELSE)).unwrap();
    assert_eq!(
        signature_of(&witnessed).unwrap(),
        signature_of(&signed).unwrap()
    );
    let envelope = cbor::decode(&witnessed).unwrap();
    let header = &envelope.as_array().unwrap()[1];
    assert!(header.get(SIGNATURE_WITNESS).is_some());
}

#[test]
fn a_genuine_token_about_something_other_than_this_signature_is_refused() {
    // Real, signed by a real authority, and evidence for a different thing. Refused whatever keys
    // the reader holds, because it is in the token's own bytes that it is not about this signature.
    let signed = key().sign(&receipt()).unwrap();
    let witnessed = with_signature_witness(&signed, &unhex(A_TOKEN_ABOUT_SOMETHING_ELSE)).unwrap();
    let refusal = open(&witnessed).unwrap_err();
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "{refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("witness over this receipt's signature"),
        "{refusal}"
    );
}

#[test]
fn a_witness_that_is_not_a_token_is_refused() {
    let signed = key().sign(&receipt()).unwrap();
    let not_a_token = with_signature_witness(&signed, b"trust me").unwrap();
    assert!(open(&not_a_token).is_err());
    let not_bytes = with_header(
        &signed,
        vec![
            kid(),
            (Value::text(SIGNATURE_WITNESS), Value::text("trust me")),
        ],
    );
    assert!(matches!(open(&not_bytes), Err(ReceiptError::Signature(_))));
}

#[test]
fn a_second_witness_is_refused_rather_than_added() {
    let signed = key().sign(&receipt()).unwrap();
    let once = with_signature_witness(&signed, &unhex(A_TOKEN_ABOUT_SOMETHING_ELSE)).unwrap();
    assert!(with_signature_witness(&once, &unhex(A_TOKEN_ABOUT_SOMETHING_ELSE)).is_err());
}

#[test]
fn anything_else_in_a_version_1_header_is_still_a_second_spelling() {
    let signed = key().sign(&receipt()).unwrap();
    let padded = with_header(
        &signed,
        vec![kid(), (Value::text("note"), Value::Bytes(vec![0; 16]))],
    );
    assert!(matches!(open(&padded), Err(ReceiptError::Signature(_))));
}

#[test]
fn version_0_allows_no_witness_at_all() {
    let mut r = receipt();
    r.version = 0;
    r.claim.taken_by = None;
    r.claim.breakdown.unclaimed_rate = None;
    r.claim.policy.source_interval_floor = None;
    r.claim.policy.frequency_slew_ppb_per_s = None;
    r.claim.policy.frequency_span_ppb = None;
    let signed = key().sign(&r).unwrap();
    assert!(open(&signed).is_ok(), "the version 0 receipt itself opens");
    let witnessed = with_signature_witness(&signed, &unhex(A_TOKEN_ABOUT_SOMETHING_ELSE)).unwrap();
    assert!(matches!(open(&witnessed), Err(ReceiptError::Signature(_))));
}
