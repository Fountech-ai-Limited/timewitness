//! What version 1 of the receipt format adds, and what a reader does with each part of it.
//!
//! Version 1 carries the terms that set a receipt's width, the part of the holdover that covers a
//! rate the agent is not correcting for, and which path the reading came by. It refuses a source
//! kind it does not know and a field it does not define, where version 0 read past both. Version 0
//! reads exactly as it did, and `a_version_1_receipt_opens.rs` holds the committed version 0
//! receipt to that byte for byte.

use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState, Stamp, Timescale, UnixNanos,
};
use timewitness_receipt::value::Value;
use timewitness_receipt::{
    cbor, open, sha256_payload, AgentKey, PolicyRecord, Receipt, ReceiptError, TakenBy,
    FORMAT_VERSION, READS,
};

const MS: i128 = 1_000_000;
const NOW: i128 = 1_788_806_207 * 1_000 * MS;

fn key() -> AgentKey {
    AgentKey::from_seed(&[21u8; 32])
}

fn source(id: &str) -> SourceState {
    SourceState {
        id: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        kept: true,
    }
}

/// A stamp from a model that has not fitted a rate, so part of its holdover is unclaimed.
fn stamp() -> Stamp {
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

fn policy() -> PolicyRecord {
    PolicyRecord {
        max_bound_width: 250 * MS,
        min_sources: 3,
        min_operators: Some(4),
        max_holdover: Some(3_600 * 1_000 * MS),
        source_interval_floor: Some(100_000),
        frequency_slew_ppb_per_s: Some(1_000),
        frequency_span_ppb: Some(100_000),
    }
}

fn receipt(taken_by: TakenBy) -> Receipt {
    Receipt::from_stamp(
        &stamp(),
        1,
        None,
        sha256_payload(b"what is being stamped"),
        key().public_key_bytes(),
        policy(),
        taken_by,
    )
}

/// The receipt's body as a value, changed by `change`, signed as it stands.
fn signed_with(change: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let mut body = receipt(TakenBy::OneShot).to_value();
    let Value::Map(pairs) = &mut body else {
        panic!("a receipt is a map")
    };
    change(pairs);
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    key().sign_value(&body)
}

/// Change one entry of a nested map, at the path given, leaving everything else alone.
fn at_path(
    pairs: &mut Vec<(Value, Value)>,
    path: &[&str],
    change: impl FnOnce(&mut Vec<(Value, Value)>),
) {
    if path.is_empty() {
        change(pairs);
        pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
        return;
    }
    for (k, v) in pairs.iter_mut() {
        if k.as_text() == Some(path[0]) {
            let Value::Map(inner) = v else {
                panic!("{} is a map", path[0])
            };
            at_path(inner, &path[1..], change);
            return;
        }
    }
    panic!("there is no {}", path[0]);
}

fn without(path: &[&str], field: &str) -> Vec<u8> {
    let field = field.to_string();
    signed_with(|pairs| {
        at_path(pairs, path, |inner| {
            let before = inner.len();
            inner.retain(|(k, _)| k.as_text() != Some(field.as_str()));
            assert_eq!(inner.len() + 1, before, "{field} was there to take out");
        });
    })
}

fn with(path: &[&str], field: &str, value: Value) -> Vec<u8> {
    let field = field.to_string();
    signed_with(|pairs| {
        at_path(pairs, path, |inner| {
            inner.retain(|(k, _)| k.as_text() != Some(field.as_str()));
            inner.push((Value::Text(field), value));
        });
    })
}

// ---------------------------------------------------------------------------
// What this code writes and what it reads
// ---------------------------------------------------------------------------

#[test]
fn this_code_writes_version_1_and_reads_0_and_1() {
    assert_eq!(FORMAT_VERSION, 1);
    assert_eq!(READS, [0, 1]);
    let opened = open(&key().sign(&receipt(TakenBy::OneShot)).unwrap()).unwrap();
    assert_eq!(opened.version, 1);
}

#[test]
fn every_field_version_1_adds_reads_back_as_it_was_written() {
    for taken_by in [TakenBy::OneShot, TakenBy::ResidentAgent] {
        let opened = open(&key().sign(&receipt(taken_by)).unwrap()).unwrap();
        assert_eq!(opened.claim.taken_by, Some(taken_by));
        assert_eq!(opened.claim.breakdown.unclaimed_rate, Some(6_400_000));
        assert_eq!(opened.claim.policy, policy());
    }
}

#[test]
fn a_version_after_the_newest_this_code_reads_is_refused_and_named() {
    let signed = with(&[], "v", Value::Int(2));
    let refusal = open(&signed).unwrap_err();
    assert!(
        matches!(refusal, ReceiptError::UnknownVersion(2)),
        "{refusal}"
    );
    let said = refusal.to_string();
    assert!(
        said.contains("version 2") && said.contains("versions 0 and 1"),
        "{said}"
    );
}

// ---------------------------------------------------------------------------
// Every field version 1 requires is required
// ---------------------------------------------------------------------------

#[test]
fn a_version_1_receipt_missing_any_field_it_requires_is_refused() {
    for (path, field) in [
        (&["claim"][..], "taken_by"),
        (&["claim", "breakdown"][..], "unclaimed_rate_ns"),
        (&["claim", "policy"][..], "source_interval_floor_ns"),
        (&["claim", "policy"][..], "frequency_slew_ppb_per_s"),
        (&["claim", "policy"][..], "frequency_span_ppb"),
        (&["claim", "policy"][..], "max_holdover_ns"),
        (&["claim", "policy"][..], "min_operators"),
    ] {
        let refusal = open(&without(path, field)).unwrap_err();
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "a version 1 receipt without {field} gave {refusal}"
        );
    }
}

#[test]
fn a_signer_will_not_sign_a_version_1_receipt_with_a_field_missing() {
    let mut r = receipt(TakenBy::OneShot);
    r.claim.policy.frequency_span_ppb = None;
    assert!(key().sign(&r).is_err());
    let mut r = receipt(TakenBy::OneShot);
    r.claim.taken_by = None;
    assert!(key().sign(&r).is_err());
}

#[test]
fn a_version_1_receipt_carrying_a_field_the_format_does_not_define_is_refused() {
    for path in [&[][..], &["claim"][..], &["claim", "policy"][..]] {
        let refusal = open(&with(path, "note", Value::Text("trust me".into()))).unwrap_err();
        assert!(matches!(refusal, ReceiptError::Field(_)), "{refusal}");
    }
}

#[test]
fn a_version_0_receipt_carrying_the_same_field_reads_as_version_0_always_has() {
    let mut r = receipt(TakenBy::OneShot);
    r.version = 0;
    r.claim.taken_by = None;
    r.claim.breakdown.unclaimed_rate = None;
    r.claim.policy.source_interval_floor = None;
    r.claim.policy.frequency_slew_ppb_per_s = None;
    r.claim.policy.frequency_span_ppb = None;
    let mut body = r.to_value();
    let Value::Map(pairs) = &mut body else {
        panic!("a receipt is a map")
    };
    pairs.push((Value::Text("note".into()), Value::Text("trust me".into())));
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    let opened = open(&key().sign_value(&body)).expect("version 0 never moves");
    assert_eq!(opened.version, 0);
    assert_eq!(opened.claim.taken_by, None);
}

#[test]
fn a_path_this_format_does_not_know_is_refused() {
    let refusal = open(&with(
        &["claim"],
        "taken_by",
        Value::Text("somebody".into()),
    ))
    .unwrap_err();
    assert!(refusal.to_string().contains("one-shot"), "{refusal}");
}

// ---------------------------------------------------------------------------
// The unclaimed part of the holdover
// ---------------------------------------------------------------------------

#[test]
fn an_unclaimed_part_larger_than_the_holdover_is_refused() {
    let signed = with(
        &["claim", "breakdown"],
        "unclaimed_rate_ns",
        Value::Int(10 * MS + 1),
    );
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn an_unclaimed_part_beside_a_claimed_rate_is_refused() {
    let signed = with(&["claim"], "frequency_ppb", Value::Int(4_250));
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn a_negative_unclaimed_part_is_refused() {
    let signed = with(&["claim", "breakdown"], "unclaimed_rate_ns", Value::Int(-1));
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn the_whole_holdover_may_be_unclaimed() {
    let signed = with(
        &["claim", "breakdown"],
        "unclaimed_rate_ns",
        Value::Int(10 * MS),
    );
    assert!(open(&signed).is_ok());
}

// ---------------------------------------------------------------------------
// The width terms
// ---------------------------------------------------------------------------

#[test]
fn a_band_of_nought_is_refused_as_unset() {
    for span in [0, -1] {
        let signed = with(&["claim", "policy"], "frequency_span_ppb", Value::Int(span));
        assert!(
            matches!(open(&signed), Err(ReceiptError::Inconsistent(_))),
            "{span}"
        );
    }
}

#[test]
fn a_negative_floor_or_slew_is_refused() {
    for field in ["source_interval_floor_ns", "frequency_slew_ppb_per_s"] {
        let signed = with(&["claim", "policy"], field, Value::Int(-1));
        assert!(
            matches!(open(&signed), Err(ReceiptError::Inconsistent(_))),
            "{field}"
        );
    }
}

#[test]
fn a_policy_rate_is_carried_in_whole_parts_per_billion() {
    assert_eq!(timewitness_receipt::ppm_as_ppb(1.0), 1_000);
    assert_eq!(timewitness_receipt::ppm_as_ppb(100.0), 100_000);
    assert_eq!(timewitness_receipt::ppm_as_ppb(0.0004), 0);
    assert_eq!(timewitness_receipt::ppm_as_ppb(0.0005), 1);
}

// ---------------------------------------------------------------------------
// A source kind nobody taught this format
// ---------------------------------------------------------------------------

fn with_a_source_kind(version: i128, kind: &str) -> Vec<u8> {
    let mut r = receipt(TakenBy::OneShot);
    r.claim.sources[0].kind = kind.to_string();
    if version == 0 {
        r.version = 0;
        r.claim.taken_by = None;
        r.claim.breakdown.unclaimed_rate = None;
        r.claim.policy.source_interval_floor = None;
        r.claim.policy.frequency_slew_ppb_per_s = None;
        r.claim.policy.frequency_span_ppb = None;
    }
    key().sign(&r).unwrap()
}

#[test]
fn version_1_refuses_a_source_kind_it_does_not_know() {
    let refusal = open(&with_a_source_kind(1, "gnss-disciplined")).unwrap_err();
    assert!(matches!(refusal, ReceiptError::Field(_)), "{refusal}");
    assert!(
        refusal.to_string().contains("gnss-disciplined"),
        "{refusal}"
    );
}

#[test]
fn version_0_reads_the_same_kind_as_it_always_has() {
    assert!(open(&with_a_source_kind(0, "gnss-disciplined")).is_ok());
}

#[test]
fn every_kind_this_product_polls_is_one_version_1_knows() {
    for kind in ["ntp", "nts", "roughtime", "local-hardware"] {
        assert!(open(&with_a_source_kind(1, kind)).is_ok(), "{kind}");
    }
}
