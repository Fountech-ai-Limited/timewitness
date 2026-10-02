//! A signed receipt is one byte string, or it is not evidence of order.
//!
//! The COSE unprotected header sits outside the signature, which is RFC 9052 behaving correctly.
//! The consequence, followed through, is that any holder of a receipt could restate it as different
//! bytes carrying the same claim and verifying identically. The chain link is the SHA-256 of those
//! bytes, so a holder could break, fork or bloat a chain without ever holding the agent's key, and
//! half of what this product claims is unbroken order.
//!
//! Each restatement below was watched being accepted before the rule that now refuses it.
//!
//! The rule chosen is that the unprotected header is exactly one entry, the key identifier, and its
//! value is the key inside the signature. Everything else in the envelope is either signed or is
//! canonical CBOR the decoder re-encodes and compares, so with that entry pinned a valid receipt has
//! exactly one spelling and the link over the file is a link over something nobody can restate. The
//! alternative was to take the link over the `Sig_structure`, which the signature genuinely covers.
//! It was not chosen because the link would then be a quantity that is not the file: two people
//! holding the same receipt could not compare `sha256sum` output, and the padding and the bit flips
//! would still be accepted.

use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState, Stamp, Timescale, UnixNanos,
};
use timewitness_receipt::{
    cbor, chain_link, open, sha256_payload, AgentKey, PolicyRecord, Receipt, ReceiptError, Value,
    MAX_ENCODED_BYTES,
};

const MS: i128 = 1_000_000;
const NOW: i128 = 1_757_000_000_000_000_000;
/// The COSE label for a key identifier.
const KID: i128 = 4;

fn key() -> AgentKey {
    AgentKey::from_seed(&[7u8; 32])
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

fn receipt() -> Receipt {
    let stamp = Stamp {
        reading: Reading {
            monotonic: MonotonicNanos(4_200_000_000),
            utc_estimate: UnixNanos(NOW),
        },
        bound: Bound {
            earliest: UnixNanos(NOW - 6 * MS),
            latest: UnixNanos(NOW + 6 * MS),
            basis: EpsilonBasis::LocalModelOnly,
            breakdown: BoundBreakdown {
                fusion: FusionRule::MarzulloThenInverseSquare {
                    offered: 3,
                    kept: 3,
                },
                intersection_half: 5 * MS,
                widest_source_network_half: 12 * MS,
                scheduling: 10_000,
                oscillator_holdover: 500_000,
                model_residual: 240_000,
                safety_margin: 250_000,
            },
        },
        sources: vec![source("alpha"), source("bravo"), source("charlie")],
        generations: Generations { boot: 3, resume: 1 },
        since_last_sync: 64_000_000_000,
        frequency_ppm: Some(4.25),
    };
    Receipt::from_stamp(
        &stamp,
        1,
        None,
        sha256_payload(b"the artefact being stamped"),
        key().public_key_bytes(),
        PolicyRecord {
            max_bound_width: 250 * MS,
            min_sources: 3,
            min_operators: Some(3),
            max_holdover: Some(3_600 * MS * 1_000),
        },
    )
}

/// One correctly signed receipt, and the four parts of its envelope taken apart.
fn parts() -> Vec<Value> {
    let signed = key().sign(&receipt()).unwrap();
    cbor::decode(&signed)
        .unwrap()
        .as_array()
        .expect("a signed receipt is a list of four things")
        .to_vec()
}

/// Put an envelope back together with a different unprotected header.
fn restated(unprotected: Value) -> Vec<u8> {
    let p = parts();
    cbor::encode(&Value::Array(vec![
        p[0].clone(),
        unprotected,
        p[2].clone(),
        p[3].clone(),
    ]))
}

fn refusal(bytes: &[u8]) -> ReceiptError {
    open(bytes).expect_err("this receipt is a restatement and is not the one that was signed")
}

#[test]
fn the_receipt_as_signed_is_accepted_and_is_the_one_spelling() {
    let signed = key().sign(&receipt()).unwrap();
    let back = open(&signed).expect("the receipt as its agent signed it");
    assert_eq!(back.sequence, 1);

    // Every part of the envelope decodes and re-encodes to the bytes it came from, so there is
    // nothing left in it a holder is free to spell a second way.
    assert_eq!(cbor::encode(&cbor::decode(&signed).unwrap()), signed);
}

#[test]
fn the_key_identifier_removed_is_refused() {
    // Accepted before this rule, at 851 bytes rather than 886, with the same claim and a different
    // chain link. The header is not signed, so nothing about the signature noticed.
    let bytes = restated(Value::Map(Vec::new()));
    assert!(bytes.len() < key().sign(&receipt()).unwrap().len());
    let refusal = refusal(&bytes);
    assert!(
        format!("{refusal}").contains("unprotected header"),
        "got {refusal}"
    );
}

#[test]
fn the_key_identifier_relabelled_is_refused() {
    // Same length, same claim, different bytes, different link. Six of the 7,088 single-bit
    // variants of a receipt were accepted and every one of them sat on this label.
    let p = parts();
    let kid = p[1]
        .as_map_get_bytes(KID)
        .expect("the signed envelope names the key");
    let bytes = restated(Value::Map(vec![(Value::Int(5), Value::Bytes(kid))]));
    let refusal = refusal(&bytes);
    assert!(
        format!("{refusal}").contains("unprotected header"),
        "got {refusal}"
    );
}

#[test]
fn a_label_nobody_reads_carrying_a_megabyte_is_refused() {
    let p = parts();
    let kid = p[1]
        .as_map_get_bytes(KID)
        .expect("the signed envelope names the key");
    let bytes = restated(Value::Map(vec![
        (Value::Int(KID), Value::Bytes(kid)),
        (Value::Int(9), Value::Bytes(vec![0x41; 1_000_000])),
    ]));
    assert!(bytes.len() > 1_000_000);

    // Refused twice over, and the size check is the one that fires, because a reader must not have
    // to parse a megabyte to find out it is a megabyte.
    let refusal = refusal(&bytes);
    assert!(format!("{refusal}").contains("bytes"), "got {refusal}");
}

#[test]
fn a_receipt_over_the_format_ceiling_is_refused_before_it_is_parsed() {
    let mut bytes = key().sign(&receipt()).unwrap();
    bytes.resize(MAX_ENCODED_BYTES + 1, 0);
    let refusal = refusal(&bytes);
    assert!(
        format!("{refusal}").contains(&MAX_ENCODED_BYTES.to_string()),
        "got {refusal}"
    );
}

#[test]
fn no_holder_can_produce_two_accepted_receipts_with_the_same_claim_and_different_links() {
    let signed = key().sign(&receipt()).unwrap();
    let original = chain_link(&signed);

    // Every restatement anybody has managed to build, and each has to be refused rather than
    // accepted with a link of its own.
    let p = parts();
    let kid = p[1].as_map_get_bytes(KID).unwrap();
    let attempts = vec![
        restated(Value::Map(Vec::new())),
        restated(Value::Map(vec![(Value::Int(5), Value::Bytes(kid.clone()))])),
        restated(Value::Map(vec![
            (Value::Int(KID), Value::Bytes(kid.clone())),
            (Value::Int(9), Value::Bytes(vec![0x41; 64])),
        ])),
        restated(Value::Map(vec![(
            Value::Int(KID),
            Value::Bytes(vec![0u8; 32]),
        )])),
    ];

    for attempt in attempts {
        assert_ne!(
            chain_link(&attempt),
            original,
            "this restatement has a link of its own, which is why it must not be accepted"
        );
        assert!(
            open(&attempt).is_err(),
            "a restatement was accepted, so a holder can fork a chain without the agent's key"
        );
    }
}

/// Reach into a decoded map for a byte string under an integer label.
trait MapGetBytes {
    fn as_map_get_bytes(&self, key: i128) -> Option<Vec<u8>>;
}

impl MapGetBytes for Value {
    fn as_map_get_bytes(&self, key: i128) -> Option<Vec<u8>> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Int(i) if *i == key))
                .and_then(|(_, v)| v.as_bytes().map(<[u8]>::to_vec)),
            _ => None,
        }
    }
}
