//! What receipt format v0 has to do.
//!
//! The tests that matter are the ones that build a dishonest receipt, sign it correctly, and check
//! that it is refused anyway. A receipt whose signature is wrong is an easy case. A receipt whose
//! signature is perfectly good and whose contents are a lie is the case this format exists for.

use timewitness_core::evidence::{drand, rfc3161, roughtime};
use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState, Stamp, Timescale, UnixNanos,
};
use timewitness_receipt::schema::Role;
use timewitness_receipt::value::Value;
use timewitness_receipt::{
    cbor, chain_link, open, sha256_payload, validate, AgentKey, Evidence, PolicyRecord, Receipt,
    ReceiptError, Scheme,
};

const MS: i128 = 1_000_000;
const NOW: i128 = 1_757_000_000_000_000_000;

fn key() -> AgentKey {
    AgentKey::from_seed(&[7u8; 32])
}

fn source(id: &str, kept: bool) -> SourceState {
    SourceState {
        id: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        kept,
    }
}

fn stamp() -> Stamp {
    Stamp {
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
                    offered: 5,
                    kept: 4,
                },
                intersection_half: 5 * MS,
                widest_source_network_half: 12 * MS,
                scheduling: 10_000,
                oscillator_holdover: 500_000,
                model_residual: 240_000,
                safety_margin: 250_000,
            },
        },
        sources: vec![
            source("alpha", true),
            source("bravo", true),
            source("charlie", true),
            source("delta", true),
            source("echo", false),
        ],
        generations: Generations { boot: 3, resume: 1 },
        since_last_sync: 64_000_000_000,
        frequency_ppm: Some(4.25),
    }
}

fn receipt() -> Receipt {
    Receipt::from_stamp(
        &stamp(),
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

// The three fixtures below carry blobs packed the way each scheme stores one, holding bytes that
// verify under nothing. That is deliberate and it is what these tests are about: the roles, the
// basis and the format, with no cryptography anywhere. Before 2026-09-08 the blobs were plain runs
// of one byte, and that day a blob that is not the shape its scheme stores became a refusal in its
// own right, which those runs of bytes are.
fn roughtime_entry() -> Evidence {
    Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("roughtime"),
        at: UnixNanos(NOW - MS),
        radius: Some(3 * MS),
        blob: roughtime::pack_blob(&[], &[], &[0xa1; 96]),
        nonce: Some(vec![0x5a; 32]),
        detail: Some("a public Roughtime server".to_string()),
    }
}

fn beacon_entry() -> Evidence {
    Evidence {
        role: Role::NotEarlierThan,
        scheme: Scheme::new("drand"),
        at: UnixNanos(NOW - 30 * MS),
        radius: None,
        blob: drand::pack_blob(&[0xb2; 32], 4_210_987, &[0xb2; 96]),
        nonce: None,
        detail: Some("round 4210987".to_string()),
    }
}

fn witness_entry() -> Evidence {
    Evidence {
        role: Role::NotLaterThan,
        scheme: Scheme::new("rfc3161"),
        at: UnixNanos(NOW + 40 * MS),
        radius: None,
        blob: rfc3161::pack_blob(&[0xc3; 64], &[0xc3; 128]),
        nonce: None,
        detail: Some("a public timestamp authority".to_string()),
    }
}

// ---------------------------------------------------------------------------
// The happy path, which has to work before anything else means anything
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_round_trips_through_the_wire_format() {
    let r = receipt();
    let signed = key().sign(&r).unwrap();
    let back = open(&signed).unwrap();
    assert_eq!(back, r);
}

#[test]
fn a_receipt_carrying_all_three_kinds_of_evidence_is_accepted_as_our_own_claim() {
    // The three entries are carried, checked against the interval and kept. What is not granted is
    // the basis: a third-party sandwich means the interval is pinned between signatures a stranger
    // can check, nothing in this tree can check one yet, and a validator does not bless a claim it
    // cannot test. That arrives with the evidence clients.
    let mut r = receipt();
    r.evidence = vec![roughtime_entry(), beacon_entry(), witness_entry()];

    let signed = key().sign(&r).unwrap();
    let back = open(&signed).unwrap();
    assert_eq!(back.evidence.len(), 3);
    assert_eq!(back.claim.basis, EpsilonBasis::LocalModelOnly);
}

#[test]
fn the_same_receipt_calling_itself_a_sandwich_is_refused() {
    let mut r = receipt();
    r.claim.basis = EpsilonBasis::ThirdPartySandwich;
    r.evidence = vec![roughtime_entry(), beacon_entry(), witness_entry()];

    let signed = key().sign(&r).unwrap();
    let refusal = open(&signed).expect_err("nothing here can verify a signed response yet");
    assert!(
        matches!(refusal, ReceiptError::OurClaimAsEvidence(_)),
        "got {refusal}"
    );
}

#[test]
fn the_same_receipt_always_produces_the_same_bytes() {
    let r = receipt();
    assert_eq!(key().sign(&r).unwrap(), key().sign(&r).unwrap());
}

#[test]
fn the_format_carries_its_own_version_number() {
    let signed = key().sign(&receipt()).unwrap();
    let envelope = cbor::decode(&signed).unwrap();
    let payload = envelope.as_array().unwrap()[2].as_bytes().unwrap();
    let body = cbor::decode(payload).unwrap();
    assert_eq!(body.get("v").and_then(Value::as_int), Some(0));
}

#[test]
fn a_receipt_altered_by_one_byte_is_refused() {
    let signed = key().sign(&receipt()).unwrap();
    for position in [10usize, 40, 120, signed.len() - 70] {
        let mut altered = signed.clone();
        altered[position] ^= 0x01;
        assert!(
            open(&altered).is_err(),
            "a receipt altered at byte {position} was accepted"
        );
    }
}

#[test]
fn a_receipt_signed_by_a_different_key_is_refused() {
    let other = AgentKey::from_seed(&[9u8; 32]);
    let r = receipt();
    // The receipt names our key and the signature is somebody else's.
    let signed = other.sign_value(&r.to_value());
    match open(&signed) {
        Err(ReceiptError::Signature(_)) => {}
        other => panic!("expected a signature refusal and got {other:?}"),
    }
}

#[test]
fn receipts_chain_by_the_hash_of_the_one_before() {
    let first = key().sign(&receipt()).unwrap();
    let link = chain_link(&first);

    let mut second = receipt();
    second.sequence = 2;
    second.chain_previous = Some(link.clone());

    let signed = key().sign(&second).unwrap();
    let back = open(&signed).unwrap();
    assert_eq!(back.sequence, 2);
    assert_eq!(back.chain_previous, Some(link));
}

// ---------------------------------------------------------------------------
// Our own word is never third-party evidence, as a set of refusals
// ---------------------------------------------------------------------------

#[test]
fn a_mislabelled_evidence_role_fails_validation() {
    // A timestamp authority's token, which proves not-later-than, placed in the field that claims
    // not-earlier-than. This is the case the format was written to refuse, and it is the shape of
    // receipt a careless implementation would produce without meaning anything by it.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::NotEarlierThan,
        ..witness_entry()
    }];

    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::MislabelledEvidence { role, scheme, why }) => {
            assert_eq!(role, "not-earlier-than");
            assert_eq!(scheme, "rfc3161");
            assert!(why.contains("not-later-than"));
        }
        other => panic!("expected a mislabelling refusal and got {other:?}"),
    }
}

#[test]
fn a_beacon_in_the_corridor_field_fails_validation() {
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::AuthenticatedUtcCorridor,
        ..beacon_entry()
    }];
    let signed = key().sign(&r).unwrap();
    assert!(matches!(
        open(&signed),
        Err(ReceiptError::MislabelledEvidence { .. })
    ));
}

#[test]
fn network_time_security_is_refused_as_evidence_by_name() {
    // The one that bites this design, and the reason it is written into the validator rather than
    // into a document. NTS authenticates packets with a symmetric key the client also holds, so a
    // client could forge a response to itself and a stranger has no signature to check.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("nts"),
        ..roughtime_entry()
    }];

    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::OurClaimAsEvidence(why)) => {
            assert!(why.contains("nts"));
            assert!(why.contains("key we also hold"));
        }
        other => panic!("expected NTS to be refused as evidence and got {other:?}"),
    }
}

#[test]
fn our_own_bound_placed_in_an_evidence_slot_is_refused() {
    // Built by hand, because the typed form will not construct it. The agent's own claim, with a
    // role stuck on the front, sitting in the evidence list.
    let mut value = receipt().to_value();
    let claim = value.get("claim").unwrap().clone();

    let Value::Map(mut claim_pairs) = claim else {
        panic!("the claim is a map")
    };
    claim_pairs.push((
        Value::text("role"),
        Value::text("authenticated-utc-corridor"),
    ));

    let Value::Map(pairs) = &mut value else {
        panic!("a receipt is a map")
    };
    for (k, v) in pairs.iter_mut() {
        if k.as_text() == Some("evidence") {
            *v = Value::Array(vec![Value::Map(claim_pairs.clone())]);
        }
    }

    let signed = key().sign_value(&value);
    match open(&signed) {
        Err(ReceiptError::OurClaimAsEvidence(why)) => {
            assert!(why.contains("agent-bound"));
        }
        other => panic!("expected our own claim in an evidence slot to be refused, got {other:?}"),
    }
}

#[test]
fn a_claim_dressed_up_as_evidence_is_refused() {
    // The other direction: a role field stuck onto the agent's own claim, where it does not belong.
    let mut value = receipt().to_value();
    let Value::Map(pairs) = &mut value else {
        panic!("a receipt is a map")
    };
    for (k, v) in pairs.iter_mut() {
        if k.as_text() == Some("claim") {
            let Value::Map(claim_pairs) = v else {
                panic!("the claim is a map")
            };
            claim_pairs.push((Value::text("role"), Value::text("not-later-than")));
        }
    }

    let signed = key().sign_value(&value);
    match open(&signed) {
        Err(ReceiptError::OurClaimAsEvidence(why)) => assert!(why.contains("role")),
        other => panic!("expected a refusal and got {other:?}"),
    }
}

#[test]
fn an_evidence_entry_carrying_the_bounds_own_fields_is_refused() {
    let mut value = receipt().to_value();
    let Value::Map(pairs) = &mut value else {
        panic!("a receipt is a map")
    };
    for (k, v) in pairs.iter_mut() {
        if k.as_text() == Some("evidence") {
            *v = Value::Array(vec![Value::map([
                ("role", Value::text("not-later-than")),
                ("scheme", Value::text("rfc3161")),
                ("at_ns", Value::Int(NOW)),
                ("blob", Value::Bytes(vec![1, 2, 3])),
                ("earliest_ns", Value::Int(NOW - MS)),
                ("latest_ns", Value::Int(NOW + MS)),
            ])]);
        }
    }
    let signed = key().sign_value(&value);
    assert!(matches!(
        open(&signed),
        Err(ReceiptError::OurClaimAsEvidence(_))
    ));
}

#[test]
fn a_sandwich_claimed_without_the_three_pieces_is_refused() {
    let mut r = receipt();
    r.claim.basis = EpsilonBasis::ThirdPartySandwich;
    r.evidence = vec![roughtime_entry()];

    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::OurClaimAsEvidence(why)) => {
            assert!(why.contains("not-later-than: false"));
        }
        other => panic!("expected a refusal and got {other:?}"),
    }
}

#[test]
fn a_corridor_entry_with_no_nonce_is_refused() {
    // Without a nonce we generated, a signed response could have been made for somebody else at
    // some other time and replayed into our receipt.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        nonce: None,
        ..roughtime_entry()
    }];
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Field(_))));
}

#[test]
fn an_unknown_scheme_proves_nothing_rather_than_being_assumed_honest() {
    let mut r = receipt();
    r.evidence = vec![Evidence {
        scheme: Scheme::new("some-new-thing"),
        ..witness_entry()
    }];
    let signed = key().sign(&r).unwrap();
    assert!(matches!(
        open(&signed),
        Err(ReceiptError::MislabelledEvidence { .. })
    ));
}

// ---------------------------------------------------------------------------
// A receipt has to agree with itself
// ---------------------------------------------------------------------------

#[test]
fn a_reading_outside_its_own_interval_is_refused() {
    let mut r = receipt();
    r.utc_estimate = UnixNanos(NOW + 100 * MS);
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn an_interval_whose_ends_are_the_wrong_way_round_is_refused() {
    let mut r = receipt();
    r.claim.earliest = UnixNanos(NOW + 10 * MS);
    r.claim.latest = UnixNanos(NOW - 10 * MS);
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn a_width_the_stated_parts_do_not_support_is_refused() {
    // The interval is widened without the breakdown being changed, so the receipt is claiming a
    // width it cannot account for.
    let mut r = receipt();
    r.claim.earliest = UnixNanos(NOW - 200 * MS);
    r.claim.latest = UnixNanos(NOW + 200 * MS);
    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::Inconsistent(why)) => assert!(why.contains("parts of the bound")),
        other => panic!("expected a refusal and got {other:?}"),
    }
}

#[test]
fn a_receipt_that_kept_no_majority_is_refused() {
    let mut r = receipt();
    r.claim.sources_kept = 2;
    for (i, s) in r.claim.sources.iter_mut().enumerate() {
        s.kept = i < 2;
    }
    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::Inconsistent(why)) => assert!(why.contains("majority")),
        other => panic!("expected a refusal and got {other:?}"),
    }
}

#[test]
fn a_source_count_that_does_not_match_the_list_is_refused() {
    let mut r = receipt();
    r.claim.sources_offered = 9;
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn a_beacon_published_after_the_latest_possible_reading_is_refused() {
    let mut r = receipt();
    r.evidence = vec![Evidence {
        at: UnixNanos(NOW + 500 * MS),
        ..beacon_entry()
    }];
    let signed = key().sign(&r).unwrap();
    match open(&signed) {
        Err(ReceiptError::Inconsistent(why)) => assert!(why.contains("not-earlier-than")),
        other => panic!("expected a refusal and got {other:?}"),
    }
}

#[test]
fn a_witness_dated_before_the_earliest_possible_reading_is_refused() {
    let mut r = receipt();
    r.evidence = vec![Evidence {
        at: UnixNanos(NOW - 500 * MS),
        ..witness_entry()
    }];
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn a_payload_hash_of_the_wrong_length_is_refused() {
    let mut r = receipt();
    r.payload.hash.truncate(20);
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn an_unknown_hash_algorithm_is_refused_rather_than_trusted() {
    let mut r = receipt();
    r.payload.algorithm = "something-else".to_string();
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Field(_))));
}

#[test]
fn a_chain_link_of_the_wrong_length_is_refused() {
    let mut r = receipt();
    r.chain_previous = Some(vec![0u8; 16]);
    let signed = key().sign(&r).unwrap();
    assert!(matches!(open(&signed), Err(ReceiptError::Inconsistent(_))));
}

#[test]
fn a_later_version_is_refused_rather_than_read_as_this_one() {
    let mut value = receipt().to_value();
    let Value::Map(pairs) = &mut value else {
        panic!("a receipt is a map")
    };
    for (k, v) in pairs.iter_mut() {
        if k.as_text() == Some("v") {
            *v = Value::Int(1);
        }
    }
    let signed = key().sign_value(&value);
    assert!(matches!(
        open(&signed),
        Err(ReceiptError::UnknownVersion(1))
    ));
}

// ---------------------------------------------------------------------------
// The human view, and the fields a later change needs
// ---------------------------------------------------------------------------

#[test]
fn the_human_view_says_the_midpoint_is_for_display_only() {
    let rendered = receipt().to_value().to_string();
    assert!(rendered.contains("\"midpoint_display_only\": true"));
    assert!(rendered.contains("\"kind\": \"agent-bound\""));
    assert!(rendered.contains("\"basis\": \"local-model-only\""));
}

#[test]
fn the_receipt_carries_the_fields_the_environment_faults_row_will_need() {
    let r = receipt();
    let v = r.to_value();
    let claim = v.get("claim").unwrap();

    assert_eq!(
        claim.get("boot_generation").and_then(Value::as_int),
        Some(3)
    );
    assert_eq!(
        claim.get("resume_generation").and_then(Value::as_int),
        Some(1)
    );

    let sources = claim.get("sources").and_then(Value::as_array).unwrap();
    assert_eq!(sources.len(), 5);
    for s in sources {
        assert!(s.has("smear"));
        assert!(s.has("timescale"));
        assert!(s.has("leap"));
    }

    let policy = claim.get("policy").unwrap();
    assert!(policy.has("max_bound_width_ns"));
    assert!(policy.has("min_sources"));
}

#[test]
fn a_receipt_reports_its_own_bound_and_never_reconstructs_one() {
    let r = receipt();
    let back = r.as_stamp();
    assert_eq!(back.bound.earliest, r.claim.earliest);
    assert_eq!(back.bound.latest, r.claim.latest);
    assert_eq!(back.bound.basis, EpsilonBasis::LocalModelOnly);
    let rate = back
        .frequency_ppm
        .expect("a non-zero frequency_ppb reads back as a claimed rate");
    assert!((rate - 4.25).abs() < 1e-9);
}

#[test]
fn validating_a_receipt_directly_gives_the_same_answer_as_opening_one() {
    let mut r = receipt();
    assert!(validate(&r).is_ok());
    r.evidence = vec![Evidence {
        role: Role::NotEarlierThan,
        ..witness_entry()
    }];
    assert!(validate(&r).is_err());
}
