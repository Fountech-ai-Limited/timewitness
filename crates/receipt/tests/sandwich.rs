//! A bound that really does rest on three outside signatures, and every way of failing to.
//!
//! This is the file where the rule that our own word is never third-party evidence stops being
//! prose. Until the evidence clients existed, a receipt claiming its bound rested on third-party
//! evidence was refused outright, because nothing could verify a signed response and three entries
//! carrying the right words were being read as proof of cryptography. What replaced that refusal is
//! a precondition, and this file is what says the precondition is real: it builds a receipt out of
//! three signatures captured from three unrelated parties within four seconds of each other, and
//! then takes it apart one way at a time.
//!
//! The precondition has five parts and the fifth is the one about the width. Two signatures four
//! seconds apart say the moment was inside those four seconds and nothing about where, so a receipt
//! resting on them claims the whole four seconds. The tests at the foot of this file hold that: a
//! narrower claim, and a claim as wide as the bracket and shifted off it, are both our own model
//! placed where evidence goes.
//!
//! Everything here runs offline. Every signature in it was made by somebody who has never heard of
//! this product.

use timewitness_core::evidence::drand::{self, Chain};
use timewitness_core::evidence::rfc3161::Authority;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::report::Outcome;
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Evidence, Payload, PolicyRecord, Receipt, Role, Scheme,
    SourceRecord,
};
use timewitness_receipt::validate::{validate, validate_with, SANDWICH_WIDTH_CEILING};
use timewitness_receipt::ReceiptError;

const DRAND: &str = include_str!("data/sandwich/drand.hex");
const ROUGHTIME: &str = include_str!("data/sandwich/roughtime.hex");
const RFC3161: &str = include_str!("data/sandwich/rfc3161.hex");
/// The nonces inside those two captures. A receipt carrying one of these blobs has to print the
/// same value beside it, so they are kept with the captures rather than restated here.
const CORRIDOR_NONCE: &str = include_str!("data/sandwich/roughtime-nonce.hex");
const WITNESS_NONCE: &str = include_str!("data/sandwich/rfc3161-nonce.hex");

/// The subject all three are about, standing in for the hash of what is being stamped.
const SUBJECT: [u8; 32] = [0x5au8; 32];

/// What each of the three states, read off the capture.
const BEACON_AT: Nanos = 1_788_806_205 * NANOS_PER_SEC;
const CORRIDOR_AT: Nanos = 1_788_806_207 * NANOS_PER_SEC;
const CORRIDOR_RADIUS: Nanos = NANOS_PER_SEC;
/// The witness's edge is the second it named and not the instant.
///
/// The token writes its time to whole seconds, so it names the second beginning at
/// 1_788_806_208 and says nothing about where inside it the authority was. The edge a receipt may
/// print beside that signature is therefore the end of that second, and this constant moved by
/// exactly one second on 2026-09-09 when the comparison started saying so. Taking the start of the
/// second for the edge is what refused a real receipt in the Action, once the agent's own bound
/// came down to about 240 ms.
const WITNESS_AT: Nanos = 1_788_806_208 * NANOS_PER_SEC + NANOS_PER_SEC;

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

/// The published long-term key of roughtime.se, the server the corridor capture asked.
const ROUGHTIME_SE_KEY: [u8; 32] = [
    0x4b, 0x70, 0x33, 0x7d, 0x92, 0x79, 0x0a, 0x34, 0x9d, 0x90, 0x9d, 0xb5, 0x64, 0x91, 0x9b, 0xc6,
    0xa7, 0x58, 0x3f, 0xf4, 0xa8, 0x13, 0xc7, 0xd7, 0x29, 0x8d, 0x3e, 0x6a, 0x27, 0x2c, 0x7a, 0x12,
];

/// The authority that signed the witness capture, pinned by the certificate it answered with.
fn digicert() -> Authority {
    Authority {
        name: "DigiCert".to_string(),
        url: "http://timestamp.digicert.com".to_string(),
        accepted_certificates: vec![[
            0x2d, 0xa0, 0x9d, 0xa7, 0xf4, 0x13, 0x1f, 0x9f, 0xe7, 0x2d, 0xb6, 0xc5, 0xe6, 0xe9,
            0xc9, 0x65, 0x67, 0x55, 0xaf, 0x04, 0x3f, 0x1e, 0xa7, 0x42, 0xcc, 0x0d, 0x21, 0x20,
            0xe1, 0x41, 0xeb, 0xfc,
        ]],
        // This reader allows nothing for DigiCert's own clock, and that is a statement this
        // reader is making rather than one the token makes. The captured token states no accuracy,
        // so without a figure here it supports no edge in UTC at all and every sandwich below
        // would be refused for that one reason instead of for the rule it was written to test.
        // Nothing that ships carries an allowance and nought is not a figure anybody should set;
        // what the change of 2026-09-19 stopped is the code assuming it. The refusal that
        // follows from the shipped material is its own test, below.
        accuracy_where_the_token_states_none: Some(0),
    }
}

/// The same authority as the material that ships carries it: no allowance at all.
fn digicert_as_it_ships() -> Authority {
    Authority {
        accuracy_where_the_token_states_none: None,
        ..digicert()
    }
}

/// The three things a verifier decided to trust before reading anything.
fn anchors() -> TrustAnchors {
    TrustAnchors::none()
        .with_roughtime("roughtime.se", ROUGHTIME_SE_KEY)
        .with_drand(Chain::quicknet())
        .with_authority(digicert())
}

fn corridor() -> Evidence {
    Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("roughtime"),
        at: UnixNanos(CORRIDOR_AT),
        radius: Some(CORRIDOR_RADIUS),
        blob: unhex(ROUGHTIME),
        nonce: Some(unhex(CORRIDOR_NONCE)),
        detail: Some("roughtime.se".to_string()),
    }
}

fn beacon() -> Evidence {
    Evidence {
        role: Role::NotEarlierThan,
        scheme: Scheme::new("drand"),
        at: UnixNanos(BEACON_AT),
        radius: None,
        blob: unhex(DRAND),
        nonce: None,
        detail: Some("drand quicknet round 32000947".to_string()),
    }
}

fn witness() -> Evidence {
    Evidence {
        role: Role::NotLaterThan,
        scheme: Scheme::new("rfc3161"),
        at: UnixNanos(WITNESS_AT),
        radius: None,
        blob: unhex(RFC3161),
        nonce: Some(unhex(WITNESS_NONCE)),
        detail: Some("DigiCert".to_string()),
    }
}

/// A receipt whose reading sits inside the corridor and whose interval is a hundred milliseconds
/// wide, which is what an ordinary machine on the public internet actually manages. That is the
/// agent's own model, so a receipt built here claims a sandwich only in the tests about the fifth
/// condition, where a hundred milliseconds inside a four second bracket is the thing refused.
fn receipt(basis: EpsilonBasis, evidence: Vec<Evidence>) -> Receipt {
    let half = 50 * NANOS_PER_MILLI;
    let breakdown = BreakdownRecord {
        intersection_half: 30 * NANOS_PER_MILLI,
        network_half: 12 * NANOS_PER_MILLI,
        scheduling: 5 * NANOS_PER_MILLI,
        oscillator_holdover: 5 * NANOS_PER_MILLI,
        model_residual: 5 * NANOS_PER_MILLI,
        safety_margin: 5 * NANOS_PER_MILLI,
        unclaimed_rate: None,
    };
    assert_eq!(
        breakdown.half_width(),
        half,
        "the parts have to add to the half width"
    );

    Receipt {
        version: 0,
        sequence: 1,
        chain_previous: None,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash: SUBJECT.to_vec(),
        },
        monotonic: 1_000_000_000,
        utc_estimate: UnixNanos(CORRIDOR_AT),
        claim: AgentClaim {
            earliest: UnixNanos(CORRIDOR_AT - half),
            latest: UnixNanos(CORRIDOR_AT + half),
            basis,
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
                max_bound_width: NANOS_PER_SEC,
                min_sources: 3,
                min_operators: Some(3),
                max_holdover: Some(3_600 * NANOS_PER_SEC),
                source_interval_floor: None,
                frequency_slew_ppb_per_s: None,
                frequency_span_ppb: None,
            },
            taken_by: None,
        },
        evidence,
        agent_public_key: vec![0u8; 32],
    }
}

/// The same receipt claiming that its bound rests on the three signatures, with the interval that
/// claim needs: from the beacon's instant to the end of the witness's second, four seconds edge to
/// edge.
///
/// A sandwich says the moment was somewhere inside what the two outside signatures enclose and
/// nothing about where, so a receipt resting on one claims the whole of that and no less. The
/// hundred milliseconds above is what the agent's own model reaches, and a receipt claiming that
/// width on a sandwich basis is claiming a precision the signatures never gave it.
fn resting_on(evidence: Vec<Evidence>) -> Receipt {
    let half = 2 * NANOS_PER_SEC;
    let mut receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
    receipt.claim.earliest = UnixNanos(CORRIDOR_AT - half);
    receipt.claim.latest = UnixNanos(CORRIDOR_AT + half);
    // The network figure sits inside the intersection term and is not added again.
    receipt.claim.breakdown = BreakdownRecord {
        intersection_half: 1_900 * NANOS_PER_MILLI,
        network_half: 400 * NANOS_PER_MILLI,
        scheduling: 50 * NANOS_PER_MILLI,
        oscillator_holdover: 20 * NANOS_PER_MILLI,
        model_residual: 20 * NANOS_PER_MILLI,
        safety_margin: 10 * NANOS_PER_MILLI,
        unclaimed_rate: None,
    };
    assert_eq!(receipt.claim.breakdown.half_width(), half);
    receipt.claim.policy.max_bound_width = 5 * NANOS_PER_SEC;
    assert_eq!(receipt.claim.earliest, UnixNanos(BEACON_AT));
    assert_eq!(receipt.claim.latest, UnixNanos(WITNESS_AT));
    receipt
}

fn all_three() -> Vec<Evidence> {
    vec![corridor(), beacon(), witness()]
}

/// A genuine round of quicknet from 2023, beside the fresh one.
///
/// Round 1000000, with the signature the chain published for it. It is real, it is checked, and
/// it is about nothing this receipt stamps, which is what makes it useful: a bracket is sized on
/// the freshest checked beacon, so an older one beside it changes nothing about what the claim has
/// to cover.
fn old_beacon() -> Evidence {
    let chain = Chain::quicknet();
    let round = 1_000_000;
    let signature = unhex(
        "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72",
    );
    Evidence {
        role: Role::NotEarlierThan,
        scheme: Scheme::new("drand"),
        at: UnixNanos(i128::from(chain.time_of(round).expect("a past round")) * NANOS_PER_SEC),
        radius: None,
        blob: drand::pack_blob(&chain.hash, round, &signature),
        nonce: None,
        detail: Some("drand quicknet round 1000000".to_string()),
    }
}

// ---------------------------------------------------------------------------------------------
// The one that has to pass.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_bound_resting_on_three_real_signatures_is_granted() {
    let receipt = resting_on(all_three());
    let verified = validate_with(&receipt, &anchors())
        .expect("a receipt whose evidence was all captured and all checks out");

    assert!(verified.basis_granted, "{}", verified.basis_reason);
    assert!(
        verified.basis_reason.contains("covers them"),
        "{}",
        verified.basis_reason
    );
    assert_eq!(verified.checked(), 3, "all three roles verified");
    assert_eq!(verified.anchors_held, 3);

    for entry in &verified.entries {
        match &entry.outcome {
            Outcome::Checked { signer, checks, .. } => {
                assert!(
                    !checks.is_empty(),
                    "{} was called checked and lists no checks",
                    entry.scheme
                );
                assert!(!signer.is_empty());
            }
            Outcome::NotChecked(why) => panic!("{} was not checked: {why}", entry.scheme),
        }
    }

    // The report is what a person reads, so it has to name every entry and say what happened.
    let lines = verified.lines();
    for scheme in ["roughtime", "drand", "rfc3161"] {
        assert!(
            lines.iter().any(|l| l.contains(scheme)),
            "the report never mentions {scheme}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Every way it should not be granted.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_verifier_holding_nothing_grants_nothing() {
    // The same receipt, read by somebody who has decided to trust no keys at all. Every arithmetic
    // check still runs and the strongest claim is refused, because there was nothing to check it
    // against. This is the state the product shipped in before the evidence clients existed.
    let receipt = resting_on(all_three());
    let err = validate(&receipt).expect_err("a sandwich granted with no anchors at all");
    assert!(matches!(err, ReceiptError::OurClaimAsEvidence(_)), "{err}");
}

#[test]
fn a_verifier_holding_two_of_the_three_grants_nothing() {
    let receipt = resting_on(all_three());
    let mut partial = anchors();
    partial.timestamp_authorities.clear();
    let err = validate_with(&receipt, &partial)
        .expect_err("a sandwich granted on two roles out of three");
    let text = err.to_string();
    assert!(text.contains("not-later-than: false"), "{text}");
}

#[test]
fn the_same_receipt_labelled_honestly_is_accepted_and_says_what_it_rests_on() {
    // A receipt carrying the same three signatures and claiming only its own model is not wrong. It
    // is under-claiming, and the report still says which entries checked out, so a reader can see
    // there was more evidence than the receipt leaned on.
    let receipt = receipt(EpsilonBasis::LocalModelOnly, all_three());
    let verified = validate_with(&receipt, &anchors()).expect("an honestly labelled receipt");
    assert!(!verified.basis_granted);
    assert_eq!(verified.checked(), 3);
}

#[test]
fn a_corridor_whose_stored_response_does_not_verify_refuses_the_whole_receipt() {
    let mut evidence = all_three();
    let last = evidence[0].blob.len() - 1;
    evidence[0].blob[last] ^= 0x01;
    let receipt = resting_on(evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a spoiled corridor response");
    assert!(matches!(err, ReceiptError::Inconsistent(_)), "{err}");
    assert!(err.to_string().contains("roughtime"), "{err}");
}

#[test]
fn a_beacon_round_that_does_not_verify_refuses_the_whole_receipt() {
    let mut evidence = all_three();
    let last = evidence[1].blob.len() - 1;
    evidence[1].blob[last] ^= 0x01;
    let receipt = resting_on(evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a spoiled drand round");
    assert!(err.to_string().contains("drand"), "{err}");
}

#[test]
fn a_token_that_does_not_verify_refuses_the_whole_receipt() {
    let mut evidence = all_three();
    let last = evidence[2].blob.len() - 1;
    evidence[2].blob[last] ^= 0x01;
    let receipt = resting_on(evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a spoiled token");
    assert!(err.to_string().contains("rfc3161"), "{err}");
}

#[test]
fn a_receipt_that_prints_a_different_moment_beside_a_real_signature_is_refused() {
    // The lie that survives a signature check. Every blob is genuine and every signature holds; the
    // numbers printed beside them, which is what a person reads and what the interval arithmetic
    // uses, have been moved.
    for (index, name) in [(0usize, "roughtime"), (1, "drand"), (2, "rfc3161")] {
        let mut evidence = all_three();
        evidence[index].at = UnixNanos(evidence[index].at.as_nanos() + 30 * NANOS_PER_MILLI);
        let receipt = resting_on(evidence);
        let err = validate_with(&receipt, &anchors())
            .unwrap_err_or_else_message(&format!("{name} moved by 30 ms was accepted"));
        assert!(err.contains(name), "{err}");
    }
}

#[test]
fn a_corridor_whose_radius_has_been_widened_is_refused() {
    // Widening the radius makes a corridor overlap an interval it should not, and the response
    // itself says what the radius is, so this is checkable rather than a matter of opinion.
    let mut evidence = all_three();
    evidence[0].radius = Some(CORRIDOR_RADIUS * 60);
    let receipt = resting_on(evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a widened corridor");
    assert!(err.to_string().contains("radius"), "{err}");
}

#[test]
fn a_corridor_bound_to_somebody_elses_subject_is_refused() {
    // The nonce in this response was derived from the subject of the capture. A receipt stamping
    // something else, and offering that response as its corridor, is offering a genuine signature
    // about a different document.
    let mut receipt = resting_on(all_three());
    receipt.payload.hash = vec![0x5b; 32];
    let err = validate_with(&receipt, &anchors()).expect_err("a corridor about another subject");
    assert!(err.to_string().contains("roughtime"), "{err}");
}

#[test]
fn evidence_a_verifier_cannot_check_is_reported_as_unchecked_rather_than_ignored() {
    let receipt = receipt(EpsilonBasis::LocalModelOnly, all_three());
    let verified = validate_with(&receipt, &TrustAnchors::none()).expect("an honest receipt");
    assert_eq!(verified.checked(), 0);
    assert_eq!(verified.entries.len(), 3);
    let lines = verified.lines().join("\n");
    assert!(lines.contains("not checked"), "{lines}");
    assert!(
        lines.contains("does not rest on third-party evidence"),
        "{lines}"
    );
}

#[test]
fn the_width_ceiling_is_stated_in_whole_seconds_and_is_an_hour() {
    // Worth pinning, because the number decides which real sandwiches are accepted and a change to
    // it should be a deliberate act rather than a drifting constant.
    assert_eq!(SANDWICH_WIDTH_CEILING, 3_600 * NANOS_PER_SEC);
}

/// Added on 2026-09-08, when the verifier shipped.
///
/// `examine_corridor` compared the printed radius against the response and the other two arms
/// compared the instant alone, so a beacon or a witness could print any radius it liked beside a
/// real signature. `check_evidence_against_the_interval` then builds the entry's interval out of
/// those printed numbers and takes whichever end is hardest on the entry, so a wide radius is a way
/// past the interval test rather than a cost.
#[test]
fn an_entry_may_not_print_an_interval_wider_than_its_signature_supports() {
    // The two roles refuse it for different reasons after the change of 2026-09-19, and the
    // reason is worth keeping apart. A round states an instant, so a radius printed beside it
    // reaches outside what the signature supports. A token whose authority states no accuracy
    // supports no interval at all, so there is nothing for a radius to reach outside of and any
    // radius is refused, which is the tighter of the two. Neither depends on what the reader
    // holds: both run off the receipt's own bytes before a key is looked at.
    for (index, name, why) in [
        (
            1usize,
            "drand",
            "reaches outside the one the signature supports",
        ),
        (
            2,
            "rfc3161",
            "the attestation supports no interval at all for a width to sit inside",
        ),
    ] {
        let mut evidence = all_three();
        evidence[index].radius = Some(365 * 24 * 3_600 * NANOS_PER_SEC);
        let receipt = resting_on(evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} entry printing a year of radius beside a real signature was accepted"
        ));
        assert!(err.contains(name), "{err}");
        assert!(err.contains(why), "{err}");
    }
}

/// The other half of the same rule: the nonce beside an entry, not the interval.
///
/// The nonce answers "could this response have been fetched in advance", it is the field a reader
/// looks at when asking that, and nothing tied it to the response. It was a printed value the
/// validator carried through untouched, and these fixtures printed thirty-two zeros beside a real
/// Roughtime capture for a fortnight without anything noticing.
///
/// Both fixtures now carry the nonce out of their own captured blob, so the honest case is the one
/// that passes, and the three cases below are the ones that must not.
#[test]
fn an_entry_may_not_print_a_nonce_the_signature_was_not_made_over() {
    // A corridor and a witness, each printing a nonce of the right length and the wrong value.
    for (index, name) in [(0usize, "roughtime"), (2, "rfc3161")] {
        let mut evidence = all_three();
        let length = evidence[index]
            .nonce
            .as_ref()
            .expect("both of these print one")
            .len();
        evidence[index].nonce = Some(vec![0u8; length]);
        let receipt = resting_on(evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} entry printing a nonce nothing signed was accepted"
        ));
        assert!(err.contains(name), "{err}");
        assert!(err.contains("made over a different"), "{err}");
    }

    // And a beacon, which signs over no nonce at all, so any nonce printed beside one is decoration.
    let mut evidence = all_three();
    evidence[1].nonce = Some(vec![9u8; 32]);
    let planted = resting_on(evidence);
    let err = validate_with(&planted, &anchors())
        .unwrap_err_or_else_message("a drand entry printing a nonce was accepted");
    assert!(err.contains("drand"), "{err}");
    assert!(err.contains("rests on nothing"), "{err}");

    // A receipt that prints no nonce claims nothing about one, and stays acceptable. Quieter than
    // the evidence is allowed; louder is what the rule refuses.
    let mut evidence = all_three();
    evidence[2].nonce = None;
    let quieter = resting_on(evidence);
    validate_with(&quieter, &anchors()).expect("an entry printing no nonce is not a fault");
}

/// The same shape as the two above, one layer down.
///
/// A receipt whose blob is four bytes of `deadbeef` is not a stored attestation of any scheme. That
/// takes no key to see: unpacking reads a magic string and two lengths and touches no cryptography.
/// It was reported as `not checked` whenever the verifier held no anchor, so the default verifier
/// refused the receipt at exit 1 and `--no-anchors` accepted it with `accepted = true` and exit 0.
///
/// Watched failing on all three schemes before the fix, 2026-09-08.
#[test]
fn a_blob_that_is_not_an_attestation_at_all_fails_with_no_anchors_as_well() {
    for (index, name) in [(0usize, "roughtime"), (1, "drand"), (2, "rfc3161")] {
        let mut evidence = all_three();
        evidence[index].blob = vec![0xde, 0xad, 0xbe, 0xef];
        let receipt = receipt(EpsilonBasis::LocalModelOnly, evidence);

        let with_keys = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a four byte {name} blob was accepted by a verifier holding keys"
        ));
        assert!(with_keys.contains(name), "{with_keys}");

        let without_keys = validate_with(&receipt, &TrustAnchors::none())
            .unwrap_err_or_else_message(&format!(
                "a four byte {name} blob was accepted under --no-anchors"
            ));
        assert!(
            without_keys.contains("needs no key to see"),
            "{without_keys}"
        );
    }
}

/// And the distinction the flag exists for survives the fix.
///
/// A real attestation nobody holds a key for is a fact about the reader, not a fault in the receipt,
/// and it still reports as not checked at exit 0.
#[test]
fn a_real_attestation_nobody_holds_a_key_for_is_still_only_not_checked() {
    let receipt = receipt(EpsilonBasis::LocalModelOnly, all_three());
    let verified = validate_with(&receipt, &TrustAnchors::none())
        .expect("a verifier holding nothing refuses nothing about a well-formed receipt");
    assert_eq!(verified.checked(), 0);
    let lines = verified.lines().join(
        "
",
    );
    assert!(lines.contains("not checked"), "{lines}");
}

/// A reader who holds keys, and not the key of the party that signed this entry.
///
/// Until 2026-09-15 each of the three arms tried every key the reader held and, where none fitted,
/// refused the receipt as contradicting itself. So a reader who took up the documented offer to
/// supply their own trust material was told an intact receipt was a lie whenever their list lacked
/// one signer, and the only way past it was to hold every key the shipped set holds, which is taking
/// our word for which keys are which. Which party signed an attestation is written in the
/// attestation itself, before any cryptography: the request names the server's long-term key, the
/// round names its chain, the token carries its certificates. A reader holding no key for that
/// party has not checked the entry, and the report says so. Watched failing on all three schemes
/// before the fix.
#[test]
fn an_attestation_by_a_party_the_reader_holds_no_key_for_is_not_checked_and_not_refused() {
    // The published key of time.txryan.com: a real server, and not the one this capture asked.
    let another_server = unhex("881563c60ff58fbcb5fa44144c161d4da6f10a9a5eb14ff4ec3e0f303264d960");
    let mut another_server_key = [0u8; 32];
    another_server_key.copy_from_slice(&another_server);
    let another_chain = Chain {
        name: "another chain",
        hash: [0x8c; 32],
        ..Chain::quicknet()
    };
    let another_authority = Authority {
        name: "somebody-else".to_string(),
        url: "http://timestamp.example".to_string(),
        accepted_certificates: vec![[0x11; 32]],
        accuracy_where_the_token_states_none: None,
    };

    let cases: [(usize, &str, TrustAnchors, &str); 3] = [
        (
            0,
            "roughtime",
            TrustAnchors::none()
                .with_roughtime("time.txryan.com", another_server_key)
                .with_drand(Chain::quicknet())
                .with_authority(digicert()),
            "long-term key",
        ),
        (
            1,
            "drand",
            TrustAnchors::none()
                .with_roughtime("roughtime.se", ROUGHTIME_SE_KEY)
                .with_drand(another_chain)
                .with_authority(digicert()),
            "chain",
        ),
        (
            2,
            "rfc3161",
            TrustAnchors::none()
                .with_roughtime("roughtime.se", ROUGHTIME_SE_KEY)
                .with_drand(Chain::quicknet())
                .with_authority(another_authority),
            "certificate",
        ),
    ];

    for (index, name, anchors, names_what) in cases {
        let plain = receipt(EpsilonBasis::LocalModelOnly, all_three());
        let verified = validate_with(&plain, &anchors).unwrap_or_else(|e| {
            panic!("a reader holding no key for the {name} signer refused an intact receipt: {e}")
        });
        assert_eq!(
            verified.checked(),
            2,
            "{name}: the other two are still checked"
        );
        match &verified.entries[index].outcome {
            Outcome::NotChecked(why) => {
                assert!(why.contains(names_what), "{name}: {why}");
                assert!(why.contains("holds no"), "{name}: {why}");
            }
            other => panic!("{name}: expected not checked, got {other:?}"),
        }

        // The same receipt claiming a sandwich is still refused, because a basis that cannot be
        // checked is not granted. What changes is the reason: the reader is told which role they
        // could not check, and not that the receipt contradicts itself.
        let claiming = resting_on(all_three());
        let err = validate_with(&claiming, &anchors)
            .unwrap_err_or_else_message(&format!("{name}: a sandwich nobody checked was granted"));
        assert!(
            err.contains("cannot be checked is not granted"),
            "{name}: {err}"
        );
        assert!(!err.contains("contradicts itself"), "{name}: {err}");
    }
}

/// And the refusal is kept for the case it was always for: the reader holds the key the attestation
/// names, and the bytes do not verify under it.
///
/// Each capture is changed in the one place only the key can see. The reader holds the right key for
/// each, so this is not a fact about the reader; it is a signature that does not check out, and a
/// receipt carrying one is wrong. Until 2026-09-15 this flipped the last byte of each blob, which
/// for the corridor is the Merkle index and for the round is a byte of the point, and both of those
/// are faults that need no key to see and are refused before any key is chosen. What only a key
/// catches is the long-term key's signature over the delegation, the group's signature over the
/// round number, and the authority's signature over the token.
#[test]
fn an_attestation_that_fails_under_a_key_the_reader_holds_for_its_signer_is_still_refused() {
    for (name, spoil) in [
        (
            "roughtime",
            spoil_the_delegation_signature as fn(&mut Evidence),
        ),
        ("drand", spoil_the_round_number),
        ("rfc3161", spoil_the_last_byte),
    ] {
        let mut evidence = all_three();
        let index = evidence
            .iter()
            .position(|e| e.scheme.as_str() == name)
            .expect("one entry per scheme");
        spoil(&mut evidence[index]);
        let receipt = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} attestation with its signature spoiled was accepted under the key it names"
        ));
        assert!(err.contains(name), "{err}");
        assert!(err.contains("does not check out against"), "{err}");
    }
}

/// The corridor's delegation signature, found by the header of the certificate message it sits in.
///
/// A Roughtime certificate is a message of two pairs, the signature at offset nought and the
/// delegation after its 64 bytes, so its header is fixed: a count of two, one offset of 64, and the
/// two tags in ascending order. The signature is the 64 bytes after that header, and it is the one
/// part of a response that only the server's published long-term key can check.
fn spoil_the_delegation_signature(entry: &mut Evidence) {
    let mut header = Vec::new();
    header.extend_from_slice(&2u32.to_le_bytes());
    header.extend_from_slice(&64u32.to_le_bytes());
    header.extend_from_slice(b"SIG\0");
    header.extend_from_slice(b"DELE");
    let at = entry
        .blob
        .windows(header.len())
        .position(|w| w == header)
        .expect("the capture carries a certificate");
    entry.blob[at + header.len()] ^= 0x01;
}

/// The round number a drand signature was made over, which is the whole of its message.
///
/// The signature stays a real point on the curve, so nothing short of the pairing against the
/// group key can tell that it is a signature over some other round.
fn spoil_the_round_number(entry: &mut Evidence) {
    entry.blob[8] ^= 0x01;
}

/// The last byte of a token, which is the end of the authority's RSA signature.
fn spoil_the_last_byte(entry: &mut Evidence) {
    let last = entry.blob.len() - 1;
    entry.blob[last] ^= 0x01;
}

// ---------------------------------------------------------------------------------------------
// A renamed signer skips nothing that needs no key.
// ---------------------------------------------------------------------------------------------

/// The key of roughtime.se as the corridor's request names it, which is the hash of the key and
/// not the key itself.
fn corridor_server_hash() -> [u8; 32] {
    timewitness_core::evidence::roughtime::server_key_hash(&ROUGHTIME_SE_KEY)
}

/// Rewrite who the corridor's request says it asked, leaving everything else as captured.
fn rename_the_corridor_signer(entry: &mut Evidence) {
    let hash = corridor_server_hash();
    let at = entry
        .blob
        .windows(32)
        .position(|w| w == hash)
        .expect("the request names the server by its key hash");
    entry.blob[at] ^= 0xff;
}

/// Rewrite which chain the round says it is from.
fn rename_the_round_chain(entry: &mut Evidence) {
    entry.blob[16..48].copy_from_slice(&[0x8c; 32]);
}

/// Change one byte inside the certificate the token carries, so no pin names it any more.
///
/// The certificate is found the way a reader finds it: a DER sequence in the reply whose SHA-256
/// is one of the digests the token reports carrying. The signature over the token is not touched.
fn rename_the_token_signer(entry: &mut Evidence) {
    use timewitness_core::evidence::rfc3161::certificate_digests;
    let digests = certificate_digests(&entry.blob).expect("the capture carries certificates");
    let blob = entry.blob.clone();
    for at in 0..blob.len().saturating_sub(4) {
        if blob[at] == 0x30 && blob[at + 1] == 0x82 {
            let len = (usize::from(blob[at + 2]) << 8) | usize::from(blob[at + 3]);
            let end = at + 4 + len;
            if end <= blob.len() {
                let digest = timewitness_core::hash::HashFunction::Sha256.digest(&blob[at..end]);
                if digests.iter().any(|d| d[..] == digest[..]) {
                    entry.blob[end - 1] ^= 0x01;
                    return;
                }
            }
        }
    }
    panic!("no certificate the token reports was found in its bytes");
}

/// The corridor with its reply replaced by zeros of the same length.
fn zero_the_corridor_reply(entry: &mut Evidence) {
    use timewitness_core::evidence::roughtime::{pack_blob, unpack_blob};
    let stored = unpack_blob(&entry.blob).expect("the capture unpacks");
    let zeros = vec![0u8; stored.reply.len()];
    entry.blob = pack_blob(stored.binding, stored.request, &zeros);
}

/// The corridor with a reply that frames correctly and carries four bytes of junk.
fn junk_the_corridor_reply(entry: &mut Evidence) {
    use timewitness_core::evidence::roughtime::{pack_blob, unpack_blob};
    let stored = unpack_blob(&entry.blob).expect("the capture unpacks");
    let mut junk = b"ROUGHTIM".to_vec();
    junk.extend_from_slice(&4u32.to_le_bytes());
    junk.extend_from_slice(b"junk");
    entry.blob = pack_blob(stored.binding, stored.request, &junk);
}

/// The round with its signature cut to five bytes, which no key is needed to see is not a point.
fn cut_the_round_signature(entry: &mut Evidence) {
    use timewitness_core::evidence::drand::{pack_blob, unpack_blob};
    let stored = unpack_blob(&entry.blob).expect("the capture unpacks");
    entry.blob = pack_blob(&stored.chain_hash, stored.round, &[1, 2, 3, 4, 5]);
}

/// The two settings a stranger reads a receipt under: the shipped kind of anchors, and none.
fn both_settings() -> [(&'static str, TrustAnchors); 2] {
    [
        ("holding keys", anchors()),
        ("holding nothing", TrustAnchors::none()),
    ]
}

/// A receipt whose signer has been renamed to a party nobody holds, with something behind the name
/// that needs no key to see is wrong, is refused whatever the reader holds.
///
/// The 2026-09-15 change read who signed an attestation off the attestation and returned not checked for a party
/// the reader holds no key for before reading anything past the outer blob. The name sits in bytes
/// the receipt's writer controls, so renaming it moved a zeroed reply, four bytes of junk and a
/// five byte signature past every check, exit 0, on the command line, the page and the Action's
/// self-check, where the only release refused them. Watched failing on every case below on
/// `2b3e092` before the fix, 2026-09-15.
#[test]
fn a_renamed_signer_skips_nothing_that_needs_no_key() {
    type Step = fn(&mut Evidence);
    let cases: [(&str, usize, Vec<Step>); 5] = [
        (
            "roughtime",
            0,
            vec![rename_the_corridor_signer, zero_the_corridor_reply],
        ),
        (
            "roughtime",
            0,
            vec![rename_the_corridor_signer, junk_the_corridor_reply],
        ),
        (
            "drand",
            1,
            vec![rename_the_round_chain, cut_the_round_signature],
        ),
        // The reply is intact and the request no longer hashes into the root the reply signs,
        // because renaming the server changed the request bytes and the leaf is over all of them.
        ("roughtime", 0, vec![rename_the_corridor_signer]),
        // Not renamed at all, and the one byte changed is the Merkle index. Under `--no-anchors`
        // this was accepted on every build, the only release included.
        ("roughtime", 0, vec![spoil_the_last_byte]),
    ];
    for (name, index, steps) in cases {
        for (setting, anchors) in both_settings() {
            let mut evidence = all_three();
            for step in &steps {
                step(&mut evidence[index]);
            }
            let receipt = receipt(EpsilonBasis::LocalModelOnly, evidence);
            let err = validate_with(&receipt, &anchors).unwrap_err_or_else_message(&format!(
                "a {name} attestation broken behind a renamed signer was accepted by a reader \
                 {setting}"
            ));
            assert!(err.contains(name), "{setting}: {err}");
            assert!(err.contains("needs no key to see"), "{setting}: {err}");
        }
    }
}

/// A token for another document behind a renamed signer, and a corridor bound to another document
/// behind one, are refused whatever the reader holds.
///
/// The binding a corridor's nonce was derived from, and the imprint a token was issued over, are
/// both inside the receipt, so whether either is about this receipt's subject needs no key.
#[test]
fn an_attestation_about_another_document_behind_a_renamed_signer_is_refused() {
    for (name, entry, rename) in [
        (
            "roughtime",
            corridor(),
            rename_the_corridor_signer as fn(&mut Evidence),
        ),
        ("rfc3161", witness(), rename_the_token_signer),
    ] {
        for (setting, anchors) in both_settings() {
            let mut entry = entry.clone();
            rename(&mut entry);
            let mut receipt = receipt(EpsilonBasis::LocalModelOnly, vec![entry]);
            receipt.payload.hash = vec![0x5b; 32];
            let err = validate_with(&receipt, &anchors).unwrap_err_or_else_message(&format!(
                "a {name} attestation about another document was accepted behind a renamed \
                 signer by a reader {setting}"
            ));
            assert!(err.contains(name), "{setting}: {err}");
            assert!(err.contains("needs no key to see"), "{setting}: {err}");
        }
    }
}

/// The numbers a receipt prints beside an entry are held to the attestation whether or not the
/// reader holds a key for its signer.
///
/// A moment, a radius and a nonce are all read off the stored bytes, so a receipt printing
/// different ones beside an entry nobody holds a key for is contradicting its own attestation and
/// no key is needed to see it. The token's signer is renamed in the receipt. The corridor's cannot
/// be, because the request is the Merkle leaf and renaming the server inside it is itself refused
/// with no key, so the corridor is read by a reader holding no Roughtime key instead, which is the
/// same state from the reader's side. A round is the one exception and it is stated: which moment
/// a round falls at is arithmetic on the chain's schedule, which is part of the anchor, so a
/// renamed round with a moved moment stays not checked rather than refused.
#[test]
fn what_is_printed_beside_an_unheld_signer_is_still_held_to_the_attestation() {
    let mut no_roughtime_key = anchors();
    no_roughtime_key.roughtime_servers.clear();
    let corridor_settings = [
        ("holding no Roughtime key", no_roughtime_key),
        ("holding nothing", TrustAnchors::none()),
    ];

    for (setting, anchors) in &corridor_settings {
        let mut evidence = all_three();
        evidence[0].at = UnixNanos(evidence[0].at.as_nanos() + 30 * NANOS_PER_MILLI);
        let moved = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&moved, anchors).unwrap_err_or_else_message(&format!(
            "a corridor printing a moved moment was accepted by a reader {setting}"
        ));
        assert!(err.contains("roughtime"), "{setting}: {err}");
        assert!(err.contains("needs no key to see"), "{setting}: {err}");

        let mut evidence = all_three();
        evidence[0].radius = Some(CORRIDOR_RADIUS * 60);
        let widened = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&widened, anchors)
            .unwrap_err_or_else_message(&format!("a widened corridor was accepted {setting}"));
        assert!(err.contains("radius"), "{setting}: {err}");
        assert!(err.contains("needs no key to see"), "{setting}: {err}");

        let mut evidence = all_three();
        evidence[0].nonce = Some(vec![0u8; 32]);
        let planted = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&planted, anchors)
            .unwrap_err_or_else_message(&format!("a planted nonce was accepted {setting}"));
        assert!(err.contains("made over a different"), "{setting}: {err}");
        assert!(err.contains("needs no key to see"), "{setting}: {err}");
    }

    for (setting, anchors) in both_settings() {
        let mut evidence = all_three();
        rename_the_token_signer(&mut evidence[2]);
        evidence[2].at = UnixNanos(evidence[2].at.as_nanos() + 30 * NANOS_PER_MILLI);
        let moved = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&moved, &anchors).unwrap_err_or_else_message(&format!(
            "a token printing a moved moment beside a renamed signer was accepted by a reader \
             {setting}"
        ));
        assert!(err.contains("rfc3161"), "{setting}: {err}");
        assert!(err.contains("needs no key to see"), "{setting}: {err}");

        let mut evidence = all_three();
        rename_the_token_signer(&mut evidence[2]);
        evidence[2].nonce = Some(vec![0u8; 16]);
        let planted = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&planted, &anchors)
            .unwrap_err_or_else_message(&format!("a planted token nonce was accepted {setting}"));
        assert!(err.contains("made over a different"), "{setting}: {err}");

        // A beacon signs over no nonce, so one printed beside a renamed round rests on nothing.
        let mut evidence = all_three();
        rename_the_round_chain(&mut evidence[1]);
        evidence[1].nonce = Some(vec![9u8; 32]);
        let planted = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&planted, &anchors)
            .unwrap_err_or_else_message(&format!("a nonce beside a round was accepted {setting}"));
        assert!(err.contains("rests on nothing"), "{setting}: {err}");
    }
}

/// Every signer unheld at once, which is the receipt a forger who has read the validator writes.
///
/// With the insides intact it is accepted with nothing checked, which is the unheld-party case and is
/// right: three genuine attestations by parties this reader holds no key for. The round and the
/// token get there by renaming inside the receipt; the corridor cannot, because the request is the
/// Merkle leaf and a renamed server inside it no longer hashes into the signed root, so that rename
/// is refused with no key and the corridor is unheld from the reader's side instead. With any
/// inside broken the receipt is refused. And a sandwich claimed over the intact one is still
/// refused, because a basis nobody checked is not granted.
#[test]
fn every_signer_unheld_at_once_is_not_checked_when_intact_and_refused_when_not() {
    let renamed = || {
        let mut evidence = all_three();
        rename_the_round_chain(&mut evidence[1]);
        rename_the_token_signer(&mut evidence[2]);
        evidence
    };
    let mut no_roughtime_key = anchors();
    no_roughtime_key.roughtime_servers.clear();
    let settings = [
        ("holding no key any entry names", no_roughtime_key),
        ("holding nothing", TrustAnchors::none()),
    ];

    for (setting, anchors) in &settings {
        let intact = receipt(EpsilonBasis::LocalModelOnly, renamed());
        let verified = validate_with(&intact, anchors).unwrap_or_else(|e| {
            panic!("three intact attestations by unheld parties were refused {setting}: {e}")
        });
        assert_eq!(verified.checked(), 0, "{setting}");
        assert!(verified.entries.iter().all(|e| !e.outcome.is_checked()));

        let claiming = resting_on(renamed());
        let err = validate_with(&claiming, anchors).unwrap_err_or_else_message(&format!(
            "a sandwich nobody checked was granted {setting}"
        ));
        assert!(
            err.contains("cannot be checked is not granted"),
            "{setting}: {err}"
        );

        for (name, index, spoil) in [
            // The corridor's rename alone, which breaks the path from the request to the root.
            (
                "roughtime",
                0usize,
                rename_the_corridor_signer as fn(&mut Evidence),
            ),
            ("roughtime", 0, zero_the_corridor_reply),
            ("drand", 1, cut_the_round_signature),
            ("rfc3161", 2, junk_the_token_reply),
        ] {
            let mut evidence = renamed();
            spoil(&mut evidence[index]);
            let receipt = receipt(EpsilonBasis::LocalModelOnly, evidence);
            let err = validate_with(&receipt, anchors).unwrap_err_or_else_message(&format!(
                "{name} broken behind three unheld signers was accepted {setting}"
            ));
            assert!(err.contains(name), "{setting}: {err}");
            assert!(err.contains("needs no key to see"), "{setting}: {err}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The fifth condition: the claim covers the bracket.
// ---------------------------------------------------------------------------------------------

/// A width inside the bracket, claimed as resting on it, is refused.
///
/// Added 2026-09-15. Until then the four conditions above were the whole test and none of them
/// read the interval the receipt claimed. The committed receipt with its basis rewritten and
/// re-signed under a fresh key was granted a sandwich on 153.875 ms inside a 2 s bracket, and the
/// verifier told the reader on its second line that the width rested on outside signatures. It
/// rested on the signer. Watched granted on `2e683e6` before the condition went in, on the command
/// line, the page and the Action's summary alike.
#[test]
fn a_width_narrower_than_the_bracket_claimed_as_resting_on_it_is_refused() {
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
    let err = validate_with(&receipt, &anchors())
        .unwrap_err_or_else_message("a 100 ms width inside a 4 s bracket was granted a sandwich");
    assert!(err.contains("does not cover"), "{err}");
    assert!(err.contains("rests on the signer's own model"), "{err}");
    assert!(
        err.contains("where outside evidence goes"),
        "the refusal names the rule it is applying: {err}"
    );
}

/// Edge to edge is enough, and one nanosecond inside either edge is not.
///
/// The bracket is the latest checked beacon to the earliest checked witness, and the claim has to
/// reach both. A claim reaching one and stopping a nanosecond short of the other has ruled that
/// nanosecond out on its own model, which is the same thing as ruling out the other 3.9 seconds.
#[test]
fn a_claim_stopping_a_nanosecond_inside_either_edge_of_the_bracket_is_refused() {
    let exact = resting_on(all_three());
    validate_with(&exact, &anchors()).expect("a claim that is the bracket, edge to edge");

    let mut short_at_the_start = resting_on(all_three());
    short_at_the_start.claim.earliest = UnixNanos(BEACON_AT + 1);
    let err = validate_with(&short_at_the_start, &anchors())
        .unwrap_err_or_else_message("a claim a nanosecond inside the beacon's edge was granted");
    assert!(err.contains("does not cover"), "{err}");

    let mut short_at_the_end = resting_on(all_three());
    short_at_the_end.claim.latest = UnixNanos(WITNESS_AT - 1);
    let err = validate_with(&short_at_the_end, &anchors())
        .unwrap_err_or_else_message("a claim a nanosecond inside the witness's edge was granted");
    assert!(err.contains("does not cover"), "{err}");
}

/// A claim as wide as the bracket and shifted off it is refused, which is why the condition is on
/// the edges and not on the width.
///
/// Half a second later at both ends, the claim is still four seconds wide, still overlaps every
/// signature, and still passes every arithmetic check the receipt is put to on its own. What it
/// does not do is cover the bracket: half a second at its start is outside what the signatures
/// enclose, and half a second at the bracket's start is outside what the claim allows.
#[test]
fn a_claim_as_wide_as_the_bracket_but_shifted_off_it_is_refused() {
    let mut shifted = resting_on(all_three());
    let by = 500 * NANOS_PER_MILLI;
    shifted.claim.earliest = UnixNanos(shifted.claim.earliest.as_nanos() + by);
    shifted.claim.latest = UnixNanos(shifted.claim.latest.as_nanos() + by);
    shifted.utc_estimate = UnixNanos(shifted.utc_estimate.as_nanos() + by);
    assert_eq!(shifted.width(), exact_width(), "the width has not changed");
    let err = validate_with(&shifted, &anchors()).unwrap_err_or_else_message(
        "a claim as wide as the bracket and shifted off it was granted",
    );
    assert!(err.contains("does not cover"), "{err}");
}

fn exact_width() -> Nanos {
    resting_on(all_three()).width()
}

/// A second genuine beacon, older, beside the fresh one: the bracket the claim has to cover is
/// sized on the fresh one and the old one widens nothing.
///
/// This is a case first built on 2026-09-15: a 2023 round of quicknet beside the round the stamp
/// fetched, on the committed receipt, claiming a sandwich over 153.875 ms. The bracket is sized on
/// the tightest checked pair, so the old round does not loosen it, and the narrow claim is refused
/// on the same condition as without it. Covering the bracket the fresh beacon sets is still
/// enough, with all four attestations checked.
#[test]
fn an_older_genuine_beacon_beside_the_fresh_one_widens_nothing_the_claim_must_cover() {
    let with_old = || {
        let mut evidence = all_three();
        evidence.insert(1, old_beacon());
        evidence
    };

    let narrow = receipt(EpsilonBasis::ThirdPartySandwich, with_old());
    let err = validate_with(&narrow, &anchors())
        .unwrap_err_or_else_message("a narrow claim was granted a sandwich beside an old round");
    assert!(err.contains("does not cover"), "{err}");

    let covering = resting_on(with_old());
    let verified =
        validate_with(&covering, &anchors()).expect("a covering claim beside an old round");
    assert!(verified.basis_granted, "{}", verified.basis_reason);
    assert_eq!(
        verified.checked(),
        4,
        "the old round is real and is checked"
    );
}

/// The honest reading of the same interval: a receipt whose claim covers the bracket and rests on
/// its own model is not granted a sandwich, and the report says it could have rested on the
/// signatures and did not.
#[test]
fn a_covering_claim_resting_on_its_own_model_is_told_what_it_did_not_rest_on() {
    let mut honest = resting_on(all_three());
    honest.claim.basis = EpsilonBasis::LocalModelOnly;
    let verified = validate_with(&honest, &anchors()).expect("an honestly labelled receipt");
    assert!(!verified.basis_granted);
    assert!(
        verified
            .basis_reason
            .contains("covers them, which it did not rest on"),
        "{}",
        verified.basis_reason
    );

    let narrow = receipt(EpsilonBasis::LocalModelOnly, all_three());
    let verified = validate_with(&narrow, &anchors()).expect("an honestly labelled receipt");
    assert!(!verified.basis_granted);
    assert!(
        verified
            .basis_reason
            .contains("even though the width is not"),
        "{}",
        verified.basis_reason
    );
}

/// The token with a reply that is not a timestamp response at all, behind an intact request.
fn junk_the_token_reply(entry: &mut Evidence) {
    use timewitness_core::evidence::rfc3161::{pack_blob, unpack_blob};
    let stored = unpack_blob(&entry.blob).expect("the capture unpacks");
    entry.blob = pack_blob(stored.request, b"not a timestamp response");
}

/// A small helper so the tests above read as sentences rather than as unwrapping.
trait Unwrapped {
    fn unwrap_err_or_else_message(self, message: &str) -> String;
}

impl<T> Unwrapped for Result<T, ReceiptError> {
    fn unwrap_err_or_else_message(self, message: &str) -> String {
        match self {
            Ok(_) => panic!("{message}"),
            Err(e) => e.to_string(),
        }
    }
}

/// On the material that ships, a sandwich cannot be granted, and the refusal says why.
///
/// Changed 2026-09-19. Both authorities that ship state no accuracy in their tokens, so
/// neither puts a number on how wrong its own clock could be and neither bounds a receipt from
/// above. Until that day the arithmetic read the absent field as a stated nought, and this exact
/// receipt was granted a sandwich on a bracket built out of that reading. A bracket is our own
/// narrowness whenever one of its edges came from an assumption we made, and the whole point of
/// the basis field is that it says whose the width is.
///
/// The refusal has to name the reason rather than report the not-later-than role as unchecked. It
/// was checked: the signature holds, the hash matches, the nonce agrees. What it does not do is
/// bound anything in UTC.
#[test]
fn a_sandwich_on_the_shipped_authorities_is_refused_because_no_accuracy_is_stated() {
    let anchors = TrustAnchors::none()
        .with_roughtime("roughtime.se", ROUGHTIME_SE_KEY)
        .with_drand(Chain::quicknet())
        .with_authority(digicert_as_it_ships());

    let claiming = resting_on(all_three());
    let err = validate_with(&claiming, &anchors)
        .unwrap_err_or_else_message("a sandwich resting on an assumed-perfect clock was granted");
    assert!(err.contains("states no accuracy of its own"), "{err}");
    assert!(
        err.contains("A sandwich needs two edges and this one has one"),
        "{err}"
    );
    assert!(
        !err.contains("cannot be checked is not granted"),
        "the witness was checked, and the refusal says it was not: {err}"
    );

    // The same receipt resting on its own model is accepted, because nothing in it is false. What
    // changes is that no edge above it is reported and the reader is told so.
    let mut own_model = resting_on(all_three());
    own_model.claim.basis = EpsilonBasis::LocalModelOnly;
    let verified = validate_with(&own_model, &anchors)
        .expect("a receipt resting on its own model is not refused by this");
    assert!(!verified.basis_granted, "{}", verified.basis_reason);
    assert_eq!(verified.checked(), 3, "all three roles were still checked");
    let bracket = verified.bracket();
    assert_eq!(bracket.not_later, None);
    assert!(bracket.not_later_was_checked_and_bounds_nothing);
    assert!(
        bracket.not_earlier.is_some(),
        "the beacon still bounds it from below"
    );
    assert_eq!(bracket.width(), None);
}

/// A reader's own allowance brings the edge back, and it is the reader's figure that moves it.
///
/// The other half of the rule above. Nothing that ships carries an allowance, so nothing here
/// says an authority's clock is good to any figure. What this holds is the route: a reader who has
/// read an authority's published practice writes what they allow, the not-later edge appears at
/// the instant the token states plus exactly that, and a sandwich becomes possible again.
#[test]
fn a_readers_own_allowance_restores_the_edge_at_exactly_what_was_allowed() {
    for allowed in [0, 250 * NANOS_PER_MILLI, NANOS_PER_SEC] {
        let anchors = TrustAnchors::none()
            .with_roughtime("roughtime.se", ROUGHTIME_SE_KEY)
            .with_drand(Chain::quicknet())
            .with_authority(Authority {
                accuracy_where_the_token_states_none: Some(allowed),
                ..digicert_as_it_ships()
            });
        let mut own_model = resting_on(all_three());
        own_model.claim.basis = EpsilonBasis::LocalModelOnly;
        let verified = validate_with(&own_model, &anchors).expect("the receipt checks out");
        let bracket = verified.bracket();
        assert_eq!(
            bracket.not_later,
            Some(UnixNanos(WITNESS_AT + allowed)),
            "an allowance of {allowed} ns put the edge somewhere else"
        );
        assert!(!bracket.not_later_was_checked_and_bounds_nothing);
    }
}
