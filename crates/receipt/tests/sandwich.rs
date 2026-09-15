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
//! Everything here runs offline. Every signature in it was made by somebody who has never heard of
//! this product.

use timewitness_core::evidence::drand::Chain;
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
/// wide, which is what an ordinary machine on the public internet actually manages.
fn receipt(basis: EpsilonBasis, evidence: Vec<Evidence>) -> Receipt {
    let half = 50 * NANOS_PER_MILLI;
    let breakdown = BreakdownRecord {
        intersection_half: 30 * NANOS_PER_MILLI,
        network_half: 12 * NANOS_PER_MILLI,
        scheduling: 5 * NANOS_PER_MILLI,
        oscillator_holdover: 5 * NANOS_PER_MILLI,
        model_residual: 5 * NANOS_PER_MILLI,
        safety_margin: 5 * NANOS_PER_MILLI,
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
            },
        },
        evidence,
        agent_public_key: vec![0u8; 32],
    }
}

fn all_three() -> Vec<Evidence> {
    vec![corridor(), beacon(), witness()]
}

// ---------------------------------------------------------------------------------------------
// The one that has to pass.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_bound_resting_on_three_real_signatures_is_granted() {
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
    let verified = validate_with(&receipt, &anchors())
        .expect("a receipt whose evidence was all captured and all checks out");

    assert!(verified.basis_granted, "{}", verified.basis_reason);
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
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
    let err = validate(&receipt).expect_err("a sandwich granted with no anchors at all");
    assert!(matches!(err, ReceiptError::OurClaimAsEvidence(_)), "{err}");
}

#[test]
fn a_verifier_holding_two_of_the_three_grants_nothing() {
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
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
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a spoiled corridor response");
    assert!(matches!(err, ReceiptError::Inconsistent(_)), "{err}");
    assert!(err.to_string().contains("roughtime"), "{err}");
}

#[test]
fn a_beacon_round_that_does_not_verify_refuses_the_whole_receipt() {
    let mut evidence = all_three();
    let last = evidence[1].blob.len() - 1;
    evidence[1].blob[last] ^= 0x01;
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a spoiled drand round");
    assert!(err.to_string().contains("drand"), "{err}");
}

#[test]
fn a_token_that_does_not_verify_refuses_the_whole_receipt() {
    let mut evidence = all_three();
    let last = evidence[2].blob.len() - 1;
    evidence[2].blob[last] ^= 0x01;
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
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
        let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
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
    let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
    let err = validate_with(&receipt, &anchors()).expect_err("a widened corridor");
    assert!(err.to_string().contains("radius"), "{err}");
}

#[test]
fn a_corridor_bound_to_somebody_elses_subject_is_refused() {
    // The nonce in this response was derived from the subject of the capture. A receipt stamping
    // something else, and offering that response as its corridor, is offering a genuine signature
    // about a different document.
    let mut receipt = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
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
    for (index, name) in [(1usize, "drand"), (2, "rfc3161")] {
        let mut evidence = all_three();
        evidence[index].radius = Some(365 * 24 * 3_600 * NANOS_PER_SEC);
        let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} entry printing a year of radius beside a real signature was accepted"
        ));
        assert!(err.contains(name), "{err}");
        assert!(
            err.contains("reaches outside the one the signature supports"),
            "{err}"
        );
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
        let receipt = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} entry printing a nonce nothing signed was accepted"
        ));
        assert!(err.contains(name), "{err}");
        assert!(err.contains("made over a different"), "{err}");
    }

    // And a beacon, which signs over no nonce at all, so any nonce printed beside one is decoration.
    let mut evidence = all_three();
    evidence[1].nonce = Some(vec![9u8; 32]);
    let planted = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
    let err = validate_with(&planted, &anchors())
        .unwrap_err_or_else_message("a drand entry printing a nonce was accepted");
    assert!(err.contains("drand"), "{err}");
    assert!(err.contains("rests on nothing"), "{err}");

    // A receipt that prints no nonce claims nothing about one, and stays acceptable. Quieter than
    // the evidence is allowed; louder is what the rule refuses.
    let mut evidence = all_three();
    evidence[2].nonce = None;
    let quieter = receipt(EpsilonBasis::ThirdPartySandwich, evidence);
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
        let claiming = receipt(EpsilonBasis::ThirdPartySandwich, all_three());
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
/// One byte is changed in the signed part of each capture. The reader holds the right key for each,
/// so this is not a fact about the reader; it is a signature that does not check out, and a receipt
/// carrying one is wrong.
#[test]
fn an_attestation_that_fails_under_a_key_the_reader_holds_for_its_signer_is_still_refused() {
    for (index, name) in [(0usize, "roughtime"), (1, "drand"), (2, "rfc3161")] {
        let mut evidence = all_three();
        let last = evidence[index].blob.len() - 1;
        evidence[index].blob[last] ^= 0x01;
        let receipt = receipt(EpsilonBasis::LocalModelOnly, evidence);
        let err = validate_with(&receipt, &anchors()).unwrap_err_or_else_message(&format!(
            "a {name} attestation with a byte changed was accepted under the key it names"
        ));
        assert!(err.contains(name), "{err}");
        assert!(err.contains("does not check out against"), "{err}");
    }
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
