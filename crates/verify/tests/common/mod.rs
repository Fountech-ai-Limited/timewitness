//! One receipt that really does rest on three outside signatures, for the verifier tests to hold.
//!
//! The three attestations are the captures the receipt crate's sandwich test uses, included from
//! where they already sit rather than copied, so there is one set of bytes in the tree and it cannot
//! drift. Every one of them was signed by a party that has never heard of this product, four seconds
//! apart, and every test here runs offline against them.
//!
//! Each test file compiles its own copy of this module and uses some of it, so anything one file
//! does not reach reads as dead code in that file's build. The allowance is on the module rather
//! than on the items, because moving it to the items would put it on whichever ones happen to be
//! unused today.

#![allow(dead_code)]

use timewitness_core::evidence::drand::Chain;
use timewitness_core::evidence::rfc3161::Authority;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Evidence, Payload, PolicyRecord, Receipt, Role, Scheme,
    SourceRecord,
};
use timewitness_receipt::AgentKey;

const DRAND: &str = include_str!("../../../receipt/tests/data/sandwich/drand.hex");
const ROUGHTIME: &str = include_str!("../../../receipt/tests/data/sandwich/roughtime.hex");
const RFC3161: &str = include_str!("../../../receipt/tests/data/sandwich/rfc3161.hex");
/// The nonces inside those two captures, kept with them for the same reason: a receipt carrying one
/// of these blobs has to print the same value beside it.
const CORRIDOR_NONCE: &str =
    include_str!("../../../receipt/tests/data/sandwich/roughtime-nonce.hex");
const WITNESS_NONCE: &str = include_str!("../../../receipt/tests/data/sandwich/rfc3161-nonce.hex");

/// The subject all three attestations are about.
pub const SUBJECT: [u8; 32] = [0x5au8; 32];

/// What each of the three states, read off the capture.
pub const BEACON_AT: Nanos = 1_788_806_205 * NANOS_PER_SEC;
pub const CORRIDOR_AT: Nanos = 1_788_806_207 * NANOS_PER_SEC;
pub const CORRIDOR_RADIUS: Nanos = NANOS_PER_SEC;
/// The end of the second the token names, and not its start.
///
/// The capture writes its time to whole seconds, so the edge a receipt may print beside that
/// signature is the end of that second. This moved by one second on 2026-09-09, when the comparison
/// started reading a stated time as the interval it names rather than as an instant.
pub const WITNESS_AT: Nanos = 1_788_806_208 * NANOS_PER_SEC + NANOS_PER_SEC;

/// Half the width of the interval the receipt claims.
///
/// Two seconds, so the claim runs from the beacon's instant to the end of the witness's second and
/// covers the whole of what the two outside signatures enclose. That is what a receipt resting on
/// a sandwich has to claim, from 2026-09-15: the signatures put the moment inside the bracket and
/// say nothing about where, so a narrower claim rests on the signer. It was fifty milliseconds
/// until then, which is what the agent's own model reaches, and the verifier granted the sandwich
/// over it because nothing compared the two.
pub const HALF: Nanos = 2 * NANOS_PER_SEC;

/// The seed the agent key in these tests is built from.
pub const SEED: [u8; 32] = [0x11u8; 32];

pub fn unhex(text: &str) -> Vec<u8> {
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

/// The three things a reader decided to trust before opening anything.
#[must_use]
pub fn anchors() -> TrustAnchors {
    TrustAnchors::none()
        .with_roughtime(
            "roughtime.se",
            [
                0x4b, 0x70, 0x33, 0x7d, 0x92, 0x79, 0x0a, 0x34, 0x9d, 0x90, 0x9d, 0xb5, 0x64, 0x91,
                0x9b, 0xc6, 0xa7, 0x58, 0x3f, 0xf4, 0xa8, 0x13, 0xc7, 0xd7, 0x29, 0x8d, 0x3e, 0x6a,
                0x27, 0x2c, 0x7a, 0x12,
            ],
        )
        .with_drand(Chain::quicknet())
        .with_authority(Authority {
            name: "DigiCert".to_string(),
            url: "http://timestamp.digicert.com".to_string(),
            accepted_certificates: vec![[
                0x2d, 0xa0, 0x9d, 0xa7, 0xf4, 0x13, 0x1f, 0x9f, 0xe7, 0x2d, 0xb6, 0xc5, 0xe6, 0xe9,
                0xc9, 0x65, 0x67, 0x55, 0xaf, 0x04, 0x3f, 0x1e, 0xa7, 0x42, 0xcc, 0x0d, 0x21, 0x20,
                0xe1, 0x41, 0xeb, 0xfc,
            ]],
            // This reader allows nothing for DigiCert's own clock, and that is a statement this
            // reader is making rather than one the token makes. The captured token states no
            // accuracy, so with no figure here it supports no edge in UTC at all and every receipt
            // in these batteries that claims a sandwich would be refused for that one reason
            // instead of for the thing the battery is about. Nothing that ships carries an
            // allowance, and what the change of 2026-09-19 stopped is the code assuming one.
            accuracy_where_the_token_states_none: Some(0),
        })
}

#[must_use]
pub fn corridor() -> Evidence {
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

#[must_use]
pub fn beacon() -> Evidence {
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

#[must_use]
pub fn witness() -> Evidence {
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

/// The agent key these tests sign with.
#[must_use]
pub fn key() -> AgentKey {
    AgentKey::from_seed(&SEED)
}

/// A receipt carrying all three roles, whose reading sits inside the corridor and whose interval is
/// the bracket the two outside signatures enclose, four seconds edge to edge, which is the least a
/// receipt resting on them may claim.
#[must_use]
pub fn receipt() -> Receipt {
    // The network figure sits inside the intersection term and is not added again.
    let breakdown = BreakdownRecord {
        intersection_half: 1_900 * NANOS_PER_MILLI,
        network_half: 400 * NANOS_PER_MILLI,
        scheduling: 50 * NANOS_PER_MILLI,
        oscillator_holdover: 20 * NANOS_PER_MILLI,
        model_residual: 20 * NANOS_PER_MILLI,
        safety_margin: 10 * NANOS_PER_MILLI,
        unclaimed_rate: None,
    };
    assert_eq!(breakdown.half_width(), HALF);

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
            earliest: UnixNanos(CORRIDOR_AT - HALF),
            latest: UnixNanos(CORRIDOR_AT + HALF),
            basis: EpsilonBasis::ThirdPartySandwich,
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
                source_interval_floor: None,
                frequency_slew_ppb_per_s: None,
                frequency_span_ppb: None,
            },
            taken_by: None,
        },
        evidence: vec![corridor(), beacon(), witness()],
        agent_public_key: key().public_key_bytes(),
    }
}

/// That receipt, signed, which is all a stranger ever has.
#[must_use]
pub fn signed() -> Vec<u8> {
    key()
        .sign(&receipt())
        .expect("the agent signs its own receipt")
}

/// The same receipt, resting on its own model rather than on a sandwich.
///
/// For a reader holding no anchors. Every attestation is still carried, so every byte of them is
/// still under the signature; what changes is the claim the receipt makes about what its bound
/// rests on, which a reader with nothing to check the attestations against could not grant anyway.
#[must_use]
pub fn receipt_local_only() -> Receipt {
    let mut receipt = receipt();
    receipt.claim.basis = EpsilonBasis::LocalModelOnly;
    receipt
}

/// That receipt, signed.
#[must_use]
pub fn signed_local_only() -> Vec<u8> {
    key()
        .sign(&receipt_local_only())
        .expect("the agent signs its own receipt")
}

/// The sandwich receipt with the interval the agent's own model reaches, a hundred milliseconds
/// round the reading, still claiming that its bound rests on the three signatures.
///
/// This is the receipt the verifier granted until 2026-09-15. The signatures enclose four seconds
/// and the claim picks a hundred milliseconds out of them on nothing but the signer's word.
#[must_use]
pub fn receipt_narrower_than_its_bracket() -> Receipt {
    let half = 50 * NANOS_PER_MILLI;
    let mut receipt = receipt();
    receipt.claim.earliest = UnixNanos(CORRIDOR_AT - half);
    receipt.claim.latest = UnixNanos(CORRIDOR_AT + half);
    receipt.claim.breakdown = BreakdownRecord {
        intersection_half: 30 * NANOS_PER_MILLI,
        network_half: 12 * NANOS_PER_MILLI,
        scheduling: 5 * NANOS_PER_MILLI,
        oscillator_holdover: 5 * NANOS_PER_MILLI,
        model_residual: 5 * NANOS_PER_MILLI,
        safety_margin: 5 * NANOS_PER_MILLI,
        unclaimed_rate: None,
    };
    assert_eq!(receipt.claim.breakdown.half_width(), half);
    receipt
}

/// That receipt, signed.
#[must_use]
pub fn signed_narrower_than_its_bracket() -> Vec<u8> {
    key()
        .sign(&receipt_narrower_than_its_bracket())
        .expect("the agent signs its own receipt")
}
