//! A witness over the subject says when the subject existed, and never when the receipt was signed.
//!
//! The certificate grade excuses a missing certificate for a receipt signed before certification
//! began. Until 2026-09-23 it counted a witness over the subject as dating the signing, so anybody
//! holding an old timestamp token over a payload could sign that payload after certification began,
//! with a key nobody certified, and have the receipt graded as one signed before it. A checked beacon
//! in the same receipt put the signing ten minutes after the cutoff and the grade did not look at it.
//!
//! Now only a witness over the receipt's own signature dates the signing, and a checked beacon at or
//! after the cutoff refuses the grade outright, since the signing cannot have come before a value it
//! carries inside the signature.

mod common;

use common::{SUBJECT, WITNESS_AT};
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::{AgentKey, Evidence, Receipt};
use timewitness_verify::certificate::Grade;
use timewitness_verify::{anchor_file, verify, verify_with_key_log, Floor, Subject};

/// A real quicknet round, 1202 s after the old witness, taken from the public chain.
fn a_later_beacon() -> (Evidence, i128) {
    let chain: [u8; 32] =
        common::unhex("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
            .try_into()
            .unwrap();
    let sig = common::unhex(
        "b64efde5869f685709115b55453a4ac486b3635264b5aee56626307bde70ec0629b8705b625b32b7b206e9a8f041889e",
    );
    let at: i128 = 1_788_807_411 * NANOS_PER_SEC;
    let mut beacon = common::beacon();
    beacon.blob = timewitness_core::evidence::drand::pack_blob(&chain, 32_001_349, &sig);
    beacon.at = UnixNanos(at);
    beacon.detail = Some("drand quicknet round 32001349".to_string());
    (beacon, at)
}

/// A receipt over the committed subject, carrying `evidence`, signed by a key nobody certified,
/// with an interval wide enough to hold every instant any of the evidence states.
fn signed_by_a_stranger(evidence: Vec<Evidence>, to: i128) -> Vec<u8> {
    let mut r: Receipt = common::receipt();
    r.claim.basis = EpsilonBasis::LocalModelOnly;
    let earliest = WITNESS_AT - 100 * NANOS_PER_SEC;
    let latest = to + 100 * NANOS_PER_SEC;
    let half = (latest - earliest) / 2;
    let mid = earliest + half;
    r.utc_estimate = UnixNanos(mid);
    r.claim.earliest = UnixNanos(mid - half);
    r.claim.latest = UnixNanos(mid + half);
    let fixed = r.claim.breakdown.scheduling
        + r.claim.breakdown.oscillator_holdover
        + r.claim.breakdown.model_residual
        + r.claim.breakdown.safety_margin;
    r.claim.breakdown.intersection_half = half - fixed;
    r.claim.policy.max_bound_width = 3_600 * NANOS_PER_SEC;
    r.evidence = evidence;
    let key = AgentKey::from_seed(&[0x77u8; 32]);
    r.agent_public_key = key.public_key_bytes();
    key.sign(&r).expect("signs")
}

fn graded(signed: &[u8], began: i128) -> Grade {
    let mut anchors = common::anchors();
    anchors.certification_began = Some(UnixNanos(began));
    let a = verify_with_key_log(
        signed,
        Subject::Digest(&SUBJECT),
        &anchors,
        &Floor::default(),
        None,
    );
    assert!(a.accepted(), "refused: {:?}", a.refusal());
    a.certificate
        .expect("certification has begun, so there is a grade")
}

#[test]
fn a_checked_beacon_after_the_cutoff_refuses_the_grade_whatever_the_subject_witness_says() {
    let (beacon, beacon_at) = a_later_beacon();
    let began = WITNESS_AT + 600 * NANOS_PER_SEC;
    assert!(WITNESS_AT < began && began < beacon_at);
    let grade = graded(
        &signed_by_a_stranger(vec![beacon, common::witness()], beacon_at),
        began,
    );
    assert!(
        !matches!(grade, Grade::BeforeCertification { .. }),
        "a receipt the beacon puts {} s after the cutoff was graded as signed before it: {grade:?}",
        (beacon_at - began) / NANOS_PER_SEC
    );
    assert!(!grade.stands(), "{grade:?}");
}

#[test]
fn leaving_the_beacon_out_does_not_let_an_old_subject_witness_date_the_signing() {
    // The same stranger, who holds the key and so chooses what the receipt carries, drops the beacon.
    let began = WITNESS_AT + 600 * NANOS_PER_SEC;
    let grade = graded(
        &signed_by_a_stranger(vec![common::witness()], WITNESS_AT),
        began,
    );
    assert!(
        !matches!(grade, Grade::BeforeCertification { .. }),
        "a witness over the subject dated the signing: {grade:?}"
    );
    assert!(!grade.stands(), "{grade:?}");
}

#[test]
fn a_witness_over_the_signature_before_the_cutoff_still_dates_the_signing() {
    // The committed version 1 receipt carries one, taken on 2026-09-21, and certification is put a
    // year later.
    let signed = common::unhex(include_str!("data/a-version-1-stamp/receipt.hex"));
    let mut published = anchor_file::published();
    published.certification_began = Some(UnixNanos(1_820_000_000 * NANOS_PER_SEC));
    let a = verify(
        &signed,
        Subject::Bytes(include_bytes!("data/a-version-1-stamp/subject.bin")),
        &published,
        &Floor::default(),
    );
    assert!(a.accepted(), "refused: {:?}", a.refusal());
    assert!(
        matches!(a.certificate, Some(Grade::BeforeCertification { .. })),
        "{:?}",
        a.certificate
    );
}
