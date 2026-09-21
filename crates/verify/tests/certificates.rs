//! Whether a receipt is a TimeWitness certificate, judged on outside evidence alone.
//!
//! Every receipt here is real at its signatures: the beacon, the corridor and the witness were
//! signed by parties who have never heard of this product, and the one token over a key log head
//! in `data/a-certifying-log/` was taken from DigiCert over the head these tests build. What is
//! made up is the key log itself, signed by a key these tests hold for us, and the moment
//! certification began, which the reader names in their trust material.
//!
//! The rule under test: the key has to be certified for a window holding both the beacon inside the
//! signature and the witness after it. The receipt's own reading decides nothing, and several of the
//! receipts below have a reading inside a window while their evidence sits outside it.

mod common;

use common::{BEACON_AT, CORRIDOR_AT, SUBJECT, WITNESS_AT};
use timewitness_core::keylog::file::{sign_head, sign_head_after, KeyLog};
use timewitness_core::keylog::{Issued, KeyEntry, Role};
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::{open_with, AgentKey};
use timewitness_verify::certificate::{Grade, NotCertified, NotChecked, Places};
use timewitness_verify::{
    anchor_file, verify, verify_with_key_log, Assessment, Floor, Subject, CERTIFICATE_QUESTION,
    KEY_LOG_QUESTION,
};

/// The secret half of the key these tests hold for our log. Made up; the real one is never here.
const OURS: [u8; 32] = [3u8; 32];

/// When certification began, for these tests: a thousand seconds before the beacon.
const BEGAN: i128 = (1_788_806_205 - 1_000) * NANOS_PER_SEC;

const WITNESS_OVER_THE_CUTOFF_HEAD: &str =
    include_str!("data/a-certifying-log/cutoff-head-witness.hex");

const SECOND: i128 = NANOS_PER_SEC;

fn our_key() -> [u8; 32] {
    sign_head(&KeyLog::default(), &OURS, UnixNanos(0)).signed_by
}

fn anchors_from(began: i128) -> TrustAnchors {
    let mut anchors = common::anchors().with_key_log_signer("ours, for these tests", our_key());
    anchors.certification_began = Some(UnixNanos(began));
    anchors
}

fn anchors() -> TrustAnchors {
    anchors_from(BEGAN)
}

fn agent_key() -> [u8; 32] {
    common::key()
        .public_key_bytes()
        .try_into()
        .expect("32 bytes")
}

fn certificate(key: [u8; 32], from: i128, until: i128) -> KeyEntry {
    KeyEntry {
        public_key: key,
        role: Role::Certificate,
        deployment: "a build runner".to_string(),
        valid_from: UnixNanos(from),
        valid_until: Some(UnixNanos(until)),
        issued: Some(Issued {
            organisation: "org-1".to_string(),
            method: "machine-credential".to_string(),
        }),
    }
}

/// The log as far as the cutoff: one entry, under a head carrying the beacon and the witness.
///
/// Built exactly as the head the witness was taken over was built, so the token checks.
fn cutoff_only() -> KeyLog {
    let mut log = KeyLog::default();
    log.entries.push(KeyEntry {
        public_key: our_key(),
        role: Role::Cutoff,
        deployment: "certification begins".to_string(),
        valid_from: UnixNanos(BEGAN),
        valid_until: None,
        issued: None,
    });
    let mut head = sign_head_after(
        &log,
        &OURS,
        UnixNanos(BEACON_AT + 60 * SECOND),
        Some(common::beacon().blob),
    );
    head.witness = Some(common::unhex(WITNESS_OVER_THE_CUTOFF_HEAD));
    log.head = Some(head);
    log
}

/// Append entries under one new head carrying `beacon`, as the app does.
fn append(mut log: KeyLog, entries: Vec<KeyEntry>, beacon: Vec<u8>, at: i128) -> KeyLog {
    if let Some(head) = log.head.take() {
        log.checkpoints.push(head);
    }
    log.entries.extend(entries);
    log.head = Some(sign_head_after(&log, &OURS, UnixNanos(at), Some(beacon)));
    log
}

/// The cutoff, then a certificate for these entries under a head carrying the same beacon.
fn certifying(entries: Vec<KeyEntry>) -> KeyLog {
    append(
        cutoff_only(),
        entries,
        common::beacon().blob,
        WITNESS_AT + 100 * SECOND,
    )
}

/// A certificate whose window holds both outside instants of the common receipt.
fn the_right_window() -> KeyEntry {
    certificate(agent_key(), BEACON_AT, WITNESS_AT + 3_600 * SECOND)
}

fn assess(signed: &[u8], log: Option<&KeyLog>, anchors: &TrustAnchors) -> Assessment {
    verify_with_key_log(
        signed,
        Subject::Digest(&SUBJECT),
        anchors,
        &Floor::default(),
        log,
    )
}

fn grade(signed: &[u8], log: Option<&KeyLog>) -> Grade {
    let a = assess(signed, log, &anchors());
    assert!(a.accepted(), "{:?}", a.refusal());
    a.certificate
        .expect("a grade where certification has begun")
}

#[test]
fn a_certified_key_with_both_outside_instants_inside_its_window_is_held() {
    let log = certifying(vec![the_right_window()]);
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert!(a.holds(), "{:?}", a.certificate);
    match a.certificate.as_ref().expect("graded") {
        Grade::Held {
            not_earlier,
            not_later,
            places,
            organisation,
            ..
        } => {
            assert_eq!(*not_earlier, UnixNanos(BEACON_AT));
            assert_eq!(not_later.at, UnixNanos(WITNESS_AT));
            assert_eq!(
                *places,
                Places::TheSubject,
                "a version 0 receipt has no witness over its signature"
            );
            assert_eq!(organisation, "org-1");
        }
        other => panic!("{other:?}"),
    }
    assert!(a
        .headline()
        .starts_with("Held as a TimeWitness certificate"));
    let detail = a.certificate.as_ref().unwrap().detail();
    assert!(detail.contains("not third-party evidence"), "{detail}");
    assert!(
        detail.contains("places the subject and not the signing"),
        "{detail}"
    );
    let step = a.step(KEY_LOG_QUESTION).expect("asked");
    assert!(
        matches!(step.state, timewitness_verify::State::Held(_)),
        "{step:?}"
    );
}

#[test]
fn a_reading_inside_a_window_is_not_enough_when_the_evidence_sits_outside_it() {
    // The reading is the corridor's instant, and this window holds it by half a second either side.
    // The beacon is two seconds before the window and the witness two seconds after.
    let tight = certificate(
        agent_key(),
        CORRIDOR_AT - SECOND / 2,
        CORRIDOR_AT + SECOND / 2,
    );
    let log = certifying(vec![tight]);
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert_eq!(
        a.receipt.as_ref().unwrap().utc_estimate,
        UnixNanos(CORRIDOR_AT),
        "the reading sits inside the window"
    );
    assert!(matches!(
        a.certificate,
        Some(Grade::Not(NotCertified::NotCertifiedThen(_)))
    ));
    assert!(!a.holds());
    assert_eq!(
        a.headline(),
        "Not a TimeWitness certificate: this key was not certified by the TimeWitness app"
    );
}

#[test]
fn evidence_straddling_either_edge_of_a_window_is_not_held() {
    for window in [
        certificate(agent_key(), BEACON_AT + SECOND, WITNESS_AT + 3_600 * SECOND),
        certificate(agent_key(), BEACON_AT, WITNESS_AT - SECOND),
    ] {
        let log = certifying(vec![window.clone()]);
        let g = grade(&common::signed(), Some(&log));
        assert!(
            matches!(g, Grade::Not(NotCertified::NotCertifiedThen(_))),
            "{window:?}: {g:?}"
        );
    }
}

#[test]
fn a_receipt_with_no_checked_witness_is_not_placed_and_is_not_held() {
    let mut receipt = common::receipt();
    receipt.evidence = vec![common::corridor(), common::beacon()];
    receipt.claim.basis = EpsilonBasis::LocalModelOnly;
    let signed = common::key().sign(&receipt).expect("signed");
    let log = certifying(vec![the_right_window()]);
    let a = assess(&signed, Some(&log), &anchors());
    assert_eq!(
        a.certificate,
        Some(Grade::Not(NotCertified::NothingPlacesIt))
    );
    assert_eq!(
        a.headline(),
        "Not a TimeWitness certificate: nothing outside this receipt places when it was signed"
    );
    assert!(!a.holds());
}

#[test]
fn an_uncertified_key_is_not_a_certificate_and_its_outside_signatures_still_print() {
    let other = AgentKey::from_seed(&[0x22; 32]);
    let mut receipt = common::receipt();
    receipt.agent_public_key = other.public_key_bytes();
    let signed = other.sign(&receipt).expect("signed");
    let log = certifying(vec![the_right_window()]);
    let a = assess(&signed, Some(&log), &anchors());
    assert!(a.accepted(), "every version 0 check still holds");
    assert!(!a.holds());
    assert_eq!(
        a.headline(),
        "Not a TimeWitness certificate: this key was not certified by the TimeWitness app"
    );
    assert_eq!(
        a.checked_entries(),
        3,
        "and the three outside signatures still check"
    );
    assert!(a
        .verdict()
        .contains("all 3 of its attestations were checked"));
}

#[test]
fn a_key_retired_before_the_witness_is_not_held() {
    let log = certifying(vec![the_right_window()]);
    let retired = KeyEntry {
        public_key: agent_key(),
        role: Role::Retired,
        deployment: "retired".to_string(),
        valid_from: UnixNanos(WITNESS_AT - SECOND),
        valid_until: None,
        issued: None,
    };
    let log = append(
        log,
        vec![retired],
        common::beacon().blob,
        WITNESS_AT + 200 * SECOND,
    );
    let g = grade(&common::signed(), Some(&log));
    match g {
        Grade::Not(NotCertified::NotCertifiedThen(why)) => {
            assert!(why.contains("retired"), "{why}")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn no_copy_and_a_copy_that_ends_before_the_signing_are_each_not_checked() {
    let a = assess(&common::signed(), None, &anchors());
    assert_eq!(a.certificate, Some(Grade::Unchecked(NotChecked::NoCopy)));
    assert_eq!(
        a.headline(),
        "Not checked as a TimeWitness certificate: no copy of the key log was given"
    );
    assert!(!a.holds(), "exits 1");

    // A copy whose newest head our clock dates two seconds after the beacon, before the witness,
    // and which certifies nothing yet.
    let server = KeyEntry {
        public_key: [9u8; 32],
        role: Role::Server,
        deployment: "a roughtime server of ours".to_string(),
        valid_from: UnixNanos(0),
        valid_until: None,
        issued: None,
    };
    let stale = append(
        cutoff_only(),
        vec![server],
        common::beacon().blob,
        BEACON_AT + 2 * SECOND,
    );
    let a = assess(&common::signed(), Some(&stale), &anchors());
    assert_eq!(a.certificate, Some(Grade::Unchecked(NotChecked::Stale)));
    assert!(a.headline().ends_with("Fetch a newer copy"));
    assert!(!a.holds());
}

#[test]
fn a_log_stating_a_different_cutoff_is_refused() {
    let log = certifying(vec![the_right_window()]);
    let a = assess(&common::signed(), Some(&log), &anchors_from(BEGAN + 1));
    assert!(!a.accepted());
    let refusal = a.refusal().expect("refused");
    assert_eq!(refusal.question, KEY_LOG_QUESTION);
    assert!(refusal
        .state
        .detail()
        .contains("states certification began at"));
    assert!(a.certificate.is_none());
}

#[test]
fn a_log_certifying_a_window_before_the_cutoff_is_refused() {
    let early = certificate(agent_key(), BEGAN - SECOND, WITNESS_AT + SECOND);
    let log = certifying(vec![early]);
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert!(!a.accepted());
    assert!(a
        .refusal()
        .unwrap()
        .state
        .detail()
        .contains("before certification began"));
}

#[test]
fn a_certificate_whose_window_began_before_the_head_that_published_it_is_refused() {
    // The window holds both instants, and it starts a second before the beacon in the head that
    // first carried it, so it certified a window that had already begun when it was written.
    let backdated = certificate(agent_key(), BEACON_AT - SECOND, WITNESS_AT + 3_600 * SECOND);
    let log = certifying(vec![backdated]);
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert!(!a.holds());
    let refusal = a.refusal().expect("refused");
    assert_eq!(refusal.question, CERTIFICATE_QUESTION);
}

#[test]
fn a_cutoff_whose_head_carries_no_witness_or_no_beacon_is_refused() {
    let mut log = certifying(vec![the_right_window()]);
    log.checkpoints[0].witness = None;
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert!(!a.accepted());
    assert!(a.refusal().unwrap().state.detail().contains("no witness"));

    // A witness taken over some other head does not check over this one.
    let mut log = certifying(vec![the_right_window()]);
    let mut other = cutoff_only();
    other.head.as_mut().unwrap().head.at = UnixNanos(BEACON_AT + 61 * SECOND);
    let resigned = sign_head_after(
        &KeyLog {
            entries: other.entries.clone(),
            ..KeyLog::default()
        },
        &OURS,
        UnixNanos(BEACON_AT + 61 * SECOND),
        Some(common::beacon().blob),
    );
    let mut moved = resigned;
    moved.witness = log.checkpoints[0].witness.clone();
    log.checkpoints[0] = moved;
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert!(!a.holds());
}

#[test]
fn a_log_signed_by_anybody_else_certifies_nothing() {
    let mut log = certifying(vec![the_right_window()]);
    let theirs = sign_head_after(
        &KeyLog {
            entries: log.entries.clone(),
            ..KeyLog::default()
        },
        &[4u8; 32],
        UnixNanos(WITNESS_AT + 100 * SECOND),
        Some(common::beacon().blob),
    );
    log.head = Some(theirs);
    let a = assess(&common::signed(), Some(&log), &anchors());
    assert_eq!(a.certificate, Some(Grade::Unchecked(NotChecked::NotOurs)));
    assert!(!a.holds());
}

/// A committed receipt, off its hex.
fn committed(hex: &str) -> Vec<u8> {
    common::unhex(hex)
}

#[test]
fn the_committed_receipts_were_signed_before_certification_and_never_say_certificate() {
    // Certification is put a year after both, as the release that fixes it will.
    let mut published = anchor_file::published();
    published.certification_began = Some(UnixNanos(1_820_000_000 * SECOND));
    let real = include_bytes!("data/a-real-stamp/receipt.cbor");
    let real_subject = include_bytes!("data/a-real-stamp/subject.bin");
    let install = committed(include_str!("data/a-runner-receipt-2026-09-14/receipt.hex"));
    for (name, bytes, subject) in [
        ("a-real-stamp", real.to_vec(), Subject::Bytes(real_subject)),
        ("a-runner-receipt-2026-09-14", install, Subject::NotSupplied),
    ] {
        let a = verify(&bytes, subject, &published, &Floor::default());
        assert!(a.accepted(), "{name}: {:?}", a.refusal());
        match &a.certificate {
            Some(Grade::BeforeCertification { witnessed, .. }) => {
                assert!(
                    witnessed.on_its_own_clock,
                    "{name}: a shipped authority states no accuracy"
                );
            }
            other => panic!("{name}: {other:?}"),
        }
        assert!(a.holds(), "{name}");
        assert_eq!(
            a.headline(),
            a.verdict(),
            "{name}: the version 0 verdict is the first line"
        );
        let detail = a.certificate.as_ref().unwrap().detail();
        assert!(
            detail.starts_with("Signed before certification began"),
            "{name}"
        );
        assert!(
            !detail.contains("TimeWitness certificate"),
            "{name}: {detail}"
        );
        assert!(!a.headline().contains("TimeWitness certificate"), "{name}");
    }
}

#[test]
fn with_no_cutoff_held_nothing_changes() {
    // What ships today: certification has not begun, so there is no grade and the exit code is the
    // version 0 one, on a receipt and a log either way.
    assert_eq!(anchor_file::CERTIFICATION_BEGAN, None);
    let published = anchor_file::published();
    assert!(published.certification_began.is_none());
    let real = include_bytes!("data/a-real-stamp/receipt.cbor");
    let a = verify(real, Subject::NotSupplied, &published, &Floor::default());
    assert!(a.certificate.is_none());
    assert_eq!(a.holds(), a.accepted());
    assert_eq!(a.headline(), a.verdict());
}

#[test]
fn a_version_1_receipt_is_placed_by_the_witness_over_its_own_signature() {
    let signed = committed(include_str!("data/a-version-1-stamp/receipt.hex"));
    let published = anchor_file::published();
    let (receipt, report) = open_with(&signed, &published).expect("opens");
    let key: [u8; 32] = receipt
        .agent_public_key
        .clone()
        .try_into()
        .expect("32 bytes");
    let beacon = receipt
        .evidence
        .iter()
        .find(|e| e.scheme.as_str() == "drand")
        .expect("a beacon")
        .clone();
    let round_at = report.bracket().not_earlier.expect("a checked beacon");

    // Its beacon is the one the head certifying it carries, so the window may start there.
    let log = append(
        cutoff_only(),
        vec![certificate(
            key,
            round_at.as_nanos(),
            round_at.as_nanos() + 86_400 * SECOND,
        )],
        beacon.blob,
        round_at.as_nanos() + 3_600 * SECOND,
    );
    let mut anchors = published.with_key_log_signer("ours, for these tests", our_key());
    anchors.certification_began = Some(UnixNanos(BEGAN));
    let a = verify_with_key_log(
        &signed,
        Subject::NotSupplied,
        &anchors,
        &Floor::default(),
        Some(&log),
    );
    assert!(a.accepted(), "{:?}", a.refusal());
    match &a.certificate {
        Some(Grade::Held {
            places, not_later, ..
        }) => {
            assert_eq!(*places, Places::TheSigning);
            assert!(not_later.on_its_own_clock);
        }
        other => panic!("{other:?}"),
    }
    assert!(a.holds());
}
