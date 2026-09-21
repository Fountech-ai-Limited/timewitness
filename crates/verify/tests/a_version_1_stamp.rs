//! A real version 1 receipt, checked by a stranger holding only what is published.
//!
//! `data/a-version-1-stamp/` was taken from the real servers with a witness over its own signature.
//! This is where the witness is shown to check against a pinned authority rather than only to be
//! refused when it is wrong, which is all a test without a live token can show.

use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::value::Value;
use timewitness_receipt::{cbor, open_with, TakenBy, SIGNATURE_WITNESS};
use timewitness_verify::{anchor_file, verify, Floor, Subject};

/// The receipt, written out as hex so the repository stays text end to end. One binary file is
/// allowed in this tree and it is named in `scripts/repo-hygiene.sh`; a second is not needed for a
/// fixture a test can read just as well from its hex.
const RECEIPT_HEX: &str = include_str!("data/a-version-1-stamp/receipt.hex");
const SUBJECT: &[u8] = include_bytes!("data/a-version-1-stamp/subject.bin");

fn receipt() -> Vec<u8> {
    let digits: Vec<u8> = RECEIPT_HEX
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

fn published() -> TrustAnchors {
    anchor_file::published()
}

#[test]
fn a_stranger_holding_the_published_keys_checks_the_witness_over_the_signature() {
    let (receipt, report) = open_with(&receipt(), &published()).expect("the receipt opens");
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.claim.taken_by, Some(TakenBy::OneShot));
    assert!(receipt.claim.policy.states_the_width_terms());
    let witness = report
        .signature_witness
        .as_ref()
        .expect("this receipt carries a witness over its signature");
    assert!(witness.outcome.is_checked(), "{:?}", witness.outcome);
    assert!(
        report
            .lines()
            .iter()
            .any(|l| l.starts_with("The signature itself is witnessed")),
        "{:?}",
        report.lines()
    );
}

#[test]
fn the_whole_verifier_accepts_it_against_its_subject() {
    let assessment = verify(
        &receipt(),
        Subject::Bytes(SUBJECT),
        &published(),
        &Floor::default(),
    );
    assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
}

fn header_of(signed: &[u8]) -> Vec<(Value, Value)> {
    let envelope = cbor::decode(signed).unwrap();
    match &envelope.as_array().unwrap()[1] {
        Value::Map(pairs) => pairs.clone(),
        _ => panic!("the header is a map"),
    }
}

fn with_header(signed: &[u8], header: Vec<(Value, Value)>) -> Vec<u8> {
    let envelope = cbor::decode(signed).unwrap();
    let mut parts = envelope.as_array().unwrap().to_vec();
    parts[1] = Value::Map(header);
    cbor::encode(&Value::Array(parts))
}

#[test]
fn a_witness_altered_by_one_byte_refuses_the_receipt() {
    let mut header = header_of(&receipt());
    for (k, v) in &mut header {
        if k.as_text() == Some(SIGNATURE_WITNESS) {
            let Value::Bytes(blob) = v else {
                panic!("the witness is bytes")
            };
            let last = blob.len() - 1;
            blob[last] ^= 1;
        }
    }
    assert!(open_with(&with_header(&receipt(), header), &published()).is_err());
}

#[test]
fn dropping_the_witness_leaves_a_receipt_that_places_only_its_subject() {
    // What a holder without the key can do. The result verifies, reports no witness, and is a
    // different file with a different chain link, so it is never the receipt the signer wrote.
    let header: Vec<(Value, Value)> = header_of(&receipt())
        .into_iter()
        .filter(|(k, _)| k.as_text() != Some(SIGNATURE_WITNESS))
        .collect();
    let dropped = with_header(&receipt(), header);
    let (_, report) = open_with(&dropped, &published()).expect("still a receipt");
    assert_eq!(report.signature_witness, None);
    assert_ne!(
        timewitness_receipt::chain_link(&dropped),
        timewitness_receipt::chain_link(&receipt())
    );
}
