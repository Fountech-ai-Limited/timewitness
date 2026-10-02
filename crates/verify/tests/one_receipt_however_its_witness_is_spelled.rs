//! A version 1 receipt is one receipt, and its witness has one spelling.
//!
//! The witness sits in the unprotected header, outside the signature, and an RFC 3161 token holds
//! plenty its own signature does not cover: the request stored beside it, the certificates it carries
//! besides the one the reader pins, the framing round the signed parts. On 2026-09-23 a sweep flipped
//! each bit of the witness on the committed version 1 receipt in turn, and 10,156 of 32,034 flips
//! still verified, each as a file with a hash of its own. The next receipt in a chain names its
//! predecessor by that hash, so a holder with no key could fork or break a chain whose unbroken order
//! is half of what this product claims.
//!
//! Two rules answer it. A receipt's hash is of the receipt as its agent signed it, with the witness
//! set aside, so dropping the witness or putting another token in its place never makes a second
//! receipt.
//! And from 2026-09-24 the witness is held to the one spelling its signatures bind, so no flip inside
//! it verifies at all. `every_bit_of_a_receipt.rs` changes every bit of this receipt, witness and all,
//! and requires every change to be refused; what is left here is the first rule.

use timewitness_receipt::value::Value;
use timewitness_receipt::{cbor, chain_link, SIGNATURE_WITNESS};
use timewitness_verify::{anchor_file, verify, Floor, Subject};

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

/// The receipt with the witness over its signature taken out, which is the file its agent wrote
/// before the witness came back.
fn without_the_witness(signed: &[u8]) -> Vec<u8> {
    let envelope = cbor::decode(signed).unwrap();
    let mut parts = envelope.as_array().unwrap().to_vec();
    let Value::Map(pairs) = &parts[1] else {
        panic!("the header is a map")
    };
    parts[1] = Value::Map(
        pairs
            .iter()
            .filter(|(k, _)| k.as_text() != Some(SIGNATURE_WITNESS))
            .cloned()
            .collect(),
    );
    cbor::encode(&Value::Array(parts))
}

#[test]
fn the_hash_is_of_the_receipt_as_its_agent_signed_it() {
    let original = receipt();
    let bare = without_the_witness(&original);
    assert!(bare.len() < original.len());
    assert_eq!(chain_link(&original), chain_link(&bare));

    // And without the witness it is still a receipt, one that says nothing about when it was signed.
    let assessment = verify(
        &bare,
        Subject::Bytes(SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
    );
    assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
}

#[test]
fn a_version_0_receipt_hashes_as_the_file_it_is() {
    let file = include_bytes!("data/a-real-stamp/receipt.cbor");
    assert_eq!(
        chain_link(file),
        timewitness_receipt::sha256_payload(file).hash
    );
}

#[test]
fn another_genuine_witness_leaves_it_the_same_receipt() {
    let decode = |text: &str| -> Vec<u8> {
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
    };
    let original = receipt();
    for again in [
        decode(include_str!(
            "data/a-version-1-stamp-witnessed-again/sectigo.hex"
        )),
        decode(include_str!(
            "data/a-version-1-stamp-witnessed-again/digicert.hex"
        )),
    ] {
        assert_ne!(again, original);
        assert_eq!(chain_link(&again), chain_link(&original));
        let assessment = verify(
            &again,
            Subject::Bytes(SUBJECT),
            &anchor_file::published(),
            &Floor::default(),
        );
        assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
    }
}
