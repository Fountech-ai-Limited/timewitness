//! A version 1 receipt is one receipt however the witness over its signature is spelled.
//!
//! The witness sits in the unprotected header, outside the signature, and an RFC 3161 token holds
//! plenty its signature does not cover: the request stored beside it, the certificates it carries
//! besides the one the reader pins, fields nobody reads. On 2026-09-23 a sweep flipped each bit of
//! the witness on the committed version 1 receipt in turn, and 10,156 of 32,034 flips still verified,
//! each as a file with a hash of its own. The next receipt in a chain names its predecessor by that
//! hash, so a holder with no key could fork or break a chain whose unbroken order is half of what this
//! product claims.
//!
//! The rule now is that a receipt's hash is of the receipt as its agent signed it, with the witness
//! over the signature set aside. This test flips every bit of the unprotected header of the committed
//! version 1 receipt and holds each flip to one of two outcomes: refused, or the same hash.

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

/// Where the unprotected header sits in the file, as a range of bytes.
fn header_span(signed: &[u8]) -> (usize, usize) {
    let envelope = cbor::decode(signed).expect("the receipt decodes");
    let header = cbor::encode(&envelope.as_array().expect("an envelope")[1]);
    let at = signed
        .windows(header.len())
        .position(|w| w == header.as_slice())
        .expect("the header is in the file");
    (at, at + header.len())
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
fn no_flip_in_the_witness_is_a_second_receipt() {
    let original = receipt();
    let link = chain_link(&original);
    let anchors = anchor_file::published();
    let (start, end) = header_span(&original);
    assert!(
        end - start > 4096,
        "the header holds the witness, {} bytes",
        end - start
    );

    let (mut same, mut refused) = (0usize, 0usize);
    let mut second = Vec::new();
    'flips: for at in start..end {
        for bit in 0..8 {
            let mut flipped = original.clone();
            flipped[at] ^= 1 << bit;
            if chain_link(&flipped) == link {
                same += 1;
                continue;
            }
            let assessment = verify(
                &flipped,
                Subject::Bytes(SUBJECT),
                &anchors,
                &Floor::default(),
            );
            if assessment.accepted() {
                second.push((at, bit));
                if second.len() == 5 {
                    break 'flips;
                }
            } else {
                refused += 1;
            }
        }
    }
    assert!(
        second.is_empty(),
        "flips inside the witness verify as receipts with a hash of their own, at byte and bit {second:?}; \
         {same} kept the hash and {refused} were refused before these"
    );
    assert_eq!(same + refused, (end - start) * 8);
    // Most of the header is the token itself, and every flip inside it keeps the hash. What is
    // refused is the key identifier, the label and the lengths round them.
    assert!(
        same > refused * 10,
        "{same} kept the hash and {refused} were refused"
    );
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
