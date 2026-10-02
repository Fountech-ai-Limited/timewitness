//! One receipt, two valid signatures, and the call that refuses the second.
//!
//! `crates/receipt/src/cose.rs` calls `verify_strict` rather than `verify`, and the comment above
//! it says why. Until this file existed that was all there was: changing the call to `verify` left
//! every test in the tree green, so the reasoning was written down and nothing held the code to it.
//!
//! What the two calls disagree about is a public key of small order. The key below is the neutral
//! point, encoded as y = 1 with the sign bit clear. Verification without the strict check asks
//! whether [s]B equals R + [k]A, and the neutral point takes [k]A to itself whatever the message
//! hashes to, so the question becomes whether [1]B equals B. It does, for every message anybody
//! ever puts in front of it, which means a receipt naming that key has a valid signature that
//! somebody who has never held a signing key can write.
//!
//! Why it matters here rather than in the abstract. A receipt's chain link is the hash of the
//! signed bytes, so unbroken order rests on one signed receipt having one spelling. A second valid
//! spelling of the same receipt is a second valid history, and order is half of what this product
//! claims.

mod common;

use timewitness_receipt::{cbor, open, ReceiptError, Value};

/// COSE header labels, from RFC 9052. 1 is the algorithm and 4 is the key id.
const HEADER_ALG: i128 = 1;
const HEADER_KID: i128 = 4;
/// EdDSA, from the COSE algorithm registry.
const ALG_EDDSA: i128 = -8;

/// The neutral point: y = 1, sign bit clear. The first of the eight points of small order.
const SMALL_ORDER_KEY: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes
};

/// The base point compressed, and then the scalar one, little-endian.
///
/// Against the key above this checks under the cofactorless equation and is refused by the strict
/// one. It is not a signature over anything: it was written here, by nobody holding anything.
const SIGNATURE_WRITTEN_BY_NOBODY: [u8; 64] = {
    let mut bytes = [0u8; 64];
    bytes[0] = 0x58;
    let mut i = 1;
    while i < 32 {
        bytes[i] = 0x66;
        i += 1;
    }
    bytes[32] = 1;
    bytes
};

/// The same receipt every other test here uses, renamed to the small-order key and handed the
/// signature above. Everything else about it is untouched and well-formed.
fn a_receipt_signed_by_nobody() -> Vec<u8> {
    let mut receipt = common::receipt();
    receipt.agent_public_key = SMALL_ORDER_KEY.to_vec();

    let payload = cbor::encode(&receipt.to_value());
    let protected = cbor::encode(&Value::Map(vec![(
        Value::Int(HEADER_ALG),
        Value::Int(ALG_EDDSA),
    )]));

    cbor::encode(&Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![(
            Value::Int(HEADER_KID),
            Value::Bytes(SMALL_ORDER_KEY.to_vec()),
        )]),
        Value::Bytes(payload),
        Value::Bytes(SIGNATURE_WRITTEN_BY_NOBODY.to_vec()),
    ]))
}

#[test]
fn a_receipt_whose_signature_is_malleable_is_refused_by_the_signature_check() {
    // Swap `verify_strict` for `verify` at the call this is about and the refusal below becomes an
    // acceptance, which is the whole reason this file exists. The suite was green either way
    // before it.
    let refusal = open(&a_receipt_signed_by_nobody())
        .expect_err("a receipt naming a key of small order is signed by nobody");

    assert!(
        matches!(refusal, ReceiptError::Signature(_)),
        "the refusal has to be about the signature rather than about anything else the receipt \
         says, got {refusal}"
    );
}
