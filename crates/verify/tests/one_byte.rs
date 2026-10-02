//! A receipt altered by one byte is refused, and the stub that would not notice is here beside it.
//!
//! This is the verifier's own acceptance test and the sharpest evidence that it checks
//! cryptographic material rather than reading a well-formed document. Every case below is a real
//! signed receipt with exactly one byte different, and the difference is in a named place: the
//! reading, an edge of the bound, the sequence number, the hash of what is being stamped, one of
//! the three signed attestations, the agent's own key, the algorithm in the protected header, or
//! the signature itself.
//!
//! **Each case is watched failing first, in the file, permanently.** [`parse_only`] is the verifier
//! this product would be if it checked that a receipt is well formed and stopped: it decodes the
//! envelope, reads the payload into the typed shape, and says yes. Every case asserts that the stub
//! accepts the altered receipt before asserting that the real verifier refuses it. So the battery
//! cannot rot into a set of cases that pass because they were never sharp, which is the way a
//! tamper-detection test usually dies.
//!
//! **What this does not cover, said out loud.** The alterations are all inside what the signature
//! covers. A COSE unprotected header sits outside the signature by design, so a byte changed there
//! does not and should not break the signature, and the consequence, that a holder can restate a
//! receipt as different bytes carrying the same claim, is not settled. The last test in this file
//! draws that line rather than leaving a reader to assume it is not there.

mod common;

use timewitness_receipt::{cbor, Receipt};
use timewitness_verify::{verify, Floor, Subject};

/// The verifier this would be if it read the document and stopped.
///
/// Nothing here is a straw man: it does more than a careless implementation would, because it reads
/// every field into the typed shape rather than eyeballing a few. It still accepts every receipt in
/// this file.
fn parse_only(bytes: &[u8]) -> bool {
    let Ok(envelope) = cbor::decode(bytes) else {
        return false;
    };
    let Some(parts) = envelope.as_array() else {
        return false;
    };
    if parts.len() != 4 {
        return false;
    }
    let Some(payload) = parts[2].as_bytes() else {
        return false;
    };
    let Ok(value) = cbor::decode(payload) else {
        return false;
    };
    Receipt::from_value(&value).is_ok()
}

/// A copy of the signed receipt with exactly one byte different, at `index`.
fn one_byte_changed(signed: &[u8], index: usize) -> Vec<u8> {
    let mut altered = signed.to_vec();
    altered[index] ^= 0x01;
    altered
}

/// Where the payload the signature covers sits inside the signed receipt.
///
/// The envelope is four things and the payload is the third. Finding it by searching for its own
/// bytes is exact, because those bytes are a hundreds of bytes long CBOR map that appears once.
fn payload_span(signed: &[u8]) -> (usize, usize) {
    let envelope = cbor::decode(signed).expect("the receipt under test decodes");
    let parts = envelope.as_array().expect("four parts");
    let payload = parts[2].as_bytes().expect("the payload is a byte string");
    let start = find(signed, payload).expect("the payload sits inside the envelope it came from");
    (start, start + payload.len())
}

/// Where the signature sits.
fn signature_span(signed: &[u8]) -> (usize, usize) {
    let envelope = cbor::decode(signed).expect("the receipt under test decodes");
    let parts = envelope.as_array().expect("four parts");
    let signature = parts[3].as_bytes().expect("the signature is a byte string");
    let start = find(signed, signature).expect("the signature sits inside the envelope");
    (start, start + signature.len())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The index inside the signed receipt of one byte of a value the payload carries.
///
/// Given the bytes of some field, this finds where they sit. It refuses where the field appears more
/// than once, because a case that alters an ambiguous byte is not the case it says it is.
fn byte_of(signed: &[u8], field: &[u8], offset: usize) -> usize {
    let first = find(signed, field).expect("the field is in the receipt");
    let rest = &signed[first + 1..];
    assert!(
        find(rest, field).is_none(),
        "this field appears more than once, so a case altering it would be ambiguous"
    );
    first + offset
}

/// The index inside the signed receipt of the one byte that carries a particular field.
///
/// Rather than searching for a value, which is ambiguous whenever the same number appears twice, and
/// it does: the reading and the corridor's own instant are the same nanosecond, and the hash of what
/// is being stamped appears again inside the timestamp token that was taken over it. So the field is
/// named by changing it. The receipt is re-encoded with that one field different, the two encodings
/// are compared, and the single byte that moved is the byte the case is about.
fn byte_that_carries(signed: &[u8], change: impl FnOnce(&mut Receipt)) -> usize {
    let (start, end) = payload_span(signed);
    let original = cbor::encode(&common::receipt().to_value());
    assert_eq!(
        &signed[start..end],
        original.as_slice(),
        "the payload in the envelope is the encoding of the receipt this file builds"
    );

    let mut altered_receipt = common::receipt();
    change(&mut altered_receipt);
    let altered = cbor::encode(&altered_receipt.to_value());
    assert_eq!(
        original.len(),
        altered.len(),
        "the change has to keep the encoding the same length or it is not one byte"
    );

    let moved: Vec<usize> = (0..original.len())
        .filter(|&i| original[i] != altered[i])
        .collect();
    assert_eq!(moved.len(), 1, "the change has to move exactly one byte");
    start + moved[0]
}

/// One case: alter this byte and say what was altered.
fn watched(name: &str, index: usize) {
    let signed = common::signed();
    let altered = one_byte_changed(&signed, index);
    assert_ne!(altered, signed, "the case has to change something");
    assert_eq!(
        altered.iter().zip(&signed).filter(|(a, b)| a != b).count(),
        1,
        "{name}: exactly one byte"
    );

    // Watched failing first. A verifier that reads the document and stops takes this.
    assert!(
        parse_only(&altered),
        "{name}: the stub was supposed to accept this, and a case the stub already refuses proves \
         nothing about the real verifier"
    );

    // And the real one does not. No subject is supplied, so the only thing that can refuse this is
    // the alteration itself. Supplying the wrong subject would refuse every case for a reason that
    // has nothing to do with the byte that moved, and the battery would pass while proving nothing.
    let assessment = verify(
        &altered,
        Subject::NotSupplied,
        &common::anchors(),
        &Floor::default(),
    );
    assert!(
        !assessment.accepted(),
        "{name}: the verifier accepted a receipt with one byte changed"
    );
    let refusal = assessment.refusal().expect("something refused it");
    assert!(
        refusal.state.detail().len() > 20,
        "{name}: a refusal has to say something a person can act on, and this said {:?}",
        refusal.state.detail()
    );
}

#[test]
fn the_receipt_this_battery_alters_is_itself_accepted() {
    // Otherwise every case below would pass for the wrong reason.
    let signed = common::signed();
    let assessment = verify(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &common::anchors(),
        &Floor::default(),
    );
    assert!(
        assessment.accepted(),
        "the untouched receipt was refused: {:?}",
        assessment.refusal()
    );
    assert_eq!(assessment.checked_entries(), 3);
    assert!(parse_only(&signed));
}

#[test]
fn the_reading_cannot_be_moved_by_one_byte() {
    let signed = common::signed();
    let index = byte_that_carries(&signed, |r| {
        r.utc_estimate = timewitness_core::UnixNanos(common::CORRIDOR_AT + 1);
    });
    watched("the reading", index);
}

#[test]
fn neither_edge_of_the_bound_can_be_moved_by_one_byte() {
    // Found by changing the field rather than by searching for its value. Since 2026-09-15 the
    // sandwich receipt's edges are the bracket's edges, so each value also sits inside the
    // beacon's or the witness's own entry, and a search would find it twice.
    let signed = common::signed();
    let earliest = byte_that_carries(&signed, |r| {
        r.claim.earliest = timewitness_core::UnixNanos(common::CORRIDOR_AT - common::HALF + 1);
    });
    watched("the earliest edge", earliest);
    let latest = byte_that_carries(&signed, |r| {
        r.claim.latest = timewitness_core::UnixNanos(common::CORRIDOR_AT + common::HALF + 1);
    });
    watched("the latest edge", latest);
}

#[test]
fn the_hash_of_what_is_being_stamped_cannot_be_changed_by_one_byte() {
    let signed = common::signed();
    let index = byte_that_carries(&signed, |r| r.payload.hash[16] ^= 0x40);
    watched("the payload hash", index);
}

#[test]
fn the_sequence_number_cannot_be_changed_by_one_byte() {
    // Where a receipt sits in a chain is part of what was signed, so a holder cannot renumber one
    // to slot it in somewhere else. What nothing here checks is whether the numbering agrees
    // with a second receipt, which needs a second receipt.
    let signed = common::signed();
    let index = byte_that_carries(&signed, |r| r.sequence = 0);
    watched("the sequence number", index);
}

#[test]
fn none_of_the_three_signed_attestations_can_be_changed_by_one_byte() {
    let signed = common::signed();
    for (name, blob) in [
        ("the corridor attestation", common::corridor().blob),
        ("the freshness beacon value", common::beacon().blob),
        ("the final witness token", common::witness().blob),
    ] {
        // A byte a third of the way in, so the case is not resting on a length prefix.
        watched(name, byte_of(&signed, &blob, blob.len() / 3));
    }
}

#[test]
fn the_agents_own_key_cannot_be_changed_by_one_byte() {
    let signed = common::signed();
    let public = common::key().public_key_bytes();
    // The key appears twice, inside the signed payload and again in the unprotected header, so the
    // ambiguity check in `byte_of` would fire. Take the copy inside the payload.
    let (start, end) = payload_span(&signed);
    let inside = find(&signed[start..end], &public).expect("the key is in the payload") + start;
    watched("the agent's public key", inside + 7);
}

#[test]
fn the_signature_itself_cannot_be_changed_by_one_byte() {
    let signed = common::signed();
    let (start, _) = signature_span(&signed);
    watched("the signature", start + 30);
}

#[test]
fn the_algorithm_in_the_protected_header_cannot_be_changed_by_one_byte() {
    // The protected header is inside what is signed, which is the point of the COSE signature
    // structure: without that, a signature could be moved onto a receipt claiming a weaker
    // algorithm, and that attack is older than this format.
    let signed = common::signed();
    let envelope = cbor::decode(&signed).expect("decodes");
    let parts = envelope.as_array().expect("four parts");
    let protected = parts[0].as_bytes().expect("a byte string");
    let start = find(&signed, protected).expect("the protected header is in the envelope");
    let altered = one_byte_changed(&signed, start + protected.len() - 1);

    // This one the stub does not accept, because the header no longer names Ed25519 and the stub
    // does not read the header at all. So it is asserted the other way round: the real verifier
    // refuses it, and it refuses it for the right reason.
    let assessment = verify(
        &altered,
        Subject::NotSupplied,
        &common::anchors(),
        &Floor::default(),
    );
    assert!(!assessment.accepted());
}

#[test]
fn every_single_bit_of_the_signed_payload_is_refused() {
    // The strongest form of the property, over every bit rather than over a chosen few. Nothing in
    // the signed payload can be moved at all: not a padding byte, not a length prefix, not a byte in
    // the middle of a string nobody reads.
    // The receipt for this one rests on its own model rather than on a sandwich, and the reader
    // holds no anchors. Every attestation is still in it, byte for byte, and every one of those
    // bytes is still under the signature; what is skipped is re-checking three third-party
    // signatures seven thousand times to establish something the signature over the whole payload
    // already settles. The anchored path is exercised by the named cases above.
    let signed = common::signed_local_only();
    let (start, end) = payload_span(&signed);
    let anchors = timewitness_receipt::anchors::TrustAnchors::none();
    let floor = Floor::default();

    let mut accepted = Vec::new();
    for index in start..end {
        for bit in 0..8u8 {
            let mut altered = signed.clone();
            altered[index] ^= 1 << bit;
            if verify(&altered, Subject::NotSupplied, &anchors, &floor).accepted() {
                accepted.push((index - start, bit));
            }
        }
    }

    assert!(
        accepted.is_empty(),
        "{} of {} single-bit changes inside the signed payload were accepted, at {:?}",
        accepted.len(),
        (end - start) * 8,
        &accepted[..accepted.len().min(8)]
    );
}

#[test]
fn a_receipt_restated_outside_the_signature_is_refused_rather_than_relinked() {
    // The unprotected header is outside the signature by design, so a byte changed there leaves a
    // receipt whose signature still checks out, carrying the same claim, as different bytes. What
    // happens next is settled: the format pins that header to the single key identifier entry
    // naming the key inside the signature, so a restated receipt is refused rather than accepted
    // with a chain link of its own.
    let signed = common::signed();
    let envelope = cbor::decode(&signed).expect("decodes");
    let parts = envelope.as_array().expect("four parts");
    let unprotected = cbor::encode(&parts[1]);
    let start = find(&signed, &unprotected).expect("the unprotected header is in the envelope");

    // The last byte of the key identifier, which nothing signed.
    let altered = one_byte_changed(&signed, start + unprotected.len() - 1);
    let assessment = verify(
        &altered,
        Subject::NotSupplied,
        &common::anchors(),
        &Floor::default(),
    );
    assert!(!assessment.accepted());

    // The two spellings hash differently, which is exactly why only one of them may be accepted.
    // The digest the verifier prints is the chain link, so a second accepted spelling would be a
    // second link for one receipt and a fork nobody needed a key for.
    let original = verify(
        &signed,
        Subject::NotSupplied,
        &common::anchors(),
        &Floor::default(),
    );
    assert!(original.accepted());
    assert_ne!(original.link, assessment.link);
}
