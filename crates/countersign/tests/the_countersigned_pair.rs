//! Slice three: the receive half, and every way two halves are not one exchange.
//!
//! The receiver reads the request on the bytes it arrived as, says what its own clock was doing,
//! and signs. What this file proves is that each pairing refusal fires against a pair that passes,
//! rather than that the honest case works.
//!
//! Two things this file deliberately proves are **not** checked, and both matter more than the
//! refusals. A pair whose two intervals overlap reads exactly like one whose intervals do not, and
//! a pair whose response is earlier than its request reads too. Deciding an order is the next slice
//! and it has to be able to say undecided out loud, which a reader that refused the overlapping case
//! would have quietly answered already, always in the same direction.

use sha2::{Digest, Sha256};
use timewitness_countersign::{
    Countersigned, Exchange, Interval, Refusal, Role, Signed, MAX_WIRE_CHARS,
};
use timewitness_receipt::AgentKey;

fn digest(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn sender() -> AgentKey {
    AgentKey::from_seed(&digest(42))
}

fn receiver() -> AgentKey {
    AgentKey::from_seed(&digest(77))
}

/// The sender's own clock, and the numbers are a plain nanosecond reading with a width either side.
fn sender_interval() -> Interval {
    Interval {
        earliest_ns: 1_788_979_278_845_210_129,
        reading_ns: 1_788_979_278_918_450_302,
        latest_ns: 1_788_979_278_999_084_899,
    }
}

/// The receiver's own clock, a fifth of a second later and no narrower.
fn receiver_interval() -> Interval {
    Interval {
        earliest_ns: 1_788_979_279_045_210_129,
        reading_ns: 1_788_979_279_118_450_302,
        latest_ns: 1_788_979_279_199_084_899,
    }
}

fn a_request() -> Exchange {
    Exchange {
        role: Role::Request,
        payload: digest(1),
        sequence: 7,
        interval: sender_interval(),
        receipt: digest(100),
        key: sender().public_key_bytes(),
        answers: None,
    }
}

fn signed_request() -> Signed {
    Signed::new(&a_request(), &sender()).expect("our own request signs")
}

/// The receiver's half, built the way a receiver builds it.
fn answered(request: &Signed) -> Countersigned {
    Countersigned::answer(
        request.to_bytes(),
        digest(2),
        1,
        receiver_interval(),
        digest(150),
        &receiver(),
    )
    .expect("our own pair is a pair")
}

#[test]
fn a_request_is_answered_and_the_pair_reads_back_under_both_keys() {
    let request = signed_request();
    let pair = answered(&request);

    assert_eq!(pair.request().exchange, a_request());
    assert_eq!(pair.response().exchange.role, Role::Response);
    assert_eq!(pair.response().exchange.key, receiver().public_key_bytes());
    assert_eq!(pair.response().exchange.interval, receiver_interval());

    // A stranger holding the two header values gets the same pair with no network and no account.
    let read = Countersigned::read(&pair.request().to_wire(), &pair.response().to_wire())
        .expect("a stranger reads the pair");
    assert_eq!(read, pair);
    // And byte for byte, because each half is named by the bytes it travelled as.
    assert_eq!(read.request().to_bytes(), request.to_bytes());
}

#[test]
fn the_response_names_the_signed_request_and_not_the_claim_inside_it() {
    // This is the decision slice three settled, held by a test so that flipping it back is a red
    // run rather than a quiet change of meaning. Ed25519 verification asks only that a signature is
    // valid, not that it is the one a well behaved signer would have produced, so one body can carry
    // more than one valid signature. Naming the body would leave a sender holding two byte strings
    // and able to present either as the thing that was answered.
    let request = signed_request();
    let pair = answered(&request);

    assert_eq!(
        pair.response().exchange.answers,
        Some(request.envelope_hash())
    );

    let mut body = Sha256::new();
    body.update(a_request().to_cbor());
    let body_hash: [u8; 32] = body.finalize().into();
    assert_ne!(pair.response().exchange.answers, Some(body_hash));

    // And the name is reproducible by anybody holding the bytes.
    let mut envelope = Sha256::new();
    envelope.update(request.to_bytes());
    let by_hand: [u8; 32] = envelope.finalize().into();
    assert_eq!(pair.response().exchange.answers, Some(by_hand));
}

#[test]
fn a_response_to_another_request_is_refused() {
    let request = signed_request();
    let pair = answered(&request);

    let mut other = a_request();
    other.sequence += 1;
    let other = Signed::new(&other, &sender()).expect("the other request signs");
    assert_ne!(other.envelope_hash(), request.envelope_hash());

    let refusal = Countersigned::join(other, pair.response().clone())
        .expect_err("a response about something else is not this pair");
    assert_eq!(refusal, Refusal::DoesNotAnswerThisRequest);
}

#[test]
fn a_request_altered_after_it_was_answered_is_refused() {
    // The point of naming a request by the hash of what travelled: change anything at all about it
    // and the response stops being about it.
    let request = signed_request();
    let pair = answered(&request);

    let mut moved = a_request();
    moved.interval.latest_ns += 1;
    let moved = Signed::new(&moved, &sender()).expect("the moved request signs");

    let refusal = Countersigned::join(moved, pair.response().clone())
        .expect_err("a request that moved is not the one that was answered");
    assert_eq!(refusal, Refusal::DoesNotAnswerThisRequest);
}

#[test]
fn one_key_signing_both_halves_is_refused() {
    // A party countersigning itself is a party agreeing with itself, and the pair exists so that
    // neither side can be contradicted by the other's clock.
    let request = signed_request();
    let refusal = Countersigned::answer(
        request.to_bytes(),
        digest(2),
        1,
        receiver_interval(),
        digest(150),
        &sender(),
    )
    .expect_err("one party is not two");
    assert_eq!(refusal, Refusal::OneKeySignedBothHalves);
}

#[test]
fn two_halves_of_the_same_kind_are_refused() {
    let request = signed_request();
    let pair = answered(&request);

    let both_requests = Countersigned::join(request.clone(), request.clone())
        .expect_err("a request is not a response");
    assert_eq!(
        both_requests,
        Refusal::Incoherent {
            detail: "the half given as the response is not a response",
        }
    );

    let both_responses = Countersigned::join(pair.response().clone(), pair.response().clone())
        .expect_err("a response is not a request");
    assert_eq!(
        both_responses,
        Refusal::Incoherent {
            detail: "the half given as the request is not a request",
        }
    );
}

#[test]
fn a_half_whose_signature_does_not_hold_never_reaches_the_pairing() {
    let request = signed_request();
    let pair = answered(&request);

    // One byte of the signature, which is the last field of the envelope.
    let mut broken = pair.response().to_bytes().to_vec();
    let last = broken.len() - 1;
    broken[last] ^= 0x01;

    let refusal = Countersigned::read_bytes(request.to_bytes(), &broken)
        .expect_err("a signature that does not hold is not a half");
    assert_eq!(refusal, Refusal::SignatureDoesNotMatch);
}

#[test]
fn the_receiver_reads_the_request_on_the_bytes_it_arrived_as() {
    // The receiver does not take somebody else's word for what the request said. Move a byte inside
    // the signed body and the answer never happens.
    let request = signed_request();
    let mut tampered = request.to_bytes().to_vec();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 0x01;

    let refusal = Countersigned::answer(
        &tampered,
        digest(2),
        1,
        receiver_interval(),
        digest(150),
        &receiver(),
    )
    .expect_err("a request that was altered is not answered");
    assert!(
        matches!(
            refusal,
            Refusal::SignatureDoesNotMatch
                | Refusal::NotDeterministicCbor
                | Refusal::NotSigned
                | Refusal::WrongType { .. }
                | Refusal::MissingField { .. }
                | Refusal::UnknownField { .. }
                | Refusal::KeyIsNotText
                | Refusal::Incoherent { .. }
        ),
        "an altered request is refused, and it was refused as {refusal}"
    );
}

#[test]
fn the_header_route_and_the_field_route_give_the_same_pair() {
    // An MCP tool call carries the same signed bytes as a field rather than as a header, so the
    // protocol cannot come to mean two things.
    let request = signed_request();
    let pair = answered(&request);

    let as_headers = Countersigned::read(&pair.request().to_wire(), &pair.response().to_wire())
        .expect("the header route");
    let as_fields =
        Countersigned::read_bytes(pair.request().to_bytes(), pair.response().to_bytes())
            .expect("the tool call route");
    assert_eq!(as_headers, as_fields);

    let by_wire = Countersigned::answer_wire(
        &request.to_wire(),
        digest(2),
        1,
        receiver_interval(),
        digest(150),
        &receiver(),
    )
    .expect("answering from a header value");
    assert_eq!(by_wire, pair);
}

#[test]
fn both_halves_fit_in_headers_with_room_to_spare() {
    // The size question was settled in slice one by measuring rather than by guessing, and the
    // answer moved the design. Measuring it again on the pair is what keeps the document honest: the
    // numbers it quotes are read off this run rather than off somebody's memory of the last one.
    let pair = answered(&signed_request());
    let request = pair.request().to_wire().chars().count();
    let response = pair.response().to_wire().chars().count();
    println!("a signed request is {request} characters and a signed response is {response}");
    assert!(request <= MAX_WIRE_CHARS, "a request fits");
    assert!(response <= MAX_WIRE_CHARS, "a response fits");
    // A response carries the extra field naming the request, so it is the larger of the two and the
    // ceiling has to have room for it rather than for the smaller one.
    assert!(
        response > request,
        "a response names a request and so is longer"
    );
}

#[test]
fn two_intervals_that_overlap_still_read_as_a_pair() {
    // The one that matters most. Overlapping intervals leave the order undecided, and that answer
    // belongs to the slice that can say so. A reader that refused this would have decided the
    // ordering question here, always in the same direction, and nobody would see it happen.
    let request = signed_request();
    let mut overlapping = receiver_interval();
    overlapping.earliest_ns = a_request().interval.earliest_ns - 1_000;
    overlapping.reading_ns = a_request().interval.reading_ns;
    overlapping.latest_ns = a_request().interval.latest_ns + 1_000;

    let pair = Countersigned::answer(
        request.to_bytes(),
        digest(2),
        1,
        overlapping,
        digest(150),
        &receiver(),
    )
    .expect("an overlapping pair is still a pair");
    assert_eq!(pair.response().exchange.interval, overlapping);
}

#[test]
fn a_response_wholly_earlier_than_its_request_still_reads_as_a_pair() {
    // The same rule from the other side, and it reads oddly on purpose. A receive interval entirely
    // before the send interval is either two clocks disagreeing by more than their own bounds or
    // somebody lying, and both of those are the ordering slice's to say rather than the reader's to
    // hide by refusing.
    let request = signed_request();
    let earlier = Interval {
        earliest_ns: a_request().interval.earliest_ns - 10_000_000_000,
        reading_ns: a_request().interval.reading_ns - 10_000_000_000,
        latest_ns: a_request().interval.latest_ns - 10_000_000_000,
    };

    let pair = Countersigned::answer(
        request.to_bytes(),
        digest(2),
        1,
        earlier,
        digest(150),
        &receiver(),
    )
    .expect("an impossible looking pair is still a pair");
    assert_eq!(pair.response().exchange.interval, earlier);
}

#[test]
fn nothing_is_signed_that_our_own_reader_would_refuse() {
    // Without this a caller signs a value that goes out and that nobody on earth can read back, this
    // side included. Each shape below is refused by the reader, so each must be refused by the
    // writer, and the writer uses the reader rather than a second list of the same conditions.
    let mut edges_the_wrong_way = a_request();
    edges_the_wrong_way.interval.latest_ns = edges_the_wrong_way.interval.earliest_ns - 1;
    assert!(matches!(
        Signed::new(&edges_the_wrong_way, &sender()),
        Err(Refusal::Incoherent { .. })
    ));

    let mut a_response_naming_nothing = a_request();
    a_response_naming_nothing.role = Role::Response;
    assert_eq!(
        Signed::new(&a_response_naming_nothing, &sender()),
        Err(Refusal::MissingField { name: "req" })
    );

    let mut a_request_naming_something = a_request();
    a_request_naming_something.answers = Some(digest(5));
    assert!(matches!(
        Signed::new(&a_request_naming_something, &sender()),
        Err(Refusal::Incoherent { .. })
    ));

    let mut a_key_of_the_wrong_length = a_request();
    a_key_of_the_wrong_length.key.truncate(31);
    assert_eq!(
        Signed::new(&a_key_of_the_wrong_length, &sender()),
        Err(Refusal::WrongType { name: "key" })
    );

    // And the control: the same helper with nothing wrong with it still signs.
    assert!(Signed::new(&a_request(), &sender()).is_ok());
}
