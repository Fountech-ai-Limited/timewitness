//! Slice six: attacking a pair rather than reading one.
//!
//! The other files in this folder prove that the honest case works and that each named refusal
//! fires against a control. This one goes the other way: it takes a pair that is known good and
//! tries to turn it into something else, one byte at a time and then by hand, and every attempt has
//! to come back refused.
//!
//! **Two of the attacks on the list are not attacks, and saying so is the point of writing them
//! down.** Swapping which key signs which half gives an exchange between the same two parties in
//! the other direction, which is a thing that happens; and sending one request twice gives two
//! valid pairs, which is a retry. Both read as valid here, deliberately, and what they cost is
//! written into the limitation the protocol document carries rather than into a refusal that would
//! turn an ordinary event into a fault.

use sha2::{Digest, Sha256};
use timewitness_countersign::{Countersigned, Exchange, Interval, Role, Signed};
use timewitness_receipt::AgentKey;

fn digest(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i % 256).unwrap_or(0));
    }
    out
}

fn sender() -> AgentKey {
    AgentKey::from_seed(&digest(42))
}

fn receiver() -> AgentKey {
    AgentKey::from_seed(&digest(77))
}

fn sender_interval() -> Interval {
    Interval {
        earliest_ns: 1_788_979_278_845_210_129,
        reading_ns: 1_788_979_278_918_450_302,
        latest_ns: 1_788_979_278_999_084_899,
    }
}

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

/// A pair, as the two byte strings a reader is handed.
fn a_pair_as_bytes() -> (Vec<u8>, Vec<u8>) {
    let request = signed_request();
    let pair = answered(&request);
    (
        pair.request().to_bytes().to_vec(),
        pair.response().to_bytes().to_vec(),
    )
}

#[test]
fn a_pair_that_has_not_been_touched_reads_as_a_pair() {
    // The control. Every test below changes one thing about these two byte strings, so if this
    // stopped passing the rest would be refusing something other than the thing they name.
    let (request, response) = a_pair_as_bytes();
    assert!(Countersigned::read_bytes(&request, &response).is_ok());
}

#[test]
fn every_bit_of_either_half_flipped_in_turn_is_refused() {
    // The battery. A change anywhere in a signed half either breaks the signature, breaks the
    // shape, or changes the bytes the other half names, and all three are refusals. What this
    // catches that a hand-written case cannot is a field somebody adds later that nothing signs.
    let (request, response) = a_pair_as_bytes();

    let mut tried = 0usize;
    for (which, half) in [("the request", &request), ("the response", &response)] {
        for index in 0..half.len() {
            for bit in 0..8u8 {
                let mut broken = half.clone();
                broken[index] ^= 1 << bit;
                if broken == *half {
                    continue;
                }
                let read = if which == "the request" {
                    Countersigned::read_bytes(&broken, &response)
                } else {
                    Countersigned::read_bytes(&request, &broken)
                };
                assert!(
                    read.is_err(),
                    "{which} with bit {bit} of byte {index} flipped still read as a pair"
                );
                tried += 1;
            }
        }
    }

    // The count is asserted rather than printed, because a battery that silently tried nothing
    // passes and looks exactly like one that tried everything.
    assert!(
        tried > 4_000,
        "only {tried} single-bit changes were tried, so this battery is not reaching the halves"
    );
}

#[test]
fn a_response_whose_payload_is_changed_after_it_was_signed_is_refused() {
    // The named attack: what came back is not what the response says came back. The payload is
    // inside the signature, so the change is caught there rather than by anything about payloads.
    let (request, response) = a_pair_as_bytes();
    let pair = Countersigned::read_bytes(&request, &response).expect("the control is a pair");
    let payload = pair.response().exchange.payload;

    let at = response
        .windows(payload.len())
        .position(|window| window == payload)
        .expect("the payload is in the signed bytes");
    let mut broken = response.clone();
    broken[at] ^= 0x01;

    assert!(
        Countersigned::read_bytes(&request, &broken).is_err(),
        "a response claiming a different payload was read as this response"
    );
}

#[test]
fn a_response_moved_onto_another_request_of_the_same_sender_is_refused() {
    // Two requests that differ in one field, each signed, and the response to the first offered
    // against the second. What refuses it is that the response names the bytes of the request it
    // answered, so the second request is not that request however similar it looks.
    let first = signed_request();
    let mut second_body = a_request();
    second_body.sequence = 8;
    let second = Signed::new(&second_body, &sender()).expect("the second request signs");

    let pair = answered(&first);
    assert!(
        Countersigned::read_bytes(second.to_bytes(), pair.response().to_bytes()).is_err(),
        "a response was read against a request it never answered"
    );
    // And the control, which is the same response against the request it did answer.
    assert!(Countersigned::read_bytes(first.to_bytes(), pair.response().to_bytes()).is_ok());
}

#[test]
fn what_a_response_names_is_the_whole_signed_request_and_not_the_claim_inside_it() {
    // The decision this protocol turns on, held here as arithmetic rather than as a sentence.
    // Ed25519 verification asks that a signature is valid, not that it is the one a well behaved
    // signer would have produced, so one body can carry more than one valid signature. If a
    // response named the body, a sender holding two such spellings could present either as the
    // thing that was answered. Naming the envelope leaves it holding exactly one.
    let request = signed_request();
    let pair = answered(&request);
    let named = pair
        .response()
        .exchange
        .answers
        .expect("a response names one");

    let mut over_the_envelope = Sha256::new();
    over_the_envelope.update(request.to_bytes());
    assert_eq!(named, over_the_envelope.finalize().as_slice());

    // The body on its own is not what is named, and this is the half that would silently be true
    // of the wrong design.
    let body = &request.to_bytes()[..request.to_bytes().len() / 2];
    let mut over_a_part = Sha256::new();
    over_a_part.update(body);
    assert_ne!(named, over_a_part.finalize().as_slice());
}

#[test]
fn the_two_keys_swapped_is_an_exchange_in_the_other_direction_and_not_a_forgery() {
    // On the attack list and it is not an attack. The protocol names roles and not parties: one
    // half says request and the other says response, and the keys say which key played which role.
    // Nothing anywhere says who holds either key, which the report to a reader states plainly.
    let mut body = a_request();
    body.key = receiver().public_key_bytes();
    let their_request = Signed::new(&body, &receiver()).expect("the other party signs a request");

    let pair = Countersigned::answer(
        their_request.to_bytes(),
        digest(2),
        1,
        sender_interval(),
        digest(150),
        &sender(),
    )
    .expect("the other direction is an exchange too");

    assert_eq!(pair.request().exchange.key, receiver().public_key_bytes());
    assert_eq!(pair.response().exchange.key, sender().public_key_bytes());
}

#[test]
fn one_request_answered_twice_gives_two_valid_pairs_and_neither_can_see_the_other() {
    // The replayed sequence number, and what actually happens. A sender can send one signed request
    // twice and a receiver can answer both; each pair is sound, and each is about one moment the
    // receiver really did read. What no holder of one exchange can see is that there was another,
    // because an exchange carries nothing about any other exchange. It is a limitation of the form
    // rather than a hole in it, and the document says so.
    let request = signed_request();
    let first = answered(&request);
    let second = Countersigned::answer(
        request.to_bytes(),
        digest(2),
        2,
        Interval {
            earliest_ns: receiver_interval().earliest_ns + 1_000_000_000,
            reading_ns: receiver_interval().reading_ns + 1_000_000_000,
            latest_ns: receiver_interval().latest_ns + 1_000_000_000,
        },
        digest(151),
        &receiver(),
    )
    .expect("answering a second time is answering");

    assert!(Countersigned::read_bytes(request.to_bytes(), first.response().to_bytes()).is_ok());
    assert!(Countersigned::read_bytes(request.to_bytes(), second.response().to_bytes()).is_ok());
    assert_ne!(first.response().to_bytes(), second.response().to_bytes());
    assert_eq!(
        first.response().exchange.answers,
        second.response().exchange.answers,
        "both answer the same request, which is how a reader would find them if they held both"
    );
}

#[test]
fn a_half_signed_by_a_key_nobody_has_heard_of_still_reads_and_still_proves_nothing_about_who() {
    // The last attack on the list, and the honest answer to it is that there is no key list to
    // fail. A pair signed by two keys a reader has never seen is a valid pair, and what it
    // establishes is that two keys signed two statements. Whether either key belongs to anybody is
    // a question this form does not answer and does not pretend to.
    let stranger = AgentKey::from_seed(&digest(200));
    let mut body = a_request();
    body.key = stranger.public_key_bytes();
    let theirs = Signed::new(&body, &stranger).expect("a stranger signs its own request");

    let pair = Countersigned::answer(
        theirs.to_bytes(),
        digest(2),
        1,
        receiver_interval(),
        digest(150),
        &receiver(),
    )
    .expect("a stranger's request is answerable");

    assert_eq!(pair.request().exchange.key, stranger.public_key_bytes());
    assert!(Countersigned::read_bytes(theirs.to_bytes(), pair.response().to_bytes()).is_ok());
}
