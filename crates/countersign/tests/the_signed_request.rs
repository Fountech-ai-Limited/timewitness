//! Slice two: the request half, signed, and every way a signed one is refused.
//!
//! Slice one put a shape on the wire and signed nothing, so a claim about somebody's clock was a
//! claim anybody on the path could have written. From here the wire form is always signed, and what
//! this file proves is that each refusal fires, against a value that passes, rather than that the
//! honest case works.
//!
//! What a verified signature buys is one thing and it is worth saying beside the tests: the party
//! holding that key signed that statement about its own clock. Not that the clock was right, and not
//! anything at all about the other party's clock. A signature does not turn a claim into evidence.

use timewitness_countersign::{base64url, Exchange, Interval, Refusal, Role, Signed, PREFIX};
use timewitness_receipt::cbor;
use timewitness_receipt::{AgentKey, Value};

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

fn somebody_else() -> AgentKey {
    AgentKey::from_seed(&digest(99))
}

fn a_request() -> Exchange {
    Exchange {
        role: Role::Request,
        payload: digest(1),
        sequence: 7,
        interval: Interval {
            earliest_ns: 1_788_979_278_845_210_129,
            reading_ns: 1_788_979_278_918_450_302,
            latest_ns: 1_788_979_278_999_084_899,
        },
        receipt: digest(100),
        key: sender().public_key_bytes(),
        answers: None,
    }
}

/// The envelope of a signed request, taken apart so a test can put it back together differently.
fn parts_of(signed: &Signed) -> Vec<Value> {
    let Value::Array(parts) = cbor::decode(signed.to_bytes()).expect("our own bytes decode") else {
        panic!("a signed exchange is an array");
    };
    parts
}

fn wire_of(parts: Vec<Value>) -> String {
    format!(
        "{PREFIX}{}",
        base64url::encode(&cbor::encode(&Value::Array(parts)))
    )
}

#[test]
fn a_signed_request_goes_out_and_comes_back_saying_the_same_thing() {
    let request = a_request();
    let signed = Signed::new(&request, &sender()).expect("our own request signs");
    let back = Signed::from_wire(&signed.to_wire()).expect("our own value reads back");
    assert_eq!(back.exchange, request);
    // And byte for byte, because a response will name this by the hash of what travelled.
    assert_eq!(back.to_bytes(), signed.to_bytes());
}

#[test]
fn the_same_signed_bytes_read_the_same_from_a_header_or_a_tool_call() {
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let as_a_header = Signed::from_wire(&signed.to_wire()).expect("the header route");
    let as_a_field = Signed::from_bytes(signed.to_bytes()).expect("the tool call route");
    assert_eq!(as_a_header, as_a_field);
}

#[test]
fn a_signed_request_fits_in_a_header_with_room_to_spare() {
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let chars = signed.to_wire().chars().count();
    println!("a signed request is {chars} characters");
    assert!(
        chars < timewitness_countersign::MAX_WIRE_CHARS / 4,
        "a signed request is {chars} characters against a ceiling of {}",
        timewitness_countersign::MAX_WIRE_CHARS
    );
}

#[test]
fn an_unsigned_body_is_refused_rather_than_read() {
    // The whole point of the slice. The body is well formed, says something true, and nobody signed
    // it, so anybody on the path could have written it.
    let body = a_request().to_cbor();
    let wire = format!("{PREFIX}{}", base64url::encode(&body));
    assert_eq!(Signed::from_wire(&wire), Err(Refusal::NotSigned));
}

#[test]
fn a_body_altered_after_it_was_signed_is_refused() {
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let mut parts = parts_of(&signed);

    // The sender's interval widened by a second at the late edge, which is the alteration with a
    // motive: it moves what the claim says about when the moment could have been.
    let Value::Bytes(payload) = parts[2].clone() else {
        panic!("the payload is a byte string");
    };
    let Value::Map(mut pairs) = cbor::decode(&payload).expect("decodes") else {
        panic!("the body is a map");
    };
    for (key, value) in pairs.iter_mut() {
        if key == &Value::text("hi") {
            let Value::Int(was) = value else {
                panic!("hi is an integer");
            };
            *value = Value::Int(*was + 1_000_000_000);
        }
    }
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    parts[2] = Value::Bytes(cbor::encode(&Value::Map(pairs)));

    assert_eq!(
        Signed::from_wire(&wire_of(parts)),
        Err(Refusal::SignatureDoesNotMatch),
        "a body widened after it was signed was not refused"
    );
}

#[test]
fn an_exchange_signed_by_a_key_it_does_not_name_is_refused_at_both_ends() {
    // At the writing end, because a claim naming somebody else's key is a claim nobody can check.
    assert_eq!(
        Signed::new(&a_request(), &somebody_else()),
        Err(Refusal::WrongType { name: "key" })
    );

    // And at the reading end, against a value built by hand, because the writing end is ours and
    // the reading end is what faces a stranger. The body names the sender and the signature is
    // somebody else's over that same body.
    let honest = Signed::new(&a_request(), &sender()).expect("signs");
    let body = cbor::decode(&a_request().to_cbor()).expect("decodes");
    let forged = somebody_else().sign_value(&body);
    let Value::Array(parts) = cbor::decode(&forged).expect("decodes") else {
        panic!("an array");
    };
    assert_ne!(parts[3], parts_of(&honest)[3], "the two signatures differ");
    assert_eq!(
        Signed::from_wire(&wire_of(parts)),
        Err(Refusal::SignatureDoesNotMatch)
    );
}

#[test]
fn the_key_outside_the_signature_is_held_to_the_key_inside_it() {
    // The unprotected header is outside the signature, so a holder could otherwise restate one
    // signed exchange as several byte strings that all verify. Each of those is a second spelling,
    // and a response names its request by the hash of what travelled.
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let missing = Refusal::WrongType {
        name: "the unprotected header",
    };

    // Dropped altogether.
    let mut parts = parts_of(&signed);
    parts[1] = Value::Map(Vec::new());
    assert_eq!(Signed::from_wire(&wire_of(parts)), Err(missing.clone()));

    // Padded with a label nobody reads.
    let mut parts = parts_of(&signed);
    let Value::Map(mut header) = parts[1].clone() else {
        panic!("a map");
    };
    let padding = "x".repeat(400);
    header.push((Value::Int(9), Value::text(&padding)));
    header.sort_by_cached_key(|(k, _)| cbor::encode(k));
    parts[1] = Value::Map(header);
    assert_eq!(Signed::from_wire(&wire_of(parts)), Err(missing.clone()));

    // Relabelled, so the one entry is not the key identifier.
    let mut parts = parts_of(&signed);
    parts[1] = Value::Map(vec![(
        Value::Int(9),
        Value::Bytes(sender().public_key_bytes()),
    )]);
    assert_eq!(Signed::from_wire(&wire_of(parts)), Err(missing));

    // Naming a different key from the one inside the signature.
    let mut parts = parts_of(&signed);
    parts[1] = Value::Map(vec![(
        Value::Int(4),
        Value::Bytes(somebody_else().public_key_bytes()),
    )]);
    assert!(matches!(
        Signed::from_wire(&wire_of(parts)),
        Err(Refusal::Incoherent { .. })
    ));

    // The control: put back untouched, it still reads.
    assert!(Signed::from_wire(&wire_of(parts_of(&signed))).is_ok());
}

#[test]
fn a_second_spelling_of_a_signed_exchange_is_refused() {
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let mut parts = parts_of(&signed);
    parts.push(Value::text("and a fifth thing"));
    assert_eq!(Signed::from_wire(&wire_of(parts)), Err(Refusal::NotSigned));

    // An envelope that is not an array at all.
    let wire = format!(
        "{PREFIX}{}",
        base64url::encode(&cbor::encode(&Value::Int(1)))
    );
    assert_eq!(Signed::from_wire(&wire), Err(Refusal::NotSigned));

    // And bytes that decode and re-encode to something else, which is refused before the envelope
    // is looked at, exactly as the unsigned body was.
    let indefinite = [0x9f, 0x01, 0xff];
    let wire = format!("{PREFIX}{}", base64url::encode(&indefinite));
    assert_eq!(Signed::from_wire(&wire), Err(Refusal::NotDeterministicCbor));
}

#[test]
fn a_field_the_form_does_not_name_is_still_refused_inside_a_signature() {
    // Signing it does not make it readable. A signed body carrying a field the form does not name is
    // a second spelling of one claim that the sender signed on purpose.
    let Value::Map(mut pairs) = cbor::decode(&a_request().to_cbor()).expect("decodes") else {
        panic!("a map");
    };
    pairs.push((Value::text("zz"), Value::text("anything at all")));
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    let envelope = sender().sign_value(&Value::Map(pairs));
    let wire = format!("{PREFIX}{}", base64url::encode(&envelope));
    assert_eq!(
        Signed::from_wire(&wire),
        Err(Refusal::UnknownField {
            name: "zz".to_string()
        })
    );
}

#[test]
fn a_signature_cannot_be_moved_onto_a_body_naming_another_algorithm() {
    // The reason the `Sig_structure` covers the protected header rather than only the payload. A
    // header naming another algorithm is refused for the algorithm before the signature is looked
    // at, so a signature made under one algorithm cannot be replayed under another.
    let signed = Signed::new(&a_request(), &sender()).expect("signs");
    let mut parts = parts_of(&signed);
    parts[0] = Value::Bytes(cbor::encode(&Value::Map(vec![(
        Value::Int(1),
        Value::Int(-7),
    )])));
    assert_eq!(Signed::from_wire(&wire_of(parts)), Err(Refusal::NotSigned));
}
