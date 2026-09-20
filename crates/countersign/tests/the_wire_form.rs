//! The countersign wire form, round-tripped and attacked, with nothing signed yet.
//!
//! Slice one of the protocol is the shape on the wire and what a receiver does with one it cannot
//! read. Signing, verifying and ordering are later slices and nothing here reaches into them.
//!
//! Every refusal below is watched refusing against a value that passes, so a green run says the
//! branch fired rather than that the test ran.

use timewitness_countersign::{
    base64url, Exchange, Interval, Refusal, Role, MAX_WIRE_CHARS, PREFIX,
};
use timewitness_receipt::cbor;
use timewitness_receipt::Value;

fn digest(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
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
        key: digest(200).to_vec(),
        answers: None,
    }
}

fn a_response() -> Exchange {
    Exchange {
        role: Role::Response,
        payload: digest(2),
        sequence: 1,
        interval: Interval {
            earliest_ns: 1_788_979_279_045_210_129,
            reading_ns: 1_788_979_279_118_450_302,
            latest_ns: 1_788_979_279_199_084_899,
        },
        receipt: digest(150),
        key: digest(250).to_vec(),
        answers: Some(a_request().body_hash()),
    }
}

/// Take a value apart, change one field, and put it back on the wire.
fn wire_with(exchange: &Exchange, edit: impl Fn(&mut Vec<(Value, Value)>)) -> String {
    let Value::Map(mut pairs) = cbor::decode(&exchange.to_cbor()).expect("our own bytes decode")
    else {
        panic!("the body is a map");
    };
    edit(&mut pairs);
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    format!(
        "{PREFIX}{}",
        base64url::encode(&cbor::encode(&Value::Map(pairs)))
    )
}

fn key_of(name: &str) -> Value {
    Value::text(name)
}

#[test]
fn a_request_and_a_response_both_go_out_and_come_back_the_same() {
    for original in [a_request(), a_response()] {
        let wire = original.to_wire();
        let back = Exchange::from_wire(&wire).expect("our own value reads back");
        assert_eq!(back, original);
        // And the bytes are the same bytes, which is what a signature will be over.
        assert_eq!(back.to_cbor(), original.to_cbor());
        assert_eq!(back.to_wire(), wire);
    }
}

#[test]
fn a_whole_exchange_fits_in_a_header_with_room_to_spare() {
    let request = a_request().to_wire();
    let response = a_response().to_wire();
    println!(
        "request {} characters, response {} characters, ceiling {MAX_WIRE_CHARS}",
        request.len(),
        response.len()
    );
    assert!(
        request.len() < 400,
        "a request is {} characters",
        request.len()
    );
    assert!(
        response.len() < 450,
        "a response is {} characters",
        response.len()
    );
    assert!(
        response.len() > request.len(),
        "a response carries one field more"
    );
}

#[test]
fn the_receipt_this_claim_came_from_is_named_and_not_carried() {
    // The committed real receipt is the case this ceiling exists for. Base64url of it would be
    // three times the whole header block a common server will accept, so it can never travel here.
    let receipt = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../verify/tests/data/a-real-stamp/receipt.cbor"
    ))
    .expect("the committed receipt is in the tree");
    let as_a_header = base64url::encode(&receipt).len();
    println!(
        "the committed receipt is {} bytes and would be {as_a_header} characters on the wire",
        receipt.len()
    );
    assert!(
        as_a_header > MAX_WIRE_CHARS * 2,
        "the receipt is {as_a_header} characters, which is no longer the reason this form names it \
         by hash, so the reason needs rewriting rather than the assertion relaxing"
    );
    assert!(a_request().to_wire().len() < MAX_WIRE_CHARS / 8);
}

#[test]
fn a_value_that_is_not_ours_is_refused_without_being_parsed() {
    assert!(matches!(
        Exchange::from_wire("tw0.AQ"),
        Err(Refusal::NotThisVersion { .. })
    ));
    assert!(matches!(
        Exchange::from_wire("Bearer something"),
        Err(Refusal::NotThisVersion { .. })
    ));
    assert!(matches!(
        Exchange::from_wire(""),
        Err(Refusal::NotThisVersion { .. })
    ));
}

#[test]
fn a_value_past_the_ceiling_is_refused_before_anything_decodes_it() {
    let long = format!("{PREFIX}{}", "A".repeat(MAX_WIRE_CHARS));
    assert!(matches!(
        Exchange::from_wire(&long),
        Err(Refusal::TooLong { .. })
    ));
    // And one exactly at the ceiling gets as far as the decoder, which is where it fails for its
    // own reason. The ceiling is not doing work the decoder should be doing.
    let at_the_ceiling = format!("{PREFIX}{}", "A".repeat(MAX_WIRE_CHARS - PREFIX.len()));
    assert!(!matches!(
        Exchange::from_wire(&at_the_ceiling),
        Err(Refusal::TooLong { .. })
    ));
}

#[test]
fn a_second_spelling_of_the_same_value_is_refused() {
    // The encoder cannot be made to emit one, because it orders a map's keys itself, so the bytes
    // are built by hand. That is the point: a second spelling never comes out of this product and
    // it can still arrive from somebody else, and the reader is what has to refuse it. Two headers
    // that mean the same thing and hash differently is a signature that can be moved.
    //
    // A two entry map with the keys the wrong way round. `a2` is a map of two, `6162` is the text
    // "b", `6161` is the text "a", and deterministic order puts "a" first.
    let out_of_order = [0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02];
    let wire = format!("{PREFIX}{}", base64url::encode(&out_of_order));
    assert_eq!(
        Exchange::from_wire(&wire),
        Err(Refusal::NotDeterministicCbor),
        "an out of order map was not refused"
    );

    // An indefinite length map, which is the other spelling CBOR allows and this format does not.
    let indefinite = [0xbf, 0x61, 0x61, 0x01, 0xff];
    let wire = format!("{PREFIX}{}", base64url::encode(&indefinite));
    assert_eq!(
        Exchange::from_wire(&wire),
        Err(Refusal::NotDeterministicCbor)
    );

    // An integer in a longer form than it needs, which is the third.
    let padded_integer = [0xa1, 0x61, 0x61, 0x18, 0x01];
    let wire = format!("{PREFIX}{}", base64url::encode(&padded_integer));
    assert_eq!(
        Exchange::from_wire(&wire),
        Err(Refusal::NotDeterministicCbor)
    );

    // And a well formed map that is simply not an exchange gets past the encoding and fails on its
    // fields, so the three above failed for the reason they say and not for being short.
    let honest_but_empty = [0xa0];
    let wire = format!("{PREFIX}{}", base64url::encode(&honest_but_empty));
    assert_eq!(
        Exchange::from_wire(&wire),
        Err(Refusal::MissingField { name: "v" })
    );
}

#[test]
fn something_that_is_not_base64_is_refused() {
    assert_eq!(Exchange::from_wire("tw1.!!!!"), Err(Refusal::NotBase64));
    assert_eq!(Exchange::from_wire("tw1.AQ=="), Err(Refusal::NotBase64));
    assert_eq!(Exchange::from_wire("tw1.A Q"), Err(Refusal::NotBase64));
}

#[test]
fn every_field_the_form_needs_is_refused_by_its_absence() {
    for name in ["v", "role", "hash", "seq", "lo", "mid", "hi", "rcpt", "key"] {
        let wire = wire_with(&a_request(), |pairs| {
            pairs.retain(|(k, _)| k != &key_of(name));
        });
        let got = Exchange::from_wire(&wire);
        match name {
            // The version is checked before the rest, and its absence reads as a version this does
            // not know rather than as a missing field.
            "v" => assert!(matches!(got, Err(Refusal::MissingField { name: "v" }))),
            _ => assert_eq!(
                got,
                Err(Refusal::MissingField { name }),
                "dropping `{name}` was not refused for being missing"
            ),
        }
    }
}

#[test]
fn a_field_of_the_wrong_shape_is_refused() {
    let wrong_key_length = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("key") {
                *v = Value::Bytes(vec![1, 2, 3]);
            }
        }
    });
    assert_eq!(
        Exchange::from_wire(&wrong_key_length),
        Err(Refusal::WrongType { name: "key" })
    );

    let hash_as_text = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("hash") {
                *v = Value::text("not bytes");
            }
        }
    });
    assert_eq!(
        Exchange::from_wire(&hash_as_text),
        Err(Refusal::WrongType { name: "hash" })
    );

    let unknown_role = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("role") {
                *v = Value::text("witness");
            }
        }
    });
    assert_eq!(
        Exchange::from_wire(&unknown_role),
        Err(Refusal::WrongType { name: "role" })
    );

    let negative_sequence = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("seq") {
                *v = Value::Int(-1);
            }
        }
    });
    assert_eq!(
        Exchange::from_wire(&negative_sequence),
        Err(Refusal::WrongType { name: "seq" })
    );
}

#[test]
fn an_interval_that_cannot_be_true_is_refused() {
    let edges_swapped = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("lo") {
                *v = Value::Int(i128::MAX / 2);
            }
        }
    });
    assert!(matches!(
        Exchange::from_wire(&edges_swapped),
        Err(Refusal::Incoherent { .. })
    ));

    let reading_outside = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("mid") {
                *v = Value::Int(0);
            }
        }
    });
    assert!(matches!(
        Exchange::from_wire(&reading_outside),
        Err(Refusal::Incoherent { .. })
    ));
}

#[test]
fn a_version_this_does_not_know_is_refused_inside_the_encoding_as_well_as_outside_it() {
    let inner_version = wire_with(&a_request(), |pairs| {
        for (k, v) in pairs.iter_mut() {
            if k == &key_of("v") {
                *v = Value::Int(2);
            }
        }
    });
    assert!(matches!(
        Exchange::from_wire(&inner_version),
        Err(Refusal::NotThisVersion { .. })
    ));
}

#[test]
fn a_response_that_names_no_request_is_refused_and_a_request_that_names_one_is_too() {
    let orphan_response = wire_with(&a_response(), |pairs| {
        pairs.retain(|(k, _)| k != &key_of("req"));
    });
    assert_eq!(
        Exchange::from_wire(&orphan_response),
        Err(Refusal::MissingField { name: "req" })
    );

    let request_answering_something = wire_with(&a_request(), |pairs| {
        pairs.push((key_of("req"), Value::Bytes(digest(9).to_vec())));
    });
    assert!(matches!(
        Exchange::from_wire(&request_answering_something),
        Err(Refusal::Incoherent { .. })
    ));
}

#[test]
fn the_same_body_reads_the_same_whether_it_came_from_a_header_or_a_tool_call() {
    // An MCP tool call carries the body as a field rather than as a header, so the two routes have
    // to agree about everything below the encoding or the protocol has two meanings.
    for original in [a_request(), a_response()] {
        let as_a_header = Exchange::from_wire(&original.to_wire()).expect("the header route");
        let decoded = cbor::decode(&original.to_cbor()).expect("the tool call route");
        let as_a_field = Exchange::from_value(&decoded).expect("the tool call route");
        assert_eq!(as_a_header, as_a_field);
    }
}

#[test]
fn the_hash_a_response_names_its_request_by_is_the_hash_of_the_request_body() {
    let request = a_request();
    let response = a_response();
    assert_eq!(response.answers, Some(request.body_hash()));
    // And it moves when the request does, or it is binding nothing.
    let mut other = request.clone();
    other.sequence += 1;
    assert_ne!(other.body_hash(), request.body_hash());
}
