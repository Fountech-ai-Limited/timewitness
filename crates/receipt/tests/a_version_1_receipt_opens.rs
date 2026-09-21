//! A version 1 receipt opens, and it reads back with every field it was signed with.
//!
//! Written against the receipt format's public surface as it stood at version 0 and nothing added
//! since, so the same file builds against the code before version 1 existed. There it fails,
//! refused as a version that code does not read, and that failure is what `v0.1` in anybody's hands
//! does with a receipt this code writes. Here it passes.

use timewitness_receipt::value::Value;
use timewitness_receipt::{cbor, open, AgentKey};

const THE_COMMITTED_RECEIPT: &[u8] =
    include_bytes!("../../verify/tests/data/a-real-stamp/receipt.cbor");

fn key() -> AgentKey {
    AgentKey::from_seed(&[11u8; 32])
}

fn sorted(mut pairs: Vec<(Value, Value)>) -> Value {
    pairs.sort_by_cached_key(|(k, _)| cbor::encode(k));
    Value::Map(pairs)
}

fn set(map: &Value, key: &str, value: Value) -> Value {
    let Value::Map(pairs) = map else {
        panic!("{key} belongs in a map")
    };
    let mut pairs: Vec<(Value, Value)> = pairs
        .iter()
        .filter(|(k, _)| k.as_text() != Some(key))
        .cloned()
        .collect();
    pairs.push((Value::Text(key.to_string()), value));
    sorted(pairs)
}

/// The committed receipt's body, rewritten as version 1 and signed again by a key of the test's own.
fn the_committed_receipt_as_version_1() -> (Vec<u8>, Vec<u8>) {
    let envelope = cbor::decode(THE_COMMITTED_RECEIPT).expect("the committed receipt decodes");
    let body = cbor::decode(envelope.as_array().unwrap()[2].as_bytes().unwrap()).unwrap();

    let claim = body.get("claim").unwrap();
    let holdover = claim
        .get("breakdown")
        .and_then(|b| b.get("oscillator_holdover_ns"))
        .and_then(Value::as_int)
        .unwrap();
    let breakdown = set(
        claim.get("breakdown").unwrap(),
        "unclaimed_rate_ns",
        Value::Int(holdover),
    );
    let mut policy = claim.get("policy").unwrap().clone();
    for (name, value) in [
        ("source_interval_floor_ns", 100_000),
        ("frequency_slew_ppb_per_s", 1_000),
        ("frequency_span_ppb", 100_000),
    ] {
        policy = set(&policy, name, Value::Int(value));
    }
    let mut claim = set(claim, "breakdown", breakdown);
    claim = set(&claim, "policy", policy);
    claim = set(&claim, "taken_by", Value::Text("one-shot".to_string()));
    // The committed receipt claims no rate, so the whole of its holdover is unclaimed, which is
    // the largest the part may be.
    assert_eq!(claim.get("frequency_ppb").and_then(Value::as_int), Some(0));

    let mut body = set(&body, "claim", claim);
    body = set(&body, "v", Value::Int(1));
    body = set(
        &body,
        "agent",
        sorted(vec![(
            Value::Text("public_key".to_string()),
            Value::Bytes(key().public_key_bytes()),
        )]),
    );
    (key().sign_value(&body), cbor::encode(&body))
}

#[test]
fn a_version_1_receipt_opens_and_reads_back_as_it_was_signed() {
    let (signed, body) = the_committed_receipt_as_version_1();
    let opened = open(&signed).expect("a version 1 receipt opens");
    assert_eq!(opened.version, 1);
    assert_eq!(
        cbor::encode(&opened.to_value()),
        body,
        "every field a version 1 receipt was signed with reads back, and nothing is dropped"
    );
}

#[test]
fn the_committed_version_0_receipt_still_reads_back_byte_for_byte() {
    let opened = open(THE_COMMITTED_RECEIPT).expect("the committed receipt opens");
    assert_eq!(opened.version, 0);
    let envelope = cbor::decode(THE_COMMITTED_RECEIPT).unwrap();
    let body = envelope.as_array().unwrap()[2].as_bytes().unwrap().to_vec();
    assert_eq!(cbor::encode(&opened.to_value()), body);
}
