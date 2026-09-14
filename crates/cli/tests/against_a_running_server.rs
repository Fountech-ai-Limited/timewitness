//! The shipped client against a Roughtime server of ours that is actually running.
//!
//! Ignored by default, because it needs a server on a network rather than a socket in this process.
//! `our_client_against_our_server.rs` is the one that runs everywhere: it proves the client and the
//! server agree over loopback with a reading handed in by the test. This one proves the other half,
//! which no unit test can reach and which is the half a deployment is wrong in: that a server we
//! have stood up somewhere answers a real request from a machine that is not it, under the key we
//! published, from a clock model it disciplined itself.
//!
//! Run it against a server by name:
//!
//! ```text
//! TIMEWITNESS_PROBE_ADDRESS=timewitness-roughtime-lhr.fly.dev:2002 \
//! TIMEWITNESS_PROBE_KEY=<64 hex characters> \
//!     cargo test -p timewitness-cli --test against_a_running_server -- --ignored --nocapture
//! ```
//!
//! Or against every server a key log names, under the key it names for it, which is how a reader
//! checks a log we serve against what the servers actually sign:
//!
//! ```text
//! TIMEWITNESS_PROBE_KEY_LOG=<a key log> //!     cargo test -p timewitness-cli --test against_a_running_server -- --ignored --nocapture
//! ```
//!
//! **What a pass means and what it does not.** It means that server answered, that the answer
//! checks against the key we published for it, and that the corridor it states is the two seconds
//! the wire format allows and not something narrower. It is not evidence of an independent
//! operator, and it never can be: the server is ours, the exchange is marked first party, and
//! `crates/clock/tests/our_own_servers.rs` is where that refusal is proved.

use std::time::Duration;

use timewitness_core::keylog::file::parse;
use timewitness_core::{MonotonicNanos, SourceKind};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};

/// Where the server is, as host and port.
const ADDRESS: &str = "TIMEWITNESS_PROBE_ADDRESS";
/// Its long-term public key, as sixty-four hex characters.
const KEY: &str = "TIMEWITNESS_PROBE_KEY";
/// A key log, whose entries say which server to ask and under which key.
const KEY_LOG: &str = "TIMEWITNESS_PROBE_KEY_LOG";

#[test]
#[ignore = "needs a Roughtime server of ours running somewhere, named in the environment"]
fn a_server_of_ours_answers_this_machine_under_the_key_we_published() {
    let address = std::env::var(ADDRESS)
        .unwrap_or_else(|_| panic!("{ADDRESS} says which server to ask, as host:port"));
    let key = std::env::var(KEY)
        .unwrap_or_else(|_| panic!("{KEY} says its long-term public key, as 64 hex characters"));
    let key = from_hex(&key).expect("the key is 64 hex characters");
    ask(&address, key);
}

#[test]
#[ignore = "needs the Roughtime servers a key log names to be running, and the log in the environment"]
fn every_server_a_key_log_names_answers_under_the_key_it_names() {
    let path =
        std::env::var(KEY_LOG).unwrap_or_else(|_| panic!("{KEY_LOG} says which key log to read"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the key log at {path} could not be read: {e}"));
    let log = parse(&text).unwrap_or_else(|e| panic!("the key log at {path} is not one: {e}"));
    assert_ne!(
        log.head_is_signed_by_the_key_it_names(),
        Some(false),
        "a head that does not check makes every entry under it worth nothing"
    );

    // An entry still in use whose deployment ends in an address is a server a reader can ask. A
    // retired key is not asked: a server that still answered under one would be the finding.
    let mut asked = 0;
    for entry in log.entries.iter().filter(|e| e.valid_until.is_none()) {
        let Some(address) = entry.deployment.rsplit(' ').next() else {
            continue;
        };
        if address.contains(':') {
            ask(address, entry.public_key);
            asked += 1;
        }
    }
    assert!(asked > 0, "the log at {path} names no server to ask");
}

/// One request to a server of ours, checked against the key given for it.
fn ask(address: &str, key: [u8; 32]) {
    // Declared as ours, because it is. The label is what keeps a corridor of ours out of the
    // independent operator count, and a probe that described it as anything else would be
    // measuring a configuration nobody would ever run.
    let described =
        RoughtimeServer::new("ours", address.to_string(), key).operated_by_us("timewitness.dev");
    let client = RoughtimeClient::new(described).waiting(Duration::from_secs(5));

    let nonce = RoughtimeClient::random_nonce().expect("a nonce");
    let exchange = client
        .poll_bound(MonotonicNanos(0), &nonce, &[])
        .unwrap_or_else(|e| panic!("{address} did not answer: {e}"));

    assert_eq!(exchange.kind, SourceKind::Roughtime);
    assert!(
        exchange.operator.is_first_party(),
        "a server of ours is not an independent chance to be wrong"
    );

    let attestation = exchange
        .attestation
        .as_ref()
        .expect("a Roughtime exchange carries evidence a stranger could check");
    let radius = attestation
        .radius
        .expect("a Roughtime response states a radius");
    assert_eq!(
        radius, 1_000_000_000,
        "a radius of one second, so a corridor of two, which is the narrowest a Roughtime corridor \
         can be whoever runs the server. Anything else here is the server claiming a width the \
         format cannot carry"
    );

    println!(
        "{address} answered under {}, stating a corridor {} s wide around its own reading",
        key[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        (radius * 2) / 1_000_000_000
    );
}

fn from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
