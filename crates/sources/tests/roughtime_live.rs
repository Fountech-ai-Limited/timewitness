//! A real round trip against a real Roughtime server.
//!
//! Ignored by default, so a build never fails because somebody else's server is down. Run it by
//! hand, and run it when the corpus under `crates/core/tests/data/roughtime/` needs replacing:
//!
//! ```text
//! cargo test -p timewitness-sources --test roughtime_live -- --ignored --nocapture
//! ```
//!
//! It prints each verified exchange as a hex blob, which is what the offline corpus is made of.
//! Capturing that way rather than by hand means the committed test data is exactly what the client
//! produced, framing and all, rather than a reconstruction of it.

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::evidence::roughtime;
use timewitness_core::MonotonicNanos;
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer, Transport};
use timewitness_sources::TimeSource;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore = "talks to somebody else's server"]
fn every_published_server_answers_and_the_answer_verifies() {
    let subject = b"a build artefact this run is standing in for";
    let mut answered = 0;

    for server in RoughtimeServer::published() {
        let client = RoughtimeClient::new(server.clone());
        let exchange = match client.poll_for_subject(MonotonicNanos(0), subject) {
            Ok(e) => e,
            Err(e) => {
                println!("{}: no answer, {e}", server.name);
                continue;
            }
        };
        answered += 1;

        let attestation = exchange
            .attestation
            .as_ref()
            .expect("a verified Roughtime exchange carries what was signed");
        let round_trip = exchange.mono_t4.since(exchange.mono_t1);
        let radius = attestation.radius.expect("Roughtime states a radius");

        // The reading is against the caller's own counter and the server's midpoint is on UTC, so
        // there is nothing to compare here beyond what the server said about itself. The one figure
        // worth printing is the round trip, and it is printed with what it was measured over.
        println!(
            "{}: round trip {} ms over the public internet from this machine, midpoint {} plus or \
             minus {} s",
            server.name,
            round_trip / 1_000_000,
            attestation.at.as_nanos() / 1_000_000_000,
            radius / 1_000_000_000
        );
        for line in client
            .describe(&attestation.blob)
            .expect("what the client accepted, the check accepts")
        {
            println!("    {line}");
        }
        println!("    blob {}", hex(&attestation.blob));

        assert!(
            radius > 0,
            "{} states a radius of zero, which the draft forbids",
            server.name
        );
        assert_eq!(
            attestation.nonce.len(),
            32,
            "{} was asked over a 32 byte nonce",
            server.name
        );
    }

    assert!(
        answered > 0,
        "no public Roughtime server answered at all, so nothing was proved either way"
    );
}

#[test]
#[ignore = "talks to somebody else's server"]
fn a_response_bound_to_the_wrong_key_is_refused_against_a_live_server() {
    // The same live response, checked against a key that is not the one that signed it. This is the
    // hostile case with a real packet rather than a constructed one.
    let server = RoughtimeServer::published()
        .into_iter()
        .next()
        .expect("there is at least one published server");
    let mut client = RoughtimeClient::new(server.clone());
    let exchange = match client.poll(MonotonicNanos(0), &[9u8; 32]) {
        Ok(e) => e,
        Err(e) => {
            println!("{} did not answer, nothing proved: {e}", server.name);
            return;
        }
    };
    let blob = exchange.attestation.expect("verified").blob;

    let mut wrong_key = server.long_term_public_key;
    wrong_key[0] ^= 0x01;
    let refused = roughtime::check(&blob, &wrong_key, &server.name);
    assert!(
        refused.is_err(),
        "a live response verified against somebody else's key"
    );
}

#[test]
#[ignore = "talks to somebody else's server"]
fn tcp_is_tried_where_a_server_offers_it() {
    for server in RoughtimeServer::published() {
        let client = RoughtimeClient::new(server.clone()).over(Transport::Tcp);
        match client.poll_for_subject(MonotonicNanos(0), b"tcp") {
            Ok(e) => println!(
                "{} answered over TCP, {} bytes stored",
                server.name,
                e.attestation.map(|a| a.blob.len()).unwrap_or(0)
            ),
            Err(e) => println!("{} does not answer over TCP: {e}", server.name),
        }
    }
}

/// Not a test of the protocol. It records what the machine's own clock said against three signed
/// third-party statements at the moment it ran, which is the only place a real figure for this
/// product can come from.
#[test]
#[ignore = "talks to somebody else's server"]
fn what_this_machine_looks_like_against_signed_third_parties() {
    for server in RoughtimeServer::published() {
        let client = RoughtimeClient::new(server.clone());
        let Ok(exchange) = client.poll_for_subject(MonotonicNanos(0), b"reading") else {
            continue;
        };
        let system = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("this machine thinks it is before 1970")
            .as_secs();
        let signed = exchange.t2.as_nanos() / 1_000_000_000;
        println!(
            "{}: the system clock reads {system} and the signed midpoint is {signed}, a difference \
             of {} s inside a stated radius of {} s",
            server.name,
            i128::from(system) - signed,
            exchange.root_dispersion / 1_000_000_000
        );
    }
}
