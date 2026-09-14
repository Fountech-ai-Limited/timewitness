//! Capture one of each of the three kinds of evidence, about the same subject, at the same moment.
//!
//! Ignored by default. This is the instrument that refreshes the corpus a receipt is built from:
//!
//! ```text
//! cargo test -p timewitness-sources --test evidence_capture -- --ignored --nocapture
//! ```
//!
//! The three have to be taken together and about one subject, because what they are for is a
//! sandwich, and three pieces of evidence gathered on different days about different things do not
//! make one. That is the whole point of the test they feed.

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::evidence::{drand, rfc3161, roughtime};
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::{MonotonicNanos, UnixNanos};
use timewitness_sources::drand::{DrandClient, DEFAULT_STALENESS};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};
use timewitness_sources::timestamp::{published_authorities, TimestampClient};
use timewitness_sources::FreshnessBeacon;

/// The subject everything in the corpus is about.
///
/// A stand-in for the hash of whatever is being stamped. It is a fixed value rather than a real
/// hash so that the corpus files and the tests that read them name the same thing without either of
/// them having to compute it.
const SUBJECT: [u8; 32] = [0x5au8; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn wrapped(bytes: &[u8]) -> String {
    let text = hex(bytes);
    text.as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "talks to three sets of somebody else's servers"]
fn one_of_each_role_about_one_subject() {
    let roughly_now = UnixNanos(
        i128::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("this machine thinks it is before 1970")
                .as_secs(),
        ) * NANOS_PER_SEC,
    );

    // Not-earlier-than first, because a beacon has to be published before the thing it pins.
    let beacon = DrandClient::quicknet();
    let round = beacon
        .fetch_near(roughly_now, DEFAULT_STALENESS)
        .expect("a current drand round");
    let stored_round = drand::unpack_blob(&round.blob).expect("unpacks");
    println!(
        "drand round {} at {} s",
        stored_round.round,
        round.at.as_nanos() / NANOS_PER_SEC
    );
    println!("BEGIN drand\n{}\nEND drand", wrapped(&round.blob));

    // The corridor, with the nonce bound to the same subject.
    for server in RoughtimeServer::published() {
        let client = RoughtimeClient::new(server.clone());
        let Ok(exchange) = client.poll_for_subject(MonotonicNanos(0), &SUBJECT) else {
            println!("{} did not answer", server.name);
            continue;
        };
        let attestation = exchange.attestation.expect("verified");
        println!(
            "roughtime {} midpoint {} s radius {} s",
            server.name,
            attestation.at.as_nanos() / NANOS_PER_SEC,
            attestation.radius.unwrap_or(0) / NANOS_PER_SEC
        );
        println!(
            "BEGIN roughtime {}\n{}\nEND roughtime",
            server.name,
            wrapped(&attestation.blob)
        );
    }

    // Not-later-than last, because a witness has to see the thing before it can say it saw it.
    for authority in published_authorities() {
        let client = TimestampClient::new(authority.clone());
        let Ok(attestation) = client.stamp(&SUBJECT) else {
            println!("{} did not answer", authority.name);
            continue;
        };
        println!(
            "rfc3161 {} at {} s",
            authority.name,
            attestation.at.as_nanos() / NANOS_PER_SEC
        );
        println!(
            "BEGIN rfc3161 {}\n{}\nEND rfc3161",
            authority.name,
            wrapped(&attestation.blob)
        );
    }

    // A last sanity read, so the log says how far apart the three ended up.
    let _ = rfc3161::SCHEME;
    let _ = roughtime::SCHEME;
}
