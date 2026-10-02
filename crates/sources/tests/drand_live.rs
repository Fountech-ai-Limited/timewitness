//! A real fetch from real drand relays.
//!
//! Ignored by default. Run it by hand, and run it when the corpus under
//! `crates/core/tests/data/drand/` needs replacing:
//!
//! ```text
//! cargo test -p timewitness-sources --test drand_live -- --ignored --nocapture
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::evidence::drand;
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::UnixNanos;
use timewitness_sources::drand::{DrandClient, DEFAULT_STALENESS};
use timewitness_sources::FreshnessBeacon;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn roughly_now() -> UnixNanos {
    // This machine's own clock, which is exactly the thing the product says not to trust. It is
    // used here as the expectation a real agent would take from its model, because a test has no
    // model. The signature is what is being proved, not the clock.
    UnixNanos(
        i128::from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("this machine thinks it is before 1970")
                .as_secs(),
        ) * NANOS_PER_SEC,
    )
}

#[test]
#[ignore = "talks to somebody else's relay"]
fn the_current_round_verifies_against_the_group_key() {
    let client = DrandClient::quicknet();
    let attestation = client
        .fetch_near(roughly_now(), DEFAULT_STALENESS)
        .expect("a current round from one of three relays");

    let stored = drand::unpack_blob(&attestation.blob).expect("what we stored unpacks");
    println!(
        "round {} at {} s, signature {} bytes, randomness {}",
        stored.round,
        attestation.at.as_nanos() / NANOS_PER_SEC,
        stored.signature.len(),
        hex(&drand::randomness_of(stored.signature))
    );
    for line in client.describe(&attestation.blob).expect("it verified") {
        println!("    {line}");
    }
    println!("    blob {}", hex(&attestation.blob));

    assert_eq!(
        attestation.radius, None,
        "a round is an instant, not a span"
    );
    assert!(
        attestation.nonce.is_empty(),
        "a beacon signs nothing of ours, so there is no nonce to keep"
    );
}

#[test]
#[ignore = "talks to somebody else's relay"]
fn every_relay_serves_the_same_bytes_for_the_same_round() {
    // Three relays, one chain. This is a check on the relays being consistent, not on the chain
    // being trustworthy: they all serve rounds signed by one group key, so agreeing proves nothing
    // about that key. It is here because a relay quietly serving something else is worth knowing.
    let round = {
        let client = DrandClient::quicknet();
        let a = client
            .fetch_near(roughly_now(), DEFAULT_STALENESS)
            .expect("a current round");
        drand::unpack_blob(&a.blob).expect("unpacks").round
    };

    let mut seen: Vec<(String, String)> = Vec::new();
    for relay in [
        "http://api.drand.sh",
        "http://api2.drand.sh",
        "http://api3.drand.sh",
    ] {
        let client = DrandClient::quicknet().from_relays(vec![relay.to_string()]);
        match client.round(round) {
            Ok(a) => seen.push((relay.to_string(), hex(&a.blob))),
            Err(e) => println!("{relay} did not answer for round {round}: {e}"),
        }
    }
    assert!(!seen.is_empty(), "no relay answered at all");
    for (relay, blob) in &seen[1..] {
        assert_eq!(
            *blob, seen[0].1,
            "{relay} and {} serve different bytes for round {round}",
            seen[0].0
        );
    }
    println!("{} relays agreed on round {round}", seen.len());
}

#[test]
#[ignore = "talks to somebody else's relay"]
fn a_round_from_long_ago_is_refused_as_stale() {
    // Round one, which is genuinely signed and genuinely published in 2023. The signature checks
    // and the round is still refused, because a not-earlier-than edge three years behind the
    // reading pins nothing anybody wanted pinned.
    let client = DrandClient::quicknet();
    let genuine = client.round(1).expect("round one is still served");
    let checked = client.describe(&genuine.blob).expect("round one verifies");
    assert!(!checked.is_empty());

    let err = client
        .from_relays(vec!["http://api.drand.sh".to_string()])
        .latest_near(UnixNanos(0), 1)
        .expect_err("a current round offered against an expectation at the epoch");
    println!("refused: {err}");
}
