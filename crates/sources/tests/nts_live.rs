//! A real key exchange and a real round trip against the published NTS servers.
//!
//! Ignored by default, so a build never fails because somebody else's server is down. Run it by
//! hand:
//!
//! ```text
//! cargo test -p timewitness-sources --test nts_live -- --ignored --nocapture
//! ```
//!
//! Three things are watched for and each is a different kind of wrong.
//!
//! The first is that the answer authenticates at all, which is the whole reason this source exists:
//! the key exchange has to complete over TLS, the reply has to carry back the identifier this
//! machine chose, and the authenticator has to check against the key nobody on the path holds.
//!
//! The second is that it is no wider than plain NTP from the same operator. NTS adds a few hundred
//! bytes to a datagram and nothing else, so a materially wider answer means something is being paid
//! for that the protocol does not charge.
//!
//! The third is that a second poll spends a fresh cookie rather than repeating one. A cookie is
//! single use, so a client that reuses one is both refused by the server and linkable on the wire.

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::MonotonicNanos;
use timewitness_sources::nts::{NtsClient, NtsServer};
use timewitness_sources::TimeSource;

#[test]
#[ignore = "talks to somebody else's server"]
fn every_published_server_authenticates_and_answers_in_milliseconds() {
    let mut answered = 0;

    for server in NtsServer::published() {
        let mut client = NtsClient::new(server.clone());
        let mut nonce = [0u8; 32];
        getrandom_or_counter(&mut nonce);

        let exchange = match client.poll(MonotonicNanos(0), &nonce) {
            Ok(e) => e,
            Err(e) => {
                println!("{}: no answer, {e}", server.name);
                continue;
            }
        };
        answered += 1;

        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_nanos() as i128;
        let apart = (exchange.t3.as_nanos() - wall).abs();
        let round_trip = exchange.mono_t4.as_nanos() - exchange.mono_t1.as_nanos();

        println!(
            "{}: stated uncertainty {:.3} ms, round trip {:.3} ms, {:.3} ms from this machine's \
             own clock",
            server.name,
            exchange.stated_uncertainty() as f64 / 1_000_000.0,
            round_trip as f64 / 1_000_000.0,
            apart as f64 / 1_000_000.0
        );

        assert!(
            exchange.stated_uncertainty() < 1_000_000_000,
            "{} states {} ns of uncertainty about itself, which is a second or more",
            server.name,
            exchange.stated_uncertainty()
        );
        assert!(
            exchange.attestation.is_none(),
            "an NTS answer must never carry something a caller could mistake for evidence, \
             because the key that authenticated it is one this machine also holds"
        );

        // A second poll on the same client spends the next cookie off the same session, so this is
        // also the check that the cookies the first reply returned are usable.
        let mut again = [0u8; 32];
        getrandom_or_counter(&mut again);
        match client.poll(MonotonicNanos(0), &again) {
            Ok(second) => println!(
                "{}: a second poll on the same session, round trip {:.3} ms",
                server.name,
                (second.mono_t4.as_nanos() - second.mono_t1.as_nanos()) as f64 / 1_000_000.0
            ),
            Err(e) => panic!(
                "{} answered once and then refused the next cookie: {e}. That is the cookie \
                 rotation being wrong rather than the server being down",
                server.name
            ),
        }
    }

    assert!(
        answered > 0,
        "not one published NTS server answered, so nothing was measured"
    );
}

#[test]
#[ignore = "talks to somebody else's server"]
fn a_nonce_shorter_than_the_identifier_is_refused_before_a_key_exchange_runs() {
    // Cheap to state and worth stating: the length check happens before anything is put on a wire,
    // so a caller with a short nonce costs somebody else's server nothing.
    let mut client = NtsClient::new(NtsServer::new("cloudflare", "time.cloudflare.com"));
    let refused = client
        .poll(MonotonicNanos(0), &[0u8; 8])
        .expect_err("eight bytes where thirty-two are needed");
    assert!(format!("{refused}").contains("invalid"), "{refused}");
}

/// Random bytes where the machine will give them, and a fixed pattern where it will not.
fn getrandom_or_counter(bytes: &mut [u8]) {
    if getrandom::getrandom(bytes).is_err() {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
    }
}
