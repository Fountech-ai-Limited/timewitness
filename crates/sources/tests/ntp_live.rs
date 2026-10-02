//! A real round trip against the published NTP servers.
//!
//! Ignored by default, so a build never fails because somebody else's server is down. Run it by
//! hand:
//!
//! ```text
//! cargo test -p timewitness-sources --test ntp_live -- --ignored --nocapture
//! ```
//!
//! What it is watching for is the thing that separates this source from Roughtime. A Roughtime
//! server states a radius in whole seconds; an NTP server states a root delay and a dispersion in
//! units of about fifteen microseconds. So the interval an answer here supports should be
//! milliseconds rather than seconds, and if it ever is not, the reason is worth knowing before a
//! bound is built on it.

use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::MonotonicNanos;
use timewitness_sources::ntp::{NtpClient, NtpServer};
use timewitness_sources::TimeSource;

#[test]
#[ignore = "talks to somebody else's server"]
fn every_published_server_answers_with_something_narrower_than_a_second() {
    let mut answered = 0;

    for server in NtpServer::published() {
        let mut client = NtpClient::new(server.clone());
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
            "{} states {} ns of uncertainty about itself, which is a second or more and is the \
             thing this source exists to improve on",
            server.name,
            exchange.stated_uncertainty()
        );
        assert!(
            exchange.attestation.is_none(),
            "an NTP answer must never carry something a caller could mistake for evidence"
        );
    }

    assert!(
        answered > 0,
        "not one published NTP server answered, so nothing was measured"
    );
}

/// Random bytes where the machine will give them, and a fixed pattern where it will not.
///
/// The challenge only has to be unpredictable to somebody on the path, and a test that cannot run
/// because a container has no entropy source tells nobody anything.
fn getrandom_or_counter(bytes: &mut [u8]) {
    if getrandom::getrandom(bytes).is_err() {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
    }
}
