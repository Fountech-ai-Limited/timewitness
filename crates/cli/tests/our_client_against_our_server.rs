//! The client this product ships, against a server this product runs.
//!
//! The server crate proves itself against `timewitness_core`'s own checker, and the two halves of
//! the wire format live in one file so they cannot drift. Neither of those proves the thing a
//! deployment needs, which is that the client this product actually ships, with its own socket
//! handling, its own timeouts and its own nonce, gets a usable bound out of a server of ours.
//!
//! It runs over loopback on a port the operating system picks, so it needs no configuration, is
//! not a live network test, and cannot collide with another copy of itself.
//!
//! **What this test is deliberately not.** It is not evidence that a server of ours is an
//! independent operator, and it is not evidence that running our own servers narrows anything. The
//! first is what `crates/clock/tests/our_own_servers.rs` refuses and the second the wire format
//! makes impossible: the radius is a whole number of seconds, so the corridor below is two seconds
//! wide and that is the narrowest it can be.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use timewitness_core::{MonotonicNanos, SourceKind};
use timewitness_roughtime_server::{serve, LongTermKey, RateLimit, Reading, Server};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};

const NOW: u64 = 1_800_000_000;

#[test]
fn the_shipped_client_polls_a_server_of_ours_and_gets_a_bound() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback port");
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("a read timeout, so the loop can see the stop flag");
    let address = socket.local_addr().expect("the port it got");

    let key = LongTermKey::from_bytes(&[99u8; 32]);
    let public_key = key.public();
    let mut server = Server::new(key, NOW).expect("a server with a delegation");
    let mut limit = RateLimit::default();

    let stop = Arc::new(AtomicBool::new(false));
    let watching = Arc::clone(&stop);
    let thread = std::thread::spawn(move || {
        let _ = serve(
            &socket,
            &mut server,
            &mut limit,
            || {
                Some(Reading {
                    seconds: NOW,
                    radius_seconds: 1,
                })
            },
            || !watching.load(Ordering::Relaxed),
            |_, _| {},
        );
    });

    // Declared as ours, which is the whole point of the label: this exchange is a real measurement
    // and it is not an independent chance to be wrong.
    let described = RoughtimeServer::new("ours", address.to_string(), public_key)
        .operated_by_us("timewitness.dev");
    let client = RoughtimeClient::new(described).waiting(Duration::from_secs(2));

    let nonce = RoughtimeClient::random_nonce().expect("a nonce");
    let exchange = client
        .poll_bound(MonotonicNanos(0), &nonce, &[])
        .expect("the shipped client gets an answer from a server of ours");

    assert_eq!(exchange.kind, SourceKind::Roughtime);
    assert!(
        exchange.operator.is_first_party(),
        "the exchange carries the label through, so the selection can act on it"
    );
    assert_eq!(exchange.operator.as_str(), "timewitness.dev");

    let attestation = exchange
        .attestation
        .as_ref()
        .expect("a Roughtime exchange carries evidence a stranger could check");
    assert_eq!(
        attestation.radius,
        Some(1_000_000_000),
        "one second of radius, so two seconds of corridor, which is the narrowest a Roughtime          corridor can be whoever runs the server"
    );

    stop.store(true, Ordering::Relaxed);
    thread.join().expect("the thread ends");
}
