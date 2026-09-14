//! The server on a real socket, answering a real client.
//!
//! Everything in the crate's own tests hands `answer` a packet directly. That proves the protocol
//! and proves nothing about the loop: a server that parses perfectly and never replies to the
//! address that asked is a server that passes all of them. So this binds a socket, runs `serve` in
//! a thread, sends it packets, and reads what comes back.
//!
//! It runs on the loopback address on a port the operating system picks, so it needs no
//! configuration and cannot collide with another copy of itself.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use timewitness_core::evidence::roughtime::{build_request, check, pack_blob};
use timewitness_roughtime_server::{serve, LongTermKey, RateLimit, Reading, Server};

const NOW: u64 = 1_800_000_000;

/// A server running in a thread, and everything needed to talk to it and stop it.
struct Running {
    address: SocketAddr,
    public_key: [u8; 32],
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    fn start(per_window: u32) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback port");
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a read timeout, so the loop can see the stop flag");
        let address = socket.local_addr().expect("the port it got");

        let key = LongTermKey::from_bytes(&[77u8; 32]);
        let public_key = key.public();
        let mut server = Server::new(key, NOW).expect("a server with a delegation");
        let mut limit = RateLimit::new(per_window, Duration::from_secs(60));

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

        Self {
            address,
            public_key,
            stop,
            thread: Some(thread),
        }
    }

    /// Send a packet and wait for an answer. `None` means none came inside `patience`.
    ///
    /// **The two waits are different lengths on purpose, and the first version of this file used
    /// one.** It waited half a second either way, which was enough alone and not enough under a
    /// whole-workspace run: the machine was compiling and running everything else, the reply came
    /// late, and a test asserting an answer went red. A test that fails when the machine is busy
    /// would fail on a runner, and this one would have gone red after being pushed rather than
    /// before.
    ///
    /// So a test expecting an answer waits a long time, because being slow is not being wrong. A
    /// test expecting silence waits a short time, because the server either replies to that packet
    /// or never will, so there is nothing a longer wait could catch.
    fn ask_waiting(&self, packet: &[u8], patience: Duration) -> Option<Vec<u8>> {
        let client = UdpSocket::bind("127.0.0.1:0").expect("a client port");
        client
            .set_read_timeout(Some(patience))
            .expect("a read timeout");
        client.send_to(packet, self.address).expect("sent");

        let mut buffer = [0u8; 1500];
        match client.recv_from(&mut buffer) {
            Ok((len, _)) => Some(buffer[..len].to_vec()),
            Err(_) => None,
        }
    }

    /// Ask, expecting an answer.
    fn ask(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.ask_waiting(packet, Duration::from_secs(10))
    }

    /// Ask, expecting silence.
    fn ask_expecting_nothing(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.ask_waiting(packet, Duration::from_millis(300))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[test]
fn a_client_gets_a_response_that_checks_against_the_published_key() {
    let server = Running::start(60);
    let nonce = [0x33; 32];
    let request = build_request(&nonce, &server.public_key);

    let response = server.ask(&request).expect("the server answered");
    let checked = check(
        &pack_blob(&[], &request, &response),
        &server.public_key,
        "a server of ours",
    )
    .expect("and the answer holds up");

    assert_eq!(checked.nonce.as_deref(), Some(nonce.as_slice()));
    assert_eq!(
        checked.latest().0 - checked.earliest().0,
        2_000_000_000,
        "two seconds is the narrowest a Roughtime corridor ever is"
    );
}

#[test]
fn a_bad_packet_gets_silence_rather_than_an_error() {
    // A Roughtime server has no error message to send: whatever it puts on the socket goes to a
    // spoofed source address as readily as to a real one. So the test is that nothing comes back,
    // and that the server is still answering afterwards.
    let server = Running::start(60);

    assert!(server
        .ask_expecting_nothing(b"this is not a roughtime packet")
        .is_none());
    assert!(server.ask_expecting_nothing(&[]).is_none());
    assert!(server.ask_expecting_nothing(&[0u8; 1400]).is_none());

    let request = build_request(&[1u8; 32], &server.public_key);
    assert!(
        server.ask(&request).is_some(),
        "three bad packets did not stop it serving"
    );
}

#[test]
fn an_address_over_its_share_gets_silence_and_the_server_keeps_running() {
    let server = Running::start(2);
    let request = build_request(&[2u8; 32], &server.public_key);

    // The limit counts by address and not by port. `ask` binds a fresh port each time, and until
    // 2026-09-15 that was enough to be a fresh address, so a client varying its port was never
    // limited. Now three asks from one address are one address asking three times: two inside
    // the share, the third silence.
    assert!(server.ask(&request).is_some());
    assert!(server.ask(&request).is_some());
    assert!(
        server.ask_expecting_nothing(&request).is_none(),
        "the third from one address is over the share whichever port it came from"
    );

    // Another address has its own share, and the server is still answering. The second loopback
    // address is one every host this runs on has.
    let other = UdpSocket::bind("127.0.0.2:0").expect("the second loopback address");
    other
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a read timeout");
    other.send_to(&request, server.address).expect("sent");
    let mut buffer = [0u8; 1500];
    assert!(
        other.recv_from(&mut buffer).is_ok(),
        "one address being over does not close the socket to anybody else"
    );
}

#[test]
fn a_server_with_no_usable_clock_answers_nobody() {
    // The property this product would look worst getting wrong. A time server whose own clock it
    // cannot vouch for stops answering rather than answering with a radius it cannot justify.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a loopback port");
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("a read timeout");
    let address = socket.local_addr().expect("the port it got");

    let key = LongTermKey::from_bytes(&[78u8; 32]);
    let public_key = key.public();
    let mut server = Server::new(key, NOW).expect("a server");
    let mut limit = RateLimit::default();
    let stop = Arc::new(AtomicBool::new(false));
    let watching = Arc::clone(&stop);

    let dropped = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&dropped);
    let thread = std::thread::spawn(move || {
        let _ = serve(
            &socket,
            &mut server,
            &mut limit,
            // The clock says it has nothing worth stating.
            || None,
            || !watching.load(Ordering::Relaxed),
            |_, d| seen.lock().expect("the list").push(d.to_string()),
        );
    });

    let client = UdpSocket::bind("127.0.0.1:0").expect("a client port");
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("a read timeout");
    client
        .send_to(&build_request(&[3u8; 32], &public_key), address)
        .expect("sent");
    let mut buffer = [0u8; 1500];
    assert!(
        client.recv_from(&mut buffer).is_err(),
        "a server that cannot vouch for its own clock states nothing"
    );

    stop.store(true, Ordering::Relaxed);
    thread.join().expect("the thread ends");

    let reasons = dropped.lock().expect("the list");
    assert_eq!(reasons.len(), 1, "the drop was counted");
    assert!(
        reasons[0].contains("will not date a response"),
        "and it says why: {}",
        reasons[0]
    );
}
