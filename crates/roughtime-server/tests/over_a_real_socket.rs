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

    /// Send a packet, and send it again rather than waiting once. `None` means no answer came at
    /// all inside `tries` sends of `patience` each.
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
    ///
    /// **And asking once is not how anything asks over UDP, which is why this file stayed
    /// intermittent after the wait was lengthened.** Under forty-eight processes burning a core
    /// each, this binary failed 59 of 100 runs on 2026-09-16, every failure a test that expected an
    /// answer and got none inside its wait. A counting transport put under `serve` in the same
    /// conditions settled what was happening: the server received every datagram that reached it
    /// and answered every one, never returned, and never dropped anything but the packet the rate
    /// limit refused. What stretched was delivery. A request or a reply on the loopback took
    /// seconds to arrive on a saturated machine, and a test that sends one datagram and calls a
    /// late reply a failure is testing the machine's scheduler.
    ///
    /// So a test expecting an answer sends again inside its budget. `tries` is not free everywhere:
    /// a resend is another packet against that address's share of the socket, so the caller sets it
    /// to what the limit in force allows rather than to whatever feels safe.
    fn ask_waiting(&self, packet: &[u8], patience: Duration, tries: u32) -> Option<Vec<u8>> {
        self.ask_from("127.0.0.1:0", packet, patience, tries)
    }

    /// The same, from an address the caller names, so a test can ask as somebody else.
    fn ask_from(
        &self,
        bind: &str,
        packet: &[u8],
        patience: Duration,
        tries: u32,
    ) -> Option<Vec<u8>> {
        let client = UdpSocket::bind(bind).expect("a client port");
        client
            .set_read_timeout(Some(patience))
            .expect("a read timeout");

        let mut buffer = [0u8; 1500];
        for _ in 0..tries {
            client.send_to(packet, self.address).expect("sent");
            if let Ok((len, _)) = client.recv_from(&mut buffer) {
                return Some(buffer[..len].to_vec());
            }
        }
        None
    }

    /// Ask, expecting an answer. Six sends of five seconds, so half a minute in all.
    ///
    /// Generous because it is free. A server that answers spends microseconds here and never sees
    /// the second send; the budget is only ever spent by a machine that has stopped scheduling
    /// this process, and on one of those no fixed budget is enough anyway.
    fn ask(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.ask_waiting(packet, Duration::from_secs(5), 6)
    }

    /// Ask once, expecting an answer, where sending again would spend a share the test is about.
    fn ask_once(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.ask_waiting(packet, Duration::from_secs(10), 1)
    }

    /// Ask, expecting silence.
    fn ask_expecting_nothing(&self, packet: &[u8]) -> Option<Vec<u8>> {
        self.ask_waiting(packet, Duration::from_millis(300), 1)
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
    //
    // These two ask once each and that is the point of them: the share is two, so a resend would
    // spend the share this test is measuring and the third ask would be silent for the wrong
    // reason. Asking once is safe here, because the measurement of 2026-09-16 found the delay on
    // the second loopback address rather than on this one.
    assert!(server.ask_once(&request).is_some());
    assert!(server.ask_once(&request).is_some());
    assert!(
        server.ask_expecting_nothing(&request).is_none(),
        "the third from one address is over the share whichever port it came from"
    );
}

#[test]
fn one_address_being_over_its_share_does_not_close_the_socket_to_anybody_else() {
    // Split out of the test above on 2026-09-16, and the share is eight rather than two on purpose.
    //
    // The second loopback address is where delivery stretches on a busy Windows machine: measured
    // that day, a reply to `127.0.0.2` arrived two to four seconds late in four runs out of six
    // while `127.0.0.1` was answered in microseconds in every one. So this half needs room to ask
    // again, and a share of two is two sends. A share of eight is eight, which is forty seconds of
    // budget, and the property being tested is unchanged: one address over its share, another
    // still answered.
    let share = 8;
    let server = Running::start(share);
    let request = build_request(&[4u8; 32], &server.public_key);

    // Put `127.0.0.1` well over its share. Three times the share rather than one more than it, so
    // a datagram going astray on a busy machine cannot leave this address inside its share and the
    // next assertion answered. The replies are read and thrown away as they come.
    let flooder = UdpSocket::bind("127.0.0.1:0").expect("a client port");
    flooder
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("a read timeout");
    let mut buffer = [0u8; 1500];
    for _ in 0..(share * 3) {
        flooder.send_to(&request, server.address).expect("sent");
        let _ = flooder.recv_from(&mut buffer);
    }
    assert!(
        server.ask_expecting_nothing(&request).is_none(),
        "this address is well over its share whichever port it sends from"
    );

    // The second loopback address is one every host this runs on has, and it has its own share.
    assert!(
        server
            .ask_from("127.0.0.2:0", &request, Duration::from_secs(5), share)
            .is_some(),
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

#[test]
fn a_client_that_asks_and_walks_away_does_not_stop_the_server() {
    // The fault of 2026-09-16, and it is the reason this file was being read as a flake.
    //
    // A client asks and closes its socket before the answer arrives. The answer then reaches a port
    // nobody is listening on. Windows has the host answer that with ICMP port-unreachable, and the
    // server's next `recv_from` on its own unconnected socket returns `ConnectionReset`, os error
    // 10054. Until this was fixed, `serve` tolerated two error kinds and returned on every other,
    // so that one packet and a close took the server off the air for everybody while the process
    // stayed up. One packet, no authentication, and nothing in the logs but a line about a socket.
    //
    // Linux does not surface ICMP on an unconnected UDP socket unless `IP_RECVERR` is set, so there
    // the sequence is simply harmless and this test passes without ever exercising the path. That
    // is also why CI never saw it and why only a desktop run went red, once in three.
    let server = Running::start(60);

    {
        let walker = UdpSocket::bind("127.0.0.1:0").expect("a client port");
        walker
            .send_to(
                &build_request(&[0x44; 32], &server.public_key),
                server.address,
            )
            .expect("sent");
        // Closed here, before the answer can be read.
    }

    // Long enough for the server to answer the closed port, for the host to answer that with ICMP,
    // and for the loop to come round to a receive and be told about it.
    std::thread::sleep(Duration::from_millis(300));

    let request = build_request(&[0x45; 32], &server.public_key);
    assert!(
        server.ask(&request).is_some(),
        "one client closing its socket does not stop the server answering anybody else"
    );
}
