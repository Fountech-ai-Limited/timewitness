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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use timewitness_core::evidence::roughtime::{build_request, check, pack_blob};
use timewitness_roughtime_server::{serve, Dropped, LongTermKey, RateLimit, Reading, Server};

const NOW: u64 = 1_800_000_000;

/// A server running in a thread, and everything needed to talk to it and stop it.
struct Running {
    address: SocketAddr,
    public_key: [u8; 32],
    stop: Arc<AtomicBool>,
    /// Set when `serve` came back before anybody asked it to stop, which is the one way the loop
    /// can fail a test in this file without a single assertion about a packet noticing.
    returned_early: Arc<AtomicBool>,
    /// How many datagrams the platform threw away as too big for the buffer. Only Windows
    /// reports one of those as an error; everywhere else the datagram is cut down and handed over.
    oversize: Arc<AtomicU64>,
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
        let returned_early = Arc::new(AtomicBool::new(false));
        let oversize = Arc::new(AtomicU64::new(0));
        let watching = Arc::clone(&stop);
        let early = Arc::clone(&returned_early);
        let counting = Arc::clone(&oversize);
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
                |_, dropped| {
                    if matches!(dropped, Dropped::Oversize(_)) {
                        counting.fetch_add(1, Ordering::Relaxed);
                    }
                },
            );
            if !watching.load(Ordering::Relaxed) {
                early.store(true, Ordering::Relaxed);
            }
        });

        Self {
            address,
            public_key,
            stop,
            returned_early,
            oversize,
            thread: Some(thread),
        }
    }

    fn returned_early(&self) -> bool {
        self.returned_early.load(Ordering::Relaxed)
    }

    fn oversize_seen(&self) -> u64 {
        self.oversize.load(Ordering::Relaxed)
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

#[test]
fn a_flood_of_oversize_datagrams_for_a_minute_does_not_stop_the_server() {
    // The second fault of 2026-09-16, found the evening the first was fixed, and the packet the
    // first fix's own argument missed.
    //
    // `serve` gives up when the socket hands back nothing but faults for over twenty seconds, and
    // the argument that kept that ceiling out of a client's reach was that every fault a client can
    // cause needs a packet, and a packet is a datagram on the next receive, which puts the run back
    // to nought. On Windows a datagram larger than the receive buffer is thrown away by the
    // platform and `recv_from` returns os error 10040 in its place. The packet arrived and the loop
    // never saw a datagram, so each one was a fault and nothing between them reset the run. About
    // a thousand of them, at the loop's own pace of fifty a second, and the real
    // `timewitness roughtime-serve` exited 1 after 20.8 s on this desktop with nothing else sent.
    //
    // Linux cuts an oversize datagram down to the buffer and hands it over, so there it arrives as
    // an ordinary bad packet and this test never reaches the path. It still runs everywhere, and
    // the count at the end says which of the two happened.
    //
    // A minute rather than the twenty-one seconds the ceiling takes, because the property is that
    // no length of this flood reaches it, and a test that stops at the ceiling is testing the
    // ceiling's arithmetic rather than the loop.
    //
    // **The limit is out of the flood's reach, and until 2026-09-19 it was not.** This ran at the
    // shipped sixty an address a minute, and on a platform that hands an oversize datagram to the
    // loop rather than throwing it away, every one of the hundred thousand this flood sends is
    // counted against `127.0.0.1`. The honest client below binds `127.0.0.1` too, so whether it was
    // answered came down to where in the window the flood happened to stop. That is a coin toss,
    // and it lost twice on 2026-09-19, at 08:59:34Z and 10:12:25Z, blocking every merge for the
    // afternoon on commits neither of which touched this code, both green on a re-run with nothing
    // changed. What the test has stopped measuring is that a flooding address is rate limited,
    // which was never this test's subject and which
    // `a_flood_from_one_address_spends_the_limit_for_every_port_on_it` measures on its own in no
    // time at all. What it still measures is the only thing it was written for: a minute of
    // oversize datagrams does not make the receive loop give up, and the server is still answering
    // afterwards.
    let server = Running::start(u32::MAX);
    let address = server.address;

    let flood = std::thread::spawn(move || {
        let sender = UdpSocket::bind("127.0.0.1:0").expect("a client port");
        let big = [0u8; 4000];
        let started = Instant::now();
        let mut sent: u64 = 0;
        while started.elapsed() < Duration::from_secs(60) {
            for _ in 0..200 {
                if sender.send_to(&big, address).is_ok() {
                    sent += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        sent
    });
    let sent = flood.join().expect("the flood ran its minute");
    assert!(sent > 100_000, "the flood barely sent anything: {sent}");

    assert!(
        !server.returned_early(),
        "a minute of oversize datagrams and nothing else made serve give up on its socket"
    );

    let request = build_request(&[0x46; 32], &server.public_key);
    assert!(
        server.ask(&request).is_some(),
        "an honest client is answered after the flood"
    );

    if cfg!(windows) {
        assert!(
            server.oversize_seen() > 1_000,
            "on Windows every one of those datagrams is reported as too big and thrown away, so \
             more than a thousand of them were counted: {}",
            server.oversize_seen()
        );
    } else {
        assert_eq!(
            server.oversize_seen(),
            0,
            "this platform cuts an oversize datagram down and hands it over, so none is counted as \
             thrown away"
        );
    }
}

/// The rate limit counts an address and not a port, so one flooder spends it for every client on
/// that address.
///
/// This is here rather than beside the limiter because it is what the flood test above was
/// accidentally asserting against. Everything in that test binds `127.0.0.1`, the flooder and the
/// honest client alike, and the limiter's key is `SocketAddr::ip`. So on a platform that hands an
/// oversize datagram to the loop rather than throwing it away, every one of the hundred thousand
/// the flood sends is counted against `127.0.0.1`, and the honest client that asks afterwards is
/// refused until the window rolls.
///
/// That is the design working. A flood is a flood whichever port it comes from, and a limit keyed
/// on the port would be no limit at all, because a port is free. What it means for a test is that
/// an honest answer after a flood from the same address is a question about where in the window the
/// flood happened to stop, which is the coin toss that failed the required check twice on
/// 2026-09-19 at 08:59:34Z and 10:12:25Z, on commits neither of which touched this code, both green
/// on a re-run with nothing changed.
///
/// No socket, no thread and no waiting: it is the arithmetic on its own.
#[test]
fn a_flood_from_one_address_spends_the_limit_for_every_port_on_it() {
    let mut limit = RateLimit::new(60, Duration::from_secs(60));
    let now = Instant::now();

    let flooder: SocketAddr = "127.0.0.1:40000".parse().expect("an address");
    for _ in 0..1_000 {
        limit.allows(flooder, now);
    }

    let honest: SocketAddr = "127.0.0.1:40001".parse().expect("an address");
    assert!(
        !limit.allows(honest, now),
        "a different port on the same address is the same address to a limit keyed on the address"
    );
    assert_eq!(limit.addresses(), 1, "both of them are one address");

    // And it is the window that lets the honest client back in, not anything about the client.
    assert!(
        limit.allows(honest, now + Duration::from_secs(61)),
        "once the window rolls the count is cleared and the address may send again"
    );
}
