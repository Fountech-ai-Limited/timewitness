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
//! checks against the key we published for it, and that the corridor it signed is one a server of
//! ours can justify: a radius of whole seconds and at least one, no wider than the cut to a whole
//! second midpoint makes it, and meeting the moment this machine, held to the public NTP servers,
//! says the server answered. It is not evidence of an independent operator, and it never can be:
//! the server is ours, the exchange is marked first party, and `crates/clock/tests/our_own_servers.rs`
//! is where that refusal is proved.
//!
//! **Why the radius is not held to exactly one second.** A server of ours states its midpoint in
//! whole seconds, so it cuts its own midpoint down to one and widens the radius by what it cut. When
//! its reading sits near the end of a second, a radius of one no longer reaches the late end of its
//! bound and it signs two. That is the safe direction and it is by design, and until 2026-09-25 this
//! file refused it, so the daily live check went red on about one run in four with nothing wrong.

use std::net::UdpSocket;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use timewitness_clock::Policy;
use timewitness_core::evidence::roughtime::build_request;
use timewitness_core::keylog::file::parse;
use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Nanos, SourceKind};
use timewitness_sources::ntp::{NtpClient, NtpServer};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};
use timewitness_sources::TimeSource;

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

#[test]
#[ignore = "needs a Roughtime server of ours running somewhere, named in the environment"]
fn a_client_that_walks_away_does_not_stop_a_server_of_ours() {
    // The defect of 2026-09-16, asked of a server that is actually deployed rather than of a socket
    // in this process. A client asks and closes its socket before the answer arrives, and the
    // server has to answer the next request from anybody.
    //
    // The loopback case is in `crates/roughtime-server/tests/over_a_real_socket.rs` and it is the
    // one that fails on an unfixed build. This one cannot fail that way and is not meant to: our
    // servers run on Linux, which does not hand ICMP to an unconnected UDP socket without
    // `IP_RECVERR`, so the packet that takes a Windows server off the air is harmless to these two.
    // What this proves is the deployment, not the platform: the fix is on the machine, the machine
    // is still answering, and a client walking away did not change that.
    let address = std::env::var(ADDRESS)
        .unwrap_or_else(|_| panic!("{ADDRESS} says which server to ask, as host:port"));
    let key = std::env::var(KEY)
        .unwrap_or_else(|_| panic!("{KEY} says its long-term public key, as 64 hex characters"));
    let key = from_hex(&key).expect("the key is 64 hex characters");

    {
        let walker = UdpSocket::bind("0.0.0.0:0").expect("a local port");
        walker
            .send_to(&build_request(&[0x61u8; 32], &key), &address)
            .unwrap_or_else(|e| panic!("the first request could not be sent to {address}: {e}"));
        // Closed here, before the answer can be read.
    }

    // Long enough for the answer to reach a port that has gone, and for whatever the host does
    // about that to reach the server.
    std::thread::sleep(Duration::from_secs(2));

    ask(&address, key);
}

/// One request to a server of ours, checked against the key given for it.
fn ask(address: &str, key: [u8; 32]) {
    // Declared as ours, because it is. The label is what keeps a corridor of ours out of the
    // independent operator count, and a probe that described it as anything else would be
    // measuring a configuration nobody would ever run.
    let described =
        RoughtimeServer::new("ours", address.to_string(), key).operated_by_us("timewitness.dev");
    let client = RoughtimeClient::new(described).waiting(Duration::from_secs(5));

    let error = *this_machines_error();
    let nonce = RoughtimeClient::random_nonce().expect("a nonce");
    let sent = wall_clock();
    let exchange = client
        .poll_bound(MonotonicNanos(0), &nonce, &[])
        .unwrap_or_else(|e| panic!("{address} did not answer: {e}"));
    let received = wall_clock();

    assert_eq!(exchange.kind, SourceKind::Roughtime, "{address}");
    assert!(
        exchange.operator.is_first_party(),
        "{address}: a server of ours is not an independent chance to be wrong"
    );

    let attestation = exchange.attestation.as_ref().unwrap_or_else(|| {
        panic!("{address}: a Roughtime exchange carries evidence a stranger could check")
    });
    let radius = attestation
        .radius
        .unwrap_or_else(|| panic!("{address}: a Roughtime response states a radius"));
    let corridor = Corridor {
        midpoint: attestation.at.0,
        radius,
    };
    let moment = Span {
        earliest: sent + error.earliest - SLACK,
        latest: received + error.latest + SLACK,
    };

    if let Err(why) = judge(address, corridor, moment, widest_bound_of_ours()) {
        panic!("{why}");
    }

    println!(
        "{address} answered under {}, radius {} s, so a corridor {} s wide around {} s; this \
         machine put the moment it answered {} ms to {} ms after that midpoint",
        key[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        radius / NANOS_PER_SEC,
        (radius * 2) / NANOS_PER_SEC,
        corridor.midpoint / NANOS_PER_SEC,
        (moment.earliest - corridor.midpoint) / NANOS_PER_MILLI,
        (moment.latest - corridor.midpoint) / NANOS_PER_MILLI,
    );
}

/// What a server signed: a midpoint in nanoseconds since 1970, and a radius in nanoseconds.
#[derive(Clone, Copy, Debug)]
struct Corridor {
    midpoint: Nanos,
    radius: Nanos,
}

/// An interval, in nanoseconds: of instants since 1970, or of how far one clock is from another.
#[derive(Clone, Copy, Debug)]
struct Span {
    earliest: Nanos,
    latest: Nanos,
}

/// Room for this machine's clock to move between being held to NTP and asking our server.
///
/// The two happen within seconds of each other, and a clock running five hundred parts per million
/// off, ten times what a consumer crystal is specified to, moves five milliseconds in ten seconds.
const SLACK: Nanos = 5 * NANOS_PER_MILLI;

/// The widest bound a server of ours will answer from.
///
/// The server asks its model for a reading per request, and the model refuses a bound wider than
/// the policy ceiling, so a server whose bound is wider than this sends nothing at all. The
/// deployment passes no `--max-width`, so the ceiling is the default one.
fn widest_bound_of_ours() -> Nanos {
    Policy::default().max_bound_width
}

/// Whether a corridor is one a server of ours could honestly have signed at that moment.
///
/// `moment` is where this machine puts the instant the server read its clock: its own clock, held
/// to the public NTP servers, across the time the request was out. `widest` is the widest bound the
/// server will answer from. Every refusal names the server, what it signed and what that broke.
///
/// Four things are held, and the last is the one the old exact one second check stood in for.
///
/// 1. The radius is whole seconds and at least one. Nothing narrower can go on the wire, so a
///    server stating less is claiming what nobody can.
/// 2. The corridor meets the moment. It is not held to contain all of it, because this machine's
///    interval is wider than the server's own bound by the round trip, so an honest corridor can end
///    inside it. A corridor that misses it entirely says the true time was somewhere else.
/// 3. The midpoint is less than a second from where the server's bound could have been centred.
///    The cut to a whole second moves a midpoint by less than one, and the server's bound holds the
///    true instant, so its centre is within half the widest bound of the moment.
/// 4. A radius one second narrower would not already have held every bound the server could have
///    had. The cut widens a radius by less than a second, so where a narrower corridor would have
///    held all of them, nothing the server did can have called for the extra second.
fn judge(address: &str, corridor: Corridor, moment: Span, widest: Nanos) -> Result<(), String> {
    let Corridor { midpoint, radius } = corridor;
    let said = format!(
        "{address} signed a midpoint of {midpoint} ns and a radius of {radius} ns, and this machine \
         put the moment it answered at {} to {} ns",
        moment.earliest, moment.latest
    );

    if radius < NANOS_PER_SEC || radius % NANOS_PER_SEC != 0 {
        return Err(format!(
            "{said}. A radius is whole seconds and at least one, so this is a width the format \
             cannot carry"
        ));
    }

    if midpoint + radius < moment.earliest || midpoint - radius > moment.latest {
        return Err(format!(
            "{said}. The corridor misses that moment entirely, so the server's clock or its model \
             is wrong"
        ));
    }

    let half = (widest + 1) / 2;
    if midpoint <= moment.earliest - half - NANOS_PER_SEC
        || midpoint >= moment.latest + half + NANOS_PER_SEC
    {
        return Err(format!(
            "{said}. That midpoint is a second or more from anywhere its bound could have been \
             centred, and the cut to a whole second moves it by less"
        ));
    }

    let narrower = radius - NANOS_PER_SEC;
    if narrower > 0
        && midpoint - narrower <= moment.earliest - widest
        && midpoint + narrower >= moment.latest + widest
    {
        return Err(format!(
            "{said}. A radius of {} s would already have held any bound of {widest} ns or less \
             around that moment, so the cut to a whole second cannot justify {} s",
            narrower / NANOS_PER_SEC,
            radius / NANOS_PER_SEC
        ));
    }

    Ok(())
}

/// How far UTC is from this machine's clock, as an interval, held to the public NTP servers.
///
/// Asked once per run and kept, so every server of ours is judged against the same measurement. The
/// servers that answer are intersected rather than averaged.
fn this_machines_error() -> &'static Span {
    static ERROR: OnceLock<Span> = OnceLock::new();
    ERROR.get_or_init(|| {
        let mut held: Option<Span> = None;
        let mut heard = Vec::new();
        for server in NtpServer::published() {
            let name = server.name.clone();
            let mut client = NtpClient::new(server).waiting(Duration::from_secs(5));
            let nonce = RoughtimeClient::random_nonce().expect("a nonce");
            let sent = wall_clock();
            let Ok(exchange) = client.poll(MonotonicNanos(0), &nonce) else {
                continue;
            };
            let received = wall_clock();

            // The server read its clock at some instant between the send and the receive here, so
            // UTC less this clock lies between what it said less the receive time and what it said
            // less the send time, widened by what the server says about its own error.
            let stated = exchange.stated_uncertainty();
            let this = Span {
                earliest: exchange.t3.0 - received - stated,
                latest: exchange.t2.0 - sent + stated,
            };
            heard.push(format!("{name} {} to {} ns", this.earliest, this.latest));
            held = Some(match held {
                None => this,
                Some(so_far) => Span {
                    earliest: so_far.earliest.max(this.earliest),
                    latest: so_far.latest.min(this.latest),
                },
            });
        }
        let held = held.unwrap_or_else(|| {
            panic!(
                "none of the public NTP servers answered, so this machine has no bound of its own \
                 to hold our servers to, and nothing about them was learnt"
            )
        });
        assert!(
            held.earliest <= held.latest,
            "the public NTP servers disagree about this machine's clock ({}), so there is no \
             bound to hold our servers to",
            heard.join(", ")
        );
        held
    })
}

/// This machine's clock, in nanoseconds since 1970.
fn wall_clock() -> Nanos {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970");
    Nanos::try_from(since.as_nanos()).expect("a clock that fits in the arithmetic")
}

// What follows needs no network. It holds the judge to the corridors a server of ours is built to
// sign, and to the ones it must refuse, so a check loose enough to pass a lying server fails here
// in the ordinary build rather than never failing at all.

/// A whole second in 2026, to put corridors around.
const SECOND: Nanos = 1_790_000_000 * NANOS_PER_SEC;

const SERVER: &str = "a-server-of-ours.example:2002";

/// The corridor our server signs for a bound, by the rule it runs: the midpoint cut down to a whole
/// second, and the radius widened by what was cut and rounded up to whole seconds, one at least.
fn signed_for(earliest: Nanos, latest: Nanos) -> Corridor {
    let middle = earliest + (latest - earliest) / 2;
    let half = latest - middle;
    let cut = middle.rem_euclid(NANOS_PER_SEC);
    let radius = (half + cut + NANOS_PER_SEC - 1) / NANOS_PER_SEC;
    Corridor {
        midpoint: middle - cut,
        radius: radius.max(1) * NANOS_PER_SEC,
    }
}

/// This machine's interval around a true instant, as a run from a runner puts it.
fn seen(instant: Nanos) -> Span {
    Span {
        earliest: instant - 40 * NANOS_PER_MILLI,
        latest: instant + 90 * NANOS_PER_MILLI,
    }
}

#[test]
fn every_corridor_our_server_is_built_to_sign_is_accepted() {
    let widest = widest_bound_of_ours();
    let mut twos = 0;
    for width in [
        2 * NANOS_PER_MILLI,
        20 * NANOS_PER_MILLI,
        150 * NANOS_PER_MILLI,
        widest,
    ] {
        for step in 0..1_000 {
            let earliest = SECOND + step * NANOS_PER_MILLI;
            let latest = earliest + width;
            let corridor = signed_for(earliest, latest);
            if corridor.radius == 2 * NANOS_PER_SEC {
                twos += 1;
            }
            // The true instant at either end of the server's bound, which is where it is hardest
            // for the check to see the reason for the second.
            for instant in [earliest, latest] {
                judge(SERVER, corridor, seen(instant), widest)
                    .unwrap_or_else(|why| panic!("an honest corridor was refused: {why}"));
            }
        }
    }
    assert!(twos > 0, "no bound here made the server sign two seconds");
}

#[test]
fn a_radius_under_a_second_is_refused_and_names_the_server() {
    let instant = SECOND + 200 * NANOS_PER_MILLI;
    for radius in [0, 999 * NANOS_PER_MILLI] {
        let why = judge(
            SERVER,
            Corridor {
                midpoint: SECOND,
                radius,
            },
            seen(instant),
            widest_bound_of_ours(),
        )
        .expect_err("a radius under a second passed");
        assert!(why.contains(SERVER), "{why}");
        assert!(why.contains("whole seconds and at least one"), "{why}");
    }
}

#[test]
fn a_radius_of_part_seconds_is_refused() {
    let why = judge(
        SERVER,
        Corridor {
            midpoint: SECOND,
            radius: 1_500 * NANOS_PER_MILLI,
        },
        seen(SECOND + 200 * NANOS_PER_MILLI),
        widest_bound_of_ours(),
    )
    .expect_err("a radius of a second and a half passed");
    assert!(why.contains("whole seconds"), "{why}");
}

#[test]
fn a_wide_radius_with_no_cut_to_justify_it_is_refused() {
    // Early in the second, where the cut is a fifth of a second and one second holds everything.
    let instant = SECOND + 200 * NANOS_PER_MILLI;
    for seconds in [2, 5] {
        let why = judge(
            SERVER,
            Corridor {
                midpoint: SECOND,
                radius: seconds * NANOS_PER_SEC,
            },
            seen(instant),
            widest_bound_of_ours(),
        )
        .expect_err("a radius the cut cannot justify passed");
        assert!(why.contains(SERVER), "{why}");
        assert!(why.contains("cannot justify"), "{why}");
    }
}

#[test]
fn a_wide_radius_whose_midpoint_was_moved_to_suit_it_is_refused() {
    // Five seconds around a midpoint four seconds early would pass the width check on its own,
    // because the true instant really is near its far end. The midpoint is what gives it away.
    let why = judge(
        SERVER,
        Corridor {
            midpoint: SECOND - 4 * NANOS_PER_SEC,
            radius: 5 * NANOS_PER_SEC,
        },
        seen(SECOND + 200 * NANOS_PER_MILLI),
        widest_bound_of_ours(),
    )
    .expect_err("a midpoint four seconds out passed");
    assert!(why.contains("a second or more"), "{why}");
}

#[test]
fn a_corridor_that_misses_the_moment_is_refused() {
    let why = judge(
        SERVER,
        Corridor {
            midpoint: SECOND + 3 * NANOS_PER_SEC,
            radius: NANOS_PER_SEC,
        },
        seen(SECOND + 200 * NANOS_PER_MILLI),
        widest_bound_of_ours(),
    )
    .expect_err("a corridor three seconds late passed");
    assert!(why.contains(SERVER), "{why}");
    assert!(why.contains("misses that moment"), "{why}");
}

#[test]
fn a_server_that_rounds_its_midpoint_rather_than_cutting_it_is_accepted_too() {
    // So the check does not have to change if the server is ever made to round to the nearest
    // second, which states one second more often.
    let widest = widest_bound_of_ours();
    for step in 0..1_000 {
        let earliest = SECOND + step * NANOS_PER_MILLI;
        let latest = earliest + widest;
        let middle = earliest + (latest - earliest) / 2;
        let nearest = (middle + NANOS_PER_SEC / 2).div_euclid(NANOS_PER_SEC) * NANOS_PER_SEC;
        let reach = (latest - nearest).max(nearest - earliest);
        let radius = ((reach + NANOS_PER_SEC - 1) / NANOS_PER_SEC).max(1) * NANOS_PER_SEC;
        let corridor = Corridor {
            midpoint: nearest,
            radius,
        };
        for instant in [earliest, latest] {
            judge(SERVER, corridor, seen(instant), widest)
                .unwrap_or_else(|why| panic!("an honest rounded corridor was refused: {why}"));
        }
    }
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
