//! `timewitness roughtime-serve`, a Roughtime server of ours run off this product's own clock model.
//!
//! ## The one thing it does not buy, said first because the whole feature invites the other reading
//!
//! Running our own Roughtime servers does not narrow anybody's bound and cannot. A Roughtime radius
//! is a `u32` of whole seconds with zero forbidden, so one second is the narrowest any server can
//! state, ours included, and a corridor is two seconds wide at its best whoever runs it. What our
//! own servers buy is a signed corridor that is there when three volunteers' servers are not, and a
//! key we publish and can be held to. Nothing here made a number smaller.
//!
//! ## Why it holds a clock model rather than reading the machine's clock
//!
//! [`timewitness_roughtime_server::Server`] refuses to invent a reading: a caller hands it a moment
//! and a radius, and a caller with no usable bound gets silence for its request. That refusal is the
//! whole reason this subcommand exists in this crate rather than as a few lines of `main` in the
//! server crate. The honest source of that pair is the thing this product is: a
//! [`Resident`] disciplined against independent sources on a schedule, exactly as
//! `timewitness agent` disciplines one. A server of ours whose radius came from its own unmeasured
//! system clock would be the fault this product sells the fix for, shipped under our own name.
//!
//! So the process is two loops sharing one model. One polls the sources and runs the selection
//! rounds, which is [`timewitness_agent::serve::poll_forever`] and is the agent's own loop rather
//! than a second copy of it. The other reads the socket and answers, and asks the model for a
//! reading per request rather than caching one.
//!
//! ## What it does not do
//!
//! It does not put itself in anybody's source list. `RoughtimeServer::published()` is what a
//! stranger installing the Action polls, and pointing that at us is a decision about what the
//! shipped agent does rather than a consequence of running a server. It is unchanged.
//!
//! It installs nothing, and there is no service, unit or scheduler entry. It runs in the foreground
//! until it is stopped, the same as the agent.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use timewitness_agent::resident::{Resident, SystemSurroundings};
use timewitness_agent::serve::{poll_forever, Cadence, Reporter};
use timewitness_clock::monotonic::SystemMonotonic;
use timewitness_clock::Policy;
use timewitness_core::bound::Bound;
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::UnixNanos;
use timewitness_roughtime_server::{
    Dropped, LongTermKey, RateLimit, Reading, Server, DEFAULT_DELEGATION_SECONDS,
};
use timewitness_sources::ntp::{NtpClient, NtpServer};
use timewitness_sources::nts::{NtsClient, NtsServer};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};
use timewitness_sources::TimeSource;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// How many reads to take when measuring the counter's own granularity.
///
/// The same two thousand the agent takes, and for the same reason: a process that will run for days
/// can afford to measure the counter it reads all day rather than falling back to the policy floor.
const GRANULARITY_READS: usize = 2_000;

/// The environment variable a long-term key may arrive in, as sixty-four hex characters.
///
/// A file is the better home for a key and `--key` is the ordinary way in. This exists because the
/// hosts these servers run on have no persistent disk: a deployment there keeps the key in the
/// platform's own secret store and hands it to the process, and without this the alternative is a
/// server that generates a fresh identity on every deploy, which is an identity nobody published
/// and no key log names.
const KEY_IN_ENVIRONMENT: &str = "TIMEWITNESS_ROUGHTIME_KEY";

/// How long to wait on the socket before looking at whether to carry on.
///
/// The loop in the server crate checks its `keep_going` between packets, so a socket with no
/// timeout on it would sit in `recv_from` forever on a quiet server and never look. Nothing here
/// stops of its own accord today, and the timeout is what keeps that a property of this file rather
/// than of the operating system.
const SOCKET_PATIENCE: Duration = Duration::from_secs(1);

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let bind = args.value("--bind").unwrap_or("0.0.0.0:2002").to_string();

    let long_term = match read_key(args) {
        Ok(key) => key,
        Err(e) => return fail(&e),
    };
    let public = long_term.public();

    let interval = match args.number("--interval") {
        Ok(Some(n)) if n >= 1 => Duration::from_secs(u64::try_from(n).unwrap_or(32)),
        Ok(Some(_)) => return fail("--interval is a whole number of seconds, at least one"),
        Ok(None) => Cadence::default().interval,
        Err(e) => return fail(&e.0),
    };
    let max_bound_width = match args.number("--max-width") {
        Ok(Some(width)) if width > 0 => width,
        Ok(Some(_)) => return fail("--max-width is a positive number of nanoseconds"),
        Ok(None) => Policy::default().max_bound_width,
        Err(e) => return fail(&e.0),
    };
    let policy = Policy {
        max_bound_width,
        ..Policy::default()
    };

    let socket = match UdpSocket::bind(&bind) {
        Ok(socket) => socket,
        Err(e) => {
            return fail(&format!(
                "nothing on this machine would give us {bind}: {e}"
            ))
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(SOCKET_PATIENCE)) {
        return fail(&format!("the socket would take no read timeout: {e}"));
    }

    // The system clock, read once, only to anchor the model. Everything after this is the monotonic
    // counter, the same as the agent does it.
    let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return fail("this machine's clock is before 1970, which is not something to build on");
    };
    let Ok(nanos) = i128::try_from(wall.as_nanos()) else {
        return fail("this machine's clock is further from 1970 than the arithmetic here reaches");
    };
    let seconds = match u64::try_from(nanos.div_euclid(NANOS_PER_SEC)) {
        Ok(seconds) => seconds,
        Err(_) => return fail("this machine's clock is before 1970 in seconds as well"),
    };

    let mut server = match Server::new(long_term, seconds) {
        Ok(server) => server,
        Err(e) => {
            return fail(&format!(
                "this server could not make its first delegation: {e}"
            ))
        }
    };

    let clock = Arc::new(SystemMonotonic::new());
    let granularity = clock.measure_granularity(GRANULARITY_READS);
    let resident = Resident::new(
        policy,
        clock.clone(),
        UnixNanos(nanos),
        granularity,
        Box::new(SystemSurroundings),
    );

    // The same three kinds the agent polls, and for the same reasons. A server of ours disciplined
    // against a single kind would be a server whose corridor rests on whatever that kind's operator
    // says, which is the thing the independence rule exists to stop.
    let mut sources: Vec<Box<dyn TimeSource + Send>> = Vec::new();
    for published in RoughtimeServer::published() {
        sources.push(Box::new(RoughtimeClient::new(published)));
    }
    for published in NtpServer::published() {
        sources.push(Box::new(NtpClient::new(published)));
    }
    for published in NtsServer::published() {
        sources.push(Box::new(NtsClient::new(published)));
    }
    let source_count = sources.len();

    let shared = Arc::new(Mutex::new(resident));
    let report: Reporter = Arc::new(|line: String| println!("  {line}"));
    let cadence = Cadence {
        interval,
        ..Cadence::default()
    };

    let polling = shared.clone();
    let polling_report = report.clone();
    let polling_clock = clock.clone();
    std::thread::spawn(move || {
        poll_forever(&polling, sources, &*polling_clock, cadence, &polling_report);
    });

    let (delegation_from, delegation_to) = server.delegation_window();
    println!(
        "{}",
        render::roughtime_serving(render::RoughtimeStart {
            bind: &bind,
            public_key: &public,
            sources: source_count,
            interval_seconds: cadence.interval.as_secs(),
            max_bound_width,
            delegation_seconds: DEFAULT_DELEGATION_SECONDS,
            delegation_from,
            delegation_to,
        })
    );

    let reading_from = shared.clone();
    let drops = report.clone();
    let mut said = Vec::new();
    let outcome = timewitness_roughtime_server::serve(
        &socket,
        &mut server,
        &mut RateLimit::default(),
        || {
            let mut resident = reading_from.lock().ok()?;
            let stamp = resident.read().ok()?;
            reading_for(&stamp.bound)
        },
        || true,
        |from, dropped| {
            // The first of each kind and nothing after it. A Roughtime server on a public address
            // is sent rubbish continuously, and a line per bad packet is a log nobody reads that
            // buries the two lines worth reading: the first time this server had no usable bound,
            // and the first time it could not build a response it had decided to send.
            let kind = kind_of(dropped);
            if !said.contains(&kind) {
                said.push(kind);
                // A receive that failed brought no address with it, which is why the address is
                // optional rather than a zero somebody would later read as a real one.
                match from {
                    Some(address) => drops(format!("{address} got nothing: {dropped}")),
                    None => drops(format!("{dropped}")),
                }
            }
        },
    );

    match outcome {
        // Unreachable while `keep_going` is always true, which it is: the loop only leaves on a
        // socket that gave back nothing but faults for over twenty seconds, and a server that has
        // lost its socket is not one that should look like it stopped tidily.
        Ok(()) => fail("this server stopped reading its own socket"),
        Err(e) => fail(&format!(
            "the socket this server reads gave back nothing but faults, so it is the socket rather than the datagrams: {e}"
        )),
    }
}

/// Which of the seven refusals this is, for counting rather than for reading.
fn kind_of(dropped: &Dropped) -> u8 {
    match dropped {
        Dropped::NotOurs(_) => 0,
        Dropped::RateLimited => 1,
        Dropped::NoReading(_) => 2,
        Dropped::CouldNotAnswer(_) => 3,
        Dropped::CouldNotSend(_) => 4,
        Dropped::CouldNotReceive(_) => 5,
        Dropped::Oversize(_) => 6,
    }
}

/// The Roughtime corridor that covers this bound, or nothing where it cannot be stated.
///
/// # The corridor covers the bound, and the rounding is the whole of the difficulty
///
/// A bound is an interval in nanoseconds and a Roughtime corridor is a midpoint and a radius in
/// whole seconds. Two roundings sit between them and both have a safe direction, which is outwards:
/// a corridor narrower than the bound it came from is this server claiming something the model
/// never said.
///
/// The radius rounds up, which [`Reading::from_nanos`] already does. The midpoint is the one that
/// bites: taking the whole seconds of the midpoint moves it **earlier** by up to a second, and a
/// radius computed before that move no longer reaches the late end of the bound. So the part that
/// is lost to the truncation is added to the half width before it is rounded, and the corridor then
/// contains the bound on both sides for every midpoint, rather than for the ones that happen to
/// land on a second.
///
/// The half width is taken as `latest - midpoint` rather than `width / 2` for the same reason. An
/// odd width halves to something short on one side, and short is the direction that must not
/// happen.
fn reading_for(bound: &Bound) -> Option<Reading> {
    let earliest = bound.earliest.0;
    let latest = bound.latest.0;
    let midpoint = earliest + (latest - earliest) / 2;
    let half_width = latest - midpoint;

    let seconds = u64::try_from(midpoint.div_euclid(NANOS_PER_SEC)).ok()?;
    let lost_to_the_truncation = midpoint.rem_euclid(NANOS_PER_SEC);

    Some(Reading::from_nanos(
        seconds,
        half_width + lost_to_the_truncation,
    ))
}

/// The long-term key, from a file or from the environment.
fn read_key(args: &Args) -> Result<LongTermKey, String> {
    if let Some(path) = args.value("--key") {
        return LongTermKey::read(std::path::Path::new(path))
            .map_err(|e| format!("the long-term key at {path} could not be read: {e}"));
    }

    let Ok(hex) = std::env::var(KEY_IN_ENVIRONMENT) else {
        return Err(format!(
            "this server needs its long-term key, either as --key <file> or as {KEY_IN_ENVIRONMENT} \
             holding 64 hex characters. It will not generate one: a key made at startup is an \
             identity nobody published and no key log names"
        ));
    };
    let secret = from_hex(hex.trim()).ok_or_else(|| {
        format!("{KEY_IN_ENVIRONMENT} is not 64 hex characters, so it is not a key")
    })?;
    Ok(LongTermKey::from_bytes(&secret))
}

/// Thirty-two bytes from sixty-four hex characters, or nothing.
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

fn fail(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use timewitness_core::bound::{BoundBreakdown, EpsilonBasis, FusionRule};

    fn bound(earliest: i128, latest: i128) -> Bound {
        Bound {
            earliest: UnixNanos(earliest),
            latest: UnixNanos(latest),
            basis: EpsilonBasis::LocalModelOnly,
            breakdown: BoundBreakdown {
                fusion: FusionRule::MarzulloThenInverseSquare {
                    offered: 9,
                    kept: 9,
                },
                intersection_half: 0,
                widest_source_network_half: 0,
                scheduling: 0,
                oscillator_holdover: 0,
                model_residual: 0,
                safety_margin: 0,
            },
        }
    }

    /// What the corridor a reading states actually covers, in nanoseconds.
    fn corridor(reading: Reading) -> (i128, i128) {
        let centre = i128::from(reading.seconds) * NANOS_PER_SEC;
        let radius = i128::from(reading.radius_seconds) * NANOS_PER_SEC;
        (centre - radius, centre + radius)
    }

    /// Where a bound starts, and how wide it is, for the walk below.
    ///
    /// **The widths are stated as whole intervals rather than as half widths, and that is the whole
    /// use of this test.** A bound built as a midpoint plus and minus a half width is symmetric by
    /// construction, so it halves back exactly and cannot tell a half width taken to the late end
    /// of the interval from one taken as half the width. Written that way the first draft of this
    /// test passed under a mutation that made the corridor a second short, which is the fault it
    /// exists for. An odd width crossing a second boundary is what separates them.
    const OFFSETS: [i128; 7] = [
        0,
        1,
        NANOS_PER_SEC / 4,
        NANOS_PER_SEC / 2,
        NANOS_PER_SEC - 1,
        123_456_789,
        999_999_999,
    ];
    const WIDTHS: [i128; 10] = [
        1,
        3,
        153_875_000,
        NANOS_PER_SEC,
        NANOS_PER_SEC + 1,
        2 * NANOS_PER_SEC,
        2 * NANOS_PER_SEC + 1,
        4 * NANOS_PER_SEC + 1,
        7 * NANOS_PER_SEC - 1,
        14 * NANOS_PER_SEC + 999_999_999,
    ];

    #[test]
    fn the_corridor_contains_the_bound_at_every_offset_and_every_width() {
        // The property, and the reason for both terms. A midpoint a nanosecond short of a second
        // truncates to the second before it, which moves the corridor almost a whole second
        // earlier; a width that is odd at a second boundary halves to a radius a second short of
        // the late end. Either way the bound this server signed for falls outside the corridor it
        // stated, which is the one direction that must never happen.
        let base = 1_800_000_000 * NANOS_PER_SEC;
        for offset in OFFSETS {
            for width in WIDTHS {
                let earliest = base + offset;
                let b = bound(earliest, earliest + width);
                let reading = reading_for(&b).expect("a bound this side of 1970 states a corridor");
                let (from, to) = corridor(reading);
                assert!(
                    from <= b.earliest.0 && to >= b.latest.0,
                    "a corridor of {from}..{to} does not cover a bound of {}..{} at offset \
                     {offset} and width {width}",
                    b.earliest.0,
                    b.latest.0
                );
            }
        }
    }

    #[test]
    fn an_odd_width_at_a_second_boundary_rounds_outwards_rather_than_to_the_nearest() {
        // The narrowest case that separates the two ways of halving, written out on its own so a
        // reader can see the arithmetic rather than trusting the walk above to contain it. A bound
        // two seconds and a nanosecond wide has a midpoint one second in, and the far end is one
        // second and a nanosecond away: a radius of one is short by that nanosecond, and the
        // format's only answer is two.
        let earliest = 1_800_000_000 * NANOS_PER_SEC;
        let b = bound(earliest, earliest + 2 * NANOS_PER_SEC + 1);
        let reading = reading_for(&b).expect("a corridor");
        assert_eq!(reading.radius_seconds, 2);
        let (from, to) = corridor(reading);
        assert!(from <= b.earliest.0 && to >= b.latest.0, "{from}..{to}");
    }

    #[test]
    fn a_bound_this_product_actually_reaches_states_the_narrowest_corridor_there_is() {
        // 153.875 ms is the width on the committed receipt fixture. It is far inside a second, and
        // the corridor is still two seconds wide, because the wire format has no way to say
        // anything narrower. Nothing our own servers do makes this number smaller.
        let midpoint = 1_800_000_000 * NANOS_PER_SEC + 250_000_000;
        let half = 153_875_000 / 2;
        let reading = reading_for(&bound(midpoint - half, midpoint + half)).expect("a corridor");
        assert_eq!(reading.radius_seconds, 1, "the floor the format sets");
        let (from, to) = corridor(reading);
        assert_eq!(to - from, 2 * NANOS_PER_SEC);
    }

    #[test]
    fn a_bound_before_1970_states_no_corridor_rather_than_wrapping() {
        assert_eq!(
            reading_for(&bound(-2 * NANOS_PER_SEC, -NANOS_PER_SEC)),
            None
        );
    }

    #[test]
    fn a_key_arrives_from_the_environment_as_hex_or_not_at_all() {
        let sixty_four = "a".repeat(64);
        assert_eq!(from_hex(&sixty_four), Some([0xaau8; 32]));
        assert_eq!(from_hex(&"a".repeat(63)), None, "too short is not a key");
        assert_eq!(from_hex(&"a".repeat(65)), None, "too long is not a key");
        assert_eq!(from_hex(&"z".repeat(64)), None, "not hex is not a key");
        // The one that would otherwise be read as a key: a leading sign is not a hex digit, and
        // `from_str_radix` would take it on a wider type.
        assert_eq!(from_hex(&format!("-1{}", "0".repeat(62))), None);
    }
}
