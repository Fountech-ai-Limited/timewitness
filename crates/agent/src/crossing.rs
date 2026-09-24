//! Asking the agent for a reading, and paying for the fact that it was taken somewhere else.
//!
//! A one-shot command reads its own counter, so the reading and the use of it are one instruction
//! apart and the model already charges for that gap in the breakdown's `scheduling` term. With a
//! resident agent the reading is taken in another process, and the caller cannot see the moment it
//! happened. That is the whole of what this module is about.
//!
//! From 2026-09-10 it is about a second thing, which the first one implies and nobody had written
//! down. A reading taken in another process is a reading taken on somebody else's word, and until
//! that date the caller took the whole answer on that word: the reading, the width, the breakdown,
//! the source list and the ceiling it was judged against all came out of the answer. So the caller
//! brings two things of its own, in [`WhatTheCallerKnows`], and neither is a proof of anything. See
//! [`crate::wire`] for what an attacker who can write the endpoint file actually gets.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use timewitness_clock::policy::{ppm_over, Policy};
use timewitness_clock::MonotonicClock;
use timewitness_core::time::{nanos_as_millis_f64, Nanos, NANOS_PER_SEC};
use timewitness_core::UnixNanos;
use timewitness_receipt::schema::Receipt;

use crate::wire::{decode_reply, is_an_agents_answer, Endpoint, WireError};

/// Why a caller could not get a reading it could stand behind.
#[derive(Clone, Debug)]
pub enum CrossingError {
    /// The agent could not be reached, or the conversation broke.
    Unreachable(String),
    /// A reply came back and could not be used.
    Wire(WireError),
    /// A reading came back and the crossing made it wider than a ceiling.
    TooWide {
        /// The interval after the crossing was paid for, in nanoseconds.
        width: Nanos,
        /// The ceiling it broke, in nanoseconds, which is the lower of the two.
        ceiling: Nanos,
        /// Whose ceiling that was.
        whose: Whose,
    },
    /// The reading is nowhere near this machine's own clock, so something is wrong somewhere.
    WildlyApart {
        /// The middle of the answer's interval, in nanoseconds since the epoch.
        reading: UnixNanos,
        /// What this machine's own clock said at about the same moment.
        local: UnixNanos,
        /// How far apart they are allowed to be before this refuses, in nanoseconds.
        allowance: Nanos,
    },
}

/// Which side of the crossing a ceiling belongs to.
///
/// Worth naming, because the two are refused for different reasons and a person reading a refusal
/// has different work to do. Their own ceiling is a setting they chose. The answering party's is a
/// setting somebody else chose, and on a machine where the endpoint file can be written it is a
/// setting an attacker chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Whose {
    /// The caller's, set with `--max-width` or left at the shipped default.
    TheCaller,
    /// The answering party's, carried in the policy block of the answer.
    TheAnsweringParty,
}

impl core::fmt::Display for CrossingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CrossingError::Unreachable(why) => write!(f, "{why}"),
            CrossingError::Wire(e) => write!(f, "{e}"),
            CrossingError::TooWide {
                width,
                ceiling,
                whose,
            } => {
                let owner = match whose {
                    Whose::TheCaller => "this caller's own ceiling",
                    Whose::TheAnsweringParty => "the answering party's ceiling",
                };
                write!(
                    f,
                    "the reading was {:.3} ms wide once the time spent asking the agent was added, \
                     and {owner} is {:.3} ms, so no receipt is issued",
                    nanos_as_millis_f64(*width),
                    nanos_as_millis_f64(*ceiling)
                )
            }
            CrossingError::WildlyApart {
                reading,
                local,
                allowance,
            } => {
                let apart = reading.as_nanos() - local.as_nanos();
                write!(
                    f,
                    "the answer puts the moment {:.3} s from where this machine's own clock puts \
                     it, and anything past {:.3} s is refused here. Either the endpoint file names \
                     something that is not this machine's agent, or this machine's clock is so far \
                     out that nothing on it can be checked against anything. No receipt is issued",
                    apart as f64 / NANOS_PER_SEC as f64,
                    *allowance as f64 / NANOS_PER_SEC as f64
                )
            }
        }
    }
}

/// A reading from the agent, and what the crossing cost.
#[derive(Clone, Debug)]
pub struct Crossed {
    /// The carrier, already widened, with the payload and the key still to be filled in.
    pub carrier: Receipt,
    /// How long the caller waited, on its own counter, in nanoseconds.
    pub round_trip: Nanos,
}

/// How long to wait for an agent that is there but not answering.
///
/// Two seconds. A reading is arithmetic over values already in memory behind one lock, so two
/// seconds is a very long time for it, and a caller hanging on a silent agent forever is a build
/// that never finishes. There is no retry: a second ask would get a second reading rather than the
/// same one, and the honest answer to an agent that will not answer is to say so.
///
/// It said "is not busy, it is wedged" until 2026-09-22, and that was wrong about the machine this
/// product runs on. Two stamps in 942 over three days ran out of patience here while the same
/// desktop was carrying several builds at once, and the agent was healthy either side of each. A
/// loaded machine is enough, which is why the refusal says which of the two things happened rather
/// than telling a reader their agent is wedged.
pub const PATIENCE: Duration = Duration::from_secs(2);

/// How far the answer may sit from this machine's own clock before the crossing refuses.
///
/// Five minutes, and the number is borrowed rather than invented. Five minutes is the default clock
/// skew Kerberos allows, so a machine further out than this already cannot get a ticket, join a
/// domain or complete most TLS handshakes: it is a machine somebody has to fix before anything on it
/// works, rather than the ordinary badly-set machine this product exists for.
///
/// Wide on purpose, and the reason is the whole product. The ordinary reason to run TimeWitness is
/// that the local clock is wrong by an amount worth bounding, so a check against that clock has to
/// leave room for it to be wrong. What is left after that room is the wild answer: hours or days,
/// which is what backdating or postdating anything is worth doing at.
pub const WILDNESS: Nanos = 300 * NANOS_PER_SEC;

/// What the caller already knows before it asks, and the only things it judges an answer against.
///
/// Before 2026-09-10 the crossing compared the answer to nothing at all: the reading, the width, the
/// source list and the ceiling all came out of the answer, so the only ceiling in the path was the
/// answering party's own. A caller with nothing of its own to check against is a caller
/// that signs whatever it is handed.
#[derive(Clone, Copy, Debug)]
pub struct WhatTheCallerKnows {
    /// This machine's own system clock, read just before the ask.
    ///
    /// Read by the caller rather than here, so a test can hand over a machine. Milliseconds of
    /// staleness do not matter against an allowance of [`WILDNESS`].
    pub local_wall: UnixNanos,
    /// The widest interval this caller will accept, whatever the answer's own policy says.
    pub ceiling: Nanos,
}

/// Whether the answer is anywhere near this machine's own clock.
///
/// **Say what this is and is not, because the difference decides how much it may be leaned on.** It
/// is a sanity check against a wild answer. It rests on the system clock, which is a clock this
/// product spends its life saying nobody should trust, and it proves nothing whatever: an answering
/// party who lies by less than [`WILDNESS`] passes it, and so does one who lies by a lot on a
/// machine whose own clock was moved to match. It is not authentication and it is not evidence.
///
/// What it is for is the `--no-evidence` path. With evidence gathered, which is the default, a
/// forged reading is caught properly: the corridor comes from servers the forger does not answer for
/// and the verifier refuses a claim that does not overlap it. With `--no-evidence` there is no
/// corridor, and a machine with no outbound HTTP is exactly the machine that has none to fall back
/// on. This is what that machine gets instead, and it is worth having because it is nearly free and
/// because the difference between a wrong answer and a wild one is the difference between a
/// plausible receipt and an obvious one.
fn not_wildly_apart(carrier: &Receipt, local: UnixNanos) -> Result<(), CrossingError> {
    let reading = carrier.utc_estimate;
    let apart = (reading.as_nanos() - local.as_nanos()).abs();
    if apart > WILDNESS {
        return Err(CrossingError::WildlyApart {
            reading,
            local,
            allowance: WILDNESS,
        });
    }
    Ok(())
}

/// Ask the agent at `endpoint` for a reading.
///
/// `clock` is the caller's own counter and it is what the round trip is measured on. It is passed in
/// rather than read here so a test can drive it. `knows` is everything the caller brings of its own,
/// and the two checks it feeds are inside this function rather than beside it on purpose: a check a
/// caller has to remember to run is a check that one day is not run.
pub fn ask(
    endpoint: &Endpoint,
    clock: &dyn MonotonicClock,
    knows: WhatTheCallerKnows,
) -> Result<Crossed, CrossingError> {
    let address = endpoint
        .address
        .to_socket_addrs()
        .map_err(|e| {
            CrossingError::Unreachable(format!("{} is not an address: {e}", endpoint.address))
        })?
        .next()
        .ok_or_else(|| {
            CrossingError::Unreachable(format!("{} resolved to nothing", endpoint.address))
        })?;

    let mut stream = TcpStream::connect_timeout(&address, PATIENCE).map_err(|e| {
        CrossingError::Unreachable(format!(
            "no agent answered at {}: {e}. Start one with `timewitness agent`",
            endpoint.address
        ))
    })?;
    stream.set_read_timeout(Some(PATIENCE)).ok();
    stream.set_write_timeout(Some(PATIENCE)).ok();
    stream.set_nodelay(true).ok();

    // The two marks the whole of this module rests on. The agent cannot read its model before it has
    // the token, so the reading is after the first mark; the caller has the answer in hand at the
    // second, so the reading is before it. Everything below follows from those two sentences.
    let asked_at = clock.now();
    stream.write_all(&endpoint.token).map_err(|e| {
        CrossingError::Unreachable(format!("the agent would not take the token: {e}"))
    })?;
    // Saying there is nothing more coming, so the agent can read a fixed number of bytes and answer
    // rather than waiting to find out whether a second message follows.
    stream.shutdown(Shutdown::Write).ok();

    let mut reply = Vec::with_capacity(4_096);
    let read = stream.read_to_end(&mut reply);
    let answered_at = clock.now();
    if let Err(e) = read {
        // Two different failures and they were both reported as the agent's until 2026-09-10. A
        // read that ran out of patience says nothing about the agent: it may be busy, it may be
        // answering somebody else, and a person told "the agent stopped mid-answer" restarts a
        // healthy one. Only a connection that actually broke is the agent stopping.
        //
        // From 2026-09-22 a read that ran out of patience says which of two things happened, and
        // the reason is a measurement rather than a preference. Over three days and 942 stamps
        // against a resident agent, two of them ran out of patience here, both on a desktop
        // carrying several builds at once, and the message they printed covered two cases at once:
        // an agent that took the connection and said nothing, and an answer that started and did
        // not finish. Those are different faults with different next steps, the first about the agent
        // getting to the ask at all and the second about the answer crossing, and the caller can
        // tell them apart without guessing because it knows how many bytes arrived.
        return Err(match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                let waited = answered_at.since(asked_at) as f64 / NANOS_PER_SEC as f64;
                let which = if reply.is_empty() {
                    "it took the connection and sent nothing at all, so it had not got to the ask \
                     inside that time"
                        .to_string()
                } else {
                    format!(
                        "it began answering, {} bytes arrived and the rest did not, so the answer \
                         was cut short rather than never started",
                        reply.len()
                    )
                };
                CrossingError::Unreachable(format!(
                    "this end waited {waited:.3} s for the agent at {} and gave up: {which}. \
                     Nothing here says the agent stopped; a machine under load is enough to do \
                     this. Underneath: {e}",
                    endpoint.address
                ))
            }
            _ => CrossingError::Unreachable(format!("the agent stopped mid-answer: {e}")),
        });
    }

    let carrier = decode_reply(&reply).map_err(CrossingError::Wire)?;
    not_wildly_apart(&carrier, knows.local_wall)?;
    let round_trip = answered_at.since(asked_at);
    let carrier = widen(&carrier, round_trip, knows.ceiling)?;
    Ok(Crossed {
        carrier,
        round_trip,
    })
}

/// How much of a reply [`an_agent_answers`] reads before it has enough to tell.
const ENOUGH_OF_A_REPLY: usize = 4_096;

/// Whether an agent still answers at `endpoint`, to the token written in it.
///
/// Asked by an agent about to start, before it writes its own address over a file somebody else may
/// be using. Until 2026-09-24 it did not ask: a second agent on a live endpoint took the file over,
/// and once it stopped the first was still running and polling other people's time servers with
/// nothing left to find it by (RC-349).
///
/// Only a loopback address is asked. An agent only ever writes one, so a file naming anywhere else
/// was not written by an agent, and a file is not a reason to send a token off this machine.
///
/// It is not proof. Once an agent has stopped, anything on this machine can take its old port and
/// answer the way an agent does, and the next start on that file is refused. That is why the refusal
/// says to delete the file where no agent of the reader's own is running.
///
/// A port nobody listens on, a port something else now holds, and an agent that says the token is
/// not its own all read as no, because each means the file outlived the agent that wrote it. An
/// agent that has not answered inside [`PATIENCE`] also reads as no. That is the one way this can
/// be wrong, and it takes an agent too stuck to answer a token in two seconds, which is an agent
/// that was not answering anybody else either. Two agents started in the same instant can both hear
/// nothing, because each asks before either has written. This closes the case somebody actually
/// meets, a second agent started while the first is up, and not that one.
#[must_use]
pub fn an_agent_answers(endpoint: &Endpoint) -> bool {
    // Parsed rather than resolved. An agent writes a number and a port, so a name in the file was not
    // written by one, and looking a name up is a wait with no ceiling of ours on it.
    let Some(address) = endpoint
        .address
        .parse::<SocketAddr>()
        .ok()
        .filter(|address| address.ip().is_loopback())
    else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&address, PATIENCE) else {
        return false;
    };
    stream.set_write_timeout(Some(PATIENCE)).ok();
    if stream.write_all(&endpoint.token).is_err() {
        return false;
    }
    stream.shutdown(Shutdown::Write).ok();

    // One wait for the whole reply rather than one per read. A party that sent a byte a second would
    // otherwise hold every start on this file for as long as it liked, with nothing printed. Whatever
    // has arrived by then is enough: a reading is known by its first byte and a refusal is a
    // sentence, so the first few thousand bytes of any reply say which it is.
    let deadline = Instant::now() + PATIENCE;
    let mut reply = Vec::with_capacity(ENOUGH_OF_A_REPLY);
    let mut chunk = [0u8; 512];
    while reply.len() < ENOUGH_OF_A_REPLY {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => reply.extend_from_slice(&chunk[..n]),
        }
    }
    is_an_agents_answer(&reply)
}

/// Pay for the crossing.
///
/// Write `c1` and `c2` for the caller's own counter at the two marks in [`ask`], and `t` for the
/// real instant the agent read its model. The agent's interval holds true UTC at `t`. What the
/// caller needs is an interval that holds true UTC at the moment it writes the receipt, which is
/// after `c2`, and it has no way to find `t` inside `[c1, c2]`.
///
/// For any instant `u` in that span, true UTC at `u` is true UTC at `t` plus `u - t`, and `u - t` is
/// somewhere in `[-(c2 - c1), c2 - c1]`. So widening the agent's interval by the span on both sides
/// gives an interval that holds true UTC at every instant of the caller's wait, including the one it
/// cares about. It is a widening in both directions and never a tightening.
///
/// One correction on top of that, and it is small enough that leaving it out would have been
/// defensible and stating it is cheaper than defending it. `c2 - c1` is measured on the caller's own
/// oscillator, which may be running fast or slow by up to the whole band a crystal occupies, so the
/// true span may be longer than the measured one by that fraction of it. The allowance is the
/// measured span plus that fraction, which at a hundred parts per million over a loopback round trip
/// of a tenth of a millisecond is one nanosecond after rounding up.
///
/// The widening goes into `scheduling`, which the format already defines as the allowance for the
/// cost and jitter of the local read itself. Under a resident agent the read costs a process
/// boundary and a lock instead of one instruction, so it is the same quantity and a larger one, and
/// a reader of the receipt sees where the width went without a new field to learn.
pub fn widen(
    carrier: &Receipt,
    round_trip: Nanos,
    callers_ceiling: Nanos,
) -> Result<Receipt, CrossingError> {
    let round_trip = round_trip.max(0);
    // The band, not the floor. The floor bounds how wrong a fitted rate was; this bounds how wrong
    // the caller's raw counter can be, which is the whole band a part is specified across.
    let allowance = round_trip + ppm_over(Policy::default().frequency_span_ppm, round_trip);

    let mut widened = carrier.clone();
    widened.claim.earliest = UnixNanos(widened.claim.earliest.as_nanos() - allowance);
    widened.claim.latest = UnixNanos(widened.claim.latest.as_nanos() + allowance);
    widened.claim.breakdown.scheduling += allowance;

    // Both ceilings, and the lower one binds. Until 2026-09-10 this measured the
    // result against `carrier.claim.policy.max_bound_width` alone, which came out of the same answer
    // being judged, so the only ceiling in the path belonged to whoever answered. An answering party
    // that states a ceiling of an hour is not thereby allowed to hand this caller an hour.
    //
    // The answering party's ceiling is still checked, because a receipt claiming a bound wider than
    // the policy it carries is one this product's own verifier refuses, and refusing here says why.
    let width = widened.width();
    let theirs = widened.claim.policy.max_bound_width;
    if width > callers_ceiling {
        return Err(CrossingError::TooWide {
            width,
            ceiling: callers_ceiling,
            whose: Whose::TheCaller,
        });
    }
    if width > theirs {
        return Err(CrossingError::TooWide {
            width,
            ceiling: theirs,
            whose: Whose::TheAnsweringParty,
        });
    }
    Ok(widened)
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_clock::monotonic::SystemMonotonic;
    use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
    use timewitness_core::{
        Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, Reading, SourceState, Stamp,
    };
    use timewitness_receipt::schema::PolicyRecord;

    fn a_reading(half_width: Nanos) -> Stamp {
        let middle = 1_757_000_000 * NANOS_PER_SEC;
        Stamp {
            reading: Reading {
                monotonic: timewitness_core::MonotonicNanos(5_000),
                utc_estimate: UnixNanos(middle),
            },
            bound: Bound {
                earliest: UnixNanos(middle - half_width),
                latest: UnixNanos(middle + half_width),
                basis: EpsilonBasis::LocalModelOnly,
                breakdown: BoundBreakdown {
                    fusion: FusionRule::MarzulloThenInverseSquare {
                        offered: 6,
                        kept: 5,
                    },
                    intersection_half: half_width - 3,
                    widest_source_network_half: 1,
                    scheduling: 1,
                    oscillator_holdover: 1,
                    unclaimed_rate: 0,
                    model_residual: 1,
                    safety_margin: 0,
                },
            },
            sources: Vec::<SourceState>::new(),
            generations: Generations::default(),
            since_last_sync: 30 * NANOS_PER_SEC,
            frequency_ppm: None,
        }
    }

    fn a_carrier(half_width: Nanos, ceiling: Nanos) -> Receipt {
        crate::wire::carrier(
            &a_reading(half_width),
            PolicyRecord {
                max_bound_width: ceiling,
                min_sources: 3,
                min_operators: Some(4),
                max_holdover: Some(3_600 * NANOS_PER_SEC),
                source_interval_floor: Some(100_000),
                frequency_slew_ppb_per_s: Some(1_000),
                frequency_span_ppb: Some(100_000),
            },
            timewitness_receipt::schema::TakenBy::ResidentAgent,
        )
    }

    #[test]
    fn the_crossing_widens_the_interval_on_both_sides_and_never_narrows_it() {
        let before = a_carrier(NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        let after =
            widen(&before, 120_000, 250 * NANOS_PER_MILLI).expect("well inside the ceiling");
        assert!(after.claim.earliest < before.claim.earliest);
        assert!(after.claim.latest > before.claim.latest);
        assert!(after.width() > before.width());
        // The estimate was inside its interval and a widening cannot put it outside one.
        assert!(after.utc_estimate >= after.claim.earliest);
        assert!(after.utc_estimate <= after.claim.latest);
    }

    #[test]
    fn the_parts_of_the_widened_bound_still_add_up_to_it() {
        // The receipt validator refuses a receipt whose breakdown does not describe its own
        // interval, so a widening that moved the edges without moving a term would produce a receipt
        // this product's own verifier turns down.
        let before = a_carrier(NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        let after =
            widen(&before, 120_000, 250 * NANOS_PER_MILLI).expect("well inside the ceiling");
        let parts = 2 * after.claim.breakdown.half_width();
        assert!(
            parts >= after.width() && parts <= after.width() + 2,
            "the parts add to {parts} and the interval is {} wide",
            after.width()
        );
        assert_eq!(
            after.claim.breakdown.scheduling - before.claim.breakdown.scheduling,
            (after.width() - before.width()) / 2,
            "the whole of the widening is in the term the format keeps it in"
        );
    }

    #[test]
    fn the_allowance_covers_a_counter_running_at_the_edge_of_its_band() {
        // A hundred parts per million of a second is a hundred microseconds, and the allowance has
        // to be the span plus that rather than the span.
        let before = a_carrier(NANOS_PER_MILLI, 10 * NANOS_PER_SEC);
        let after =
            widen(&before, NANOS_PER_SEC, 10 * NANOS_PER_SEC).expect("inside a ten second ceiling");
        let paid = after.claim.breakdown.scheduling - before.claim.breakdown.scheduling;
        assert_eq!(paid, NANOS_PER_SEC + 100_000);
    }

    #[test]
    fn a_crossing_that_pushes_the_bound_past_the_agents_own_ceiling_refuses() {
        // The alternative is a receipt claiming a bound wider than the policy it carries, which the
        // verifier refuses anyway. Refusing here says why.
        // The caller's ceiling is left generous here so the one being tested is the answer's own.
        let before = a_carrier(120 * NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        match widen(&before, 20 * NANOS_PER_MILLI, 10 * NANOS_PER_SEC) {
            Err(CrossingError::TooWide {
                width,
                ceiling,
                whose,
            }) => {
                assert!(width > ceiling);
                assert_eq!(whose, Whose::TheAnsweringParty);
            }
            other => panic!("a crossing that blew the ceiling should refuse, not {other:?}"),
        }
    }

    /// The instant `a_reading` centres on, which is what a truthful machine's clock would say.
    const MIDDLE: Nanos = 1_757_000_000 * NANOS_PER_SEC;

    #[test]
    fn an_answer_nowhere_near_this_machines_clock_is_refused_whichever_way_it_lies() {
        // The property, rather than the one case testing built. What is being checked is that the
        // distance decides it, in both directions, at any size: a run that only proved a harness
        // three hours in the past would close on a harness.
        let carrier = a_carrier(NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        for seconds in [
            -86_400, -10_800, -3_600, -600, -301, 301, 600, 3_600, 10_800, 86_400,
        ] {
            // The answer is fixed and the machine's own clock is what moves, which is the same
            // distance and is the shape the real path has: the answer arrives and the caller has
            // only its own clock to hold it against.
            let local = UnixNanos(MIDDLE - Nanos::from(seconds) * NANOS_PER_SEC);
            match not_wildly_apart(&carrier, local) {
                Err(CrossingError::WildlyApart { allowance, .. }) => {
                    assert_eq!(allowance, WILDNESS);
                }
                other => panic!("{seconds} s apart was not refused: {other:?}"),
            }
        }
    }

    #[test]
    fn an_answer_inside_the_allowance_is_taken_however_wrong_this_machines_clock_is() {
        // The other half, and it is the half that keeps the check honest. A machine whose clock is
        // minutes out is the ordinary machine this product is for, so a check against that clock
        // must not refuse it. Anything inside the allowance passes, at the edge included.
        let carrier = a_carrier(NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        for seconds in [-300, -299, -60, -1, 0, 1, 60, 299, 300] {
            let local = UnixNanos(MIDDLE - Nanos::from(seconds) * NANOS_PER_SEC);
            assert!(
                not_wildly_apart(&carrier, local).is_ok(),
                "{seconds} s apart is inside the allowance and was refused"
            );
        }
    }

    #[test]
    fn the_answering_party_does_not_get_to_raise_the_ceiling_it_is_judged_by() {
        // The caller's own ceiling. The answer states an hour, the caller accepts 250 ms, and the
        // answer is 240 ms wide. Before 2026-09-10 the hour won because it was the only ceiling
        // read.
        let generous = a_carrier(120 * NANOS_PER_MILLI, 3_600 * NANOS_PER_SEC);
        match widen(&generous, 20 * NANOS_PER_MILLI, 250 * NANOS_PER_MILLI) {
            Err(CrossingError::TooWide { whose, ceiling, .. }) => {
                assert_eq!(whose, Whose::TheCaller);
                assert_eq!(ceiling, 250 * NANOS_PER_MILLI);
            }
            other => panic!("the answering party's hour was taken as the ceiling: {other:?}"),
        }

        // And the caller's ceiling is a ceiling and not a floor: an answer inside both is taken.
        let modest = a_carrier(NANOS_PER_MILLI, 3_600 * NANOS_PER_SEC);
        assert!(widen(&modest, 120_000, 250 * NANOS_PER_MILLI).is_ok());
    }

    #[test]
    fn a_round_trip_of_nothing_costs_nothing() {
        let before = a_carrier(NANOS_PER_MILLI, 250 * NANOS_PER_MILLI);
        let after = widen(&before, 0, 250 * NANOS_PER_MILLI).expect("no widening at all");
        assert_eq!(after.width(), before.width());
        assert_eq!(after.claim.breakdown, before.claim.breakdown);
    }

    #[test]
    fn a_file_is_live_only_while_its_own_agent_answers_it() {
        use crate::wire::{encode_refusal, NOT_THIS_TOKEN};
        use std::net::TcpListener;

        // A party on a loopback port that answers the way an agent does, once.
        fn party(reply: Vec<u8>) -> Endpoint {
            let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            let endpoint =
                Endpoint::fresh(listener.local_addr().expect("the port").to_string()).unwrap();
            std::thread::spawn(move || {
                if let Ok((mut taken, _)) = listener.accept() {
                    let mut token = [0u8; crate::wire::TOKEN_BYTES];
                    let _ = taken.read_exact(&mut token);
                    let _ = taken.write_all(&reply);
                }
            });
            endpoint
        }

        assert!(an_agent_answers(&party(encode_refusal(
            "the model has never synchronised"
        ))));
        assert!(!an_agent_answers(&party(encode_refusal(NOT_THIS_TOKEN))));
        assert!(!an_agent_answers(&party(
            b"HTTP/1.1 400 Bad Request\r\n".to_vec()
        )));

        // A port nobody holds any more.
        let gone = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = gone.local_addr().expect("the port").to_string();
        drop(gone);
        assert!(!an_agent_answers(&Endpoint::fresh(address).unwrap()));

        // Somewhere off this machine, which is never asked at all.
        assert!(!an_agent_answers(&Endpoint::fresh("192.0.2.1:9").unwrap()));
    }

    /// A party that takes the connection and then behaves as `then` says, for long enough that the
    /// caller's patience runs out. It hands back what `ask` said, so a test reads the refusal a
    /// person would be shown.
    fn ran_out_of_patience_on(then: fn(&mut std::net::TcpStream)) -> String {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("the port it took").to_string();
        let held = std::thread::spawn(move || {
            let (mut taken, _) = listener.accept().expect("the caller's connection");
            then(&mut taken);
            // Held open past the caller's patience, because a party that closes the connection is
            // the other fault entirely and this is not a test of that one.
            std::thread::sleep(PATIENCE + Duration::from_millis(500));
        });
        let endpoint = Endpoint::fresh(address).expect("an endpoint");
        let knows = WhatTheCallerKnows {
            local_wall: UnixNanos(1_757_000_000 * NANOS_PER_SEC),
            ceiling: 250 * NANOS_PER_MILLI,
        };
        let said = match ask(&endpoint, &SystemMonotonic::new(), knows) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a party that never answered was taken as an answer"),
        };
        held.join().expect("the party's thread");
        said
    }

    #[test]
    fn a_party_that_takes_the_connection_and_says_nothing_is_told_apart_from_one_cut_short() {
        // The fault the three-day capture caught twice in 942 stamps. Until 2026-09-22 both of
        // these printed the same sentence, which named neither of them and told the reader their
        // agent might be wedged.
        let silent = ran_out_of_patience_on(|_| {});
        assert!(
            silent.contains("sent nothing at all"),
            "a silent party is not named as one: {silent}"
        );
        assert!(
            !silent.contains("began answering"),
            "a silent party is described as having started: {silent}"
        );

        let cut_short = ran_out_of_patience_on(|taken| {
            taken.write_all(&[0xd9, 0xd9, 0xf7]).expect("three bytes");
            taken.flush().ok();
        });
        assert!(
            cut_short.contains("began answering") && cut_short.contains("3 bytes"),
            "an answer cut short is not named as one: {cut_short}"
        );
        assert!(
            !cut_short.contains("sent nothing at all"),
            "an answer that started is described as never started: {cut_short}"
        );

        // Both still say the thing that was right about the old message: this end cannot tell
        // whether the agent stopped, so nobody is sent to restart a healthy one.
        for said in [&silent, &cut_short] {
            assert!(
                said.contains("Nothing here says the agent stopped"),
                "the refusal blames the agent: {said}"
            );
        }
    }

    #[test]
    fn every_way_a_crossing_refuses_says_why_in_plain_words() {
        use timewitness_core::refusal::{insides_in, one_of_each};

        let mut refused: Vec<CrossingError> = one_of_each()
            .iter()
            .map(|v| CrossingError::Wire(WireError::Refused(v.to_string())))
            .collect();
        refused.push(CrossingError::Wire(WireError::PastCeiling {
            width: 1_203_645_522,
            ceiling: 250 * NANOS_PER_MILLI,
            why: "the bound has grown to 1203.645522 ms, past the 250 ms ceiling".into(),
        }));
        refused.push(CrossingError::Unreachable("no agent answered".into()));
        for whose in [Whose::TheCaller, Whose::TheAnsweringParty] {
            refused.push(CrossingError::TooWide {
                width: 1_203_645_522,
                ceiling: 250 * NANOS_PER_MILLI,
                whose,
            });
        }
        refused.push(CrossingError::WildlyApart {
            reading: UnixNanos(1_757_000_000 * NANOS_PER_SEC),
            local: UnixNanos(1_757_000_900 * NANOS_PER_SEC),
            allowance: 600 * NANOS_PER_SEC,
        });

        for e in refused {
            let said = e.to_string();
            assert_eq!(insides_in(&said), None, "{said}");
            if let CrossingError::TooWide { .. } = e {
                // A ten-digit count of nanoseconds is a number nobody reads at a glance.
                assert!(said.contains("1203.646 ms"), "{said}");
                assert!(said.contains("250.000 ms"), "{said}");
            }
        }
    }
}
