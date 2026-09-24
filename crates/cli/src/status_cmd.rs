//! `timewitness status`: is the agent up, and how wide is its bound right now.
//!
//! The one question a person asks of a resident agent on an ordinary day. It asks the agent the same
//! thing `stamp --agent` asks, over the same boundary, and says what came back in words: the width
//! of the bound, how many sources it rests on, how long since the model last heard from one, and
//! whether the agent is refusing. Nothing is signed and nothing is written.
//!
//! It adds no message to the agent's protocol. A reading already carries everything a status needs,
//! so asking for one is the status, and an agent that will not give a reading has told us the other
//! thing worth knowing.
//!
//! ## How wrong the clock could be, from the first minute
//!
//! A person who has just started an agent asks one thing of it, and until 2026-09-24 this command
//! could not answer it for the first two minutes or so. A fresh agent works out a bound within
//! seconds and then spends its first minutes with that bound above the 250 ms it will sign for,
//! because a line fitted over a few seconds of measurements is being stretched across a thirty-two
//! second gap. The agent refused, and the refusal was all a status had to print.
//!
//! The width was never missing. The model worked it out and refused because of it, and from that
//! date the refusal carries it. So a status now says the width whether or not a stamp would be
//! signed at it, in one plain sentence, and says which. Nothing is narrowed to get there: the width
//! printed is the model's own, the agent still refuses to sign it, and a wide honest answer at ten
//! seconds is worth more to somebody new than a narrow one at three minutes.
//!
//! Two times are stated, and both come from ten measured starts written down in the README with the
//! machine, the network and the date: how soon a fresh agent has a first bound at all, and how long
//! it spends refusing most stamps before a refusal becomes occasional. `scripts/status-from-cold.py`
//! starts the agent from cold and holds the first of them to what it measures on every run.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use timewitness_agent::crossing::{ask, CrossingError, WhatTheCallerKnows};
use timewitness_agent::wire::{Endpoint, WireError};
use timewitness_clock::monotonic::SystemMonotonic;
use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::UnixNanos;
use timewitness_verify::width_in_words;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// The widest reading a status will describe rather than refuse: an hour, the widest interval the
/// verifier reads at all. A status reports a wide bound; it is `stamp` that declines to sign one.
const DESCRIBE_UP_TO: i128 = 3_600 * NANOS_PER_SEC;

/// How soon a fresh agent has a first bound for a status to state, in seconds.
///
/// 30 s, a stated time held to ten measured starts rather than chosen: on 2026-09-24 they gave a
/// first width at 1.9 s to 6.6 s of uptime on an ordinary desktop. The margin is for a first round
/// that waits out a source or two, since a round asks nine servers one after another and each may
/// take five seconds to give up. The README carries the starts, with the machine, the network and
/// the date, and `scripts/status-from-cold.py` fails if a start takes longer than this or if the
/// README states a different figure.
pub const FIRST_BOUND_WITHIN: u64 = 30;

/// How long a status goes on telling somebody that a fresh agent is still settling, in seconds.
///
/// Three minutes, read off the same ten starts rather than chosen. Over their first two minutes 1224
/// of 1809 answers were refused, and from three minutes to five 38 of 1810 were. There is no moment
/// after which a refusal stops: an agent refuses whenever the top of a sweep between rounds crosses
/// its ceiling, and on the machine measured four of the ten starts refused once or more in their
/// last fifteen seconds of five minutes. So this is where a refusal stopped being the usual answer,
/// and the sentence it gates says so rather than promising a time after which none come.
pub const SETTLES_WITHIN: u64 = 180;

pub fn run(args: &Args) -> Outcome {
    let endpoint_path = match args.required("--agent") {
        Ok(path) => path,
        Err(e) => {
            return Outcome {
                text: format!("{}\n\n{}", render::failure(&e.0), render::usage()),
                code: 2,
            }
        }
    };
    let endpoint = match Endpoint::read(Path::new(endpoint_path)) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            return Outcome {
                text: render::failure(&format!(
                    "no agent is running from {endpoint_path}: {e}. Start one with `timewitness \
                     agent --endpoint {endpoint_path}`"
                )),
                code: 1,
            }
        }
    };
    let uptime = up_for(Path::new(endpoint_path));

    let Some(local_wall) = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i128::try_from(d.as_nanos()).ok())
    else {
        return Outcome {
            text: render::failure("this machine's clock is before 1970"),
            code: 1,
        };
    };
    let knows = WhatTheCallerKnows {
        local_wall: UnixNanos(local_wall),
        ceiling: DESCRIBE_UP_TO,
    };

    match ask(&endpoint, &SystemMonotonic::new(), knows) {
        Ok(crossed) => {
            let claim = &crossed.carrier.claim;
            let width = claim.latest.as_nanos() - claim.earliest.as_nanos();
            // Counted the way the verifier counts, so a status and a receipt never disagree.
            let operators = claim.operators();
            let mut text = format!(
                "The agent at {} is up and answering.\n\n{} A stamp taken now would carry that \
                 bound.\n",
                endpoint.address,
                how_wrong(width),
            );
            if let Some(line) = still_settling(uptime) {
                text.push_str(&line);
                text.push('\n');
            }
            text.push_str(&format!(
                "\n\
                 \x20 bound now     {} wide, on {} of {} sources, run by {} operators\n\
                 \x20 last heard    {:.3} s ago, from a source\n\
                 \x20 asking took   {:.3} ms, and a stamp widens its interval by that\n\
                 \x20 system clock  left alone. The agent measures and vouches; nothing in it \
                 sets this machine's clock\n\n\
                 The bound is how wrong the reading could be, not how right it is.",
                width_in_words(width),
                claim.sources_kept,
                claim.sources_offered,
                operators.kept,
                claim.since_last_sync as f64 / NANOS_PER_SEC as f64,
                crossed.round_trip as f64 / 1e6,
            ));
            Outcome { text, code: 0 }
        }
        Err(CrossingError::Unreachable(why)) => Outcome {
            text: render::failure(&format!("the agent is not answering: {why}")),
            code: 1,
        },
        // The model worked out a bound and it was past the ceiling, in the agent or once the
        // crossing was paid for. Either way the width is known, and it is what a person asked for.
        Err(CrossingError::Wire(WireError::PastCeiling {
            width,
            ceiling,
            why,
        })) => past_ceiling(&endpoint.address, width, ceiling, uptime, &why),
        Err(e @ CrossingError::TooWide { width, ceiling, .. }) => {
            past_ceiling(&endpoint.address, width, ceiling, uptime, &format!("{e}"))
        }
        Err(e) => {
            let mut text = render::failure(&format!(
                "the agent at {} is up and would not give a reading a stamp could use: {e}",
                endpoint.address
            ));
            if let Some(line) = first_bound_to_come(uptime) {
                text.push_str("\n\n");
                text.push_str(&line);
            }
            Outcome { text, code: 1 }
        }
    }
}

/// The plain sentence, which is the whole of what somebody new asks of a status.
///
/// The width rather than half of it. The reading and true UTC both sit inside an interval this wide,
/// on the model's word, so the reading is out by no more than the width. The reading is not the
/// middle of the interval, so half of it would be a claim the arithmetic does not make.
fn how_wrong(width: Nanos) -> String {
    if width > DESCRIBE_UP_TO {
        "Right now the time it gives could be wrong by more than an hour.".to_string()
    } else {
        format!(
            "Right now the time it gives could be wrong by as much as {}.",
            width_in_words(width)
        )
    }
}

/// What a status says when the agent has a bound and will not sign at it.
///
/// Exit status 1, as for any refusal, because a script asking whether a stamp would be signed now is
/// owed the same answer it got before the width was printed.
fn past_ceiling(
    address: &str,
    width: Nanos,
    ceiling: Nanos,
    uptime: Option<Duration>,
    why: &str,
) -> Outcome {
    let mut text = format!(
        "The agent at {address} is up, and would not sign a stamp right now.\n\n{} That is past \
         the {} it will sign for, so a stamp taken now would be refused.\n",
        how_wrong(width),
        width_in_words(ceiling),
    );
    text.push_str(&still_settling(uptime).unwrap_or_else(|| {
        "The bound widens between the agent's rounds and narrows each time it hears from its \
         sources again, so asking again in a few seconds may get a different answer."
            .to_string()
    }));
    text.push_str(&format!("\n\n\x20 the agent said  {why}"));
    Outcome { text, code: 1 }
}

/// The line for an agent still inside its first minutes, or nothing once it is past them.
fn still_settling(uptime: Option<Duration>) -> Option<String> {
    let up = uptime?.as_secs();
    (up < SETTLES_WITHIN).then(|| {
        format!(
            "It started {up} s ago. While a fresh agent learns this machine's clock its bound swings \
             above its ceiling between rounds, so most stamps in its first two minutes are refused \
             and a refusal is only occasional after about three. The next answer may be a refusal."
        )
    })
}

/// The line for an agent with no bound yet, while it is young enough that one is still coming.
fn first_bound_to_come(uptime: Option<Duration>) -> Option<String> {
    let up = uptime?.as_secs();
    (up < FIRST_BOUND_WITHIN).then(|| {
        format!(
            "It started {up} s ago and is still asking its sources. A fresh agent has had a first \
             bound within {FIRST_BOUND_WITHIN} s of starting in every start measured, so ask again \
             then."
        )
    })
}

/// Roughly how long the agent has been up, from when it wrote its endpoint file.
///
/// The agent writes that file once, as it starts, so its age is the agent's age to within the few
/// milliseconds before the first round. It is read off this machine's own clock, which this product
/// spends its life saying nobody should trust, and it is used only to choose which sentence to print.
/// No figure in any bound or any receipt comes from it. A file dated in the future gives nothing
/// rather than a guess.
fn up_for(endpoint: &Path) -> Option<Duration> {
    let written = std::fs::metadata(endpoint).ok()?.modified().ok()?;
    SystemTime::now().duration_since(written).ok()
}
