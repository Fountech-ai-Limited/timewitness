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

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_agent::crossing::{ask, CrossingError, WhatTheCallerKnows};
use timewitness_agent::wire::Endpoint;
use timewitness_clock::monotonic::SystemMonotonic;
use timewitness_core::time::NANOS_PER_SEC;
use timewitness_core::UnixNanos;
use timewitness_verify::width_in_words;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// The widest reading a status will describe rather than refuse: an hour, the widest interval the
/// verifier reads at all. A status reports a wide bound; it is `stamp` that declines to sign one.
const DESCRIBE_UP_TO: i128 = 3_600 * NANOS_PER_SEC;

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
            let text = format!(
                "The agent at {} is up and answering.\n\n\
                 \x20 bound now     {} wide, on {} of {} sources, run by {} operators\n\
                 \x20 last heard    {:.3} s ago, from a source\n\
                 \x20 asking took   {:.3} ms, and a stamp widens its interval by that\n\
                 \x20 system clock  left alone. The agent measures and vouches; nothing in it \
                 sets this machine's clock\n\n\
                 The bound is how wrong the reading could be, not how right it is.",
                endpoint.address,
                width_in_words(width),
                claim.sources_kept,
                claim.sources_offered,
                operators.kept,
                claim.since_last_sync as f64 / NANOS_PER_SEC as f64,
                crossed.round_trip as f64 / 1e6,
            );
            Outcome { text, code: 0 }
        }
        Err(CrossingError::Unreachable(why)) => Outcome {
            text: render::failure(&format!("the agent is not answering: {why}")),
            code: 1,
        },
        Err(e) => Outcome {
            text: render::failure(&format!(
                "the agent at {} is up and would not give a reading a stamp could use: {e}",
                endpoint.address
            )),
            code: 1,
        },
    }
}
