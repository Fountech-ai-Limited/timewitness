//! `timewitness agent`, the process that stays up.
//!
//! It disciplines this machine's clock against the published sources on a schedule, holds one model
//! between stamps, and answers a reading to whoever asks over a loopback boundary. `timewitness
//! stamp --agent` is what asks.
//!
//! ## What it does not do, said here because a reader will assume otherwise
//!
//! It installs nothing. There is no Windows service, no systemd unit, no scheduler entry and
//! nothing that starts at boot. It is a foreground process that runs until it is stopped, and if
//! this machine restarts it is not running afterwards. The limitation list says so on all three
//! surfaces.
//!
//! It does not set this machine's clock. The default is measure and vouch, exactly as the one-shot
//! command's is, because the Windows time service contends with any other discipliner by design and
//! a second one fighting it makes both worse.
//!
//! It does not sign anything and it is never told what is being stamped. It hands over a reading and
//! the caller builds its own receipt over its own subject with its own key.
//!
//! ## Why it prints as it goes rather than returning a result
//!
//! Every other subcommand runs, produces text and exits, so the text is a return value and this
//! crate's `render` module is the only thing that formats it. This one does not end, so there is
//! nothing to return until it is stopped. It prints the same way `render` would and it prints
//! nothing a person has to act on.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use timewitness_agent::resident::{Resident, SystemSurroundings};
use timewitness_agent::serve::{serve, Cadence, Reporter};
use timewitness_agent::wire::Endpoint;
use timewitness_clock::monotonic::SystemMonotonic;
use timewitness_clock::Policy;
use timewitness_core::{Operator, UnixNanos};
use timewitness_sources::ntp::{NtpClient, NtpServer};
use timewitness_sources::nts::{NtsClient, NtsServer};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};
use timewitness_sources::TimeSource;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// How many reads to take when measuring the counter's own granularity.
///
/// Two thousand, which takes a few milliseconds once at startup. The one-shot command does not do
/// this at all and passes nought, so the model falls back to the policy floor; an agent that is
/// going to run for hours can afford to measure the thing it will be reading all day.
const GRANULARITY_READS: usize = 2_000;

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let endpoint_path = match args.required("--endpoint") {
        Ok(path) => path,
        Err(e) => return fail(&e.0),
    };

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

    // The port is the operating system's to choose. A fixed one would collide with whatever else is
    // on this machine and would have to be configured, and there is nothing here for a stranger to
    // find: the address is written into a file only this account can read, beside the token.
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) => {
            return fail(&format!(
                "nothing on this machine would give us a port: {e}"
            ))
        }
    };
    let address = match listener.local_addr() {
        Ok(address) => address.to_string(),
        Err(e) => return fail(&format!("the port we were given has no address: {e}")),
    };
    let endpoint = match Endpoint::fresh(address.clone()) {
        Ok(endpoint) => endpoint,
        Err(e) => return fail(&format!("{e}")),
    };
    if let Err(e) = endpoint.write(std::path::Path::new(endpoint_path)) {
        return fail(&format!("{endpoint_path} could not be written: {e}"));
    }

    // The system clock, read once, only to anchor the model. Everything after this is the monotonic
    // counter, and the model reports against the anchor rather than re-reading a clock something
    // else may be steering underneath it.
    let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return fail("this machine's clock is before 1970, which is not something to build on");
    };
    let Ok(nanos) = i128::try_from(wall.as_nanos()) else {
        return fail("this machine's clock is further from 1970 than the arithmetic here reaches");
    };
    let clock = Arc::new(SystemMonotonic::new());
    let granularity = clock.measure_granularity(GRANULARITY_READS);
    let resident = Resident::new(
        policy,
        clock,
        UnixNanos(nanos),
        granularity,
        Box::new(SystemSurroundings),
    );

    // What disciplines the clock, which is the same list the one-shot command polls. Three kinds and
    // each is here for a different reason. Roughtime signs and cannot narrow the bound, because it
    // states its uncertainty in whole seconds. Plain NTP narrows the bound and signs nothing. NTS
    // narrows nothing that plain NTP does not, and is here because its answer cannot be written by
    // somebody on the path, which is the one thing plain NTP cannot say about itself. Evidence is
    // the caller's to gather at the moment it stamps, because an attestation is over the subject and
    // the agent is never shown one.
    let mut sources: Vec<Box<dyn TimeSource + Send>> = Vec::new();
    for server in RoughtimeServer::published() {
        sources.push(Box::new(RoughtimeClient::new(server)));
    }
    for server in NtpServer::published() {
        sources.push(Box::new(NtpClient::new(server)));
    }
    for server in NtsServer::published() {
        sources.push(Box::new(NtsClient::new(server)));
    }

    let cadence = Cadence {
        interval,
        ..Cadence::default()
    };
    println!(
        "{}",
        render::agent_started(
            endpoint_path,
            &address,
            render::AgentStart {
                sources: sources.len(),
                operators: distinct_operators(&sources),
                min_operators: policy.min_operators,
                interval_seconds: cadence.interval.as_secs(),
                granularity,
                max_bound_width,
            },
        )
    );

    let report: Reporter = Arc::new(|line: String| println!("  {line}"));
    serve(
        resident,
        sources,
        endpoint.token,
        &listener,
        cadence,
        report,
    );

    // Only reachable if the listener stopped handing over connections, which is a machine fault
    // rather than a way of stopping the agent. Stopping it is a signal, and a signal does not come
    // back here.
    fail("this machine stopped accepting connections on the loopback interface")
}

/// How many distinct operators a list of sources reaches.
///
/// Counted here rather than taken from the length of the list, because the length of the list is the
/// flattering number: three of the nine servers this product ships against are two names at one
/// company, and a person choosing what to point an agent at should see both figures before they add
/// a tenth name at a company that is already in it.
fn distinct_operators(sources: &[Box<dyn TimeSource + Send>]) -> usize {
    sources
        .iter()
        .map(|s| s.operator().clone())
        .collect::<BTreeSet<Operator>>()
        .len()
}

fn fail(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 1,
    }
}
