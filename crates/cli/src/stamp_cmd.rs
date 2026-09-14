//! `timewitness stamp`, which is what a producer runs.
//!
//! It disciplines a clock model against whatever sources it can reach, takes one local reading with
//! no network in it, and writes a signed receipt over the hash of a file.
//!
//! ## What this does under continuous integration, which is the case it was built for
//!
//! A build runner is a machine that has existed for ninety seconds, not a laptop that has been up
//! for a fortnight, and everything below follows from that.
//!
//! **The bound is wide and it says so.** The shipped agent policy refuses anything over 250
//! milliseconds, so a run under CI raises its own ceiling, and the ceiling it raised is written into
//! the receipt where a verifier reads it. A receipt issued from an under-sourced model carrying a
//! bound as tight as a well-synchronised laptop's would be the lie this product exists to stop, and
//! it is an easy one to tell by accident under time pressure.
//!
//! **Two kinds of source are polled and they do different jobs.** A Roughtime server signs over a
//! nonce this machine chose, so its answer is the only one a stranger can check, and it states its
//! own uncertainty as a radius in whole seconds, so a round of Roughtime servers alone can only
//! ever support an interval seconds wide. A plain NTP server states a root delay and a dispersion
//! in units of about fifteen microseconds and signs nothing at all. So the evidence comes from one
//! kind and the width comes from the other, and neither can do the other's job. Where a runner
//! cannot reach one of them, its sources are absent from the round rather than assumed, and the
//! width the receipt carries is whatever the sources that did answer support.
//!
//! **The evidence is gathered inside the workflow's own budget.** Three attestations, one per role,
//! each a single round trip. Nothing here waits on a confirmation that takes longer than the job:
//! an OpenTimestamps anchor into a public chain can take tens of minutes to confirm and is not
//! built, which the shipped list of limitations already says.
//!
//! **What could not be gathered is absent rather than implied.** A source that did not answer is not
//! in the receipt, the count of sources that answered is what actually answered, and a receipt with
//! two roles instead of three does not get to claim its bound rests on a sandwich. The verifier then
//! reports what is there.
//!
//! ## The other way this runs, through a resident agent
//!
//! With `--agent` the reading comes from a resident agent rather than from a model built here. Every
//! step after the reading is the same: the same subject hash, the same evidence gathering, the same
//! key, the same receipt. What changes is where the bound came from and how old the synchronisation
//! behind it is.
//!
//! The two paths meet at a carrier, which is a receipt with the reading and the bound in it and the
//! payload, the sequence and the key still to be filled in. One-shot builds a model, polls and makes
//! a carrier from what it read; `--agent` asks for a carrier and pays for the crossing. Nothing
//! below the join knows which it was handed, which is what keeps the two from drifting apart.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_agent::crossing::{ask, WhatTheCallerKnows, WILDNESS};
use timewitness_agent::resident::note_interruptions;
use timewitness_agent::wire::{carrier, Endpoint};
use timewitness_clock::monotonic::SystemMonotonic;
use timewitness_clock::{
    Applied, ClockModel, Discipline, MonotonicClock, Policy, ShadowDiscipline,
};
use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::{Attestation, UnixNanos};
use timewitness_platform::EnvironmentWatch;
use timewitness_receipt::schema::{Evidence, PolicyRecord, Receipt, Role, Scheme};
use timewitness_receipt::{chain_link, sha256_payload, AgentKey};
use timewitness_sources::drand::DrandClient;
use timewitness_sources::ntp::{NtpClient, NtpServer};
use timewitness_sources::nts::{NtsClient, NtsServer};
use timewitness_sources::roughtime::{RoughtimeClient, RoughtimeServer};
use timewitness_sources::timestamp::{published_authorities, TimestampClient};
use timewitness_sources::{FinalWitness, TimeSource};

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// How wide a bound this will sign for when nothing else is said.
///
/// Thirty seconds, and the size of that number is the honest cost of having no time source but three
/// public Roughtime servers.
///
/// Measured from this machine on 2026-09-08, four rounds against the three servers: the interval
/// came out 16.399 s wide, of which 3.073 s of half width was the sources overlapping and 5.126 s
/// of half width was the regression's own standard error. Doubled, that second term is 10.3 s of
/// the 16.4 s, so it is the largest single part by some way.
///
/// The two terms have different causes and the difference matters. The first is the sources: a
/// Roughtime server states its uncertainty as a radius in whole seconds, so the intervals going
/// into the intersection are seconds wide and nothing this code does can narrow them. The second is
/// this code, fitting a line through four points taken inside two seconds whose midpoints move by
/// seconds. That one is arithmetic on a baseline too short to support it, and it does shrink on a
/// resident agent with a baseline of minutes, which the product has from 2026-09-09: measured on an
/// ordinary desktop that day, 24.3 to 25.0 ms of half width through an agent at thirty-six minutes
/// of uptime against 39.3 to 45.6 ms from this path twelve minutes earlier. What it does not do is
/// change the case this constant is for. A build runner is a machine that has existed for ninety
/// seconds, so there is nothing for an agent to be resident on, and the ceiling here still has to
/// cover a model built from nothing.
///
/// Thirty leaves room for a slower path and still refuses a receipt that says nothing. It is a
/// ceiling and not a target: what a particular run actually achieved is the interval in the receipt,
/// and the shipped agent policy, for a machine with real time sources, is 250 milliseconds.
const CI_MAX_BOUND_WIDTH: Nanos = 30 * NANOS_PER_SEC;

/// How many times to poll before reading, when nothing else is said.
///
/// Sixteen, and it was four until 2026-09-08. Four was chosen on the arithmetic of the fit, three
/// points to estimate a frequency and a fourth to measure the fit by, and nobody measured what it
/// cost. Two passes at each of nine settings, taken here at 12:54 and 12:56 on 2026-09-08 against
/// the three public Roughtime servers with `--no-evidence`:
///
/// | rounds | width | the model's own residual | wall |
/// |---|---|---|---|
/// | 1 | 6.155 s, 6.154 s | 0 | under a second |
/// | 2 | 6.150 s, 6.151 s | 0 | 1 s |
/// | 3 | 17.378 s, 17.383 s | 5.613 s | 1 to 2 s |
/// | 4 | 16.433 s, 13.763 s | 5.143 s | 2 s |
/// | 8 | 14.092 s, 14.104 s | 3.9 s | 3 s |
/// | 12 | 12.807 s, 12.821 s | 3.330 s | 5 s |
/// | 16 | 12.021 s, 12.019 s | 2.936 s | 6 s |
/// | 24 | 11.020 s, 11.008 s | 2.433 s | 9 to 10 s |
/// | 32 | 10.398 s, 10.397 s | 2.125 s | 13 s |
///
/// The whole of the movement is `model_residual`, the standard error of the fitted offset doubled
/// by the coverage factor. Below `Policy::regression_min_points`, which is three, no line is fitted
/// and the scatter of the measurements is never measured, so it never enters the width. That is why
/// one round looks best and is not: it is narrower because less was measured, which is the
/// overclaim this product exists to refuse.
///
/// Four is close to the worst setting on that curve, and it is unstable there: the two passes came
/// out 2.67 s apart, where sixteen agreed to 3 ms. Sixteen is the knee. It costs about four seconds
/// more of a build than four rounds and takes 4.4 s off the interval, and past it each further
/// second of build time buys less than a quarter of a second of width. `crates/cli/tests/
/// rounds_and_the_help.rs` holds the shape and the shipped help text together.
const DEFAULT_ROUNDS: usize = 16;

/// How long to leave between polls, when nothing else is said.
///
/// None, and that is a measurement rather than an omission.
///
/// The expectation was that spreading the polls would shrink the bound: the regression fits a line
/// through the synchronisations and carries its own standard error into the width, and four points
/// taken inside two seconds are four points at the same instant as far as a line through them is
/// concerned. Measured from this machine on 2026-09-08 against the three public Roughtime servers,
/// it barely moves. Four rounds with no gap took 2 s and gave 16.399 s of width with a 5.126 s
/// residual. Four rounds three seconds apart took 12 s and gave 16.435 s. Eight rounds eight seconds
/// apart took 60 s and gave 14.078 s, with the residual down to 3.966 s.
///
/// So a minute of a build's time buys about two seconds off a fourteen second interval. Waiting a
/// little is not worth it, and the shape of those three readings says why: the residual does come
/// down as the baseline lengthens, from 5.126 s over two seconds to 3.966 s over a minute, so it is
/// a fitting artefact and not only the servers. A minute is simply nowhere near long enough. The
/// option is here for somebody who wants to try it on a different path, and the thing that actually
/// moves this number is a baseline of minutes rather than seconds, which needs an agent that stays
/// running. `timewitness agent` is that agent from 2026-09-09 and it took about a fifth off the
/// width on an ordinary desktop. It is no use to a build runner, which has been alive for ninety
/// seconds when the workflow reaches this code.
///
/// More rounds with no gap is the cheaper half of the same effect, and `DEFAULT_ROUNDS` carries the
/// curve. Sixteen rounds back to back took 6 s and gave 12.02 s, against the 14.078 s that eight
/// rounds a minute apart bought.
const DEFAULT_GAP_SECONDS: u64 = 0;

/// How far a beacon round may sit from where the model thinks the present is.
///
/// Two minutes. A drand relay can lag by a few rounds of three seconds, and a value further out than
/// this is not a lagging relay, it is a different moment.
const BEACON_TOLERANCE: Nanos = 120 * NANOS_PER_SEC;

/// A reading and its bound, before anything about the subject is put in it.
///
/// The two ways this command can get one meet here, and the code below the join cannot tell which it
/// was handed. That is deliberate: one receipt builder, one evidence step, one signature, so the two
/// paths cannot drift into signing different things.
struct Reading {
    /// A receipt with the reading and the bound in it, and the payload, the sequence, the chain link
    /// and the key still to be filled in.
    carrier: Receipt,
    /// What the run should say about how the reading was come by.
    notes: Vec<String>,
}

/// Run it.
pub fn run(args: &Args) -> Outcome {
    // Before anything is read, hashed or written. `key_from` makes a private key where there is not
    // one already, so a refusal after it would leave a key on disk for a run that never happened.
    if args.value("--agent").is_some() {
        if let Err(text) = nothing_from_the_other_path(args) {
            return fail(&text);
        }
        // The same parse `from_the_agent` runs, run here only to refuse early. It is called twice
        // rather than threaded through, because the alternative is a badly written `--max-width`
        // turned down after `key_from` has already put a private key on disk for a run that never
        // happened, which is the fault the block above exists to avoid.
        if let Err(text) = a_ceiling_of_our_own(args) {
            return fail(&text);
        }
    }

    let subject_path = match args.required("--subject") {
        Ok(path) => path,
        Err(e) => return fail(&e.0),
    };
    let out_path = match args.required("--out") {
        Ok(path) => path,
        Err(e) => return fail(&e.0),
    };

    let subject = match fs::read(subject_path) {
        Ok(bytes) => bytes,
        Err(e) => return fail(&format!("{subject_path} could not be read: {e}")),
    };
    let payload = sha256_payload(&subject);
    let subject_hash: [u8; 32] = match payload.hash.clone().try_into() {
        Ok(hash) => hash,
        Err(_) => return fail("a sha-256 hash is 32 bytes"),
    };

    let key = match key_from(args) {
        Ok(key) => key,
        Err(text) => return fail(&text),
    };

    let sequence = match args.number("--sequence") {
        Ok(Some(n)) => u64::try_from(n).unwrap_or(1),
        Ok(None) => 1,
        Err(e) => return fail(&e.0),
    };
    let previous = match args.value("--previous") {
        None => None,
        Some(path) => match fs::read(path) {
            Ok(bytes) => Some(chain_link(&bytes)),
            Err(e) => return fail(&format!("{path} could not be read: {e}")),
        },
    };

    let Reading {
        carrier: mut receipt,
        mut notes,
    } = match args.value("--agent") {
        Some(endpoint_path) => match from_the_agent(args, endpoint_path) {
            Ok(reading) => reading,
            Err(text) => return fail(&text),
        },
        None => match from_a_model_of_our_own(args) {
            Ok(reading) => reading,
            Err(text) => return fail(&text),
        },
    };

    // What the carrier was holding a place for. The agent never sees any of it, and the one-shot
    // path fills in the same four fields at the same point, so a receipt is assembled once.
    receipt.sequence = sequence;
    receipt.chain_previous = previous;
    receipt.payload = payload;
    receipt.agent_public_key = key.public_key_bytes();

    if !args.flag("--no-evidence") {
        let (evidence, gathered) = gather(&subject_hash, receipt.utc_estimate);
        receipt.evidence = evidence;
        notes.extend(gathered);
    }

    let signed = match key.sign(&receipt) {
        Ok(bytes) => bytes,
        Err(e) => return fail(&format!("the receipt would not sign: {e}")),
    };
    if let Err(e) = fs::write(out_path, &signed) {
        return fail(&format!("{out_path} could not be written: {e}"));
    }

    let mut text = render::stamped(
        out_path,
        signed.len(),
        receipt.width(),
        (receipt.claim.sources_offered, receipt.claim.sources_kept),
        receipt.evidence.len(),
    );
    for note in notes {
        text.push_str(&format!("  {note}\n"));
    }
    text.push_str(&format!(
        "  The agent's public key is {}. Nothing links it to anybody yet; there is no public key\n  log, and the verifier says so rather than implying otherwise.\n",
        render::hex(&receipt.agent_public_key)
    ));

    Outcome { text, code: 0 }
}

/// Refuse the options that belong to the other path, rather than dropping them.
///
/// `--rounds` and `--gap` describe polling this run is not doing. An option silently ignored is how
/// somebody comes to believe the number they gave was applied, which is the same fault as reporting
/// held for a check that was never run.
///
/// **`--max-width` was on this list until 2026-09-10.** The reasoning written here was that the
/// ceiling is the agent's own and is set where the agent is started, which was true and was the
/// defect: a caller whose only ceiling is the answering party's has no ceiling. On this path the
/// option means the widest interval this caller will accept, which is a different sentence from the
/// one it means on the other path and is the sentence the help text now gives it.
/// The widest interval this run will accept from an agent.
///
/// The default is the shipped policy's own ceiling rather than the answer's, which is the whole
/// point: an answering party that states an hour does not thereby get to hand this run an hour.
/// Somebody who deliberately started an agent wider says so here as well, which is one more thing
/// to type and is a ceiling somebody chose rather than one somebody was given.
fn a_ceiling_of_our_own(args: &Args) -> Result<Nanos, String> {
    match args.number("--max-width") {
        Ok(Some(width)) if width > 0 => Ok(width),
        Ok(Some(_)) => Err("--max-width is a positive number of nanoseconds".into()),
        Ok(None) => Ok(Policy::default().max_bound_width),
        Err(e) => Err(e.0),
    }
}

fn nothing_from_the_other_path(args: &Args) -> Result<(), String> {
    for option in ["--rounds", "--gap"] {
        if args.value(option).is_some() {
            return Err(format!(
                "{option} describes polling, and with --agent the polling is the agent's. Set it \
                 on `timewitness agent` instead"
            ));
        }
    }
    Ok(())
}

/// Ask a resident agent for a reading.
///
/// The whole of the network work has already happened, somewhere else, on a schedule. What is left
/// here is a loopback round trip, and the caller pays for that round trip by widening the interval
/// on both sides, which `timewitness_agent::crossing` carries the argument for.
///
/// The options that belong to the other path are refused before this, in `run`, so that nothing has
/// been written by the time one of them is turned down.
///
/// **What this run brings of its own.** Whoever writes the endpoint file chooses which process
/// answers, so the answer is somebody else's word about the time and about how wide they were
/// prepared to be. Two things go into `WhatTheCallerKnows` against that: this machine's own clock,
/// read here rather than in the crate so a test can hand over a machine, and the widest interval
/// this run will accept. Neither is a proof and the crate's own documentation says so at length. On
/// the default path the thing that actually catches a forged reading is the third-party corridor
/// gathered afterwards, and this is what the `--no-evidence` path has instead of one.
fn from_the_agent(args: &Args, endpoint_path: &str) -> Result<Reading, String> {
    let endpoint = Endpoint::read(Path::new(endpoint_path)).map_err(|e| format!("{e}"))?;

    let ceiling = a_ceiling_of_our_own(args)?;
    // Read as late as possible and no later. The comparison it feeds allows five minutes, so the
    // milliseconds between here and the answer are not what decides anything; what matters is that
    // it is this machine's reading and not one that arrived in the answer.
    let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return Err(
            "this machine's clock is before 1970, which is not something to build on".into(),
        );
    };
    let Ok(nanos) = i128::try_from(wall.as_nanos()) else {
        return Err(
            "this machine's clock is further from 1970 than the arithmetic here reaches".into(),
        );
    };
    let knows = WhatTheCallerKnows {
        local_wall: UnixNanos(nanos),
        ceiling,
    };

    let clock = SystemMonotonic::new();
    let crossed = ask(&endpoint, &clock, knows).map_err(|e| format!("{e}"))?;

    let age = crossed.carrier.claim.since_last_sync;
    let apart = crossed.carrier.utc_estimate.as_nanos() - knows.local_wall.as_nanos();
    let notes = vec![
        format!(
            "the reading came from the agent at {}, whose model last heard from a source {:.3} s \
             ago. Nothing was asked over the network to take it",
            endpoint.address,
            age as f64 / NANOS_PER_SEC as f64
        ),
        format!(
            "asking it took {:.3} ms, and the interval was widened by that on both sides, because \
             the reading was taken somewhere inside the wait and this end cannot say where",
            crossed.round_trip as f64 / 1_000_000.0
        ),
        format!(
            "the answer sits {:.3} s from this machine's own clock, which is inside the {:.0} s \
             this run refuses past. That is a sanity check against a wild answer and it is not \
             evidence of anything: the clock it rests on is the one this product exists because \
             nobody should trust",
            apart as f64 / NANOS_PER_SEC as f64,
            WILDNESS as f64 / NANOS_PER_SEC as f64
        ),
    ];
    Ok(Reading {
        carrier: crossed.carrier,
        notes,
    })
}

/// Build a model here, poll it, read it once and throw it away.
///
/// This is what runs under continuous integration and it is what the whole of the module comment
/// above describes. The residual it carries is the price of a baseline measured in seconds.
#[allow(clippy::too_many_lines)]
fn from_a_model_of_our_own(args: &Args) -> Result<Reading, String> {
    let rounds = match args.number("--rounds") {
        Ok(Some(n)) if n >= 1 => usize::try_from(n).unwrap_or(DEFAULT_ROUNDS),
        Ok(Some(_)) => return Err("--rounds is at least one".into()),
        Ok(None) => DEFAULT_ROUNDS,
        Err(e) => return Err(e.0),
    };

    let max_bound_width = match args.number("--max-width") {
        Ok(Some(width)) if width > 0 => width,
        Ok(Some(_)) => return Err("--max-width is a positive number of nanoseconds".into()),
        Ok(None) => CI_MAX_BOUND_WIDTH,
        Err(e) => return Err(e.0),
    };
    let policy = Policy {
        max_bound_width,
        ..Policy::default()
    };

    // The system clock, read once, only to anchor the model. Everything after this is the monotonic
    // counter, and the model reports against the anchor rather than re-reading a clock something
    // else may be steering underneath it.
    let Ok(wall) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return Err(
            "this machine's clock is before 1970, which is not something to build on".into(),
        );
    };
    let clock = Arc::new(SystemMonotonic::new());
    let Ok(nanos) = i128::try_from(wall.as_nanos()) else {
        return Err(
            "this machine's clock is further from 1970 than the arithmetic here reaches".into(),
        );
    };
    let anchor = UnixNanos(nanos);
    let mut model = ClockModel::new(policy, Box::new(Handle(clock.clone())), anchor, 0);

    // What disciplines the clock, which is not the same list as what produces evidence. Every
    // Roughtime server is in both, because its answer is signed; every NTP and NTS server is in this
    // one only, because neither answer is. NTS authenticates and a stranger still cannot check it,
    // since the key that authenticated it is one this machine also holds. The two lists are built
    // separately rather than filtered out of one, so nothing downstream has to remember which kind
    // it is holding.
    let mut disciplining: Vec<Box<dyn TimeSource>> = Vec::new();
    for server in RoughtimeServer::published() {
        disciplining.push(Box::new(RoughtimeClient::new(server)));
    }
    for server in NtpServer::published() {
        disciplining.push(Box::new(NtpClient::new(server)));
    }
    for server in NtsServer::published() {
        disciplining.push(Box::new(NtsClient::new(server)));
    }
    let polls_per_round = disciplining.len();

    let gap = match args.number("--gap") {
        Ok(Some(n)) if n >= 0 => u64::try_from(n).unwrap_or(DEFAULT_GAP_SECONDS),
        Ok(Some(_)) => return Err("--gap is not negative".into()),
        Ok(None) => DEFAULT_GAP_SECONDS,
        Err(e) => return Err(e.0),
    };

    // What the model cannot see for itself: the machine going to sleep, and another time service
    // moving the clock underneath it. Both are read from the operating system's own counters and
    // both drive the model's ordinary refusal rather than a path of their own.
    let mut watch = EnvironmentWatch::new();
    watch.look(clock.now());

    let mut notes = Vec::new();
    let mut answered = 0usize;
    for round in 0..rounds {
        if round > 0 && gap > 0 {
            std::thread::sleep(std::time::Duration::from_secs(gap));
        }
        note_interruptions(&mut model, watch.look(clock.now()), &mut notes);
        for source in &mut disciplining {
            // Thirty-two random bytes, whatever the source does with them. Roughtime signs over all
            // of them and an NTP server echoes the first eight, so the same call serves both and
            // neither is handed a challenge it did not get to choose.
            let nonce = RoughtimeClient::random_nonce().map_err(|e| format!("{e}"))?;
            match source.poll(clock.now(), &nonce) {
                Ok(exchange) => {
                    model.ingest(&exchange);
                    answered += 1;
                }
                Err(e) => {
                    if round == 0 {
                        notes.push(format!("{} did not answer: {e}", source.id()));
                    }
                }
            }
        }
        let validity = model.synchronise();
        if round + 1 == rounds && !validity.is_valid() {
            return Err(format!(
                "the model will not answer: {validity:?}. {} of {} polls came back. A receipt is \
                 not issued from a model that cannot support one",
                answered,
                rounds * polls_per_round
            ));
        }
    }

    // One last look before the reading. Anything that happened to this machine's clock between the
    // final synchronisation and the stamp is exactly what a receipt must not be issued over.
    note_interruptions(&mut model, watch.look(clock.now()), &mut notes);

    let stamp = model.read().map_err(|refusal| {
        format!(
            "no receipt: {refusal}. This is the refusal working rather than a fault. A wider \
             interval says something true and a narrow wrong one does not"
        )
    })?;

    // Measure and vouch, which on this machine means the system clock is left exactly as it was
    // found. Said out loud in the run's own output because the alternative, an agent that quietly
    // fights whatever else is disciplining the clock, is what this default exists to avoid.
    let mut discipline = ShadowDiscipline;
    match discipline.apply(stamp.frequency_ppm.unwrap_or(0.0)) {
        // Parts per million is a rate and not a distance, so this says running fast or slow rather
        // than "from UTC", which the line used to say and which invited a reader to take it as an
        // offset. Where the model would not stand behind a rate it is not printed at all: over a
        // run this short the fit measures the servers' jitter divided by two seconds, and a figure
        // in the thousands on the first line of the output is the first thing a hostile reviewer
        // reads.
        Ok(Applied::Vouched) => notes.push(match stamp.frequency_ppm {
            Some(ppm) => format!(
                "the system clock was measured and left alone, running at {ppm:.3} parts per \
                 million against the model"
            ),
            None => {
                "the system clock was measured and left alone. No rate is reported: this run's \
                     baseline is too short to tell one oscillator rate from another, and the whole \
                     of what the fit allowed is in the width instead"
                    .to_string()
            }
        }),
        Ok(Applied::Rate {
            requested_ppm,
            applied_ppm,
        }) => notes.push(format!(
            "the system clock's rate was changed by {applied_ppm:.3} parts per million, having \
             asked for {requested_ppm:.3}"
        )),
        Err(e) => notes.push(format!("the clock was not disciplined: {e}")),
    }

    Ok(Reading {
        carrier: carrier(
            &stamp,
            PolicyRecord {
                max_bound_width: policy.max_bound_width,
                min_sources: policy.min_sources as u32,
                min_operators: Some(policy.min_operators as u32),
                max_holdover: Some(policy.max_holdover),
            },
        ),
        notes,
    })
}

/// One attestation in each role, or as many of the three as answered.
///
/// `reading` is where the receipt says the moment was, and it is used to pick the beacon round
/// nearest that moment. Nothing else here depends on how the reading was arrived at, which is why
/// this takes the one value rather than the whole stamp.
fn gather(subject_hash: &[u8; 32], reading: UnixNanos) -> (Vec<Evidence>, Vec<String>) {
    let mut evidence = Vec::new();
    let mut notes = Vec::new();
    let clock = SystemMonotonic::new();

    // The corridor. The nonce is derived from the hash of what is being stamped and a fresh salt, so
    // the response is about this subject and could not have been fetched in advance.
    for server in RoughtimeServer::published() {
        let client = RoughtimeClient::new(server);
        match client.poll_for_subject(clock.now(), subject_hash) {
            Ok(exchange) => {
                if let Some(attestation) = exchange.attestation {
                    evidence.push(entry(
                        Role::AuthenticatedUtcCorridor,
                        "roughtime",
                        &attestation,
                        client.server().name.clone(),
                    ));
                    break;
                }
            }
            Err(e) => notes.push(format!("no corridor from {}: {e}", client.server().name)),
        }
    }
    if evidence.is_empty() {
        notes.push(
            "no authenticated corridor, so this receipt has nothing outside it supporting the \
             bound and says so"
                .to_string(),
        );
    }

    // Not earlier than.
    let beacon = DrandClient::quicknet();
    match beacon.latest_near(reading, BEACON_TOLERANCE) {
        Ok(attestation) => evidence.push(entry(
            Role::NotEarlierThan,
            "drand",
            &attestation,
            beacon.chain().name.to_string(),
        )),
        Err(e) => notes.push(format!("no freshness beacon: {e}")),
    }

    // Not later than.
    let mut witnessed = false;
    for authority in published_authorities() {
        let name = authority.name.clone();
        let client = TimestampClient::new(authority);
        match client.witness(subject_hash) {
            Ok(attestation) => {
                // What the authority says about ordering its own tokens goes beside its name. The
                // product's claim is unbroken order, so a reader of the receipt should not have to
                // parse the token to find out whether the authority put its name to any of it.
                let detail = match client.orders_by_stated_time(&attestation.blob) {
                    Ok(true) => format!(
                        "{name}, which states its own tokens are ordered by the times they state"
                    ),
                    _ => format!(
                        "{name}, which makes no claim that the times it states order its own tokens"
                    ),
                };
                evidence.push(entry(Role::NotLaterThan, "rfc3161", &attestation, detail));
                witnessed = true;
                break;
            }
            Err(e) => notes.push(format!("no witness from {name}: {e}")),
        }
    }
    if !witnessed {
        notes.push(
            "no final witness, so nothing outside says this is not newer than it claims".into(),
        );
    }

    (evidence, notes)
}

fn entry(role: Role, scheme: &str, attestation: &Attestation, detail: String) -> Evidence {
    Evidence {
        role,
        scheme: Scheme::new(scheme),
        at: attestation.at,
        radius: attestation.radius,
        blob: attestation.blob.clone(),
        nonce: if attestation.nonce.is_empty() {
            None
        } else {
            Some(attestation.nonce.clone())
        },
        detail: Some(detail),
    }
}

/// The signing key, made where there is not one already.
///
/// A build runner has no key and nobody to ask for one, and a step that needs a secret configured is
/// not a one-line install. So a key is generated where the file is absent, and the receipt says
/// what that buys: the receipt proves that whoever signed it held that key, and until a public log of
/// agent keys exists it proves nothing about who that was. The verifier reports exactly that.
///
/// The file this writes is a private key and not a cache. It is the whole of what an agent is, so
/// deleting it loses nothing that can be recovered and copying it hands somebody the ability to sign
/// as this agent.
fn key_from(args: &Args) -> Result<AgentKey, String> {
    let path = args.required("--key").map_err(|e| e.0)?;
    if let Ok(bytes) = fs::read(path) {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{path} is not a 32 byte seed"))?;
        return Ok(AgentKey::from_seed(&seed));
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| format!("this machine would not give us random bytes: {e}"))?;
    write_private(Path::new(path), &seed)
        .map_err(|e| format!("{path} could not be written: {e}"))?;
    Ok(AgentKey::from_seed(&seed))
}

/// Write a private key, readable and writable by its owner and nobody else.
///
/// The permission goes on at creation rather than after the write, because a `chmod` after the fact
/// leaves a window with the bytes on disk and the world able to read them. On a platform with no
/// mode bits this is an ordinary create and the file inherits whatever the directory gives it, which
/// is stated here rather than left to be discovered.
///
/// `create_new` rather than `create`. Reaching here means the file could not be read, which is
/// usually because it is not there and could be because somebody else is writing it; either way,
/// writing over a key would orphan every receipt already signed with the old one.
fn write_private(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(seed)?;
    file.sync_all()
}

fn fail(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 1,
    }
}

/// The monotonic counter, shared between the model and the callers that stamp a round trip.
struct Handle(Arc<SystemMonotonic>);

impl MonotonicClock for Handle {
    fn now(&self) -> timewitness_core::MonotonicNanos {
        self.0.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_this_raises_for_a_build_runner_is_wider_than_the_shipped_one_and_says_why() {
        // If these ever cross, a receipt from CI would be refused by its own policy rather than
        // carrying an honest wide bound, and the failure would look like a network fault.
        assert!(
            CI_MAX_BOUND_WIDTH > Policy::default().max_bound_width,
            "a build runner cannot reach the shipped ceiling and has to raise its own"
        );
        // And it stays well under the width at which a verifier stops believing an interval at
        // all, so a receipt from a build runner is read rather than refused on its width.
        assert!(CI_MAX_BOUND_WIDTH < timewitness_verify::Floor::default().max_interval_width / 100);
    }

    /// A folder of this test's own, in the machine's temporary space, removed at the end.
    fn a_scratch_folder(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("timewitness-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    #[cfg_attr(
        not(unix),
        ignore = "this platform has no mode bits, so the permission cannot be read back here. CI is Linux and does read it."
    )]
    fn the_generated_key_is_readable_only_by_its_owner() {
        let dir = a_scratch_folder("key-mode");
        let path = dir.join("agent.key");

        let mut seed = [0u8; 32];
        seed[0] = 7;
        write_private(&path, &seed).expect("a key in a folder that was not there");

        assert_eq!(fs::read(&path).unwrap().len(), 32);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let key = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(key, 0o600, "the key is {key:o} and should be 600");
            let folder = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(folder, 0o700, "the folder is {folder:o} and should be 700");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_key_already_there_is_never_written_over() {
        // Writing over one would orphan every receipt already signed with it, and there is no way
        // back from that: the old key is the only thing that could have signed them.
        let dir = a_scratch_folder("key-clobber");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent.key");

        write_private(&path, &[1u8; 32]).expect("the first one");
        let second = write_private(&path, &[2u8; 32]);

        assert!(second.is_err(), "the second write should have been refused");
        assert_eq!(fs::read(&path).unwrap(), vec![1u8; 32]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stamp_without_a_subject_refuses_before_anything_goes_out() {
        let args = crate::args::parse(&["stamp".to_string()]).unwrap();
        let outcome = run(&args);
        assert_eq!(outcome.code, 1);
        assert!(outcome.text.contains("--subject"), "{}", outcome.text);
    }
}
