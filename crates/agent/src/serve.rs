//! The loop: poll on a schedule, answer whenever asked, and never let one wait behind the other.
//!
//! One lock, and the shape is set by a single fact. A poll is network work measured in seconds and a
//! reading is arithmetic over values already in memory. Holding the model while polling would put
//! every stamp behind the slowest source on the machine's network path, so the polling happens
//! outside the lock and only the selection round that follows it goes inside.
//!
//! The lock is the one thing a resident agent adds to the read path that a one-shot command did not
//! have. It is held for the length of a selection round or a reading, which is arithmetic over a few
//! dozen values, and the caller is already paying for the whole crossing in the bound. Nothing here
//! is a hot path: a build stamps once.
//!
//! ## Why a caller gets a thread, from 2026-09-10
//!
//! This said until then that a second thread per caller would be a service where a boundary was
//! asked for, and that one accepting thread was enough because the work behind each caller is
//! microseconds. The work is microseconds. The wait is not, and the wait is what somebody else
//! supplies: [`answer`] reads a fixed number of token bytes and a caller that connects and sends
//! nothing holds that read for the whole of [`PATIENCE`]. On one accepting thread, two such sockets
//! stopped the machine issuing receipts, and a legitimate ask behind twenty of them took 40 s.
//! Measured 2026-09-10 on an ordinary desktop.
//!
//! So the accepting thread accepts and does nothing else. Each caller gets a short-lived thread that
//! reads the token, answers and exits, and the model stays behind the one mutex it was already
//! behind. Threads in flight are capped at [`CALLERS_AT_ONCE`] and a caller past the cap is refused
//! rather than queued, so the cost of holding the agent up is threads rather than seconds and a
//! refusal says so rather than a silence. The cap is a refusal and it is on the cannot-prove list
//! with the rest of them.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use timewitness_clock::MonotonicClock;
use timewitness_sources::{Exchange, TimeSource};

use crate::resident::Resident;
use crate::wire::{carrier, encode_reading, encode_refusal, tokens_match, TOKEN_BYTES};

/// How often the agent asks the sources, and how hard it works to be able to answer at all.
#[derive(Clone, Copy, Debug)]
pub struct Cadence {
    /// How many rounds to run back to back before settling into the schedule.
    ///
    /// Four. The model needs three sources for a majority and three points before it fits a line at
    /// all, so an agent that started on the schedule below would have nothing to fit for a minute
    /// and a half. Four rounds back to back take a few seconds and buy a fit that exists.
    ///
    /// **A fit that exists is not a fit worth signing, and this comment claimed it was until
    /// 2026-09-10.** It said the agent is useful from then on. Measured, it is not: the four rounds
    /// are a second apart, so the line is fitted across a baseline of about three seconds and then
    /// extrapolated across the thirty-two second gap below, and the residual that comes out of that
    /// is far past the shipped ceiling. On an ordinary desktop the agent refuses nearly every
    /// reading for its first two to three minutes.
    ///
    /// Measured 2026-09-10 on an ordinary Windows desktop against the shipped nine servers at a
    /// thirty-two second interval and a 250 ms ceiling, one reading every five seconds for twelve
    /// minutes, twice: the last refusal was at 166 s of uptime on the run at 14:51 and at 168 s on
    /// the run at 15:04, with 25 and 24 of the first 34 readings refused. **Do not read a first
    /// signature as the agent having settled.** The second run signed at 6 s, straight after these
    /// rounds and before the first full gap had to be extrapolated across, and then refused every
    /// reading from 11 s to 69 s. The first run refused at 0 s and 5 s and did not sign until 73 s.
    /// The whole curve is written down for a reader in `docs/what-timewitness-cannot-prove.md`
    /// rather than only here, because a refusal nobody was told about is a surprise, and every
    /// claim this product makes ships beside what it cannot prove to stop those.
    pub settling_rounds: usize,
    /// How long to leave between settling rounds.
    pub settling_gap: Duration,
    /// How long to leave between rounds once it has settled.
    ///
    /// Thirty-two seconds, and the number is a trade rather than a preference.
    ///
    /// Longer costs width. A reading taken just before the next round is extrapolated over the whole
    /// gap, and the model charges for that at the frequency floor plus how far the rate may have
    /// moved, which is a rate per second, so the cost grows with the square of the gap. Fifteen
    /// parts per million plus one per second, over the gap: 0.5 ms at sixteen seconds, 1.5 ms at
    /// thirty-two, 5.1 ms at sixty-four. Against a residual this whole crate exists to bring down
    /// from 36.4 ms, five milliseconds of it back is not free.
    ///
    /// Shorter costs somebody else's servers. The sources are three public NTP servers and three
    /// public Roughtime servers, run by other people at their own expense. RFC 5905 sets sixteen
    /// seconds as the shortest an NTP client may poll at, so thirty-two is one step inside what the
    /// protocol permits and each server sees one packet in that time.
    ///
    /// A deployment with its own servers can set whatever it likes. This is the default for a
    /// machine using the published list, and the polite half of the trade decided it.
    pub interval: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            settling_rounds: 4,
            settling_gap: Duration::from_millis(250),
            interval: Duration::from_secs(32),
        }
    }
}

/// Somewhere for the agent to say what it is doing.
pub type Reporter = Arc<dyn Fn(String) + Send + Sync>;

/// How many callers this agent answers at once.
///
/// Sixty-four, and the number is a trade between two ways of being unavailable rather than a limit
/// anybody is expected to reach. A machine stamps a handful of times a build, so sixty-four at once
/// is far past any honest load, and the whole reason for a number at all is the dishonest one:
/// without a cap, a caller that connects and never speaks buys a thread at the cost of a socket, and
/// enough of those is a thread per socket.
///
/// **Say plainly what the cap does and does not buy, because a number like this reads as a
/// solution.** It converts a cheap, permanent outage into an expensive, temporary one, and that is
/// all it does. Before it, two idle sockets held the agent for as long as somebody cared to keep
/// them. With it, somebody wanting the same outage has to hold sixty-four connections and open a
/// fresh one every time [`TOKEN_PATIENCE`] runs out on one, which is well over a hundred connections
/// a second; the agent stays up throughout, answers the moment a slot frees, and refuses in words
/// rather than going quiet. Nobody should read it as making the agent proof against somebody who
/// already runs code on this machine. See [`crate::wire`] for what that person can actually do,
/// which is worse than this and is not fixed by a number.
///
/// Sixty-four rather than something tighter because the cap has to sit above the load a test and a
/// build can honestly produce. Twenty idle sockets must not stop a legitimate ask, and a cap of
/// sixteen would have met that with a refusal, which is a different behaviour wearing the same word.
pub const CALLERS_AT_ONCE: usize = 64;

/// Run the agent until it is stopped.
///
/// This never returns of its own accord. The poll loop runs on a thread of its own and this one
/// accepts connections.
pub fn serve(
    resident: Resident,
    sources: Vec<Box<dyn TimeSource + Send>>,
    token: [u8; TOKEN_BYTES],
    listener: &TcpListener,
    cadence: Cadence,
    report: Reporter,
) {
    let clock = resident.clock();
    let shared = Arc::new(Mutex::new(resident));

    let polling = shared.clone();
    let polling_report = report.clone();
    std::thread::spawn(move || {
        poll_forever(&polling, sources, &*clock, cadence, &polling_report);
    });

    answer_callers(&shared, &token, listener, &report);
}

/// Accept callers and hand each one to a thread of its own, until the listener stops.
///
/// Its own function because it is the half of [`serve`] a test can drive. A test that wanted this
/// loop had to start a polling thread with it, which meant handing over real sources or watching a
/// model be invalidated by empty rounds; the test of idle sockets needed the accept loop and nothing
/// else.
pub fn answer_callers(
    shared: &Arc<Mutex<Resident>>,
    token: &[u8; TOKEN_BYTES],
    listener: &TcpListener,
    report: &Reporter,
) {
    let in_flight = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                report(format!("a caller could not be accepted: {e}"));
                continue;
            }
        };

        // Claimed before the thread starts, so the count cannot be beaten by two accepts racing to
        // spawn. A claim that turns out to be past the cap is given straight back.
        if in_flight.fetch_add(1, Ordering::SeqCst) >= CALLERS_AT_ONCE {
            in_flight.fetch_sub(1, Ordering::SeqCst);
            turn_away(stream, report);
            continue;
        }

        let model = shared.clone();
        let token = *token;
        let theirs = report.clone();
        let held = in_flight.clone();
        let spawned = std::thread::Builder::new()
            .name("timewitness-caller".into())
            .spawn(move || {
                answer(&model, &token, stream, &theirs);
                held.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            // A machine that will not give this a thread is a machine in trouble, and the honest
            // answer is to say so and carry on accepting rather than to stop the agent.
            in_flight.fetch_sub(1, Ordering::SeqCst);
            report(format!(
                "this machine would not give us a thread for a caller: {e}"
            ));
        }
    }
}

/// Tell a caller past the cap why, rather than dropping it or making it wait.
///
/// Refusing rather than queueing is the point of the cap. A queue behind a full cap is the same
/// unavailability the cap exists to stop, moved somewhere a caller cannot see it, and a caller that
/// is told can retry, report it or fall back to polling for itself.
fn turn_away(mut stream: TcpStream, report: &Reporter) {
    // This one runs on the accepting thread, so every wait in it is a wait everybody else is behind.
    // Fifty milliseconds is a loopback read of thirty-two bytes the caller sent before this socket
    // was even accepted, which is why it can be this short here and cannot be this short in
    // `answer`.
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .ok();
    stream.set_write_timeout(Some(PATIENCE)).ok();
    stream.set_nodelay(true).ok();

    // Take what the caller already sent before turning it away. A socket closed with unread bytes
    // still in it is reset rather than ended, and a reset throws away whatever was on its way out,
    // so the caller is told the agent broke off mid-answer. That is the one thing that did not
    // happen, and telling somebody it did sends them to restart a healthy agent.
    let mut sent = [0u8; TOKEN_BYTES];
    let _ = stream.read(&mut sent);

    let refusal = encode_refusal(&format!(
        "this agent is already answering {CALLERS_AT_ONCE} callers and will not queue behind them. \
         Ask again in a moment"
    ));
    if stream.write_all(&refusal).is_err() {
        report("a caller past the cap went away before the refusal did".into());
    }
    let _ = stream.flush();
}

/// Ask every source, then hand the round to the model.
///
/// The polling is outside the lock and the selection round is inside it. That is the whole reason
/// this is a function rather than four lines in `serve`.
///
/// Public for the same reason [`answer_callers`] is: it is the half of [`serve`] that disciplines
/// the model, and something other than the loopback agent now wants it. A Roughtime server of ours
/// has to state its own uncertainty rather than assume it, so the process running one holds a
/// [`Resident`] disciplined exactly as the agent's is and reads a bound off it per request. Two
/// copies of this loop would be two answers to how often our own servers poll somebody else's.
pub fn poll_forever(
    shared: &Arc<Mutex<Resident>>,
    mut sources: Vec<Box<dyn TimeSource + Send>>,
    clock: &dyn MonotonicClock,
    cadence: Cadence,
    report: &Reporter,
) {
    let mut round = 0usize;
    loop {
        let mut exchanges = Vec::with_capacity(sources.len());
        for source in &mut sources {
            // Thirty-two random bytes, whatever the source does with them. A Roughtime server signs
            // over all of them and an NTP server echoes the first eight, so the same call serves
            // both and neither is handed a challenge it did not get to choose.
            let mut nonce = [0u8; 32];
            if getrandom::getrandom(&mut nonce).is_err() {
                report(
                    "this machine would not give us random bytes, so the round was skipped".into(),
                );
                break;
            }
            match source.poll(clock.now(), &nonce) {
                Ok(exchange) => exchanges.push(exchange),
                Err(e) => {
                    // Only on the first round. A server that is unreachable stays unreachable and a
                    // line about it every thirty-two seconds is a log nobody reads.
                    if round == 0 {
                        report(format!("{} did not answer: {e}", source.id()));
                    }
                }
            }
        }

        take(shared, &exchanges, report);

        round += 1;
        std::thread::sleep(if round < cadence.settling_rounds {
            cadence.settling_gap
        } else {
            cadence.interval
        });
    }
}

/// Hand a round to the model, under the lock and no longer.
fn take(shared: &Arc<Mutex<Resident>>, exchanges: &[Exchange], report: &Reporter) {
    match shared.lock() {
        Ok(mut resident) => {
            let validity = resident.take(exchanges);
            if !validity.is_valid() {
                report(format!("the model will not answer: {validity:?}"));
            }
        }
        // The polling thread is the only one that can leave the model half updated, and it is this
        // one, so reaching here means the answering side panicked while reading. Saying so is all
        // there is to do; the answering side refuses on the same condition.
        Err(_) => {
            report("the model was left in an unknown state and this agent will not use it".into())
        }
    }
}

/// How long to wait for a caller that connected and then went quiet.
///
/// Two seconds, matching the patience on the other side. It governs the write now rather than the
/// read: a caller that has stopped reading its own answer is the one thing left that this waits two
/// seconds for.
const PATIENCE: Duration = Duration::from_secs(2);

/// How long to wait for the thirty-two bytes of token, which is a different question.
///
/// Half a second, and it is shorter than [`PATIENCE`] on purpose. A caller writes its token straight
/// after connecting, over loopback, so the honest case is microseconds and half a second is three
/// orders of magnitude of room for a machine under load or a caller that was descheduled between the
/// connect and the write. Anything slower than that is a socket somebody opened and abandoned.
///
/// The distance between the two numbers is what a slot costs an attacker. Every socket held with
/// nothing on it occupies one of [`CALLERS_AT_ONCE`] for this long and no longer, so keeping the
/// agent full costs a hundred and twenty-eight connections a second rather than sixty-four sockets
/// opened once. It does not make the agent proof against anything; it makes the outage expensive and
/// noisy instead of free and silent.
const TOKEN_PATIENCE: Duration = Duration::from_millis(500);

/// Answer one caller.
///
/// Runs on a thread of its own from 2026-09-10, so the wait below is that caller's and nobody
/// else's. Public because a test drives both sides of the boundary in one process, which is the only
/// way to check what crosses it without starting a machine.
pub fn answer(
    shared: &Arc<Mutex<Resident>>,
    token: &[u8; TOKEN_BYTES],
    mut stream: TcpStream,
    report: &Reporter,
) {
    stream.set_read_timeout(Some(TOKEN_PATIENCE)).ok();
    stream.set_write_timeout(Some(PATIENCE)).ok();
    stream.set_nodelay(true).ok();

    let mut offered = [0u8; TOKEN_BYTES];
    if let Err(e) = stream.read_exact(&mut offered) {
        report(format!("a caller connected and sent no token: {e}"));
        return;
    }
    if !tokens_match(&offered, token) {
        let _ = stream.write_all(&encode_refusal(
            "that is not this agent's token. The endpoint file this agent wrote carries the right \
             one, and it is readable only by the account the agent runs as",
        ));
        return;
    }

    let reply = match shared.lock() {
        Ok(mut resident) => {
            let policy = resident.policy_record();
            match resident.read() {
                Ok(stamp) => encode_reading(&carrier(&stamp, policy)),
                // The refusal working rather than a fault. A wider interval says something true and
                // a narrow wrong one does not, and the last good reading is never offered.
                Err(refusal) => encode_refusal(&format!("{refusal}")),
            }
        }
        Err(_) => encode_refusal(
            "this agent's model was left in an unknown state by a thread that stopped, so it will \
             not answer",
        ),
    };

    if let Err(e) = stream.write_all(&reply) {
        report(format!("a caller went away before the answer did: {e}"));
    }
    let _ = stream.flush();
}
