//! Both sides of the boundary, in one process, with the machine's behaviour written by hand.
//!
//! A resident agent is two things and only one of them is a daemon. The other is the set of answers
//! it has to give when the machine underneath it misbehaves, and those are what this file is for:
//! they cannot be tested against a real machine, because a test cannot make a laptop sleep, so the
//! machine is handed over instead.
//!
//! The socket here is real loopback and the reply really is encoded and decoded. What is fabricated
//! is the world: the counter, the system clock, the pair of counters that says whether the machine
//! slept, and the sources' answers. Everything between the request and the reading is the shipped
//! code.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use timewitness_receipt::TakenBy;

use timewitness_agent::crossing::{ask, CrossingError, WhatTheCallerKnows, WILDNESS};
use timewitness_agent::resident::{Resident, Surroundings};
use timewitness_agent::serve::{answer, answer_callers, CALLERS_AT_ONCE};
use timewitness_agent::wire::{Endpoint, WireError, TOKEN_BYTES};
use timewitness_clock::monotonic::{MonotonicClock, SystemMonotonic, TestClock};
use timewitness_clock::Policy;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
    UnixNanos,
};
use timewitness_platform::continuous::Elapsed;
use timewitness_platform::Marks;
use timewitness_sources::Exchange;

/// Where the fabricated machine starts on UTC. A Wednesday in September 2026, and nothing turns on
/// which one.
const ANCHOR: Nanos = 1_757_000_000 * NANOS_PER_SEC;
/// Where its counter starts. Not zero, because a counter whose origin is zero hides an arithmetic
/// error that treats the origin as the epoch.
const MONO_ORIGIN: u64 = 900_000_000_000;

/// A machine whose sleeping and whose clock a test writes.
#[derive(Clone)]
struct HandMade {
    /// Total nanoseconds this machine has spent suspended since it started.
    slept: Arc<AtomicI64>,
    /// How far something else has moved the system clock, in nanoseconds.
    stepped: Arc<AtomicI64>,
}

impl HandMade {
    fn awake() -> Self {
        Self {
            slept: Arc::new(AtomicI64::new(0)),
            stepped: Arc::new(AtomicI64::new(0)),
        }
    }

    fn sleep_for(&self, nanos: Nanos) {
        self.slept.fetch_add(
            i64::try_from(nanos).expect("a test sleeps for less than an age"),
            Ordering::SeqCst,
        );
    }

    fn something_else_moves_the_clock(&self, nanos: Nanos) {
        self.stepped.fetch_add(
            i64::try_from(nanos).expect("a step a test can write down"),
            Ordering::SeqCst,
        );
    }
}

impl Surroundings for HandMade {
    fn marks(&mut self, monotonic: MonotonicNanos) -> Marks {
        // The counter the agent stamps from is the one that stops while the machine sleeps, which is
        // what the fabricated counter is, so running time is that counter and nothing else.
        let running = Nanos::from(monotonic.as_nanos() - MONO_ORIGIN);
        let slept = Nanos::from(self.slept.load(Ordering::SeqCst));
        let stepped = Nanos::from(self.stepped.load(Ordering::SeqCst));
        Marks {
            wall: UnixNanos(ANCHOR + running + slept + stepped),
            monotonic,
            elapsed: Some(Elapsed {
                including_suspend: running + slept,
                excluding_suspend: running,
            }),
        }
    }
}

/// The agent's counter, handed to both the model and the source fixtures.
struct Handle(Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// One honest source's answer, on a symmetric path.
///
/// `offset` is how far this source thinks the local clock is out, so a source with an offset of
/// nothing is telling the truth about a machine whose clock is right. The two timestamps it returns
/// are built from that: the request reaches it half a round trip after it left, and it answers
/// immediately.
fn honest(
    id: &str,
    at: MonotonicNanos,
    offset: Nanos,
    round_trip: Nanos,
    stated: Nanos,
) -> Exchange {
    let local_t1 = ANCHOR + Nanos::from(at.as_nanos() - MONO_ORIGIN);
    let arrived = UnixNanos(local_t1 + offset + round_trip / 2);
    Exchange {
        source: SourceId::new(id.to_string()),
        operator: Operator::new(id.to_string()),
        kind: SourceKind::Ntp,
        t2: arrived,
        t3: arrived,
        mono_t1: at,
        mono_t4: at.advanced(round_trip),
        root_delay: 0,
        root_dispersion: stated,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        attestation: None,
    }
}

/// A round from four sources that agree well enough to leave a majority and not so well that any
/// of them swallows another whole.
///
/// Equal widths and different centres, on purpose. Four identical intervals would each contain the
/// others, which is the shape the selection rule of 2026-09-09 refuses as a majority made only of
/// free agreement, and a fixture that trips that rule would be testing the rule rather than this.
///
/// **Four rather than three from 2026-09-09**, because the shipped policy now needs four distinct
/// operators before it will sign and each of these is its own. A fixture standing for a working
/// deployment has to look like one the policy would accept, and three did not any more.
fn a_round(at: MonotonicNanos) -> Vec<Exchange> {
    vec![
        honest("alpha", at, 0, 10 * NANOS_PER_MILLI, NANOS_PER_MILLI),
        honest(
            "bravo",
            at,
            2 * NANOS_PER_MILLI,
            10 * NANOS_PER_MILLI,
            NANOS_PER_MILLI,
        ),
        honest(
            "charlie",
            at,
            -2 * NANOS_PER_MILLI,
            10 * NANOS_PER_MILLI,
            NANOS_PER_MILLI,
        ),
        honest(
            "delta",
            at,
            4 * NANOS_PER_MILLI,
            10 * NANOS_PER_MILLI,
            NANOS_PER_MILLI,
        ),
    ]
}

/// A resident agent on a fabricated machine, synchronised and ready to answer.
fn a_synchronised_agent() -> (Resident, Arc<TestClock>, HandMade) {
    let clock = Arc::new(TestClock::starting_at(MONO_ORIGIN));
    let machine = HandMade::awake();
    let mut resident = Resident::new(
        Policy::default(),
        Arc::new(Handle(clock.clone())),
        UnixNanos(ANCHOR),
        0,
        Box::new(machine.clone()),
    );
    // Three rounds a second apart, which is what the model needs before it will fit a line.
    for _ in 0..3 {
        let round = a_round(clock.now());
        clock.advance_seconds(1);
        assert!(
            resident.take(&round).is_valid(),
            "the fixture has to give the model something it can stand behind"
        );
    }
    (resident, clock, machine)
}

/// What a caller on this fabricated machine knows: a clock that agrees with the agent's, and the
/// shipped ceiling.
///
/// The clock is `ANCHOR` rather than the real machine's, on purpose. A test process's own clock is
/// thirty-odd years from where this fixture puts the world, so a caller reading it would be refused
/// by the check on how far apart the clocks are, and rightly. The fabricated machine has a
/// fabricated caller.
fn a_caller_who_agrees() -> WhatTheCallerKnows {
    WhatTheCallerKnows {
        local_wall: UnixNanos(ANCHOR),
        ceiling: Policy::default().max_bound_width,
    }
}

/// Answer `count` callers on a thread, then stop.
fn answering(
    shared: &Arc<Mutex<Resident>>,
    listener: TcpListener,
    token: [u8; TOKEN_BYTES],
    count: usize,
) -> std::thread::JoinHandle<()> {
    let shared = shared.clone();
    std::thread::spawn(move || {
        let report: timewitness_agent::serve::Reporter = Arc::new(|_line: String| {});
        for stream in listener.incoming().take(count) {
            let Ok(stream) = stream else { continue };
            answer(&shared, &token, stream, &report);
        }
    })
}

#[test]
fn a_reading_crosses_the_boundary_whole() {
    let (resident, _clock, _machine) = a_synchronised_agent();
    let expected = {
        let mut r = resident;
        let stamp = r.read().expect("a synchronised model answers");
        let policy = r.policy_record();
        let carrier = timewitness_agent::wire::carrier(&stamp, policy, TakenBy::ResidentAgent);
        (r, carrier)
    };
    let (resident, before) = expected;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    // The caller's own counter is the real one, so the round trip is a real span and the widening
    // it pays for is a real widening rather than nothing.
    let client_clock = SystemMonotonic::new();
    let crossed = ask(&endpoint, &client_clock, a_caller_who_agrees()).expect("a reading");
    thread.join().expect("the answering thread");

    let after = &crossed.carrier;
    assert!(crossed.round_trip > 0, "a real socket takes some time");

    // Everything the model said about how it got there survives the crossing, field for field. This
    // is the check that matters most: a lossy crossing would put numbers in a signed receipt that
    // describe a round nobody ran.
    assert_eq!(after.claim.sources_offered, 4);
    assert_eq!(after.claim.sources_kept, before.claim.sources_kept);
    assert_eq!(after.claim.sources, before.claim.sources);
    assert_eq!(after.claim.fusion, before.claim.fusion);
    assert_eq!(after.claim.policy, before.claim.policy);
    assert_eq!(after.claim.boot_generation, before.claim.boot_generation);
    assert_eq!(
        after.claim.resume_generation,
        before.claim.resume_generation
    );
    assert_eq!(after.monotonic, before.monotonic);

    // And the interval is the agent's, widened by the crossing and by nothing else.
    let paid = after.claim.breakdown.scheduling - before.claim.breakdown.scheduling;
    assert!(
        paid >= crossed.round_trip,
        "the crossing has to be paid for"
    );
    assert_eq!(after.claim.earliest, before.claim.earliest - paid);
    assert_eq!(after.claim.latest, before.claim.latest + paid);
    assert_eq!(after.width(), before.width() + 2 * paid);
}

#[test]
fn a_machine_that_slept_between_polls_is_caught_on_the_read_path() {
    // The failure this whole design turns on. The model synchronised, then the lid closed, then
    // somebody asked for a stamp before the next poll came round. An agent that looks only when it
    // polls answers that request from a model whose clock went away, and it answers confidently.
    let (mut resident, clock, machine) = a_synchronised_agent();
    assert!(resident.read().is_ok(), "the model was fine a moment ago");

    // Ten minutes away. The counter the agent stamps from did not move while the machine was gone,
    // which is the whole reason the model cannot see this for itself.
    machine.sleep_for(600 * NANOS_PER_SEC);
    clock.advance(NANOS_PER_MILLI as u64);

    let refusal = resident
        .read()
        .expect_err("a model whose machine slept must not answer");
    assert!(
        format!("{refusal}").contains("suspend") || format!("{refusal:?}").contains("Suspended"),
        "the refusal has to say what happened: {refusal:?}"
    );
    assert!(
        resident
            .notes()
            .iter()
            .any(|n| n.contains("suspended for 600.000 s")),
        "the agent has to be able to say how long it was away: {:?}",
        resident.notes()
    );
}

#[test]
fn a_clock_moved_by_something_else_between_polls_is_caught_on_the_read_path() {
    // The Windows case, which is the ordinary case rather than an unusual one: the built-in time
    // service contends with any other discipliner by design.
    let (mut resident, clock, machine) = a_synchronised_agent();
    assert!(resident.read().is_ok());

    machine.something_else_moves_the_clock(4 * NANOS_PER_SEC);
    clock.advance(NANOS_PER_MILLI as u64);

    let refusal = resident
        .read()
        .expect_err("a model whose clock was stepped must not answer");
    assert!(
        format!("{refusal:?}").contains("SystemClockStepped"),
        "{refusal:?}"
    );
}

#[test]
fn the_refusal_crosses_the_boundary_as_a_refusal_and_never_as_a_reading() {
    // A boundary that turned a refusal into anything a caller could sign would undo the whole of the
    // model's discipline, which is that it never returns the last good interval.
    let (mut resident, clock, machine) = a_synchronised_agent();
    machine.sleep_for(600 * NANOS_PER_SEC);
    clock.advance(NANOS_PER_MILLI as u64);
    assert!(resident.read().is_err());

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    let client_clock = SystemMonotonic::new();
    match ask(&endpoint, &client_clock, a_caller_who_agrees()) {
        Err(CrossingError::Wire(e)) => {
            let said = format!("{e}");
            assert!(said.contains("resumed from sleep"), "{said}");
        }
        other => panic!("a suspended machine must not hand out a reading: {other:?}"),
    }
    thread.join().expect("the answering thread");
}

#[test]
fn a_bound_past_the_ceiling_crosses_with_its_width_and_is_still_refused() {
    // What `status` reads during a fresh agent's first minutes. The model has a bound and it is too
    // wide to sign, so the refusal carries the width the model worked out, the same figure a direct
    // read gives, and nothing a caller could sign comes out of it.
    let (mut resident, clock, _machine) = a_synchronised_agent();
    clock.advance_seconds(3_000);
    let (width, ceiling) = match resident.read() {
        Err(refusal) => match refusal.validity {
            timewitness_core::Validity::BoundTooWide { width, ceiling } => (width, ceiling),
            other => panic!("the fixture has to leave the bound past the ceiling: {other:?}"),
        },
        Ok(stamp) => panic!("a model this far out should not answer: {stamp:?}"),
    };
    assert_eq!(ceiling, Policy::default().max_bound_width);
    assert!(width > ceiling);

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    let client_clock = SystemMonotonic::new();
    match ask(&endpoint, &client_clock, a_caller_who_agrees()) {
        Err(CrossingError::Wire(e @ WireError::PastCeiling { .. })) => {
            let WireError::PastCeiling {
                width: crossed,
                ceiling: theirs,
                ..
            } = &e
            else {
                unreachable!()
            };
            assert_eq!(
                *crossed, width,
                "the width has to cross as the model worked it out"
            );
            assert_eq!(*theirs, ceiling);
            let said = format!("{e}");
            assert!(
                said.starts_with("the agent would not give a reading"),
                "{said}"
            );
            assert!(said.contains("past the 250 ms ceiling"), "{said}");
        }
        other => {
            panic!("a bound past the ceiling must cross as a refusal with its width: {other:?}")
        }
    }
    thread.join().expect("the answering thread");
}

#[test]
fn a_caller_without_the_token_gets_nothing() {
    use std::io::{Read, Write};

    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("an address").to_string();
    let endpoint = Endpoint::fresh(address.clone()).expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    let mut stream = TcpStream::connect(&address).expect("a connection");
    stream
        .write_all(&[0u8; TOKEN_BYTES])
        .expect("a wrong token");
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).expect("an answer");
    thread.join().expect("the answering thread");

    assert!(
        !reply.is_empty(),
        "a caller is told why rather than dropped"
    );
    assert!(
        timewitness_agent::wire::decode_reply(&reply).is_err(),
        "a wrong token must never come back with a reading"
    );
}

#[test]
fn a_model_held_past_its_own_ceiling_refuses_rather_than_widening_for_ever() {
    // The other half of holding a model between stamps. An agent whose sources have all gone quiet
    // still has a model, and the honest answer past a point is a refusal rather than a very wide
    // number, because a caller who sees a number will use it.
    let (mut resident, clock, _machine) = a_synchronised_agent();
    assert!(resident.read().is_ok());
    clock.advance_seconds(3_600);
    let refusal = resident
        .read()
        .expect_err("an hour of silence is not a bound");
    let said = format!("{refusal:?}");
    assert!(
        said.contains("HoldoverExceeded") || said.contains("BoundTooWide"),
        "{said}"
    );
}

#[test]
fn the_resident_agent_refuses_a_round_that_is_four_names_at_two_companies() {
    // Independent operators disciplining the clock, proved on the agent path rather than argued
    // from the model's own tests. The resident holds the shipped policy, so the operator floor has
    // to bite here as well; an agent that took a round its own one-shot command would refuse is two
    // products.
    //
    // The round is the working fixture with the operators relabelled and nothing else touched, so
    // the arithmetic that would have produced a bound is unchanged and the only thing refusing it
    // is who the four names belong to.
    let clock = Arc::new(TestClock::starting_at(MONO_ORIGIN));
    let machine = HandMade::awake();
    let mut resident = Resident::new(
        Policy::default(),
        Arc::new(Handle(clock.clone())),
        UnixNanos(ANCHOR),
        0,
        Box::new(machine),
    );

    let mut last = timewitness_core::Validity::Valid;
    for _ in 0..3 {
        let round: Vec<Exchange> = a_round(clock.now())
            .into_iter()
            .enumerate()
            .map(|(i, mut e)| {
                e.operator = Operator::new(if i < 2 { "one.example" } else { "two.example" });
                e
            })
            .collect();
        clock.advance_seconds(1);
        last = resident.take(&round);
    }

    assert!(
        !last.is_valid(),
        "the agent signed on two parties: {last:?}"
    );
    let said = format!("{last:?}");
    assert!(
        said.contains("InsufficientOperators"),
        "refused for the wrong reason: {said}"
    );

    // And the same four names at four companies is the fixture this file already trusts, so the
    // refusal above is the operator rule and not the fixture being unusable.
    let (mut honest_agent, _clock, _machine) = a_synchronised_agent();
    assert!(honest_agent.read().is_ok());
}

#[test]
fn idle_sockets_do_not_stop_this_machine_issuing_receipts() {
    // Twenty callers connect and none of them says anything, which costs a socket
    // each and nothing else. Until 2026-09-10 the accept loop served each one inline and waited the
    // whole of its patience before it even looked at the token, so those twenty sockets bought
    // forty seconds of everybody else's time: measured at 40158 ms against 56 ms alone.
    //
    // The property is that a legitimate ask is not behind them. It is not that the answer is narrow
    // enough to use, and asserting the second made this test flaky: the crossing widens the
    // interval by the round trip, so on a busy machine an honest ask can come back past the caller's
    // own 250 ms ceiling and be refused for saying so. That refusal is the design working. This
    // failed once in five full-suite runs on 2026-09-10 under the load of a Linux-target clippy,
    // with `TooWide { width: 426278836, ceiling: 250000000, whose: TheCaller }`, and passed on every
    // run in isolation, so the fix read as done on a quiet machine.
    //
    // So the assertion is on the shape of the answer. Something came back, and it was either a
    // reading or a refusal naming the caller's own ceiling, which is the only thing the crossing
    // itself can produce. A silence or a queue is neither.
    //
    // Five seconds is the stated time. The old accept loop served each idle socket inline and waited
    // the whole of its two second patience before it looked at the token, measured at 40158 ms
    // against 56 ms alone, so the criterion is an eighth of what the fault cost and eight times the
    // patience one socket buys. Nothing between those two figures is a load this desktop produces.
    use std::time::{Duration, Instant};

    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("an address").to_string();
    let endpoint = Endpoint::fresh(address.clone()).expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));

    let serving = shared.clone();
    let token = endpoint.token;
    std::thread::spawn(move || {
        let report: timewitness_agent::serve::Reporter = Arc::new(|_line: String| {});
        answer_callers(&serving, &token, &listener, &report);
    });

    // Held open for the length of the test. Nothing is written on any of them, which is the whole
    // of the attack.
    let idle: Vec<TcpStream> = (0..20)
        .map(|i| TcpStream::connect(&address).unwrap_or_else(|e| panic!("idle socket {i}: {e}")))
        .collect();
    assert_eq!(idle.len(), 20);

    let client_clock = SystemMonotonic::new();
    let started = Instant::now();
    let answered = ask(&endpoint, &client_clock, a_caller_who_agrees());
    let waited = started.elapsed();

    assert!(
        waited < Duration::from_secs(5),
        "a legitimate ask took {waited:?} behind twenty idle sockets"
    );
    match answered {
        Ok(crossed) => assert!(crossed.round_trip > 0, "a real socket takes some time"),
        Err(CrossingError::TooWide { whose, .. }) => assert_eq!(
            format!("{whose:?}"),
            "TheCaller",
            "the only ceiling the crossing itself can break is the caller's own"
        ),
        other => panic!("nothing came back from behind twenty idle sockets: {other:?}"),
    }
    drop(idle);
}

#[test]
fn a_caller_past_the_cap_is_refused_rather_than_queued() {
    // The other half of the idle sockets fix, and the half that is a refusal. A cap that queued
    // would be the same unavailability moved somewhere a caller cannot see it, so past the cap the
    // agent says so and the caller can do something about it.
    //
    // The cap is filled with sockets that say nothing, each of which holds its thread for the two
    // second patience, so within that window every further caller is refused. Reading is done with a
    // short timeout across all of them rather than in accept order, because which socket the kernel
    // hands over first is not something a test should rest on.
    use std::io::Read;
    use std::time::{Duration, Instant};

    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("an address").to_string();
    let endpoint = Endpoint::fresh(address.clone()).expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));

    let serving = shared.clone();
    let token = endpoint.token;
    std::thread::spawn(move || {
        let report: timewitness_agent::serve::Reporter = Arc::new(|_line: String| {});
        answer_callers(&serving, &token, &listener, &report);
    });

    let mut sockets: Vec<TcpStream> = (0..CALLERS_AT_ONCE + 4)
        .map(|i| TcpStream::connect(&address).unwrap_or_else(|e| panic!("socket {i}: {e}")))
        .collect();
    for socket in &sockets {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a short read timeout");
    }

    // Well inside the two second patience, so nothing has freed a thread by giving up.
    let deadline = Instant::now() + Duration::from_millis(1_200);
    let mut refused = 0usize;
    while Instant::now() < deadline && refused == 0 {
        for socket in &mut sockets {
            let mut reply = Vec::new();
            let _ = socket.read_to_end(&mut reply);
            if reply.is_empty() {
                continue;
            }
            let said = format!(
                "{}",
                timewitness_agent::wire::decode_reply(&reply)
                    .expect_err("a caller past the cap must never get a reading")
            );
            assert!(
                said.contains("already answering"),
                "a caller past the cap was turned down for the wrong reason: {said}"
            );
            refused += 1;
        }
    }

    assert!(
        refused > 0,
        "{} callers were opened against a cap of {CALLERS_AT_ONCE} and none was refused",
        sockets.len()
    );
}

#[test]
fn an_answer_from_a_party_whose_time_is_wild_is_refused_before_anything_is_signed() {
    // The caller's own check, driven over a real socket rather than over the arithmetic. The agent
    // here is honest and it is the caller's own clock that disagrees, which is the same distance and
    // is the shape the real path has: the answer arrives, and all the caller has to hold it against
    // is its own clock.
    //
    // Both directions and several sizes, because the property is the distance and not the one
    // forged case that found it. Three hours is the case testing built and it is one entry in the
    // table rather than the whole of it.
    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let apart_by = [-86_400, -10_800, -600, 600, 10_800, 86_400];
    let thread = answering(&shared, listener, endpoint.token, apart_by.len());
    let client_clock = SystemMonotonic::new();

    for seconds in apart_by {
        let knows = WhatTheCallerKnows {
            local_wall: UnixNanos(ANCHOR - Nanos::from(seconds) * NANOS_PER_SEC),
            ceiling: Policy::default().max_bound_width,
        };
        match ask(&endpoint, &client_clock, knows) {
            Err(CrossingError::WildlyApart { allowance, .. }) => {
                assert_eq!(allowance, WILDNESS);
            }
            other => panic!("an answer {seconds} s from this machine's clock was taken: {other:?}"),
        }
    }
    thread.join().expect("the answering thread");
}

#[test]
fn an_honest_agent_on_this_machine_still_stamps_with_the_check_in() {
    // The honest case, and the half a check like this fails. A sanity check that refuses the
    // honest case is worse than no check, because the honest case is every case. The agent is the
    // same fixture the rest of this file trusts and the caller's clock is the one that machine
    // would have, within the allowance.
    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    let client_clock = SystemMonotonic::new();
    let crossed = ask(&endpoint, &client_clock, a_caller_who_agrees())
        .expect("an honest agent and a caller whose clock agrees");
    thread.join().expect("the answering thread");

    assert!(crossed.carrier.width() <= Policy::default().max_bound_width);
}

#[test]
fn the_answering_party_does_not_choose_the_ceiling_it_is_judged_by_over_a_real_socket() {
    // The caller's own ceiling, over the boundary. The caller states a ceiling narrower than the
    // bound it is handed, and the answer's own policy is wide enough to allow it. Before 2026-09-10
    // the answer's policy was the only ceiling read, so this crossing was taken.
    let (resident, _clock, _machine) = a_synchronised_agent();
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let endpoint = Endpoint::fresh(listener.local_addr().expect("an address").to_string())
        .expect("random bytes");
    let shared = Arc::new(Mutex::new(resident));
    let thread = answering(&shared, listener, endpoint.token, 1);

    let client_clock = SystemMonotonic::new();
    let knows = WhatTheCallerKnows {
        local_wall: UnixNanos(ANCHOR),
        // A microsecond. No real bound is this narrow, which is the point: whatever the answer
        // says about its own ceiling, this caller will not take it.
        ceiling: 1_000,
    };
    match ask(&endpoint, &client_clock, knows) {
        Err(CrossingError::TooWide { whose, ceiling, .. }) => {
            assert_eq!(
                format!("{whose:?}"),
                "TheCaller",
                "the caller's own ceiling has to be the one that bit"
            );
            assert_eq!(ceiling, 1_000);
        }
        other => panic!("a caller's own ceiling was not applied: {other:?}"),
    }
    thread.join().expect("the answering thread");
}

/// One source that answers and says its own clock is not synchronised.
///
/// Everything else about it is an honest answer on a symmetric path, so the only reason it is not a
/// candidate is the thing it said about itself.
fn says_its_own_clock_is_wrong(id: &str, at: MonotonicNanos) -> Exchange {
    let mut e = honest(id, at, 0, 10 * NANOS_PER_MILLI, NANOS_PER_MILLI);
    e.leap = LeapIndicator::Unsynchronised;
    e
}

/// A source saying its own clock is wrong is not a candidate and is still in the receipt, marked as
/// not kept, because a reader who cannot see that it answered cannot see why the count of sources is
/// what it is.
///
/// Both halves of this product have to read that receipt the same way. Until this test went in they
/// did not: the model counted `sources_offered` over the candidates and listed everything that
/// answered, and the validator refused the difference. An honest round produced a receipt our own
/// verifier called inconsistent.
///
/// Four unsynchronised sources rather than one, on purpose. One would leave four kept out of five
/// and pass a majority taken either way, so it would not say which set the majority is over. Four
/// leaves four kept out of eight, which is a clean majority of the candidates and not a majority of
/// everything that answered.
///
/// Driven end to end for the same reason. Asserting on the model alone, or on a receipt built by
/// hand, is what let the disagreement stand: each side was right about its own arithmetic.
#[test]
fn a_source_reporting_itself_unsynchronised_leaves_a_receipt_this_product_accepts() {
    let clock = Arc::new(TestClock::starting_at(MONO_ORIGIN));
    let machine = HandMade::awake();
    let mut resident = Resident::new(
        Policy::default(),
        Arc::new(Handle(clock.clone())),
        UnixNanos(ANCHOR),
        0,
        Box::new(machine),
    );
    for _ in 0..3 {
        let at = clock.now();
        let mut round = a_round(at);
        for id in ["echo", "foxtrot", "golf", "hotel"] {
            round.push(says_its_own_clock_is_wrong(id, at));
        }
        clock.advance_seconds(1);
        assert!(
            resident.take(&round).is_valid(),
            "four honest sources are a round whatever the other four said about themselves"
        );
    }

    let stamp = resident.read().expect("a synchronised model answers");
    let carrier =
        timewitness_agent::wire::carrier(&stamp, resident.policy_record(), TakenBy::ResidentAgent);

    assert_eq!(
        carrier.claim.sources.len(),
        8,
        "everything that answered is in the list"
    );
    assert_eq!(
        carrier.claim.sources_offered, 8,
        "and the count is over the same set"
    );
    assert_eq!(carrier.claim.sources_kept, 4);
    for s in carrier.claim.sources.iter().filter(|s| !s.kept) {
        assert_eq!(
            s.leap, "unsynchronised",
            "the only sources not kept here are the ones that said so"
        );
    }

    timewitness_receipt::validate(&carrier)
        .expect("this product's validator has to accept a receipt this product signed");
}
