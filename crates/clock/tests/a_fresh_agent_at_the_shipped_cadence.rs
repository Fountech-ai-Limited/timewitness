//! A fresh agent at the shipped policy and cadence, on sources that scatter, has to start signing
//! and then keep signing.
//!
//! The regression case for the resident agent that stopped converging on 2026-09-18. Four settling
//! rounds a quarter of a second apart give the first fit a baseline under a second, so its frequency
//! error bar is the sources' scatter divided by almost nothing: tens of thousands of parts per
//! million, which is noise and not a measurement of this counter. Between `ad5e9b7` and `974d0a3`
//! that error bar was fed into the ageing of every source interval on the next round, the widened
//! intervals made a wider intersection, the wider intersection made a regression point with almost
//! no weight against the settling points, the fit stayed on the sub-second baseline, and the next
//! round was wider again. On an ordinary desktop against the nine published servers the agent signed
//! once at 3 s of uptime and then refused every reading it was asked for, at sixteen to twenty-two
//! seconds of width.
//!
//! What this rig does. Six sources behind six operators, so the shipped independence floor is met,
//! on internet-sized paths whose round trips vary from round to round and whose delay splits
//! between the two legs however a fixed pseudo-random sequence says, so the offsets scatter inside
//! their own intervals the way a public path makes them. The schedule is the agent's own: four
//! rounds 250 ms apart, then one every thirty-two seconds, with a reading taken straight after each
//! round and every ten seconds until the next, which is how the real agent was probed on
//! 2026-09-18. The machine drifts at an ordinary twelve parts per million.
//!
//! What it asserts. A reading is signed before three minutes of uptime, and from three minutes to
//! twelve the agent refuses no more than one reading in ten. Both figures are the ones the
//! cannot-prove document states for the real agent, with room, because this is arithmetic and not a
//! path.
//!
//! **This is a simulated network with a known true offset, per `common/mod.rs`.** Every width here
//! is the arithmetic of the model and nothing here is a reading from a real path. The measurement
//! on a real path is on the honesty surfaces, with its date and conditions.

mod common;

use common::{Path, World};

use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::MonotonicNanos;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The agent's shipped schedule, as `timewitness_agent::Cadence` ships it.
///
/// Written down here because the crate that ships the cadence depends on this one and not the other
/// way round, and held to `Cadence::default` from outside by
/// `crates/agent/tests/the_shipped_cadence.rs`, which reads these three lines and the default
/// together. A change to either copy alone turns that file red and names which of the two moved.
///
/// Until 2026-09-20 this file held them with an assertion of each literal against itself, which
/// could not fail. A cadence change would have left this rig simulating the old schedule, green,
/// while the P0 it is the regression case for is a P0 about the schedule the agent actually keeps.
const SETTLING_ROUNDS: usize = 4;
const SETTLING_GAP_MS: u64 = 250;
const INTERVAL_S: u64 = 32;

/// A fixed sequence, so the scatter is the same on every run and a red result can be reproduced.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Six sources behind six operators on public paths.
fn sources() -> Vec<Path> {
    vec![
        Path::honest("alpha", 18, 1).operated_by("one.example"),
        Path::honest("bravo", 26, 2).operated_by("two.example"),
        Path::honest("charlie", 14, 1).operated_by("three.example"),
        Path::honest("delta", 40, 3).operated_by("four.example"),
        Path::honest("echo", 22, 1).operated_by("five.example"),
        Path::honest("foxtrot", 34, 2).operated_by("six.example"),
    ]
}

/// The same path this round: up to half as long again, split between the legs wherever the
/// sequence puts it.
fn this_round(path: &Path, sequence: &mut Sequence) -> Path {
    let stretch = 1.0 + 0.5 * sequence.next();
    let rtt = ((path.round_trip() as f64) * stretch) as Nanos;
    let mut p = path.clone();
    p.out = rtt;
    p.back = 0;
    p.with_split(sequence.next())
}

/// One reading: seconds of uptime, and the width or the refusal.
type Reading = (u64, Result<Nanos, String>);

/// Run the agent's schedule for `seconds` of uptime and hand back every reading it was asked for.
fn readings_over(seconds: u64) -> Vec<Reading> {
    let policy = Policy::default();
    let paths = sources();
    let world = World::drifting(0, 12.0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
    let mut sequence = Sequence(0x5eed_2026_0918);

    let uptime = |clock: &TestClock| clock.now().since(world.mono0) / NANOS_PER_SEC;
    let mut out: Vec<Reading> = Vec::new();
    let read = |model: &ClockModel, clock: &TestClock, out: &mut Vec<Reading>| {
        let up = uptime(clock) as u64;
        match model.read() {
            Ok(stamp) => out.push((up, Ok(stamp.bound.width()))),
            Err(refusal) => out.push((up, Err(format!("{refusal}")))),
        }
    };

    let mut round = 0usize;
    while uptime(&clock) < seconds as Nanos {
        let now = clock.now();
        for path in &paths {
            let p = this_round(path, &mut sequence);
            model.ingest(&world.exchange(&p, now));
        }
        model.synchronise();
        read(&model, &clock, &mut out);

        if round < SETTLING_ROUNDS {
            clock.advance(SETTLING_GAP_MS * NANOS_PER_MILLI as u64);
        } else {
            // The probe's cadence: a reading every ten seconds across the gap.
            for _ in 0..3 {
                clock.advance_seconds(10);
                read(&model, &clock, &mut out);
            }
            clock.advance_seconds(INTERVAL_S - 30);
        }
        round += 1;
    }
    out
}

#[test]
fn a_fresh_agent_signs_before_three_minutes_and_keeps_signing() {
    let readings = readings_over(12 * 60);
    for (up, r) in &readings {
        match r {
            Ok(w) => println!("{up} s\tsigned\t{} ms", *w as f64 / NANOS_PER_MILLI as f64),
            Err(why) => println!("{up} s\trefused\t{why}"),
        }
    }

    // After the settling rounds, which is where the real agent signs once and then stops.
    let first_signed = readings
        .iter()
        .filter(|(up, r)| *up >= 5 && r.is_ok())
        .map(|(up, _)| *up)
        .next();
    assert!(
        first_signed.is_some_and(|up| up < 180),
        "the agent did not sign between five seconds and three minutes of uptime: first signature \
         after settling at {first_signed:?}"
    );

    let settled: Vec<&Reading> = readings.iter().filter(|(up, _)| *up >= 180).collect();
    let refused = settled.iter().filter(|(_, r)| r.is_err()).count();
    assert!(
        !settled.is_empty() && refused * 10 <= settled.len(),
        "from three minutes to twelve the agent refused {refused} of {} readings, which is more \
         than one in ten",
        settled.len()
    );
}
