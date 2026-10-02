//! A source that stops answering, on a machine drifting inside the band.
//!
//! The control beside `a_round_spread_out_in_time.rs` and `a_round_spread_across_its_sources.rs`.
//! Those two spread a round out in time and found a signed bound with the truth outside it; this one
//! asks the same question a different way, by leaving one source's answer to go stale while the rest
//! keep answering, and it found nothing either before the ageing was fixed or after. It is kept
//! because a control that found nothing is what says a later change has broken something.
//!
//! Every read here has an elapsed time of nought, so the allowance for the oscillator is nought and
//! the only thing under test is how a source's own interval is carried over the local counter. A
//! source quiet for a few rounds contributes an interval that was short by `(rate - floor) x age`
//! while the ageing ran at the frequency floor alone; `timewitness_clock::CounterAgeing` is what
//! replaced that floor.
//!
//! Read-only probe, on the simulated network at `crates/clock/tests/common/mod.rs`, where the truth
//! is a number the harness wrote down.

#![allow(dead_code)]

mod common;

use common::{Path, World};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, UnixNanos};
use timewitness_sources::Exchange;

struct Clock(Arc<AtomicU64>);

impl MonotonicClock for Clock {
    fn now(&self) -> MonotonicNanos {
        MonotonicNanos(self.0.load(Ordering::SeqCst))
    }
}

const ROUND_S: u64 = 32;

#[derive(Debug)]
enum Outcome {
    Inside(Nanos),
    Outside(Nanos, Nanos),
    Refused(String),
}

/// Four honest sources. Every one answers for `warm` rounds, then delta stops and the other three
/// go on for `quiet` more rounds. The read is taken at the instant of the last round, so the
/// elapsed time is nought and the oscillator allowance is nought with it.
fn run(policy: Policy, ppm: f64, warm: usize, quiet: usize) -> Outcome {
    let world = World::drifting(0, ppm);
    let start = world.mono0.as_nanos();
    let counter = Arc::new(AtomicU64::new(start));
    let wall = world.system(MonotonicNanos(start));
    let mut model = ClockModel::new(policy, Box::new(Clock(counter.clone())), wall, 0);

    let paths = [
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 14, 1),
        Path::honest("charlie", 10, 1),
        Path::honest("delta", 12, 1),
    ];

    for round in 0..(warm + quiet) {
        if round > 0 {
            counter.fetch_add(ROUND_S * NANOS_PER_SEC as u64, Ordering::SeqCst);
        }
        let now = MonotonicNanos(counter.load(Ordering::SeqCst));
        let jitter_us = (24 + (round as i128 % 5) * 18) * 5;
        for (n, path) in paths.iter().enumerate() {
            if n == 3 && round >= warm {
                continue;
            }
            let mut path = path.clone();
            let lean = ((n as i128 % 2) * 2 - 1) * jitter_us * NANOS_PER_MICRO;
            path.out += lean;
            path.back -= lean;
            let e: Exchange = world.exchange(&path, now);
            model.ingest(&e);
        }
        model.synchronise();
    }

    match model.read() {
        Ok(stamp) => {
            let truth: UnixNanos = world.utc(stamp.reading.monotonic);
            let width = stamp.bound.width();
            if stamp.bound.contains(truth) {
                Outcome::Inside(width)
            } else {
                let past = if truth < stamp.bound.earliest {
                    stamp.bound.earliest.0 - truth.0
                } else {
                    truth.0 - stamp.bound.latest.0
                };
                Outcome::Outside(width, past)
            }
        }
        Err(refusal) => Outcome::Refused(format!("{refusal}")),
    }
}

#[test]
fn a_quiet_source_on_a_machine_inside_the_band() {
    let mut worst: Option<(f64, usize, usize, Nanos, Nanos)> = None;
    let mut lines = Vec::new();
    for ppm in [20.0_f64, 30.0, 40.0, 50.0, -40.0, -50.0] {
        for warm in [1_usize, 2, 4] {
            for quiet in 1..=24_usize {
                let outcome = run(Policy::default(), ppm, warm, quiet);
                let age_s = (quiet as u64) * ROUND_S;
                let cell = match &outcome {
                    Outcome::Inside(w) => format!("INSIDE\twidth={w}"),
                    Outcome::Outside(w, past) => {
                        if worst.is_none() || worst.unwrap().4 < *past {
                            worst = Some((ppm, warm, quiet, *w, *past));
                        }
                        format!("OUTSIDE\twidth={w}\tpast={past}")
                    }
                    Outcome::Refused(r) => format!("REFUSED\t{r}"),
                };
                lines.push(format!(
                    "ppm={ppm}\twarm={warm}\tquiet={quiet}\tage_s={age_s}\t{cell}"
                ));
            }
        }
    }
    for l in &lines {
        println!("{l}");
    }
    match worst {
        None => println!("RESULT: no cell signed a bound with the truth outside"),
        Some((ppm, warm, quiet, w, past)) => println!(
            "RESULT: worst OUTSIDE at ppm={ppm} warm={warm} quiet={quiet} age_s={} width={w} past={past}",
            quiet as u64 * ROUND_S
        ),
    }
    assert!(
        worst.is_none(),
        "a signed bound missed the truth on a machine inside the band: {worst:?}"
    );
}
