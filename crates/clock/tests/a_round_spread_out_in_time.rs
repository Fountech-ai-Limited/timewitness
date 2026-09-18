//! A round spread out in time, on a machine drifting legally inside the band.
//!
//! The regression case for a bound that was signed with the truth outside it. Written on 2026-09-18
//! and kept below this comment as it was written; only this comment has been rewritten, because the
//! rest of it described the defect in the present tense and the defect is fixed.
//!
//! What it does. Four sources, two groups, the early group polled `stagger_s` seconds before the
//! late one, and the read taken at the instant the late group went out, so the elapsed time is
//! nought and the oscillator allowance is nought with it. Nothing about holdover is in the way;
//! what is being read is the ageing of a source's own interval over the local counter.
//!
//! What it read before the fix, at `ba3ec25` and again at `7f8bf1c`: 412 of 17280 cells signed a
//! bound with the truth outside, worst 140.001 us past the near end, tightest surviving margin one
//! nanosecond. `ClockModel::candidates_at` aged every sample at `Policy::frequency_floor_ppm`,
//! fifteen parts per million at the default, while the band the same policy states for that counter
//! is a hundred, so the largest magnitude a part may honestly show is fifty. A sample of age `a` on
//! a machine running at `r` was displaced by `r x a` and widened by `floor x a`.
//!
//! What it reads now: 0 of 17280, tightest margin 149.995 us. The ageing term is
//! `timewitness_clock::CounterAgeing`, which carries everything the model knows about the counter's
//! rate rather than the floor alone, and that type's documentation says why it widens and never
//! corrects.
//!
//! Read-only probe. The truth is a number the harness wrote down, on the simulated network at
//! `crates/clock/tests/common/mod.rs`, and nothing here is a reading from a real path.

#![allow(dead_code)]

mod common;

use common::{Path, World};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, SmearPolicy, SourceKind, Timescale, UnixNanos,
};
use timewitness_sources::Exchange;

struct Clock(Arc<AtomicU64>);

impl MonotonicClock for Clock {
    fn now(&self) -> MonotonicNanos {
        MonotonicNanos(self.0.load(Ordering::SeqCst))
    }
}

const ROUND_S: u64 = 32;

const WIDEST: Nanos = i64::MAX as Nanos;

/// N28: one policy at its narrowest on every term `Policy::fault` allows.
fn narrowest() -> Policy {
    Policy {
        min_sources: 1,
        min_operators: 1,
        samples_per_source: 1,
        coverage_factor: 1.0,
        holdover_allowance: 0,
        safety_margin: 0,
        scheduling_floor: 0,
        source_interval_floor: 1,
        weight_floor: 1,
        max_holdover: WIDEST,
        max_bound_width: WIDEST,
        leap_smear_window: 0,
        leap_divergence_ceiling: 1,
        regression_window: 1,
        regression_min_points: 3,
        history_capacity: 3,
        ..Policy::default()
    }
}

/// N12: coverage one and every allowance at nought, the rest shipped.
fn no_allowances() -> Policy {
    Policy {
        coverage_factor: 1.0,
        holdover_allowance: 0,
        safety_margin: 0,
        scheduling_floor: 0,
        source_interval_floor: 1,
        ..Policy::default()
    }
}

#[derive(Debug, Clone)]
enum Outcome {
    Margin(Nanos, Nanos),
    Outside(Nanos, Nanos),
    Refused(String),
}

fn lan(id: &'static str) -> Path {
    Path {
        id,
        operator: id,
        first_party: false,
        out: 100 * NANOS_PER_MICRO,
        back: 100 * NANOS_PER_MICRO,
        think: 0,
        stated: 50 * NANOS_PER_MICRO,
        server_error: 0,
        kind: SourceKind::Ntp,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        timescale: Timescale::Utc,
    }
}

/// One cell. `rounds` rounds at 32 s. In every round the first source is polled `stagger_s` seconds
/// before the other three, and the read is taken at the instant the last three went out.
fn run(
    policy: &Policy,
    ppm: f64,
    rounds: usize,
    stagger_s: u64,
    wide: bool,
    early_n: usize,
) -> Outcome {
    let world = World::drifting(0, ppm);
    let start = world.mono0.as_nanos();
    let counter = Arc::new(AtomicU64::new(start));
    let wall = world.system(MonotonicNanos(start));
    let mut model = ClockModel::new(*policy, Box::new(Clock(counter.clone())), wall, 0);

    let paths: Vec<Path> = if wide {
        vec![
            Path::honest("alpha", 12, 1),
            Path::honest("bravo", 14, 1),
            Path::honest("charlie", 10, 1),
            Path::honest("delta", 12, 1),
        ]
    } else {
        vec![lan("alpha"), lan("bravo"), lan("charlie"), lan("delta")]
    };

    for round in 0..rounds {
        if round > 0 {
            counter.fetch_add(ROUND_S * NANOS_PER_SEC as u64, Ordering::SeqCst);
        }
        // The early sources go out first.
        let early = MonotonicNanos(counter.load(Ordering::SeqCst));
        for path in paths.iter().take(early_n) {
            let e: Exchange = world.exchange(path, early);
            model.ingest(&e);
        }

        // Then the rest of the round, `stagger_s` later.
        counter.fetch_add(stagger_s * NANOS_PER_SEC as u64, Ordering::SeqCst);
        let late = MonotonicNanos(counter.load(Ordering::SeqCst));
        for path in paths.iter().skip(early_n) {
            let e: Exchange = world.exchange(path, late);
            model.ingest(&e);
        }
        model.synchronise();
    }

    match model.read() {
        Ok(stamp) => {
            let truth: UnixNanos = world.utc(stamp.reading.monotonic);
            let width = stamp.bound.width();
            if stamp.bound.contains(truth) {
                let margin = (truth.0 - stamp.bound.earliest.0).min(stamp.bound.latest.0 - truth.0);
                Outcome::Margin(width, margin)
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
fn a_round_spread_out_in_time_on_a_machine_inside_the_band() {
    let mut worst: Option<(String, Nanos, Nanos)> = None;
    let mut outside = 0usize;
    let mut tightest: Option<Nanos> = None;
    let mut tight_tag = String::new();
    let mut cells = 0usize;
    for (pname, policy) in [
        ("D", Policy::default()),
        ("N28", narrowest()),
        ("N12", no_allowances()),
    ] {
        let half_band = policy.frequency_span_ppm / 2.0;
        for wide in [false, true] {
            for ppm in [15.0_f64, 25.0, 40.0, 50.0, -40.0, -50.0] {
                assert!(ppm.abs() <= half_band);
                for rounds in [1_usize, 2, 3, 4, 16] {
                    for early_n in [1_usize, 2, 3] {
                        for stagger_s in 0_u64..=31 {
                            cells += 1;
                            let o = run(&policy, ppm, rounds, stagger_s, wide, early_n);
                            let tag = format!(
                        "policy={pname}\trig={}\tppm={ppm}\trounds={rounds}\tearly_n={early_n}\tstagger_s={stagger_s}",
                        if wide { "internet" } else { "lan" }
                    );
                            match &o {
                                Outcome::Margin(w, m) => {
                                    if tightest.map_or(true, |t| t > *m) {
                                        tightest = Some(*m);
                                        tight_tag = tag.clone();
                                    }
                                    println!("{tag}\tINSIDE\twidth={w}\tmargin={m}")
                                }
                                Outcome::Refused(r) => println!("{tag}\tREFUSED\t{r}"),
                                Outcome::Outside(w, past) => {
                                    outside += 1;
                                    println!("{tag}\tOUTSIDE\twidth={w}\tpast={past}");
                                    if worst.as_ref().map_or(true, |x| x.2 < *past) {
                                        worst = Some((tag, *w, *past));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("RESULT: {outside} of {cells} cells signed a bound with the truth outside");
    println!("RESULT: tightest margin {tightest:?} at {tight_tag}");
    if let Some((tag, w, past)) = &worst {
        println!("RESULT: worst {tag} width={w} past={past}");
    }
    assert_eq!(
        outside, 0,
        "a signed bound missed the truth on a machine inside the band: {worst:?}"
    );
}
