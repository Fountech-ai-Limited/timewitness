//! B. A round spread across its sources, on a machine inside the band and on one outside it.
//!
//! Frozen and hashed before a line of the fix was written. The rig beside this one,
//! `a_round_spread_out_in_time.rs`, splits a round into two groups and reads at the instant the late group went out, so the
//! elapsed time is nought and only the sample-ageing path is live. This rig widens that on five
//! axes at once, because a guard graded only against the set its own builder froze has been graded
//! against its author.
//!
//! What it widens:
//!
//! 1. Every source goes out at its own instant, `step_s` apart, rather than two groups. Four, five
//!    and six sources, so the majority is not always the same shape.
//! 2. The read is taken nought, one and thirty seconds after the last exchange, so the holdover
//!    path is live beside the ageing path rather than switched off.
//! 3. The machine's rate sits at the band edge, and in some cells it changes rate part way through,
//!    so the slew term is live too.
//! 4. A machine outside the band, at sixty, a hundred and twenty and minus a hundred and twenty
//!    parts per million. Those cells are recorded and never asserted: a machine outside the band is
//!    a stated limit of this product and not a property this arithmetic can promise. What the record
//!    is for is the movement, and for watching the band read-back fire.
//! 5. Policies D, N12 and N28, the same three rig A uses, because the shipped default's fixed
//!    allowances were what hid the hole.
//!
//! The property, scored on the in-band cells alone: every cell is a refusal or an interval holding
//! `World::utc`.
//!
//! What it read at `7f8bf1c`, before the fix: 90 of 4725 in-band cells signed a bound with the truth
//! outside, worst 129.998 us. What it reads now: 0 of 4725. The out-of-band cells went the other
//! way, from 8 of 324 to 12 of 324, and they are recorded rather than asserted for exactly that
//! reason: outside the band every allowance the model derives from the band is an assumption the
//! machine has broken, wider intervals let more sources agree on a region none of them is right
//! about, and this arithmetic promises nothing there. `docs/what-timewitness-cannot-prove.md` says
//! so in the product's own words.

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

const NAMES: [&str; 6] = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];

/// One cell. `rounds` rounds at 32 s. Inside each round every source goes out `step_s` after the
/// one before it, and the read is taken `read_after_s` after the last one.
fn run(
    policy: &Policy,
    ppm: f64,
    ramp_to: Option<f64>,
    sources: usize,
    rounds: usize,
    step_s: u64,
    read_after_s: u64,
) -> Outcome {
    let world = match ramp_to {
        Some(to) => World::drifting(0, ppm).changing_rate(2 * ROUND_S, to),
        None => World::drifting(0, ppm),
    };
    let start = world.mono0.as_nanos();
    let counter = Arc::new(AtomicU64::new(start));
    let wall = world.system(MonotonicNanos(start));
    let mut model = ClockModel::new(*policy, Box::new(Clock(counter.clone())), wall, 0);

    let paths: Vec<Path> = NAMES.iter().take(sources).map(|n| lan(n)).collect();

    for round in 0..rounds {
        if round > 0 {
            counter.fetch_add(ROUND_S * NANOS_PER_SEC as u64, Ordering::SeqCst);
        }
        for path in &paths {
            let at = MonotonicNanos(counter.load(Ordering::SeqCst));
            let e: Exchange = world.exchange(path, at);
            model.ingest(&e);
            counter.fetch_add(step_s * NANOS_PER_SEC as u64, Ordering::SeqCst);
        }
        // The counter is one step past the last source. Put it back, so `step_s` is the distance
        // between two sources and not also a distance after the round.
        counter.fetch_sub(step_s * NANOS_PER_SEC as u64, Ordering::SeqCst);
        model.synchronise();
    }

    counter.fetch_add(read_after_s * NANOS_PER_SEC as u64, Ordering::SeqCst);

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
fn a_round_spread_across_its_sources() {
    // Inside the band at the default, which is a hundred parts per million from end to end, so the
    // largest magnitude a part may honestly show is fifty. The last two are the edge itself.
    let inside: [(f64, Option<f64>); 7] = [
        (15.0, None),
        (25.0, None),
        (40.0, None),
        (50.0, None),
        (-50.0, None),
        // The rate moves part way through, so the slew term is live.
        (10.0, Some(50.0)),
        (-10.0, Some(-50.0)),
    ];
    // Outside the band. Recorded, never asserted: it is a stated limit and not a promise.
    let outside_the_band: [(f64, Option<f64>); 3] = [(60.0, None), (120.0, None), (-120.0, None)];

    let mut cells = 0usize;
    let mut outside = 0usize;
    let mut worst: Option<(String, Nanos, Nanos)> = None;
    let mut widest: Option<(String, Nanos)> = None;
    let mut band_cells = 0usize;
    let mut band_outside = 0usize;

    for (pname, policy) in [
        ("D", Policy::default()),
        ("N28", narrowest()),
        ("N12", no_allowances()),
    ] {
        for (ppm, ramp_to) in inside {
            for sources in [4_usize, 5, 6] {
                for rounds in [1_usize, 2, 3, 4, 16] {
                    for step_s in [0_u64, 1, 4, 11, 29] {
                        for read_after_s in [0_u64, 1, 30] {
                            cells += 1;
                            let tag = format!(
                                "policy={pname}\tppm={ppm}\tramp_to={ramp_to:?}\tsources={sources}\trounds={rounds}\tstep_s={step_s}\tread_after_s={read_after_s}"
                            );
                            let o =
                                run(&policy, ppm, ramp_to, sources, rounds, step_s, read_after_s);
                            match &o {
                                Outcome::Margin(w, m) => {
                                    if widest.as_ref().map_or(true, |x| x.1 < *w) {
                                        widest = Some((tag.clone(), *w));
                                    }
                                    println!("{tag}\tINSIDE\twidth={w}\tmargin={m}");
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

        // Recorded and not asserted.
        for (ppm, ramp_to) in outside_the_band {
            for sources in [4_usize, 6] {
                for rounds in [1_usize, 4, 16] {
                    for step_s in [0_u64, 11, 29] {
                        for read_after_s in [0_u64, 30] {
                            band_cells += 1;
                            let tag = format!(
                                "BAND\tpolicy={pname}\tppm={ppm}\tsources={sources}\trounds={rounds}\tstep_s={step_s}\tread_after_s={read_after_s}"
                            );
                            let o =
                                run(&policy, ppm, ramp_to, sources, rounds, step_s, read_after_s);
                            match &o {
                                Outcome::Margin(w, m) => {
                                    println!("{tag}\tINSIDE\twidth={w}\tmargin={m}")
                                }
                                Outcome::Refused(r) => println!("{tag}\tREFUSED\t{r}"),
                                Outcome::Outside(w, past) => {
                                    band_outside += 1;
                                    println!("{tag}\tOUTSIDE\twidth={w}\tpast={past}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    println!("RESULT: {outside} of {cells} in-band cells signed a bound with the truth outside");
    println!(
        "RESULT: {band_outside} of {band_cells} out-of-band cells signed a bound with the truth outside, recorded and not asserted"
    );
    if let Some((tag, w, past)) = &worst {
        println!("RESULT: worst {tag} width={w} past={past}");
    }
    if let Some((tag, w)) = &widest {
        println!("RESULT: widest in-band signed width {w} at {tag}");
    }
    assert_eq!(
        outside, 0,
        "a signed bound missed the truth on a machine inside the band: {worst:?}"
    );
}
