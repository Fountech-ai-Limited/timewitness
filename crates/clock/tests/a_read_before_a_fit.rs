//! A read before a fit, on a world whose truth is written down.
//!
//! The property this file grades: before the model has fitted a rate, the allowance it carries for the
//! oscillator is at least half the band the policy states, times the elapsed time. That is proved
//! on the arithmetic in `the_band_before_a_fit.rs` with no world in the test. This file confirms
//! it on worlds, and it reads where nothing else in the crate reads: after one and two rounds,
//! which is before `regression_min_points` is reached, and inside the first minute after a round.
//! `bound_battery.rs` runs twenty rounds first and probes from one minute out, so the part of the
//! curve where the truth escaped on 2026-09-17 was never read.
//!
//! Frozen and hashed before the fix it grades was written, 2026-09-18. It runs against the
//! model as it stands, so it reads red before the fix and green after, and what it reads either way
//! is written to `R181_OUT` as one TSV per policy, one line per read.
//!
//! The grade. On every world whose true rate magnitude never passes half the band, every read is a
//! refusal or an interval holding `World::utc`. A world outside the band is outside what the bound
//! claims and is INFO, except one set of cells: `Policy::default()` on a machine
//! drifting at a hundred parts per million after one and two rounds, read from nought to sixty
//! seconds, which the default's fixed allowances are calculated to hold and which this file measures
//! rather than takes on trust. A panic anywhere fails.
//!
//! Two attacks are here by name. N28 is the narrowest policy `Policy::fault` accepts, on a rig where
//! only alpha and a point source at the truth answer, on a machine drifting forty parts per
//! million; it signed 432.002 us with the truth 143.999 us outside nine seconds after one round at
//! `6b5d7a6`. B7C1 is `Policy::default()` on four honest local sources on 200 us paths, one round, a
//! machine drifting a hundred parts per million; it signed with the truth up to 313.99 us outside
//! from eighteen seconds after the round.

#![allow(dead_code)]

mod common;

use common::{claiming_no_uncertainty, Path, World};

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, SmearPolicy, SourceKind, Timescale, UnixNanos,
};
use timewitness_sources::Exchange;

const WIDEST: Nanos = i64::MAX as Nanos;

struct Clock(Arc<AtomicU64>);

impl MonotonicClock for Clock {
    fn now(&self) -> MonotonicNanos {
        MonotonicNanos(self.0.load(Ordering::SeqCst))
    }
}

/// The reads, in seconds after the last round. The first eight are the ones nothing in the crate
/// read before this file; the rest are the probes `bound_battery.rs` already makes.
const READS_S: [u64; 13] = [0, 1, 5, 9, 20, 32, 45, 60, 120, 300, 900, 1800, 3600];

/// One, two, then the two the fit exists at.
const ROUNDS: [usize; 4] = [1, 2, 3, 16];

fn d() -> Policy {
    Policy::default()
}

/// One policy at its narrowest on every term `Policy::fault` allows, rates at the shipped figures.
/// This is N28's policy and `fault()` returns `None` on it.
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
        ..d()
    }
}

/// Coverage one and every allowance at nought, the rest shipped. t9's N12.
fn no_allowances() -> Policy {
    Policy {
        coverage_factor: 1.0,
        holdover_allowance: 0,
        safety_margin: 0,
        scheduling_floor: 0,
        source_interval_floor: 1,
        ..d()
    }
}

fn policies() -> Vec<(&'static str, Policy)> {
    vec![
        ("D", d()),
        ("N28", narrowest()),
        ("N12", no_allowances()),
        (
            "N35",
            Policy {
                max_holdover: WIDEST,
                max_bound_width: WIDEST,
                ..no_allowances()
            },
        ),
        (
            "C1",
            Policy {
                coverage_factor: 1.0,
                ..d()
            },
        ),
        // The widest band a policy may state, with the holdover to read it out.
        (
            "W",
            Policy {
                frequency_span_ppm: 1_000_000.0,
                max_holdover: 10 * 86_400 * NANOS_PER_SEC,
                max_bound_width: WIDEST,
                ..d()
            },
        ),
        // The narrowest policy with the band widened past the machines below, so every world is
        // inside it and the fixed allowances are still nought.
        (
            "N28W",
            Policy {
                frequency_span_ppm: 400.0,
                ..narrowest()
            },
        ),
    ]
}

/// Worlds inside the shipped band, at its edge, and outside it. The rate changes stay inside the
/// band on both sides where the world is graded, and the second rate arrives inside the first
/// minute so a read before three rounds sees it.
fn worlds() -> Vec<(&'static str, World)> {
    vec![
        ("still0", World::still(0)),
        ("drift+12", World::drifting(0, 12.0)),
        ("drift-12", World::drifting(0, -12.0)),
        ("drift+40", World::drifting(0, 40.0)),
        ("drift-40", World::drifting(0, -40.0)),
        ("drift+49.9", World::drifting(0, 49.9)),
        ("drift-50", World::drifting(0, -50.0)),
        ("drift3000-40", World::drifting(3000, -40.0)),
        (
            "chg12to-45at20",
            World::drifting(0, 12.0).changing_rate(20, -45.0),
        ),
        (
            "chg40to-40at5",
            World::drifting(0, 40.0).changing_rate(5, -40.0),
        ),
        ("discip40", World::disciplined_elsewhere(40.0)),
        ("drift+100", World::drifting(0, 100.0)),
        ("drift-100", World::drifting(0, -100.0)),
        ("drift+60", World::drifting(0, 60.0)),
    ]
}

/// The largest rate magnitude the world shows at any moment.
fn rate_magnitude(world: &World) -> f64 {
    let second = world.rate_change.map_or(0.0, |c| c.ppm.abs());
    world.drift_ppm.abs().max(second)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Rig {
    /// Four honest sources on ordinary internet paths.
    J,
    /// The same four and a point source at the truth stating no uncertainty.
    P,
    /// Four honest sources on 200 us local paths stating 50 us. B7C1's rig.
    L,
    /// Alpha alone and the point source. N28's rig.
    A,
}

fn internet() -> Vec<Path> {
    vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 40, 3),
    ]
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

fn paths_for(rig: Rig) -> Vec<Path> {
    match rig {
        Rig::J | Rig::P => internet(),
        Rig::L => vec![lan("alpha"), lan("bravo"), lan("charlie"), lan("delta")],
        Rig::A => vec![Path::honest("alpha", 12, 1)],
    }
}

fn has_point_source(rig: Rig) -> bool {
    matches!(rig, Rig::P | Rig::A)
}

#[derive(Clone, Debug)]
enum Outcome {
    Inside(Nanos),
    /// Width, and how far past the nearer end the truth sits.
    Outside(Nanos, Nanos),
    Refused(String),
}

/// One cell: a model built on `policy`, run `rounds` rounds at 32 s on `rig` in `world`, then read
/// at every entry of `READS_S` after the last round.
fn run_cell(policy: Policy, world: &World, rig: Rig, rounds: usize) -> Vec<(u64, Outcome)> {
    let start = world.mono0.as_nanos();
    let counter = Arc::new(AtomicU64::new(start));
    let wall = world.system(MonotonicNanos(start));
    let mut model = ClockModel::new(policy, Box::new(Clock(counter.clone())), wall, 0);
    let paths = paths_for(rig);
    // The lean the t9 harness gives the internet paths, so the fitted numbers here are the numbers
    // that harness fitted; a fifth of it on the local paths, which are a hundredth the length.
    let lean_scale: i128 = if rig == Rig::L { 1 } else { 5 };
    for round in 0..rounds {
        if round > 0 {
            counter.fetch_add(32 * 1_000_000_000, Ordering::SeqCst);
        }
        let now = MonotonicNanos(counter.load(Ordering::SeqCst));
        let jitter_us = (24 + (round as i128 % 5) * 18) * lean_scale;
        for (n, path) in paths.iter().enumerate() {
            let mut path = path.clone();
            let lean = ((n as i128 % 2) * 2 - 1) * jitter_us * NANOS_PER_MICRO;
            path.out += lean;
            path.back -= lean;
            let e: Exchange = world.exchange(&path, now);
            model.ingest(&e);
        }
        if has_point_source(rig) {
            let truth = world.true_offset(now);
            let e = claiming_no_uncertainty(world, "echo", truth, now, 20 * NANOS_PER_MILLI);
            model.ingest(&e);
        }
        model.synchronise();
    }
    let last = counter.load(Ordering::SeqCst);
    let mut out = Vec::new();
    for s in READS_S {
        counter.store(last + s * 1_000_000_000, Ordering::SeqCst);
        let outcome = match model.read() {
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
        };
        out.push((s, outcome));
    }
    out
}

/// What a read owes, by where its world sits against the band.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Owed {
    /// Refused or inside, or the property fails.
    Hold,
    /// Recorded and not graded: the world is outside the band the policy states.
    Info,
}

fn owed(policy_name: &str, policy: &Policy, world: &World, rounds: usize, read_s: u64) -> Owed {
    if rate_magnitude(world) <= policy.frequency_span_ppm / 2.0 {
        return Owed::Hold;
    }
    // The default holds a hundred parts per million before a fit inside the first minute on its
    // fixed allowances, and that is measured here rather than taken as read.
    if policy_name == "D" && rate_magnitude(world) <= 100.0 && rounds < 3 && read_s <= 60 {
        return Owed::Hold;
    }
    Owed::Info
}

fn run_policy(name: &'static str, policy: Policy) {
    // Where the grid goes when nobody asked for it: the temp directory, so an ordinary test run
    // leaves nothing in the crate.
    let dir = std::env::var("R181_OUT")
        .unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    let mut lines =
        vec!["# policy\tworld\trig\trounds\tread_s\towed\toutcome\twidth_ns\tdetail".to_string()];
    let mut failures = Vec::new();
    let mut inside = 0usize;
    let mut refused = 0usize;
    let mut outside_info = 0usize;
    for (wname, world) in worlds() {
        for rig in [Rig::J, Rig::P, Rig::L, Rig::A] {
            for rounds in ROUNDS {
                let res = catch_unwind(AssertUnwindSafe(|| run_cell(policy, &world, rig, rounds)));
                let reads = match res {
                    Ok(reads) => reads,
                    Err(_) => {
                        let line =
                            format!("{name}\t{wname}\t{rig:?}\t{rounds}\t-\tHold\tPANIC\t0\t");
                        failures.push(line.clone());
                        lines.push(line);
                        continue;
                    }
                };
                for (s, outcome) in reads {
                    let owed = owed(name, &policy, &world, rounds, s);
                    let (tag, width, detail) = match &outcome {
                        Outcome::Inside(w) => {
                            inside += 1;
                            ("INSIDE", *w, String::new())
                        }
                        Outcome::Outside(w, past) => {
                            if owed == Owed::Info {
                                outside_info += 1;
                            }
                            (
                                "OUTSIDE",
                                *w,
                                format!("truth {past} ns past the nearer end"),
                            )
                        }
                        Outcome::Refused(r) => {
                            refused += 1;
                            ("REFUSED", 0, r.chars().take(160).collect())
                        }
                    };
                    let line =
                        format!("{name}\t{wname}\t{rig:?}\t{rounds}\t{s}\t{owed:?}\t{tag}\t{width}\t{detail}");
                    if owed == Owed::Hold && tag == "OUTSIDE" {
                        failures.push(line.clone());
                    }
                    lines.push(line);
                }
            }
        }
    }
    let summary = format!(
        "R181|{name}\tfault={:?}\tinside={inside}\trefused={refused}\toutside_graded={}\toutside_info={outside_info}",
        policy.fault(),
        failures.len()
    );
    println!("{summary}");
    lines.insert(0, format!("# {summary}"));
    std::fs::write(format!("{dir}/{name}.tsv"), lines.join("\n") + "\n").expect("write the grid");
    assert!(
        failures.is_empty(),
        "{name}: {} reads signed an interval with the truth outside on a world inside the band:\n{}",
        failures.len(),
        failures.iter().take(12).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn d_the_shipped_policy() {
    run_policy("D", d());
}

#[test]
fn n28_the_narrowest_policy_the_validator_accepts() {
    run_policy("N28", narrowest());
}

#[test]
fn n12_coverage_one_and_no_allowances() {
    run_policy("N12", no_allowances());
}

#[test]
fn n35_no_allowances_and_no_ceiling() {
    let (name, policy) = policies().into_iter().find(|(n, _)| *n == "N35").unwrap();
    run_policy(name, policy);
}

#[test]
fn c1_coverage_one_alone() {
    run_policy(
        "C1",
        Policy {
            coverage_factor: 1.0,
            ..d()
        },
    );
}

#[test]
fn w_the_widest_band() {
    let (name, policy) = policies().into_iter().find(|(n, _)| *n == "W").unwrap();
    run_policy(name, policy);
}

#[test]
fn n28w_the_narrowest_policy_with_a_band_that_reaches_every_world() {
    let (name, policy) = policies().into_iter().find(|(n, _)| *n == "N28W").unwrap();
    run_policy(name, policy);
}

/// The two attacks that found the fault, asserted on their own cells so a failure names them.
#[test]
fn n28_and_b7c1_by_name() {
    // N28: nine seconds after one round, drifting forty parts per million, alpha and the point
    // source only, the narrowest policy.
    for world in [World::drifting(0, 40.0), World::drifting(3000, -40.0)] {
        for rounds in [1, 2] {
            let reads = run_cell(narrowest(), &world, Rig::A, rounds);
            let (_, at_nine) = reads.iter().find(|(s, _)| *s == 9).unwrap();
            assert!(
                !matches!(at_nine, Outcome::Outside(..)),
                "N28 after {rounds} rounds at 9 s: {at_nine:?}"
            );
        }
    }
    // B7C1: the shipped policy, four honest local sources, one and two rounds, a machine drifting a
    // hundred parts per million, every read to sixty seconds.
    for rounds in [1, 2] {
        let reads = run_cell(d(), &World::drifting(0, 100.0), Rig::L, rounds);
        for (s, outcome) in reads.iter().filter(|(s, _)| *s <= 60) {
            assert!(
                !matches!(outcome, Outcome::Outside(..)),
                "B7C1 after {rounds} rounds at {s} s: {outcome:?}"
            );
        }
    }
}
