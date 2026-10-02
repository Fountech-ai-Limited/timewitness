//! What the clock model is asked to do.
//!
//! Every test here works against a simulated network whose true offset is a number the test wrote
//! down, so an assertion about the bound is a question about whether the interval holds the truth
//! rather than a question about whether the model agrees with itself.

mod common;

use common::{four_honest_sources, Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, SmearPolicy, SourceKind, Timescale, Validity};

use std::sync::Arc;

/// A model wired to a clock the test drives, with the sources polled once at the current instant.
struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn new(world: World, paths: Vec<Path>) -> Self {
        Self::with_policy(world, paths, common::arithmetic_policy())
    }

    fn with_policy(world: World, paths: Vec<Path>, policy: Policy) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
            paths,
        }
    }

    /// Poll every source once and run a selection round.
    fn poll_and_synchronise(&mut self) -> Validity {
        let now = self.clock.now_value();
        for p in &self.paths {
            let e = self.world.exchange(p, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }

    /// Poll and synchronise `rounds` times, `spacing_s` apart.
    fn run_for(&mut self, rounds: usize, spacing_s: u64) -> Validity {
        let mut last = Validity::NeverSynchronised;
        for i in 0..rounds {
            if i > 0 {
                self.clock.advance_seconds(spacing_s);
            }
            last = self.poll_and_synchronise();
        }
        last
    }

    /// True UTC right now, which is what the bound has to contain.
    fn truth(&self) -> timewitness_core::UnixNanos {
        self.world.utc(self.clock.now_value())
    }
}

/// A handle so the test and the model share one counter.
struct ClockHandle(Arc<TestClock>);

impl timewitness_clock::MonotonicClock for ClockHandle {
    fn now(&self) -> timewitness_core::MonotonicNanos {
        self.0.now()
    }
}

trait TestClockExt {
    fn now_value(&self) -> timewitness_core::MonotonicNanos;
}

impl TestClockExt for TestClock {
    fn now_value(&self) -> timewitness_core::MonotonicNanos {
        use timewitness_clock::MonotonicClock;
        self.now()
    }
}

#[test]
fn a_local_read_returns_a_reading_and_a_bound() {
    let mut rig = Rig::new(World::still(6), four_honest_sources());
    assert_eq!(rig.run_for(6, 64), Validity::Valid);

    let stamp = rig.model.read().expect("a synchronised model answers");

    assert!(
        stamp.bound.width() > 0,
        "a bound with no width is a claim nobody can support"
    );
    assert!(stamp.estimate_within_bound());
    assert!(
        stamp.bound.contains(rig.truth()),
        "the bound {:?} does not hold the true time {:?}",
        stamp.bound,
        rig.truth()
    );
    assert_eq!(stamp.bound.basis, EpsilonBasis::LocalModelOnly);
}

#[test]
fn the_reading_is_nanoseconds_and_the_bound_is_milliseconds() {
    // Resolution is not accuracy, as an assertion rather than a sentence. The reading carries
    // every nanosecond the counter offered. The bound is quoted at the scale the network allows
    // and is far wider.
    let mut rig = Rig::new(World::still(0), four_honest_sources());
    rig.run_for(6, 64);
    let stamp = rig.model.read().unwrap();

    assert!(stamp.reading.monotonic.as_nanos() > 0);
    assert!(
        stamp.bound.width() > NANOS_PER_MILLI,
        "a bound of {} ns over the public internet is not a figure anybody measured",
        stamp.bound.width()
    );
    assert!(stamp.bound.width_millis() < 250.0);
}

#[test]
fn a_source_fed_a_wrong_interval_is_discarded_rather_than_averaged_in() {
    // Five sources, one of them eight hundred milliseconds out. Marzullo throws it away. A mean
    // over the five would have dragged the answer a hundred and sixty milliseconds off the truth.
    let liar_error = 800 * NANOS_PER_MILLI;
    let mut paths = four_honest_sources();
    paths.push(Path::honest("echo", 10, 1).lying_by(liar_error));

    let mut rig = Rig::new(World::still(6), paths);
    assert_eq!(rig.run_for(6, 64), Validity::Valid);

    let stamp = rig.model.read().unwrap();

    let liar = stamp
        .sources
        .iter()
        .find(|s| s.id.as_str() == "echo")
        .unwrap();
    assert!(
        !liar.kept,
        "the source that disagreed with everybody was kept"
    );
    assert_eq!(stamp.sources.iter().filter(|s| s.kept).count(), 4);

    assert!(stamp.bound.contains(rig.truth()));

    // What a plain average of the five would have produced, for comparison. The gap between this
    // and the truth is the whole reason clocks are intersected rather than averaged.
    let mean_pull = liar_error / 5;
    let actual_error = (stamp.reading.utc_estimate - rig.truth()).abs();
    assert!(
        actual_error < mean_pull / 10,
        "the reading is {actual_error} ns from the truth, and a mean would have been {mean_pull} ns out"
    );
}

#[test]
fn two_sources_against_two_is_refused_rather_than_guessed() {
    let paths = vec![
        Path::honest("alpha", 10, 1),
        Path::honest("bravo", 10, 1),
        Path::honest("charlie", 10, 1).lying_by(500 * NANOS_PER_MILLI),
        Path::honest("delta", 10, 1).lying_by(500 * NANOS_PER_MILLI),
    ];
    let mut rig = Rig::new(World::still(0), paths);
    let outcome = rig.poll_and_synchronise();
    assert_eq!(
        outcome,
        Validity::NoMajority {
            present: 4,
            agreeing: 2
        }
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn fewer_sources_than_the_policy_needs_is_refused() {
    let paths = vec![Path::honest("alpha", 10, 1), Path::honest("bravo", 10, 1)];
    let mut rig = Rig::new(World::still(0), paths);
    assert_eq!(
        rig.poll_and_synchronise(),
        Validity::InsufficientSources {
            present: 2,
            required: 3
        }
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn the_survivors_are_weighted_and_not_meaned() {
    // One tight source and three loose ones, all honest, with the tight one nearest the truth by
    // construction because its interval is narrowest. The weighting has to be visible in the
    // answer: the reading sits within the tight source's own interval, which a plain mean over four
    // midpoints would not guarantee.
    let paths = vec![
        Path::honest("tight", 2, 0),
        Path::honest("loose-a", 60, 5),
        Path::honest("loose-b", 70, 6),
        Path::honest("loose-c", 80, 7),
    ];
    let mut rig = Rig::new(World::still(3), paths);
    rig.run_for(6, 64);
    let stamp = rig.model.read().unwrap();

    let error = (stamp.reading.utc_estimate - rig.truth()).abs();
    assert!(
        error < 2 * NANOS_PER_MILLI,
        "the tight source should dominate, and the reading is {error} ns out"
    );
}

#[test]
fn the_regression_recovers_the_frequency_the_machine_is_actually_drifting_at() {
    let mut rig = Rig::new(World::drifting(0, 12.0), four_honest_sources());
    assert_eq!(rig.run_for(20, 64), Validity::Valid);
    let stamp = rig.model.read().unwrap();
    // Twenty rounds at sixty-four seconds is a twenty minute baseline, which is long enough for the
    // model to stand behind a rate. A fit it will not stand behind reports `None`, and this test is
    // the other half of that rule: a good fit is still believed and still recovers the truth.
    let rate = stamp
        .frequency_ppm
        .expect("a twenty minute baseline supports a rate");
    assert!(
        (rate - 12.0).abs() < 3.0,
        "measured {rate} parts per million against a true 12"
    );
}

#[test]
fn a_read_needs_no_network_and_nothing_but_the_model() {
    // The model holds no sources. It cannot reach one, so a read cannot wait on a packet. The test
    // makes that concrete by dropping every path before reading.
    let mut rig = Rig::new(World::still(4), four_honest_sources());
    rig.run_for(6, 64);
    rig.paths.clear();

    let first = rig.model.read().unwrap();
    let second = rig.model.read().unwrap();
    assert!(second.reading.monotonic >= first.reading.monotonic);
    assert!(second.bound.contains(rig.truth()));
}

#[test]
fn the_model_exposes_what_every_source_is_doing() {
    let mut paths = four_honest_sources();
    paths[0].smear = SmearPolicy::Linear {
        window_seconds: 86_400,
    };
    paths[1].kind = SourceKind::Roughtime;
    paths[2].timescale = Timescale::Tai { offset_seconds: 37 };

    let mut rig = Rig::new(World::still(0), paths);
    rig.run_for(4, 64);
    let states = rig.model.source_states();

    assert_eq!(states.len(), 4);
    let alpha = states.iter().find(|s| s.id.as_str() == "alpha").unwrap();
    assert_eq!(
        alpha.smear,
        SmearPolicy::Linear {
            window_seconds: 86_400
        }
    );
    let bravo = states.iter().find(|s| s.id.as_str() == "bravo").unwrap();
    assert_eq!(bravo.kind, SourceKind::Roughtime);
    let charlie = states.iter().find(|s| s.id.as_str() == "charlie").unwrap();
    assert_eq!(charlie.timescale, Timescale::Tai { offset_seconds: 37 });
}

#[test]
fn a_source_answering_on_tai_is_brought_onto_utc_before_it_is_intersected() {
    let mut paths = four_honest_sources();
    paths[2].timescale = Timescale::Tai { offset_seconds: 37 };

    let mut rig = Rig::new(World::still(2), paths);
    assert_eq!(rig.run_for(4, 64), Validity::Valid);
    let stamp = rig.model.read().unwrap();

    // A source thirty-seven seconds away on an unconverted timescale would never have overlapped
    // the others, so its survival is the proof the conversion happened.
    let charlie = stamp
        .sources
        .iter()
        .find(|s| s.id.as_str() == "charlie")
        .unwrap();
    assert!(charlie.kept);
    assert!(stamp.bound.contains(rig.truth()));
}

#[test]
fn a_failed_round_leaves_the_last_good_synchronisation_in_place() {
    let mut rig = Rig::new(World::still(3), four_honest_sources());
    rig.run_for(6, 64);
    let before = rig.model.read().unwrap();

    // Every source goes quiet, so nothing new arrives and the next round has too few to work with.
    rig.paths.clear();
    rig.clock.advance_seconds(64);
    let outcome = rig.model.synchronise();
    assert!(matches!(
        outcome,
        Validity::Valid | Validity::InsufficientSources { .. }
    ));

    let after = rig
        .model
        .read()
        .expect("holdover carries on from the last good round");
    assert!(after.bound.width() >= before.bound.width());
    assert!(after.bound.contains(rig.truth()));
}

#[test]
fn the_bound_carries_a_breakdown_that_adds_up() {
    let mut rig = Rig::new(World::still(5), four_honest_sources());
    rig.run_for(8, 64);
    rig.clock.advance_seconds(300);
    let stamp = rig.model.read().unwrap();

    let b = stamp.bound.breakdown;
    let half = b.half_width();
    assert!(
        2 * half >= stamp.bound.width(),
        "the parts add to less than the whole"
    );
    assert!(
        2 * half <= stamp.bound.width() + 1,
        "the parts add to more than the whole"
    );

    // The network figure is reported and is not in the sum, because it already sits inside the
    // intersection term.
    assert!(b.widest_source_network_half > 0);
    assert!(
        b.oscillator_holdover > 0,
        "five minutes of holdover has to show up"
    );
}

#[test]
fn a_shorter_round_trip_gives_a_tighter_bound() {
    let lan = vec![
        Path::honest("a", 1, 0),
        Path::honest("b", 1, 0),
        Path::honest("c", 1, 0),
        Path::honest("d", 1, 0),
    ];
    let internet = vec![
        Path::honest("a", 40, 4),
        Path::honest("b", 44, 4),
        Path::honest("c", 38, 3),
        Path::honest("d", 50, 5),
    ];

    let mut near = Rig::new(World::still(0), lan);
    near.run_for(8, 64);
    let near_stamp = near.model.read().unwrap();

    let mut far = Rig::new(World::still(0), internet);
    far.run_for(8, 64);
    let far_stamp = far.model.read().unwrap();

    assert!(
        near_stamp.bound.width() < far_stamp.bound.width(),
        "a one millisecond path gave {} ns and a forty millisecond path gave {} ns",
        near_stamp.bound.width(),
        far_stamp.bound.width()
    );
}

#[test]
fn a_leap_second_with_mixed_smear_policies_is_refused() {
    let mut paths = four_honest_sources();
    paths[0] = paths[0].clone().announcing_leap();
    paths[1] = paths[1].clone().smearing(SmearPolicy::Linear {
        window_seconds: 86_400,
    });

    let mut rig = Rig::new(World::still(0), paths);
    let outcome = rig.poll_and_synchronise();
    assert!(
        matches!(outcome, Validity::TimescaleConflict { .. }),
        "expected a refusal near a leap event, got {outcome:?}"
    );
}

#[test]
fn away_from_a_leap_event_mixed_smear_policies_are_fine() {
    let mut paths = four_honest_sources();
    paths[1] = paths[1].clone().smearing(SmearPolicy::Linear {
        window_seconds: 86_400,
    });

    let mut rig = Rig::new(World::still(0), paths);
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
}

#[test]
fn a_policy_with_a_tighter_ceiling_refuses_a_bound_it_cannot_support() {
    let policy = Policy {
        max_bound_width: NANOS_PER_MILLI,
        ..common::arithmetic_policy()
    };

    let paths = vec![
        Path::honest("a", 80, 8),
        Path::honest("b", 90, 9),
        Path::honest("c", 70, 7),
        Path::honest("d", 100, 10),
    ];
    let mut rig = Rig::with_policy(World::still(0), paths, policy);
    assert_eq!(rig.run_for(4, 64), Validity::Valid);

    let refusal = rig
        .model
        .read()
        .expect_err("a bound wider than the ceiling has to be refused");
    assert!(matches!(
        refusal.validity,
        timewitness_core::Validity::BoundTooWide { .. }
    ));
}

#[test]
fn the_shortest_round_trip_in_the_window_is_the_one_used() {
    // The same source answers three times, once quickly on a symmetric path and twice slowly on
    // badly split ones. The quick sample is the one the model works from, so the answer stays near
    // the truth.
    let mut rig = Rig::new(World::still(0), four_honest_sources());

    let slow = Path::honest("alpha", 200, 1).with_split(1.0);
    let quick = Path::honest("alpha", 4, 1);
    let now = rig.clock.now_value();
    rig.model.ingest(&rig.world.exchange(&slow, now));
    rig.model.ingest(&rig.world.exchange(&quick, now));
    rig.model.ingest(&rig.world.exchange(&slow, now));

    for p in &four_honest_sources()[1..] {
        rig.model.ingest(&rig.world.exchange(p, now));
    }
    assert_eq!(rig.model.synchronise(), Validity::Valid);

    let stamp = rig.model.read().unwrap();
    assert!(stamp.bound.contains(rig.truth()));
    let alpha = stamp
        .sources
        .iter()
        .find(|s| s.id.as_str() == "alpha")
        .unwrap();
    assert!(
        alpha.kept,
        "the quick sample should have kept this source inside the majority"
    );
}

#[test]
fn seconds_of_holdover_show_up_as_nanoseconds_of_width() {
    let mut rig = Rig::new(World::still(0), four_honest_sources());
    rig.run_for(8, 64);
    let fresh = rig.model.read().unwrap().bound.width();

    rig.clock.advance_seconds(600);
    let held = rig.model.read().unwrap().bound.width();

    let grew_by = held - fresh;
    let floor: Nanos = (15.0 * (600 * NANOS_PER_SEC) as f64 / 1_000_000.0) as Nanos;
    assert!(
        grew_by >= floor,
        "ten minutes of holdover grew the bound by {grew_by} ns, and the oscillator floor alone is {floor} ns on each side"
    );
}
