//! An input to the bound arithmetic that is not a policy field is refused, or the bound holds the
//! truth.
//!
//! `Policy::fault` ranges every policy field, and `a_bad_policy.rs` holds it to that. The
//! arithmetic takes four more kinds of input that no validator sees: the four timestamps of an
//! exchange, what a source states about its own uncertainty, the platform's counter granularity,
//! and the counter reading a round or a stamp is taken at. On the evening of 2026-09-17 a cold set
//! (`tests/build-checks/2026-09-17-181-3/attacks.tsv` under the product root) found each of the
//! first, second and fourth reaching the width unchecked: a source timestamp at the integer's edge
//! panicked inside `Sample::from_exchange`, a reply stamped as arriving before its request was read
//! as a round trip of nought, a reply stamped `u64::MAX` on the counter held the model's idea of now
//! in the far future, and a counter stepped back sixty seconds after the last round read a bound
//! with no holdover in it and the truth outside it.
//!
//! Every case here is one of those, on the rig that set used, and the question is the one the
//! set asks: the model refuses with a typed refusal, or the interval it signs holds
//! `World::true_offset` at the read instant. Narrower is not a failure.

mod common;

use common::{Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy, RejectedExchange};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, Stamp, UnixNanos, Validity};
use timewitness_sources::Exchange;

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The shipped policy with the independence floor lowered, because the four simulated sources are
/// four operators and the floor has tests of its own elsewhere.
fn shipped() -> Policy {
    Policy {
        min_operators: 2,
        ..Policy::default()
    }
}

struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
}

impl Rig {
    fn new(world: World, policy: Policy) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
        }
    }

    /// Sixteen rounds at 32 s over four honest sources whose paths lean by a moving amount, with
    /// `tamper` applied to alpha's exchange every round.
    fn run(&mut self, rounds: i128, tamper: impl Fn(&mut Exchange)) -> Validity {
        let paths = [
            Path::honest("alpha", 12, 1),
            Path::honest("bravo", 24, 2),
            Path::honest("charlie", 8, 1),
            Path::honest("delta", 40, 3),
        ];
        let mut last = Validity::NeverSynchronised;
        for round in 0..rounds {
            if round > 0 {
                self.clock.advance_seconds(32);
            }
            let jitter_us = 120 + (round % 5) * 90;
            let now = self.clock.now();
            for (n, path) in paths.iter().enumerate() {
                let lean = ((n as i128 % 2) * 2 - 1) * jitter_us * NANOS_PER_MICRO;
                let mut path = path.clone();
                path.out += lean;
                path.back -= lean;
                let mut e = self.world.exchange(&path, now);
                if n == 0 {
                    tamper(&mut e);
                }
                self.model.ingest(&e);
            }
            last = self.model.synchronise();
        }
        last
    }

    /// Read at `at` seconds from the last round, negative meaning before it.
    fn read_at(&self, at: i64) -> Result<Stamp, Validity> {
        let base = self.clock.now().as_nanos() as i128;
        let target = base + (at as i128) * NANOS_PER_SEC;
        let counter = TestClock::starting_at(target.clamp(0, u64::MAX as i128) as u64);
        // The model holds its own clock handle, so the reading is taken by moving the shared
        // counter and putting it back afterwards.
        let now = self.clock.now();
        let delta = counter.now().as_nanos() as i128 - now.as_nanos() as i128;
        if delta >= 0 {
            self.clock.advance(delta as u64);
        } else {
            // TestClock only advances, so a backwards read rebuilds the position from nought.
            let back = (-delta) as u64;
            let restore = self.clock.now().as_nanos() - back;
            step_back(&self.clock, back);
            debug_assert_eq!(self.clock.now().as_nanos(), restore);
        }
        let out = self.model.read().map_err(|r| r.validity);
        // Put the counter back where the rounds left it.
        let here = self.clock.now().as_nanos() as i128;
        let want = now.as_nanos() as i128;
        if want >= here {
            self.clock.advance((want - here) as u64);
        } else {
            step_back(&self.clock, (here - want) as u64);
        }
        out
    }

    fn holds_truth(&self, stamp: &Stamp) -> bool {
        let truth = self.world.utc(stamp.reading.monotonic);
        stamp.bound.earliest <= truth && truth <= stamp.bound.latest
    }

    /// Refused, or the truth is inside, at every read from before the last round to past the
    /// holdover ceiling.
    fn refuses_or_holds(&self, what: &str) {
        // Negative reads before the model's origin clamp to the counter's nought, which is before
        // the origin on every world here, and are refused for that reason.
        for at in [-900, -400, -60, 0, 32, 120, 900, 1800, 3600, 3601] {
            match self.read_at(at) {
                Ok(stamp) => assert!(
                    self.holds_truth(&stamp),
                    "{what}: at {at} s the model signed {} ns wide with the truth outside",
                    stamp.bound.width()
                ),
                Err(validity) => assert!(!validity.is_valid(), "{what}: refused as valid"),
            }
        }
    }
}

/// `TestClock` only goes forward, so a backwards step wraps the counter round through nought,
/// which `MonotonicNanos` holds as a plain `u64`.
fn step_back(clock: &TestClock, by: u64) {
    clock.advance(u64::MAX - by + 1);
}

fn honest(e: &mut Exchange) {
    let _ = e;
}

#[test]
fn the_rig_itself_holds_the_truth_on_every_world_it_grades() {
    // The property is graded against worlds the shipped policy holds on. This is the check that it
    // does, so a failure below is the attack's and not the rig's.
    for (name, world) in worlds() {
        for rounds in [1, 2, 3, 16] {
            let mut rig = Rig::new(world, shipped());
            assert_eq!(
                rig.run(rounds, honest),
                Validity::Valid,
                "{name} after {rounds}"
            );
            rig.refuses_or_holds(&format!("default on {name} after {rounds} rounds"));
        }
    }
}

fn worlds() -> Vec<(&'static str, World)> {
    vec![
        ("still", World::still(0)),
        ("drifting +12", World::drifting(0, 12.0)),
        ("drifting -12", World::drifting(0, -12.0)),
        ("drifting +40", World::drifting(0, 40.0)),
        (
            "changing rate",
            World::drifting(0, 12.0).changing_rate(400, 30.0),
        ),
        ("disciplined elsewhere", World::disciplined_elsewhere(12.0)),
    ]
}

#[test]
fn a_source_timestamp_at_the_integer_edge_is_refused_and_never_panics() {
    // Every combination of the source's two timestamps at i128::MIN and i128::MAX, and each on its
    // own: nine cases, and each was a subtract or add with overflow at 3399099 (C34 of the set at
    // `tests/deep-test/2026-09-17-t8/frozen/r181/attacks.tsv` under the product root).
    let extremes = [None, Some(i128::MIN), Some(i128::MAX)];
    for t2 in extremes {
        for t3 in extremes {
            if t2.is_none() && t3.is_none() {
                continue;
            }
            let mut rig = Rig::new(World::drifting(0, 40.0), shipped());
            let world = rig.world;
            let mut e = world.exchange(&Path::honest("alpha", 12, 1), rig.clock.now());
            if let Some(v) = t2 {
                e.t2 = UnixNanos(v);
            }
            if let Some(v) = t3 {
                e.t3 = UnixNanos(v);
            }
            assert_eq!(
                rig.model.ingest(&e),
                Some(RejectedExchange::TimestampOutOfRange),
                "t2 {t2:?} t3 {t3:?}"
            );
            // And with the same exchange tampered every round, the three honest sources carry the
            // bound and it holds the truth.
            assert_eq!(
                rig.run(16, |e| {
                    if let Some(v) = t2 {
                        e.t2 = UnixNanos(v);
                    }
                    if let Some(v) = t3 {
                        e.t3 = UnixNanos(v);
                    }
                }),
                Validity::Valid
            );
            rig.refuses_or_holds("timestamps at the edge");
        }
    }
}

#[test]
fn a_reply_stamped_before_its_request_is_refused_rather_than_read_as_instant() {
    // At 3399099 the saturating subtraction read this as a round trip of nought, which is the
    // shortest there is and so the sample the window preferred for the rest of the run (C32 of the same set).
    let mut rig = Rig::new(World::drifting(0, 12.0), shipped());
    let now = rig.clock.now();
    let mut e = rig.world.exchange(&Path::honest("alpha", 12, 1), now);
    e.mono_t4 = MonotonicNanos(e.mono_t1.as_nanos() - 1);
    assert_eq!(
        rig.model.ingest(&e),
        Some(RejectedExchange::HomeBeforeItLeft)
    );
    e.mono_t4 = MonotonicNanos(e.mono_t1.as_nanos() - 20_000_000);
    assert_eq!(
        rig.model.ingest(&e),
        Some(RejectedExchange::HomeBeforeItLeft)
    );
    assert_eq!(
        rig.run(16, |e| e.mono_t4 =
            MonotonicNanos(e.mono_t1.as_nanos() - 20_000_000)),
        Validity::Valid
    );
    rig.refuses_or_holds("reply before request");
}

#[test]
fn a_request_stamped_before_the_model_started_is_refused() {
    let mut rig = Rig::new(World::still(0), shipped());
    let now = rig.clock.now();
    let mut e = rig.world.exchange(&Path::honest("alpha", 12, 1), now);
    e.mono_t1 = MonotonicNanos(0);
    e.mono_t4 = MonotonicNanos(0);
    assert_eq!(
        rig.model.ingest(&e),
        Some(RejectedExchange::BeforeTheModelStarted)
    );
    let mut e = rig.world.exchange(&Path::honest("alpha", 12, 1), now);
    e.mono_t1 = MonotonicNanos(rig.world.mono0.as_nanos() - 1);
    assert_eq!(
        rig.model.ingest(&e),
        Some(RejectedExchange::BeforeTheModelStarted)
    );
}

#[test]
fn a_reply_stamped_in_the_far_future_cannot_hold_the_model_fresh() {
    // At 3399099 a reply with `mono_t4` at `u64::MAX` became the newest exchange, every later
    // reading measured nought elapsed from it, and the truth was outside from fifteen minutes on
    // (cold set D23). That one is refused at the door, because its local end is past the range
    // any term is carried in. One stamped an hour ahead is inside the range and is taken; what
    // holds the truth then is that a reading before the reply came home is measured from the
    // moment the request went out, so the hour buys the source nothing.
    let mut rig = Rig::new(World::drifting(0, 12.0), shipped());
    let now = rig.clock.now();
    let mut e = rig.world.exchange(&Path::honest("alpha", 12, 1), now);
    e.mono_t4 = MonotonicNanos(u64::MAX);
    assert_eq!(
        rig.model.ingest(&e),
        Some(RejectedExchange::TimestampOutOfRange)
    );
    assert_eq!(
        rig.run(2, |e| e.mono_t4 = MonotonicNanos(u64::MAX)),
        Validity::Valid
    );
    rig.refuses_or_holds("reply at u64::MAX");
    for rounds in [1, 2, 3, 16] {
        let mut rig = Rig::new(World::drifting(0, 12.0), shipped());
        assert_eq!(
            rig.run(rounds, |e| e.mono_t4 =
                e.mono_t1.advanced(3_600 * NANOS_PER_SEC)),
            Validity::Valid
        );
        rig.refuses_or_holds("reply an hour ahead");
    }
}

#[test]
fn a_source_stating_an_uncertainty_no_clock_can_have_is_refused() {
    let mut rig = Rig::new(World::drifting(0, 12.0), shipped());
    let now = rig.clock.now();
    for (delay, dispersion) in [(-1, 0), (0, -1), (i128::MAX, 0), (0, i128::MAX)] {
        let mut e = rig.world.exchange(&Path::honest("alpha", 12, 1), now);
        e.root_delay = delay;
        e.root_dispersion = dispersion;
        assert_eq!(
            rig.model.ingest(&e),
            Some(RejectedExchange::StatedUncertaintyOutOfRange),
            "delay {delay} dispersion {dispersion}"
        );
    }
    assert_eq!(
        rig.run(16, |e| {
            e.root_dispersion = i128::MAX;
            e.root_delay = i128::MAX;
        }),
        Validity::Valid
    );
    rig.refuses_or_holds("stated uncertainty at the edge");
}

#[test]
fn a_reading_before_the_last_exchange_is_extrapolated_backwards_and_not_taken_as_fresh() {
    // The counter stepped back after the rounds. At 3399099 a read sixty seconds before the newest
    // exchange got the width of the moment of synchronisation and no holdover (C30 of the same set), and nine
    // hundred seconds before it on a clock drifting at forty parts per million the truth was
    // outside (cold set D17). The reading is as far from the exchange as one that far after it,
    // and the interval has to say so.
    for (name, world) in worlds() {
        for rounds in [1, 2, 3, 16] {
            let mut rig = Rig::new(world, shipped());
            assert_eq!(rig.run(rounds, honest), Validity::Valid);
            rig.refuses_or_holds(&format!("backwards on {name} after {rounds} rounds"));
            let forward = rig.read_at(600).map(|s| s.bound.width());
            let backward = rig.read_at(-600).map(|s| s.bound.width());
            let (Ok(forward), Ok(backward)) = (forward, backward) else {
                continue;
            };
            // The exchange's own round trip is inside the forward figure and not the backward
            // one, so they agree to within a round trip's growth rather than exactly.
            let slack: Nanos = 2 * 200 * NANOS_PER_MICRO;
            assert!(
                (forward - backward).abs() <= slack,
                "{name} after {rounds}: 600 s forward is {forward} ns wide and 600 s backward is \
                 {backward} ns, which is not the same distance"
            );
        }
    }
    // And the fitted rate is run the other way over the distance, so the point estimate stays
    // near the truth: forty parts per million over four hundred seconds is sixteen milliseconds,
    // which is what the correction removes and what running it the wrong way would double.
    let mut rig = Rig::new(World::drifting(0, 40.0), shipped());
    assert_eq!(rig.run(16, honest), Validity::Valid);
    let stamp = rig.read_at(-400).expect("inside the holdover ceiling");
    let truth = rig.world.utc(stamp.reading.monotonic);
    let miss = (stamp.reading.utc_estimate.as_nanos() - truth.as_nanos()).abs();
    assert!(
        miss < 4 * NANOS_PER_MILLI_,
        "four hundred seconds before the fit, the point estimate is {miss} ns from the truth"
    );
}

const NANOS_PER_MILLI_: Nanos = 1_000_000;

#[test]
fn a_reading_before_the_last_exchange_is_refused_past_the_holdover_ceiling() {
    let mut rig = Rig::new(
        World::still(0),
        Policy {
            max_holdover: 200 * NANOS_PER_SEC,
            ..shipped()
        },
    );
    assert_eq!(rig.run(16, honest), Validity::Valid);
    match rig.read_at(-201) {
        Err(Validity::HoldoverExceeded { .. }) => {}
        other => panic!("past the ceiling before the last exchange read {other:?}"),
    }
    match rig.read_at(-3601) {
        Err(Validity::CounterBeforeStart { .. }) => {}
        other => panic!("before the model started read {other:?}"),
    }
}

#[test]
fn a_counter_stepped_back_between_two_rounds_leaves_the_bound_holding_the_truth() {
    for (name, world) in worlds() {
        let mut rig = Rig::new(world, shipped());
        let paths = [
            Path::honest("alpha", 12, 1),
            Path::honest("bravo", 24, 2),
            Path::honest("charlie", 8, 1),
            Path::honest("delta", 40, 3),
        ];
        for round in 0..16u64 {
            if round > 0 {
                rig.clock.advance_seconds(32);
            }
            if round == 9 {
                step_back(&rig.clock, 100 * NANOS_PER_SEC as u64);
            }
            let now = rig.clock.now();
            for p in &paths {
                let e = rig.world.exchange(p, now);
                rig.model.ingest(&e);
            }
            rig.model.synchronise();
        }
        rig.refuses_or_holds(&format!("counter back mid-run on {name}"));
    }
}

#[test]
fn the_platform_granularity_is_held_to_its_range() {
    for granularity in [i128::MIN, -1, 0, i128::MAX] {
        let world = World::drifting(0, 12.0);
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(
            shipped(),
            Box::new(ClockHandle(clock.clone())),
            wall,
            granularity,
        );
        let mut rig = Rig {
            clock,
            world,
            model,
        };
        assert_eq!(
            rig.run(16, honest),
            Validity::Valid,
            "granularity {granularity}"
        );
        rig.refuses_or_holds(&format!("granularity {granularity}"));
    }
}
