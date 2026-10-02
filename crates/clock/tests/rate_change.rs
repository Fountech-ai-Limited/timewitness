//! What happens to the bound when the oscillator changes rate during holdover.
//!
//! The model fits a line through the last few synchronisations, corrects the reading by the fitted
//! frequency, and widens for how wrong that frequency could be. The correction is worth having and
//! the widening is where the trouble was: it allowed fifteen parts per million, which is NTP's
//! `PHI`, and `PHI` bounds the total frequency error of an extrapolation that has not been
//! corrected. Applying the same figure to what is left after correcting is applying it to a
//! different quantity.
//!
//! So a rate that was one value while the model was measuring it and another value afterwards put
//! true UTC outside a receipt that signed and validated cleanly: 79.669 ms outside at a forty parts
//! per million change, which is more than the whole of the product's stated honest range and is an
//! ordinary temperature change rather than an attack.
//!
//! The suite could not see it because `common/mod.rs` modelled drift as one constant, so the one
//! condition that breaks the bound was the one condition the harness could not build. It can now.
//!
//! Every test here was watched failing before it was allowed to pass, and the two policy fields it
//! defends were each planted out afterwards and watched failing again.

mod common;

use common::{four_honest_sources, Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{MonotonicNanos, UnixNanos, Validity};

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn new(world: World, paths: Vec<Path>, policy: Policy) -> Self {
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

    fn now(&self) -> MonotonicNanos {
        self.clock.now()
    }

    fn run_for(&mut self, rounds: usize, spacing_s: u64) -> Validity {
        let mut last = Validity::NeverSynchronised;
        for i in 0..rounds {
            if i > 0 {
                self.clock.advance_seconds(spacing_s);
            }
            let now = self.now();
            for p in &self.paths {
                let e = self.world.exchange(p, now);
                self.model.ingest(&e);
            }
            last = self.model.synchronise();
        }
        last
    }

    fn truth(&self) -> UnixNanos {
        self.world.utc(self.now())
    }
}

/// Twenty rounds at sixty-four seconds, which is the ordinary poll interval, then the sources go
/// away and the rate changes at the same moment.
///
/// Returns the worst distance from true UTC to the reported interval over the holdover, in
/// nanoseconds, and zero where every reading held the truth or refused.
fn worst_miss_after(change_ppm: f64, holdover_minutes: &[u64], policy: Policy) -> Nanos {
    let rounds = 20u64;
    let spacing = 64u64;
    let settled_at = rounds.saturating_sub(1) * spacing;

    let mut worst = 0;
    for minutes in holdover_minutes {
        let world = World::drifting(0, 8.0).changing_rate(settled_at, 8.0 + change_ppm);
        let mut rig = Rig::new(world, four_honest_sources(), policy);
        assert_eq!(rig.run_for(rounds as usize, spacing), Validity::Valid);

        rig.clock.advance_seconds(minutes * 60);
        let Ok(stamp) = rig.model.read() else {
            // A refusal is the honest answer past the point where the model can support an
            // interval, and it is never a miss.
            continue;
        };
        let truth = rig.truth();
        let miss = if stamp.bound.contains(truth) {
            0
        } else {
            (truth.as_nanos() - stamp.bound.earliest.as_nanos())
                .abs()
                .min((truth.as_nanos() - stamp.bound.latest.as_nanos()).abs())
        };
        worst = worst.max(miss);
    }
    worst
}

/// The holdover points the second sweep covered, in minutes.
const SWEEP: [u64; 9] = [1, 2, 5, 10, 15, 23, 30, 38, 55];

// ---------------------------------------------------------------------------
// The property: at every reading the model either refuses or holds the truth
// ---------------------------------------------------------------------------

#[test]
fn the_bound_holds_the_truth_when_the_rate_changes_during_holdover() {
    // The table from the second sweep, and the figures beside each row are what the model reported
    // before this was fixed: 3.837 ms at 18 ppm, 10.917 ms at 20, 79.669 ms at 40, 294.117 ms at
    // 100. Every one of them signed and validated cleanly.
    for change in [16.0, 18.0, 20.0, 40.0, 100.0] {
        let miss = worst_miss_after(change, &SWEEP, common::arithmetic_policy());
        assert_eq!(
            miss, 0,
            "a {change} ppm change in the oscillator's rate put true UTC {miss} ns outside a bound \
             the model was prepared to sign"
        );
    }
}

#[test]
fn a_rate_that_falls_is_no_different_from_one_that_rises() {
    for change in [-16.0, -20.0, -40.0, -100.0] {
        let miss = worst_miss_after(change, &SWEEP, common::arithmetic_policy());
        assert_eq!(
            miss, 0,
            "a {change} ppm change left the truth {miss} ns out"
        );
    }
}

#[test]
fn path_jitter_does_not_rescue_it_and_does_not_have_to() {
    // Five milliseconds of asymmetry on every path, which is what the sweep used to check that the
    // miss was the extrapolation rather than the network.
    let paths: Vec<Path> = four_honest_sources()
        .into_iter()
        .map(|p| p.with_split(0.75))
        .collect();

    for change in [20.0, 40.0] {
        let settled_at = 19 * 64;
        for minutes in SWEEP {
            let world = World::drifting(0, 8.0).changing_rate(settled_at, 8.0 + change);
            let mut rig = Rig::new(world, paths.clone(), common::arithmetic_policy());
            assert_eq!(rig.run_for(20, 64), Validity::Valid);
            rig.clock.advance_seconds(minutes * 60);
            if let Ok(stamp) = rig.model.read() {
                assert!(
                    stamp.bound.contains(rig.truth()),
                    "a {change} ppm change at {minutes} minutes of holdover on a skewed path left \
                     the bound {:?} without the truth",
                    stamp.bound
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The two allowances the property rests on, each tested on its own
// ---------------------------------------------------------------------------

#[test]
fn the_allowance_for_the_rate_moving_is_what_holds_the_truth() {
    // The same forty parts per million change at two settings of the one policy field. With the
    // allowance switched off the model misses; with it on, it does not. Sever the field from the
    // arithmetic and both runs come out the same, so this fails either way round.
    let without = Policy {
        frequency_span_ppm: 0.0,
        frequency_slew_ppm_per_second: 0.0,
        ..common::arithmetic_policy()
    };
    assert!(
        worst_miss_after(40.0, &SWEEP, without) > 0,
        "with no allowance for the rate moving, a forty parts per million change has to miss, and \
         if it does not then this test is measuring nothing"
    );
    assert_eq!(
        worst_miss_after(40.0, &SWEEP, common::arithmetic_policy()),
        0
    );
}

#[test]
fn the_frequency_floor_binds_when_the_regression_is_confident() {
    // The floor exists for the case where the model's own measurement of its frequency error comes
    // out tighter than the hardware can support. Four tight sources over a long baseline give a
    // regression standard error well under the floor, so the floor is what sets the widening.
    //
    // The two allowances for the rate moving are switched off, because they are much the larger
    // term and would hide the floor entirely. That isolation is the point: before this test the
    // floor could be deleted from the source with all 281 tests still passing.
    let tight = vec![
        Path::honest("alpha", 1, 0),
        Path::honest("bravo", 1, 0),
        Path::honest("charlie", 1, 0),
        Path::honest("delta", 1, 0),
    ];
    let base = Policy {
        frequency_span_ppm: 0.0,
        frequency_slew_ppm_per_second: 0.0,
        max_bound_width: NANOS_PER_SEC,
        ..common::arithmetic_policy()
    };

    let width_at = |floor_ppm: f64| -> Nanos {
        let policy = Policy {
            frequency_floor_ppm: floor_ppm,
            ..base
        };
        let mut rig = Rig::new(World::drifting(0, 8.0), tight.clone(), policy);
        assert_eq!(rig.run_for(28, 64), Validity::Valid);
        let settled = rig.model.read().unwrap().bound.width();
        rig.clock.advance_seconds(1_200);
        rig.model.read().unwrap().bound.width() - settled
    };

    let floored = width_at(15.0);
    let unfloored = width_at(0.0);
    assert!(
        floored > unfloored,
        "the frequency floor changes nothing over twenty minutes of holdover: {floored} ns of \
         growth against {unfloored} ns, so the regression is already above the floor and this \
         source set cannot see it"
    );
    // Twenty minutes at fifteen parts per million is eighteen milliseconds on each side.
    let expected = 2 * 18 * NANOS_PER_MILLI;
    assert!(
        floored >= expected,
        "twenty minutes of holdover grew the bound by {floored} ns and the floor alone is {expected} ns"
    );
}

#[test]
fn the_allowance_grows_with_the_gap_and_then_stops_growing() {
    // The rate cannot jump and it cannot wander for ever, so the allowance is the smaller of a slew
    // over the elapsed time and the whole band the part is specified across. Both halves are
    // checked here: doubling the gap early more than doubles the widening, and past the cap it does
    // not.
    let mut rig = Rig::new(
        World::drifting(0, 4.0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    assert_eq!(rig.run_for(20, 64), Validity::Valid);

    let at = |seconds: u64| -> Nanos {
        let mut probe = Rig::new(
            World::drifting(0, 4.0),
            four_honest_sources(),
            common::arithmetic_policy(),
        );
        probe.run_for(20, 64);
        probe.clock.advance_seconds(seconds);
        probe.model.read().map(|s| s.bound.width()).unwrap_or(-1)
    };

    let settled = at(0);
    let per_second = |seconds: u64| -> f64 { (at(seconds) - settled) as f64 / seconds as f64 };

    // While the slew is what binds, the widening per second of gap is itself growing, because the
    // rate has had longer to move. This is the comparison that separates an allowance which grows
    // with the gap from a flat one: on a flat allowance the fixed part of the widening amortises
    // over a longer gap and this figure falls instead of rising. At the fifteen parts per million
    // the model carried until today it went from 130,000 ns per second at ten seconds to 46,667 at
    // sixty.
    let early = per_second(10);
    let later = per_second(60);
    assert!(
        later > early,
        "under the cap the widening per second should be growing with the gap, and it went from \
         {early:.0} ns per second at ten seconds to {later:.0} at sixty"
    );

    // Past the cap the rate cannot have moved any further, so the widening per second flattens.
    let capped = per_second(400);
    let more_capped = per_second(800);
    assert!(
        (capped - more_capped).abs() < capped * 0.05,
        "past the cap the widening per second should be flat, and it is {capped:.0} at four \
         hundred seconds against {more_capped:.0} at eight hundred"
    );
    assert!(
        more_capped > later,
        "and the capped figure should still be the larger one: {more_capped:.0} against {later:.0}"
    );
}

#[test]
fn the_model_refuses_rather_than_extrapolating_through_a_rate_it_cannot_bound() {
    // The bound-width ceiling is what stops the holdover at the default policy, and it stops it
    // long before the hour the holdover ceiling allows. That is the honest outcome: an hour of
    // holdover on a machine whose crystal is warming up is not something to put a number on.
    let mut rig = Rig::new(
        World::drifting(0, 8.0),
        four_honest_sources(),
        common::arithmetic_policy(),
    );
    assert_eq!(rig.run_for(20, 64), Validity::Valid);

    rig.clock.advance_seconds(55 * 60);
    match rig.model.read() {
        Ok(stamp) => panic!(
            "fifty-five minutes of holdover produced a {} ns bound rather than a refusal",
            stamp.bound.width()
        ),
        Err(refusal) => assert!(
            matches!(refusal.validity, Validity::BoundTooWide { .. }),
            "expected the width ceiling to be what stops it, and got {:?}",
            refusal.validity
        ),
    }
}
