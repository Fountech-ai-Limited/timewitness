//! One test per entry in `timewitness_clock::LossOfUtc`, and a test that there are no others.
//!
//! The enumeration says, for every way a reading can lose UTC, whether the model widens or refuses.
//! This file is what stops that being a comment. Each test names its entry, does the thing, and
//! asserts the response the entry claims; `the_list_is_covered_in_full` then asserts that the set of
//! entries named here is the whole of `LossOfUtc::ALL`, so a new entry with no test fails the suite.
//!
//! Four earlier fixes were each raised on this property and each finished on the examples the fix
//! happened to list, which is how a fifth fault in the same layer survived all four. A list with a
//! coverage test is the answer to that: the next fault is a missing entry, and a missing entry is a
//! red suite.

mod common;

use common::{claiming_no_uncertainty, stating_an_impossible_reply, Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, LossOfUtc, MonotonicClock, Policy, Response};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{LeapIndicator, MonotonicNanos, SmearPolicy, Stamp, UnixNanos, Validity};

use std::sync::Arc;

/// The window the large public smearing services spread a leap second across.
const DAY_SMEAR: SmearPolicy = SmearPolicy::Linear {
    window_seconds: 86_400,
};

/// A model wired to a counter the test drives.
struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn new(world: World, paths: Vec<Path>) -> Self {
        Self::with(world, paths, common::arithmetic_policy(), 0)
    }

    fn with(world: World, paths: Vec<Path>, policy: Policy, granularity: Nanos) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(
            policy,
            Box::new(ClockHandle(clock.clone())),
            wall,
            granularity,
        );
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

    fn poll_and_synchronise(&mut self) -> Validity {
        let now = self.now();
        for p in &self.paths {
            let e = self.world.exchange(p, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }

    /// Poll and synchronise `rounds` times, `spacing_s` apart, and insist every round succeeded.
    fn run_for(&mut self, rounds: usize, spacing_s: u64) {
        for i in 0..rounds {
            if i > 0 {
                self.clock.advance_seconds(spacing_s);
            }
            let v = self.poll_and_synchronise();
            assert_eq!(v, Validity::Valid, "round {i} of the healthy run");
        }
    }

    fn stamp(&self) -> Stamp {
        self.model.read().expect("this model can answer")
    }

    fn truth(&self) -> UnixNanos {
        self.world.utc(self.now())
    }
}

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

fn three_sources() -> Vec<Path> {
    vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
    ]
}

/// A policy that will not refuse on width while a test is asking about something else.
fn wide_enough() -> Policy {
    Policy {
        max_bound_width: 600 * NANOS_PER_SEC,
        ..common::arithmetic_policy()
    }
}

// ---------------------------------------------------------------------------------------------
// The ten that refuse.
// ---------------------------------------------------------------------------------------------

#[test]
fn nothing_measured_yet() {
    let rig = Rig::new(World::still(0), three_sources());
    assert_eq!(rig.model.validity(), Validity::NeverSynchronised);
    assert!(rig.model.read().is_err(), "there is nothing to answer with");
}

#[test]
fn too_few_sources() {
    let two = vec![Path::honest("alpha", 12, 1), Path::honest("bravo", 24, 2)];
    let mut rig = Rig::new(World::still(0), two);
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
fn no_majority_agrees() {
    // Three sources half a second apart from each other. No two intervals overlap, so nothing is a
    // majority and the model cannot say which of the three is the broken one.
    let apart = 500 * NANOS_PER_MILLI;
    let scattered = vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2).lying_by(apart),
        Path::honest("charlie", 8, 1).lying_by(-apart),
    ];
    let mut rig = Rig::new(World::still(0), scattered);
    let v = rig.poll_and_synchronise();
    assert!(
        matches!(v, Validity::NoMajority { .. }),
        "three sources that agree with nobody cannot produce a bound, got {v:?}"
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn majority_only_from_free_agreement() {
    // The entry textbook Marzullo would not have, added 2026-09-09 by a deliberate decision. Two
    // honest servers 10 s apart at a radius of 3 s agree nowhere, and one source stating a radius
    // of an hour turns that into a majority of two out of three. It is a real majority by the
    // published rule and the model refuses it, because the source that made it could not have been
    // put in the minority by anything the other two said.
    let policy = Policy {
        max_bound_width: 60 * NANOS_PER_SEC,
        min_sources: 2,
        ..common::arithmetic_policy()
    };
    let sources = vec![
        Path::honest("alpha", 20, 3_000),
        Path::honest("bravo", 20, 3_000).lying_by(10 * NANOS_PER_SEC),
        Path::honest("charlie", 20, 3_600_000),
    ];
    let mut rig = Rig::with(World::still(0), sources, policy, 0);
    let v = rig.poll_and_synchronise();
    assert_eq!(
        v,
        Validity::FreeMajority {
            present: 3,
            informative: 2
        },
        "the majority is the wide source's to give and the model has to refuse it, got {v:?}"
    );
    assert!(rig.model.read().is_err());
    assert_eq!(
        LossOfUtc::MajorityOnlyFromFreeAgreement.response(),
        Response::Refuses
    );
}

#[test]
fn source_disclaims_its_own_clock() {
    let mut paths = three_sources();
    paths[2].leap = LeapIndicator::Unsynchronised;
    let mut rig = Rig::new(World::still(0), paths);
    assert_eq!(
        rig.poll_and_synchronise(),
        Validity::InsufficientSources {
            present: 2,
            required: 3
        },
        "a source saying its own clock is wrong is not a candidate, so two are left"
    );
}

#[test]
fn reply_that_cannot_be_true() {
    let world = World::still(0);
    let mut rig = Rig::new(world, three_sources());
    let at = rig.now();
    let impossible = stating_an_impossible_reply(
        &rig.world,
        "hostile",
        0,
        at,
        2 * NANOS_PER_MILLI,
        10 * NANOS_PER_MILLI,
    );
    assert!(
        rig.model.ingest(&impossible).is_some(),
        "a reply whose own two timestamps cannot both be true never becomes a sample"
    );
}

#[test]
fn sources_disagree_across_a_leap() {
    // Three sources spreading the second and one inserting it, all announcing the leap. Neither
    // side is broken and they are a second apart, which is a second of error inside an interval
    // claiming milliseconds.
    let paths = vec![
        Path::honest("alpha", 12, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("bravo", 24, 2)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("charlie", 8, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("delta", 20, 2).announcing_leap(),
    ];
    let mut rig = Rig::new(World::still(0), paths);
    let v = rig.poll_and_synchronise();
    assert!(
        matches!(v, Validity::TimescaleConflict { .. }),
        "a pending leap the sources handle differently has to refuse, got {v:?}"
    );
}

#[test]
fn machine_slept() {
    let mut rig = Rig::new(World::still(0), three_sources());
    rig.run_for(1, 0);
    rig.model.note_resume();
    assert!(
        matches!(
            rig.model.validity(),
            Validity::SuspendedSinceLastSync { .. }
        ),
        "everything measured before the machine went away describes a clock that has been on its \
         own since"
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn clock_stepped() {
    let mut rig = Rig::new(World::still(0), three_sources());
    rig.run_for(1, 0);
    rig.model.note_system_clock_step(NANOS_PER_SEC);
    assert!(
        matches!(rig.model.validity(), Validity::SystemClockStepped { .. }),
        "a step is evidence of a second discipliner, and one that moves the clock can usually \
         steer the counter too"
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn contact_lost() {
    let mut rig = Rig::with(World::still(0), three_sources(), wide_enough(), 0);
    rig.run_for(1, 0);
    let ceiling = rig.model.policy().max_holdover;

    rig.clock.advance_seconds(1);
    assert_eq!(rig.model.validity(), Validity::Valid, "one second is fine");

    // Past the ceiling, measured from the exchange and not from the round that used it.
    rig.clock
        .advance((ceiling as u64) / 1_000_000_000 * 1_000_000_000);
    rig.model.synchronise();
    assert!(
        matches!(rig.model.validity(), Validity::HoldoverExceeded { .. }),
        "past the ceiling the model refuses, whatever the poller is doing"
    );
    assert!(rig.model.read().is_err());
}

#[test]
fn interval_too_wide() {
    // A ceiling under the width three ordinary internet paths produce.
    let narrow = Policy {
        max_bound_width: 1_000,
        ..common::arithmetic_policy()
    };
    let mut rig = Rig::with(World::still(0), three_sources(), narrow, 0);
    assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
    let refusal = rig
        .model
        .read()
        .expect_err("a micosecond-wide ceiling cannot hold a millisecond-wide interval");
    assert!(
        matches!(refusal.validity, Validity::BoundTooWide { .. }),
        "past the width ceiling the answer is a refusal and not a very wide number, got {:?}",
        refusal.validity
    );
}

// ---------------------------------------------------------------------------------------------
// The ten that widen.
// ---------------------------------------------------------------------------------------------

#[test]
fn network_asymmetry() {
    // The whole of the round trip on one leg is the worst case, and nothing in the four timestamps
    // can see it. What the model does is carry half the round trip as width.
    let slow = 40 * NANOS_PER_MILLI;
    let paths = vec![
        Path::honest("alpha", 12, 1).with_split(1.0),
        Path::honest("bravo", 40, 1).with_split(0.0),
        Path::honest("charlie", 8, 1),
    ];
    let mut rig = Rig::new(World::still(0), paths);
    rig.run_for(1, 0);
    let stamp = rig.stamp();
    assert_eq!(
        stamp.bound.breakdown.widest_source_network_half,
        slow / 2,
        "the widest half round trip among the survivors is carried and reported"
    );
    assert!(
        stamp.bound.contains(rig.truth()),
        "the interval holds the truth even where every path is at its worst asymmetry"
    );
}

#[test]
fn source_stated_uncertainty() {
    let modest: Vec<Path> = three_sources();
    let candid: Vec<Path> = three_sources()
        .into_iter()
        .map(|mut p| {
            p.stated += 20 * NANOS_PER_MILLI;
            p
        })
        .collect();

    let mut a = Rig::new(World::still(0), modest);
    let mut b = Rig::new(World::still(0), candid);
    a.run_for(1, 0);
    b.run_for(1, 0);
    assert!(
        b.stamp().bound.width() > a.stamp().bound.width(),
        "a source that states more uncertainty about itself makes the interval wider, not narrower"
    );
}

#[test]
fn source_understates_itself() {
    // Three sources claiming they spent the whole round trip thinking and know their own time
    // exactly. Every one of them is a point rather than an interval.
    let world = World::still(0);
    let mut rig = Rig::new(world, Vec::new());
    let at = rig.now();
    for (i, id) in ["alpha", "bravo", "charlie"].into_iter().enumerate() {
        // Twenty microseconds apart, which is inside the floor, so the three still agree and the
        // question the test is asking is about the width of a point rather than about a majority.
        let e = claiming_no_uncertainty(
            &rig.world,
            id,
            (i as Nanos) * 20_000,
            at,
            4 * NANOS_PER_MILLI,
        );
        assert_eq!(rig.model.ingest(&e), None);
    }
    assert_eq!(rig.model.synchronise(), Validity::Valid);

    let floor = rig.model.policy().source_interval_floor;
    let stamp = rig.stamp();
    assert!(
        stamp.bound.width() >= 2 * floor,
        "a source claiming to know its time exactly is floored to a width before it is compared \
         with anybody; the interval came back {} ns wide against a floor of {floor} ns",
        stamp.bound.width()
    );
}

#[test]
fn sample_ageing() {
    // The same exchanges, selected at once and selected a minute later. The intersection is wider
    // the second time, because the machine's clock moved during that minute and nobody watched it.
    let world = World::still(0);
    let paths = three_sources();

    let mut early = Rig::with(world, paths.clone(), wide_enough(), 0);
    let at = early.now();
    for p in &paths {
        let e = early.world.exchange(p, at);
        early.model.ingest(&e);
    }
    assert_eq!(early.model.synchronise(), Validity::Valid);
    let fresh = early.stamp().bound.breakdown.intersection_half;

    let mut late = Rig::with(world, paths.clone(), wide_enough(), 0);
    let at = late.now();
    for p in &paths {
        let e = late.world.exchange(p, at);
        late.model.ingest(&e);
    }
    late.clock.advance_seconds(60);
    assert_eq!(late.model.synchronise(), Validity::Valid);
    let aged = late.stamp().bound.breakdown.intersection_half;

    assert!(
        aged > fresh,
        "a minute-old exchange supports a wider interval than a fresh one; it went from {fresh} \
         ns to {aged} ns"
    );
}

#[test]
fn oscillator_holdover() {
    let mut rig = Rig::with(World::still(0), three_sources(), wide_enough(), 0);
    rig.run_for(4, 60);
    let at_once = rig.stamp().bound.breakdown.oscillator_holdover;

    rig.clock.advance_seconds(60);
    let after_a_minute = rig.stamp().bound.breakdown.oscillator_holdover;
    assert!(
        after_a_minute > at_once,
        "extrapolating for a minute costs width; it went from {at_once} ns to {after_a_minute} ns"
    );
}

#[test]
fn rate_moved_after_the_fit() {
    // The allowance for the rate moving grows with elapsed time, so the holdover term grows faster
    // than the time does. A fixed allowance would grow exactly in step, and that is the shape an
    // earlier fault had: fifteen parts per million doing two jobs, and forty parts per million of
    // ordinary temperature change putting true UTC outside a receipt that signed cleanly.
    let mut rig = Rig::with(World::still(0), three_sources(), wide_enough(), 0);
    rig.run_for(4, 60);

    rig.clock.advance_seconds(60);
    let one = rig.stamp().bound.breakdown.oscillator_holdover;
    rig.clock.advance_seconds(60);
    let two = rig.stamp().bound.breakdown.oscillator_holdover;

    assert!(
        two > 2 * one,
        "the holdover allowance has to grow faster than the elapsed time, because the rate itself \
         may have moved; one minute gave {one} ns and two gave {two} ns"
    );
}

#[test]
fn rate_the_model_would_not_claim() {
    // Four rounds a second apart. The baseline is far too short to measure this machine's
    // oscillator against sources whose midpoints move by milliseconds, so the model claims no rate
    // and carries the magnitude of the fit it threw away as width instead.
    let mut rig = Rig::with(World::drifting(0, 40.0), three_sources(), wide_enough(), 0);
    for i in 0..4 {
        if i > 0 {
            rig.clock.advance_seconds(1);
        }
        assert_eq!(rig.poll_and_synchronise(), Validity::Valid);
    }
    let stamp = rig.stamp();
    assert!(
        stamp.frequency_ppm.is_none(),
        "a fit over four seconds is the sources' jitter divided by a short baseline, and reporting \
         it as this machine's frequency error is quoting a figure nobody measured"
    );

    rig.clock.advance_seconds(60);
    let held = rig.stamp();
    assert!(
        held.bound.contains(rig.truth()),
        "the rate the model would not claim still has to be paid for in width, or a minute of \
         holdover puts the truth outside the interval"
    );
}

#[test]
fn model_residual() {
    // Sources whose paths differ enough for the fitted line to have real scatter under it.
    let noisy = vec![
        Path::honest("alpha", 12, 1).with_split(0.9),
        Path::honest("bravo", 60, 3).with_split(0.1),
        Path::honest("charlie", 8, 1).with_split(0.5),
        Path::honest("delta", 40, 2).with_split(0.8),
    ];
    let mut rig = Rig::with(World::drifting(0, 20.0), noisy, wide_enough(), 0);
    rig.run_for(6, 60);
    let stamp = rig.stamp();
    assert!(
        stamp.bound.breakdown.model_residual > 0,
        "the scatter of the measurements under the fitted line is width, and it is usually the \
         largest term there is"
    );
    assert!(
        stamp.bound.width() >= 2 * stamp.bound.breakdown.model_residual,
        "every half-width term appears on both sides of the reading"
    );
}

#[test]
fn local_read_cost() {
    let coarse = 5 * NANOS_PER_MILLI;
    let mut fine = Rig::with(World::still(0), three_sources(), wide_enough(), 0);
    let mut blunt = Rig::with(World::still(0), three_sources(), wide_enough(), coarse);
    fine.run_for(1, 0);
    blunt.run_for(1, 0);

    let a = fine.stamp();
    let b = blunt.stamp();
    assert_eq!(
        b.bound.breakdown.scheduling, coarse,
        "a counter measured to tick every five milliseconds gets five milliseconds of allowance"
    );
    assert_eq!(
        b.bound.width() - a.bound.width(),
        2 * (coarse - a.bound.breakdown.scheduling),
        "the difference is the allowance, on both sides of the reading and nowhere else"
    );
}

#[test]
fn safety_margin() {
    let mut rig = Rig::with(World::still(0), three_sources(), wide_enough(), 0);
    rig.run_for(1, 0);
    let stamp = rig.stamp();
    let margin = rig.model.policy().safety_margin;
    assert_eq!(stamp.bound.breakdown.safety_margin, margin);
    assert!(
        stamp.bound.width() >= 2 * margin,
        "the fixed allowance is on both sides of every interval the model signs"
    );
}

// ---------------------------------------------------------------------------------------------
// And the test that keeps the list honest.
// ---------------------------------------------------------------------------------------------

/// Every entry above, in the order the enumeration lists them.
///
/// Adding an entry to `LossOfUtc::ALL` without adding it here fails this test, and adding it here
/// without a test above is caught by reading: each name matches the function that covers it.
const COVERED: [LossOfUtc; 21] = [
    LossOfUtc::NothingMeasuredYet,
    LossOfUtc::TooFewSources,
    LossOfUtc::NoMajorityAgrees,
    LossOfUtc::MajorityOnlyFromFreeAgreement,
    LossOfUtc::SourceDisclaimsItsOwnClock,
    LossOfUtc::ReplyThatCannotBeTrue,
    LossOfUtc::SourcesDisagreeAcrossALeap,
    LossOfUtc::MachineSlept,
    LossOfUtc::ClockStepped,
    LossOfUtc::ContactLost,
    LossOfUtc::IntervalTooWide,
    LossOfUtc::NetworkAsymmetry,
    LossOfUtc::SourceStatedUncertainty,
    LossOfUtc::SourceUnderstatesItself,
    LossOfUtc::SampleAgeing,
    LossOfUtc::OscillatorHoldover,
    LossOfUtc::RateMovedAfterTheFit,
    LossOfUtc::RateTheModelWouldNotClaim,
    LossOfUtc::ModelResidual,
    LossOfUtc::LocalReadCost,
    LossOfUtc::SafetyMargin,
];

#[test]
fn the_list_is_covered_in_full() {
    for entry in LossOfUtc::ALL {
        assert!(
            COVERED.contains(&entry),
            "{} is a way a reading can lose UTC and no test in this file covers it",
            entry.name()
        );
    }
    for entry in COVERED {
        assert!(
            LossOfUtc::ALL.contains(&entry),
            "{} is covered here and is not in the enumeration",
            entry.name()
        );
    }
    assert_eq!(COVERED.len(), LossOfUtc::ALL.len());
}

#[test]
fn the_two_halves_of_the_list_are_both_populated() {
    // A list that only refused would describe a model that never signs anything, and a list that
    // only widened would describe one that never declines. Both halves have to be real.
    let refuses = LossOfUtc::ALL
        .iter()
        .filter(|e| e.response() == Response::Refuses)
        .count();
    let widens = LossOfUtc::ALL.len() - refuses;
    assert!(
        refuses > 0 && widens > 0,
        "{refuses} refuse, {widens} widen"
    );
}
