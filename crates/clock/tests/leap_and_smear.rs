//! The leap second, the smear window, and the source that says its own clock is wrong.
//!
//! A leap second is the one fault in this list that is scheduled rather than adversarial. It
//! arrives on a date everybody knows, and on that date a source that spreads the second across a
//! day and a source that inserts it as a second disagree by up to a second while both of them are
//! working correctly. Intersecting the two as though they agreed puts a second of error inside an
//! interval that claims milliseconds, and nothing in the receipt would say so.
//!
//! The tests here are written against the three windows that matter and they are not the same
//! window. Before the leap, while it is announced, the sources still agree. Through the smear, once
//! the announcement has been cleared, they do not. And away from a leap altogether they agree
//! again, so a guard that refuses then is a guard that has made the product useless.

mod common;

use common::{Path, World};
use timewitness_clock::model::ClockModel;
use timewitness_clock::monotonic::TestClock;
use timewitness_clock::MonotonicClock;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{LeapIndicator, SmearPolicy, Validity};

/// The window the large public smearing services spread a leap second across.
const DAY_SMEAR: SmearPolicy = SmearPolicy::Linear {
    window_seconds: 86_400,
};

/// A shorter window, which is a real pairing: operators pick their own.
const FOUR_HOUR_SMEAR: SmearPolicy = SmearPolicy::Linear {
    window_seconds: 14_400,
};

/// A model on a still machine, with a counter the test moves by hand.
fn model_on(world: &World) -> (ClockModel, std::sync::Arc<TestClock>) {
    let clock = std::sync::Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let model = ClockModel::new(
        common::arithmetic_policy(),
        Box::new(Handle(clock.clone())),
        world.wall0,
        100,
    );
    (model, clock)
}

/// Lets the test hold the counter while the model owns one too.
struct Handle(std::sync::Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> timewitness_core::MonotonicNanos {
        self.0.now()
    }
}

/// Poll every path once and run a selection round.
fn round(model: &mut ClockModel, world: &World, paths: &[Path], clock: &TestClock) -> Validity {
    for (i, path) in paths.iter().enumerate() {
        clock.advance((i as u64 + 1) * 1_000_000);
        let exchange = world.exchange(path, clock.now());
        model.ingest(&exchange);
    }
    model.synchronise()
}

/// Three sources part way through spreading a leap second and one that inserted it as a second.
///
/// The three are 400 ms behind UTC, which is where a day-long smear sits a few hours in. Neither
/// side is broken and neither side is on UTC in the way the other is.
fn mid_smear_pool() -> Vec<Path> {
    let behind = -400 * NANOS_PER_MILLI;
    vec![
        Path::honest("alpha", 12, 1)
            .smearing(DAY_SMEAR)
            .lying_by(behind),
        Path::honest("bravo", 24, 2)
            .smearing(DAY_SMEAR)
            .lying_by(behind),
        Path::honest("charlie", 8, 1)
            .smearing(DAY_SMEAR)
            .lying_by(behind),
        Path::honest("delta", 20, 2),
    ]
}

#[test]
fn a_pending_leap_with_sources_that_disagree_about_smearing_is_refused() {
    // The case the guard was written for. It has always worked and it stays here so that widening
    // the guard cannot quietly break the arm that already held.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let paths: Vec<Path> = mid_smear_pool()
        .into_iter()
        .map(|p| {
            let mut p = p;
            p.leap = LeapIndicator::AddSecond;
            p.server_error = 0;
            p
        })
        .collect();

    let validity = round(&mut model, &world, &paths, &clock);
    assert!(
        matches!(validity, Validity::TimescaleConflict { .. }),
        "a pending leap across sources that handle it differently has to refuse, got {validity:?}"
    );
}

#[test]
fn the_guard_stays_armed_through_the_smear_after_the_announcement_clears() {
    // The fault. A leap is announced, the model synchronises happily because every source in the
    // pool spreads the second the same way, and then the leap happens and the announcement is
    // cleared. From that moment the sources are spreading the second over windows of different
    // lengths, which is a disagreement of hundreds of milliseconds, and until 2026-09-08 the model
    // had disarmed itself at exactly that point.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);

    let mut announced = vec![
        Path::honest("alpha", 12, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("bravo", 24, 2)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("charlie", 8, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("delta", 20, 2)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
    ];
    assert_eq!(
        round(&mut model, &world, &announced, &clock),
        Validity::Valid,
        "sources that all smear the same way agree, announcement or not"
    );

    // The leap happens. Nobody announces anything any more, which is correct, and two of the four
    // are now on a shorter smear window than the other two. They still overlap, so nothing is
    // thrown out and the shape of the discard says nothing. The only thing that can see this is the
    // model remembering that a leap was announced.
    for path in &mut announced {
        path.leap = LeapIndicator::None;
    }
    announced[2].smear = FOUR_HOUR_SMEAR;
    announced[3].smear = FOUR_HOUR_SMEAR;
    clock.advance_seconds(60);

    let validity = round(&mut model, &world, &announced, &clock);
    assert!(
        matches!(validity, Validity::TimescaleConflict { .. }),
        "inside the smear window the model has to refuse, got {validity:?}"
    );
}

#[test]
fn the_guard_disarms_once_the_smear_window_has_passed() {
    // The other half of the same property. A guard that never disarms refuses for ever, and a
    // product that refuses for ever is not a safer product.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);

    let mut paths = vec![
        Path::honest("alpha", 12, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("bravo", 24, 2)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("charlie", 8, 1)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
        Path::honest("delta", 20, 2)
            .smearing(DAY_SMEAR)
            .announcing_leap(),
    ];
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);

    for path in &mut paths {
        path.leap = LeapIndicator::None;
    }
    paths[2].smear = FOUR_HOUR_SMEAR;
    paths[3].smear = FOUR_HOUR_SMEAR;

    // A day and an hour after the announcement, which is past the widest window any of them
    // declared. They agree again, and the model has no reason left to refuse.
    clock.advance_seconds(25 * 3_600);
    assert_eq!(
        round(&mut model, &world, &paths, &clock),
        Validity::Valid,
        "past the smear window a mixed pool agrees again and refusing would be refusing for nothing"
    );
}

#[test]
fn an_agent_that_never_saw_the_announcement_refuses_the_split_it_can_see() {
    // An agent started part way through the smear window has nothing latched and nothing announced.
    // What it can still see is the shape of the disagreement: everything thrown out smears one way,
    // everything kept smears the other, and the gap is well under the one second a leap can be.
    // Taking the majority here would be taking the smeared sources, which are deliberately not on
    // UTC for that day.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);

    let validity = round(&mut model, &world, &mid_smear_pool(), &clock);
    assert!(
        matches!(validity, Validity::TimescaleConflict { .. }),
        "a discard that falls exactly along the smear line is not an outlier, got {validity:?}"
    );
}

#[test]
fn an_ordinary_outlier_in_a_pool_that_does_not_smear_is_still_just_an_outlier() {
    // The false-refusal guard. Where nothing in the pool declares a smear, a source 400 ms out is a
    // broken clock, and throwing it out is what selection is for.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let paths = vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 20, 2).lying_by(-400 * NANOS_PER_MILLI),
    ];

    assert_eq!(
        round(&mut model, &world, &paths, &clock),
        Validity::Valid,
        "a pool that does not smear has no smear to be confused by"
    );
}

#[test]
fn a_disagreement_wider_than_a_leap_second_is_not_a_smear() {
    // A leap second is one second, so a source two seconds out is not spreading one however it
    // declares itself. Marzullo's discard is the right answer and the guard stays out of it.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let paths = vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 20, 2)
            .smearing(DAY_SMEAR)
            .lying_by(-2 * NANOS_PER_SEC),
    ];

    assert_eq!(
        round(&mut model, &world, &paths, &clock),
        Validity::Valid,
        "two seconds is not a leap second and the discard stands"
    );
}

#[test]
fn a_source_that_says_its_own_clock_is_wrong_is_not_used() {
    // The indicator was carried on every sample, written into the receipt, and read by nothing.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let mut paths = common::four_honest_sources();
    paths[3].leap = LeapIndicator::Unsynchronised;

    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);

    let states = model.source_states();
    let unsynchronised = states
        .iter()
        .find(|s| s.id.as_str() == "delta")
        .expect("a source that answered is reported whether it was used or not");
    assert!(
        !unsynchronised.kept,
        "a source announcing that its own clock is wrong must not be in the intersection"
    );
    assert_eq!(
        states.len(),
        4,
        "it is still reported, so a reader can see why"
    );
}

#[test]
fn a_majority_that_says_its_own_clocks_are_wrong_leaves_too_few_to_answer() {
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let mut paths = common::four_honest_sources();
    for path in paths.iter_mut().take(3) {
        path.leap = LeapIndicator::Unsynchronised;
    }

    let validity = round(&mut model, &world, &paths, &clock);
    assert_eq!(
        validity,
        Validity::InsufficientSources {
            present: 1,
            required: 3
        },
        "three of four saying their own clocks are wrong leaves one source, not four"
    );
}

#[test]
fn the_smear_window_comes_from_what_the_sources_declare() {
    // A source that will not say what it does is treated as the widest case rather than as no case,
    // and the guard covers the whole of it. Checked through the model rather than against the
    // helper, because the helper is private and the behaviour is what matters.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);

    let mut paths = vec![
        Path::honest("alpha", 12, 1)
            .smearing(SmearPolicy::Unknown)
            .announcing_leap(),
        Path::honest("bravo", 24, 2)
            .smearing(SmearPolicy::Unknown)
            .announcing_leap(),
        Path::honest("charlie", 8, 1)
            .smearing(SmearPolicy::Unknown)
            .announcing_leap(),
    ];
    // Unknown conflicts with everything, including itself, so the announced round already refuses.
    // What this test is about is what happens after the announcement clears.
    let announced = round(&mut model, &world, &paths, &clock);
    assert!(matches!(announced, Validity::TimescaleConflict { .. }));

    for path in &mut paths {
        path.leap = LeapIndicator::None;
    }
    clock.advance_seconds(12 * 3_600);
    let validity = round(&mut model, &world, &paths, &clock);
    assert!(
        matches!(validity, Validity::TimescaleConflict { .. }),
        "a source that will not say what it does is assumed to smear over the widest window there \
         is, so half a day later the guard is still armed, got {validity:?}"
    );
}

#[test]
fn nothing_here_narrows_a_bound() {
    // The rule that governs every change to this file: a guard may widen an interval or refuse, and
    // it may never make one narrower than it was.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let paths = common::four_honest_sources();
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);
    let before = model
        .read()
        .expect("a synchronised model reads")
        .bound
        .width();

    let (mut guarded, guarded_clock) = model_on(&world);
    let mut announced = paths;
    for path in &mut announced {
        path.leap = LeapIndicator::AddSecond;
        path.smear = DAY_SMEAR;
    }
    assert_eq!(
        round(&mut guarded, &world, &announced, &guarded_clock),
        Validity::Valid
    );
    let after: Nanos = guarded
        .read()
        .expect("a synchronised model reads")
        .bound
        .width();

    assert!(
        after >= before,
        "the leap guard narrowed a bound, {after} against {before}"
    );
}

/// A source is described by the sample the bound was built from, and not by an older one.
///
/// `leap` is per packet. A source can answer soundly, and answer again five minutes later saying its
/// own clock is not synchronised, with both samples still in its window. The selection uses the
/// fresher sample, because ageing costs more over five minutes than four milliseconds of round trip
/// buys. Until 2026-09-19 the receipt described the source by the older, quicker one, so it said
/// sound about a source that had said the opposite, on the one field a verifier acts on.
///
/// The direction is the only one that matters. A rule preferring the narrowest aged interval can
/// prefer a longer round trip only where that sample is younger, so the sample the receipt showed
/// was always the stale one.
#[test]
fn a_source_is_described_by_the_sample_the_bound_was_built_from() {
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let mut paths = common::four_honest_sources();
    paths[3] = Path::honest("delta", 6, 1);
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);

    clock.advance(300 * NANOS_PER_SEC as u64);
    paths[3] = Path::honest("delta", 10, 1);
    paths[3].leap = LeapIndicator::Unsynchronised;
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);

    let states = model.source_states();
    let delta = states
        .iter()
        .find(|s| s.id.as_str() == "delta")
        .expect("a source that answered is reported whether it was used or not");
    assert_eq!(
        delta.leap,
        LeapIndicator::Unsynchronised,
        "the receipt describes a source by the sample the round used, and that sample said its own \
         clock was not synchronised"
    );
    assert!(
        !delta.kept,
        "and having said so it cannot be one of the sources the bound rests on"
    );
}

#[test]
fn a_leap_refusal_names_how_each_source_handles_the_second_in_words() {
    // Both leap refusals name how the sources handle the second, and until 2026-09-24 they named it
    // with the policy's debug form, `Linear { window_seconds: 86400 }`, in a sentence a person reads.
    let world = World::still(0);
    let (mut split, clock) = model_on(&world);
    let at_the_split = round(&mut split, &world, &mid_smear_pool(), &clock);

    let (mut pending, clock) = model_on(&world);
    let announced: Vec<Path> = mid_smear_pool()
        .into_iter()
        .map(|mut p| {
            p.leap = LeapIndicator::AddSecond;
            p.server_error = 0;
            p
        })
        .collect();
    let while_pending = round(&mut pending, &world, &announced, &clock);

    for validity in [at_the_split, while_pending] {
        assert!(
            matches!(validity, Validity::TimescaleConflict { .. }),
            "{validity:?}"
        );
        let said = timewitness_core::Refusal::new(validity).to_string();
        assert_eq!(timewitness_core::refusal::insides_in(&said), None, "{said}");
        assert!(said.contains("86400 s"), "the window is still said: {said}");
    }
}
