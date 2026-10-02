//! The attacks on a bounded clock that reach phase 1 and had no test of their own.
//!
//! Most of the attacks a hostile reviewer would list already have one here, written for their own
//! reasons by whoever was fixing something at the time and never joined up to the attack they
//! answer. What is in this file is the remainder: three properties nothing was checking.
//!
//! Each one carries its own defective control, which is the shape the rest of this suite uses. A
//! test that only asserts the good outcome cannot tell the difference between a guard that works and
//! a case the guard never sees, so each test first shows the same input passing where the property
//! is not being asked for, and only then shows it caught.

mod common;

use common::{Path, World};
use timewitness_clock::model::ClockModel;
use timewitness_clock::monotonic::TestClock;
use timewitness_clock::MonotonicClock;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, MonotonicNanos, Validity};

struct Handle(std::sync::Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

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

fn round(model: &mut ClockModel, world: &World, paths: &[Path], clock: &TestClock) -> Validity {
    for (i, path) in paths.iter().enumerate() {
        clock.advance((i as u64 + 1) * 1_000_000);
        model.ingest(&world.exchange(path, clock.now()));
    }
    model.synchronise()
}

/// Which sources a run kept, by name, in order.
fn kept(model: &ClockModel) -> Vec<String> {
    let mut names: Vec<String> = model
        .source_states()
        .into_iter()
        .filter(|s| s.kept)
        .map(|s| s.id.as_str().to_string())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Source selection independence
// ---------------------------------------------------------------------------

#[test]
fn a_source_cannot_change_which_other_sources_are_used() {
    // The attack is written about a requester choosing its own evidence. Phase 1 has no requester,
    // so the reachable half is the source itself: answering does not buy a source any say in
    // whether the others are believed.
    let world = World::still(0);

    let honest = vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
    ];
    let (mut alone, clock) = model_on(&world);
    assert_eq!(round(&mut alone, &world, &honest, &clock), Validity::Valid);
    let without = kept(&alone);
    assert_eq!(without.len(), 3, "the control has to keep all three");

    // The same three, with a source that lies by a quarter of a second added to the pool. It is
    // discarded, and the question is whether its presence moved anybody else.
    let mut with_liar = honest.clone();
    with_liar.push(Path::honest("delta", 20, 2).lying_by(250 * NANOS_PER_MILLI));
    let (mut invaded, clock) = model_on(&world);
    assert_eq!(
        round(&mut invaded, &world, &with_liar, &clock),
        Validity::Valid
    );

    assert_eq!(
        kept(&invaded),
        without,
        "a source that answered changed which of the others were used"
    );
}

#[test]
fn a_source_answering_more_often_does_not_gain_by_it() {
    // The retry half of the same attack. A source that answers eight times where the others answer
    // once gets one interval, because the window keeps its shortest round trip rather than counting
    // its replies.
    let world = World::still(0);
    let honest = vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
    ];

    let (mut once, clock) = model_on(&world);
    assert_eq!(round(&mut once, &world, &honest, &clock), Validity::Valid);
    let plain = once.read().expect("a synchronised model reads");

    let (mut many, clock) = model_on(&world);
    for (i, path) in honest.iter().enumerate() {
        clock.advance((i as u64 + 1) * 1_000_000);
        many.ingest(&world.exchange(path, clock.now()));
    }
    // Alpha answers seven more times, which fills its window and no one else's.
    for _ in 0..7 {
        clock.advance(1_000_000);
        many.ingest(&world.exchange(&honest[0], clock.now()));
    }
    assert_eq!(many.synchronise(), Validity::Valid);
    let insistent = many.read().expect("a synchronised model reads");

    assert_eq!(
        insistent.sources.len(),
        plain.sources.len(),
        "answering repeatedly turned one source into several"
    );
    assert!(
        insistent.bound.width() >= plain.bound.width() - NANOS_PER_MILLI,
        "answering repeatedly bought a narrower bound: {} against {}",
        insistent.bound.width(),
        plain.bound.width()
    );
}

// ---------------------------------------------------------------------------
// Outage exploitation
// ---------------------------------------------------------------------------

#[test]
fn a_source_going_quiet_never_narrows_the_bound_and_never_upgrades_it() {
    // No outage releases capacity, upgrades assurance, or turns a refusal into a success. The first
    // half here is arithmetic and the second is a type: what a bound rests on is decided where the
    // bound is computed, and no amount of evidence going missing can move it upward.
    let world = World::still(0);
    let all = common::four_honest_sources();

    let (mut whole, clock) = model_on(&world);
    assert_eq!(round(&mut whole, &world, &all, &clock), Validity::Valid);
    let full = whole.read().expect("a synchronised model reads");

    // The control: with every source answering, the bound is what it is. Now one stops.
    let fewer: Vec<Path> = all.iter().take(3).cloned().collect();
    let (mut short, clock) = model_on(&world);
    assert_eq!(round(&mut short, &world, &fewer, &clock), Validity::Valid);
    let reduced = short.read().expect("a synchronised model reads");

    assert!(
        reduced.bound.width() >= full.bound.width(),
        "losing a source made the interval narrower, {} against {}",
        reduced.bound.width(),
        full.bound.width()
    );
    assert_eq!(
        reduced.bound.basis,
        EpsilonBasis::LocalModelOnly,
        "the model's own bound is never anything but its own claim"
    );
    assert_eq!(full.bound.basis, EpsilonBasis::LocalModelOnly);

    // And one more going quiet is a refusal rather than a thinner answer.
    let too_few: Vec<Path> = all.iter().take(2).cloned().collect();
    let (mut starved, clock) = model_on(&world);
    assert_eq!(
        round(&mut starved, &world, &too_few, &clock),
        Validity::InsufficientSources {
            present: 2,
            required: 3
        }
    );
    assert!(starved.read().is_err(), "two sources bought a bound");
}

#[test]
fn an_outage_that_lasts_is_a_refusal_rather_than_a_wider_and_wider_answer() {
    // The other end of the same attack. A model left to extrapolate does not go on producing
    // answers, and the refusal when it comes says which ceiling it hit.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    assert_eq!(
        round(&mut model, &world, &common::four_honest_sources(), &clock),
        Validity::Valid
    );

    let mut last = model
        .read()
        .expect("a synchronised model reads")
        .bound
        .width();
    let mut refused_after: Option<Nanos> = None;
    for minute in 1..=30 {
        clock.advance_seconds(60);
        match model.read() {
            Ok(stamp) => {
                let width = stamp.bound.width();
                assert!(
                    width >= last,
                    "an interval got narrower while the sources were unreachable"
                );
                last = width;
            }
            Err(_) => {
                refused_after = Some(Nanos::from(minute));
                break;
            }
        }
    }
    let minutes = refused_after.expect("thirty minutes of silence has to end in a refusal");
    assert!(
        (10..=25).contains(&minutes),
        "the refusal came after {minutes} minutes, which is not where the policy says it should"
    );
}

// ---------------------------------------------------------------------------
// Equivocation and rollback together
// ---------------------------------------------------------------------------

#[test]
fn a_source_conflict_a_rollback_and_a_restored_state_give_one_history() {
    // The campaign rather than the parts: a source that starts contradicting the others, a clock
    // moved backwards underneath the agent, and the state coming back afterwards. The pass condition
    // is one coherent bounded history, with no averaged contradiction and no interval that stopped
    // holding the truth.
    let world = World::still(0);
    let (mut model, clock) = model_on(&world);
    let mut paths = common::four_honest_sources();

    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);
    let first = model.read().expect("a synchronised model reads");
    assert!(
        first.bound.contains(world.utc(clock.now())),
        "the interval has to hold the truth before anything is done to it"
    );

    // One source starts contradicting the others by a tenth of a second. The answer is to throw it
    // out, and never to split the difference.
    clock.advance_seconds(10);
    paths[3] = paths[3].clone().lying_by(100 * NANOS_PER_MILLI);
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);
    let during = model.read().expect("a synchronised model reads");
    assert!(
        during.bound.contains(world.utc(clock.now())),
        "the conflict moved the interval off the truth, which is what averaging would do"
    );
    assert!(
        during
            .sources
            .iter()
            .any(|s| s.id.as_str() == "delta" && !s.kept),
        "the contradicting source is reported and not used"
    );

    // Something moves the machine's clock backwards. It is recorded after the fact and there is no
    // interface here that could have stopped it.
    clock.advance_seconds(10);
    model.note_system_clock_step(-5 * NANOS_PER_SEC);
    let refusal = model.read().expect_err("a rolled-back clock has no bound");
    assert_eq!(
        refusal.validity,
        Validity::SystemClockStepped {
            by: -5 * NANOS_PER_SEC
        }
    );

    // The state comes back. The history that follows is continuous with the one before it: the same
    // model, the same anchor, and an interval that still holds the truth.
    clock.advance_seconds(10);
    paths[3] = Path::honest("delta", 40, 3);
    assert_eq!(round(&mut model, &world, &paths, &clock), Validity::Valid);
    let after = model.read().expect("a synchronised model reads");
    assert!(
        after.bound.contains(world.utc(clock.now())),
        "the interval after the rollback does not hold the truth"
    );
    assert_eq!(
        after.generations().0,
        first.generations().0,
        "a clock being set is not a machine rebooting and not a machine resuming"
    );

    // And the whole run is one history: every reading the model gave sits inside its own interval,
    // and every interval held UTC.
    for stamp in [&first, &during, &after] {
        assert!(stamp.estimate_within_bound());
        assert_eq!(stamp.bound.basis, EpsilonBasis::LocalModelOnly);
    }
}

/// The two counters a receipt carries, as a pair a test can compare.
trait Generations {
    fn generations(&self) -> (u64, u64);
}

impl Generations for timewitness_core::Stamp {
    fn generations(&self) -> (u64, u64) {
        (self.generations.boot, self.generations.resume)
    }
}

#[test]
fn the_source_list_is_the_products_and_not_a_callers() {
    // The half of source selection independence that is structural rather than arithmetic. Nothing
    // reaches the published server list from outside: it is a function of no arguments, so there is
    // no request shape that could ask for a friendlier server.
    let published = timewitness_sources::roughtime::RoughtimeServer::published();
    assert!(
        published.len() >= 3,
        "a majority needs three and the shipped list has {}",
        published.len()
    );
    let again = timewitness_sources::roughtime::RoughtimeServer::published();
    let names: Vec<String> = published.iter().map(|s| s.name.clone()).collect();
    let names_again: Vec<String> = again.iter().map(|s| s.name.clone()).collect();
    assert_eq!(
        names, names_again,
        "the list has to be the same list every time it is asked for"
    );
}
