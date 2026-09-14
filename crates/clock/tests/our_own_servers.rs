//! A source the deployment runs itself is not one of its independent operators.
//!
//! This product is about to run two Roughtime servers of its own. They answer like anybody else's,
//! their signatures check like anybody else's, and a receipt resting on them is not resting on a
//! party independent of the one that issued it. The rule is that our own bound never sits where
//! third-party evidence belongs, and a count of independent operators that quietly includes us is
//! that rule broken with every signature still verifying.
//!
//! So a first-party source disciplines nothing less than any other source does. It is polled, it is
//! selected, its interval is in the arithmetic, and it is left out of the two counts that decide
//! whether the round may be signed at all: the operator majority and the operator floor.
//!
//! **What this file is really testing is a refusal that was a signature before 2026-09-12.** Every
//! test here is written the same way: take a round that signs, change nothing but who is said to be
//! running some of it, and watch the model refuse. Nothing here can make the model sign a round it
//! would otherwise have refused, which is the property the whole independence rule rests on and is
//! asserted at the bottom of this file.

mod common;

use common::{Path, World};

use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{independence, ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI};
use timewitness_core::{MonotonicNanos, Operator, UnixNanos, Validity};

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The shipped policy with the width ceiling raised, exactly as `four_to_six.rs` uses it.
///
/// The floors and the independence number are the shipped ones. A change to `min_operators` has to
/// be visible here as well as there.
fn as_shipped() -> Policy {
    Policy {
        max_bound_width: 30_000 * NANOS_PER_MILLI,
        ..Policy::default()
    }
}

fn source(id: &'static str, operator: &'static str, error: Nanos) -> Path {
    Path::honest(id, 20, 1)
        .operated_by(operator)
        .lying_by(error)
}

fn our_source(id: &'static str, operator: &'static str, error: Nanos) -> Path {
    Path::honest(id, 20, 1)
        .operated_by_us(operator)
        .lying_by(error)
}

fn one_round(paths: &[Path]) -> (ClockModel, Validity, UnixNanos) {
    let world = World::still(0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(as_shipped(), Box::new(ClockHandle(clock.clone())), wall, 0);

    let now = clock.now();
    for path in paths {
        model.ingest(&world.exchange(path, now));
    }
    let validity = model.synchronise();
    (model, validity, world.utc(now))
}

/// Four strangers sign. This is the control, and every test below is this round with one thing
/// changed.
#[test]
fn four_independent_operators_sign_and_that_is_the_control() {
    let round = vec![
        source("a", "one.example", 0),
        source("b", "two.example", NANOS_PER_MILLI),
        source("c", "three.example", -NANOS_PER_MILLI),
        source("d", "four.example", 2 * NANOS_PER_MILLI),
    ];
    let (model, validity, truth) = one_round(&round);
    assert_eq!(validity, Validity::Valid);
    let stamp = model.read().expect("a valid model reads");
    assert!(stamp.bound.earliest <= truth && truth <= stamp.bound.latest);
}

/// The case this fix is about. Two of those four are ours and the round no longer clears the floor.
///
/// Nothing about the measurements changed. The same four servers answered, the same four intervals
/// agree, and Marzullo signs it as readily as before. What changed is that two of the four parties
/// are the party issuing the receipt, so there are two independent chances to be wrong and the
/// shipped floor wants four.
#[test]
fn two_of_the_four_being_ours_turns_a_signature_into_a_refusal() {
    let round = vec![
        source("a", "one.example", 0),
        source("b", "two.example", NANOS_PER_MILLI),
        our_source("c", "timewitness.dev", -NANOS_PER_MILLI),
        our_source("d", "timewitness.dev", 2 * NANOS_PER_MILLI),
    ];
    let (_, validity, _) = one_round(&round);
    assert!(
        matches!(
            validity,
            Validity::InsufficientOperators {
                present: 2,
                required: 4
            }
        ),
        "two strangers and two of our own is two independent parties, got {validity:?}"
    );
}

/// A deployment cannot reach the floor on its own servers however many of them it runs.
///
/// Six names, six of them ours, every interval agreeing perfectly. This is the shape the whole
/// independence rule exists to refuse, with the one party being us rather than a stranger's
/// company, and it is the one a product running its own servers would otherwise walk into first.
#[test]
fn a_round_of_nothing_but_our_own_servers_is_refused_however_many_there_are() {
    let round = vec![
        our_source("a", "timewitness.dev", 0),
        our_source("b", "timewitness.dev", NANOS_PER_MILLI),
        our_source("c", "timewitness.dev", -NANOS_PER_MILLI),
        our_source("d", "tw-one.example", 2 * NANOS_PER_MILLI),
        our_source("e", "tw-two.example", -2 * NANOS_PER_MILLI),
        our_source("f", "tw-three.example", 3 * NANOS_PER_MILLI),
    ];
    let (_, validity, _) = one_round(&round);
    assert!(
        matches!(
            validity,
            Validity::InsufficientOperators {
                present: 0,
                required: 4
            }
        ),
        "six servers of ours are nought independent parties, got {validity:?}"
    );
}

/// Our own servers on top of four strangers still sign, and still hold the truth.
///
/// The other direction, and it matters as much: a first-party source is not refused and is not
/// ignored. It is polled and selected and its interval narrows the intersection like any other. All
/// this rule does is decline to count it as a party.
#[test]
fn our_own_servers_beside_enough_strangers_sign_and_are_still_used() {
    let round = vec![
        source("a", "one.example", 0),
        source("b", "two.example", NANOS_PER_MILLI),
        source("c", "three.example", -NANOS_PER_MILLI),
        source("d", "four.example", 2 * NANOS_PER_MILLI),
        our_source("ours", "timewitness.dev", -2 * NANOS_PER_MILLI),
    ];
    let (model, validity, truth) = one_round(&round);
    assert_eq!(validity, Validity::Valid, "four strangers still carry it");

    let stamp = model.read().expect("a valid model reads");
    assert!(stamp.bound.earliest <= truth && truth <= stamp.bound.latest);
    assert!(
        stamp
            .sources
            .iter()
            .any(|s| s.id.as_str() == "ours" && s.kept),
        "the first-party source is selected like any other, not skipped"
    );
}

/// One mislabelled entry cannot put our own servers back among the independent parties.
///
/// Two sources give the same operator name and disagree about whether it is us. The name is treated
/// as ours, which is the merging direction the whole file takes: it can only ever lower the count
/// and refuse. The opposite rule would let one wrong entry restore a party that is not independent,
/// and nothing would go red.
#[test]
fn a_name_is_ours_the_moment_any_source_under_it_says_so() {
    let offered = vec![
        Operator::new("timewitness.dev"),
        Operator::first_party("timewitness.dev"),
        Operator::new("one.example"),
        Operator::new("two.example"),
    ];
    assert_eq!(
        independence::distinct(&offered),
        2,
        "the disputed name is ours, so two strangers are left"
    );
    assert_eq!(independence::first_party(&offered), 1);

    let standing = independence::assess(&offered, &[0, 1, 2, 3]);
    assert_eq!(standing.offered, 2);
    assert_eq!(standing.kept, 2);
    assert_eq!(standing.first_party, 1);
}

/// The identity is the name. The flag never splits one party into two.
///
/// This is the fault the merging rule above exists to make impossible, checked at the level below
/// it: if the flag were part of `Operator`'s equality, a set holding both spellings would hold two,
/// and the count the floor is made of would go up rather than down.
#[test]
fn the_flag_is_not_part_of_the_identity() {
    let stated = Operator::new("timewitness.dev");
    let ours = Operator::first_party("timewitness.dev");

    assert_eq!(stated, ours, "same name, same party");
    let both: std::collections::BTreeSet<Operator> = [stated.clone(), ours.clone()].into();
    assert_eq!(both.len(), 1, "a set of the two holds one");
    assert!(!stated.is_first_party());
    assert!(ours.is_first_party());
    assert_eq!(stated.as_str(), ours.as_str());
}

/// The property the whole rule rests on: this can only ever refuse.
///
/// Marking sources as ours removes parties from both counts, and both tests are monotone in those
/// counts. So there is no round anywhere that this change turns from a refusal into a signature.
/// The test walks every subset of a five-source round and asserts it, rather than arguing it.
#[test]
fn marking_a_source_as_ours_never_turns_a_refusal_into_a_signature() {
    let names = [
        "one.example",
        "two.example",
        "three.example",
        "four.example",
        "five.example",
    ];

    for mask in 0u32..(1 << names.len()) {
        let offered: Vec<Operator> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                if mask & (1 << i) == 0 {
                    Operator::new(*n)
                } else {
                    Operator::first_party(*n)
                }
            })
            .collect();
        let all: Vec<usize> = (0..names.len()).collect();

        let plain: Vec<Operator> = names.iter().map(|n| Operator::new(*n)).collect();
        let before = independence::assess(&plain, &all);
        let after = independence::assess(&offered, &all);

        assert!(
            after.offered <= before.offered && after.kept <= before.kept,
            "marking {mask:b} as ours raised a count: {before:?} became {after:?}"
        );
        for floor in 0..=names.len() {
            assert!(
                !(after.meets(floor) && !before.meets(floor)),
                "marking {mask:b} as ours met a floor of {floor} that the same round missed"
            );
        }
    }
}
