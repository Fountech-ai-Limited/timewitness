//! The ordering arithmetic, attacked at the one place it can be wrong: the boundary.
//!
//! Two moments are in a known order when every moment one could have been is before every moment
//! the other could have been. The whole of the risk is in the word "before", because touching at a
//! point leaves the same instant possible, and a comparison that is not strict would call that an
//! order and be quietly wrong forever after.
//!
//! So the boundary is seeded at every setting rather than sampled: one nanosecond short of
//! touching, exactly touching, and one nanosecond past it.

use timewitness_core::time::UnixNanos;
use timewitness_core::{order_of, MomentInterval, Order};

fn at(earliest: i128, latest: i128) -> MomentInterval {
    MomentInterval::new(UnixNanos(earliest), UnixNanos(latest))
}

#[test]
fn two_intervals_that_do_not_touch_are_in_a_known_order() {
    let first = at(1_000, 2_000);
    let second = at(3_000, 4_000);
    assert_eq!(order_of(&first, &second), Order::Before { gap_ns: 1_000 });
    assert_eq!(order_of(&second, &first), Order::After { gap_ns: 1_000 });
    assert!(order_of(&first, &second).is_decided());
}

#[test]
fn the_boundary_is_seeded_at_every_setting_and_touching_is_undecided() {
    let first = at(1_000, 2_000);

    // A nanosecond of clear space: an order, and the narrowest one there is.
    assert_eq!(
        order_of(&first, &at(2_001, 3_000)),
        Order::Before { gap_ns: 1 }
    );

    // Touching at exactly one point: the two could be the same instant, so nobody can say.
    assert_eq!(
        order_of(&first, &at(2_000, 3_000)),
        Order::Undecided { overlap_ns: 0 }
    );

    // A nanosecond of overlap: undecided, and visibly so.
    assert_eq!(
        order_of(&first, &at(1_999, 3_000)),
        Order::Undecided { overlap_ns: 1 }
    );
}

#[test]
fn an_interval_inside_another_is_undecided_by_its_own_width() {
    let outer = at(1_000, 9_000);
    let inner = at(4_000, 5_000);
    assert_eq!(
        order_of(&outer, &inner),
        Order::Undecided { overlap_ns: 1_000 }
    );
    assert_eq!(
        order_of(&inner, &outer),
        Order::Undecided { overlap_ns: 1_000 }
    );
}

#[test]
fn one_moment_against_itself_is_undecided() {
    // The same claim twice is not evidence that a thing happened before itself.
    let only = at(1_000, 2_000);
    assert_eq!(
        order_of(&only, &only),
        Order::Undecided { overlap_ns: 1_000 }
    );
}

#[test]
fn an_instant_with_no_width_still_obeys_the_same_rule() {
    // A zero width interval is not a thing this product produces, and the arithmetic must not have
    // a special case for it, because a special case is where a rule goes to differ from itself.
    let instant = at(2_000, 2_000);
    assert_eq!(
        order_of(&instant, &at(2_001, 2_001)),
        Order::Before { gap_ns: 1 }
    );
    assert_eq!(
        order_of(&instant, &at(2_000, 2_000)),
        Order::Undecided { overlap_ns: 0 }
    );
}

#[test]
fn edges_the_wrong_way_round_are_said_rather_than_swapped() {
    // Quietly swapping them would turn a fault in whatever produced the interval into a narrower
    // answer, which is the direction this product never goes.
    let inverted = at(3_000, 1_000);
    assert!(!inverted.is_coherent());
    assert_eq!(order_of(&inverted, &at(5_000, 6_000)), Order::Incoherent);
    assert_eq!(order_of(&at(5_000, 6_000), &inverted), Order::Incoherent);
    assert!(!order_of(&inverted, &at(5_000, 6_000)).is_decided());
}

#[test]
fn the_answer_is_the_same_question_asked_from_either_side() {
    // Swapping the two arguments must swap the verdict and nothing else. A rule that did not hold
    // this would give two answers to one question depending on which receipt a reader opened first.
    let cases = [
        (at(0, 10), at(20, 30)),
        (at(20, 30), at(0, 10)),
        (at(0, 10), at(10, 20)),
        (at(0, 100), at(40, 50)),
        (at(5, 5), at(5, 5)),
    ];
    for (a, b) in cases {
        let forwards = order_of(&a, &b);
        let backwards = order_of(&b, &a);
        match (forwards, backwards) {
            (Order::Before { gap_ns: one }, Order::After { gap_ns: two })
            | (Order::After { gap_ns: one }, Order::Before { gap_ns: two }) => {
                assert_eq!(one, two, "the gap does not depend on which way it is asked");
            }
            (Order::Undecided { overlap_ns: one }, Order::Undecided { overlap_ns: two }) => {
                assert_eq!(
                    one, two,
                    "the overlap does not depend on which way it is asked"
                );
            }
            other => panic!("the two answers do not correspond: {other:?}"),
        }
    }
}

#[test]
fn a_gap_is_never_reported_as_negative_and_an_overlap_never_as_more_than_the_narrower_interval() {
    // A swept property rather than three examples, because the arithmetic is two subtractions and
    // the way a subtraction goes wrong is a sign.
    let first = at(1_000, 2_000);
    for start in 0..4_000 {
        let second = at(start, start + 500);
        match order_of(&first, &second) {
            Order::Before { gap_ns } | Order::After { gap_ns } => {
                assert!(gap_ns > 0, "an order has clear space, not {gap_ns}");
            }
            Order::Undecided { overlap_ns } => {
                assert!(
                    overlap_ns >= 0,
                    "an overlap is not negative, not {overlap_ns}"
                );
                assert!(
                    overlap_ns <= 500,
                    "an overlap is no wider than the narrower interval, not {overlap_ns}"
                );
            }
            Order::Incoherent => panic!("both of these are coherent"),
        }
    }
}
