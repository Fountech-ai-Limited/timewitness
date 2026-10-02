//! A stranger holds two receipts and asks which came first.
//!
//! Everything here runs offline against bytes, the way the reader who asks this question has to.
//! There is no network in the path and no account, and the two receipts are all that is supplied:
//! whatever the answer is, it came out of the files.
//!
//! The battery is written around the answer the product exists to be willing to give. An order that
//! the two intervals do not support has to come back undecided however firmly the chain links the
//! two receipts, because a chain link is an argument about which receipt was signed and not about
//! which moment happened.

mod common;

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::schema::BreakdownRecord;
use timewitness_receipt::{chain_link, AgentKey};
use timewitness_verify::{
    order_of_receipts, verify_with_key_log, Assessment, Floor, Link, Subject, Verdict, Which,
};

/// The moment the first receipt of every pair here is about.
const NOON: Nanos = 1_788_800_000 * NANOS_PER_SEC;

/// Half the width of the bound each of these receipts claims, which is about what this product
/// reaches through the resident agent.
const HALF: Nanos = 60 * NANOS_PER_MILLI;

/// Half a bound this verifier will not believe from anybody, whatever the receipt says about
/// itself.
const TOO_NARROW: Nanos = 100;

/// The other agent, for the pairs that are not one chain.
const ANOTHER_SEED: [u8; 32] = [0x22u8; 32];

/// A signed receipt claiming a bound around `at`, in a chain at `sequence` behind `previous`.
///
/// It rests on its own model and carries no attestations, which is what every receipt this product
/// issues today does. The order question is about the two intervals, and dressing these in a
/// sandwich would pin them to the one moment the captured signatures are about.
fn a_receipt(
    key: &AgentKey,
    sequence: u64,
    previous: Option<Vec<u8>>,
    at: Nanos,
    half: Nanos,
) -> Vec<u8> {
    let mut receipt = common::receipt();
    receipt.sequence = sequence;
    receipt.chain_previous = previous;
    receipt.evidence = Vec::new();
    receipt.claim.basis = EpsilonBasis::LocalModelOnly;
    receipt.claim.earliest = UnixNanos(at - half);
    receipt.claim.latest = UnixNanos(at + half);
    receipt.utc_estimate = UnixNanos(at);
    receipt.claim.breakdown = BreakdownRecord {
        intersection_half: half - 3,
        network_half: 0,
        scheduling: 1,
        oscillator_holdover: 1,
        model_residual: 1,
        safety_margin: 0,
        unclaimed_rate: None,
    };
    receipt.agent_public_key = key.public_key_bytes();
    key.sign(&receipt).expect("the agent signs its own receipt")
}

/// What a reader with no keys at all establishes about one receipt.
///
/// No anchors, because these receipts carry no attestations and a reader holding keys for
/// signatures that are not there learns the same thing either way.
fn checked(bytes: &[u8]) -> Assessment {
    verify_with_key_log(
        bytes,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
        None,
    )
}

/// The reading over two receipts, in the order they are given.
fn reading(first: &[u8], second: &[u8]) -> timewitness_verify::PairReading {
    order_of_receipts(&checked(first), &checked(second))
}

#[test]
fn two_linked_receipts_a_second_apart_establish_their_own_order() {
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let second = a_receipt(
        &key,
        5,
        Some(chain_link(&first)),
        NOON + NANOS_PER_SEC,
        HALF,
    );

    let reading = reading(&first, &second);
    assert_eq!(
        reading.link,
        Link::Names {
            earlier: Which::First
        }
    );
    assert_eq!(
        reading.verdict,
        Verdict::Established {
            earlier: Which::First,
            // A second apart, less the two half widths that face each other.
            gap_ns: NANOS_PER_SEC - 2 * HALF,
        }
    );
    assert!(reading.stands());
    assert!(reading.first_held && reading.second_held);
}

#[test]
fn the_same_two_receipts_the_other_way_round_answer_about_the_receipts_and_not_the_typing() {
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let second = a_receipt(
        &key,
        5,
        Some(chain_link(&first)),
        NOON + NANOS_PER_SEC,
        HALF,
    );

    let reading = reading(&second, &first);
    assert_eq!(
        reading.link,
        Link::Names {
            earlier: Which::Second
        }
    );
    assert_eq!(
        reading.verdict,
        Verdict::Established {
            earlier: Which::Second,
            gap_ns: NANOS_PER_SEC - 2 * HALF,
        }
    );
}

#[test]
fn two_linked_receipts_closer_together_than_their_own_bounds_are_undecided() {
    // The whole point of the product. These two stamps really did happen in the order the chain
    // says, and the two signed claims do not establish it, because each agent's own bound is wider
    // than the distance between the two readings. The answer is that nobody can say.
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let second = a_receipt(
        &key,
        5,
        Some(chain_link(&first)),
        NOON + 10 * NANOS_PER_MILLI,
        HALF,
    );

    let reading = reading(&first, &second);
    assert_eq!(
        reading.link,
        Link::Names {
            earlier: Which::First
        }
    );
    assert_eq!(
        reading.verdict,
        Verdict::Undecided {
            overlap_ns: 2 * HALF - 10 * NANOS_PER_MILLI,
        }
    );
    assert!(!reading.stands());
    // And the chain still says which of the two was signed first. It is a different question with a
    // different answer, and losing it would be as wrong as letting it settle the first one.
    assert_eq!(reading.link.signed_first(), Some(Which::First));
    assert!(reading.link.rests_on_a_hash());
}

#[test]
fn intervals_touching_at_a_point_are_undecided_and_a_nanosecond_apart_is_not() {
    let key = common::key();
    let first = a_receipt(&key, 1, None, NOON, HALF);

    let touching = a_receipt(&key, 2, Some(chain_link(&first)), NOON + 2 * HALF, HALF);
    assert_eq!(
        reading(&first, &touching).verdict,
        Verdict::Undecided { overlap_ns: 0 },
        "two moments that could be the same instant are not an order"
    );

    let clear = a_receipt(&key, 2, Some(chain_link(&first)), NOON + 2 * HALF + 1, HALF);
    assert_eq!(
        reading(&first, &clear).verdict,
        Verdict::Established {
            earlier: Which::First,
            gap_ns: 1
        },
        "an order with one nanosecond of room is still an order"
    );
}

#[test]
fn a_chain_link_running_against_the_intervals_is_a_contradiction() {
    // The agent signed that this receipt follows the other, and signed an interval putting its
    // moment wholly before. One of its own claims is false and the pair does not say which.
    let key = common::key();
    let later_moment = a_receipt(&key, 4, None, NOON + NANOS_PER_SEC, HALF);
    let earlier_moment = a_receipt(&key, 5, Some(chain_link(&later_moment)), NOON, HALF);

    let reading = reading(&later_moment, &earlier_moment);
    assert_eq!(
        reading.verdict,
        Verdict::Contradicted {
            signed_first: Which::First,
            gap_ns: NANOS_PER_SEC - 2 * HALF,
        }
    );
    assert!(!reading.stands());
}

#[test]
fn a_link_is_checked_against_the_bytes_the_reader_was_handed() {
    // Two receipts of one chain with one missing between them. The link in the second names bytes
    // the reader does not hold, so it is not a link here, and what is left is the agent's own word
    // about where each sits.
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let missing = a_receipt(
        &key,
        5,
        Some(chain_link(&first)),
        NOON + NANOS_PER_SEC,
        HALF,
    );
    let third = a_receipt(
        &key,
        6,
        Some(chain_link(&missing)),
        NOON + 2 * NANOS_PER_SEC,
        HALF,
    );

    let reading = reading(&first, &third);
    assert_eq!(
        reading.link,
        Link::SameAgentApart {
            earlier: Which::First,
            apart: 2
        }
    );
    assert!(!reading.link.rests_on_a_hash());
    // The intervals still answer, and they are the only thing that established it.
    assert!(reading.verdict.is_decided());
}

#[test]
fn a_sequence_number_that_disagrees_with_the_hash_is_reported_and_the_hash_is_believed() {
    let key = common::key();
    let first = a_receipt(&key, 9, None, NOON, HALF);
    let second = a_receipt(
        &key,
        2,
        Some(chain_link(&first)),
        NOON + NANOS_PER_SEC,
        HALF,
    );

    let reading = reading(&first, &second);
    assert_eq!(
        reading.link,
        Link::NamesAgainstItsOwnSequence {
            earlier: Which::First
        }
    );
    // The intervals are a second apart and both receipts held, so the moments alone would stand.
    // They do not, because the agent that signed both has contradicted itself inside its own chain,
    // and an order resting on two claims of a broken agent is not one to rely on.
    assert!(reading.verdict.is_decided());
    assert!(reading.first_held && reading.second_held);
    assert!(
        !reading.stands(),
        "an order stands over a chain the reader names as faulty"
    );
}

#[test]
fn two_receipts_at_one_sequence_number_are_a_fork() {
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let second = a_receipt(&key, 4, None, NOON + NANOS_PER_SEC, HALF);

    let reading = reading(&first, &second);
    assert_eq!(reading.link, Link::TwoAtOneSequence);
    assert_eq!(reading.link.signed_first(), None);
    // A fork says nothing about order, so the intervals are left to answer on their own.
    assert!(reading.verdict.is_decided());
    // And what they answer does not stand. A fork at one sequence number is what a restored or
    // rolled-back agent leaves behind, so both intervals come from an agent whose own record is
    // broken. Found 2026-09-21: this said stands=true.
    assert!(reading.first_held && reading.second_held);
    assert!(!reading.stands(), "an order stands over a forked chain");
}

#[test]
fn a_sound_chain_with_the_same_gap_still_stands() {
    // The control for the two above: the same second apart, one agent, one place apart, and
    // neither naming the other. Nothing is wrong with this chain, so the order stands.
    let key = common::key();
    let first = a_receipt(&key, 4, None, NOON, HALF);
    let second = a_receipt(&key, 5, None, NOON + NANOS_PER_SEC, HALF);

    let reading = reading(&first, &second);
    assert!(matches!(reading.link, Link::SameAgentApart { .. }));
    assert!(reading.stands());
}

#[test]
fn two_agents_are_not_a_chain_and_neither_bound_is_evidence_about_the_other() {
    let ours = common::key();
    let theirs = AgentKey::from_seed(&ANOTHER_SEED);
    let first = a_receipt(&ours, 1, None, NOON, HALF);
    let second = a_receipt(&theirs, 1, None, NOON + NANOS_PER_SEC, HALF);

    let reading = reading(&first, &second);
    assert_eq!(reading.link, Link::TwoAgents);
    assert_eq!(
        reading.verdict,
        Verdict::Established {
            earlier: Which::First,
            gap_ns: NANOS_PER_SEC - 2 * HALF,
        }
    );
}

#[test]
fn one_receipt_handed_over_twice_is_said_rather_than_answered() {
    let key = common::key();
    let one = a_receipt(&key, 4, None, NOON, HALF);

    let reading = reading(&one, &one);
    assert_eq!(reading.link, Link::OneReceiptTwice);
    assert_eq!(
        reading.verdict,
        Verdict::Undecided {
            overlap_ns: 2 * HALF
        }
    );
}

#[test]
fn an_order_over_a_receipt_that_did_not_hold_does_not_stand() {
    // The gap is a whole second and the chain link is there. None of that matters: an order
    // argument over a receipt this reader refused is an argument about a document.
    let key = common::key();
    let mut refused = common::receipt();
    refused.sequence = 4;
    refused.evidence = Vec::new();
    refused.claim.basis = EpsilonBasis::LocalModelOnly;
    // A bound two hundred nanoseconds wide, which this verifier refuses however honestly the
    // receipt keeps to its own promises: no path this product is built for reaches it.
    refused.claim.earliest = UnixNanos(NOON - TOO_NARROW);
    refused.claim.latest = UnixNanos(NOON + TOO_NARROW);
    refused.utc_estimate = UnixNanos(NOON);
    refused.claim.breakdown = BreakdownRecord {
        intersection_half: TOO_NARROW - 3,
        network_half: 0,
        scheduling: 1,
        oscillator_holdover: 1,
        model_residual: 1,
        safety_margin: 0,
        unclaimed_rate: None,
    };
    let refused = key.sign(&refused).expect("it still signs");

    let sound = a_receipt(
        &key,
        5,
        Some(chain_link(&refused)),
        NOON + NANOS_PER_SEC,
        HALF,
    );

    let reading = reading(&refused, &sound);
    assert!(
        !reading.first_held,
        "the floor refuses a bound narrower than a microsecond"
    );
    assert!(reading.second_held);
    assert_eq!(
        reading.verdict,
        Verdict::Established {
            earlier: Which::First,
            gap_ns: NANOS_PER_SEC - HALF - TOO_NARROW
        }
    );
    assert!(
        !reading.stands(),
        "an order resting on a refused receipt stands on nothing"
    );
}
