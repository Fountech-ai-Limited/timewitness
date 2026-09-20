//! Two receipts, and what follows about which came first.
//!
//! This is the second half of the claim the product opens with. The first half is bounded time, one
//! moment and a width around it, and `verify` answers that about one receipt. The second half is
//! unbroken order, which is a question about two, and until now nothing in the tree read two
//! receipts at once.
//!
//! ## Two statements, and they are not the same statement
//!
//! Two receipts of one chain carry two different things a reader can ask about order, and the whole
//! of the care in this module is keeping them apart.
//!
//! **The intervals say which moment came first.** Each receipt states an interval its own agent's
//! clock could have been in, and the two intervals either sit clear of each other or they do not.
//! That arithmetic is in `timewitness_core::order_of` and it is not repeated here: this module
//! reads receipts and hands the two intervals to the one copy of the comparison. Where the
//! intervals touch or overlap the answer is that nobody can say, and that is an answer rather than
//! a failure.
//!
//! **The chain says which receipt was signed first.** A receipt names the one before it by the
//! sha256 of its signed bytes, so those bytes had to exist at the moment the link was signed. That
//! is an argument about the order of two acts and it rests on a hash rather than on a clock.
//!
//! The second is not a stronger version of the first. It says nothing about UTC, it cannot be
//! compared with a moment on anybody else's machine, and it is only ever about receipts one agent
//! made. What it is good for is that it cannot be re-ordered afterwards: a forger who wants to
//! swap two linked receipts has to find a second preimage of a sha256.
//!
//! ## When the two disagree
//!
//! An agent that signs B naming A, and also signs an interval for B that is wholly before its
//! interval for A, has contradicted itself. Both statements are its own and both are signed, so a
//! reader does not have to decide which party is lying: whichever way round it happened, one of
//! that agent's own claims is false, and the usual reason is a clock that left the bound its agent
//! stated. This module reports that and does not guess which claim to drop.
//!
//! ## What is deliberately not here
//!
//! **Nothing about the two intervals narrows either of them.** Two agents disciplined two clocks
//! against their own sources, and neither one's bound is evidence about the other's.
//!
//! **Nothing here is third-party evidence and the answer never becomes any.** Both intervals are
//! the agents' own claims. What backs each of them is the evidence inside each receipt, which is
//! what the rest of this crate checks, and an order that rests on a receipt that did not hold is
//! reported as resting on it.

use timewitness_core::time::Nanos;
use timewitness_core::{order_of, MomentInterval, Order};

use crate::Assessment;

/// Which of the two receipts, in the order the reader handed them over.
///
/// It is the position rather than a name, because the two files have no order of their own and
/// calling one the earlier before the question is answered is how an answer gets assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    /// The one given first.
    First,
    /// The one given second.
    Second,
}

impl Which {
    /// The other one.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }

    /// The word a person reads.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::First => "the first",
            Self::Second => "the second",
        }
    }
}

/// How the two receipts are related, before any clock is looked at.
///
/// Every variant is a different amount of evidence and they are kept apart for that reason. A hash
/// link is an argument; two sequence numbers are an assertion; two agents are neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// The two files are one receipt handed over twice.
    OneReceiptTwice,
    /// One receipt names the other by the sha256 of its signed bytes.
    ///
    /// The named one was signed first, and that cannot be re-ordered after the fact without a
    /// second preimage of a sha256. It is the strongest thing two receipts can say about their own
    /// order and it is still only about signing.
    Names {
        /// The one that was signed first.
        earlier: Which,
    },
    /// One names the other by hash, and the two sequence numbers say the opposite.
    ///
    /// The agent has contradicted itself inside its own chain. The hash is the half that cannot be
    /// faked, so it is the half reported as the link, and the disagreement is a fault in whatever
    /// produced the pair.
    NamesAgainstItsOwnSequence {
        /// The one the hash says was signed first.
        earlier: Which,
    },
    /// The same agent key and two different sequence numbers, with neither naming the other.
    ///
    /// The receipts between them are not here, so the links cannot be walked. What is left is the
    /// agent's own signed word about where each sits in its chain, which is worth having and is not
    /// the same as the hash argument above.
    SameAgentApart {
        /// The one with the lower sequence number.
        earlier: Which,
        /// How many places apart the two sequence numbers are.
        apart: u64,
    },
    /// The same agent key and the same sequence number on two receipts that are not the same.
    ///
    /// The chain has forked, which is the one thing a sequence number exists to make visible. It
    /// says nothing about order and it says a great deal about the agent.
    TwoAtOneSequence,
    /// Two different agent keys, so these are not two receipts of one chain.
    ///
    /// The interval question is still a question, and it is the only one left.
    TwoAgents,
    /// One of the two could not be read as a receipt, so there is nothing to relate.
    Unreadable,
}

impl Link {
    /// The word a script reads.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::OneReceiptTwice => "one-receipt-twice",
            Self::Names { .. } => "names",
            Self::NamesAgainstItsOwnSequence { .. } => "names-against-its-own-sequence",
            Self::SameAgentApart { .. } => "same-agent-apart",
            Self::TwoAtOneSequence => "two-at-one-sequence",
            Self::TwoAgents => "two-agents",
            Self::Unreadable => "unreadable",
        }
    }

    /// Which receipt the chain says was signed first, where it says anything.
    ///
    /// A fork says nothing, two agents say nothing, and one receipt twice has nothing to say about
    /// itself. Those three return `None`, which is why this is not a field.
    #[must_use]
    pub const fn signed_first(self) -> Option<Which> {
        match self {
            Self::Names { earlier }
            | Self::NamesAgainstItsOwnSequence { earlier }
            | Self::SameAgentApart { earlier, .. } => Some(earlier),
            Self::OneReceiptTwice | Self::TwoAtOneSequence | Self::TwoAgents | Self::Unreadable => {
                None
            }
        }
    }

    /// Whether the chain's answer rests on a hash rather than on the agent's word alone.
    #[must_use]
    pub const fn rests_on_a_hash(self) -> bool {
        matches!(
            self,
            Self::Names { .. } | Self::NamesAgainstItsOwnSequence { .. }
        )
    }
}

/// What can be said about which of the two moments came first.
///
/// The verdict is about the moments, because that is the question the product's claim is about. The
/// chain's answer is beside it in [`PairReading::link`] rather than folded into it, so that a
/// reader cannot come away with one word covering two different statements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The two intervals sit clear of each other, so the order of the moments follows.
    Established {
        /// The one whose moment came first.
        earlier: Which,
        /// The clear space between the two intervals, which is how much room the answer had.
        gap_ns: Nanos,
    },
    /// The two intervals touch or overlap, so these two claims do not settle it.
    ///
    /// **This is an answer.** One of the two moments did come first in the world; what these
    /// receipts do not do is say which, because each agent's own bound is wider than the distance
    /// between the two readings.
    Undecided {
        /// How much of the two intervals is common to both, zero where they meet at a point.
        overlap_ns: Nanos,
    },
    /// The chain and the intervals say opposite things, so one of the claims is false.
    Contradicted {
        /// The one the chain says was signed first.
        signed_first: Which,
        /// The clear space between the two intervals, which run the other way.
        gap_ns: Nanos,
    },
    /// Nothing follows, and this says so rather than picking something.
    ///
    /// Either a receipt could not be read, or one of the intervals has its edges the wrong way
    /// round. Kept apart from undecided because they mean different things: undecided is a sound
    /// pair that does not settle the question, and this is a pair that cannot be reasoned from.
    NotSayable,
}

impl Verdict {
    /// The word a script reads, and the word the sentence a person reads opens with.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Established { .. } => "established",
            Self::Undecided { .. } => "undecided",
            Self::Contradicted { .. } => "contradicted",
            Self::NotSayable => "not-sayable",
        }
    }

    /// Whether an order of the moments was established at all.
    #[must_use]
    pub const fn is_decided(self) -> bool {
        matches!(self, Self::Established { .. })
    }
}

impl core::fmt::Display for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Established { earlier, gap_ns } => write!(
                f,
                "established: {} of the two moments came first, with {gap_ns} ns of clear space \
                 between the two intervals",
                earlier.word()
            ),
            Self::Undecided { overlap_ns } => write!(
                f,
                "undecided: the two intervals overlap by {overlap_ns} ns, so these two receipts do \
                 not establish which moment came first"
            ),
            Self::Contradicted {
                signed_first,
                gap_ns,
            } => write!(
                f,
                "contradicted: the chain says {} was signed first and the intervals put its moment \
                 {gap_ns} ns wholly after the other, and both cannot be true",
                signed_first.word()
            ),
            Self::NotSayable => write!(
                f,
                "not sayable: one of the two could not be read as a claim about a moment, so \
                 nothing follows from the pair"
            ),
        }
    }
}

/// Everything two receipts say about their own order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairReading {
    /// How the two are related, before any clock is looked at.
    pub link: Link,
    /// What the two intervals give, from the one copy of the comparison.
    pub moments: Order,
    /// What follows about which moment came first.
    pub verdict: Verdict,
    /// Whether the first receipt held everything the reader was able to check.
    pub first_held: bool,
    /// Whether the second did.
    pub second_held: bool,
}

impl PairReading {
    /// Whether an order was established over two receipts that both held.
    ///
    /// An order argument over a receipt that was refused is not an argument, so this is false there
    /// however clear the gap was.
    #[must_use]
    pub const fn stands(&self) -> bool {
        self.verdict.is_decided() && self.first_held && self.second_held
    }
}

/// Read two receipts that have already been checked, and say what follows about their order.
///
/// They are taken as assessments rather than as bytes because the order question is the second
/// question and not the first. A reader who has not checked the two receipts has an order between
/// two documents rather than between two moments, and the only way to make that hard to do by
/// accident is to make this function impossible to call without the checking having happened.
///
/// Neither assessment is allowed to be about a receipt that could not be read: where either is,
/// the verdict is [`Verdict::NotSayable`] and the link is the least this can claim.
#[must_use]
pub fn order_of_receipts(first: &Assessment, second: &Assessment) -> PairReading {
    let (Some(a), Some(b)) = (first.receipt.as_ref(), second.receipt.as_ref()) else {
        return PairReading {
            link: Link::Unreadable,
            moments: Order::Incoherent,
            verdict: Verdict::NotSayable,
            first_held: first.accepted(),
            second_held: second.accepted(),
        };
    };

    let link = link_between(
        &a.agent_public_key,
        &b.agent_public_key,
        a.sequence,
        b.sequence,
        a.chain_previous.as_deref(),
        b.chain_previous.as_deref(),
        &first.link,
        &second.link,
    );

    let moments = order_of(
        &MomentInterval::new(a.claim.earliest, a.claim.latest),
        &MomentInterval::new(b.claim.earliest, b.claim.latest),
    );

    PairReading {
        link,
        moments,
        verdict: verdict_from(link, moments),
        first_held: first.accepted(),
        second_held: second.accepted(),
    }
}

/// Which relation the two receipts are in.
///
/// The order of the tests is the order of how much each one proves. A hash link is checked before
/// the sequence numbers so that a pair whose sequence numbers disagree with the hash is reported as
/// the fault it is rather than being read as an ordinary pair some distance apart.
#[allow(clippy::too_many_arguments)]
fn link_between(
    first_key: &[u8],
    second_key: &[u8],
    first_sequence: u64,
    second_sequence: u64,
    first_previous: Option<&[u8]>,
    second_previous: Option<&[u8]>,
    first_bytes_hash: &[u8],
    second_bytes_hash: &[u8],
) -> Link {
    if first_bytes_hash == second_bytes_hash {
        return Link::OneReceiptTwice;
    }
    if first_key != second_key {
        return Link::TwoAgents;
    }

    // A link is a statement about bytes, so it is checked against the hash of the bytes the reader
    // handed over and not against anything reconstructed from the parsed receipt. A holder can
    // restate a receipt as different bytes carrying the same claim, and such a restatement is not
    // the thing the other receipt named.
    let names_first = second_previous == Some(first_bytes_hash);
    let names_second = first_previous == Some(second_bytes_hash);
    if names_first || names_second {
        let earlier = if names_first {
            Which::First
        } else {
            Which::Second
        };
        let sequence_agrees = match earlier {
            Which::First => first_sequence < second_sequence,
            Which::Second => second_sequence < first_sequence,
        };
        return if sequence_agrees {
            Link::Names { earlier }
        } else {
            Link::NamesAgainstItsOwnSequence { earlier }
        };
    }

    match first_sequence.cmp(&second_sequence) {
        core::cmp::Ordering::Less => Link::SameAgentApart {
            earlier: Which::First,
            apart: second_sequence - first_sequence,
        },
        core::cmp::Ordering::Greater => Link::SameAgentApart {
            earlier: Which::Second,
            apart: first_sequence - second_sequence,
        },
        core::cmp::Ordering::Equal => Link::TwoAtOneSequence,
    }
}

/// The verdict the two answers make together.
///
/// The intervals decide it. The chain can only ever turn an established order into a contradiction,
/// and it can never make an undecided pair decided: a hash says which receipt was signed first and
/// says nothing about where either moment sat in UTC, so letting it settle the moment question
/// would be answering one question with the evidence for another.
const fn verdict_from(link: Link, moments: Order) -> Verdict {
    match moments {
        Order::Incoherent => Verdict::NotSayable,
        Order::Undecided { overlap_ns } => Verdict::Undecided { overlap_ns },
        Order::Before { gap_ns } => decided(link, Which::First, gap_ns),
        Order::After { gap_ns } => decided(link, Which::Second, gap_ns),
    }
}

/// An established interval order, held against what the chain says about the same pair.
const fn decided(link: Link, earlier: Which, gap_ns: Nanos) -> Verdict {
    match link.signed_first() {
        Some(signed_first) if !the_same(signed_first, earlier) => Verdict::Contradicted {
            signed_first,
            gap_ns,
        },
        _ => Verdict::Established { earlier, gap_ns },
    }
}

/// Whether two of these name the same receipt. Written out because a const function cannot reach
/// for the derived comparison.
const fn the_same(a: Which, b: Which) -> bool {
    matches!(
        (a, b),
        (Which::First, Which::First) | (Which::Second, Which::Second)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_HASH: [u8; 4] = [0xa1, 0xa2, 0xa3, 0xa4];
    const B_HASH: [u8; 4] = [0xb1, 0xb2, 0xb3, 0xb4];
    const ONE_KEY: [u8; 3] = [1, 2, 3];
    const ANOTHER_KEY: [u8; 3] = [9, 9, 9];

    /// The link between two receipts, named the way the arguments read at the call site.
    fn link(
        keys: (&[u8], &[u8]),
        sequences: (u64, u64),
        previous: (Option<&[u8]>, Option<&[u8]>),
        hashes: (&[u8], &[u8]),
    ) -> Link {
        link_between(
            keys.0,
            keys.1,
            sequences.0,
            sequences.1,
            previous.0,
            previous.1,
            hashes.0,
            hashes.1,
        )
    }

    #[test]
    fn a_receipt_naming_the_other_by_the_bytes_it_was_handed_is_the_strongest_link() {
        assert_eq!(
            link(
                (&ONE_KEY, &ONE_KEY),
                (4, 5),
                (None, Some(&A_HASH)),
                (&A_HASH, &B_HASH)
            ),
            Link::Names {
                earlier: Which::First
            }
        );

        // The same pair handed over the other way round, which has to answer the same thing about
        // the receipts rather than about the order they were typed in.
        assert_eq!(
            link(
                (&ONE_KEY, &ONE_KEY),
                (5, 4),
                (Some(&B_HASH), None),
                (&A_HASH, &B_HASH)
            ),
            Link::Names {
                earlier: Which::Second
            }
        );
    }

    #[test]
    fn a_link_that_names_bytes_nobody_handed_over_is_not_a_link() {
        // The reader holds two receipts of one chain with one missing between them. The link cannot
        // be walked, so what is left is the two sequence numbers and the agent's word.
        assert_eq!(
            link(
                (&ONE_KEY, &ONE_KEY),
                (4, 6),
                (None, Some(&[0xcc, 0xcc])),
                (&A_HASH, &B_HASH)
            ),
            Link::SameAgentApart {
                earlier: Which::First,
                apart: 2
            }
        );
    }

    #[test]
    fn a_hash_link_that_disagrees_with_its_own_sequence_numbers_is_reported_rather_than_smoothed() {
        // Somebody has built a receipt that names a later one as its predecessor. The hash is the
        // half that cannot be faked, so it wins, and the disagreement is said out loud.
        assert_eq!(
            link(
                (&ONE_KEY, &ONE_KEY),
                (9, 2),
                (None, Some(&A_HASH)),
                (&A_HASH, &B_HASH)
            ),
            Link::NamesAgainstItsOwnSequence {
                earlier: Which::First
            }
        );
    }

    #[test]
    fn two_receipts_at_one_sequence_number_are_a_fork_and_not_an_order() {
        let forked = link(
            (&ONE_KEY, &ONE_KEY),
            (7, 7),
            (None, None),
            (&A_HASH, &B_HASH),
        );
        assert_eq!(forked, Link::TwoAtOneSequence);
        assert_eq!(forked.signed_first(), None);
    }

    #[test]
    fn two_agents_are_not_a_chain_and_the_same_bytes_twice_are_not_two_receipts() {
        assert_eq!(
            link(
                (&ONE_KEY, &ANOTHER_KEY),
                (1, 2),
                (None, None),
                (&A_HASH, &B_HASH)
            ),
            Link::TwoAgents
        );
        assert_eq!(
            link(
                (&ONE_KEY, &ONE_KEY),
                (1, 1),
                (None, None),
                (&A_HASH, &A_HASH)
            ),
            Link::OneReceiptTwice
        );
    }

    #[test]
    fn the_chain_never_decides_a_question_the_intervals_left_open() {
        // This is the rule the module exists to hold. A hash says which receipt was signed first
        // and says nothing about UTC, so a pair whose intervals overlap stays undecided however
        // firmly the chain links them.
        let overlapping = Order::Undecided { overlap_ns: 400 };
        for linked in [
            Link::Names {
                earlier: Which::First,
            },
            Link::SameAgentApart {
                earlier: Which::First,
                apart: 1,
            },
            Link::TwoAgents,
        ] {
            assert_eq!(
                verdict_from(linked, overlapping),
                Verdict::Undecided { overlap_ns: 400 },
                "{} decided a question the intervals left open",
                linked.word()
            );
        }
    }

    #[test]
    fn intervals_that_agree_with_the_chain_establish_the_order() {
        assert_eq!(
            verdict_from(
                Link::Names {
                    earlier: Which::First
                },
                Order::Before { gap_ns: 12 }
            ),
            Verdict::Established {
                earlier: Which::First,
                gap_ns: 12
            }
        );
        assert_eq!(
            verdict_from(
                Link::Names {
                    earlier: Which::Second
                },
                Order::After { gap_ns: 12 }
            ),
            Verdict::Established {
                earlier: Which::Second,
                gap_ns: 12
            }
        );
    }

    #[test]
    fn intervals_running_against_the_chain_are_a_contradiction_and_not_an_order() {
        // The agent signed a link saying this receipt came after the other, and an interval saying
        // its moment was wholly before. Both are its own and both are signed, so one of them is
        // false and this does not pick which.
        assert_eq!(
            verdict_from(
                Link::Names {
                    earlier: Which::First
                },
                Order::After { gap_ns: 500 }
            ),
            Verdict::Contradicted {
                signed_first: Which::First,
                gap_ns: 500
            }
        );
    }

    #[test]
    fn a_chain_that_says_nothing_leaves_an_established_order_established() {
        // Two agents, or a fork, or one receipt twice: there is nothing to contradict, so an order
        // the intervals establish stands on the intervals alone.
        for silent in [Link::TwoAgents, Link::TwoAtOneSequence, Link::Unreadable] {
            assert_eq!(
                verdict_from(silent, Order::After { gap_ns: 7 }),
                Verdict::Established {
                    earlier: Which::Second,
                    gap_ns: 7
                },
                "{} changed an answer it has no evidence about",
                silent.word()
            );
        }
    }

    #[test]
    fn an_interval_with_its_edges_the_wrong_way_round_settles_nothing() {
        assert_eq!(
            verdict_from(
                Link::Names {
                    earlier: Which::First
                },
                Order::Incoherent
            ),
            Verdict::NotSayable
        );
    }

    #[test]
    fn every_verdict_and_every_link_has_a_word_of_its_own() {
        let verdicts = [
            Verdict::Established {
                earlier: Which::First,
                gap_ns: 1,
            }
            .word(),
            Verdict::Undecided { overlap_ns: 1 }.word(),
            Verdict::Contradicted {
                signed_first: Which::First,
                gap_ns: 1,
            }
            .word(),
            Verdict::NotSayable.word(),
        ];
        let mut seen = verdicts.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), verdicts.len(), "two verdicts share one word");

        // And the sentence a person reads opens with the word a script reads, so the two surfaces
        // cannot come away with different answers.
        for verdict in [
            Verdict::Established {
                earlier: Which::First,
                gap_ns: 1,
            },
            Verdict::Undecided { overlap_ns: 1 },
            Verdict::Contradicted {
                signed_first: Which::First,
                gap_ns: 1,
            },
        ] {
            assert!(
                verdict.to_string().starts_with(verdict.word()),
                "{}",
                verdict
            );
        }
        assert!(Verdict::NotSayable.to_string().starts_with("not sayable"));
    }
}
