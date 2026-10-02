//! The verifier's own floor, which is the difference between checking numbers and checking labels.
//!
//! Every plausibility test a receipt can be put to has two possible sources for its threshold. One
//! is the receipt, which carries the widest interval its agent said it would sign for and the fewest
//! sources it said it would answer on. The other is the verifier, which decided in advance. Using
//! only the first is checking a document against its own opinion of itself: a receipt claiming a
//! bound zero nanoseconds wide, resting on one source, and stating a width ceiling of zero passes
//! every test in the receipt crate, because it kept to every promise it made. It is also a claim
//! that nothing in this field can support, and the person reading it is a stranger who has been told
//! this product proves when something happened.
//!
//! So a verifier holds its own numbers and applies them to the numbers the receipt carries. Both
//! sets are checked. A receipt has to keep its own word and clear this floor.
//!
//! **Every threshold here only ever refuses.** That is the reason it is safe to set one on a
//! quantity nobody has measured. Being wrong in one direction refuses an honest receipt, which the
//! reader sees and can act on, by supplying their own floor. Being wrong in the other direction
//! accepts a false one silently, and the reader never finds out. The whole of the reasoning for
//! each number below is which of those two costs it is buying.

use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_SEC};

/// What this verifier will not believe, whatever a receipt says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Floor {
    /// The narrowest interval this verifier will accept as a bound.
    pub min_interval_width: Nanos,
    /// The widest.
    pub max_interval_width: Nanos,
    /// The fewest sources that may have answered with a clock they stood behind.
    pub min_candidate_sources: u32,
    /// The fewest distinct parties that may stand behind the sources selection kept.
    pub min_operators_kept: u32,
    /// The largest a signed receipt may be, in bytes.
    pub max_encoded_bytes: usize,
}

/// A microsecond of total width.
///
/// The product's own tightest published condition is about a hundred microseconds of accuracy to
/// UTC on a cloud instance with a hypervisor clock, and certified microseconds need hardware. So a
/// receipt claiming a whole interval narrower than one microsecond is claiming, on any path this
/// product is built for, something the product itself says it cannot do. It is two orders of
/// magnitude below the tightest condition quoted anywhere in the documents, which is the margin
/// that keeps it a backstop rather than an answer.
///
/// It is deliberately not set at the two hundred microseconds today's agent policy cannot go below,
/// because a receipt is read years after it is issued and a future agent on better hardware will
/// honestly beat that. A floor at the policy's own value would refuse those, and the refusal would
/// look identical to catching a lie.
pub const MIN_INTERVAL_WIDTH: Nanos = NANOS_PER_MICRO;

/// An hour of total width.
///
/// Past an hour an interval says nothing about when something happened that a calendar would not,
/// and the same figure is already the ceiling on how far apart the two outside signatures of a
/// sandwich may sit. An agent at the shipped policy refuses long before this: its own ceiling is 250
/// milliseconds and its holdover runs out at about sixteen minutes.
pub const MAX_INTERVAL_WIDTH: Nanos = 3_600 * NANOS_PER_SEC;

/// Three sources that could have disagreed with somebody.
///
/// With three, a majority beats one bad clock, which is the whole reason the selection rule exists.
/// Two is not a majority test, it is two clocks agreeing, and one is a clock. This is the agent's
/// own `min_sources` applied from the outside, so that a receipt stating `min_sources: 1` and
/// keeping to it does not get to pass on its own word.
///
/// It is counted over the candidates rather than over everything that answered, and it was named
/// `MIN_SOURCES_OFFERED` until `sources_offered` was corrected to mean how many answered. A source
/// that told the agent its own clock was not synchronised is in the receipt and is not in this
/// count: it cannot help a majority it could never have been part of.
pub const MIN_CANDIDATE_SOURCES: u32 = 3;

/// Three parties standing behind the sources that were kept.
///
/// `MIN_CANDIDATE_SOURCES` counts names and names are free. One company answering on nine addresses
/// clears it with six to spare and is one chance to be wrong. Marzullo's guarantee holds while
/// fewer than half the sources are faulty, a fault happens to whoever runs the server rather than
/// to the address, so a floor on names is a floor on the wrong quantity. This is the same
/// arithmetic as the one above applied to the thing it was always about: with three parties a
/// majority beats one bad one, with two there is no majority, and with one there is a clock.
///
/// **Three rather than the four the shipped agent requires, and the gap is the point.** Four is a
/// choice made against the server lists this product ships with today, so a floor at four would
/// refuse an honest receipt from an agent pointed at a different set, or from one on a network
/// where a party was unreachable. Three is arithmetic and holds whatever anybody points an agent
/// at. The verifier is read by a stranger years later, and a threshold that encodes today's
/// deployment is a threshold that starts refusing honest receipts as the deployment changes.
///
/// A receipt that names no operator at all does not clear this, and that is deliberate. Such a
/// receipt is judged on everything else by `timewitness_receipt`, whose question is whether the
/// agent kept to its own word, and a format it predates is not something to hold it to. This
/// question is the reader's and it is different: they are being asked to believe the sources failed
/// separately, and a receipt with no labels offers nothing to believe it on. Refusing is the
/// direction the reader can see and act on. A reader who wants those receipts sets the field to
/// nought and gets them.
pub const MIN_OPERATORS_KEPT: u32 = 3;

/// Sixty-four kilobytes, which is the format's own ceiling and not a number of this crate's.
///
/// A receipt carrying three real attestations is a little over three kilobytes, and the largest of
/// the three, an RFC 3161 token with its certificate, is under two. Twenty times that leaves room
/// for a format that grows and refuses a file that is not a receipt at all.
///
/// It is taken from the receipt crate rather than restated here, because the two are the same
/// number and a verifier that reads more than the format allows is reading something that is not a
/// receipt. A reader may still lower it. Padding a header nobody reads is refused a second time,
/// over in `cose::open`, which now holds a receipt to one spelling.
pub const MAX_ENCODED_BYTES: usize = timewitness_receipt::MAX_ENCODED_BYTES;

impl Default for Floor {
    fn default() -> Self {
        Self {
            min_interval_width: MIN_INTERVAL_WIDTH,
            max_interval_width: MAX_INTERVAL_WIDTH,
            min_candidate_sources: MIN_CANDIDATE_SOURCES,
            min_operators_kept: MIN_OPERATORS_KEPT,
            max_encoded_bytes: MAX_ENCODED_BYTES,
        }
    }
}

impl Floor {
    /// The floor as lines a person reads, so the numbers a receipt was judged against are visible
    /// beside the verdict rather than compiled in and unstated.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!(
                "an interval no narrower than {} and no wider than {}",
                crate::human_width(self.min_interval_width),
                crate::human_width(self.max_interval_width)
            ),
            format!(
                "at least {} sources answering with a clock they stood behind",
                self.min_candidate_sources
            ),
            format!(
                "at least {} distinct operators behind the sources that were kept",
                self.min_operators_kept
            ),
            format!("a receipt no larger than {} bytes", self.max_encoded_bytes),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_floor_sits_below_every_condition_the_product_quotes() {
        let floor = Floor::default();
        // A hundred microseconds of accuracy to UTC is the tightest condition in the documents, and
        // a whole interval around it is two hundred. The floor has to be under that or it refuses
        // the product's own best case.
        assert!(floor.min_interval_width < 200 * NANOS_PER_MICRO);
        // And it has to be above zero, which is the receipt the floor exists for.
        assert!(floor.min_interval_width > 0);
        assert!(floor.max_interval_width > floor.min_interval_width);
    }

    #[test]
    fn the_floor_says_its_own_numbers_out_loud() {
        let lines = Floor::default().lines();
        assert_eq!(lines.len(), 4);
        // Both spellings of every width, because the nanoseconds are the exact value and nobody
        // reads eleven digits.
        assert!(lines.iter().any(|l| l.contains("1000 ns")));
        assert!(lines.iter().any(|l| l.contains("1.000 us")));
        assert!(lines.iter().any(|l| l.contains("3600.000 s")));
        assert!(lines.iter().any(|l| l.contains("3 sources")));
        assert!(lines.iter().any(|l| l.contains("3 distinct operators")));
    }

    #[test]
    fn a_width_is_written_in_units_a_person_holds() {
        use crate::human_width;
        assert_eq!(human_width(999), "999 ns");
        assert_eq!(human_width(NANOS_PER_MICRO), "1.000 us (1000 ns)");
        assert_eq!(human_width(16_424_131_876), "16.424 s (16424131876 ns)");
        // The agent's own shipped ceiling and the Action's, so both read as the numbers they are
        // quoted as everywhere else.
        assert_eq!(human_width(250_000_000), "250.000 ms (250000000 ns)");
        assert_eq!(human_width(30 * NANOS_PER_SEC), "30.000 s (30000000000 ns)");
    }
}
