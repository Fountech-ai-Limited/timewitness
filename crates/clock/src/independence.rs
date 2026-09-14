//! Counting operators rather than names, which is what makes a majority mean something.
//!
//! [`crate::marzullo`] answers the question a majority of *intervals* allow. This file answers the
//! question a majority of *parties* allow, and until 2026-09-09 nothing did. The difference is not
//! decoration. Marzullo's guarantee is that the region holds the truth while fewer than half the
//! sources are wrong, and the word doing the work in that sentence is "half": it counts faults, and
//! a fault is something that happens to a party, not to a hostname.
//!
//! So one company answering on nine addresses is one fault dressed as nine sources. It passes every
//! test in this crate that counts intervals, it makes a majority on its own, and the count in the
//! receipt says nine. The front page of this product says four to six independent sources, and until
//! this file existed the word independent was carried entirely by prose.
//!
//! # The rule
//!
//! **A majority that rests on fewer than half the operators is not a majority, and the model refuses
//! rather than answering.**
//!
//! Two counts, taken over the same round. The operators that answered, and the operators that had at
//! least one source survive the selection. The second has to be more than half the first. That is
//! the same shape as the interval test one level up, applied to the thing that actually fails.
//!
//! # What it does in each direction, which is the part worth checking
//!
//! **Several servers at one company can no longer outvote the rest.** Six sources at one operator
//! against three at three operators is a textbook majority of six to three, and the region is the
//! one operator's. Here it is one operator kept out of four offered, which is not a majority, so the
//! round is refused. That is the whole point of the file.
//!
//! **Nor can several companies acting together, if they are outnumbered as companies.** Three
//! operators with two servers each is six sources against three honest single-server operators, and
//! the same arithmetic refuses it: three kept of six offered is not more than half.
//!
//! **A liar with several names helps rather than hurts.** Where two servers at one operator are both
//! thrown out, that operator contributes one discarded vote rather than two, and the honest
//! operators reach their majority more easily. That is correct and it is not a loophole: two lies
//! from one party are one party lying.
//!
//! # What it costs
//!
//! Availability, in one direction only. A round with too few operators is refused where it used to
//! be signed, and a refusal is visible: it says which count fell short, and a deployment answers it
//! by adding an operator rather than by arguing with the arithmetic. Nothing here can make the model
//! sign something it would previously have refused, which is the property the tests assert.
//!
//! # What it cannot see
//!
//! Everything [`timewitness_core::Operator`] cannot see, which is a shared upstream, a shared path,
//! a shared satellite constellation and a shared implementation. Read that type before treating the
//! count here as a count of genuinely independent parties. It is an upper bound on independence and
//! the honesty surfaces say so.

use std::collections::BTreeSet;

use timewitness_core::Operator;

/// What a round looked like once its sources were grouped by who runs them.
///
/// **Both counts are of independent parties, and a party that is us is in neither.** A deployment
/// running its own time servers, which this product is about to do, has sources whose signatures
/// check like anybody else's and whose faults are not separate from its own. The rule that our own
/// word is never third-party evidence is the reason: a count that includes us puts our own word
/// inside the number that is supposed to be free of it. So a first-party operator is counted on its
/// own line and left out of the arithmetic that decides whether a round is signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Independence {
    /// How many distinct independent operators answered.
    pub offered: usize,
    /// How many of them had at least one source survive the selection.
    pub kept: usize,
    /// How many distinct operators that answered were us.
    ///
    /// It is reported rather than enforced. Nothing refuses a round for having first-party sources
    /// in it: they discipline the clock like any other source and their intervals are real
    /// measurements. What they do not do is count towards the majority or the floor, and this is
    /// how a reader sees that they were there at all.
    pub first_party: usize,
}

impl Independence {
    /// Whether the surviving operators are more than half of those that answered.
    ///
    /// The same test `marzullo::Intersection::has_majority` makes over intervals, made over the
    /// parties behind them. A round passing one and failing the other is a round where the count of
    /// sources and the count of chances to be wrong are different numbers, which is the case this
    /// whole file is about.
    #[must_use]
    pub const fn has_majority(&self) -> bool {
        2 * self.kept > self.offered
    }

    /// Whether enough distinct operators survived to meet a floor.
    #[must_use]
    pub const fn meets(&self, floor: usize) -> bool {
        self.kept >= floor
    }
}

/// Which names belong to a party that is us.
///
/// A name is ours the moment any source under it says so. That is the merging direction this whole
/// file and [`Operator`] both take: it can only ever lower the independent count and refuse a
/// round, never raise one and sign it. The opposite rule, needing every source under a name to
/// agree before believing it, would let one mislabelled entry put our own servers back among the
/// independent parties, and nothing would go red.
fn ours(operators: &[Operator]) -> BTreeSet<&str> {
    operators
        .iter()
        .filter(|o| o.is_first_party())
        .map(Operator::as_str)
        .collect()
}

/// Group a round by operator and count what survived.
///
/// `operators` is one entry per source offered, in the order the selection saw them. `kept` is the
/// indices of the sources that survived, as `marzullo::partition` returns them.
///
/// An index in `kept` that is not an index into `operators` is ignored rather than panicking. The
/// two lists come from the same round and always agree today; ignoring is the direction that
/// undercounts survivors, so a caller that ever breaks that agreement gets a refusal rather than a
/// signature.
///
/// **A party that is us is counted separately and is in neither of the two numbers the tests above
/// read.** See [`Independence`] for why.
#[must_use]
pub fn assess(operators: &[Operator], kept: &[usize]) -> Independence {
    let ours = ours(operators);
    let independent = |o: &&Operator| !ours.contains(o.as_str());

    let offered: BTreeSet<&Operator> = operators.iter().filter(independent).collect();
    let surviving: BTreeSet<&Operator> = kept
        .iter()
        .filter_map(|i| operators.get(*i))
        .filter(independent)
        .collect();
    Independence {
        offered: offered.len(),
        kept: surviving.len(),
        first_party: ours.len(),
    }
}

/// How many distinct independent operators are in a list of sources.
///
/// A party that is us is not one of them, for the reason [`Independence`] gives.
#[must_use]
pub fn distinct(operators: &[Operator]) -> usize {
    let ours = ours(operators);
    operators
        .iter()
        .filter(|o| !ours.contains(o.as_str()))
        .collect::<BTreeSet<&Operator>>()
        .len()
}

/// How many distinct operators in a list are us.
#[must_use]
pub fn first_party(operators: &[Operator]) -> usize {
    ours(operators).len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(names: &[&str]) -> Vec<Operator> {
        names.iter().map(|n| Operator::new(*n)).collect()
    }

    #[test]
    fn nine_names_at_three_companies_are_three_operators() {
        let round = ops(&[
            "a.com", "a.com", "a.com", "b.com", "b.com", "b.com", "c.com", "c.com", "c.com",
        ]);
        assert_eq!(distinct(&round), 3);
        let found = assess(&round, &[0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(found.offered, 3);
        assert_eq!(found.kept, 3);
        assert!(found.has_majority());
    }

    /// The case the file exists for, stated as the two answers side by side.
    ///
    /// Six sources at one company against three at three others. Counting intervals, six of nine
    /// agreed and that is a majority by any reading of Marzullo. Counting parties, one of four
    /// agreed, which is not, and the round is refused.
    #[test]
    fn one_company_answering_six_times_does_not_make_a_majority() {
        let round = ops(&[
            "a.com", "a.com", "a.com", "a.com", "a.com", "a.com", "b.com", "c.com", "d.com",
        ]);
        let kept = [0, 1, 2, 3, 4, 5];
        assert_eq!(kept.len() * 2, 12, "six of nine intervals is a majority");

        let found = assess(&round, &kept);
        assert_eq!(found.offered, 4);
        assert_eq!(found.kept, 1);
        assert!(
            !found.has_majority(),
            "one operator of four is not a majority however many names it answers on"
        );
    }

    /// Colluding operators cannot buy a majority with extra servers either.
    #[test]
    fn three_companies_with_two_servers_each_do_not_outvote_three_with_one() {
        let round = ops(&[
            "a.com", "a.com", "b.com", "b.com", "c.com", "c.com", "d.com", "e.com", "f.com",
        ]);
        let found = assess(&round, &[0, 1, 2, 3, 4, 5]);
        assert_eq!(found.offered, 6);
        assert_eq!(found.kept, 3);
        assert!(!found.has_majority(), "three of six is not more than half");
    }

    /// Two lies from one party are one party lying, so discarding both helps the honest majority.
    #[test]
    fn a_liar_with_two_names_costs_the_honest_sources_one_vote_and_not_two() {
        let round = ops(&["liar.com", "liar.com", "b.com", "c.com"]);
        let found = assess(&round, &[2, 3]);
        assert_eq!(found.offered, 3);
        assert_eq!(found.kept, 2);
        assert!(found.has_majority());
    }

    #[test]
    fn the_shipped_default_shape_passes() {
        // Nine servers over six operators, which is what the three published lists reach: two of
        // them answer on two protocols each and one company answers on two names.
        let round = ops(&[
            "int08h.com",
            "netnod.se",
            "txryan.com",
            "cloudflare.com",
            "google.com",
            "ptb.de",
            "cloudflare.com",
            "netnod.se",
            "ptb.de",
        ]);
        assert_eq!(distinct(&round), 6);
        let found = assess(&round, &(0..9).collect::<Vec<usize>>());
        assert_eq!(found.kept, 6);
        assert!(found.has_majority());
        assert!(found.meets(4));
        assert!(!found.meets(7));
    }

    #[test]
    fn an_index_outside_the_round_undercounts_rather_than_panicking() {
        let round = ops(&["a.com", "b.com"]);
        let found = assess(&round, &[0, 99]);
        assert_eq!(found.offered, 2);
        assert_eq!(found.kept, 1);
    }

    #[test]
    fn nothing_offered_reaches_no_majority_and_no_floor() {
        let found = assess(&[], &[]);
        assert_eq!(found.offered, 0);
        assert_eq!(found.kept, 0);
        assert!(
            !found.has_majority(),
            "nought is not more than half of nought"
        );
        assert!(!found.meets(1));
    }
}
