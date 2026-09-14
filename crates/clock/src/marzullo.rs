//! Marzullo's intersection, which is how sources get combined without being averaged.
//!
//! Every source hands in an interval. The algorithm finds the region a majority of those intervals
//! allow, and anything not reaching that region is a source that disagrees with the majority. A
//! source that disagrees with the majority is broken or hostile, and the answer to a broken source
//! is to throw it away, not to let it pull an average around.
//!
//! NTP has used this since the 1980s and the guarantee it gives is the one this product needs: the
//! region contains the true value provided fewer than half the sources are wrong. That proviso is
//! why the caller checks for a majority afterwards and refuses when it does not have one.
//!
//! **Majority, not maximum, and the difference is the whole of the first fault fixed here.** Until
//! 2026-09-07 this file returned the region where the *largest* number of intervals overlapped,
//! which is the special case of Marzullo's algorithm that tolerates no faulty source at all. It
//! reads like the tightest honest answer and it is not one, because agreement is something a source
//! can give away for free: a server that states no uncertainty contributes a single point, every
//! honest interval covers that point, the count there is therefore the highest anywhere, and one
//! packet takes the whole region. Three honest sources holding 22.520 ms and one liar produced
//! 0.520 ms, 9 ms off UTC, with all four counted as agreeing.
//!
//! Marzullo's own statement of the algorithm is the one that carries the guarantee: with at most
//! `f` faulty sources, take the smallest interval containing every point that at least `n - f` of
//! the intervals allow. The most this product can tolerate and still have a majority is
//! `f = n - (n / 2 + 1)`, so `n - f` is the majority itself, and that is what is computed here.
//!
//! What that buys is a property worth stating plainly, because it is the product's second sentence:
//! a source in the minority can neither narrow the region below what a majority supports nor widen
//! it beyond what a majority supports. It can no longer do anything at all on its own. The price is
//! that the region is wider than the all-sources overlap whenever honest sources disagree slightly,
//! and that is the honest direction: the narrower answer was only ever available by assuming every
//! source was telling the truth, which is the assumption the product exists not to make.
//!
//! **What that property does not cover, found 2026-09-08.** It is about a source in the minority,
//! and a source stating a radius of an hour is never in the minority: it overlaps everything, so it
//! is always inside the region and always counted among those that agree. Being counted raises the
//! number offered, which raises the number of faults this arithmetic tolerates, and that is a real
//! effect on the answer. Two honest servers 10 s apart at a radius of 3 s do not overlap, so
//! nothing reaches a majority and the model refuses. Add one source stating an hour and two of the
//! three now allow every point from the first server's floor to the second server's ceiling, so a
//! majority exists and the answer comes back 16 s wide, where neither honest source supports more
//! than 6 s and the two together support nothing.
//!
//! The region it reports does hold the truth while at most one of the three is faulty, which is what
//! this algorithm promises, so nothing signed is a lie. Two things about it are still wrong and one
//! of them was fixed on 2026-09-08: `partition` stopped counting a source that both swallows every
//! other one and is the only reason a majority exists, so `sources_kept` no longer said three
//! sources agreed when two of them agreed about nothing and the third agreed with everything.
//!
//! # This file departs from textbook Marzullo, on purpose, and the departure is the next paragraph
//!
//! A reader who knows the algorithm should read this before reading the code, because what is here
//! is stricter than the published rule and would otherwise look like a bug.
//!
//! **The rule.** A majority that exists only because of sources that could not have disagreed with
//! anybody is not a majority, and the model refuses instead of answering.
//!
//! Decided on 2026-09-09, against three options, and the reasoning is this: a bound that can be
//! manufactured by a source saying nothing is the first thing a sceptic goes looking for, and this
//! product is sold on the bound being trustworthy. Textbook Marzullo answers a different question.
//! It asks whether the region holds the truth given at most `f` faults, and in the case above it
//! does. This product also has to answer whether anything corroborated anything, and there the
//! honest answer is no.
//!
//! **What "could not have disagreed" means, and why it needs no threshold.** A source is set aside
//! when it contains every interval outside the set being set aside whole. That is not a judgement
//! about how wide it is; it is a statement about this round. Such a source overlaps everything on
//! offer, so no answer any other source could have given would have put it in the minority. It gave
//! its agreement away before the others spoke. The test was asked of one source at a time until
//! 2026-09-10 and is asked of a set now, for the reason the second departure below gives.
//!
//! An absolute threshold was the obvious alternative and it is worse. "Wider than ten seconds" is a
//! number somebody picks, it is wrong on a datacentre and wrong again on a phone tethered over a
//! train's wifi, and it would have to be re-picked every time the product gets more accurate. The
//! relative test needs no number and scales with whatever the sources are actually doing.
//!
//! **What the rule does to an answer, which is the part worth checking.** It can only turn an answer
//! into a refusal. It never moves a region and it never accepts anything textbook Marzullo refuses.
//! The region is computed over every source that answered, exactly as before; the rule reads that
//! region and decides whether to stand behind it. `has_majority` is the textbook test and this one,
//! both, so a caller inherits the stricter rule without asking for it.
//!
//! **And the guarantee is stricter than the standard rather than different from it.** Marzullo's
//! promise holds wherever it held before, because the region is unchanged. What is added is a second
//! promise on top: when this model answers, at least a majority of the sources that could have
//! contradicted each other did not.
//!
//! # The second departure: who decides which source is in the minority
//!
//! The rule above decides whether to stand behind a region at all. This one decides which sources
//! are allowed to answer that question, and it lives in `select` rather than in `intersect` because
//! it is about the selection round rather than about the sweep.
//!
//! **The rule.** A source that could not have disagreed with anybody may not decide which other
//! source is in the minority.
//!
//! **What was wrong without it.** Marzullo takes `f` faults out of `n` sources and asks for `n - f`
//! intervals to allow a point. A source that could not have disagreed allows every point any other
//! source allows, so it adds one to the count everywhere at once while adding about half of one to
//! the threshold. Each such source therefore hands about half a vote to any position at all,
//! including a position only a liar is standing in. Three of them hand out one and a half, which is
//! enough to carry a liar on its own.
//!
//! `select` carries the measurement, what the fix does to a region, and the half of that fix that
//! is not taken here because taking it would narrow honest bounds.
//!
//! **Which sources could not have disagreed, once it is a group rather than one.** The single-source
//! test above asks whether an interval contains every other interval in the round. Three Roughtime
//! servers fail it on each other, because none of them contains the other two, and pass it on
//! everything narrow, so not one of them was ever set aside and all three were counted as sources
//! that agreed. The test is therefore asked of a set: a set is free agreement when every member of
//! it contains every interval outside the set whole.
//!
//! Such a set is always the wide end of the round. A member contains every non-member, so it is at
//! least as wide as every non-member, and the narrowest member is therefore no narrower than the
//! widest non-member. So the search is over the cuts in the width order and nothing else, largest
//! set first, and the answer is the largest set that passes. Intervals of the same width stay on the
//! same side of a cut, which keeps the answer independent of the order the sources arrived in and
//! keeps a set of identical sources whole.
//!
//! **Free agreement may never outnumber what is left, and that condition is half the rule.**
//! Containment reads both ways: three honest sources stating eleven milliseconds each contain a
//! fourth stating no uncertainty at all, so on the containment test alone the three honest ones
//! are the free agreement and the one point is left to decide everything. That is the
//! single-point fault above arriving from the other side, and one packet claiming certainty would
//! take the region by it. So nothing is set aside unless what is left is at least as large as
//! what is set aside.
//!
use timewitness_core::{Nanos, OffsetInterval};

/// What the sweep found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intersection {
    /// The smallest region holding every point that `required` of the intervals allow.
    ///
    /// Where nothing reaches that count, this is the region the textbook algorithm would have
    /// signed, or where the textbook refuses too, the region of largest overlap. Either way the
    /// caller has something to report alongside its refusal, and a reader holding the same intervals
    /// can see what was on offer and why we did not stand behind it. Check `has_majority` before
    /// using it for anything else.
    pub region: OffsetInterval,
    /// The most intervals that overlap at any one point.
    pub agreeing: usize,
    /// How many intervals were offered.
    pub offered: usize,
    /// How many have to overlap before the region means anything.
    ///
    /// The faults behind this figure are counted over the sources that could have disagreed and
    /// never over the number offered, which is the second departure in the module documentation.
    /// With nothing set aside it is the plain majority of the round.
    pub required: usize,
    /// The intervals that could not have disagreed with anybody, as indices into the input.
    ///
    /// Each of them contains every interval outside this set whole, so no answer any of those
    /// sources could have given would have put it in the minority. Empty in the ordinary case. See
    /// the module documentation for why the test is relative rather than a width, and why it is
    /// asked of a set rather than of one source at a time.
    pub could_not_disagree: Vec<usize>,
    /// Whether the majority is there only because of the sources in `could_not_disagree`.
    ///
    /// True when the intervals left after those are set aside do not reach a majority of their own.
    /// `has_majority` is false whenever this is true, so a caller that only asks that question gets
    /// the stricter rule without knowing about this field. It is public so a refusal can say what
    /// happened rather than only that something did.
    pub free_majority: bool,
}

impl Intersection {
    /// How many sources could have disagreed with somebody.
    ///
    /// The round less the free agreement, and the population the fault tolerance is counted over. A
    /// caller with a floor on how many sources it wants behind a bound applies it to this rather
    /// than to `offered`, because `offered` counts sources that agreed before anybody spoke.
    #[must_use]
    pub fn informative(&self) -> usize {
        self.offered - self.could_not_disagree.len()
    }

    /// Whether more than half of the intervals offered agree, and whether that majority is worth
    /// anything.
    ///
    /// Two tests, not one. The first is Marzullo's. The second is this product's own and refuses a
    /// majority that only exists because of sources that could not have disagreed with anybody; it
    /// is `free_majority` and the module documentation carries the reasoning.
    #[must_use]
    pub const fn has_majority(&self) -> bool {
        2 * self.agreeing > self.offered && !self.free_majority
    }

    /// Whether the textbook algorithm alone would have called this a majority.
    ///
    /// Only for saying what the departure costs, in a test or in a message to a reader who knows
    /// Marzullo. Nothing in the model decides anything on this.
    #[must_use]
    pub const fn has_textbook_majority(&self) -> bool {
        2 * self.agreeing > self.offered
    }
}

/// How many of `offered` intervals make a majority.
const fn majority_of(offered: usize) -> usize {
    offered / 2 + 1
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    // Lower ends sort before upper ends at the same value, so two intervals that touch at a single
    // point count as overlapping there rather than missing each other.
    Lower,
    Upper,
}

/// Find the smallest region holding every point the required number of intervals allow, and say
/// whether the sources that could have disagreed stand behind it.
///
/// Returns `None` only when no intervals were offered. With one interval the answer is that
/// interval, which is correct and which the caller then rejects for want of sources.
///
/// Two departures from the textbook, both in the module documentation and both worth reading before
/// the code. The faults tolerated are counted over the sources that could have disagreed rather than
/// over the number offered, which is what `required` carries. And a majority that exists only
/// because of sources that could not have disagreed is refused, which is what `free_majority`
/// records for the refusal to quote.
#[must_use]
pub fn intersect(intervals: &[OffsetInterval]) -> Option<Intersection> {
    if intervals.is_empty() {
        return None;
    }

    let mut found = sweep(intervals, majority_of(intervals.len()))?;

    // The whole of the departure from the textbook, in three lines. Set aside the sources that could
    // not have disagreed, and ask the survivors the same question the sweep just asked everybody.
    // Where the survivors reach no majority of their own, the majority above was theirs to give and
    // they gave it for free.
    found.could_not_disagree = could_not_disagree(intervals);
    if !found.could_not_disagree.is_empty() && found.has_textbook_majority() {
        let theirs = survivors_of(intervals, &found.could_not_disagree);
        let their_majority = majority_of(theirs.len());
        found.free_majority = match sweep(&theirs, their_majority) {
            Some(theirs) => !theirs.has_textbook_majority(),
            // `could_not_disagree` never takes the whole round, so this arm is unreachable.
            // Refusing rather than answering is the safe reading of it if that ever stops holding.
            None => true,
        };
    }

    Some(found)
}

/// The intervals left once the free agreement is set aside, in the order they arrived.
fn survivors_of(intervals: &[OffsetInterval], aside: &[usize]) -> Vec<OffsetInterval> {
    intervals
        .iter()
        .enumerate()
        .filter(|(i, _)| !aside.contains(i))
        .map(|(_, interval)| *interval)
        .collect()
}

/// Marzullo's sweep, asking for whatever count the caller worked out.
///
/// One sweep of the sorted endpoints does both jobs. The count rises at every lower end and falls
/// at every upper end, so the region wanted is bracketed by the first value at which the count
/// reaches `required` and the last value at which it leaves it. The peak count is tracked at the
/// same time, because that is what the majority test is made against.
///
/// Private, and the only place the endpoints are ever walked. Splitting the count out of it is what
/// lets the rule above change what is asked for without there being a second algorithm to keep in
/// step with this one.
fn sweep(intervals: &[OffsetInterval], required: usize) -> Option<Intersection> {
    if intervals.is_empty() {
        return None;
    }

    let mut ends: Vec<(Nanos, End)> = Vec::with_capacity(intervals.len() * 2);
    for i in intervals {
        ends.push((i.lo, End::Lower));
        ends.push((i.hi, End::Upper));
    }
    ends.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| match (a.1, b.1) {
            (End::Lower, End::Upper) => core::cmp::Ordering::Less,
            (End::Upper, End::Lower) => core::cmp::Ordering::Greater,
            _ => core::cmp::Ordering::Equal,
        })
    });

    let mut open = 0usize;
    let mut peak = 0usize;
    let mut peak_lo: Nanos = 0;
    let mut peak_hi: Option<Nanos> = None;
    let mut majority_lo: Option<Nanos> = None;
    let mut majority_hi: Option<Nanos> = None;

    for (value, end) in ends {
        match end {
            End::Lower => {
                open += 1;
                if open > peak {
                    peak = open;
                    peak_lo = value;
                    // The region has just been reopened, so its far end is not known yet.
                    peak_hi = None;
                }
                if open == required && majority_lo.is_none() {
                    majority_lo = Some(value);
                }
            }
            End::Upper => {
                if peak_hi.is_none() && open == peak {
                    // The first interval to close after the count last rose is what ends the
                    // region of maximum overlap.
                    peak_hi = Some(value);
                }
                if open == required {
                    // The count is about to fall below a majority. Keep the last such value, so a
                    // majority region in two parts is reported as the interval spanning both.
                    majority_hi = Some(value);
                }
                open -= 1;
            }
        }
    }

    let region = match (majority_lo, majority_hi) {
        (Some(lo), Some(hi)) => OffsetInterval::new(lo, hi),
        // No point anywhere reached a majority. The caller refuses; the peak region is reported
        // with it so the refusal can say what the sources did do.
        _ => OffsetInterval::new(peak_lo, peak_hi.unwrap_or(peak_lo)),
    };

    Some(Intersection {
        region,
        agreeing: peak,
        offered: intervals.len(),
        required,
        could_not_disagree: Vec::new(),
        free_majority: false,
    })
}

/// Which intervals could not have disagreed with anybody, as indices into the input.
///
/// **The test is about a set and not about one source.** A set of intervals is free agreement when
/// every member of it contains every interval outside the set whole. It was asked of one source at
/// a time until 2026-09-10, iterating so that setting aside the widest could expose a second one
/// behind it, and that shape misses the case the product actually meets: three Roughtime servers
/// each contain every NTP interval on offer and none of them contains the other two, so not one of
/// them qualified on its own and all three were counted as sources that agreed.
///
/// **Why the search is over the width order alone.** A member of such a set contains every
/// non-member, so it is at least as wide as every non-member, so the narrowest member is no
/// narrower than the widest non-member. Any free set is therefore the wide end of the round cut at
/// some width, and walking the cuts from the widest downwards finds the largest one that passes.
/// Nothing else has to be searched.
///
/// A cut is taken between distinct widths rather than between sources, so intervals of the same
/// width stay together. That is what keeps a set of identical sources whole, and it makes the answer
/// independent of the order the sources arrived in.
///
/// **Free agreement may never outnumber what is left, and this is the condition that keeps the rule
/// from being the fault it was written against.** Containment reads both ways. Three honest sources
/// stating eleven milliseconds each contain a fourth that states no uncertainty at all, so on the
/// containment test alone the three honest ones are the free agreement and the single point is left
/// to decide everything. That is the fault of 2026-09-07 over again: one packet claiming certainty
/// takes the whole region, and it would take it by making every honest source look like free
/// agreement. So a cut is only taken where what is left is at least as large as what is set aside,
/// which refuses that shape and still takes the two wide sources out of a round of four.
///
/// It never takes the whole round: the narrowest width in the round is never a cut, so at least
/// every interval of that width is left. The answer is empty in the ordinary case, where no source
/// swallowed the whole of the rest of the round.
fn could_not_disagree(intervals: &[OffsetInterval]) -> Vec<usize> {
    let widths: Vec<Nanos> = intervals.iter().map(OffsetInterval::width).collect();
    let mut cuts: Vec<Nanos> = widths.clone();
    cuts.sort_unstable();
    cuts.dedup();
    // The widest is not a cut, because a cut there leaves nothing outside the set for its members to
    // have failed to disagree with.
    cuts.pop();

    for cut in cuts {
        let wide: Vec<usize> = (0..intervals.len()).filter(|i| widths[*i] > cut).collect();
        let narrow: Vec<usize> = (0..intervals.len()).filter(|i| widths[*i] <= cut).collect();
        // Free agreement may never outnumber what is left. See the function documentation: this is
        // the line that stops the rule becoming the 2026-09-07 fault in a mirror.
        if narrow.len() < wide.len() {
            continue;
        }
        // Every member is strictly wider than every non-member by construction, so the only thing
        // left to ask is whether it swallows them.
        let free = wide.iter().all(|w| {
            narrow
                .iter()
                .all(|n| contains_whole(&intervals[*w], &intervals[*n]))
        });
        if free {
            return wide;
        }
    }

    Vec::new()
}

/// Whether `outer` allows every offset `inner` allows.
const fn contains_whole(outer: &OffsetInterval, inner: &OffsetInterval) -> bool {
    outer.lo <= inner.lo && outer.hi >= inner.hi
}

/// Split the intervals into the ones that constrained the region and the ones that did not.
///
/// The two lists are returned as indices into the input, so the caller can carry whatever it has
/// attached to each interval across the split.
///
/// The first test is a plain overlap against the region, which is the wording of the rule that
/// readings are never averaged into a true time: a source is discarded when its interval does not
/// overlap the majority. A source that does overlap is kept and is then weighted, and being kept is
/// not the same as being believed: a source inside the region can no longer move the region,
/// because the region is what a majority allows and one source is not a majority.
///
/// **The second test was added on 2026-09-08, and it is about the count rather than the region.** A
/// source that states a radius of an hour overlaps everything, so it survived the overlap test and
/// was reported as a source that agreed. Two honest Roughtime servers 10 s apart at a radius of 3 s
/// give no majority and a refusal; add one source stating an hour and the answer appears 16 s wide
/// with `offered: 3, kept: 3`, and that third figure is what a reader is given as the number of
/// sources that supported the bound. It supported nothing. It could not have disagreed with
/// anything, and a source that cannot disagree cannot agree either.
///
/// So a source that both swallows every other source whole and is the only reason a majority exists
/// at all is discarded here. Two conditions and both are needed, because each alone catches honest
/// work. Swallowing on its own is the ordinary case: three servers with different stated radii and
/// the same answer, where the widest contains the other two and is still corroborating them.
/// Creating the majority on its own is impossible for a source that could have disagreed, because a
/// source narrow enough to disagree is a source the others had to overlap.
///
/// Together they name one thing exactly: a source that turned a refusal into a bound while being
/// unable to contradict anybody. It is not counted among those that agreed, because it did not
/// agree with anything. It could not have done otherwise.
///
/// The narrowest source is never swallowed by anything, so at least one always survives and the
/// list never empties.
///
/// **What changed on 2026-09-09, and why this test stays anyway.** Until then, stopping such a
/// source from creating a majority in the first place was an open question rather than a defect,
/// and this test was all there was. It was decided: `intersect` now refuses that majority outright,
/// so a round reaching this function has already been through the stricter rule and the second test
/// below has nothing left to catch. It stays because `partition` is public and does not know what
/// its caller checked. A caller that partitions without asking `has_majority` first still gets a
/// count of the sources that supported the region, rather than one inflated by a source that
/// supported nothing.
#[must_use]
pub fn partition(
    intervals: &[OffsetInterval],
    region: &OffsetInterval,
) -> (Vec<usize>, Vec<usize>) {
    let mut kept = Vec::new();
    let mut discarded = Vec::new();
    for (i, interval) in intervals.iter().enumerate() {
        if interval.overlaps(region) && !made_the_majority_by_itself(intervals, i) {
            kept.push(i);
        } else {
            discarded.push(i);
        }
    }
    (kept, discarded)
}

/// What one selection round decided: the region to stand behind, and which sources held it up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// Everything the sweep over the whole round found, including the majority tests.
    pub found: Intersection,
    /// The region the surviving sources support, which is the term that goes in the bound.
    ///
    /// The same as `found.region` on every round where nothing extra was thrown out, and narrower
    /// exactly where a source that used to be kept is now in the minority. See `select`.
    pub region: OffsetInterval,
    /// The sources that held the region up, as indices into the input.
    pub kept: Vec<usize>,
    /// The sources selection threw out, as indices into the input.
    pub discarded: Vec<usize>,
}

/// Run one selection round: decide who is in the minority, then take the region without them.
///
/// # The departure this adds
///
/// **Who is in the minority is decided by the sources that could have disagreed, and by nobody
/// else.** `partition` asked whether a source reached the region a majority of the whole round
/// allowed, and a source that could not have disagreed with anybody is in that majority whatever
/// happens, so it lends its count to every position on offer including a liar's.
///
/// Measured on 2026-09-09 in `crates/clock/tests/two_kinds_of_source.rs`. Three honest NTP servers
/// throw out a liar two hundred milliseconds off them. Add three Roughtime servers stating a radius
/// of a second each and the liar is kept: seven sources tolerate three faults, the liar plus the
/// three wide servers is four, and that is a majority. The interval went from 69 ms to 223.5 ms and
/// the point estimate moved 82.6 ms, so three more honest servers bought a worse answer.
///
/// Nothing signed then was untrue and both bounds held UTC, which is why this is a strictness change
/// rather than a correctness fix. What was wrong is that the three faults were never earned. A
/// server stating a radius of a second could not have disagreed with one stating a millisecond
/// whatever either of them said, so it may not decide which of them is lying.
///
/// So the minority test is made over the sources that could have disagreed, at their own majority,
/// and the region is then swept over what is left standing. The count demanded of that sweep is
/// still the majority of the whole round, which is the half of this that matters most:
///
/// **This can narrow a region only by throwing a source out, and never otherwise.** A source that
/// does not reach the region contributes nothing inside it, so dropping it from the sweep cannot
/// move an edge; the region therefore comes back byte for byte where the discards are the discards
/// `partition` would have made. Where an extra source is thrown out, the region narrows by exactly
/// what that source was holding open. That is the only honest direction for a figure: a bound
/// narrows because something real got narrower, which here is a liar leaving the round.
///
/// **What this does not do, and it is the other half of the same fix.** The count demanded is still
/// the majority of the round as offered, so a source that could not have disagreed still raises how
/// many faults the width tolerates. Counting that over the sources that could have disagreed is the
/// same arithmetic pointed at the width, and it narrows ordinary honest rounds rather than only
/// hostile ones: four servers agreeing perfectly, nested inside each other because they agree, come
/// down to the narrowest of them with no fault tolerance left at all. That is a decision about the
/// product's central claim rather than a defect to fix, and it is still an open question.
///
/// Returns `None` only when no intervals were offered.
#[must_use]
pub fn select(intervals: &[OffsetInterval]) -> Option<Selection> {
    let found = intersect(intervals)?;

    // The sources that could have disagreed, and the region they support at their own majority.
    // Where the round has no free agreement in it this is the whole round and the region below is
    // the one `partition` was always asked about.
    let informative: Vec<usize> = (0..intervals.len())
        .filter(|i| !found.could_not_disagree.contains(i))
        .collect();
    let theirs: Vec<OffsetInterval> = informative.iter().map(|i| intervals[*i]).collect();
    let their_region = match sweep(&theirs, majority_of(theirs.len())) {
        Some(theirs) => theirs.region,
        None => found.region,
    };

    let (kept, discarded) = partition(intervals, &their_region);
    let standing: Vec<OffsetInterval> = kept.iter().map(|i| intervals[*i]).collect();
    let region = match sweep(&standing, majority_of(intervals.len())) {
        Some(taken) if taken.agreeing >= majority_of(intervals.len()) => taken.region,
        // Nothing left standing reaches the count the round asks for. The caller is refusing
        // anyway wherever that can happen, and reporting what the whole round found is the reading
        // that says the most about why.
        _ => found.region,
    };

    Some(Selection {
        found,
        region,
        kept,
        discarded,
    })
}

/// Whether the interval at `at` swallows every other one and is the whole reason there is a
/// majority.
fn made_the_majority_by_itself(intervals: &[OffsetInterval], at: usize) -> bool {
    if !swallows_every_other(intervals, at) {
        return false;
    }
    let rest: Vec<OffsetInterval> = intervals
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != at)
        .map(|(_, interval)| *interval)
        .collect();
    // `Option::is_none_or` would read better and is newer than this crate's minimum compiler.
    match intersect(&rest) {
        Some(found) => !found.has_majority(),
        None => true,
    }
}

/// Whether the interval at `at` contains every other interval, and at least one of them strictly.
///
/// The "at least one strictly" is what keeps a set of identical sources whole: three servers
/// stating the same interval each contain the others, and none of them is the free agreement this
/// is about.
fn swallows_every_other(intervals: &[OffsetInterval], at: usize) -> bool {
    let mine = &intervals[at];
    let mut wider_than_one = false;
    for (i, other) in intervals.iter().enumerate() {
        if i == at {
            continue;
        }
        if mine.lo > other.lo || mine.hi < other.hi {
            return false;
        }
        if mine.lo < other.lo || mine.hi > other.hi {
            wider_than_one = true;
        }
    }
    wider_than_one
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(lo: Nanos, hi: Nanos) -> OffsetInterval {
        OffsetInterval::new(lo, hi)
    }

    #[test]
    fn nothing_offered_gives_nothing_back() {
        assert!(intersect(&[]).is_none());
    }

    #[test]
    fn four_sources_give_the_region_a_majority_of_them_allow() {
        // All four overlap on [-3, 4] and three of the four overlap on [-6, 10]. The wider one is
        // the answer, because taking the narrower one is taking every source's word for it.
        let intervals = [iv(-10, 10), iv(-6, 12), iv(-8, 4), iv(-3, 20)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.agreeing, 4);
        assert_eq!(found.required, 3);
        assert_eq!(found.region, iv(-6, 10));
        assert!(found.has_majority());
    }

    #[test]
    fn a_source_claiming_certainty_cannot_take_the_region() {
        // Three sources that agree over a wide interval, and one that states a single point inside
        // it. Every honest interval covers that point, so the point is where the most intervals
        // overlap, and under the maximum-overlap rule it was the whole answer.
        let honest = iv(-11, 11);
        let intervals = [honest, honest, honest, iv(9, 9)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.agreeing, 4);
        assert_eq!(found.region, honest, "one source took the region");
        assert!(found.region.contains(0), "and took it away from the truth");
    }

    #[test]
    fn a_source_in_the_minority_cannot_widen_the_region_either() {
        // Rewritten 2026-09-08. It tried five zero-width points and nothing else, which is the one
        // shape that cannot widen anything whatever the rule is, so it passed under a rule it was
        // not testing. Widening needs a source wider than the region, so that is what it tries now:
        // every width from narrower than the honest sources to far wider, at every offset from well
        // below them to well above.
        let honest = iv(-11, 11);
        for lie_lo in [-4_000, -40, -12, -9, 0, 9, 12, 40] {
            for width in [0, 1, 20, 500, 8_000] {
                let liar = iv(lie_lo, lie_lo + width);
                let found = intersect(&[honest, honest, honest, liar]).unwrap();
                assert_eq!(
                    found.region, honest,
                    "a source at {liar:?} moved the region a majority supports"
                );
            }
        }
    }

    /// The case the departure from textbook Marzullo exists for, with both rules run side by side.
    ///
    /// Two honest sources that do not overlap give no majority and a refusal. One source stating a
    /// radius wide enough to cover both of them turns that into an answer spanning the gap between
    /// them. Nothing about that answer is a lie: it is what Marzullo's arithmetic gives once three
    /// intervals are offered and one fault is tolerated, and the region does hold the truth while at
    /// most one of the three is faulty.
    ///
    /// This product refuses it anyway, decided on 2026-09-09. The test asserts both halves, because
    /// a guarantee nobody can demonstrate the difference of is not a guarantee: the textbook rule
    /// says majority and ours says no.
    #[test]
    fn a_majority_made_only_of_free_agreement_is_refused() {
        let first = iv(-3_000, 3_000);
        let second = iv(7_000, 13_000);
        let everything = iv(-3_600_000, 3_600_000);

        let two = intersect(&[first, second]).unwrap();
        assert!(
            !two.has_majority(),
            "two sources 10 s apart at a radius of 3 s agree nowhere"
        );

        let three = intersect(&[first, second, everything]).unwrap();
        assert!(
            three.has_textbook_majority(),
            "the textbook rule counts two of three, and this is the reading we depart from"
        );
        assert!(three.free_majority);
        assert_eq!(three.could_not_disagree, vec![2]);
        assert!(
            !three.has_majority(),
            "the only reason there is a majority is a source that could not have disagreed"
        );

        assert_eq!(
            three.region,
            iv(-3_000, 13_000),
            "the region is still the textbook one, so a refusal can say what was on offer"
        );
    }

    /// One pass is not enough, which is the case that made the rule a loop.
    ///
    /// Two useless sources, the second a minute wider than the first. Only the wider of the two
    /// contains the other, so a single pass sets that one aside and leaves the second holding a
    /// majority it is equally unable to have earned.
    #[test]
    fn free_agreement_is_set_aside_until_none_is_left() {
        let first = iv(-3_000, 3_000);
        let second = iv(7_000, 13_000);
        let hour = iv(-3_600_000, 3_600_000);
        let hour_and_a_minute = iv(-3_660_000, 3_660_000);

        let four = intersect(&[first, second, hour, hour_and_a_minute]).unwrap();
        assert!(four.has_textbook_majority());
        assert_eq!(
            four.could_not_disagree,
            vec![2, 3],
            "both wide sources are free agreement and one pass only finds the wider"
        );
        assert!(!four.has_majority());
    }

    /// Marzullo's own answer over a round, for a test that wants to say what the textbook would
    /// have done with the same intervals.
    fn textbook(intervals: &[OffsetInterval]) -> Intersection {
        sweep(intervals, majority_of(intervals.len())).expect("a round with sources in it")
    }

    /// The rules never accept anything the textbook refuses, and never widen a region.
    ///
    /// It is the whole of what the two departures claim, so it is checked over a spread of shapes
    /// rather than argued for in a comment. Anything asserted here failing means the guarantee is
    /// weaker than the standard rather than stricter, which is the one direction that is not
    /// allowed.
    ///
    /// **The assertion was equality until 2026-09-10 and it is containment now.** The first
    /// departure never moved a region, because it only ever decided whether to stand behind
    /// one. The second changes how many intervals have to allow a point, so where free
    /// agreement is set aside the region is smaller than the textbook one. Smaller is the
    /// direction that asks for more agreement rather than less, which is why containment is the
    /// right test and equality was.
    #[test]
    fn the_rules_only_ever_ask_for_more_agreement_and_never_less() {
        let shapes: [&[OffsetInterval]; 8] = [
            &[iv(-10, 10), iv(-6, 12), iv(-8, 4), iv(-3, 20)],
            &[iv(-11, 11), iv(-11, 11), iv(-11, 11), iv(9, 9)],
            &[
                iv(-3_000, 3_000),
                iv(7_000, 13_000),
                iv(-3_600_000, 3_600_000),
            ],
            &[iv(-7, 7), iv(-14, 14), iv(-5, 5)],
            &[iv(0, 10), iv(10, 20), iv(5, 15)],
            &[iv(-10, 10), iv(-8, 8), iv(1_000, 1_020), iv(1_005, 1_025)],
            &[iv(0, 10), iv(100, 110), iv(5, 105)],
            &[iv(-5, 5)],
        ];
        for shape in shapes {
            let found = intersect(shape).unwrap();
            let marzullo = textbook(shape);
            assert!(
                found.required >= marzullo.required,
                "the rule asked for less agreement than Marzullo on {shape:?}"
            );
            assert!(
                contains_whole(&marzullo.region, &found.region),
                "the rule widened the region on {shape:?}, from {:?} to {:?}",
                marzullo.region,
                found.region
            );
            assert_eq!(found.agreeing, marzullo.agreeing);
            if found.has_majority() {
                assert!(
                    marzullo.has_textbook_majority(),
                    "the rule accepted {shape:?}, which Marzullo refuses"
                );
            }
        }
    }

    /// Every interval whose ends are drawn from a small grid, which is the alphabet the two
    /// exhaustive checks below run over.
    ///
    /// A grid rather than a list of shapes somebody chose. Eight hand-written shapes prove that
    /// eight shapes behave, and the claim this file makes is about every round it will ever see.
    fn every_interval_up_to(width: Nanos) -> Vec<OffsetInterval> {
        let mut all = Vec::new();
        for lo in 0..=width {
            for hi in lo..=width {
                all.push(iv(lo, hi));
            }
        }
        all
    }

    /// Call `visit` with every ordered set of `size` intervals drawn from `alphabet`.
    fn every_round_of(
        alphabet: &[OffsetInterval],
        size: usize,
        mut visit: impl FnMut(&[OffsetInterval]),
    ) {
        let mut at = vec![0usize; size];
        loop {
            let round: Vec<OffsetInterval> = at.iter().map(|i| alphabet[*i]).collect();
            visit(&round);

            let mut carry = size;
            while carry > 0 {
                carry -= 1;
                at[carry] += 1;
                if at[carry] < alphabet.len() {
                    break;
                }
                at[carry] = 0;
                if carry == 0 {
                    return;
                }
            }
        }
    }

    /// What is left of a round once the free agreement is set aside.
    fn survivors_of(intervals: &[OffsetInterval]) -> Vec<OffsetInterval> {
        let aside = could_not_disagree(intervals);
        intervals
            .iter()
            .enumerate()
            .filter(|(i, _)| !aside.contains(i))
            .map(|(_, interval)| *interval)
            .collect()
    }

    /// How often each of the two interesting outcomes was reached, so a check cannot pass by never
    /// reaching them.
    #[derive(Default)]
    struct Tally {
        rounds: usize,
        refused_where_the_textbook_signs: usize,
        signed_with_free_agreement_present: usize,
    }

    /// The rule's exact effect, stated as one equivalence and checked over every round in the grid.
    ///
    /// **`has_majority` is true exactly when the sources that could have disagreed reach a majority
    /// among themselves.** That single sentence carries both directions, and the second direction is
    /// the one this test exists for.
    ///
    /// One direction is the guarantee the file already claimed: where the survivors reach nothing,
    /// the answer is refused. The other is the one nothing was checking, and it is the dangerous
    /// one. **The failure that hurts is an honest round refused, not a dishonest one signed.** An
    /// agent that stops signing looks like a network fault, nobody reads it as a defect, and a suite
    /// that only asserts refusals happen would watch it pass. So the equivalence is asserted in both
    /// directions at once: the rule cannot refuse a round whose survivors agree, whatever the shape
    /// of the round.
    ///
    /// It also asserts that the count is the textbook one on every round and that the region is
    /// never wider than the textbook one, over a generated space rather than over eight shapes.
    ///
    /// The equivalence is provable rather than only observed, and the proof is why the arithmetic
    /// below is allowed to be a check rather than a search. Every set-aside interval contains every
    /// interval left in the round whole. Take a point that a majority of the `k` survivors allow.
    /// Each of the `m` set-aside intervals contains a survivor that allows it, so all `m` allow it
    /// too, and the count there is at least `k / 2 + 1 + m`, which is exactly what `required` asks
    /// for. And in the other direction, a point reaching `required` needs at least `k / 2 + 1` of
    /// the survivors, because only `m` intervals were set aside. So the two can never disagree, in
    /// either direction, and neither an honest round is refused nor a free majority signed.
    #[test]
    fn the_rule_refuses_exactly_when_the_survivors_reach_no_majority_of_their_own() {
        let alphabet = every_interval_up_to(4);
        let mut tally = Tally::default();

        for size in 1..=4 {
            every_round_of(&alphabet, size, |round| {
                let found = intersect(round).expect("a round with sources in it");
                let marzullo = textbook(round);

                assert!(
                    contains_whole(&marzullo.region, &found.region),
                    "the rule widened the region on {round:?}"
                );
                assert_eq!(found.agreeing, marzullo.agreeing, "on {round:?}");
                assert_eq!(found.offered, marzullo.offered, "on {round:?}");

                let survivors = survivors_of(round);
                assert!(
                    !survivors.is_empty(),
                    "the set-aside emptied the round on {round:?}"
                );
                let survivors_agree = textbook(&survivors).has_textbook_majority();

                assert_eq!(
                    found.has_majority(),
                    survivors_agree,
                    "the rule and the survivors disagree on {round:?}: the survivors are \
                     {survivors:?} and the rule set aside {:?}",
                    found.could_not_disagree
                );

                tally.rounds += 1;
                if marzullo.has_textbook_majority() && !found.has_majority() {
                    tally.refused_where_the_textbook_signs += 1;
                }
                if !found.could_not_disagree.is_empty() && found.has_majority() {
                    tally.signed_with_free_agreement_present += 1;
                }
            });
        }

        // A property test that never reaches the case it is about passes for the wrong reason, and
        // one in this crate did exactly that once. Both interesting outcomes have to occur.
        assert_eq!(tally.rounds, 54_240, "the grid changed size");
        assert!(
            tally.refused_where_the_textbook_signs > 0,
            "the grid never produced a round this rule refuses, so it proved nothing"
        );
        assert!(
            tally.signed_with_free_agreement_present > 0,
            "the grid never produced a round with free agreement in it that was still signed"
        );
    }

    /// A round of sources that genuinely could have disagreed and did not is signed, always.
    ///
    /// The same claim as the equivalence above, put the way the risk was written: where every source
    /// in the round could have been contradicted by the others, this file's rule has nothing to set
    /// aside and must behave exactly like textbook Marzullo. If it ever does not, the agent has
    /// started refusing honest rounds.
    #[test]
    fn a_round_nobody_could_agree_with_for_free_is_decided_by_the_textbook_alone() {
        let alphabet = every_interval_up_to(5);
        let mut honest_rounds = 0usize;
        let mut signed = 0usize;

        for size in 2..=3 {
            every_round_of(&alphabet, size, |round| {
                let found = intersect(round).expect("a round with sources in it");
                if !found.could_not_disagree.is_empty() {
                    return;
                }
                honest_rounds += 1;
                assert_eq!(
                    found.has_majority(),
                    found.has_textbook_majority(),
                    "no source here could agree for free, so the rule may not touch {round:?}"
                );
                if found.has_majority() {
                    signed += 1;
                }
            });
        }

        assert!(
            honest_rounds > 0,
            "the grid produced no round of this shape"
        );
        assert!(
            signed > 0,
            "and none of them was signed, so nothing was proved"
        );
    }

    /// A bridging source is not free agreement, and telling the two apart is the point of the test.
    ///
    /// The middle source overlaps both of the others and contains neither. It could have disagreed
    /// with either of them and it did not, and it excludes everything outside itself, so it is doing
    /// real work and the majority it takes part in stands.
    #[test]
    fn a_source_that_bridges_two_that_disagree_still_counts() {
        let intervals = [iv(0, 10), iv(100, 110), iv(5, 105)];
        let found = intersect(&intervals).unwrap();
        assert!(found.could_not_disagree.is_empty());
        assert!(found.has_majority());
        assert_eq!(found.region, iv(5, 105));
    }

    #[test]
    fn a_source_wider_than_the_region_still_counts() {
        // The rule is about a source that swallows every other source, not about one wider than the
        // region. A source with a larger stated radius than its neighbours is the ordinary case and
        // it is doing real work: it could have disagreed with them and it did not.
        let intervals = [iv(-10, 10), iv(-6, 12), iv(-8, 4), iv(900, 1_100)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.region, iv(-6, 4));
        let (kept, discarded) = partition(&intervals, &found.region);
        assert_eq!(
            kept,
            vec![0, 1, 2],
            "the first is wider than the region at both ends and swallows nothing"
        );
        assert_eq!(discarded, vec![3]);
    }

    #[test]
    fn the_widest_of_several_agreeing_sources_still_counts() {
        // Three honest servers with the same answer and different stated radii, which is what a
        // real pool looks like. The widest swallows the other two and is corroborating them: take
        // it away and the remaining two still reach a majority, so it did not make one. Selection
        // from 2026-09-10 sets it aside for deciding who is in the minority, and nobody here is, so
        // the region is where it always was.
        let intervals = [iv(-7, 7), iv(-14, 14), iv(-5, 5)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.could_not_disagree, vec![1]);
        assert_eq!(found.informative(), 2);
        assert_eq!(found.region, iv(-7, 7));
        let taken = select(&intervals).unwrap();
        assert_eq!(taken.region, iv(-7, 7), "an honest round was narrowed");
        assert_eq!(taken.kept, vec![0, 1, 2]);
        assert!(taken.discarded.is_empty());
    }

    /// Selection narrows a region by throwing a source out, and never any other way.
    ///
    /// The half of the fix that is built, checked over every round in the grid rather than over the
    /// case that raised it. Two things are asserted on every round. The region selection stands
    /// behind is never wider than the one the whole round supports. And where selection threw out
    /// exactly what `partition` over that region would have thrown out, the region is that region,
    /// byte for byte: an honest round cannot be narrowed by this rule, only a round with somebody
    /// in it that the sources which could have disagreed put in the minority.
    #[test]
    fn a_region_narrows_only_where_a_source_was_thrown_out() {
        let alphabet = every_interval_up_to(4);
        let mut unchanged = 0usize;
        let mut narrowed = 0usize;

        every_round_of(&alphabet, 3, |round| {
            let taken = select(round).expect("a round with sources in it");
            let (_, would_have) = partition(round, &taken.found.region);

            assert!(
                contains_whole(&taken.found.region, &taken.region),
                "selection widened the region on {round:?}"
            );

            if taken.discarded == would_have {
                unchanged += 1;
                assert_eq!(
                    taken.region, taken.found.region,
                    "the same sources were thrown out and the region moved on {round:?}"
                );
            } else {
                narrowed += 1;
                assert!(
                    taken.discarded.len() > would_have.len(),
                    "selection kept a source the whole round threw out, on {round:?}"
                );
            }
        });

        // Pinned rather than bounded, in this file's usual way: a check that only asks for "some"
        // passes for the wrong reason the day the rule changes shape.
        assert_eq!(unchanged, 2_871, "the grid or the rule changed shape");
        assert_eq!(narrowed, 504, "the grid or the rule changed shape");
    }

    /// Adding sources that could not have disagreed changes nobody's standing.
    ///
    /// The property the fix is about, put the way the harm was written. Each round gets two more
    /// sources, both stretched a whole span past its widest interval at each end, so both swallow
    /// everything and neither could have disagreed with anybody. Exactly the same sources have to
    /// be thrown out afterwards as before.
    ///
    /// **It skips rounds rather than asserting over all of them, and the tally is why that is not an
    /// escape hatch.** Free agreement is only ever set aside while what is left is at least as
    /// large, so two more free sources can push a round past that line and change which of its own
    /// sources are set aside. The round that could have disagreed is then a different round.
    #[test]
    fn sources_that_could_not_have_disagreed_change_nobody_else_s_standing() {
        let alphabet = every_interval_up_to(4);
        let mut compared = 0usize;

        every_round_of(&alphabet, 3, |round| {
            let before = select(round).expect("a round with sources in it");

            let lo = round.iter().map(|i| i.lo).min().expect("a round");
            let hi = round.iter().map(|i| i.hi).max().expect("a round");
            let span = (hi - lo).max(1);
            let mut with_free = round.to_vec();
            with_free.push(iv(lo - span, hi + span));
            with_free.push(iv(lo - 2 * span, hi + 2 * span));
            let after = select(&with_free).expect("the same round and two more");

            assert!(
                after.found.could_not_disagree.contains(&3)
                    && after.found.could_not_disagree.contains(&4),
                "a source swallowing the whole round was counted as one that could have                  disagreed, on {round:?}"
            );
            if after.found.informative() != before.found.informative() {
                return;
            }
            compared += 1;
            let still_out: Vec<usize> = after
                .discarded
                .iter()
                .copied()
                .filter(|i| *i < round.len())
                .collect();
            assert_eq!(
                still_out, before.discarded,
                "two sources that could not have disagreed changed who was in the minority on                  {round:?}"
            );
        });

        assert_eq!(compared, 2_028, "the grid or the guard changed shape");
    }

    #[test]
    fn identical_sources_all_count() {
        // The region is exactly what each of them says, so none of them is wider than it and the
        // ordinary case is untouched by the rule above.
        let honest = iv(-11, 11);
        let intervals = [honest, honest, honest];
        let found = intersect(&intervals).unwrap();
        let (kept, discarded) = partition(&intervals, &found.region);
        assert_eq!(kept, vec![0, 1, 2]);
        assert!(discarded.is_empty());
    }

    #[test]
    fn the_source_that_disagrees_is_discarded_and_not_blended_in() {
        let good = [iv(-10, 10), iv(-6, 12), iv(-8, 4)];
        let liar = iv(900, 1_100);
        let intervals = [good[0], good[1], good[2], liar];

        let found = intersect(&intervals).unwrap();
        assert_eq!(found.agreeing, 3);
        assert!(found.has_majority());

        let (kept, discarded) = partition(&intervals, &found.region);
        assert_eq!(kept, vec![0, 1, 2]);
        assert_eq!(discarded, vec![3]);

        // The region owes nothing at all to the source that lied. Had the four been averaged, the
        // answer would have been dragged 250 units away from the truth.
        assert!(found.region.hi < 100);
    }

    #[test]
    fn two_against_two_is_not_a_majority() {
        let intervals = [iv(-10, 10), iv(-8, 8), iv(1_000, 1_020), iv(1_005, 1_025)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.agreeing, 2);
        assert_eq!(found.offered, 4);
        assert!(!found.has_majority());
    }

    #[test]
    fn intervals_that_only_touch_still_overlap() {
        // All three meet at the single point 10, so the count reaches three there rather than
        // stopping at two. The region reported is the one two of the three allow.
        let intervals = [iv(0, 10), iv(10, 20), iv(5, 15)];
        let found = intersect(&intervals).unwrap();
        assert_eq!(found.agreeing, 3);
        assert_eq!(found.required, 2);
        assert_eq!(found.region, iv(5, 15));
    }

    #[test]
    fn one_source_alone_is_reported_as_no_majority_by_the_caller() {
        let found = intersect(&[iv(-5, 5)]).unwrap();
        assert_eq!(found.agreeing, 1);
        assert_eq!(found.offered, 1);
        // One out of one passes the arithmetic test, which is why the model checks the source count
        // separately before it ever gets here.
        assert!(found.has_majority());
    }

    #[test]
    fn every_kept_interval_reaches_the_region_and_the_far_one_does_not() {
        let intervals = [iv(-10, 10), iv(-6, 12), iv(-8, 4), iv(-3, 20), iv(500, 600)];
        let found = intersect(&intervals).unwrap();
        let (kept, discarded) = partition(&intervals, &found.region);
        for i in &kept {
            assert!(intervals[*i].overlaps(&found.region));
        }
        assert_eq!(discarded, vec![4]);
    }

    #[test]
    fn the_region_holds_the_truth_while_a_majority_of_sources_are_honest() {
        // The property the whole file exists for, checked over every placement of one liar against
        // four honest sources whose intervals differ from each other.
        let truth = 0;
        let honest = [iv(-11, 9), iv(-7, 13), iv(-9, 11), iv(-13, 7)];
        for lie_lo in [-30, -12, -6, -1, 0, 1, 6, 12, 30] {
            for width in [0, 1, 20, 500] {
                let mut intervals = honest.to_vec();
                intervals.push(iv(lie_lo, lie_lo + width));
                let found = intersect(&intervals).unwrap();
                assert!(found.has_majority());
                assert!(
                    found.region.contains(truth),
                    "a liar at [{lie_lo}, {}] left the region {:?}, which does not hold the truth",
                    lie_lo + width,
                    found.region
                );
            }
        }
    }
}
