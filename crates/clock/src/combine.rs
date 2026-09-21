//! Combining the survivors, which is weighting and never averaging.
//!
//! Once the sources that disagree have been discarded, the ones left are weighted by the inverse
//! square of what each of them said about itself, so a tight nearby source counts for far more than
//! a loose distant one. A plain mean over the survivors would treat a source with a fifty
//! millisecond interval as the equal of one with a two millisecond interval, which is not what
//! either of them said.
//!
//! ## What is weighted is each source's own width and not the interval it ends up with
//!
//! A source's interval is two things added together: what the source itself supports, which is half
//! its round trip plus what it said about its own distance from its reference, and the model's
//! ageing of that sample over the time since it arrived. Every source in a round is aged over
//! roughly the same time, so the second term is very nearly common to all of them.
//!
//! A term they all share carries no information about which of them to believe. Worse, it is the
//! same model error applied to every source rather than an independent one, and inverse-variance
//! weighting is only the right answer over the parts that are independent. Adding it in before
//! weighting drags every weight toward every other, which is a plain mean arriving by the back
//! door.
//!
//! It was measured rather than argued. At sixty seconds of age the ageing term went from 0.9 ms to
//! 8.4 ms when the model started carrying what it actually knows about the counter, and a 1 ms
//! source against a 50 ms source went from a weight ratio of 717 to a ratio of 38. The ratio the
//! two sources' own numbers support is 2500 and it does not move with age at all.
//!
//! The ageing term is not thrown away. It is in the width of every source's interval, so it is in
//! the intersection those intervals produce, which is the interval this product claims. What
//! changes here is only where inside that interval the point estimate sits.
//!
//! The result is a point estimate and nothing more. The claim this product makes is the interval
//! the intersection produced, and the point is clamped into it so it can never sit outside its own
//! bound.

use timewitness_core::{Nanos, OffsetInterval};

/// The point estimate and how it was arrived at.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Combination {
    /// The weighted point estimate, already clamped inside the region it came from.
    pub offset: Nanos,
    /// The sum of the weights, which the regression uses to weight this round against others.
    pub weight: f64,
}

/// The weight a source's own width carries.
///
/// Inverse square of that width, floored so a source claiming no uncertainty at all cannot claim
/// infinite authority. A source reporting no uncertainty is reporting something it cannot know, and
/// the floor is what stops that claim swamping every other source.
///
/// The width handed in is the source's own, twice [`Sample::own_half`], and never the width of the
/// interval it ends up with. The module note above says why.
///
/// `width_floor` is `Policy::weight_floor` and is nothing else. It was the allowance for reading the
/// local counter until 2026-09-07, which is a number ten thousand times larger and about something
/// unrelated. Where every survivor sat at or below it, every weight came out the same and this
/// function returned a plain mean of the midpoints without saying so, which is the one combination
/// the averaging rule forbids by name. Keep the two apart.
///
/// [`Sample::own_half`]: crate::sample::Sample::own_half
#[must_use]
pub fn weight_of(own_width: Nanos, width_floor: Nanos) -> f64 {
    let width = own_width.max(width_floor.max(1)) as f64;
    1.0 / (width * width)
}

/// Combine the surviving intervals into one point inside `region`.
///
/// `own_halves` runs alongside `survivors` and carries each source's own half width, before the
/// model's ageing. A shorter list than `survivors` is a caller fault and is refused rather than
/// guessed at, because silently falling back to the interval width is the behaviour this signature
/// exists to remove.
///
/// Returns `None` when nothing survived.
#[must_use]
pub fn combine(
    survivors: &[OffsetInterval],
    own_halves: &[Nanos],
    region: &OffsetInterval,
    width_floor: Nanos,
) -> Option<Combination> {
    if survivors.is_empty() || own_halves.len() != survivors.len() {
        return None;
    }

    let mut total_weight = 0.0f64;
    let mut weighted_sum = 0.0f64;
    for (interval, own_half) in survivors.iter().zip(own_halves) {
        let w = weight_of(own_half.saturating_mul(2), width_floor);
        total_weight += w;
        weighted_sum += w * interval.midpoint() as f64;
    }

    if total_weight <= 0.0 || !total_weight.is_finite() {
        return None;
    }

    let raw = weighted_sum / total_weight;
    let offset = if raw.is_finite() {
        raw as Nanos
    } else {
        region.midpoint()
    };

    // The weighted point is a summary of the survivors and the region is the set of offsets every
    // survivor allows. When a wide, badly placed source drags the point outside the region, the
    // region wins, because the region is the part that is actually supported.
    let clamped = offset.clamp(region.lo, region.hi);

    Some(Combination {
        offset: clamped,
        weight: total_weight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};

    fn iv(lo: Nanos, hi: Nanos) -> OffsetInterval {
        OffsetInterval::new(lo, hi)
    }

    /// Half of each interval's own width, for a round where the model has aged nothing.
    fn halves(intervals: &[OffsetInterval]) -> Vec<Nanos> {
        intervals.iter().map(|i| i.width() / 2).collect()
    }

    #[test]
    fn a_tight_source_outweighs_a_loose_one() {
        let tight = iv(-NANOS_PER_MILLI, NANOS_PER_MILLI);
        let loose = iv(30 * NANOS_PER_MILLI, 70 * NANOS_PER_MILLI);
        assert!(weight_of(tight.width(), 1) > weight_of(loose.width(), 1) * 100.0);
    }

    #[test]
    fn the_result_is_not_the_plain_mean_of_the_midpoints() {
        // Midpoints are 0 and 40 ms, so a plain mean would be 20 ms. Inverse square weighting on
        // widths of 2 ms and 40 ms puts the answer four hundred times closer to the tight source.
        let tight = iv(-NANOS_PER_MILLI, NANOS_PER_MILLI);
        let loose = iv(20 * NANOS_PER_MILLI, 60 * NANOS_PER_MILLI);
        let region = iv(-NANOS_PER_MILLI, 60 * NANOS_PER_MILLI);
        let combined = combine(&[tight, loose], &halves(&[tight, loose]), &region, 1).unwrap();
        let plain_mean = 20 * NANOS_PER_MILLI;
        assert!(combined.offset < plain_mean / 10, "got {}", combined.offset);
    }

    #[test]
    fn the_point_never_sits_outside_the_region_it_came_from() {
        // A wide source placed far away drags the weighted point out of the region. The region is
        // what every survivor allows, so the point is pulled back into it.
        let near = iv(0, 20);
        let far = iv(19, 100_000);
        let region = iv(19, 20);
        let combined = combine(&[near, far], &halves(&[near, far]), &region, 1).unwrap();
        assert!(
            region.contains(combined.offset),
            "{} not in {region:?}",
            combined.offset
        );
    }

    #[test]
    fn a_zero_width_interval_cannot_claim_infinite_authority() {
        let exact = iv(5, 5);
        let normal = iv(-10, 10);
        let region = iv(5, 5);
        let combined =
            combine(&[exact, normal], &halves(&[exact, normal]), &region, 1_000).unwrap();
        assert!(combined.weight.is_finite());
        assert_eq!(combined.offset, 5);
    }

    #[test]
    fn nothing_surviving_gives_nothing_back() {
        assert!(combine(&[], &[], &iv(0, 0), 1).is_none());
    }

    #[test]
    fn a_list_of_halves_that_does_not_match_the_survivors_is_refused_rather_than_guessed_at() {
        let a = iv(-1, 1);
        let b = iv(9, 11);
        assert!(combine(&[a, b], &[1], &iv(-1, 11), 1).is_none());
        assert!(combine(&[a, b], &[1, 1, 1], &iv(-1, 11), 1).is_none());
        assert!(combine(&[a, b], &[1, 1], &iv(-1, 11), 1).is_some());
    }

    /// The ageing term is common to the round, so it must not change which source is believed.
    ///
    /// This is queue-free arithmetic and it is the whole of what the change is for. A 1 ms source
    /// and a 50 ms source are weighted 2500 to 1 by their own numbers. Age them both by 8.4 ms,
    /// which is what a minute costs at the shipped policy, and weighting on the aged widths gives
    /// 38 to 1. Weighting on their own widths gives 2500 to 1 at every age.
    #[test]
    fn ageing_the_round_does_not_change_how_much_the_weighting_discriminates() {
        let tight_own = NANOS_PER_MILLI;
        let loose_own = 50 * NANOS_PER_MILLI;
        let region = iv(-200 * NANOS_PER_MILLI, 200 * NANOS_PER_MILLI);

        let ratio_on_own = weight_of(tight_own * 2, 1) / weight_of(loose_own * 2, 1);
        assert!(
            (ratio_on_own - 2500.0).abs() < 1.0,
            "a fifty times tighter source earns two and a half thousand times the weight, not {ratio_on_own}"
        );

        let mut points = Vec::new();
        for ageing in [0, NANOS_PER_MILLI / 10, 8_400_000, 100 * NANOS_PER_MILLI] {
            let tight = OffsetInterval::centred(0, tight_own + ageing);
            let loose = OffsetInterval::centred(40 * NANOS_PER_MILLI, loose_own + ageing);
            let combined = combine(&[tight, loose], &[tight_own, loose_own], &region, 1)
                .expect("two survivors combine");
            points.push(combined.offset);

            let on_the_aged_widths = weight_of(tight.width(), 1) / weight_of(loose.width(), 1);
            assert!(
                on_the_aged_widths <= ratio_on_own + 1.0,
                "the aged ratio can only ever be smaller, and it is {on_the_aged_widths}"
            );
        }

        // Every age gives the same point, because the term that moved is no longer in the weights.
        assert!(
            points.windows(2).all(|w| w[0] == w[1]),
            "the point moved with the age of the round: {points:?}"
        );
        // And it is nowhere near the plain mean of 20 ms, which is where the aged weighting drifts.
        assert!(
            points[0] < 2 * NANOS_PER_MILLI,
            "the point is {} and a plain mean would be {}",
            points[0],
            20 * NANOS_PER_MILLI
        );
    }

    /// The old behaviour, kept as the record of what was wrong rather than as a thing to go back to.
    #[test]
    fn weighting_on_the_aged_widths_walks_toward_a_plain_mean_as_the_round_ages() {
        let tight_own = NANOS_PER_MILLI;
        let loose_own = 50 * NANOS_PER_MILLI;
        let region = iv(-200 * NANOS_PER_MILLI, 200 * NANOS_PER_MILLI);
        let plain_mean = 20 * NANOS_PER_MILLI;

        let mut previous = 0;
        for ageing in [0, 8_400_000, 100 * NANOS_PER_MILLI, NANOS_PER_SEC] {
            let tight = OffsetInterval::centred(0, tight_own + ageing);
            let loose = OffsetInterval::centred(40 * NANOS_PER_MILLI, loose_own + ageing);
            // What the code did before: the aged widths, handed in as though they were their own.
            let combined = combine(
                &[tight, loose],
                &[tight.width() / 2, loose.width() / 2],
                &region,
                1,
            )
            .expect("two survivors combine");
            assert!(
                combined.offset >= previous,
                "each step of ageing moved the point toward the mean, {} then {}",
                previous,
                combined.offset
            );
            previous = combined.offset;
        }
        assert!(
            previous > plain_mean / 2,
            "at a second of ageing the old weighting is most of the way to the plain mean of {plain_mean}, and it reached {previous}"
        );
    }
}

#[cfg(test)]
mod floor_tests {
    use super::*;
    use crate::policy::Policy;
    use timewitness_core::time::NANOS_PER_MICRO;

    /// Two sources on a local network, both tighter than the allowance for a local counter read.
    /// Half of each interval's own width, for a round where the model has aged nothing.
    fn halves(intervals: &[OffsetInterval]) -> Vec<Nanos> {
        intervals.iter().map(|i| i.width() / 2).collect()
    }

    fn two_lan_sources() -> (OffsetInterval, OffsetInterval) {
        (
            OffsetInterval::centred(0, NANOS_PER_MICRO),
            OffsetInterval::centred(400 * NANOS_PER_MICRO, 4 * NANOS_PER_MICRO),
        )
    }

    #[test]
    fn sources_tighter_than_the_read_allowance_are_still_weighted_against_each_other() {
        // Both intervals are narrower than `scheduling_floor`, which is what a good local network
        // looks like. At the policy's weight floor the tight one carries sixteen times the weight of
        // the loose one, so the combined point sits close to it rather than half way between.
        let (tight, loose) = two_lan_sources();
        let region = OffsetInterval::new(-100 * NANOS_PER_MICRO, 500 * NANOS_PER_MICRO);
        let floor = Policy::default().weight_floor;

        let combined = combine(&[tight, loose], &halves(&[tight, loose]), &region, floor)
            .expect("two survivors combine");
        let mean = (tight.midpoint() + loose.midpoint()) / 2;

        assert!(
            combined.offset < mean / 2,
            "the point is {} and an unweighted mean would be {mean}, so the weighting is not doing anything",
            combined.offset
        );
        assert!(
            weight_of(tight.width(), floor) > 10.0 * weight_of(loose.width(), floor),
            "a four times tighter source should carry sixteen times the weight"
        );
    }

    #[test]
    fn the_read_allowance_would_have_flattened_them_into_a_mean() {
        // The same two sources at the value the floor used to take, which is what the combination
        // degenerated to. Kept as the record of what was wrong: the assertion is that this is a
        // plain mean, and the test above is that the shipped floor is not.
        let (tight, loose) = two_lan_sources();
        let region = OffsetInterval::new(-100 * NANOS_PER_MICRO, 500 * NANOS_PER_MICRO);
        let shared = Policy::default().scheduling_floor;

        let combined = combine(&[tight, loose], &halves(&[tight, loose]), &region, shared)
            .expect("two survivors combine");
        let mean = (tight.midpoint() + loose.midpoint()) / 2;

        let a = weight_of(tight.width(), shared);
        let b = weight_of(loose.width(), shared);
        assert!(
            (a - b).abs() < a * 1e-12,
            "at the old shared value every weight was identical, and these are {a} and {b}"
        );
        assert_eq!(
            combined.offset, mean,
            "which made the combination an unweighted mean of the midpoints"
        );
    }

    #[test]
    fn the_two_floors_are_not_the_same_number() {
        let p = Policy::default();
        assert_ne!(
            p.weight_floor, p.scheduling_floor,
            "the cost of a local read and the width below which a source may not claim authority are unrelated quantities, and holding them as one value is what produced the mean"
        );
    }
}
