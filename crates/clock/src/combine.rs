//! Combining the survivors, which is weighting and never averaging.
//!
//! Once the sources that disagree have been discarded, the ones left are weighted by the inverse
//! square of their interval widths, so a tight nearby source counts for far more than a loose
//! distant one. A plain mean over the survivors would treat a source with a fifty millisecond
//! interval as the equal of one with a two millisecond interval, which is not what either of them
//! said.
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

/// The weight one interval carries.
///
/// Inverse square of the width, with the width floored so a zero-width interval cannot claim
/// infinite authority. A source reporting no uncertainty at all is reporting something it cannot
/// know, and the floor is what stops that claim swamping every other source.
///
/// `width_floor` is `Policy::weight_floor` and is nothing else. It was the allowance for reading the
/// local counter until 2026-09-07, which is a number ten thousand times larger and about something
/// unrelated. Where every survivor sat at or below it, every weight came out the same and this
/// function returned a plain mean of the midpoints without saying so, which is the one combination
/// the averaging rule forbids by name. Keep the two apart.
#[must_use]
pub fn weight_of(interval: &OffsetInterval, width_floor: Nanos) -> f64 {
    let width = interval.width().max(width_floor.max(1)) as f64;
    1.0 / (width * width)
}

/// Combine the surviving intervals into one point inside `region`.
///
/// Returns `None` when nothing survived.
#[must_use]
pub fn combine(
    survivors: &[OffsetInterval],
    region: &OffsetInterval,
    width_floor: Nanos,
) -> Option<Combination> {
    if survivors.is_empty() {
        return None;
    }

    let mut total_weight = 0.0f64;
    let mut weighted_sum = 0.0f64;
    for interval in survivors {
        let w = weight_of(interval, width_floor);
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
    use timewitness_core::time::NANOS_PER_MILLI;

    fn iv(lo: Nanos, hi: Nanos) -> OffsetInterval {
        OffsetInterval::new(lo, hi)
    }

    #[test]
    fn a_tight_source_outweighs_a_loose_one() {
        let tight = iv(-NANOS_PER_MILLI, NANOS_PER_MILLI);
        let loose = iv(30 * NANOS_PER_MILLI, 70 * NANOS_PER_MILLI);
        assert!(weight_of(&tight, 1) > weight_of(&loose, 1) * 100.0);
    }

    #[test]
    fn the_result_is_not_the_plain_mean_of_the_midpoints() {
        // Midpoints are 0 and 40 ms, so a plain mean would be 20 ms. Inverse square weighting on
        // widths of 2 ms and 40 ms puts the answer four hundred times closer to the tight source.
        let tight = iv(-NANOS_PER_MILLI, NANOS_PER_MILLI);
        let loose = iv(20 * NANOS_PER_MILLI, 60 * NANOS_PER_MILLI);
        let region = iv(-NANOS_PER_MILLI, 60 * NANOS_PER_MILLI);
        let combined = combine(&[tight, loose], &region, 1).unwrap();
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
        let combined = combine(&[near, far], &region, 1).unwrap();
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
        let combined = combine(&[exact, normal], &region, 1_000).unwrap();
        assert!(combined.weight.is_finite());
        assert_eq!(combined.offset, 5);
    }

    #[test]
    fn nothing_surviving_gives_nothing_back() {
        assert!(combine(&[], &iv(0, 0), 1).is_none());
    }
}

#[cfg(test)]
mod floor_tests {
    use super::*;
    use crate::policy::Policy;
    use timewitness_core::time::NANOS_PER_MICRO;

    /// Two sources on a local network, both tighter than the allowance for a local counter read.
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

        let combined = combine(&[tight, loose], &region, floor).expect("two survivors combine");
        let mean = (tight.midpoint() + loose.midpoint()) / 2;

        assert!(
            combined.offset < mean / 2,
            "the point is {} and an unweighted mean would be {mean}, so the weighting is not doing              anything",
            combined.offset
        );
        assert!(
            weight_of(&tight, floor) > 10.0 * weight_of(&loose, floor),
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

        let combined = combine(&[tight, loose], &region, shared).expect("two survivors combine");
        let mean = (tight.midpoint() + loose.midpoint()) / 2;

        let a = weight_of(&tight, shared);
        let b = weight_of(&loose, shared);
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
            "the cost of a local read and the width below which a source may not claim authority              are unrelated quantities, and holding them as one value is what produced the mean"
        );
    }
}
