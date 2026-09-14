//! Weighted linear regression for offset and frequency.
//!
//! Over a window of minutes the model has a series of combined offsets. A straight line through
//! them gives two things: where the clock is now, and how fast it is running away. The second is
//! the frequency error in parts per million, and it is what lets the bound grow at the right rate
//! when the sources go quiet.
//!
//! Two decisions in here are worth stating rather than leaving in the arithmetic.
//!
//! The x axis is centred on the most recent point. That makes the intercept the fitted offset at
//! that moment and its standard error the standard error of that same value, so nothing has to be
//! propagated forward by hand.
//!
//! When the points scatter more than their own weights say they should, the standard errors are
//! scaled up by the square root of the reduced chi-square. That is the conservative direction and
//! the only one available: a model that fits badly is a model whose numbers deserve less
//! confidence, not more.

use timewitness_core::time::{MonotonicNanos, Nanos, NANOS_PER_SEC};

/// One completed synchronisation, as the regression sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    /// When the synchronisation happened, on the monotonic counter.
    pub at: MonotonicNanos,
    /// The combined offset at that moment, in nanoseconds.
    pub offset: Nanos,
    /// Half the width of the intersection at that moment, in nanoseconds.
    pub half_width: Nanos,
}

/// What the fit says.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fit {
    /// The fitted offset at the most recent point, in nanoseconds.
    pub offset: Nanos,
    /// The standard error of that offset, in nanoseconds, never negative.
    pub offset_stderr: Nanos,
    /// The frequency error, in parts per million. Positive means the local clock runs slow.
    pub frequency_ppm: f64,
    /// The standard error of the frequency, in parts per million.
    pub frequency_stderr_ppm: f64,
    /// How many points went into the fit.
    pub points: usize,
}

/// Fit a line through the points, using the last one as the origin of the x axis.
///
/// Returns `None` when there are too few points, or when they all sit at the same instant so no
/// slope can be separated from the intercept. The caller then falls back to the frequency floor,
/// which is the honest answer when nothing has been measured.
#[must_use]
pub fn fit(points: &[Point], min_points: usize) -> Option<Fit> {
    if points.len() < min_points.max(3) {
        return None;
    }

    let last = points.last()?.at;

    // Raw weights are one over the square of a nanosecond width, so they come out around ten to the
    // minus thirteen and their products underflow towards the point where a degeneracy test cannot
    // tell a flat series from a fine one. So the sums are formed with the weights divided by their
    // own mean, which leaves the fitted line untouched and puts the arithmetic back near one. The
    // mean is carried separately and put back into the variances, which do depend on the absolute
    // scale of the weights.
    let mut prepared: Vec<(f64, f64, f64)> = Vec::with_capacity(points.len());
    for p in points {
        // Seconds before the most recent point, so x is zero or negative and the intercept is the
        // fitted value at the moment the model last synchronised.
        let x = -(last.since(p.at) as f64) / NANOS_PER_SEC as f64;
        let y = p.offset as f64;
        let half = p.half_width.max(1) as f64;
        let w = 1.0 / (half * half);
        if !w.is_finite() || w <= 0.0 {
            continue;
        }
        prepared.push((x, y, w));
    }

    if prepared.len() < min_points.max(3) {
        return None;
    }

    let mean_weight = prepared.iter().map(|(_, _, w)| *w).sum::<f64>() / prepared.len() as f64;
    if !mean_weight.is_finite() || mean_weight <= 0.0 {
        return None;
    }

    let mut s = 0.0f64;
    let mut sx = 0.0f64;
    let mut sy = 0.0f64;
    let mut sxx = 0.0f64;
    let mut sxy = 0.0f64;
    for (x, y, w) in &prepared {
        let w = w / mean_weight;
        s += w;
        sx += w * x;
        sy += w * y;
        sxx += w * x * x;
        sxy += w * x * y;
    }

    let delta = s * sxx - sx * sx;
    // Cauchy's inequality makes this quantity non-negative, and it reaches zero exactly when every
    // point sits at the same instant. The test is relative rather than absolute, because an
    // absolute floor would reject a perfectly good fit whose sums happen to be small.
    if !delta.is_finite() || delta <= (s * sxx).abs() * 1e-12 {
        return None;
    }

    let intercept = (sxx * sy - sx * sxy) / delta;
    let slope_ns_per_s = (s * sxy - sx * sy) / delta;

    let mut chi2 = 0.0f64;
    for (x, y, w) in &prepared {
        let residual = y - intercept - slope_ns_per_s * x;
        chi2 += (w / mean_weight) * residual * residual;
    }
    let dof = (prepared.len() - 2) as f64;
    // The true reduced chi-square, with the weight scale put back.
    let reduced = if dof > 0.0 {
        mean_weight * chi2 / dof
    } else {
        1.0
    };
    // Scaling up for a poor fit and never down for a flattering one.
    let scale = reduced.max(1.0).sqrt();

    let offset_stderr = ((sxx / (mean_weight * delta)).max(0.0)).sqrt() * scale;
    let frequency_stderr_ns_per_s = ((s / (mean_weight * delta)).max(0.0)).sqrt() * scale;

    // A nanosecond per second is a part per billion, so a thousandth of it is a part per million.
    let frequency_ppm = slope_ns_per_s / 1_000.0;
    let frequency_stderr_ppm = frequency_stderr_ns_per_s / 1_000.0;

    Some(Fit {
        offset: intercept as Nanos,
        offset_stderr: offset_stderr.ceil().max(0.0) as Nanos,
        frequency_ppm,
        frequency_stderr_ppm,
        points: prepared.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_core::time::NANOS_PER_MILLI;

    fn series(count: usize, spacing_s: u64, start_offset: Nanos, ppm: f64) -> Vec<Point> {
        (0..count)
            .map(|i| {
                let elapsed_ns = (i as u64) * spacing_s * NANOS_PER_SEC as u64;
                let drift = (ppm * elapsed_ns as f64 / 1_000_000.0) as Nanos;
                Point {
                    at: MonotonicNanos(elapsed_ns),
                    offset: start_offset + drift,
                    half_width: 2 * NANOS_PER_MILLI,
                }
            })
            .collect()
    }

    #[test]
    fn too_few_points_produce_no_fit() {
        assert!(fit(&series(2, 60, 0, 0.0), 3).is_none());
    }

    #[test]
    fn a_clean_series_recovers_the_frequency_it_was_built_with() {
        let points = series(12, 64, 3 * NANOS_PER_MILLI, 4.0);
        let f = fit(&points, 3).unwrap();
        assert!(
            (f.frequency_ppm - 4.0).abs() < 0.01,
            "got {}",
            f.frequency_ppm
        );
    }

    #[test]
    fn the_intercept_is_the_offset_at_the_most_recent_point() {
        let points = series(12, 64, 3 * NANOS_PER_MILLI, 4.0);
        let expected = points.last().unwrap().offset;
        let f = fit(&points, 3).unwrap();
        assert!((f.offset - expected).abs() < NANOS_PER_MILLI / 100);
    }

    #[test]
    fn a_scattered_series_reports_a_larger_standard_error() {
        let clean = fit(&series(12, 64, 0, 4.0), 3).unwrap();

        let mut noisy = series(12, 64, 0, 4.0);
        for (i, p) in noisy.iter_mut().enumerate() {
            let kick = if i % 2 == 0 {
                3 * NANOS_PER_MILLI
            } else {
                -3 * NANOS_PER_MILLI
            };
            p.offset += kick;
        }
        let noisy = fit(&noisy, 3).unwrap();

        assert!(
            noisy.offset_stderr > clean.offset_stderr,
            "clean {} noisy {}",
            clean.offset_stderr,
            noisy.offset_stderr
        );
        assert!(noisy.frequency_stderr_ppm > clean.frequency_stderr_ppm);
    }

    #[test]
    fn points_all_at_one_instant_give_no_slope() {
        let points = vec![
            Point {
                at: MonotonicNanos(0),
                offset: 0,
                half_width: NANOS_PER_MILLI,
            },
            Point {
                at: MonotonicNanos(0),
                offset: 1,
                half_width: NANOS_PER_MILLI,
            },
            Point {
                at: MonotonicNanos(0),
                offset: 2,
                half_width: NANOS_PER_MILLI,
            },
        ];
        assert!(fit(&points, 3).is_none());
    }

    #[test]
    fn standard_errors_are_never_negative() {
        let f = fit(&series(8, 64, 0, -7.5), 3).unwrap();
        assert!(f.offset_stderr >= 0);
        assert!(f.frequency_stderr_ppm >= 0.0);
    }
}
