//! The third branch of the ageing invariant, which was stated for the whole type and asserted on
//! the other two.
//!
//! `CounterAgeing` says that on a machine whose true rate magnitude never passes half the band, a
//! sample that held the truth when it was taken still holds it after ageing. `the_band_before_a_fit.rs`
//! asserts that where nothing has been fitted and where the model has refused the fit it has, and
//! both of those carry at least half the band, so the sentence holds unconditionally on them. The
//! third branch is a fit the model stands behind, and there the widening is the sum of what the fit
//! measured rather than half the band, and the sum can be smaller.
//!
//! It is smaller often enough to matter. A fit claiming 12.0 ppm at a standard error of 1.0 widens
//! at 37 ppm over ten seconds, and a machine at -50.0 ppm, which is legally inside the band, has
//! moved 50 ppm in the same ten seconds. The sample is 130 us short of holding the truth it held
//! when it was taken. That is the sentence being false on the branch, not the arithmetic being
//! wrong: the ageing widens and never corrects, by the decision written on `CounterAgeing`, and the
//! rate is corrected for once in `read` from a reference instant this term does not share.
//!
//! What makes the branch sound is an assumption the sentence did not state until 2026-09-20: the
//! machine's true rate lies inside the coverage interval of the fit the model is standing behind.
//! That is what a regression through real data is measuring, so it is the ordinary case rather than
//! a get-out, and it is now written on the type beside the first assumption.
//!
//! No reachable path produces a wrong bound from this. A fit is made by regression through the
//! sources' own answers, so it measures the rate it is fitting, and the shortfall where the
//! assumption fails is bounded at 306 us on `Policy::default` against a bound of about 154 ms. What
//! this file protects is the sentence, because the sentence is what a later run reads when it is
//! deciding whether the floor can come out.

use timewitness_clock::policy::ppm_over;
use timewitness_clock::{BandReading, CounterAgeing, Policy, RateKnowledge};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};

fn d() -> Policy {
    Policy::default()
}

/// A fit the model will stand behind: inside the band, and sharp enough to separate one rate in the
/// band from another.
fn claimed(ppm: f64, stderr_ppm: f64) -> RateKnowledge {
    RateKnowledge {
        frequency_ppm: Some(ppm),
        frequency_stderr_ppm: stderr_ppm,
        unclaimed_frequency_ppm: 0.0,
        band: BandReading::Inside {
            magnitude_ppm: ppm.abs(),
        },
    }
}

/// How far a machine running at `true_ppm` has carried the truth away from a sample over `age`.
fn displacement(true_ppm: f64, age: Nanos) -> Nanos {
    ppm_over(true_ppm.abs(), age)
}

/// The claimed rates a fit inside the band can hand back, at the edges the model decides on.
fn claimed_rates() -> Vec<f64> {
    vec![
        0.0, 0.5, -0.5, 3.0, -3.0, 12.0, -12.0, 30.0, -30.0, 49.9, -49.9,
    ]
}

/// Standard errors sharp enough that `separates_the_band` accepts the fit at the default policy,
/// where the coverage factor is two and the band is a hundred.
fn standard_errors() -> Vec<f64> {
    vec![0.0, 0.1, 1.0, 5.0, 20.0, 49.0]
}

/// True rates inside the band, including both edges.
fn true_rates() -> Vec<f64> {
    vec![
        0.0, 1.0, -1.0, 7.5, -7.5, 25.0, -25.0, 49.9, -49.9, 50.0, -50.0,
    ]
}

/// One nanosecond doubling to the default holdover ceiling, plus the three reads the agent
/// actually takes at.
fn ages() -> Vec<Nanos> {
    let mut out = Vec::new();
    let mut age: Nanos = 1;
    while age < d().max_holdover {
        out.push(age);
        age = age.saturating_mul(2);
    }
    out.push(d().max_holdover);
    for seconds in [10, 32, 900] {
        out.push(seconds * NANOS_PER_SEC);
    }
    out
}

/// Whether a true rate lies inside the coverage interval of the fit the model is standing behind.
///
/// This is the assumption the claimed branch rests on. A fit of `f` with a standard error of `s`
/// says the rate is `f` give or take `s` times the coverage factor, and a regression through real
/// data measures the rate it is fitting, so this is what the ordinary case looks like.
fn inside_the_fits_own_interval(
    policy: &Policy,
    fit_ppm: f64,
    stderr_ppm: f64,
    true_ppm: f64,
) -> bool {
    (true_ppm - fit_ppm).abs() <= stderr_ppm * policy.coverage_factor
}

#[test]
fn a_claimed_fit_ages_a_sample_without_losing_the_truth_inside_the_fits_own_interval() {
    let policy = d();
    let mut cells = 0usize;
    let mut skipped = 0usize;

    for fit_ppm in claimed_rates() {
        for stderr_ppm in standard_errors() {
            let rate = claimed(fit_ppm, stderr_ppm);
            let ageing = CounterAgeing::new(&policy, &rate);
            for true_ppm in true_rates() {
                if !inside_the_fits_own_interval(&policy, fit_ppm, stderr_ppm, true_ppm) {
                    skipped += 1;
                    continue;
                }
                for age in ages() {
                    let widening = ageing.dispersion(age);
                    let moved = displacement(true_ppm, age);
                    assert!(
                        widening >= moved,
                        "a fit claiming {fit_ppm} ppm at a standard error of {stderr_ppm} ppm \
                         widened a sample by {widening} ns over {age} ns, and a machine at \
                         {true_ppm} ppm carried the truth {moved} ns in the same time, so a sample \
                         that held it no longer does"
                    );
                    cells += 1;
                }
            }
        }
    }

    // The sweep is worth nothing if the condition has swallowed it, and a grid that only ever
    // shrinks is how that happens with nobody noticing. Written out rather than computed, because a
    // count computed from the lists that built it agrees with anything.
    assert!(
        cells >= 11_316,
        "{cells} cells is not the grid this file describes, with {skipped} pairs outside the fit's \
         own interval"
    );
}

#[test]
fn the_same_sweep_outside_the_fits_own_interval_is_where_the_sentence_was_false() {
    // The other half, and the reason the assumption is written on the type rather than assumed. The
    // cells the test above steps over are not all sound: some of them lose the truth, and the
    // sentence as it stood said they could not. This asserts that at least one does, so an attempt
    // to drop the condition from the invariant has to argue with a number.
    let policy = d();
    let mut worst: Option<(f64, f64, f64, Nanos, Nanos)> = None;

    for fit_ppm in claimed_rates() {
        for stderr_ppm in standard_errors() {
            let ageing = CounterAgeing::new(&policy, &claimed(fit_ppm, stderr_ppm));
            for true_ppm in true_rates() {
                if inside_the_fits_own_interval(&policy, fit_ppm, stderr_ppm, true_ppm) {
                    continue;
                }
                for age in ages() {
                    let short = displacement(true_ppm, age) - ageing.dispersion(age);
                    if short > 0 && worst.is_none_or(|(_, _, _, _, w)| short > w) {
                        worst = Some((fit_ppm, stderr_ppm, true_ppm, age, short));
                    }
                }
            }
        }
    }

    let (fit_ppm, stderr_ppm, true_ppm, age, short) = worst.expect(
        "the claimed branch is short of the truth somewhere outside the fit's own \
                      interval, and finding nowhere means the arithmetic now covers the branch \
                      unconditionally and the invariant can say so",
    );
    assert!(
        short < NANOS_PER_MILLI,
        "a fit claiming {fit_ppm} ppm at a standard error of {stderr_ppm} ppm left a sample \
         {short} ns short of a machine at {true_ppm} ppm over {age} ns, which is past the \
         millisecond this shortfall has been bounded at"
    );
}

/// The worst cell of the three, worked by hand rather than found by a sweep.
///
/// A fit claiming nought at a standard error of nought is the sharpest fit there is, and it widens
/// by the policy's own floor plus the slew over the age. A machine at the band edge is legal under
/// the first assumption and is carried away from the sample at fifty parts per million. Ten seconds
/// in, the widening is 250 us and the truth has moved 500 us.
#[test]
fn a_perfect_fit_of_nought_does_not_cover_a_machine_at_the_band_edge() {
    let policy = d();
    let ageing = CounterAgeing::new(&policy, &claimed(0.0, 0.0));
    let age = 10 * NANOS_PER_SEC;

    assert_eq!(ageing.dispersion(age), 250 * 1_000);
    assert_eq!(
        displacement(policy.frequency_span_ppm / 2.0, age),
        500 * 1_000
    );
    assert!(
        ageing.dispersion(age) < displacement(policy.frequency_span_ppm / 2.0, age),
        "the invariant's first assumption alone covers the claimed branch, which it did not on \
         2026-09-18 and which the second assumption on `CounterAgeing` exists for"
    );

    // And the same fit does hold the truth for every machine its own interval allows, which is one
    // machine, since an error bar of nought allows no other.
    assert!(ageing.dispersion(age) >= displacement(0.0, age));
}
