//! The numbers the model runs on, and where each of them came from.
//!
//! Every value here is either a measurement with its conditions, or a choice. The two are labelled,
//! because a choice quoted later as a measurement is how a product ends up defending a number
//! nobody ever took.

use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_MILLI, NANOS_PER_SEC};

/// How wrong a free-running oscillator is assumed to be, in parts per million.
///
/// A laptop oscillator wanders by one to ten parts per million with temperature. NTP has used
/// fifteen for four decades as the figure it will not go below, and the model takes the larger of
/// that and its own measured standard error, so a short regression window cannot talk the bound
/// down to something the hardware does not support. This is an assumption, not a measurement on
/// this machine.
///
/// It covers how wrong the fitted frequency was at the moment it was fitted, and it covers nothing
/// else. NTP's fifteen bounds the total error of an extrapolation that has not been corrected;
/// this model corrects by the fitted frequency first, so the same figure applied afterwards is
/// being applied to a different quantity. How far the rate moves after the fit is
/// `Policy::frequency_slew_ppm_per_second` and `Policy::frequency_span_ppm`, and the two are added
/// rather than maximised.
pub const FREQUENCY_FLOOR_PPM: f64 = 15.0;

/// The widest any one term of a bound is carried as, in nanoseconds: about 292 years.
///
/// A term the arithmetic cannot put a number on, because an input to it was not a number, is carried
/// as this rather than as nought. Nought is the one wrong answer, because it narrows the bound at the
/// moment the input is known to be bad. This is far past every ceiling a policy can set, so a bound
/// holding it is refused as too wide, and it is small enough that the handful of terms a bound is
/// built from add up inside the integer they are carried in rather than overflowing it.
pub const WIDEST: Nanos = i64::MAX as Nanos;

/// The largest rate any field may state, in parts per million: a million, which is the whole clock.
///
/// A rate past this says the oscillator can be more than entirely wrong, which is not a rate. It is
/// held here so that every allowance a legal policy can produce is a finite number well inside
/// [`WIDEST`], and [`WIDEST`] is reached only by an input the validator did not see, which is what
/// makes it the second net rather than a value a policy can ask for.
pub const WIDEST_RATE_PPM: f64 = 1_000_000.0;

/// The slowest an oscillator's rate may be assumed to move, in parts per million per second.
///
/// One, which is the shipped figure and the reasoning is on `Policy::frequency_slew_ppm_per_second`.
/// It is a floor as well as a default from 2026-09-17: a policy may allow for a rate that moves
/// faster than this and never for one that moves slower, because slower is a claim about hardware
/// this code has not measured, and a policy stating nought signed a bound with true UTC outside it
/// fifteen minutes after its second round on a clock drifting at an ordinary twelve parts per
/// million.
pub const SLEW_FLOOR_PPM_PER_SECOND: f64 = 1.0;

/// The narrowest band an oscillator's rate may be assumed to occupy, in parts per million.
///
/// A hundred, which is a consumer part's specified fifty either side across its temperature range;
/// the reasoning is on `Policy::frequency_span_ppm`. A floor for the same reason as the slew: a
/// narrower band is a better crystal than the one this product documents, and nothing here has
/// measured one.
pub const SPAN_FLOOR_PPM: f64 = 100.0;

/// How the model runs.
///
/// Every field is public, so a policy can be built by struct update from the default and nothing that
/// makes one can be relied on to have looked at it. [`Policy::fault`] is what looks at it, and the
/// model asks it before every synchronisation and every read. The rule it applies is one rule said
/// of every field: a value the arithmetic cannot stand behind is refused, and never narrows the bound
/// or overflows the integer it is carried in. The field documentation below says what each field is
/// for; the ranges are stated once, in `fault`, so the two cannot drift apart.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Policy {
    /// How many sources have to answer before a majority means anything.
    ///
    /// Three. With three, a majority beats one bad clock. With four or more it still does after one
    /// drops out, which is why four to six is the design point rather than three.
    ///
    /// **This counts names and `min_operators` counts parties, and the second is the binding one on
    /// the shipped default.** A count of sources was the only floor there was until 2026-09-09,
    /// which meant three addresses at one company cleared it. Both are kept because they refuse
    /// different things: a deployment can be short of servers without being short of operators, and
    /// the arithmetic below still needs enough intervals for a majority to be a majority.
    pub min_sources: usize,

    /// How many distinct operators have to survive the selection before the model will sign.
    ///
    /// **Four**, which is the lower end of what the front page says and the number the shipped
    /// server lists are chosen to clear with two to spare. The three published lists reach nine
    /// servers standing behind six operators, so two operators can go dark and the agent carries on.
    ///
    /// A choice, and here is what it is chosen against. Three would match `min_sources` and buy
    /// nothing that the operator majority test does not already give. Five or six would refuse the
    /// shipped default the moment one operator was unreachable, and an agent that refuses on an
    /// ordinary network fault teaches its operator to lower the floor, which is worse than a floor
    /// one lower. Four leaves the claim on the front page true in code and leaves room for the
    /// network to be the network.
    ///
    /// A round short of this refuses. It does not widen the bound and carry on: widening is what the
    /// model does when it knows how wrong it might be, and not knowing who is behind the answers is
    /// not a quantity that can be added to an interval.
    ///
    /// What it is a floor on is [`timewitness_core::Operator`], which is who runs a server, and that
    /// type is the place that says what independence here can and cannot see.
    pub min_operators: usize,

    /// How many exchanges to keep per source.
    ///
    /// Eight, which is the depth NTP's own filter uses. The model prefers the sample with the
    /// shortest round trip from this window, because the shortest round trip is the one least
    /// likely to have been delayed unevenly.
    pub samples_per_source: usize,

    /// The floor on the assumed frequency error, in parts per million.
    ///
    /// This bounds how wrong the model's own measurement of the rate is, at the moment it was
    /// measured, and nothing else. How far the rate then moves is a separate quantity with two
    /// fields of its own below, and holding the two as one number was an earlier fault.
    pub frequency_floor_ppm: f64,

    /// How fast the oscillator's rate may move, in parts per million per second.
    ///
    /// The model corrects a reading by the frequency it fitted at the last synchronisation, so what
    /// it has to allow for afterwards is not how wrong that fit was, it is how far the rate has
    /// moved since. A crystal's rate moves with temperature and temperature moves in minutes, so
    /// the allowance is small over a poll interval and large over an outage.
    ///
    /// One part per million per second is far above what any thermal ramp can do: a part with a
    /// tempco of a part per million per degree would need the crystal to warm by sixty degrees in a
    /// minute to reach it. It is set that high on purpose, because a rate can also step rather than
    /// ramp, when a hypervisor moves a guest or the machine changes clock source underneath us, and
    /// over a short gap the interval the sources agreed on absorbs a step anyway.
    ///
    /// A choice, not a measurement, and it only ever widens.
    pub frequency_slew_ppm_per_second: f64,

    /// The whole band the oscillator's rate may occupy, in parts per million.
    ///
    /// The rate cannot wander for ever, so the allowance above stops here. A consumer part is
    /// specified at plus or minus fifty parts per million across its temperature range, which is a
    /// hundred parts per million from one end of the band to the other, and the rate cannot move
    /// further than that however long it is given.
    ///
    /// This is what sets the real holdover limit at the default policy. A hundred parts per million
    /// against `max_bound_width` puts the last usable reading at about sixteen minutes after the
    /// last synchronisation, well inside the hour `max_holdover` allows, and the refusal that comes
    /// back past it is `BoundTooWide`. Run on 2026-09-07 against four honest sources in the
    /// simulated harness at `crates/clock/tests/common/mod.rs`, which is a network whose true offset
    /// the test wrote down rather than an internet path: 26.6 ms of width at the moment of
    /// synchronising, 37.7 ms after one poll interval of holdover, 234.6 ms at fifteen minutes, and
    /// a refusal by sixteen and a half. Nothing here has been read off a real source list, because
    /// the one source client that exists states its uncertainty in whole seconds.
    /// That is the honest outcome: an hour of holdover on a machine whose crystal is warming up is
    /// not something to put a number on.
    ///
    /// Half of it is also what the model carries for a rate it is not correcting for, which is
    /// every read before a fit exists and every read after a fit it refused: the largest
    /// magnitude a part inside the band may honestly show, over the elapsed time, on top of the
    /// floor above. Until 2026-09-18 a read before a fit carried the floor alone, and the floor
    /// bounds a measurement rather than a raw counter. `crates/clock/src/model.rs`,
    /// `oscillator_holdover`, states the invariant and the three assumptions it rests on, and
    /// the first of them is that this band is true of the machine.
    ///
    /// A choice about hardware, not a measurement on this machine, and it only ever widens.
    pub frequency_span_ppm: f64,

    /// How many standard errors of the regression to carry into the bound.
    ///
    /// Two. A choice, and a conservative one: it widens the interval rather than narrowing it.
    pub coverage_factor: f64,

    /// A fixed allowance added whenever the model is extrapolating past its last synchronisation.
    ///
    /// A choice. It covers the part of holdover that the frequency estimate does not describe, such
    /// as a temperature step between two polls.
    pub holdover_allowance: Nanos,

    /// A fixed allowance for everything the model does not attempt to describe.
    ///
    /// A choice, applied at all times.
    pub safety_margin: Nanos,

    /// The smallest allowance for the local read itself.
    ///
    /// The model measures the monotonic counter's granularity at startup and uses the larger of the
    /// two. This floor covers the thread being descheduled between the read and its use, which the
    /// granularity measurement does not see.
    pub scheduling_floor: Nanos,

    /// The narrowest interval any single source's answer may support.
    ///
    /// A source hands over two of the four timestamps in an exchange and states its own
    /// uncertainty, and all three are things it chooses. A source willing to claim that it spent
    /// the whole round trip thinking, and that it knows its own time exactly, hands the model a
    /// point rather than an interval. This is the floor that stops it, and it is applied to the
    /// source's own half width before the source is compared with anybody else.
    ///
    /// RFC 5905 does the same thing with `MINDISP`, at five milliseconds, inside the root distance,
    /// so no NTP server can present a zero-width correctness interval either. Ours is smaller,
    /// because five milliseconds is a figure for the public internet and the conditions this
    /// product quotes are tighter than that: about a millisecond on a good local network and about
    /// a hundred microseconds on a cloud instance with a hypervisor clock. Both of those are
    /// quoted from public research and neither has been measured by this code, which reaches
    /// neither today. A floor above either would become the answer rather than a backstop under it.
    /// A hundred microseconds of half width sits below every condition the product quotes and four
    /// orders of magnitude above a point.
    ///
    /// A choice, not a measurement, and it only ever widens.
    pub source_interval_floor: Nanos,

    /// The narrowest interval a source may be weighted as though it had.
    ///
    /// Weights are the inverse square of the interval width, so a source reporting zero uncertainty
    /// would claim infinite authority and swamp every other source. This is the floor that stops it.
    ///
    /// It is a separate number from `scheduling_floor` and that separation is the point of it. The
    /// two were one value until 2026-09-07, which was wrong in a way nothing could see: the cost of
    /// reading a local counter and the width below which a source may not claim authority are
    /// unrelated quantities that happened to be the same size. Where every surviving interval sat
    /// at or below the shared value, every weight came out identical and the combination
    /// degenerated to an unweighted mean of the midpoints, which is the one combination this
    /// product names and forbids: readings averaged into a true time. It could not happen over the
    /// public internet, where the allowance is microseconds and the intervals are milliseconds. It
    /// was one coarse granularity reading away on a local network.
    ///
    /// A nanosecond, because that is the resolution the arithmetic is carried in and no real source
    /// can support an interval narrower than one. A choice, and a floor rather than a measurement.
    pub weight_floor: Nanos,

    /// The longest the model will extrapolate before it refuses instead.
    ///
    /// A choice, and the outer backstop rather than the binding one. At the default policy
    /// `max_bound_width` bites first, somewhere under twenty minutes, because the allowance for the
    /// rate moving reaches its whole band by then. This value is what stops a policy that has
    /// widened its own ceiling from extrapolating for a day.
    pub max_holdover: Nanos,

    /// The widest interval the model is prepared to put its name to.
    ///
    /// A choice. Past this the honest answer is a refusal rather than a very wide number, because a
    /// caller who sees a number will use it and a caller who sees a refusal will not.
    pub max_bound_width: Nanos,

    /// How long a smear window to assume for a source that does not say what it does.
    ///
    /// A leap second is announced hours before it happens and the announcement is cleared the
    /// moment it has happened, which is the moment a smearing source starts diverging from a
    /// stepping one. So the announcement is the wrong signal to arm a guard with, and the model
    /// keeps the guard armed for this long after the last announcement it saw instead. Where the
    /// sources declare their own smear windows the widest of those is used and this value is not
    /// reached for.
    ///
    /// Twenty-four hours, because that is the window the large public smearing services spread a
    /// leap second across, and a guard armed for less than the smear it is guarding against is a
    /// guard that goes quiet part way through the danger.
    ///
    /// A choice, not a measurement, and it only ever refuses.
    pub leap_smear_window: Nanos,

    /// The widest divergence between sources that may still be read as a leap smear.
    ///
    /// One second, because a leap second is one second. Two sources further apart than that are
    /// not disagreeing about how to spread a leap second, they are disagreeing about the time, and
    /// throwing the minority out is the correct answer to that rather than a refusal.
    ///
    /// Arithmetic rather than a choice: it follows from what a leap second is.
    pub leap_divergence_ceiling: Nanos,

    /// How far back the regression looks.
    ///
    /// A window shorter than a few polls does not empty the fit. The model keeps
    /// `regression_min_points` points whatever the window says, because a fit that has been starved
    /// below what it needs has no residual, and no residual is a narrower bound rather than a more
    /// honest one. Until 2026-09-17 it kept two, which is one short of a fit, so a window of thirty-one
    /// seconds at a thirty-two second cadence halved the width in silence.
    pub regression_window: Nanos,

    /// How many points the regression needs before it will estimate a frequency at all.
    ///
    /// Three, because two points fit a line exactly and leave no residual to measure the fit by.
    pub regression_min_points: usize,

    /// How many synchronisation results to keep for the regression.
    pub history_capacity: usize,
}

impl Policy {
    /// What makes this policy one the bound arithmetic cannot stand behind, if anything does.
    ///
    /// Every field is public, so a policy can be built by struct update from the default and nothing
    /// that makes one can be relied on to have looked at it. The model asks this itself, before it
    /// synchronises and before it reads, and refuses with the answer. The model holds its own copy of
    /// the policy, so nothing a caller does to its copy afterwards reaches the arithmetic.
    ///
    /// Until the morning of 2026-09-17 this looked at the coverage factor and the three rates and at
    /// nothing else, and the same afternoon a cold set found that a negative safety margin narrowed
    /// the bound, a safety margin at the integer's floor inverted the interval and panicked, and a
    /// history capacity of nought took the residual out of the width. Each of those is one field of
    /// the same class, so this now says one thing of every field rather than three things of four.
    ///
    /// The coverage factor has to be a number no smaller than one. Below one it carries less than a
    /// single standard error into the bound, and at nought or below, or not a number, it used to take
    /// the model's own residual out of the width altogether. Each rate in parts per million has to be
    /// a number and must not be more than [`WIDEST_RATE_PPM`], because a rate past the whole clock is
    /// not a rate.
    ///
    /// **Each rate also has a floor, and the floor is the shipped figure**: [`FREQUENCY_FLOOR_PPM`],
    /// [`SLEW_FLOOR_PPM_PER_SECOND`] and [`SPAN_FLOOR_PPM`]. Until the evening of 2026-09-17 nought
    /// was allowed, on the reasoning that the tests switch a term off with it to see the others,
    /// and a cold set found what that reasoning missed: the three rates are the model's whole
    /// knowledge of the oscillator before it has fitted one, and a policy stating that the crystal
    /// cannot drift signed a bound with true UTC outside it fifteen minutes after its second round.
    /// A rate below the shipped figure is a claim that this machine's hardware is better than the
    /// hardware this product documents, and no measurement here supports that claim; a rate above
    /// it is a caller allowing for worse hardware, which only ever widens. So a policy may raise any
    /// of the three and may lower none, and a test that wants to see one term without the others
    /// compares two policies that differ in that term alone.
    ///
    /// Each allowance in nanoseconds, the holdover allowance, the safety margin and the scheduling
    /// floor, is a term added to the width, so it must not be negative and must not be more than
    /// [`WIDEST`], which is what keeps a handful of terms inside the integer they are summed in. Each
    /// floor on what a source may claim, the source interval floor and the weight floor, is at least
    /// a nanosecond, which is the resolution the arithmetic is carried in and narrower than any
    /// interval a real source can support; a floor of nought lets a source hand the model a point.
    /// Each ceiling and each window, the bound ceiling, the holdover ceiling, the regression window
    /// and the leap divergence ceiling, is at least a nanosecond and at most [`WIDEST`]: a ceiling of
    /// nought refuses everything and says nothing, and a ceiling past the widest term lets a term the
    /// arithmetic could not compute through. The leap smear window may be nought, because nought is
    /// the honest window where every source steps, and it must not be negative, because a negative
    /// window never arms the guard. The regression needs at least three points, because two fit a
    /// line exactly and leave no residual, and the history has to be able to hold that many. A source
    /// window holds at least one sample, and at least one source and one operator have to answer,
    /// because a floor of nought is not a floor.
    #[must_use]
    pub fn fault(&self) -> Option<String> {
        if !self.coverage_factor.is_finite() || self.coverage_factor < 1.0 {
            return Some(format!(
                "coverage_factor is {} and has to be a number no smaller than one",
                self.coverage_factor
            ));
        }
        let rates = [
            (
                "frequency_floor_ppm",
                self.frequency_floor_ppm,
                FREQUENCY_FLOOR_PPM,
            ),
            (
                "frequency_slew_ppm_per_second",
                self.frequency_slew_ppm_per_second,
                SLEW_FLOOR_PPM_PER_SECOND,
            ),
            (
                "frequency_span_ppm",
                self.frequency_span_ppm,
                SPAN_FLOOR_PPM,
            ),
        ];
        for (name, value, floor) in rates {
            // Not a number fails both halves, so it is refused here without a test of its own.
            if value.is_nan() || value < floor {
                return Some(format!(
                    "{name} is {value} and has to be a number no smaller than {floor}, which is \
                     the hardware this product documents; a policy may allow for worse and never \
                     for better"
                ));
            }
            if value > WIDEST_RATE_PPM {
                return Some(format!(
                    "{name} is {value} parts per million and a rate past a million is more than the \
                     whole clock"
                ));
            }
        }
        let allowances = [
            ("holdover_allowance", self.holdover_allowance),
            ("safety_margin", self.safety_margin),
            ("scheduling_floor", self.scheduling_floor),
            ("leap_smear_window", self.leap_smear_window),
        ];
        for (name, value) in allowances {
            if !(0..=WIDEST).contains(&value) {
                return Some(format!(
                    "{name} is {value} ns and has to be between nought and {WIDEST} ns, because it is \
                     added to the width"
                ));
            }
        }
        let at_least_a_nanosecond = [
            ("source_interval_floor", self.source_interval_floor),
            ("weight_floor", self.weight_floor),
            ("max_bound_width", self.max_bound_width),
            ("max_holdover", self.max_holdover),
            ("regression_window", self.regression_window),
            ("leap_divergence_ceiling", self.leap_divergence_ceiling),
        ];
        for (name, value) in at_least_a_nanosecond {
            if !(1..=WIDEST).contains(&value) {
                return Some(format!(
                    "{name} is {value} ns and has to be between one and {WIDEST} ns"
                ));
            }
        }
        if self.regression_min_points < 3 {
            return Some(format!(
                "regression_min_points is {} and a residual needs at least three points",
                self.regression_min_points
            ));
        }
        if self.history_capacity < self.regression_min_points {
            return Some(format!(
                "history_capacity is {} and cannot hold the {} points the regression needs",
                self.history_capacity, self.regression_min_points
            ));
        }
        let at_least_one = [
            ("samples_per_source", self.samples_per_source),
            ("min_sources", self.min_sources),
            ("min_operators", self.min_operators),
        ];
        for (name, value) in at_least_one {
            if value < 1 {
                return Some(format!("{name} is {value} and has to be at least one"));
            }
        }
        None
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_sources: 3,
            min_operators: 4,
            samples_per_source: 8,
            frequency_floor_ppm: FREQUENCY_FLOOR_PPM,
            frequency_slew_ppm_per_second: 1.0,
            frequency_span_ppm: 100.0,
            coverage_factor: 2.0,
            holdover_allowance: 500 * NANOS_PER_MICRO,
            safety_margin: 250 * NANOS_PER_MICRO,
            scheduling_floor: 10 * NANOS_PER_MICRO,
            source_interval_floor: 100 * NANOS_PER_MICRO,
            weight_floor: 1,
            max_holdover: 3_600 * NANOS_PER_SEC,
            max_bound_width: 250 * NANOS_PER_MILLI,
            leap_smear_window: 86_400 * NANOS_PER_SEC,
            leap_divergence_ceiling: NANOS_PER_SEC,
            regression_window: 1_800 * NANOS_PER_SEC,
            regression_min_points: 3,
            history_capacity: 256,
        }
    }
}

/// Nanoseconds of error accumulated by a frequency error of `ppm` over `elapsed` nanoseconds.
///
/// One part per million is one millisecond per thousand seconds. The arithmetic is done in floating
/// point and rounded up, so the answer is never smaller than the true product.
///
/// This is an allowance, so it is never less than nought and never less than it stands for. A rate
/// that is not a number, or is negative, has no allowance anybody could compute, and the answer is
/// [`WIDEST`] rather than nought: nought would narrow the bound on exactly the input that says the
/// bound cannot be known. The same ceiling holds a finite rate too large to mean anything.
#[must_use]
pub fn ppm_over(ppm: f64, elapsed: Nanos) -> Nanos {
    if elapsed <= 0 {
        return 0;
    }
    if !ppm.is_finite() || ppm < 0.0 {
        return WIDEST;
    }
    let product = (ppm * (elapsed as f64) / 1_000_000.0).ceil();
    if !product.is_finite() || product >= WIDEST as f64 {
        return WIDEST;
    }
    product as Nanos
}

/// The same, keeping the sign, for propagating an estimated drift rather than an uncertainty.
///
/// `elapsed` may be negative here and nowhere else: a reading taken before the fit it is corrected
/// by is corrected backwards, by the same rate over the same distance.
#[must_use]
pub fn signed_ppm_over(ppm: f64, elapsed: Nanos) -> Nanos {
    if elapsed == 0 || !ppm.is_finite() {
        return 0;
    }
    // Held inside the same ceiling as an allowance, so a correction cannot carry an interval past
    // what the integer holds. The cast saturates, and the clamp is applied to the integer rather than
    // the float because the ceiling has no exact float: as a float it rounds up to one past itself.
    let product = ppm * (elapsed as f64) / 1_000_000.0;
    (product as Nanos).clamp(-WIDEST, WIDEST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_ppm_is_one_millisecond_per_thousand_seconds() {
        let thousand_seconds = 1_000 * NANOS_PER_SEC;
        assert_eq!(ppm_over(1.0, thousand_seconds), NANOS_PER_MILLI);
    }

    #[test]
    fn uncertainty_growth_never_rounds_down() {
        // A third of a nanosecond of growth still counts as growth.
        assert_eq!(ppm_over(1.0, 333), 1);
        assert_eq!(ppm_over(0.0, NANOS_PER_SEC), 0);
    }

    #[test]
    fn an_allowance_nobody_can_compute_is_the_widest_and_never_nought() {
        // Each of these but the last returned nought or a negative number until
        // 2026-09-17, which took the oscillator out of the width.
        let second = NANOS_PER_SEC;
        assert_eq!(ppm_over(f64::NAN, second), WIDEST);
        assert_eq!(ppm_over(f64::INFINITY, second), WIDEST);
        assert_eq!(ppm_over(f64::NEG_INFINITY, second), WIDEST);
        assert_eq!(ppm_over(-5.0, second), WIDEST);
        assert_eq!(ppm_over(1e300, second), WIDEST);
        assert_eq!(ppm_over(-0.0, second), 0);
    }

    #[test]
    fn a_signed_correction_is_held_inside_the_same_ceiling_as_an_allowance() {
        // Past the ceiling the float would saturate to the integer's own ceiling on the cast, which
        // is far wider than any allowance and overflows the moment it is added to an end.
        let second = NANOS_PER_SEC;
        assert_eq!(signed_ppm_over(1e300, second), WIDEST);
        assert_eq!(signed_ppm_over(-1e300, second), -WIDEST);
        assert_eq!(signed_ppm_over(f64::NAN, second), 0);
        assert_eq!(signed_ppm_over(-2.0, 1_000 * second), -2 * NANOS_PER_MILLI);
    }

    #[test]
    fn a_signed_correction_runs_backwards_over_a_negative_distance() {
        // A reading taken before the fit is corrected by the same rate the other way. This returned
        // nought until 2026-09-17, so a counter stepped back got the fitted offset uncorrected.
        let second = NANOS_PER_SEC;
        assert_eq!(signed_ppm_over(2.0, -1_000 * second), -2 * NANOS_PER_MILLI);
        assert_eq!(signed_ppm_over(-2.0, -1_000 * second), 2 * NANOS_PER_MILLI);
        assert_eq!(signed_ppm_over(2.0, 0), 0);
    }

    #[test]
    fn a_rate_below_the_shipped_figure_is_refused_by_name() {
        // Each rate at its floor is legal; the next float down, nought, a subnormal and negative
        // nought are refused naming the field. Nought was legal until 2026-09-17 and a policy of
        // three noughts signed a bound with the truth outside it.
        type Set = fn(f64) -> Policy;
        let d = Policy::default();
        let cases: [(&str, f64, Set); 3] = [
            ("frequency_floor_ppm", FREQUENCY_FLOOR_PPM, |v| Policy {
                frequency_floor_ppm: v,
                ..Policy::default()
            }),
            (
                "frequency_slew_ppm_per_second",
                SLEW_FLOOR_PPM_PER_SECOND,
                |v| Policy {
                    frequency_slew_ppm_per_second: v,
                    ..Policy::default()
                },
            ),
            ("frequency_span_ppm", SPAN_FLOOR_PPM, |v| Policy {
                frequency_span_ppm: v,
                ..Policy::default()
            }),
        ];
        for (field, floor, set) in cases {
            assert_eq!(set(floor).fault(), None, "{field} at its floor is legal");
            assert_eq!(
                set(floor * 2.0).fault(),
                None,
                "{field} above its floor is legal"
            );
            let below = f64::from_bits(floor.to_bits() - 1);
            for value in [below, 0.0, 5e-324, -0.0, f64::MIN_POSITIVE, -5.0] {
                let fault = set(value)
                    .fault()
                    .unwrap_or_else(|| panic!("{field} at {value} was not refused"));
                assert!(fault.contains(field), "{field} at {value}: {fault}");
            }
        }
        assert_eq!(d.fault(), None);
    }

    #[test]
    fn every_field_outside_its_range_is_named_by_the_fault() {
        // One value per field on the wrong side of its own range, and the fault has to name the
        // field. The full set, at every edge and in combination, is `tests/a_bad_policy.rs`.
        let d = Policy::default();
        let bad: Vec<(&str, Policy)> = vec![
            (
                "frequency_floor_ppm",
                Policy {
                    frequency_floor_ppm: WIDEST_RATE_PPM + 1.0,
                    ..d
                },
            ),
            (
                "holdover_allowance",
                Policy {
                    holdover_allowance: -1,
                    ..d
                },
            ),
            (
                "safety_margin",
                Policy {
                    safety_margin: WIDEST + 1,
                    ..d
                },
            ),
            (
                "scheduling_floor",
                Policy {
                    scheduling_floor: i128::MIN,
                    ..d
                },
            ),
            (
                "leap_smear_window",
                Policy {
                    leap_smear_window: -1,
                    ..d
                },
            ),
            (
                "source_interval_floor",
                Policy {
                    source_interval_floor: 0,
                    ..d
                },
            ),
            (
                "weight_floor",
                Policy {
                    weight_floor: 0,
                    ..d
                },
            ),
            (
                "max_bound_width",
                Policy {
                    max_bound_width: 0,
                    ..d
                },
            ),
            (
                "max_holdover",
                Policy {
                    max_holdover: -1,
                    ..d
                },
            ),
            (
                "regression_window",
                Policy {
                    regression_window: 0,
                    ..d
                },
            ),
            (
                "leap_divergence_ceiling",
                Policy {
                    leap_divergence_ceiling: 0,
                    ..d
                },
            ),
            (
                "regression_min_points",
                Policy {
                    regression_min_points: 2,
                    ..d
                },
            ),
            (
                "history_capacity",
                Policy {
                    history_capacity: 2,
                    ..d
                },
            ),
            (
                "samples_per_source",
                Policy {
                    samples_per_source: 0,
                    ..d
                },
            ),
            (
                "min_sources",
                Policy {
                    min_sources: 0,
                    ..d
                },
            ),
            (
                "min_operators",
                Policy {
                    min_operators: 0,
                    ..d
                },
            ),
        ];
        for (field, policy) in bad {
            let fault = policy
                .fault()
                .unwrap_or_else(|| panic!("{field} out of range was not refused"));
            assert!(fault.contains(field), "{field}: {fault}");
        }
        // The edges themselves are legal.
        let edges = Policy {
            holdover_allowance: WIDEST,
            safety_margin: 0,
            source_interval_floor: 1,
            weight_floor: 1,
            max_bound_width: WIDEST,
            max_holdover: 1,
            regression_window: 1,
            leap_smear_window: 0,
            leap_divergence_ceiling: 1,
            regression_min_points: 3,
            history_capacity: 3,
            samples_per_source: 1,
            min_sources: 1,
            min_operators: 1,
            frequency_span_ppm: WIDEST_RATE_PPM,
            ..d
        };
        assert_eq!(edges.fault(), None);
    }

    #[test]
    fn the_shipped_policy_has_no_fault_and_a_bad_field_is_named() {
        assert_eq!(Policy::default().fault(), None);
        for factor in [0.0, -0.0, -1.0, 0.5, 0.999_999_999, f64::NAN, f64::INFINITY] {
            let policy = Policy {
                coverage_factor: factor,
                ..Policy::default()
            };
            let fault = policy
                .fault()
                .expect("a coverage factor under one is refused");
            assert!(fault.contains("coverage_factor"), "{fault}");
        }
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -5.0, -0.0] {
            let policy = Policy {
                frequency_span_ppm: value,
                ..Policy::default()
            };
            let fault = policy.fault().expect("a bad rate is refused");
            assert!(fault.contains("frequency_span_ppm"), "{fault}");
        }
    }

    #[test]
    fn growth_over_no_elapsed_time_is_nothing() {
        assert_eq!(ppm_over(15.0, 0), 0);
        assert_eq!(ppm_over(15.0, -5), 0);
    }

    #[test]
    fn the_default_policy_needs_three_sources() {
        assert_eq!(Policy::default().min_sources, 3);
    }
}
