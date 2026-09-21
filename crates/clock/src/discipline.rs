//! How the measured frequency error is acted on.
//!
//! There is no step anywhere in this file, and there is no method by which a caller could ask for
//! one. That is the point. Stepping a clock makes time jump backwards or repeat a value, and a
//! stamp taken either side of a step is a stamp nobody can order. So the only correction available
//! is a rate: if the oscillator runs four parts per million fast, slow it by four parts per
//! million, and let the error come out over the following minutes.
//!
//! Two modes, and the default is the quiet one. In shadow mode the agent never touches the system
//! clock at all and keeps its own model over the monotonic counter instead. That is what runs on
//! Windows, where the operating system's own time service fights any second discipliner, and on any
//! machine where the agent is not entitled to the clock. In rate mode the agent owns the clock and
//! slews it, through whatever the platform offers.

use timewitness_core::Nanos;

/// Something that can slow or speed the machine's clock.
///
/// Deliberately narrow. There is no `step`, no `set_time` and no way to add one without changing
/// this trait, which is the structural version of the rule rather than a comment asking people to
/// behave.
pub trait RateAdjuster {
    /// Ask for the clock to run `ppm` parts per million faster than it otherwise would.
    ///
    /// A negative value slows it. The implementation clamps to whatever the platform allows and
    /// reports what it actually applied.
    fn set_rate_ppm(&mut self, ppm: f64) -> Result<f64, DisciplineError>;

    /// The largest rate change the platform will accept, in parts per million.
    fn max_rate_ppm(&self) -> f64;
}

/// Why a rate could not be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisciplineError {
    /// The agent is not entitled to change this machine's clock.
    NotPermitted,
    /// The platform has no rate adjustment interface the agent can reach.
    Unsupported,
    /// The platform refused for its own reason.
    Platform(String),
}

impl core::fmt::Display for DisciplineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DisciplineError::NotPermitted => {
                write!(f, "this agent is not entitled to change the system clock")
            }
            DisciplineError::Unsupported => {
                write!(
                    f,
                    "this platform offers no rate adjustment the agent can reach"
                )
            }
            DisciplineError::Platform(d) => write!(f, "the platform refused: {d}"),
        }
    }
}

impl std::error::Error for DisciplineError {}

/// What a discipline pass did.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Applied {
    /// Nothing was done to the system clock, on purpose.
    Vouched,
    /// The system clock's rate was changed by this many parts per million.
    Rate {
        /// What was asked for.
        requested_ppm: f64,
        /// What the platform accepted.
        applied_ppm: f64,
    },
}

/// Something that can act on a measured frequency error.
pub trait Discipline {
    /// Act on a frequency error of `frequency_ppm`, positive meaning the local clock runs slow.
    fn apply(&mut self, frequency_ppm: f64) -> Result<Applied, DisciplineError>;

    /// Whether this discipline touches the machine's own clock.
    fn touches_system_clock(&self) -> bool;
}

/// Measure and vouch. The system clock is left exactly as it was found.
///
/// This is the default because it can run beside chrony, ntpd or the Windows time service without a
/// fight, and because a stamp does not need the system clock to be right. It needs to know how
/// wrong it is.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowDiscipline;

impl Discipline for ShadowDiscipline {
    fn apply(&mut self, _frequency_ppm: f64) -> Result<Applied, DisciplineError> {
        Ok(Applied::Vouched)
    }

    fn touches_system_clock(&self) -> bool {
        false
    }
}

/// Slew the machine's clock by rate, through a platform adapter.
///
/// Used only where the operator has asked for it and the agent has the rights. The correction is
/// the measured error itself, clamped to what the platform accepts, so a wildly wrong measurement
/// produces a slow correction rather than a jump.
///
/// The two signs line up rather than cancel, and that sentence used to read the other way round.
/// `frequency_ppm` is positive when the local clock loses time against UTC, and `set_rate_ppm` is
/// documented as parts per million faster, so a clock that is slow is asked to run faster by the
/// amount it is slow by. Negating it asked a slow clock to run slower, which does not fail to
/// correct the error, it doubles it. Nothing implements `RateAdjuster` outside this crate's tests,
/// so nothing ran the wrong correction; what made it worth fixing now is that the guard asserted
/// the wrong outcome, so the first platform adapter written against it would have been blessed by a
/// green suite.
#[derive(Clone, Debug)]
pub struct RateDiscipline<A: RateAdjuster> {
    adjuster: A,
}

impl<A: RateAdjuster> RateDiscipline<A> {
    /// Wrap a platform adapter.
    pub fn new(adjuster: A) -> Self {
        Self { adjuster }
    }

    /// The adapter underneath, for a caller that needs to inspect it.
    pub fn adjuster(&self) -> &A {
        &self.adjuster
    }
}

impl<A: RateAdjuster> Discipline for RateDiscipline<A> {
    fn apply(&mut self, frequency_ppm: f64) -> Result<Applied, DisciplineError> {
        if !frequency_ppm.is_finite() {
            return Err(DisciplineError::Platform(
                "the measured frequency error is not a number".to_string(),
            ));
        }
        let max = self.adjuster.max_rate_ppm().abs();
        let requested = frequency_ppm.clamp(-max, max);
        let applied = self.adjuster.set_rate_ppm(requested)?;
        Ok(Applied::Rate {
            requested_ppm: requested,
            applied_ppm: applied,
        })
    }

    fn touches_system_clock(&self) -> bool {
        true
    }
}

/// How long a rate correction of `applied_ppm` takes to remove `error` nanoseconds of offset.
///
/// Reported so an operator can see that a correction is a slew with a duration rather than an event.
#[must_use]
pub fn slew_duration(error: Nanos, applied_ppm: f64) -> Option<Nanos> {
    if applied_ppm.abs() < f64::EPSILON || !applied_ppm.is_finite() {
        return None;
    }
    let seconds = (error as f64).abs() / (applied_ppm.abs() / 1_000_000.0);
    if !seconds.is_finite() {
        return None;
    }
    Some(seconds as Nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeAdjuster {
        max: f64,
        last: Option<f64>,
    }

    impl RateAdjuster for FakeAdjuster {
        fn set_rate_ppm(&mut self, ppm: f64) -> Result<f64, DisciplineError> {
            self.last = Some(ppm);
            Ok(ppm)
        }
        fn max_rate_ppm(&self) -> f64 {
            self.max
        }
    }

    struct RefusingAdjuster;

    impl RateAdjuster for RefusingAdjuster {
        fn set_rate_ppm(&mut self, _ppm: f64) -> Result<f64, DisciplineError> {
            Err(DisciplineError::NotPermitted)
        }
        fn max_rate_ppm(&self) -> f64 {
            500.0
        }
    }

    /// The requested rate, or a panic naming what came back instead.
    fn requested(applied: Applied) -> f64 {
        match applied {
            Applied::Rate { requested_ppm, .. } => requested_ppm,
            other => panic!("a rate discipline has to report a rate, got {other:?}"),
        }
    }

    #[test]
    fn a_slow_clock_is_asked_to_speed_up_and_a_fast_one_to_slow_down() {
        // The physical outcome and not the sign of an intermediate. A test written the other way
        // round passes whichever convention the code happens to be using, which is how this one
        // asserted for a day that a fast clock should be sped up.
        let mut d = RateDiscipline::new(FakeAdjuster {
            max: 500.0,
            last: None,
        });

        // Positive is a clock that loses time against UTC, and `set_rate_ppm` is documented as
        // parts per million faster, so the correction that removes the error is positive too.
        let speed_up = requested(
            d.apply(4.0)
                .expect("the fake accepts anything inside its max"),
        );
        assert!(
            speed_up > 0.0,
            "a clock running four parts per million slow has to be asked to run faster, and it was asked for {speed_up} ppm"
        );

        let slow_down = requested(
            d.apply(-4.0)
                .expect("the fake accepts anything inside its max"),
        );
        assert!(
            slow_down < 0.0,
            "a clock running four parts per million fast has to be asked to run slower, and it was asked for {slow_down} ppm"
        );

        // And by the amount measured, since the whole point of a rate correction is that it removes
        // the error over the following minutes rather than approximately.
        assert!((speed_up - 4.0).abs() < f64::EPSILON);
        assert!((slow_down + 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn a_wild_measurement_is_clamped_and_never_jumped() {
        let mut d = RateDiscipline::new(FakeAdjuster {
            max: 500.0,
            last: None,
        });
        // Both signs, because a clamp that holds in one direction and not the other is a clamp
        // that has been tested by accident.
        assert!((requested(d.apply(90_000.0).unwrap()) - 500.0).abs() < f64::EPSILON);
        assert!((requested(d.apply(-90_000.0).unwrap()) + 500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn shadow_mode_leaves_the_system_clock_alone() {
        let mut d = ShadowDiscipline;
        assert_eq!(d.apply(37.0).unwrap(), Applied::Vouched);
        assert!(!d.touches_system_clock());
    }

    #[test]
    fn a_platform_that_refuses_is_reported_rather_than_worked_around() {
        let mut d = RateDiscipline::new(RefusingAdjuster);
        assert_eq!(d.apply(1.0), Err(DisciplineError::NotPermitted));
    }

    #[test]
    fn a_slew_has_a_duration() {
        // Ten milliseconds of error at one hundred parts per million takes one hundred seconds.
        let hundred_seconds = 100 * timewitness_core::time::NANOS_PER_SEC;
        assert_eq!(slew_duration(10_000_000, 100.0), Some(hundred_seconds));
        assert_eq!(slew_duration(10_000_000, 0.0), None);
    }
}
