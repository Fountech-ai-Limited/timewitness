//! Why the model will not answer.
//!
//! A model that cannot support a bound refuses. It does not return a very wide bound and it does
//! not return the last good one. Those two behaviours look like working software and are the way a
//! wrong stamp gets signed, so the type system makes them impossible: a read returns either a stamp
//! or one of these, and there is no third case.

use crate::time::Nanos;
use core::fmt;

/// Whether the model is in a state where it can answer at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Validity {
    /// The model holds a bound it can support right now.
    Valid,
    /// The model has never completed a synchronisation.
    NeverSynchronised,
    /// The machine slept or suspended and has not synchronised since it came back.
    SuspendedSinceLastSync {
        /// Which resume generation the machine is on now.
        resume_generation: u64,
    },
    /// Something other than this agent moved the machine's clock, and there has been no
    /// synchronisation since.
    ///
    /// The agent does not stop the other discipliner and makes no attempt to. It records that the
    /// machine's timekeeping was interfered with and declines to sign until it has measured the
    /// clock again, because whatever stepped the clock may also be steering the counter the model
    /// reads.
    SystemClockStepped {
        /// How far the system clock moved against a counter no clock adjustment can touch, in
        /// nanoseconds. Positive means the clock was moved forward.
        by: Nanos,
    },
    /// Contact with the sources has been lost for longer than the model is willing to extrapolate.
    HoldoverExceeded {
        /// The age of the newest exchange the model still holds, in nanoseconds. Measured from the
        /// exchange and not from the selection round that used it, so a poller running over a
        /// window nothing is refreshing cannot hold this at nought.
        elapsed: Nanos,
        /// The longest holdover the policy allows, in nanoseconds.
        ceiling: Nanos,
    },
    /// Fewer sources answered than the policy requires for a majority to mean anything.
    InsufficientSources {
        /// How many answered.
        present: usize,
        /// How many the policy requires.
        required: usize,
    },
    /// Sources answered but no majority of them agreed on an overlapping interval.
    NoMajority {
        /// How many answered.
        present: usize,
        /// The most that overlapped at any one point, which did not reach a majority.
        agreeing: usize,
    },
    /// A majority existed and the only reason it did is sources that could not have disagreed.
    ///
    /// This is the one refusal textbook Marzullo would not have made, added 2026-09-09. A source
    /// whose interval contains every other interval in the round cannot be put in the minority by
    /// any answer the others could have given, so its agreement costs it nothing. Where setting
    /// those sources aside leaves the rest without a majority of their own, the majority was theirs
    /// to give and nothing was corroborated. The reasoning, and why the test is relative rather
    /// than a width in seconds, is in `timewitness_clock::marzullo`.
    FreeMajority {
        /// How many answered.
        present: usize,
        /// How many of them could have been put in the minority by another source, which is the set
        /// that failed to reach a majority between them.
        informative: usize,
    },
    /// Fewer distinct operators answered than the policy requires.
    ///
    /// A count of sources is a count of names, and names are free. This is the count of parties
    /// behind them, which is what a fault happens to. Added 2026-09-09, because the front page says
    /// four to six independent sources and nothing in the code knew what independent meant.
    ///
    /// The agent declined to sign. It did not stop anything happening, and there is no path in this
    /// design by which it could: whatever was going to be stamped went ahead unstamped.
    /// Raised at two points in one round, so `present` is the count that fell short rather than one
    /// fixed quantity: the operators that answered, where the round was short of them before the
    /// intervals were combined, and the operators still standing after selection, where it was short
    /// of them afterwards. Both are the same question about the same round and both refuse the same
    /// way, which is why they are one variant.
    InsufficientOperators {
        /// How many distinct operators stood behind the round at the point it fell short.
        present: usize,
        /// How many the policy requires.
        required: usize,
    },
    /// A majority of the intervals agreed and the parties behind them were not a majority.
    ///
    /// One company answering on six addresses is six intervals and one chance to be wrong. Marzullo
    /// counts the intervals and signs; this product counts the companies and refuses. See
    /// `timewitness_clock::independence`.
    OperatorMajority {
        /// How many distinct operators answered.
        present: usize,
        /// How many of them had a source survive the selection.
        supporting: usize,
    },
    /// A leap event is pending and the surviving sources do not handle it the same way.
    ///
    /// A smeared source and a stepped source disagree by a second across a leap event. Intersecting
    /// them would put a second of error inside an interval that claims milliseconds, so the model
    /// refuses instead.
    TimescaleConflict {
        /// A short description of which sources disagree and how.
        detail: String,
    },
    /// The bound has grown wider than the policy is prepared to put its name to.
    BoundTooWide {
        /// The width the model computed, in nanoseconds.
        width: Nanos,
        /// The widest the policy accepts, in nanoseconds.
        ceiling: Nanos,
    },
}

impl Validity {
    /// Whether a read may proceed.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Validity::Valid)
    }
}

/// The error a caller gets when it asks for a stamp and the model will not give one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The state that caused the refusal.
    pub validity: Validity,
}

impl Refusal {
    /// A refusal for a given state.
    #[must_use]
    pub const fn new(validity: Validity) -> Self {
        Self { validity }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.validity {
            Validity::Valid => write!(f, "no refusal"),
            Validity::NeverSynchronised => {
                write!(
                    f,
                    "the clock has not synchronised yet, so there is no bound to give"
                )
            }
            Validity::SuspendedSinceLastSync { resume_generation } => write!(
                f,
                "the machine resumed from sleep (generation {resume_generation}) and has not \
                 synchronised since, so the bound is unknown"
            ),
            Validity::SystemClockStepped { by } => write!(
                f,
                "this machine's clock was moved {} ms by something other than this agent, and \
                 there has been no synchronisation since, so the bound is unknown",
                crate::time::nanos_as_millis_f64(*by)
            ),
            Validity::HoldoverExceeded { elapsed, ceiling } => write!(
                f,
                "the sources have been unreachable for {} ms, past the {} ms this model will \
                 extrapolate over",
                crate::time::nanos_as_millis_f64(*elapsed),
                crate::time::nanos_as_millis_f64(*ceiling)
            ),
            Validity::InsufficientSources { present, required } => write!(
                f,
                "{present} sources answered and {required} are needed before a majority means \
                 anything"
            ),
            Validity::NoMajority { present, agreeing } => write!(
                f,
                "{agreeing} of {present} sources agreed, which is not a majority, so one of them \
                 is broken and the model cannot say which"
            ),
            Validity::FreeMajority {
                present,
                informative,
            } => write!(
                f,
                "{present} sources answered and a majority only existed because {} of them state \
                 an interval so wide it covers every other answer on offer; the {informative} that \
                 could have disagreed do not agree with each other, so nothing corroborated \
                 anything",
                present.saturating_sub(*informative)
            ),
            Validity::InsufficientOperators { present, required } => write!(
                f,
                "{present} operators stood behind this round and {required} are needed, so this \
                 agent declined to sign; several names at one company are one chance to be wrong \
                 rather than several"
            ),
            Validity::OperatorMajority {
                present,
                supporting,
            } => write!(
                f,
                "the sources that agreed are run by {supporting} of the {present} operators that \
                 answered, which is not a majority of them, so this agent declined to sign"
            ),
            Validity::TimescaleConflict { detail } => {
                write!(
                    f,
                    "the sources disagree about a pending leap second: {detail}"
                )
            }
            Validity::BoundTooWide { width, ceiling } => write!(
                f,
                "the bound has grown to {} ms, past the {} ms ceiling this model will sign for",
                crate::time::nanos_as_millis_f64(*width),
                crate::time::nanos_as_millis_f64(*ceiling)
            ),
        }
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_valid_is_valid() {
        assert!(Validity::Valid.is_valid());
        assert!(!Validity::NeverSynchronised.is_valid());
        assert!(!Validity::NoMajority {
            present: 4,
            agreeing: 2
        }
        .is_valid());
    }

    #[test]
    fn a_refusal_says_why_in_plain_words() {
        let r = Refusal::new(Validity::InsufficientSources {
            present: 2,
            required: 3,
        });
        let said = r.to_string();
        assert!(said.contains('2'));
        assert!(said.contains('3'));
    }
}
