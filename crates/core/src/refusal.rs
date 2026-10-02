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
    /// The policy the model was given is one its arithmetic cannot stand behind.
    ///
    /// A coverage factor under one, or a rate that is not a number or is negative. Each of those
    /// used to narrow the bound rather than widen it, so the model refuses before it synchronises
    /// and before it reads. Added 2026-09-17.
    PolicyRefused {
        /// Which field, what it held, and what it has to be.
        detail: String,
    },
    /// The counter reads earlier than the moment this model started.
    ///
    /// A monotonic counter only goes forward, so a reading before the model's own origin is a
    /// platform fault, and nothing the model holds describes a moment it was not running for. Added
    /// 2026-09-17, when a cold set stepped the counter back past the origin and found the model
    /// projecting its anchor backwards over a moment it had never measured.
    CounterBeforeStart {
        /// How far before the model's origin the counter reads, in nanoseconds.
        by: Nanos,
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
        write!(f, "{}", self.validity)
    }
}

/// Why the model will not answer, as a person reads it.
///
/// This is the only way a refusal reaches anybody. Its debug form is for a test failing, and a
/// sentence built from it prints the type's insides, which is what a stamp with no network did
/// until 2026-09-24. Every sentence here is held to plain words by the tests below.
impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Validity::Valid => write!(f, "no refusal"),
            Validity::NeverSynchronised => {
                write!(
                    f,
                    "the clock has not synchronised yet, so there is no bound to give"
                )
            }
            // The generation count is for the receipt and the verifier. A person needs to know
            // the machine slept, and how many times it has is not a reason.
            Validity::SuspendedSinceLastSync { .. } => write!(
                f,
                "this machine resumed from sleep and has not synchronised since, so the bound is \
                 unknown until it hears from its sources again"
            ),
            Validity::SystemClockStepped { by } => write!(
                f,
                "this machine's clock was moved {} ms by something other than this agent, and \
                 there has been no synchronisation since, so the bound is unknown",
                crate::time::nanos_as_millis_f64(*by)
            ),
            Validity::CounterBeforeStart { by } => write!(
                f,
                "the monotonic counter reads {} ms before the moment this model started, which a counter that only goes forward cannot do, so nothing here describes this moment",
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
            Validity::PolicyRefused { detail } => write!(
                f,
                "this model was given a policy its arithmetic cannot stand behind, so it declined \
                 to sign: {detail}"
            ),
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

/// One of each refusal, so a test can read every sentence a person could be handed.
///
/// The list is held to the type by [`kind_of`], whose match has no catch-all arm. A refusal added
/// to [`Validity`] does not compile until it has a number there, and the test that reads this list
/// fails until the list carries one of it. So a new refusal cannot reach anybody without its
/// sentence having been read first. `Valid` is not here, because it is not a refusal.
#[doc(hidden)]
#[must_use]
pub fn one_of_each() -> Vec<Validity> {
    vec![
        Validity::NeverSynchronised,
        Validity::SuspendedSinceLastSync {
            resume_generation: 3,
        },
        Validity::SystemClockStepped { by: -2_500_000_000 },
        Validity::HoldoverExceeded {
            elapsed: 1_000_000_000_000,
            ceiling: 960_000_000_000,
        },
        Validity::InsufficientSources {
            present: 0,
            required: 3,
        },
        Validity::NoMajority {
            present: 5,
            agreeing: 2,
        },
        Validity::FreeMajority {
            present: 6,
            informative: 3,
        },
        Validity::InsufficientOperators {
            present: 2,
            required: 4,
        },
        Validity::OperatorMajority {
            present: 6,
            supporting: 2,
        },
        Validity::TimescaleConflict {
            detail: "time.example handles a leap second by stepping it and ntp.example handles \
                     it by spreading it over 86400 s, and a leap second is pending"
                .to_string(),
        },
        Validity::PolicyRefused {
            detail: "coverage_factor is 0.5 and has to be a number no smaller than one".to_string(),
        },
        Validity::CounterBeforeStart { by: 1_500_000 },
        Validity::BoundTooWide {
            width: 1_203_645_522,
            ceiling: 250_000_000,
        },
    ]
}

/// How many kinds of refusal there are, which is the number of arms in [`kind_of`] less `Valid`.
#[doc(hidden)]
pub const KINDS_OF_REFUSAL: usize = 13;

/// Which kind of refusal this is, numbered from one, or nought for `Valid`.
///
/// No catch-all arm, on purpose. It is the line that will not compile when a refusal is added, and
/// that is what sends the person adding one to [`one_of_each`].
#[doc(hidden)]
#[must_use]
pub const fn kind_of(validity: &Validity) -> usize {
    match validity {
        Validity::Valid => 0,
        Validity::NeverSynchronised => 1,
        Validity::SuspendedSinceLastSync { .. } => 2,
        Validity::SystemClockStepped { .. } => 3,
        Validity::HoldoverExceeded { .. } => 4,
        Validity::InsufficientSources { .. } => 5,
        Validity::NoMajority { .. } => 6,
        Validity::FreeMajority { .. } => 7,
        Validity::InsufficientOperators { .. } => 8,
        Validity::OperatorMajority { .. } => 9,
        Validity::TimescaleConflict { .. } => 10,
        Validity::PolicyRefused { .. } => 11,
        Validity::CounterBeforeStart { .. } => 12,
        Validity::BoundTooWide { .. } => 13,
    }
}

/// What in a sentence would tell a person they had been handed the program's insides rather than a
/// reason, or nothing where it reads as words.
///
/// A refusal printed with its debug form reads `InsufficientSources { present: 0, required: 3 }`,
/// which was found on 2026-09-24 in the sentence a stamp with no network printed. Three marks give
/// that away whatever the type: braces, a path separator, and a word joined from two capitalised
/// words. The names of the refusals themselves are looked for as well, because a variant with no
/// fields prints as one bare capitalised word and none of the three marks catches it.
#[doc(hidden)]
#[must_use]
pub fn insides_in(said: &str) -> Option<String> {
    for mark in ["{", "}", "::", "Some(", "Ok(", "Err("] {
        if said.contains(mark) {
            return Some(mark.to_string());
        }
    }
    const NAMES: [&str; 17] = [
        "Valid",
        "NeverSynchronised",
        "SuspendedSinceLastSync",
        "SystemClockStepped",
        "HoldoverExceeded",
        "InsufficientSources",
        "NoMajority",
        "FreeMajority",
        "InsufficientOperators",
        "OperatorMajority",
        "TimescaleConflict",
        "PolicyRefused",
        "CounterBeforeStart",
        "BoundTooWide",
        "Linear",
        "SmearPolicy",
        "Validity",
    ];
    for word in said.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if NAMES.contains(&word) {
            return Some(word.to_string());
        }
        let joined = word
            .chars()
            .zip(word.chars().skip(1))
            .any(|(a, b)| a.is_lowercase() && b.is_uppercase());
        if joined {
            return Some(word.to_string());
        }
    }
    None
}

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

    #[test]
    fn the_list_holds_one_of_every_refusal() {
        let mut seen: Vec<usize> = one_of_each().iter().map(kind_of).collect();
        seen.sort_unstable();
        let every: Vec<usize> = (1..=KINDS_OF_REFUSAL).collect();
        assert_eq!(seen, every, "one_of_each has to carry each refusal once");
    }

    #[test]
    fn every_refusal_says_why_in_plain_words() {
        for validity in one_of_each() {
            let said = Refusal::new(validity.clone()).to_string();
            assert_eq!(insides_in(&said), None, "{said}");
            assert_eq!(
                validity.to_string(),
                said,
                "a state and its refusal say one thing"
            );
        }
    }

    #[test]
    fn the_insides_are_caught_in_every_shape_they_came_in() {
        let debug = format!(
            "{:?}",
            Validity::InsufficientSources {
                present: 0,
                required: 3
            }
        );
        assert!(insides_in(&debug).is_some(), "{debug}");
        assert!(insides_in(&format!("{:?}", Validity::NeverSynchronised)).is_some());
        assert!(insides_in("handles a leap second as Linear").is_some());
        assert!(insides_in("the refusal said Some(3)").is_some());
        assert_eq!(
            insides_in("0 sources answered and 3 are needed, time.cloudflare.com did not answer"),
            None
        );
    }
}
