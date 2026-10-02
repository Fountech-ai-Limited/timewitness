//! Every way a reading can lose UTC, and what the model does about each one.
//!
//! This list is the point of the crate stated once. A bound that has lost UTC must widen or refuse,
//! and the two are not interchangeable: a widening keeps a reading that is still true and says so
//! less precisely, a refusal declines to say anything at all. What is forbidden is the third
//! behaviour, carrying on at the same width, and it is forbidden because it is the only one of the
//! three that looks like working software from the outside.
//!
//! The list exists because the faults kept being fixed one at a time. Four earlier fixes were each
//! raised on a property and each finished on the examples the fix happened to name, so the fifth
//! fault in the same layer was still there after all four. A fix cannot be finished on an example
//! when the example is one entry in a list somebody has to keep complete.
//!
//! Two rules hold it to that. Every entry names where it is handled, in words a reader can go and
//! check against the code. And `crates/clock/tests/loss_of_utc.rs` carries one test per entry and a
//! test that the set of tested entries is [`LossOfUtc::ALL`], so adding an entry without a test
//! fails the suite rather than passing quietly.
//!
//! Nothing in the running model reads this enumeration. It is a description of behaviour that lives
//! elsewhere, held honest by tests rather than by being called, and that is deliberate: a list the
//! model consulted would be a second place for the decision to live, and the two would drift.

/// What the model does when a reading has lost UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    /// The interval grows to keep holding the truth, and the reading stays usable.
    Widens,
    /// The model declines to answer. It never hands back the last good interval and it never hands
    /// back a very wide one for the caller to notice.
    Refuses,
}

/// One way a reading can lose UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossOfUtc {
    /// Nothing has been measured yet, so there is no interval to give.
    NothingMeasuredYet,
    /// Fewer sources answered than the policy requires before a majority means anything.
    TooFewSources,
    /// Sources answered and no majority of them overlapped, so one is broken and the model cannot
    /// say which.
    NoMajorityAgrees,
    /// A majority of the sources overlapped and the only reason it did is one or more of them
    /// stating an interval so wide it covers every other answer in the round.
    ///
    /// This is the one entry textbook Marzullo would not have. See `marzullo` for the rule and for
    /// the decision of 2026-09-09 behind it.
    MajorityOnlyFromFreeAgreement,
    /// A source says its own clock is not synchronised, so its answer means nothing.
    SourceDisclaimsItsOwnClock,
    /// A reply whose own two timestamps cannot both be true, which computes a negative round trip.
    ReplyThatCannotBeTrue,
    /// The surviving sources handle a leap second differently, which puts a second of error inside
    /// an interval claiming milliseconds.
    SourcesDisagreeAcrossALeap,
    /// The machine slept, so everything measured before it went away describes a clock that has
    /// since been on its own for an unknown time.
    MachineSlept,
    /// Something other than this agent moved the system clock, which is evidence that a second
    /// discipliner is active and may also be steering the counter.
    ClockStepped,
    /// The newest exchange behind the interval is older than the model will extrapolate over.
    ContactLost,
    /// The interval has grown wider than the policy is prepared to put its name to.
    IntervalTooWide,
    /// The round trip was split unevenly between the two legs, and no arithmetic over the four
    /// timestamps can see how unevenly.
    NetworkAsymmetry,
    /// What the source said about its own distance from its reference.
    SourceStatedUncertainty,
    /// A source claiming to know its own time exactly, which is a point rather than an interval and
    /// is floored to a width before it is compared with anybody.
    SourceUnderstatesItself,
    /// The gap between the exchange arriving and the round that used it, over which the machine's
    /// clock moved and nobody watched.
    SampleAgeing,
    /// The gap between the newest exchange and the reading, over which the model is extrapolating
    /// at the frequency uncertainty it measured.
    OscillatorHoldover,
    /// The oscillator's rate is not the rate that was fitted, because a crystal changes rate as it
    /// warms and a hypervisor changes it when it likes.
    RateMovedAfterTheFit,
    /// A fitted rate the model would not stand behind. The correction is not applied, so the whole
    /// magnitude of it is carried as width instead.
    RateTheModelWouldNotClaim,
    /// The scatter of the measurements themselves, which the regression reports as the standard
    /// error of the offset and the coverage factor multiplies.
    ModelResidual,
    /// The cost and the granularity of the local counter read, including the thread being
    /// descheduled between the read and its use.
    LocalReadCost,
    /// The fixed allowance the policy adds to every interval, for what none of the above named.
    SafetyMargin,
}

impl LossOfUtc {
    /// Every way there is, and the list a test has to cover in full.
    pub const ALL: [LossOfUtc; 21] = [
        LossOfUtc::NothingMeasuredYet,
        LossOfUtc::TooFewSources,
        LossOfUtc::NoMajorityAgrees,
        LossOfUtc::MajorityOnlyFromFreeAgreement,
        LossOfUtc::SourceDisclaimsItsOwnClock,
        LossOfUtc::ReplyThatCannotBeTrue,
        LossOfUtc::SourcesDisagreeAcrossALeap,
        LossOfUtc::MachineSlept,
        LossOfUtc::ClockStepped,
        LossOfUtc::ContactLost,
        LossOfUtc::IntervalTooWide,
        LossOfUtc::NetworkAsymmetry,
        LossOfUtc::SourceStatedUncertainty,
        LossOfUtc::SourceUnderstatesItself,
        LossOfUtc::SampleAgeing,
        LossOfUtc::OscillatorHoldover,
        LossOfUtc::RateMovedAfterTheFit,
        LossOfUtc::RateTheModelWouldNotClaim,
        LossOfUtc::ModelResidual,
        LossOfUtc::LocalReadCost,
        LossOfUtc::SafetyMargin,
    ];

    /// Whether the model widens the interval or refuses to answer.
    #[must_use]
    pub const fn response(self) -> Response {
        match self {
            LossOfUtc::NothingMeasuredYet
            | LossOfUtc::TooFewSources
            | LossOfUtc::NoMajorityAgrees
            | LossOfUtc::MajorityOnlyFromFreeAgreement
            | LossOfUtc::SourceDisclaimsItsOwnClock
            | LossOfUtc::ReplyThatCannotBeTrue
            | LossOfUtc::SourcesDisagreeAcrossALeap
            | LossOfUtc::MachineSlept
            | LossOfUtc::ClockStepped
            | LossOfUtc::ContactLost
            | LossOfUtc::IntervalTooWide => Response::Refuses,
            LossOfUtc::NetworkAsymmetry
            | LossOfUtc::SourceStatedUncertainty
            | LossOfUtc::SourceUnderstatesItself
            | LossOfUtc::SampleAgeing
            | LossOfUtc::OscillatorHoldover
            | LossOfUtc::RateMovedAfterTheFit
            | LossOfUtc::RateTheModelWouldNotClaim
            | LossOfUtc::ModelResidual
            | LossOfUtc::LocalReadCost
            | LossOfUtc::SafetyMargin => Response::Widens,
        }
    }

    /// The name a test covers this entry under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            LossOfUtc::NothingMeasuredYet => "nothing measured yet",
            LossOfUtc::TooFewSources => "too few sources",
            LossOfUtc::NoMajorityAgrees => "no majority agrees",
            LossOfUtc::MajorityOnlyFromFreeAgreement => "majority only from free agreement",
            LossOfUtc::SourceDisclaimsItsOwnClock => "source disclaims its own clock",
            LossOfUtc::ReplyThatCannotBeTrue => "reply that cannot be true",
            LossOfUtc::SourcesDisagreeAcrossALeap => "sources disagree across a leap",
            LossOfUtc::MachineSlept => "machine slept",
            LossOfUtc::ClockStepped => "clock stepped",
            LossOfUtc::ContactLost => "contact lost",
            LossOfUtc::IntervalTooWide => "interval too wide",
            LossOfUtc::NetworkAsymmetry => "network asymmetry",
            LossOfUtc::SourceStatedUncertainty => "source stated uncertainty",
            LossOfUtc::SourceUnderstatesItself => "source understates itself",
            LossOfUtc::SampleAgeing => "sample ageing",
            LossOfUtc::OscillatorHoldover => "oscillator holdover",
            LossOfUtc::RateMovedAfterTheFit => "rate moved after the fit",
            LossOfUtc::RateTheModelWouldNotClaim => "rate the model would not claim",
            LossOfUtc::ModelResidual => "model residual",
            LossOfUtc::LocalReadCost => "local read cost",
            LossOfUtc::SafetyMargin => "safety margin",
        }
    }

    /// Where the behaviour lives, for a reader who wants to check the entry against the code.
    #[must_use]
    pub const fn handled_in(self) -> &'static str {
        match self {
            LossOfUtc::NothingMeasuredYet
            | LossOfUtc::MachineSlept
            | LossOfUtc::ClockStepped
            | LossOfUtc::ContactLost => "model::ClockModel::validity_at",
            LossOfUtc::TooFewSources
            | LossOfUtc::NoMajorityAgrees
            | LossOfUtc::MajorityOnlyFromFreeAgreement => {
                "model::ClockModel::synchronise, against marzullo::intersect"
            }
            LossOfUtc::SourceDisclaimsItsOwnClock => {
                "model::ClockModel::synchronise, the eligibility filter"
            }
            LossOfUtc::ReplyThatCannotBeTrue => "sample::Sample::from_exchange",
            LossOfUtc::SourcesDisagreeAcrossALeap => {
                "model::timescale_conflict and model::smear_split"
            }
            LossOfUtc::IntervalTooWide => "model::ClockModel::read, against policy.max_bound_width",
            LossOfUtc::NetworkAsymmetry
            | LossOfUtc::SourceStatedUncertainty
            | LossOfUtc::SourceUnderstatesItself
            | LossOfUtc::SampleAgeing => "sample::Sample::interval_at",
            LossOfUtc::OscillatorHoldover
            | LossOfUtc::RateMovedAfterTheFit
            | LossOfUtc::RateTheModelWouldNotClaim
            | LossOfUtc::ModelResidual
            | LossOfUtc::LocalReadCost
            | LossOfUtc::SafetyMargin => "model::ClockModel::read, the widening terms",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_appears_once_in_the_list() {
        for (i, a) in LossOfUtc::ALL.iter().enumerate() {
            for b in LossOfUtc::ALL.iter().skip(i + 1) {
                assert_ne!(a, b, "{} is listed twice", a.name());
            }
        }
    }

    #[test]
    fn every_entry_has_a_distinct_name() {
        for (i, a) in LossOfUtc::ALL.iter().enumerate() {
            for b in LossOfUtc::ALL.iter().skip(i + 1) {
                assert_ne!(
                    a.name(),
                    b.name(),
                    "two entries answer to the name {}",
                    a.name()
                );
            }
        }
    }

    #[test]
    fn every_entry_says_which_of_the_two_it_does() {
        // There is no third answer, and the point of the type is that there cannot be one. This
        // test is here so the sentence is asserted somewhere rather than only written down.
        for entry in LossOfUtc::ALL {
            assert!(matches!(
                entry.response(),
                Response::Widens | Response::Refuses
            ));
            assert!(
                !entry.handled_in().is_empty(),
                "{} names nowhere",
                entry.name()
            );
        }
    }
}
