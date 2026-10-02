//! What a time source is, and the raw exchange one produces.
//!
//! This crate holds the shape every source has to fill in, and the clients that fill it in. A
//! client here does one thing: put a request on a socket and hand what came back to the check that
//! decides whether it holds up. That check is not here. It is in
//! [`timewitness_core::evidence`], because a stranger's verifier applies the same rules to the same
//! bytes and cannot see this crate.
//!
//! The arithmetic on an exchange lives in the clock model, not here. This crate's job is to say
//! what was observed; deciding what it means is somebody else's.

#![forbid(unsafe_code)]

pub mod drand;
pub mod http;
pub mod ntp;
pub mod nts;
pub mod roughtime;
pub mod timestamp;

use timewitness_core::{
    Attestation, LeapIndicator, MonotonicNanos, Nanos, Operator, SmearPolicy, SourceId, SourceKind,
    Timescale, UnixNanos,
};

/// One completed request and reply against a time source.
///
/// The standard exchange every NTP client makes has four timestamps: two the machine took and two
/// the server reported. The server's own processing time falls out of the round trip arithmetic,
/// which is the whole reason there are four rather than two.
///
/// **Only the server's two are here.** A source client reports what it observed of the source and
/// the two counter marks it took while doing it, and it reports no local time at all. This is
/// deliberate and it is the one thing about this type worth reading twice. A machine has more than
/// one local clock: the system clock, which another time service is usually steering, and the
/// projection the clock model runs forward over the monotonic counter. They disagree by more every
/// minute on any machine where something else is holding the system clock near UTC, which is most
/// machines. An offset measured against one of them and an interval anchored to the other describe
/// nothing, and no amount of care in a client fixes it, because the client cannot see the model's
/// projection. So the model stamps both ends of the round trip itself, off the two counter marks,
/// and the clock the offsets are measured against is the clock the bound is anchored to by
/// construction rather than by anybody remembering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Which source answered.
    pub source: SourceId,
    /// Who runs it.
    ///
    /// Carried on the exchange rather than looked up later for the same reason the local
    /// timestamps are not on it: the selection has to be able to group sources by operator without
    /// anybody downstream remembering to. A client knows who it is talking to and nothing after it
    /// does.
    pub operator: Operator,
    /// What that source speaks, and so what its answer may be used for.
    pub kind: SourceKind,

    /// When the source says it received the request.
    pub t2: UnixNanos,
    /// When the source says it sent the reply.
    pub t3: UnixNanos,

    /// The monotonic counter as the request went out.
    ///
    /// The model turns this into a local UTC value itself. Take it as close to the write as the
    /// transport allows, because everything between the read and the packet leaving is charged to
    /// the round trip and so to the width of the bound.
    pub mono_t1: MonotonicNanos,
    /// The monotonic counter as the reply came in.
    pub mono_t4: MonotonicNanos,

    /// The source's own total delay back to its reference, in nanoseconds.
    ///
    /// This is NTP's root delay. Half of it is the part of the source's uncertainty that comes from
    /// the path between the source and whatever it is disciplined by.
    pub root_delay: Nanos,
    /// The source's own accumulated dispersion back to its reference, in nanoseconds.
    pub root_dispersion: Nanos,

    /// The timescale the source answers on.
    pub timescale: Timescale,
    /// What the source does with a leap second.
    pub smear: SmearPolicy,
    /// What the source last said about an upcoming leap second.
    pub leap: LeapIndicator,

    /// What the source signed, where it signed anything.
    ///
    /// `None` for a plain NTP server, which authenticates nothing and can only improve the clock.
    /// A Roughtime server signs over the nonce we sent, and that signature is the only part of the
    /// exchange a stranger can check for themselves, so it is carried out of this crate rather than
    /// thrown away once the offset has been taken.
    pub attestation: Option<Attestation>,
}

impl Exchange {
    /// The uncertainty the source states about itself, in nanoseconds.
    ///
    /// This is the root distance NTP already publishes: the accumulated dispersion plus half the
    /// accumulated delay. Meinberg states the inequality directly, that the clock error is at most
    /// the offset plus the root dispersion plus half the root delay, and this term is the second
    /// and third parts of it. Half the round trip we measured ourselves is added separately, by the
    /// clock model, because it is our own contribution rather than the source's.
    #[must_use]
    pub fn stated_uncertainty(&self) -> Nanos {
        let dispersion = self.root_dispersion.max(0);
        let half_delay = self.root_delay.max(0) / 2;
        dispersion + half_delay
    }
}

/// Something that can be asked what time it is.
///
/// Every source returns an exchange rather than a time, because a time on its own is not something
/// this product is willing to act on.
pub trait TimeSource {
    /// Which source this is.
    fn id(&self) -> &SourceId;

    /// Who runs it.
    ///
    /// On the trait rather than left to the caller, because a source that cannot say who runs it
    /// cannot be counted towards the independence floor, and a floor with a hole in it is not one.
    fn operator(&self) -> &Operator;

    /// What it speaks. This decides whether its answer can ever be portable evidence.
    fn kind(&self) -> SourceKind;

    /// Ask it, and report what came back.
    ///
    /// `now` is the monotonic counter at the moment of the call, passed in rather than read here so
    /// a test can drive the clock.
    ///
    /// `nonce` is generated by the caller and sent with the request. A source that can sign puts
    /// its signature over these bytes and returns both in the exchange's attestation, which is what
    /// makes the answer evidence rather than advice. A source that cannot sign ignores it. It is a
    /// parameter rather than something a client invents so that the bytes in the receipt are the
    /// bytes the caller can show it chose.
    fn poll(&mut self, now: MonotonicNanos, nonce: &[u8]) -> Result<Exchange, SourceError>;
}

/// Why a source could not be polled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    /// The request went out and nothing came back within the deadline.
    Timeout,
    /// Something came back and it was not a valid response.
    Malformed(String),
    /// The transport itself failed.
    Transport(String),
    /// The source said it is not synchronised, so its answer means nothing.
    Unsynchronised,
}

impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SourceError::Timeout => write!(f, "the source did not answer in time"),
            SourceError::Malformed(d) => {
                write!(f, "the source answered with something invalid: {d}")
            }
            SourceError::Transport(d) => write!(f, "the transport failed: {d}"),
            SourceError::Unsynchronised => write!(f, "the source says it is not synchronised"),
        }
    }
}

impl std::error::Error for SourceError {}

/// Something that publishes an unpredictable value at a known moment.
///
/// **Not a [`TimeSource`], and the difference is the whole point.** A time source answers a
/// question we asked, with four timestamps that make an offset. A beacon answers nobody: it
/// publishes on a schedule, everybody reads the same value, and there is no round trip to measure.
/// Its value is that nobody could have known the value beforehand, so a document containing it was
/// finished afterwards. It disciplines no clock and it never enters the Marzullo intersection.
///
/// The moment a beacon value belongs to is arithmetic on the beacon's published schedule rather
/// than a signed statement. That is a real limitation and every implementation says so in what it
/// returns, because a reader who thinks the signature covers the time has the wrong idea of what a
/// not-earlier-than entry proves.
pub trait FreshnessBeacon {
    /// The beacon's name, for a person reading a receipt.
    fn name(&self) -> &str;

    /// The scheme name the receipt format uses for this beacon.
    fn scheme(&self) -> &'static str;

    /// Fetch the current published value and check it.
    ///
    /// `expected` is where the agent's own model believes the present is, and `tolerance` is how far
    /// from that a published value may be before it is refused. A beacon far behind the reading is
    /// not evidence for it: the edge it pins is one nobody needed pinning. The expectation comes
    /// from a clock the agent already admits it cannot fully trust, which is why the corridor role
    /// exists separately.
    fn fetch_near(&self, expected: UnixNanos, tolerance: Nanos)
        -> Result<Attestation, SourceError>;
}

/// Something that will put its own name to having seen a value.
///
/// The opposite edge from a beacon. A beacon proves a document is not older than a moment because
/// it contains something unpredictable; a witness proves a document is not newer than a moment
/// because somebody else recorded having seen it. Neither can do the other's job.
pub trait FinalWitness {
    /// The witness's name, for a person reading a receipt.
    fn name(&self) -> &str;

    /// The scheme name the receipt format uses for this witness.
    fn scheme(&self) -> &'static str;

    /// Show the witness a hash and keep what it says about having seen it.
    fn witness(&self, subject_hash: &[u8]) -> Result<Attestation, SourceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(root_delay: Nanos, root_dispersion: Nanos) -> Exchange {
        Exchange {
            source: SourceId::new("test"),
            operator: Operator::new("test"),
            kind: SourceKind::Ntp,
            t2: UnixNanos(0),
            t3: UnixNanos(0),
            mono_t1: MonotonicNanos(0),
            mono_t4: MonotonicNanos(0),
            root_delay,
            root_dispersion,
            timescale: Timescale::Utc,
            smear: SmearPolicy::None,
            leap: LeapIndicator::None,
            attestation: None,
        }
    }

    #[test]
    fn stated_uncertainty_is_dispersion_plus_half_the_root_delay() {
        let e = exchange(4_000_000, 1_000_000);
        assert_eq!(e.stated_uncertainty(), 1_000_000 + 2_000_000);
    }

    #[test]
    fn negative_reported_figures_do_not_shrink_the_uncertainty() {
        let e = exchange(-4_000_000, -1_000_000);
        assert_eq!(e.stated_uncertainty(), 0);
    }

    #[test]
    fn an_exchange_carries_the_nonce_it_sent_and_the_response_it_got_back() {
        let mut e = exchange(0, 0);
        assert_eq!(e.attestation, None, "a plain server signs nothing");

        e.attestation = Some(Attestation::over_interval(
            b"the nonce we chose".to_vec(),
            b"the bytes the server signed".to_vec(),
            UnixNanos(1_757_000_000_000_000_000),
            3_000_000,
        ));

        let carried = e.attestation.expect("the exchange keeps what it was given");
        assert_eq!(carried.nonce, b"the nonce we chose");
        assert_eq!(carried.latest() - carried.earliest(), 6_000_000);
    }
}
