//! Checking a stored attestation for itself, with no network and nobody to ask.
//!
//! Everything under here takes bytes and a public key and answers one question: does this blob
//! really say what a receipt claims it says. There is no socket in this module and there never
//! will be. Fetching evidence is the sources crate's job; deciding whether the bytes hold up is
//! this one's, because two very different callers need the same answer and neither may see the
//! other.
//!
//! The agent calls it the moment a response arrives, before anything from that response reaches
//! the clock model. A verifier that has never spoken to us calls it years later on the same bytes
//! carried in the receipt. Both get the same function, so a receipt cannot be accepted by the
//! agent under one rule and by a stranger under another.
//!
//! It sits in this crate for the reason [`crate::Attestation`] does. The clock model and the
//! receipt both need it, and neither is allowed to depend on the other.
//!
//! **A check that cannot be made is reported as not made.** Nothing here returns a partial pass or
//! a warning. Either the bytes were verified against a key, in which case [`Checked`] says exactly
//! which checks ran, or an error comes back naming what failed. The rule that our own bound is
//! never third-party evidence turns on this distinction: our own bound is a claim, and only a
//! signature a stranger can check is evidence.

pub mod der;
pub mod drand;
pub mod rfc3161;
pub mod roughtime;

use crate::time::UnixNanos;

/// What checking one blob established.
///
/// The `checks` list is not decoration. The verifier prints it, so a person reading a receipt can
/// see which entries were tested and how, rather than being told a receipt is good. An entry with
/// an empty list has not been checked and does not support anything.
/// The two ends are private, and that is the point of them. Every value in a receipt that moves an
/// edge inwards is a value somebody else chose, so an interval whose end is before its start has to
/// be a thing this type cannot hold rather than a thing every reader has to remember to check. One
/// path could already produce one, from an RFC 3161 accuracy read as a magnitude, and it was found
/// by attacking that path rather than by reading this one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// The scheme whose rules were applied, spelled as the receipt format spells it.
    pub scheme: &'static str,
    /// Who signed it, as the blob and the key together identify them.
    pub signer: String,
    /// The earliest instant the signed content supports, where it supports one at all.
    ///
    /// `None` is a scheme that checked out and put no number on where the moment sits. It is not
    /// the same fact as an interval of zero width and it may never be read as one. An RFC 3161
    /// token whose authority left the accuracy field out is the case this exists for: the
    /// signature holds, the hash matches, and the authority has said nothing about how wrong its
    /// own clock could be, so there is no edge to compute. Carrying that as an instant is the
    /// tightening direction and it is what this field was until 2026-09-19.
    earliest: Option<UnixNanos>,
    /// The latest instant the signed content supports, never before `earliest`.
    ///
    /// Absent under the same rule as `earliest`, and absent together with it: a scheme either says
    /// where the moment sits or it does not.
    latest: Option<UnixNanos>,
    /// The nonce the signature was made over, where the scheme signs over one.
    pub nonce: Option<Vec<u8>>,
    /// What was checked, one line each, in the order it was checked.
    pub checks: Vec<String>,
}

impl Checked {
    /// What checking a blob established over an interval.
    ///
    /// Refuses an interval whose end is before its start. Ordering the two silently would be worse
    /// than accepting them: the caller has been handed something impossible and would be told
    /// nothing about it.
    pub fn over(
        scheme: &'static str,
        signer: String,
        earliest: UnixNanos,
        latest: UnixNanos,
        nonce: Option<Vec<u8>>,
        checks: Vec<String>,
    ) -> Result<Self, EvidenceError> {
        if latest < earliest {
            return Err(EvidenceError::Inconsistent(format!(
                "an interval ending at {} that starts at {}, which is not an interval",
                latest.as_nanos(),
                earliest.as_nanos()
            )));
        }
        Ok(Self {
            scheme,
            signer,
            earliest: Some(earliest),
            latest: Some(latest),
            nonce,
            checks,
        })
    }

    /// What checking a blob established where the blob says nothing about where the moment sits.
    ///
    /// Added 2026-09-19. The signature checked out and the content is what it
    /// claims to be, and the scheme still put no number on the interval. That is a different
    /// answer from an interval and a different answer from an unchecked entry, and a reader who
    /// cannot tell the three apart will read the wrong one as the strongest.
    #[must_use]
    pub fn with_no_interval(
        scheme: &'static str,
        signer: String,
        nonce: Option<Vec<u8>>,
        checks: Vec<String>,
    ) -> Self {
        Self {
            scheme,
            signer,
            earliest: None,
            latest: None,
            nonce,
            checks,
        }
    }

    /// What checking a blob established about a single instant.
    ///
    /// A beacon round is one of these: it pins an edge and asserts nothing about the other one.
    #[must_use]
    pub fn at_instant(
        scheme: &'static str,
        signer: String,
        at: UnixNanos,
        nonce: Option<Vec<u8>>,
        checks: Vec<String>,
    ) -> Self {
        Self {
            scheme,
            signer,
            earliest: Some(at),
            latest: Some(at),
            nonce,
            checks,
        }
    }

    /// The earliest instant the signed content supports, where it supports one.
    #[must_use]
    pub const fn earliest(&self) -> Option<UnixNanos> {
        self.earliest
    }

    /// The latest instant the signed content supports, where it supports one.
    #[must_use]
    pub const fn latest(&self) -> Option<UnixNanos> {
        self.latest
    }

    /// The midpoint of the interval the blob supports, where it supports one.
    #[must_use]
    pub fn midpoint(&self) -> Option<UnixNanos> {
        let (earliest, latest) = (self.earliest?, self.latest?);
        Some(UnixNanos((earliest.as_nanos() + latest.as_nanos()) / 2))
    }

    /// Half the width of that interval, where there is one.
    #[must_use]
    pub fn radius(&self) -> Option<crate::time::Nanos> {
        let (earliest, latest) = (self.earliest?, self.latest?);
        Some((latest.as_nanos() - earliest.as_nanos()) / 2)
    }
}

/// Why a blob was not accepted.
///
/// Every variant carries enough for a person to act on. "Invalid" on its own tells a user nothing
/// and tells an attacker nothing either, which is the wrong trade for a format whose whole purpose
/// is that a stranger can audit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// The bytes are not the shape this scheme has.
    Malformed(String),
    /// A signature did not verify against the key it was supposed to.
    BadSignature(String),
    /// The response was signed over something other than what we sent.
    WrongNonce(String),
    /// The signing key was not the one the server delegated to, or was used outside its window.
    OutsideDelegation(String),
    /// The blob is internally inconsistent: it disagrees with itself.
    Inconsistent(String),
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EvidenceError::Malformed(d) => write!(f, "the response is malformed: {d}"),
            EvidenceError::BadSignature(d) => write!(f, "a signature does not check out: {d}"),
            EvidenceError::WrongNonce(d) => {
                write!(f, "the response was not signed over what we sent: {d}")
            }
            EvidenceError::OutsideDelegation(d) => {
                write!(f, "the signing key was not entitled to sign this: {d}")
            }
            EvidenceError::Inconsistent(d) => {
                write!(f, "the response contradicts itself: {d}")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_interval_that_ends_before_it_starts_cannot_be_built() {
        // Ordering the two silently would be worse than accepting them, because the caller has been
        // handed something impossible and would be told nothing about it.
        let err = Checked::over(
            "rfc3161",
            "an authority stating minus one hour".to_string(),
            UnixNanos(3_600_000_000_000),
            UnixNanos(0),
            None,
            Vec::new(),
        )
        .expect_err("an interval cannot end before it starts");
        assert!(matches!(err, EvidenceError::Inconsistent(_)));
    }

    #[test]
    fn an_interval_that_is_a_single_instant_is_fine() {
        let at = UnixNanos(1_757_000_000_000_000_000);
        let checked = Checked::at_instant("drand", "quicknet".to_string(), at, None, Vec::new());
        assert_eq!(checked.earliest(), Some(at));
        assert_eq!(checked.latest(), Some(at));
        assert_eq!(checked.radius(), Some(0));
        assert!(Checked::over("drand", String::new(), at, at, None, Vec::new()).is_ok());
    }
}
