//! What can be wrong with a receipt, said in words somebody can act on.
//!
//! The mislabelling errors are the ones that matter. A receipt presenting the agent's own bound as
//! though a third party had signed it, or a beacon value in the field that is supposed to carry a
//! signed timestamp, is not a malformed file. It is a false claim in a well-formed file, and the
//! error text says which claim and why it is not allowed.

use core::fmt;

/// Why a receipt was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    /// The bytes are not deterministic CBOR, or are not CBOR at all.
    Encoding(String),
    /// The COSE envelope is wrong, or the signature does not check out.
    Signature(String),
    /// A field is missing, or is the wrong shape, or carries a value this format does not know.
    ///
    /// The third of those was added to the sentence on 2026-09-19, when an unreadable leap value
    /// started being refused here. It had always been in the variant's meaning and never in its
    /// words, and the words are what a reader is handed.
    Field(String),
    /// The receipt is a version this code does not know.
    UnknownVersion(i128),
    /// An evidence entry claims a role its scheme cannot support.
    MislabelledEvidence {
        /// What the entry said it proves.
        role: String,
        /// What it actually carries.
        scheme: String,
        /// Why the two do not go together.
        why: String,
    },
    /// Something that is our own claim has been put where third-party evidence goes.
    OurClaimAsEvidence(String),
    /// The receipt's numbers do not support each other.
    Inconsistent(String),
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::Encoding(d) => write!(f, "the receipt is not readable: {d}"),
            ReceiptError::Signature(d) => write!(f, "the signature does not check out: {d}"),
            ReceiptError::Field(d) => write!(
                f,
                "the receipt has a field missing, or one this format cannot read: {d}"
            ),
            ReceiptError::UnknownVersion(v) => write!(
                f,
                "this receipt says it is version {v} and this code reads versions 0 and 1, so it \
                 will not guess at what the fields mean. A verifier that reads version {v} will"
            ),
            ReceiptError::MislabelledEvidence { role, scheme, why } => write!(
                f,
                "a piece of evidence claims to prove {role} and carries a {scheme}, which cannot: \
                 {why}"
            ),
            ReceiptError::OurClaimAsEvidence(d) => write!(
                f,
                "the agent's own bound has been placed where third-party evidence goes, which is \
                 the one thing this format exists to make impossible: {d}"
            ),
            ReceiptError::Inconsistent(d) => write!(f, "the receipt contradicts itself: {d}"),
        }
    }
}

impl std::error::Error for ReceiptError {}
