//! The receipt format, which this code writes at version 1 and reads at versions 0 and 1.
//!
//! A receipt is a long-lived artefact. Once one is issued it has to keep meaning the same thing
//! years later, to a verifier that never spoke to us, so the format is frozen and versioned from
//! the first release.
//!
//! The shape it is frozen in is the point. There are two places a statement about time can sit and
//! they are not interchangeable. `claim` holds the agent's own bound, which is the most precise
//! number in the receipt and the only one that rests on trusting us. `evidence` holds third-party
//! attestations, each labelled with what it proves and each carrying the signed response in full.
//! Presenting the first as the second is the central dishonesty available to a product in this
//! field, and here it is not a rule anybody has to remember: the two are different shapes and
//! [`validate`] refuses a receipt that blurs them.
//!
//! This crate never learns how a bound is computed. It carries one.
//!
//! The specification is `docs/receipt-format-v0.md` beside the code, and `docs/receipt-format-v1.md`
//! for what version 1 adds to it.

#![forbid(unsafe_code)]

pub mod anchors;
pub mod cbor;
pub mod cose;
pub mod error;
pub mod json;
pub mod report;
pub mod schema;
pub mod validate;
pub mod value;

pub use anchors::{RoughtimeServerKey, TrustAnchors};
pub use cose::{check_signature, envelope_parts, open, open_with, AgentKey, Envelope};
pub use error::ReceiptError;
pub use report::{Bracket, EntryReport, Outcome, Verified};
pub use schema::{
    ppm_as_ppb, AgentClaim, BreakdownRecord, Evidence, Operators, Payload, PolicyRecord, Receipt,
    Role, Scheme, SourceRecord, TakenBy, CLAIM_KIND, FORMAT_VERSION, READS,
};
pub use validate::{validate, validate_shape, validate_with};
pub use value::Value;

/// The largest a signed receipt may be, in bytes.
///
/// A receipt carrying three real attestations is a little over three kilobytes, and the largest
/// single part of one, an RFC 3161 token with its certificate, is under two. Twenty times that
/// leaves room for a format that grows and refuses a file that is not a receipt at all. It is
/// checked before anything is decoded, because a reader must not have to parse a megabyte to find
/// out that it is a megabyte, and `docs/receipt-format-v0.md` states the same figure.
pub const MAX_ENCODED_BYTES: usize = 64 * 1024;

/// The SHA-256 of some bytes, as a payload record.
///
/// Here rather than in the caller so every receipt names the algorithm the same way.
#[must_use]
pub fn sha256_payload(bytes: &[u8]) -> Payload {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Payload {
        algorithm: "sha-256".to_string(),
        hash: hasher.finalize().to_vec(),
    }
}

/// The SHA-256 of a signed receipt, which is what the next receipt in a chain links back to.
#[must_use]
pub fn chain_link(signed_receipt: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(signed_receipt);
    hasher.finalize().to_vec()
}
