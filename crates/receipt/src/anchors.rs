//! What a verifier decided to trust before it read anything.
//!
//! This is the whole of the trust in the product, gathered in one type so that it can be looked at.
//! A Roughtime server's long-term key, a drand chain's group key, a timestamp authority's signing
//! certificate: three things, chosen in advance, against which a receipt's evidence is checked.
//! Nothing else is trusted, and in particular nothing a receipt says about itself is.
//!
//! **An empty set is a legitimate state and it is the default.** A verifier holding no anchors can
//! still check a receipt's own signature and every arithmetic claim it makes about itself. What it
//! cannot do is grant the receipt a bound resting on third-party evidence, because it has nothing to
//! check that evidence against. It says so, entry by entry, rather than passing quietly.
//!
//! **Anchors are not a chain to a root.** Each one names a specific key or certificate rather than
//! an authority allowed to issue many. That is a narrower statement than trusted and it is the
//! honest one for what this code actually does. Chaining a timestamp authority's certificate to a
//! commercial root is a different piece of work and is not built.

use timewitness_core::evidence::drand::Chain;
use timewitness_core::evidence::rfc3161::Authority;

/// A Roughtime server, and the key its answers are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoughtimeServerKey {
    /// A name for a person reading the verifier's output.
    pub name: String,
    /// The server's published long-term key.
    pub long_term_public_key: [u8; 32],
}

/// A key that signs the head of our key log, and the name a reader knows it by.
///
/// The one anchor that is ours rather than a third party's, and it is kept apart from the three
/// evidence kinds for that reason. It supports no evidence role and never carries a receipt: what
/// it decides is whether a key log in front of the reader is one we signed, so that the step `is
/// that key one of ours` is answered off our list and not off anybody's. A reader who holds no key
/// here gets that step unanswered for every log, which is what a reader holding no key knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogSigner {
    /// A name for a person reading the verifier's output.
    pub name: String,
    /// The Ed25519 key a head has to be signed by.
    pub public_key: [u8; 32],
}

/// Everything a verifier is prepared to trust, before it reads a receipt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    /// Roughtime servers whose signatures may support the corridor role.
    pub roughtime_servers: Vec<RoughtimeServerKey>,
    /// drand chains whose rounds may support the not-earlier-than role.
    pub drand_chains: Vec<Chain>,
    /// Timestamp authorities whose tokens may support the not-later-than role.
    pub timestamp_authorities: Vec<Authority>,
    /// Keys a key log's head may be signed by for the log to count as ours.
    pub key_log_signers: Vec<KeyLogSigner>,
}

impl TrustAnchors {
    /// Nothing trusted at all.
    ///
    /// A receipt read against this can be checked for everything except what its evidence says,
    /// which is reported as unchecked rather than assumed.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether anything at all is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roughtime_servers.is_empty()
            && self.drand_chains.is_empty()
            && self.timestamp_authorities.is_empty()
    }

    /// Add a Roughtime server.
    #[must_use]
    pub fn with_roughtime(mut self, name: impl Into<String>, key: [u8; 32]) -> Self {
        self.roughtime_servers.push(RoughtimeServerKey {
            name: name.into(),
            long_term_public_key: key,
        });
        self
    }

    /// Add a drand chain.
    #[must_use]
    pub fn with_drand(mut self, chain: Chain) -> Self {
        self.drand_chains.push(chain);
        self
    }

    /// Add a timestamp authority.
    #[must_use]
    pub fn with_authority(mut self, authority: Authority) -> Self {
        self.timestamp_authorities.push(authority);
        self
    }

    /// Add a key our key log's head may be signed by.
    #[must_use]
    pub fn with_key_log_signer(mut self, name: impl Into<String>, key: [u8; 32]) -> Self {
        self.key_log_signers.push(KeyLogSigner {
            name: name.into(),
            public_key: key,
        });
        self
    }

    /// The keys a key log's head may be signed by, as bytes, for the check that reads them.
    #[must_use]
    pub fn key_log_signer_keys(&self) -> Vec<[u8; 32]> {
        self.key_log_signers
            .iter()
            .map(|signer| signer.public_key)
            .collect()
    }

    /// How many pieces of third-party trust material are held, for a verifier reporting what it
    /// checked evidence against.
    ///
    /// The key log signer is not counted. It is ours, it supports no evidence entry, and a reader
    /// comparing this figure with the entries checked would be counting a key that checks none of
    /// them.
    #[must_use]
    pub fn count(&self) -> usize {
        self.roughtime_servers.len() + self.drand_chains.len() + self.timestamp_authorities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_trusted_by_default() {
        let anchors = TrustAnchors::none();
        assert!(anchors.is_empty());
        assert_eq!(anchors.count(), 0);
    }

    #[test]
    fn anchors_accumulate_and_are_counted() {
        let anchors = TrustAnchors::none()
            .with_roughtime("somewhere", [1u8; 32])
            .with_drand(Chain::quicknet());
        assert!(!anchors.is_empty());
        assert_eq!(anchors.count(), 2);
    }

    #[test]
    fn the_key_log_signer_is_held_and_is_not_counted_as_evidence_material() {
        let anchors = TrustAnchors::none().with_key_log_signer("ours", [9u8; 32]);
        assert_eq!(anchors.key_log_signer_keys(), vec![[9u8; 32]]);
        assert_eq!(
            anchors.count(),
            0,
            "our own key checks no evidence entry and is not counted beside them"
        );
    }
}
