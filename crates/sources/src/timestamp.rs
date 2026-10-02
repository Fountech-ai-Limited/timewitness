//! The RFC 3161 client: post a hash, keep what came back.
//!
//! Every rule about what a token has to satisfy is in
//! [`timewitness_core::evidence::rfc3161`]. This file posts and stores.
//!
//! Four authorities were tried on 2026-09-07 and all four answered, free and with no account. Two
//! are built in, and [`published_authorities`] says what happened to the other two. A deployment
//! that wants more adds them, and `discover_pin` prints what it needs to add one.

use std::time::Duration;

use timewitness_core::evidence::rfc3161::{self, Authority};
use timewitness_core::Attestation;

use crate::{http, FinalWitness, SourceError};

/// How long to wait for an authority.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// The content type a timestamp request and its reply carry.
const REQUEST_TYPE: &str = "application/timestamp-query";

/// A client for one timestamp authority.
#[derive(Clone, Debug)]
pub struct TimestampClient {
    authority: Authority,
    timeout: Duration,
}

impl TimestampClient {
    /// A client for an authority.
    #[must_use]
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The authority this client asks.
    #[must_use]
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Ask an authority to put its name to having seen a hash, and check what comes back.
    ///
    /// The nonce is fresh from the operating system. Without one an authority could answer with a
    /// token it made earlier, and a not-later-than edge from a token made earlier is an edge in the
    /// wrong place.
    pub fn stamp(&self, subject_hash: &[u8; 32]) -> Result<Attestation, SourceError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| {
            SourceError::Transport(format!("this machine would not give us random bytes: {e}"))
        })?;

        let request = rfc3161::build_request(subject_hash, &nonce);
        let reply = http::post(&self.authority.url, REQUEST_TYPE, &request, self.timeout)?;
        let blob = rfc3161::pack_blob(&request, &reply);

        // `check` is `inspect` then `under`, so running the two apart runs exactly what running
        // them together runs. They are apart here because the instant that goes into the receipt
        // comes off the token alone and the signature check needs the pin.
        let inspected = rfc3161::inspect(&blob, subject_hash)
            .map_err(|e| SourceError::Malformed(e.to_string()))?;
        inspected
            .under(&self.authority)
            .map_err(|e| SourceError::Malformed(e.to_string()))?;

        // The instant stored is the latest the time the token writes can name, which is what the
        // token states and is the same for every reader. It is deliberately not the not-later-than
        // edge in UTC: that edge needs the authority's own account of its clock error, an authority
        // stating none supports no edge at all, and a reader's own allowance may not reach a value
        // every other reader has to agree with. Changed 2026-09-19.
        let at = inspected.stated_instant();
        Ok(Attestation::at_instant(nonce.to_vec(), blob, at))
    }

    /// Whether the authority claims its own tokens are ordered by the times they state.
    ///
    /// Worth putting in front of a person reading a receipt, because this product's claim is
    /// unbroken order and this is an authority speaking to it. It is that authority's account of
    /// its own practice and nothing here can check it, so the words that carry it say whose claim
    /// it is.
    pub fn orders_by_stated_time(&self, blob: &[u8]) -> Result<bool, SourceError> {
        rfc3161::orders_by_stated_time(blob).map_err(|e| SourceError::Malformed(e.to_string()))
    }

    /// What was checked, in words, for a caller that wants to report it.
    pub fn describe(&self, blob: &[u8], subject_hash: &[u8]) -> Result<Vec<String>, SourceError> {
        rfc3161::check(blob, &self.authority, subject_hash)
            .map(|c| c.checks)
            .map_err(|e| SourceError::Malformed(e.to_string()))
    }

    /// Ask an authority for a token and report which certificate signed it, without trusting it.
    ///
    /// **This is how a pin is chosen, not how one is checked.** Run it once against an authority
    /// you have decided to use, look at what it prints, satisfy yourself that the certificate is
    /// that authority's, and put the value in the [`Authority`]. Calling it at verification time
    /// would amount to trusting whatever key arrived.
    pub fn discover_pin(&self, subject_hash: &[u8; 32]) -> Result<[u8; 32], SourceError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|e| {
            SourceError::Transport(format!("this machine would not give us random bytes: {e}"))
        })?;
        let request = rfc3161::build_request(subject_hash, &nonce);
        let reply = http::post(&self.authority.url, REQUEST_TYPE, &request, self.timeout)?;
        let blob = rfc3161::pack_blob(&request, &reply);
        rfc3161::discover_signing_certificate(&blob)
            .map_err(|e| SourceError::Malformed(e.to_string()))
    }
}

impl FinalWitness for TimestampClient {
    fn name(&self) -> &str {
        &self.authority.name
    }

    fn scheme(&self) -> &'static str {
        rfc3161::SCHEME
    }

    fn witness(&self, subject_hash: &[u8]) -> Result<Attestation, SourceError> {
        let hash: [u8; 32] = subject_hash.try_into().map_err(|_| {
            SourceError::Malformed(format!(
                "a subject hash of {} bytes, and this client asks about a 32 byte one",
                subject_hash.len()
            ))
        })?;
        self.stamp(&hash)
    }
}

/// The authorities this client was proved against, with the certificate each signed with.
///
/// Four were tried on 2026-09-07 and all four answered, free and with no account. Two are here.
///
/// | Authority | Signed with | Certificates over four requests |
/// |---|---|---|
/// | DigiCert, `timestamp.digicert.com` | SHA-256 with RSA | one, the same every time |
/// | Sectigo, `timestamp.sectigo.com` | SHA-384 with RSA | one, the same every time |
/// | freetsa.org, `freetsa.org/tsr` | ECDSA with SHA-512 | not readable by this code |
/// | GlobalSign through ai.moda, `rfc3161.ai.moda` | SHA-384 with RSA | three different ones |
///
/// The two that are missing are missing for reasons worth stating rather than hiding. `freetsa.org`
/// signs with ECDSA, which this code does not implement and refuses by name rather than skipping.
/// `rfc3161.ai.moda` answered from three different signing certificates in four requests, one of
/// which was DigiCert's own, so it cannot be pinned to one certificate and using it beside DigiCert
/// would not be two independent witnesses anyway.
///
/// **The pin goes stale and that is a property rather than a fault.** These certificates expire and
/// will be replaced, and when they are, fetching a new token here starts failing loudly. Tokens
/// already inside receipts stay checkable, because the certificate travels inside the token.
/// Chaining to a root instead of pinning a leaf is the durable answer and is not built.
///
/// **None of these is a qualified trust service and none of these tokens carries legal weight.** A
/// timestamp from a free authority is a third party's signed statement about what it saw and when,
/// which is what the not-later-than role needs and is not a legal instrument.
/// The table itself is [`timewitness_core::evidence::rfc3161::published_authorities`], re-exported
/// here so a caller reaching for a client finds the authorities beside it. It lives in `core`
/// because a verifier needs the same pins and may not import this crate.
pub use timewitness_core::evidence::rfc3161::published_authorities;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_authority_has_a_pin_and_a_plain_address() {
        let all = published_authorities();
        assert_eq!(all.len(), 2);
        for authority in all {
            assert!(
                authority.url.starts_with("http://"),
                "{} is not a plain address",
                authority.name
            );
            assert!(
                !authority.accepted_certificates.is_empty(),
                "{} has no pinned certificate, so it would accept anything",
                authority.name
            );
        }
    }

    #[test]
    fn a_subject_hash_of_the_wrong_length_is_refused_before_anything_goes_out() {
        let client = TimestampClient::new(Authority {
            name: "nobody".to_string(),
            url: "http://127.0.0.1:1".to_string(),
            accepted_certificates: vec![[0u8; 32]],
            accuracy_where_the_token_states_none: None,
        });
        let err = client
            .witness(b"short")
            .expect_err("five bytes is not a SHA-256 hash");
        assert!(matches!(err, SourceError::Malformed(_)), "{err}");
    }

    #[test]
    fn an_authority_that_cannot_be_reached_says_so_rather_than_going_quiet() {
        let client = TimestampClient::new(Authority {
            name: "nobody".to_string(),
            url: "http://127.0.0.1:1".to_string(),
            accepted_certificates: vec![[0u8; 32]],
            accuracy_where_the_token_states_none: None,
        });
        let err = client
            .stamp(&[0u8; 32])
            .expect_err("a port nothing is listening on");
        assert!(matches!(err, SourceError::Transport(_)), "{err}");
    }
}
