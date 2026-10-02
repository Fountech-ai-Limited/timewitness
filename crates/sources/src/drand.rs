//! The drand client: fetch a round, check it, refuse a stale one.
//!
//! The pairing check is in [`timewitness_core::evidence::drand`], for the reason every check in
//! this product is over there: a stranger's verifier applies the same rules to the same bytes.
//!
//! What is here is the fetch and one judgement the verifier cannot make, which is whether the round
//! we were handed is the current one. A relay that answers with a round from last Tuesday is
//! answering honestly, in the sense that the signature checks: the round really was published then.
//! It is still useless as evidence, because a not-earlier-than edge a week behind the reading pins
//! nothing anybody cares about. So the client says what round it expected and refuses one too far
//! from it, and it says out loud which clock that expectation came from.

use std::time::Duration;

use timewitness_core::evidence::drand::{self, Chain};
use timewitness_core::time::{Nanos, NANOS_PER_SEC};
use timewitness_core::{Attestation, UnixNanos};

use crate::{http, FreshnessBeacon, SourceError};

/// How long to wait for a relay.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);

/// How far from the expected round a fetched one may be before it is refused.
///
/// Five minutes, on a chain whose rounds are three seconds apart, so a hundred rounds of slack. It
/// is generous on purpose: the expectation comes from the agent's own model and the point of this
/// check is to catch a relay that is hours or days behind, not to police a second.
pub const DEFAULT_STALENESS: Nanos = 300 * NANOS_PER_SEC;

/// A client for one drand chain, over one or more relays.
#[derive(Clone, Debug)]
pub struct DrandClient {
    chain: Chain,
    relays: Vec<String>,
    timeout: Duration,
}

impl DrandClient {
    /// The chain and relays this client was built and proved against.
    ///
    /// Three relays, and they are three ways to reach one chain rather than three beacons. Fetching
    /// from more than one is about a relay being down or behind, and it is not independence: every
    /// one of them serves rounds signed by the same group key, so a compromise of that key is not
    /// something more relays would catch.
    #[must_use]
    pub fn quicknet() -> Self {
        Self {
            chain: Chain::quicknet(),
            relays: vec![
                "http://api.drand.sh".to_string(),
                "http://api2.drand.sh".to_string(),
                "http://api3.drand.sh".to_string(),
            ],
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The relays this client will ask, in the order it asks them.
    ///
    /// Readable so the document listing what a host has to reach is held to the list the client
    /// actually carries.
    #[must_use]
    pub fn relays(&self) -> &[String] {
        &self.relays
    }

    /// The same client with a different set of relays.
    #[must_use]
    pub fn from_relays(mut self, relays: Vec<String>) -> Self {
        self.relays = relays;
        self
    }

    /// The chain this client speaks for.
    #[must_use]
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    fn chain_hash_hex(&self) -> String {
        self.chain.hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Fetch one round from whichever relay answers first, and check it.
    ///
    /// The round number is decided here rather than by the relay wherever the caller knows what it
    /// wants, because "give me the latest" is a question whose answer the caller cannot check.
    pub fn round(&self, round: u64) -> Result<Attestation, SourceError> {
        let path = format!("/{}/public/{round}", self.chain_hash_hex());
        let mut last: Option<SourceError> = None;
        for relay in &self.relays {
            match self.fetch_and_check(&format!("{relay}{path}"), Some(round)) {
                Ok(a) => return Ok(a),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| SourceError::Transport("no relay was configured".to_string())))
    }

    /// Fetch whatever the relay calls the latest round, and refuse it if it is not near the round
    /// the caller expected.
    ///
    /// `expected` comes from the agent's own model of UTC. That is the honest source for it: the
    /// machine has no other idea of the time, and if the model is wrong then the corridor evidence
    /// is what catches that, not this. The tolerance is the width of the disagreement this is
    /// willing to put down to a relay lagging.
    pub fn latest_near(
        &self,
        expected: UnixNanos,
        tolerance: Nanos,
    ) -> Result<Attestation, SourceError> {
        let path = format!("/{}/public/latest", self.chain_hash_hex());
        let mut last: Option<SourceError> = None;
        for relay in &self.relays {
            match self.fetch_and_check(&format!("{relay}{path}"), None) {
                Ok(attestation) => {
                    let drift = attestation.at.as_nanos() - expected.as_nanos();
                    if drift > tolerance {
                        last = Some(SourceError::Malformed(format!(
                            "{relay} answered with a round dated {} s after the time this agent \
                             believes it is, which is further ahead than a relay lag explains",
                            drift / NANOS_PER_SEC
                        )));
                        continue;
                    }
                    if -drift > tolerance {
                        last = Some(SourceError::Malformed(format!(
                            "{relay} answered with a round {} s old, and a not-earlier-than edge \
                             that far behind the reading pins nothing",
                            -drift / NANOS_PER_SEC
                        )));
                        continue;
                    }
                    return Ok(attestation);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| SourceError::Transport("no relay was configured".to_string())))
    }

    fn fetch_and_check(
        &self,
        url: &str,
        expected_round: Option<u64>,
    ) -> Result<Attestation, SourceError> {
        let body = http::get(url, self.timeout)?;
        let round: u64 = http::json_field(&body, "round")
            .ok_or_else(|| SourceError::Malformed(format!("{url} answered with no round")))?
            .parse()
            .map_err(|_| {
                SourceError::Malformed(format!("{url} answered with an unreadable round"))
            })?;
        if let Some(wanted) = expected_round {
            if round != wanted {
                return Err(SourceError::Malformed(format!(
                    "{url} was asked for round {wanted} and answered with {round}"
                )));
            }
        }
        let signature_hex = http::json_field(&body, "signature")
            .ok_or_else(|| SourceError::Malformed(format!("{url} answered with no signature")))?;
        let signature = unhex(&signature_hex).ok_or_else(|| {
            SourceError::Malformed(format!("{url} answered with a signature that is not hex"))
        })?;

        let blob = drand::pack_blob(&self.chain.hash, round, &signature);
        let checked =
            drand::check(&blob, &self.chain).map_err(|e| SourceError::Malformed(e.to_string()))?;

        // A round falls at one instant on the chain's published schedule, so a checked round with
        // no instant in it is malformed rather than a beacon that declined to say.
        let at = checked.earliest().ok_or_else(|| {
            SourceError::Malformed(format!(
                "{url} answered with a round that falls at no moment"
            ))
        })?;
        Ok(Attestation::at_instant(Vec::new(), blob, at))
    }

    /// What was checked, in words, for a caller that wants to report it.
    pub fn describe(&self, blob: &[u8]) -> Result<Vec<String>, SourceError> {
        drand::check(blob, &self.chain)
            .map(|c| c.checks)
            .map_err(|e| SourceError::Malformed(e.to_string()))
    }
}

impl FreshnessBeacon for DrandClient {
    fn name(&self) -> &str {
        self.chain.name
    }

    fn scheme(&self) -> &'static str {
        drand::SCHEME
    }

    fn fetch_near(
        &self,
        expected: UnixNanos,
        tolerance: Nanos,
    ) -> Result<Attestation, SourceError> {
        self.latest_near(expected, tolerance)
    }
}

/// A hex string as the bytes it names, or nothing at all.
///
/// It works over bytes rather than over characters, and that is the point of it. The length of a
/// `str` is in bytes and its slice boundaries are in characters, so a reader that checks the length
/// and slices by index is checking one thing and relying on another. One accented character in a
/// signature field was enough: "end byte index 2 is not a char boundary", in debug and in release
/// alike, from a field a drand relay chose and nobody had signed yet.
///
/// Nothing here indexes anything. A byte that is not a hex digit is a byte that is not a hex digit,
/// whether it is part of a character or not.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

/// One hex digit as the value it stands for.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_that_is_not_hex_is_refused_rather_than_half_read() {
        assert_eq!(unhex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex(""), None);
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn the_client_names_the_chain_it_speaks_for() {
        let client = DrandClient::quicknet();
        assert_eq!(client.name(), "drand quicknet");
        assert_eq!(client.scheme(), "drand");
        assert_eq!(client.chain_hash_hex().len(), 64);
    }

    #[test]
    fn a_relay_that_cannot_be_reached_produces_the_reason_rather_than_a_silence() {
        // Nothing listens here, so this exercises the path where every relay fails.
        let client = DrandClient::quicknet().from_relays(vec!["http://127.0.0.1:1".to_string()]);
        let err = client
            .round(1)
            .expect_err("a round from a port nothing is listening on");
        assert!(matches!(err, SourceError::Transport(_)), "{err}");
    }

    #[test]
    fn hex_with_a_character_that_is_not_ascii_is_refused_rather_than_panicking() {
        // One non-ASCII character anywhere in a signature field. The slice was taken by byte offset
        // with the length checked and the character boundaries not, so this said "end byte index 2
        // is not a char boundary", in debug and in release alike.
        assert_eq!(unhex("0\u{e9}0"), None);
        assert_eq!(unhex("\u{e9}\u{e9}"), None);
        assert_eq!(unhex("00\u{e9}"), None);
        assert_eq!(unhex("\u{1f600}"), None);
        assert_eq!(unhex("ab\u{e9}cd"), None);
    }

    #[test]
    fn no_run_of_random_text_makes_the_hex_reader_panic() {
        // Seeded, in the tree, and a floor rather than a proof, the same as the chunk reader's.
        let mut seed = 0xc0ff_ee12_3456_789au64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet: Vec<char> = "0123456789abcdefABCDEF\u{e9}\u{4e2d}\u{1f600} -\n\0"
            .chars()
            .collect();
        for _ in 0..200_000 {
            let len = (next() % 24) as usize;
            let text: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            let _ = unhex(&text);
        }
    }
}
