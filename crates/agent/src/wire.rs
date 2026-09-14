//! What crosses the boundary, and how a caller finds the agent to cross it.
//!
//! Two messages and no more. A client sends a token and nothing else, and gets back either a reading
//! or a refusal. Nothing is negotiated, there is no second request and there is no method to add one
//! to, because a protocol belongs to phase 2 and phase 2 has not started.
//!
//! ## The reading is carried as a receipt, on purpose
//!
//! The obvious thing to write here was a second wire format for a [`Stamp`]. That would have been a
//! second encoder, a second decoder and a second set of rules about what a field may hold, none of
//! it exercised by anything a stranger runs.
//!
//! So a reading crosses as an unsigned receipt in the frozen receipt format instead. It carries the
//! reading, the whole bound with its breakdown, every source's state, the generations and the age of
//! the synchronisation, which is all of what the reading is, and it carries the agent's own policy
//! beside them. The encoder and the decoder are the ones a consumer's verifier runs on every receipt
//! it is ever shown, so this boundary is covered by the tamper battery and the decoder fuzzing
//! already in the tree rather than by tests written for it alone.
//!
//! Three fields on the carrier are placeholders and the client replaces every one: the payload,
//! which the agent never sees and has no business seeing; the sequence and chain link, which belong
//! to whoever is keeping the chain; and the public key, because the agent does not sign and the
//! caller does. [`CARRIER_SEQUENCE`] and [`carrier`] name them where a reader will find them.
//!
//! ## The endpoint file, and what it is and is not
//!
//! The agent listens on a loopback port the operating system chooses and writes the address and a
//! random token to a file only its owner may read. A caller reads that file and presents the token.
//!
//! That is an ownership check and not an authentication protocol, and the difference is worth
//! writing down. It stops another account on the same machine asking this agent for readings. It
//! does nothing at all against something already running as the same user, which could read the file
//! itself.
//!
//! ## What somebody who can write the endpoint file gets, which is more than reading one
//!
//! This paragraph said until 2026-09-10 that an attacker at that level gains the ability to learn
//! what time the model thinks it is. That was a statement about reading the file and it left out the
//! writing, which is the half that matters. The whole of what a caller trusts is in the file: the
//! address it connects to and the token it presents. Whoever writes it chooses which process
//! answers.
//!
//! So the party who answers dictates the reading, the width, the breakdown, the source list and the
//! policy, and the caller signs all of it with its own key. The agent hands out readings rather than
//! signatures and the caller supplies the signature, which means the attacker does not need one:
//! they get a receipt signed by the real key over a time they chose. That is not learning what the
//! model thinks. It is writing what the model is taken to have said.
//!
//! Two things stand between that and a receipt a stranger believes, and neither is this file.
//!
//! The first is third-party evidence, which is the default and is the one that actually holds. An
//! authenticated corridor is gathered by the caller from servers the attacker does not answer for,
//! and a receipt whose claim does not overlap its corridor is refused by the verifier. A forgery
//! three hours out was caught that way on 2026-09-10 and it was caught twice, once by the beacon at
//! gathering time and once by the verifier.
//!
//! The second is [`crate::crossing::WhatTheCallerKnows`], which is a sanity check and is on the
//! `--no-evidence` path where there is no corridor to fall back on. It is not authentication, it
//! proves nothing, and the clock it rests on is the one this whole product exists because nobody
//! should trust. It refuses a wild answer and it would not notice a careful one.

use std::fs;
use std::path::Path;

use timewitness_core::Stamp;
use timewitness_receipt::schema::{PolicyRecord, Receipt};
use timewitness_receipt::{cbor, sha256_payload, MAX_ENCODED_BYTES};

/// How many bytes of token a caller presents.
pub const TOKEN_BYTES: usize = 32;

/// The sequence number on a carrier, which is never a receipt's own sequence.
///
/// Zero, because a chain starts at one. A carrier that reached a verifier by mistake would be
/// refused rather than read as the first receipt of a chain.
pub const CARRIER_SEQUENCE: u64 = 0;

/// The first byte of a reply, saying which of the two things follows.
const A_READING: u8 = 1;
/// The same, for a refusal, whose body is the reason as text.
const A_REFUSAL: u8 = 0;

/// The largest reply this will read, which is one carrier and its marker byte.
const MAX_REPLY_BYTES: usize = MAX_ENCODED_BYTES + 1;

/// Why a message could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The reply was empty, truncated or longer than a reply can be.
    Malformed(String),
    /// The agent refused to give a reading, and this is what it said.
    Refused(String),
    /// The endpoint file was not there, or was not one.
    Endpoint(String),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Malformed(why) => write!(f, "the agent's answer could not be read: {why}"),
            WireError::Refused(why) => write!(f, "the agent would not give a reading: {why}"),
            WireError::Endpoint(why) => write!(f, "{why}"),
        }
    }
}

/// Where an agent is listening, and the token that says a caller may ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The loopback address, as `127.0.0.1:port`.
    pub address: String,
    /// The token a caller presents, which is the whole of the check.
    pub token: [u8; TOKEN_BYTES],
}

impl Endpoint {
    /// An endpoint at `address` with a token nobody has seen.
    pub fn fresh(address: impl Into<String>) -> Result<Self, WireError> {
        let mut token = [0u8; TOKEN_BYTES];
        getrandom::getrandom(&mut token).map_err(|e| {
            WireError::Endpoint(format!("this machine would not give us random bytes: {e}"))
        })?;
        Ok(Self {
            address: address.into(),
            token,
        })
    }

    /// Write it where a caller will look, readable by its owner and nobody else.
    ///
    /// The permission goes on at creation rather than after the write, so there is no window with
    /// the token on disk and the world able to read it. This is the same argument, and the same
    /// shape, as the one on the agent's private key. On a platform with no mode bits the file
    /// inherits what the directory gives it, which is stated here rather than left to be found out.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }
        // Not `create_new`. An agent that was killed leaves its file behind and the next one has to
        // be able to start, which is the opposite of the key file, where writing over one would
        // orphan every receipt it ever signed. There is nothing here that cannot be made again.
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(self.as_text().as_bytes())?;
        file.sync_all()
    }

    /// Read one back.
    pub fn read(path: &Path) -> Result<Self, WireError> {
        let text = fs::read_to_string(path).map_err(|e| {
            WireError::Endpoint(format!(
                "{} could not be read, so there is no agent to ask: {e}",
                path.display()
            ))
        })?;
        Self::parse(&text)
    }

    /// The two lines a caller reads.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut hex = String::with_capacity(TOKEN_BYTES * 2);
        for b in self.token {
            hex.push_str(&format!("{b:02x}"));
        }
        format!("{}\n{}\n", self.address, hex)
    }

    /// The same, back again.
    pub fn parse(text: &str) -> Result<Self, WireError> {
        let mut lines = text.lines();
        let address = lines
            .next()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                WireError::Endpoint("that file has no address on its first line".into())
            })?
            .to_string();
        let hex = lines.next().map(str::trim).unwrap_or_default();
        if hex.len() != TOKEN_BYTES * 2 {
            return Err(WireError::Endpoint(format!(
                "that file's token is {} characters and a token is {}",
                hex.len(),
                TOKEN_BYTES * 2
            )));
        }
        let mut token = [0u8; TOKEN_BYTES];
        for (i, slot) in token.iter_mut().enumerate() {
            let pair = &hex[i * 2..i * 2 + 2];
            *slot = u8::from_str_radix(pair, 16)
                .map_err(|_| WireError::Endpoint("that file's token is not hexadecimal".into()))?;
        }
        Ok(Self { address, token })
    }
}

/// Whether two tokens are the same, without saying how far a wrong one got.
///
/// A comparison that stops at the first byte that differs tells whoever is guessing how much of
/// their guess was right, one byte at a time, and a token guessed a byte at a time is a token in a
/// few thousand tries rather than never. This one always reads all of it.
#[must_use]
pub fn tokens_match(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut differences = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        differences |= x ^ y;
    }
    differences == 0
}

/// A reading, in the shape it crosses in.
///
/// The payload is the hash of nothing rather than a hash of something, because the agent is not told
/// what is being stamped and does not want to be. The caller replaces it with the real one. The
/// public key is empty for the same kind of reason: the agent does not sign.
#[must_use]
pub fn carrier(stamp: &Stamp, policy: PolicyRecord) -> Receipt {
    Receipt::from_stamp(
        stamp,
        CARRIER_SEQUENCE,
        None,
        sha256_payload(&[]),
        Vec::new(),
        policy,
    )
}

/// A reading, ready to send.
#[must_use]
pub fn encode_reading(carrier: &Receipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(1_024);
    out.push(A_READING);
    out.extend_from_slice(&cbor::encode(&carrier.to_value()));
    out
}

/// A refusal, ready to send, carrying the reason a person reads.
#[must_use]
pub fn encode_refusal(why: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(why.len() + 1);
    out.push(A_REFUSAL);
    out.extend_from_slice(why.as_bytes());
    out
}

/// Take a reply apart.
///
/// A refusal comes back as an error rather than as a value, because a caller that has to remember to
/// check a field is a caller that one day does not. There is no third case: either a reading was
/// given or a reason was.
pub fn decode_reply(bytes: &[u8]) -> Result<Receipt, WireError> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(WireError::Malformed(format!(
            "{} bytes came back and a reply is at most {MAX_REPLY_BYTES}",
            bytes.len()
        )));
    }
    match bytes.split_first() {
        None => Err(WireError::Malformed("nothing came back".into())),
        Some((&A_REFUSAL, rest)) => Err(WireError::Refused(
            String::from_utf8_lossy(rest).into_owned(),
        )),
        Some((&A_READING, rest)) => {
            let value = cbor::decode(rest).map_err(|e| WireError::Malformed(format!("{e}")))?;
            Receipt::from_value(&value).map_err(|e| WireError::Malformed(format!("{e}")))
        }
        Some((other, _)) => Err(WireError::Malformed(format!(
            "a reply starts with {A_READING} or {A_REFUSAL} and this one starts with {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_survives_being_written_down_and_read_back() {
        let mut endpoint = Endpoint::fresh("127.0.0.1:9").expect("random bytes");
        endpoint.token[0] = 0;
        endpoint.token[TOKEN_BYTES - 1] = 255;
        let text = endpoint.as_text();
        assert_eq!(Endpoint::parse(&text).expect("a parse"), endpoint);
    }

    #[test]
    fn two_agents_do_not_get_the_same_token() {
        let a = Endpoint::fresh("127.0.0.1:1").expect("random bytes");
        let b = Endpoint::fresh("127.0.0.1:2").expect("random bytes");
        assert_ne!(a.token, b.token);
    }

    #[test]
    fn a_truncated_endpoint_file_is_refused_rather_than_padded() {
        assert!(Endpoint::parse("127.0.0.1:9\nbeef\n").is_err());
        assert!(Endpoint::parse("127.0.0.1:9\n").is_err());
        assert!(Endpoint::parse("").is_err());
        assert!(Endpoint::parse(&"zz".repeat(TOKEN_BYTES)).is_err());
    }

    #[test]
    fn a_token_that_differs_anywhere_does_not_match() {
        let a = [7u8; TOKEN_BYTES];
        let mut b = a;
        assert!(tokens_match(&a, &b));
        for i in 0..TOKEN_BYTES {
            b = a;
            b[i] ^= 1;
            assert!(!tokens_match(&a, &b), "byte {i} was not compared");
        }
        assert!(!tokens_match(&a, &a[..TOKEN_BYTES - 1]));
    }

    #[test]
    fn a_refusal_comes_back_as_an_error_and_not_as_a_value() {
        let bytes = encode_refusal("the model has never synchronised");
        match decode_reply(&bytes) {
            Err(WireError::Refused(why)) => assert_eq!(why, "the model has never synchronised"),
            other => panic!("a refusal should not decode to {other:?}"),
        }
    }

    #[test]
    fn a_reply_this_does_not_recognise_is_refused_rather_than_guessed_at() {
        assert!(matches!(decode_reply(&[]), Err(WireError::Malformed(_))));
        assert!(matches!(
            decode_reply(&[9, 1, 2, 3]),
            Err(WireError::Malformed(_))
        ));
        assert!(matches!(
            decode_reply(&[A_READING, 0xff]),
            Err(WireError::Malformed(_))
        ));
        assert!(matches!(
            decode_reply(&vec![A_READING; MAX_REPLY_BYTES + 1]),
            Err(WireError::Malformed(_))
        ));
    }
}
