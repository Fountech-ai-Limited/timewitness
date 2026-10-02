//! What crosses the boundary, and how a caller finds the agent to cross it.
//!
//! Two messages and no more. A client sends a token and nothing else, and gets back either a reading
//! or a refusal. Nothing is negotiated, there is no second request and there is no method to add one
//! to, because a protocol belongs to phase 2 and phase 2 has not started.
//!
//! A refusal comes in two shapes and both are refusals. Most carry a reason and nothing else. The one
//! where the model worked out a bound and found it past its ceiling carries that width and that
//! ceiling as numbers beside the reason, from 2026-09-24, because `timewitness status` has to say how
//! wrong the clock could be during the minutes a fresh agent spends above its ceiling, and reading a
//! number back out of a sentence is how a status breaks the day the sentence is reworded. Neither
//! shape decodes to anything a caller could sign.
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

use timewitness_clock::Policy;
use timewitness_core::time::Nanos;
use timewitness_core::Stamp;
use timewitness_receipt::schema::{ppm_as_ppb, PolicyRecord, Receipt, TakenBy, FORMAT_VERSION};
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
/// The same, for a refusal over a bound past the ceiling, whose body is the width and the ceiling as
/// sixteen bytes each, big-endian, and then the reason as text.
const A_REFUSAL_PAST_CEILING: u8 = 2;

/// The bytes the two figures on a refusal past the ceiling take up, ahead of the reason.
const PAST_CEILING_FIGURES: usize = 32;

/// The largest reply this will read, which is one carrier and its marker byte.
const MAX_REPLY_BYTES: usize = MAX_ENCODED_BYTES + 1;

/// Why a message could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireError {
    /// The reply was empty, truncated or longer than a reply can be.
    Malformed(String),
    /// The agent refused to give a reading, and this is what it said.
    Refused(String),
    /// The agent refused because the bound it worked out is wider than it will sign for, and said
    /// how wide.
    ///
    /// Still a refusal. The width is the model's own, at the moment it was asked, and it crosses so a
    /// person can be told how wrong the clock could be; nothing here turns it into a reading.
    PastCeiling {
        /// The width the model worked out, in nanoseconds.
        width: Nanos,
        /// The widest the agent will sign for, in nanoseconds.
        ceiling: Nanos,
        /// What the agent said, which is the same sentence a plain refusal would have carried.
        why: String,
    },
    /// The endpoint file was not there, or was not one.
    Endpoint(String),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Malformed(why) => write!(f, "the agent's answer could not be read: {why}"),
            WireError::Refused(why) | WireError::PastCeiling { why, .. } => {
                write!(f, "the agent would not give a reading: {why}")
            }
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
///
/// `taken_by` says which path the reading came by, and it is the caller's to say rather than the
/// answer's: a stamp reading a resident agent's answer writes `ResidentAgent` over whatever the
/// answer claimed, because the answer is whoever wrote the endpoint file.
#[must_use]
pub fn carrier(stamp: &Stamp, policy: PolicyRecord, taken_by: TakenBy) -> Receipt {
    Receipt::from_stamp(
        stamp,
        CARRIER_SEQUENCE,
        None,
        sha256_payload(&[]),
        Vec::new(),
        policy,
        taken_by,
    )
}

/// The parts of a policy a receipt carries, from the policy itself.
///
/// One function for both paths, so the resident agent and the one-shot stamp cannot come to state
/// different things about the same policy. Every limit and every width term is stated: the two
/// limits version 0 left out on its oldest receipts, and the three terms version 1 added.
#[must_use]
pub fn policy_record(policy: &Policy) -> PolicyRecord {
    PolicyRecord {
        max_bound_width: policy.max_bound_width,
        min_sources: policy.min_sources as u32,
        min_operators: Some(policy.min_operators as u32),
        max_holdover: Some(policy.max_holdover),
        source_interval_floor: Some(policy.source_interval_floor),
        frequency_slew_ppb_per_s: Some(ppm_as_ppb(policy.frequency_slew_ppm_per_second)),
        frequency_span_ppb: Some(ppm_as_ppb(policy.frequency_span_ppm)),
    }
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

/// A refusal over a bound past the ceiling, ready to send, carrying the width and the ceiling as
/// well as the reason.
#[must_use]
pub fn encode_refusal_past_ceiling(width: Nanos, ceiling: Nanos, why: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + PAST_CEILING_FIGURES + why.len());
    out.push(A_REFUSAL_PAST_CEILING);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&ceiling.to_be_bytes());
    out.extend_from_slice(why.as_bytes());
    out
}

/// Take a reply apart.
///
/// A refusal comes back as an error rather than as a value, because a caller that has to remember to
/// check a field is a caller that one day does not. There is no third case: either a reading was
/// given or a reason was.
///
/// The receipt format version crosses with the reading, and it is the whole of the negotiation: a
/// reading in any version other than the one this end writes is refused and named. The terms that set
/// the width are the answering agent's to state, because the policy that governed the bound is the
/// policy of the process that held the model, so an agent from an older build cannot have its reading
/// finished here. It is told to run from the same release rather than half read.
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
        Some((&A_REFUSAL_PAST_CEILING, rest)) => {
            if rest.len() < PAST_CEILING_FIGURES {
                return Err(WireError::Malformed(format!(
                    "a refusal past the ceiling carries {PAST_CEILING_FIGURES} bytes of figures and \
                     this one carries {}",
                    rest.len()
                )));
            }
            let (figures, why) = rest.split_at(PAST_CEILING_FIGURES);
            let mut width = [0u8; 16];
            let mut ceiling = [0u8; 16];
            width.copy_from_slice(&figures[..16]);
            ceiling.copy_from_slice(&figures[16..]);
            let (width, ceiling) = (Nanos::from_be_bytes(width), Nanos::from_be_bytes(ceiling));
            // A refusal past the ceiling whose width is not past a positive ceiling says two things
            // at once, and a status would print both. Read it as the malformed answer it is.
            if ceiling <= 0 || width <= ceiling {
                return Err(WireError::Malformed(format!(
                    "a refusal past the ceiling gave a width of {width} ns against a ceiling of \
                     {ceiling} ns, which is not past it"
                )));
            }
            Err(WireError::PastCeiling {
                width,
                ceiling,
                why: String::from_utf8_lossy(why).into_owned(),
            })
        }
        Some((&A_READING, rest)) => {
            let value = cbor::decode(rest).map_err(|e| WireError::Malformed(format!("{e}")))?;
            let carrier =
                Receipt::from_value(&value).map_err(|e| WireError::Malformed(format!("{e}")))?;
            if carrier.version != FORMAT_VERSION {
                return Err(WireError::Malformed(format!(
                    "the agent answered in receipt format v{} and this end writes v{FORMAT_VERSION}. \
                     The terms that set the width are the agent's to state, so run the agent from \
                     the same release as this command",
                    carrier.version
                )));
            }
            Ok(carrier)
        }
        Some((other, _)) => Err(WireError::Malformed(format!(
            "a reply starts with {A_READING}, {A_REFUSAL} or {A_REFUSAL_PAST_CEILING} and this one \
             starts with {other}"
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
    fn a_refusal_past_the_ceiling_carries_its_width_and_is_still_a_refusal() {
        let why =
            "the bound has grown to 1203.645 ms, past the 250 ms ceiling this model will sign for";
        let bytes = encode_refusal_past_ceiling(1_203_645_522, 250_000_000, why);
        match decode_reply(&bytes) {
            Err(WireError::PastCeiling {
                width,
                ceiling,
                why: said,
            }) => {
                assert_eq!(width, 1_203_645_522);
                assert_eq!(ceiling, 250_000_000);
                assert_eq!(said, why);
            }
            other => panic!("a refusal past the ceiling should not decode to {other:?}"),
        }
        // Said the way any other refusal is said, so a stamp refused this way reads as it did.
        let err = decode_reply(&bytes).expect_err("a refusal");
        assert_eq!(
            format!("{err}"),
            format!("the agent would not give a reading: {why}")
        );
        // A width that saturated on the way to the ceiling crosses whole rather than wrapping.
        let widest = encode_refusal_past_ceiling(i128::MAX, 250_000_000, "");
        assert!(matches!(
            decode_reply(&widest),
            Err(WireError::PastCeiling {
                width: i128::MAX,
                ..
            })
        ));
    }

    #[test]
    fn a_refusal_past_the_ceiling_that_is_not_past_it_is_malformed() {
        for (width, ceiling) in [(250, 250), (100, 250), (-5, 250), (5, 0), (5, -1)] {
            assert!(
                matches!(
                    decode_reply(&encode_refusal_past_ceiling(width, ceiling, "why")),
                    Err(WireError::Malformed(_))
                ),
                "{width} against {ceiling}"
            );
        }
    }

    #[test]
    fn a_refusal_past_the_ceiling_cut_short_is_malformed_rather_than_padded() {
        let bytes = encode_refusal_past_ceiling(1, 2, "why");
        for cut in 1..=PAST_CEILING_FIGURES {
            assert!(
                matches!(decode_reply(&bytes[..cut]), Err(WireError::Malformed(_))),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_reading_in_an_older_format_is_refused_and_says_what_to_run() {
        // What an agent from the release before version 1 sends: a carrier in version 0, which states
        // no width terms, no unclaimed part and no path.
        let stamp = timewitness_core::Stamp {
            reading: timewitness_core::Reading {
                monotonic: timewitness_core::MonotonicNanos(1),
                utc_estimate: timewitness_core::UnixNanos(1_788_800_000_000_000_000),
            },
            bound: timewitness_core::Bound {
                earliest: timewitness_core::UnixNanos(1_788_800_000_000_000_000 - 1_000),
                latest: timewitness_core::UnixNanos(1_788_800_000_000_000_000 + 1_000),
                basis: timewitness_core::EpsilonBasis::LocalModelOnly,
                breakdown: timewitness_core::BoundBreakdown {
                    fusion: timewitness_core::FusionRule::MarzulloThenInverseSquare {
                        offered: 0,
                        kept: 0,
                    },
                    intersection_half: 1_000,
                    widest_source_network_half: 0,
                    scheduling: 0,
                    oscillator_holdover: 0,
                    unclaimed_rate: 0,
                    model_residual: 0,
                    safety_margin: 0,
                },
            },
            sources: Vec::new(),
            generations: timewitness_core::Generations { boot: 0, resume: 0 },
            since_last_sync: 0,
            frequency_ppm: None,
        };
        let mut older = carrier(
            &stamp,
            policy_record(&Policy::default()),
            TakenBy::ResidentAgent,
        );
        older.version = 0;
        older.claim.taken_by = None;
        older.claim.breakdown.unclaimed_rate = None;
        older.claim.policy.source_interval_floor = None;
        older.claim.policy.frequency_slew_ppb_per_s = None;
        older.claim.policy.frequency_span_ppb = None;
        match decode_reply(&encode_reading(&older)) {
            Err(WireError::Malformed(why)) => {
                assert!(why.contains("receipt format v0"), "{why}");
                assert!(why.contains("same release"), "{why}");
            }
            other => panic!("an older agent's reading should be refused, not {other:?}"),
        }
        // And the reading this end's own agent sends is taken.
        let current = carrier(
            &stamp,
            policy_record(&Policy::default()),
            TakenBy::ResidentAgent,
        );
        assert!(decode_reply(&encode_reading(&current)).is_ok());
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
