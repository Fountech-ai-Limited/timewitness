//! The countersign wire form: what travels in an `X-Bounded-Time` header or on an MCP tool call.
//!
//! Two agents each say what their own clock was doing, sign it, and hand it to the other. Either
//! side can then show a stranger what was sent and what was received, in what order, and inside
//! what interval, and neither can be contradicted by the other's clock.
//!
//! This module is the shape on the wire and nothing else. It does not sign, it does not verify a
//! signature, and it does not decide an order. Those are separate pieces and they are built on top
//! of this one.
//!
//! ## What a stranger gets from one of these, said before the format
//!
//! Two parties who each hold a key each signed a statement about their own clock, and the two
//! statements are consistent with an ordering. That is the whole of it. **Neither party's interval
//! is third-party evidence for the other**, whatever the two of them agree between themselves, and
//! an exchange never becomes evidence by being countersigned. The third-party evidence lives in the
//! receipt each side's claim came from, which this form names by hash and does not carry.
//!
//! ## Why it names the receipt rather than carrying it
//!
//! Measured rather than assumed: the committed real receipt in this repository is 9,765 bytes, and
//! base64url of that is 13,020 characters. Common servers refuse a single header line at 8 KB and a
//! request's whole header block at 8 to 16 KB, so a receipt with its attestations in it cannot go in
//! a header at all. Putting it there anyway would mean the protocol worked on a test rig and was
//! dropped by the first load balancer in front of a real service.
//!
//! So what travels is the claim, the hashes that bind it to a payload and to a receipt, and the key
//! that signs it. A holder of the full receipt ties the two together by hashing it. A holder of only
//! the exchange has the ordering argument and knows it has nothing else, because the format gives it
//! nowhere to pretend otherwise.
//!
//! ## The form
//!
//! ```text
//! X-Bounded-Time: tw1.<base64url, no padding, of deterministic CBOR>
//! ```
//!
//! The `tw1.` prefix is readable without decoding anything, so a receiver refuses a version it does
//! not know before it parses a byte. That is the same rule receipt format v0 applies to its own
//! version field, and for the same reason: a reader that guesses at fields it has not been taught
//! about is a reader that will one day guess wrong about a bound.
//!
//! ## What a receiver does with one it cannot parse
//!
//! It carries on. Nothing here enforces anything: a request with an unreadable `X-Bounded-Time` is
//! the same request it would have been with no header at all, and what the receiver records is that
//! no exchange happened and why. A receiver that failed the request would be enforcing, which this
//! product does not do and does not claim to.

#![forbid(unsafe_code)]

use timewitness_receipt::cbor;
use timewitness_receipt::Value;

pub mod base64url;
pub mod countersigned;
pub mod signed;

pub use countersigned::{Countersigned, Ordering};
pub use signed::Signed;

/// The prefix every wire value carries, version and all.
pub const PREFIX: &str = "tw1.";

/// The wire version inside the encoding, which the signature will cover once there is one.
///
/// It is stated twice on purpose. The prefix is for a reader deciding whether to parse at all, and
/// this is for a reader deciding what the bytes mean. A version carried only outside the signed
/// payload is a version anybody on the path can rewrite.
pub const VERSION: i128 = 1;

/// Every field name this form knows, in the order the encoder writes them.
///
/// It sits beside the writer on purpose. A field added to [`Exchange::to_cbor`] and not added here
/// is refused by our own reader, which shows up as a failing test rather than as a header the other
/// side quietly drops.
pub const FIELDS: [&str; 10] = [
    "v", "role", "hash", "seq", "lo", "mid", "hi", "rcpt", "key", "req",
];

/// The longest header value this will emit or accept, in characters.
///
/// Four kilobytes. Common servers refuse a single header line at 8 KB and a whole header block at 8
/// to 16 KB, and a request carries other headers, so half of the smaller of those is the ceiling
/// here. An exchange that has to be larger than this is an exchange that has stopped being a claim
/// and started being a receipt, and receipts travel in bodies.
pub const MAX_WIRE_CHARS: usize = 4096;

/// A sha256 digest, held as its own type so one cannot be passed where another belongs.
pub type Digest32 = [u8; 32];

/// Which half of the exchange this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The sender's half: what is being sent, when the sender's clock says it was.
    Request,
    /// The receiver's half: what came back, when the receiver's clock says it arrived.
    Response,
}

impl Role {
    /// The word this role is written as on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Request => "request",
            Role::Response => "response",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "request" => Some(Role::Request),
            "response" => Some(Role::Response),
            _ => None,
        }
    }
}

/// One party's interval of UTC for the moment it read, in nanoseconds since the Unix epoch.
///
/// `reading` is a display value and is flagged as one wherever it is shown, exactly as it is in a
/// receipt. The claim is the pair of edges; the midpoint is not the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    /// The earliest UTC the moment could have been.
    pub earliest_ns: i128,
    /// The model's own estimate, which is a display value and never the claim.
    pub reading_ns: i128,
    /// The latest UTC the moment could have been.
    pub latest_ns: i128,
}

impl Interval {
    /// Whether the edges are in order and the reading sits between them.
    #[must_use]
    pub const fn is_coherent(&self) -> bool {
        self.earliest_ns <= self.reading_ns && self.reading_ns <= self.latest_ns
    }
}

/// One half of a countersign exchange, before anything signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    /// Which half this is.
    pub role: Role,
    /// The payload this half is about: what is being sent, or what came back.
    pub payload: Digest32,
    /// Where this sits in the signing agent's own chain of receipts.
    pub sequence: u64,
    /// What that agent's clock was doing at the moment it read.
    pub interval: Interval,
    /// The full signed receipt this claim was taken from, named by hash and not carried.
    pub receipt: Digest32,
    /// The public key of the agent that signs this half, 32 bytes of Ed25519.
    pub key: Vec<u8>,
    /// For a response, the request it answers, named by the sha256 of the signed request as it
    /// travelled.
    ///
    /// It is the hash of the whole envelope and not of the claim inside it. The reason is in
    /// [`Signed::envelope_hash`] and it is short: one body can carry more than one valid signature,
    /// so a body hash would let a sender hold two byte strings and present either as the thing that
    /// was answered.
    ///
    /// `None` on a request. A response without it is refused, because a response that names no
    /// request can be pasted onto any request at all.
    pub answers: Option<Digest32>,
}

/// Why a wire value was not read.
///
/// Every one of these means the same thing to the receiver: no exchange happened, carry on with the
/// request. They are kept apart so the reason can be recorded, not so that any of them can be
/// treated differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// It does not start `tw1.`, so it is not ours, or it is a version this does not know.
    NotThisVersion {
        /// What the value started with, at most the first sixteen characters, for the record.
        found: String,
    },
    /// Longer than [`MAX_WIRE_CHARS`].
    TooLong {
        /// How long it actually was.
        chars: usize,
    },
    /// The part after the prefix is not base64url without padding.
    NotBase64,
    /// The bytes are not deterministic CBOR, or they decode and re-encode to something else.
    NotDeterministicCbor,
    /// A field the form requires is not there.
    MissingField {
        /// Which one.
        name: &'static str,
    },
    /// A field is there and is the wrong shape.
    WrongType {
        /// Which one.
        name: &'static str,
    },
    /// A field the form does not name is on the wire.
    ///
    /// This is the one second spelling the re-encode guard in [`Exchange::from_wire`] cannot see.
    /// An unknown field is part of the decoded value, so it encodes back to the bytes it arrived
    /// as and that comparison passes. A reader that then looks up only the names it knows drops
    /// the field and re-emits the clean spelling, which is two values meaning the same thing and
    /// hashing differently. Refusing it here is what stops a signature over [`Exchange::to_cbor`]
    /// covering bytes that never travelled.
    UnknownField {
        /// What it was called, at most the first thirty-two characters.
        name: String,
    },
    /// A key on the wire is not text, and every field this form names is.
    KeyIsNotText,
    /// It is not a signed exchange at all: the envelope is the wrong shape, or names another
    /// algorithm.
    ///
    /// An unsigned body is refused here rather than read. A claim about somebody's clock that
    /// nobody signed is a claim anybody on the path could have written.
    NotSigned,
    /// The signature does not match the body, or it was made by a different key.
    SignatureDoesNotMatch,
    /// The two halves are not one exchange: the response does not name this request.
    ///
    /// Its own name for a way a pair goes wrong, rather than a general incoherence, because this is
    /// the check the whole pairing rests on. A response is only about the request whose signed bytes
    /// it names, and a pair that fails here is two unrelated halves somebody has put side by side.
    DoesNotAnswerThisRequest,
    /// One key signed both halves, so there are not two parties here.
    ///
    /// What a countersigned exchange is for is that neither party can be contradicted by the
    /// other's clock. Where one key signed both, there is no other party and the ordering argument
    /// is a party agreeing with itself. It is refused rather than reported, for the same reason a
    /// response naming no request is: a reader who has to notice it is a reader who will one day
    /// not.
    OneKeySignedBothHalves,
    /// The values decode but say something that cannot be true.
    Incoherent {
        /// What is wrong with it, in words a person reads once.
        detail: &'static str,
    },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Refusal::NotThisVersion { found } => {
                write!(f, "it does not start `{PREFIX}`, it starts `{found}`")
            }
            Refusal::TooLong { chars } => {
                write!(
                    f,
                    "it is {chars} characters and the ceiling is {MAX_WIRE_CHARS}"
                )
            }
            Refusal::NotBase64 => write!(f, "the part after the prefix is not base64url"),
            Refusal::NotDeterministicCbor => {
                write!(
                    f,
                    "the bytes are not the deterministic encoding of what they decode to"
                )
            }
            Refusal::MissingField { name } => write!(f, "`{name}` is not there"),
            Refusal::WrongType { name } => write!(f, "`{name}` is the wrong shape"),
            Refusal::UnknownField { name } => {
                write!(f, "`{name}` is a field this form does not name")
            }
            Refusal::KeyIsNotText => {
                write!(f, "a key on the wire is not text and every field here is")
            }
            Refusal::NotSigned => write!(f, "it is not a signed exchange"),
            Refusal::SignatureDoesNotMatch => write!(
                f,
                "the signature does not match the exchange, so either it was altered after it was signed or it was signed by a different key"
            ),
            Refusal::DoesNotAnswerThisRequest => write!(
                f,
                "the response names a different request, so these two halves are not one exchange"
            ),
            Refusal::OneKeySignedBothHalves => write!(
                f,
                "one key signed both halves, so there is no second party and nothing here is a countersignature"
            ),
            Refusal::Incoherent { detail } => write!(f, "{detail}"),
        }
    }
}

impl Exchange {
    /// The CBOR body, before the prefix and the base64url.
    ///
    /// This is what a signature will cover, so the ordering here is the ordering the encoder
    /// produces and nothing about it is left to a caller.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut pairs: Vec<(&'static str, Value)> = vec![
            ("v", Value::Int(VERSION)),
            ("role", Value::text(self.role.as_str())),
            ("hash", Value::Bytes(self.payload.to_vec())),
            ("seq", Value::Int(i128::from(self.sequence))),
            ("lo", Value::Int(self.interval.earliest_ns)),
            ("mid", Value::Int(self.interval.reading_ns)),
            ("hi", Value::Int(self.interval.latest_ns)),
            ("rcpt", Value::Bytes(self.receipt.to_vec())),
            ("key", Value::Bytes(self.key.clone())),
        ];
        if let Some(answers) = self.answers {
            pairs.push(("req", Value::Bytes(answers.to_vec())));
        }
        cbor::encode(&Value::map(pairs))
    }

    /// Read a decoded CBOR value as an exchange.
    ///
    /// Separate from [`Self::from_wire`] because an MCP tool call carries the same body as a field
    /// rather than as a header, so the two routes share everything below the encoding.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as above.
    pub fn from_value(value: &Value) -> Result<Self, Refusal> {
        let Value::Map(pairs) = value else {
            return Err(Refusal::WrongType { name: "the body" });
        };
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
                .map(|(_, v)| v)
        };

        let int = |name: &'static str| -> Result<i128, Refusal> {
            match get(name) {
                Some(Value::Int(n)) => Ok(*n),
                Some(_) => Err(Refusal::WrongType { name }),
                None => Err(Refusal::MissingField { name }),
            }
        };
        let bytes = |name: &'static str| -> Result<Vec<u8>, Refusal> {
            match get(name) {
                Some(Value::Bytes(b)) => Ok(b.clone()),
                Some(_) => Err(Refusal::WrongType { name }),
                None => Err(Refusal::MissingField { name }),
            }
        };
        let digest = |name: &'static str| -> Result<Digest32, Refusal> {
            let raw = bytes(name)?;
            <Digest32>::try_from(raw.as_slice()).map_err(|_| Refusal::WrongType { name })
        };

        if int("v")? != VERSION {
            return Err(Refusal::NotThisVersion {
                found: format!("{PREFIX} carrying v {}", int("v")?),
            });
        }

        // Every key is one this form names, or the whole value is refused. The version is read
        // first, above, because a later version of this form will carry fields v1 does not name and
        // refusing that for the field rather than for the version tells the next reader the wrong
        // thing.
        //
        // This is the half of the second-spelling rule that `from_wire`'s re-encode guard cannot
        // reach. An unknown field is in the decoded value, so it encodes back to the bytes it
        // arrived as and that comparison passes; ignoring it here and re-emitting the clean
        // spelling would leave two values that mean the same thing and hash differently, which is
        // the fault deterministic encoding exists to remove. From the slice that signs
        // `to_cbor()`, it would be a signature over bytes nobody sent.
        for (key, _) in pairs {
            match key {
                Value::Text(name) if FIELDS.contains(&name.as_str()) => {}
                Value::Text(name) => {
                    return Err(Refusal::UnknownField {
                        name: name.chars().take(32).collect(),
                    })
                }
                _ => return Err(Refusal::KeyIsNotText),
            }
        }

        let role = match get("role") {
            Some(Value::Text(t)) => Role::from_str(t).ok_or(Refusal::WrongType { name: "role" })?,
            Some(_) => return Err(Refusal::WrongType { name: "role" }),
            None => return Err(Refusal::MissingField { name: "role" }),
        };

        let sequence =
            u64::try_from(int("seq")?).map_err(|_| Refusal::WrongType { name: "seq" })?;
        let interval = Interval {
            earliest_ns: int("lo")?,
            reading_ns: int("mid")?,
            latest_ns: int("hi")?,
        };
        if !interval.is_coherent() {
            return Err(Refusal::Incoherent {
                detail: "the edges are out of order or the reading is not between them",
            });
        }

        let key = bytes("key")?;
        if key.len() != 32 {
            return Err(Refusal::WrongType { name: "key" });
        }

        let answers = match get("req") {
            Some(Value::Bytes(_)) => Some(digest("req")?),
            Some(_) => return Err(Refusal::WrongType { name: "req" }),
            None => None,
        };
        // A response that names no request can be pasted onto any request at all, and a request
        // that names one is answering something nobody sent. Both are refused here rather than
        // later, because a half-shaped exchange that reaches the signing step is one somebody will
        // have to reason about twice.
        match (role, answers.is_some()) {
            (Role::Response, false) => {
                return Err(Refusal::MissingField { name: "req" });
            }
            (Role::Request, true) => {
                return Err(Refusal::Incoherent {
                    detail: "a request names no request of its own",
                });
            }
            _ => {}
        }

        Ok(Exchange {
            role,
            payload: digest("hash")?,
            sequence,
            interval,
            receipt: digest("rcpt")?,
            key,
            answers,
        })
    }
}
