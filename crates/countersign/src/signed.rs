//! The signed half of the exchange: one party's claim, signed by the key it names.
//!
//! Slice one of this protocol put the shape on the wire and signed nothing. This is what makes the
//! shape worth carrying. An unsigned exchange is a claim anybody on the path could have written, so
//! from here the wire form is always signed and the reader refuses one that is not.
//!
//! ## What is signed, and what that buys
//!
//! The body is [`Exchange::to_cbor`], and what is signed is the `Sig_structure` of RFC 9052 over it,
//! through the same envelope a receipt uses. That is deliberate and it is one function rather than
//! two: a second reader of one signature format is a second chance to disagree about what was
//! signed, which is the fault the deterministic encoding rules exist to remove one layer down.
//!
//! The key a signature is checked against is the `key` field **inside** the signed body. It is never
//! the key identifier in the unprotected header, which sits outside the signature and is anybody's
//! to rewrite. The header carries a copy so a reader can see whose it claims to be before doing the
//! work, and the copy is held to the signed one rather than trusted.
//!
//! ## What it does not buy, and why that is a rule here rather than a caveat
//!
//! A verified signature says the party holding that key signed that statement about its own clock.
//! It says nothing about whether the clock was right, and the other party's signature says nothing
//! about this one's. Neither interval is third-party evidence for the other and no amount of
//! countersigning makes one so. The third-party evidence lives in the receipt each claim came from,
//! which this form names by hash and does not carry.

use timewitness_receipt::{cbor, check_signature, envelope_parts, AgentKey, Value};

use crate::base64url;
use crate::{Exchange, Refusal, MAX_WIRE_CHARS, PREFIX};

/// One party's claim and the signature over it, as it travels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// What was said.
    pub exchange: Exchange,
    /// The `COSE_Sign1` bytes, which are what the wire value encodes.
    envelope: Vec<u8>,
}

impl Signed {
    /// Sign an exchange with the key it names.
    ///
    /// # Errors
    ///
    /// [`Refusal::WrongType`] where the exchange names a different public key from the one signing
    /// it, because a claim that names somebody else's key is a claim nobody can check; and
    /// [`Refusal::TooLong`] where the result would not fit in a header, which is checked here rather
    /// than left for the receiver to find.
    pub fn new(exchange: &Exchange, key: &AgentKey) -> Result<Self, Refusal> {
        if exchange.key != key.public_key_bytes() {
            return Err(Refusal::WrongType { name: "key" });
        }
        let body = cbor::decode(&exchange.to_cbor()).map_err(|_| Refusal::NotDeterministicCbor)?;
        let envelope = key.sign_value(&body);
        let signed = Self {
            exchange: exchange.clone(),
            envelope,
        };
        let chars = signed.to_wire().chars().count();
        if chars > MAX_WIRE_CHARS {
            return Err(Refusal::TooLong { chars });
        }
        Ok(signed)
    }

    /// The whole header value, prefix and all.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let mut out = String::from(PREFIX);
        out.push_str(&base64url::encode(&self.envelope));
        out
    }

    /// The signed bytes, for a route that carries them as a field rather than as a header.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.envelope
    }

    /// Read a signed header value back, checking the signature, or say why it was not read.
    ///
    /// # Errors
    ///
    /// Every failure is a [`Refusal`], and every refusal means the same thing to a receiver: no
    /// exchange happened, carry on with the request.
    pub fn from_wire(value: &str) -> Result<Self, Refusal> {
        if value.chars().count() > MAX_WIRE_CHARS {
            return Err(Refusal::TooLong {
                chars: value.chars().count(),
            });
        }
        let Some(rest) = value.strip_prefix(PREFIX) else {
            return Err(Refusal::NotThisVersion {
                found: value.chars().take(16).collect(),
            });
        };
        let bytes = base64url::decode(rest).ok_or(Refusal::NotBase64)?;
        Self::from_bytes(&bytes)
    }

    /// The same, from the signed bytes themselves.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as above.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        // The whole envelope is held to one spelling, not only the body inside it. A holder who
        // could restate a signed exchange as different bytes carrying the same claim would have two
        // spellings of one thing that hash differently, and an ordering argument rests on hashes.
        let decoded = cbor::decode(bytes).map_err(|_| Refusal::NotDeterministicCbor)?;
        if cbor::encode(&decoded) != bytes {
            return Err(Refusal::NotDeterministicCbor);
        }

        let (protected, payload, signature, unprotected) =
            envelope_parts(bytes).map_err(|_| Refusal::NotSigned)?;

        // The body is read before the signature because the key the signature is checked against is
        // inside it. Nothing acts on what is read until the signature has been checked.
        let body = cbor::decode(&payload).map_err(|_| Refusal::NotDeterministicCbor)?;
        if cbor::encode(&body) != payload {
            return Err(Refusal::NotDeterministicCbor);
        }
        let exchange = Exchange::from_value(&body)?;

        check_signature(
            &protected,
            &payload,
            &signature,
            &exchange.key,
            "signing agent's",
            "exchange",
        )
        .map_err(|_| Refusal::SignatureDoesNotMatch)?;

        check_unprotected_header(&unprotected, &exchange)?;

        Ok(Self {
            exchange,
            envelope: bytes.to_vec(),
        })
    }
}

/// The COSE label for a key identifier in an unprotected header.
const HEADER_KID: i128 = 4;

/// The unprotected header holds one entry, the key identifier, and it names the key inside the
/// signature.
///
/// This is the rule that makes a signed exchange one byte string, and it is the receipt format's own
/// rule applied here for the same reason. The unprotected header is outside the signature, which is
/// RFC 9052 working as designed; the consequence followed through is that a holder could otherwise
/// restate an exchange as different bytes carrying the same claim and verifying identically, by
/// dropping the key identifier, relabelling it, or padding a label nobody reads. Each of those is a
/// second spelling, and a response names its request by the hash of what travelled.
fn check_unprotected_header(unprotected: &Value, exchange: &Exchange) -> Result<(), Refusal> {
    let Value::Map(pairs) = unprotected else {
        return Err(Refusal::WrongType {
            name: "the unprotected header",
        });
    };
    if pairs.len() != 1 {
        return Err(Refusal::WrongType {
            name: "the unprotected header",
        });
    }
    let (label, named) = &pairs[0];
    if label != &Value::Int(HEADER_KID) {
        return Err(Refusal::WrongType {
            name: "the unprotected header",
        });
    }
    match named {
        Value::Bytes(bytes) if bytes == &exchange.key => Ok(()),
        _ => Err(Refusal::Incoherent {
            detail: "the key identifier outside the signature is not the key inside it",
        }),
    }
}
