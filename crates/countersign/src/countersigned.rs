//! The receive half: a receiver reads the request, says what its own clock was doing, and signs.
//!
//! Slice two made one party's claim worth carrying. This is the other party. The receiver reads the
//! request **on the bytes it arrived as**, checks the signature over those bytes, and then makes its
//! own half: the hash of what it is sending back, where that sits in its own chain, the interval its
//! own clock gives it, the receipt that interval came from, and the name of the request it is
//! answering. It signs that with its own key, and the two halves together are the countersigned
//! exchange.
//!
//! ## What the pair proves, and it is the same short sentence as before
//!
//! Two parties who each hold a key each signed a statement about their own clock, and the two
//! statements are consistent with an ordering. Countersigning adds a second party and it adds
//! nothing else. **Neither interval becomes third-party evidence for the other**, and the pair is
//! not evidence that either clock was right. The evidence for each interval is in the receipt that
//! half names by hash, which this form does not carry.
//!
//! ## What this piece deliberately does not do
//!
//! **It does not decide an order and it does not look at the two intervals together.** That is the
//! next piece, and the reason it is not here is not tidiness. Two intervals that overlap leave the
//! order undecided, and a pair that refused to read unless the response were later would be
//! answering the ordering question at parse time, in the direction that always says yes. So a
//! perfectly ordinary pair whose intervals overlap reads here exactly as one whose intervals do not,
//! and the answer about order comes from somewhere that can say "undecided" out loud.
//!
//! **It does not enforce anything.** A receiver that will not countersign records a refusal and the
//! request is the request it would have been with no header at all.

use timewitness_receipt::AgentKey;

use crate::signed::Signed;
use crate::{Digest32, Exchange, Interval, Refusal, Role};

/// A request and the response that answers it, both signed, both checked.
///
/// It cannot be built from two halves that are not one exchange, so holding one of these is the
/// check rather than a reason to run it again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Countersigned {
    request: Signed,
    response: Signed,
}

impl Countersigned {
    /// The receiver's act: read the request off the bytes it arrived as, and answer it.
    ///
    /// The request is read here rather than taken as something already parsed, because the property
    /// this rests on is about bytes. What the response names is the sha256 of exactly these bytes,
    /// so a caller that had parsed the request elsewhere and passed the parsed thing in could hand
    /// this a claim that never travelled in this spelling.
    ///
    /// `payload` is the hash of what is being sent back. `sequence`, `interval` and `receipt` are
    /// the receiver's own and say nothing about the sender's.
    ///
    /// # Errors
    ///
    /// Any [`Refusal`] the request itself earns, and every one of them means the same thing: no
    /// exchange happened and the receiver carries on. Beyond those, [`Refusal::WrongType`] where the
    /// interval's edges are out of order, and the pairing refusals from [`Self::join`].
    pub fn answer(
        request_bytes: &[u8],
        payload: Digest32,
        sequence: u64,
        interval: Interval,
        receipt: Digest32,
        key: &AgentKey,
    ) -> Result<Self, Refusal> {
        let request = Signed::from_bytes(request_bytes)?;
        let response = Exchange {
            role: Role::Response,
            payload,
            sequence,
            interval,
            receipt,
            key: key.public_key_bytes(),
            answers: Some(request.envelope_hash()),
        };
        let signed = Signed::new(&response, key)?;
        Self::join(request, signed)
    }

    /// The same, from a header value rather than from the signed bytes.
    ///
    /// # Errors
    ///
    /// As [`Self::answer`].
    pub fn answer_wire(
        request_value: &str,
        payload: Digest32,
        sequence: u64,
        interval: Interval,
        receipt: Digest32,
        key: &AgentKey,
    ) -> Result<Self, Refusal> {
        let request = Signed::from_wire(request_value)?;
        Self::answer(
            request.to_bytes(),
            payload,
            sequence,
            interval,
            receipt,
            key,
        )
    }

    /// Read a pair back from two header values, checking both signatures and the pairing.
    ///
    /// This is what a stranger runs. There is no network in it and no account: both halves carry
    /// everything the check needs.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as above.
    pub fn read(request_value: &str, response_value: &str) -> Result<Self, Refusal> {
        Self::join(
            Signed::from_wire(request_value)?,
            Signed::from_wire(response_value)?,
        )
    }

    /// The same, from the signed bytes of each half.
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as above.
    pub fn read_bytes(request_bytes: &[u8], response_bytes: &[u8]) -> Result<Self, Refusal> {
        Self::join(
            Signed::from_bytes(request_bytes)?,
            Signed::from_bytes(response_bytes)?,
        )
    }

    /// Put two already checked halves together, or say why they are not one exchange.
    ///
    /// Three things are checked here and a fourth is deliberately absent.
    ///
    /// The roles have to be one of each, because two requests are two senders and two responses
    /// answer nothing. The response has to name this request by the hash of the bytes it travelled
    /// as, which is what makes a response about one request rather than about any request with the
    /// same claim in it. And the two keys have to differ, because a party countersigning itself is a
    /// party agreeing with itself, and the whole point of the pair is that neither side can be
    /// contradicted by the other's clock.
    ///
    /// **What is not checked is the relation between the two intervals**, and that is the ordering
    /// question rather than a pairing question. See the note at the head of this module.
    ///
    /// # Errors
    ///
    /// [`Refusal::Incoherent`] where the roles are wrong, [`Refusal::DoesNotAnswerThisRequest`]
    /// where the response names something else, and [`Refusal::OneKeySignedBothHalves`] where there
    /// is only one party.
    pub fn join(request: Signed, response: Signed) -> Result<Self, Refusal> {
        if request.exchange.role != Role::Request {
            return Err(Refusal::Incoherent {
                detail: "the half given as the request is not a request",
            });
        }
        if response.exchange.role != Role::Response {
            return Err(Refusal::Incoherent {
                detail: "the half given as the response is not a response",
            });
        }
        if response.exchange.answers != Some(request.envelope_hash()) {
            return Err(Refusal::DoesNotAnswerThisRequest);
        }
        if request.exchange.key == response.exchange.key {
            return Err(Refusal::OneKeySignedBothHalves);
        }
        Ok(Self { request, response })
    }

    /// The sender's half.
    #[must_use]
    pub const fn request(&self) -> &Signed {
        &self.request
    }

    /// The receiver's half.
    #[must_use]
    pub const fn response(&self) -> &Signed {
        &self.response
    }
}
