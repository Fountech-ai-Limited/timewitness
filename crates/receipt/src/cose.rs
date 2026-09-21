//! The COSE envelope, and the agent's own signature over a receipt.
//!
//! A single signer, so the structure is COSE_Sign1 from RFC 9052: a four element array holding the
//! protected header as a byte string, the unprotected header as a map, the payload as a byte
//! string, and the signature.
//!
//! What is signed is not the payload on its own. It is the `Sig_structure` the specification
//! defines, being the literal text `Signature1`, the protected header bytes, any external data, and
//! the payload, all encoded canonically. Signing the payload alone would let somebody move a
//! signature onto a receipt with a different algorithm in its header, which is a real attack and an
//! old one.
//!
//! The algorithm is Ed25519, which COSE calls EdDSA and numbers minus eight. The agent's public key
//! travels in the receipt itself, so a verifier holds everything it needs without asking us for
//! anything. Checking that key against a public key log is a later change, and until it exists a
//! receipt proves the agent that signed it held that key, not that the key is one of ours.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor;
use crate::error::ReceiptError;
use crate::schema::Receipt;
use crate::validate;
use crate::value::Value;

/// The COSE label for the algorithm in a protected header.
const HEADER_ALG: i128 = 1;
/// The COSE label for a key identifier in an unprotected header.
const HEADER_KID: i128 = 4;
/// The COSE algorithm number for Ed25519.
const ALG_EDDSA: i128 = -8;

/// The agent's signing key.
pub struct AgentKey {
    signing: SigningKey,
}

impl AgentKey {
    /// A key from a 32 byte seed.
    ///
    /// The seed comes from the caller so that key handling, which is its own subject, stays outside
    /// this crate.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The public half, which is what goes in the receipt.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    /// Encode a receipt and sign it, producing a complete COSE_Sign1 object.
    pub fn sign(&self, receipt: &Receipt) -> Result<Vec<u8>, ReceiptError> {
        if receipt.agent_public_key != self.public_key_bytes() {
            return Err(ReceiptError::Signature(
                "the receipt names a different public key from the one signing it".into(),
            ));
        }
        // A receipt is signed in a version this code reads and in the shape that version has, so a
        // version 1 receipt with a field missing is refused here rather than signed and then refused
        // by every reader afterwards. The stamp command only ever builds version 1; version 0 is
        // signed here only so the tests can go on proving that version 0 still reads.
        if !crate::schema::READS.contains(&receipt.version) {
            return Err(ReceiptError::UnknownVersion(receipt.version));
        }
        let c = &receipt.claim;
        let version_1_fields = [
            c.taken_by.is_some(),
            c.breakdown.unclaimed_rate.is_some(),
            c.policy.source_interval_floor.is_some(),
            c.policy.frequency_slew_ppb_per_s.is_some(),
            c.policy.frequency_span_ppb.is_some(),
        ];
        let whole = if receipt.version >= 1 {
            version_1_fields.iter().all(|held| *held)
                && c.policy.max_holdover.is_some()
                && c.policy.min_operators.is_some()
        } else {
            version_1_fields.iter().all(|held| !*held)
        };
        if !whole {
            return Err(ReceiptError::Signature(format!(
                "this receipt says it is version {} and does not have that version's fields. \
                 Version 1 states its width terms, the unclaimed part of its holdover, its two \
                 limits and the path its reading came by, and version 0 states no width term, no \
                 unclaimed part and no path",
                receipt.version
            )));
        }

        Ok(self.sign_value(&receipt.to_value()))
    }

    /// Sign whatever value tree it is handed, without asking whether it is a sensible receipt.
    ///
    /// This exists so the validator can be tested. Checking that a mislabelled receipt is refused
    /// needs a mislabelled receipt that is correctly signed, and one that the typed `Receipt` will
    /// not construct, so there has to be a way past the types. It is also what will build the
    /// conformance vectors the adversarial battery needs.
    ///
    /// Nothing in the agent's own path calls this. [`AgentKey::sign`] is the door for that.
    #[must_use]
    pub fn sign_value(&self, value: &Value) -> Vec<u8> {
        let payload = cbor::encode(value);
        let protected = cbor::encode(&Value::Map(vec![(
            Value::Int(HEADER_ALG),
            Value::Int(ALG_EDDSA),
        )]));

        let to_sign = sig_structure(&protected, &payload);
        let signature = self.signing.sign(&to_sign);

        cbor::encode(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![(
                Value::Int(HEADER_KID),
                Value::Bytes(self.public_key_bytes()),
            )]),
            Value::Bytes(payload),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
    }
}

/// A `COSE_Sign1` taken apart: the protected header, the payload, the signature, and the
/// unprotected header as the value it decoded to.
pub type Envelope = (Vec<u8>, Vec<u8>, Vec<u8>, Value);

/// The three parts of a `COSE_Sign1` this product signs, with the algorithm already checked.
///
/// The protected header, the payload and the signature, in that order; the unprotected header is
/// returned beside them as the value it decoded to, because a caller that cares what is in it has to
/// hold it to its own rule and nothing here can do that for every caller.
///
/// Public because the countersign wire form signs its own body with the same envelope, and one copy
/// of the arithmetic is the point: two readers of one format is two chances to disagree about what
/// was signed.
///
/// # Errors
///
/// A [`ReceiptError::Signature`] where the bytes are not a `COSE_Sign1` of this shape, or where the
/// protected header names an algorithm other than Ed25519.
pub fn envelope_parts(bytes: &[u8]) -> Result<Envelope, ReceiptError> {
    let envelope = cbor::decode(bytes)?;
    let parts = envelope
        .as_array()
        .ok_or_else(|| ReceiptError::Signature("a signed value is a list of four things".into()))?;
    if parts.len() != 4 {
        return Err(ReceiptError::Signature(format!(
            "a signed value has four parts and this one has {}",
            parts.len()
        )));
    }

    let protected = parts[0].as_bytes().ok_or_else(|| {
        ReceiptError::Signature("the protected header is not a byte string".into())
    })?;
    let payload = parts[2]
        .as_bytes()
        .ok_or_else(|| ReceiptError::Signature("the payload is not a byte string".into()))?;
    let signature = parts[3]
        .as_bytes()
        .ok_or_else(|| ReceiptError::Signature("the signature is not a byte string".into()))?;

    // The protected header is itself deterministic CBOR and is checked as such, because it is part
    // of what was signed.
    let header = cbor::decode(protected)?;
    let alg = header
        .as_map_get(HEADER_ALG)
        .and_then(|v| v.as_int())
        .ok_or_else(|| ReceiptError::Signature("the protected header names no algorithm".into()))?;
    if alg != ALG_EDDSA {
        return Err(ReceiptError::Signature(format!(
            "this is signed with COSE algorithm {alg} and this code checks Ed25519, which is minus \
             eight"
        )));
    }

    Ok((
        protected.to_vec(),
        payload.to_vec(),
        signature.to_vec(),
        parts[1].clone(),
    ))
}

/// Check a signature over the `Sig_structure` the protected header and payload make.
///
/// The key is the caller's to find, and it comes from inside the payload rather than from the
/// unprotected header, which is outside the signature and anybody's to rewrite.
///
/// # Errors
///
/// A [`ReceiptError::Signature`] where the key or the signature is not the right length or shape, or
/// where the signature does not match.
pub fn check_signature(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
    key: &[u8],
    key_owner: &str,
    signed_thing: &str,
) -> Result<(), ReceiptError> {
    let key_bytes: [u8; 32] = key.try_into().map_err(|_| {
        ReceiptError::Signature(format!("the {key_owner} public key is not 32 bytes"))
    })?;
    let verifying = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
        ReceiptError::Signature(format!("the {key_owner} public key is not usable: {e}"))
    })?;

    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| ReceiptError::Signature("an Ed25519 signature is 64 bytes".into()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    // `verify_strict` rather than `verify`. The two differ on public keys and signature commitments
    // with a small order component, which no honest signer produces and which give one signed
    // message more than one valid signature. A format whose chain link is the hash of a file cannot
    // afford a second valid spelling anywhere in it.
    verifying
        .verify_strict(&sig_structure(protected, payload), &signature)
        .map_err(|_| {
            ReceiptError::Signature(format!(
                "the signature does not match the {signed_thing}, so either the {signed_thing} was \
                 altered after it was signed or it was signed by a different key"
            ))
        })
}

/// What actually gets signed, per RFC 9052.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::text("Signature1"),
        Value::Bytes(protected.to_vec()),
        // No external data. Present because the structure has four elements and leaving it out
        // would change what a verifier reconstructs.
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// Read a signed receipt, check the signature, and validate what it says.
///
/// The order matters and it is deliberate. Size first, so nothing allocates from a file that is not
/// a receipt. Then the bytes are checked for a single canonical spelling, then the envelope is taken
/// apart and the payload read far enough to find the key it names, then the signature, then the
/// claims. Reading the payload before the signature is unavoidable, because the key the signature is
/// checked against is inside the payload; what that reading does is fill in a typed structure and
/// refuse a shape it does not recognise, and nothing acts on any of it. Everything that reasons
/// about what the receipt says is in [`validate`], and that runs after the signature.
pub fn open(bytes: &[u8]) -> Result<Receipt, ReceiptError> {
    open_with(bytes, &crate::anchors::TrustAnchors::none()).map(|(receipt, _)| receipt)
}

/// The same door, with what the reader decided to trust carried through it.
///
/// [`open`] checks a receipt against nothing but itself, which is all a caller holding no keys can
/// do. This one hands the anchors to the validator, so the report that comes back says which
/// evidence entries were checked and against whose key. A verifier needs both halves in one call:
/// checking the signature and then validating separately would leave a window in which a caller
/// could act on a receipt whose signature had not been looked at.
pub fn open_with(
    bytes: &[u8],
    anchors: &crate::anchors::TrustAnchors,
) -> Result<(Receipt, crate::report::Verified), ReceiptError> {
    let receipt = read_and_check_signature(bytes)?;
    let report = validate::validate_with(&receipt, anchors)?;
    Ok((receipt, report))
}

fn read_and_check_signature(bytes: &[u8]) -> Result<Receipt, ReceiptError> {
    if bytes.len() > crate::MAX_ENCODED_BYTES {
        return Err(ReceiptError::Signature(format!(
            "this file is {} bytes and a receipt is no more than {} bytes",
            bytes.len(),
            crate::MAX_ENCODED_BYTES
        )));
    }

    let (protected, payload, signature, unprotected) = envelope_parts(bytes)?;

    let value = cbor::decode(&payload)?;
    validate::validate_shape(&value)?;
    let receipt = Receipt::from_value(&value)?;

    check_signature(
        &protected,
        &payload,
        &signature,
        &receipt.agent_public_key,
        "agent's",
        "receipt",
    )?;

    check_unprotected_header(&unprotected, &receipt)?;

    Ok(receipt)
}

/// The unprotected header holds one entry, the key identifier, and it names the key inside the
/// signature.
///
/// This is the rule that makes a signed receipt one byte string. The unprotected header is outside
/// the signature, which is RFC 9052 working as designed, and the consequence followed through is
/// that a holder could otherwise restate a receipt as different bytes carrying the same claim and
/// verifying identically: drop the key identifier, relabel it, or pad a label nobody reads with a
/// megabyte. Each of those is a second spelling of one receipt, and the chain link is the hash of
/// the spelling, so a holder could fork or break a chain without ever holding the agent's key.
/// Unbroken order is half of what this product claims.
///
/// Everything else in the envelope is either covered by the signature or is canonical CBOR the
/// decoder re-encodes and compares. With this entry pinned, a receipt this function accepts has
/// exactly one valid spelling, so the hash of the file is a hash of something nobody can restate.
///
/// A disagreement here was previously a warning about the file rather than about the receipt,
/// because the signed copy of the key is the one that counts. That reading is correct about what the
/// receipt means and it is the wrong rule for a format that chains by hashing bytes.
fn check_unprotected_header(header: &Value, receipt: &Receipt) -> Result<(), ReceiptError> {
    let pairs = match header {
        Value::Map(pairs) => pairs,
        _ => {
            return Err(ReceiptError::Signature(
                "the unprotected header is not a map".into(),
            ))
        }
    };
    if pairs.len() != 1 {
        return Err(ReceiptError::Signature(format!(
            "the unprotected header holds {} entries and a receipt carries one, the key identifier. \
             Nothing there is signed, so anything else in it is a second spelling of this receipt",
            pairs.len()
        )));
    }

    let kid = header
        .as_map_get(HEADER_KID)
        .and_then(Value::as_bytes)
        .ok_or_else(|| {
            ReceiptError::Signature(
                "the unprotected header holds one entry and it is not the key identifier".into(),
            )
        })?;
    if kid != receipt.agent_public_key.as_slice() {
        return Err(ReceiptError::Signature(
            "the key named outside the signature is not the key named inside it".into(),
        ));
    }
    Ok(())
}

trait MapGet {
    fn as_map_get(&self, key: i128) -> Option<&Value>;
}

impl MapGet for Value {
    fn as_map_get(&self, key: i128) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs
                .iter()
                .find(|(k, _)| matches!(k, Value::Int(i) if *i == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}
