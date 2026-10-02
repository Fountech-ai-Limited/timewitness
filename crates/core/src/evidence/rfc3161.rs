//! An RFC 3161 timestamp token, checked from the bytes up.
//!
//! **What this proves.** A named authority put its signature to a statement that it had been shown
//! a particular hash, and that its clock read a particular moment when it did. Whoever held that
//! hash therefore held it no later than then. That is the not-later-than edge, and it is the one
//! edge the other two roles cannot supply: a corridor says where our own clock sat and a beacon
//! says a document is not older than a public moment, and neither of them stops a document being
//! made up afterwards.
//!
//! **What it does not prove, and this is not a small list.**
//!
//! - It says nothing about the authority's clock being right. It is that authority's word.
//! - It is not a qualified trust service and carries no legal presumption anywhere. Standing of that
//!   kind comes from accreditation, not from a signature. No legal weight is claimed, and that
//!   is in the product's "cannot prove" list in those words.
//! - This code checks that the token was signed by the key in a certificate whose hash the caller
//!   pinned in advance. It does **not** walk a chain to a commercial root, check revocation, or
//!   check the timestamping extended key usage. A token that passes here was signed by the key you
//!   said you expected, which is a precise statement and a narrower one than "trusted".
//! - The stored request is signed by nobody. Roughtime binds ours in through the Merkle leaf and
//!   this scheme has no equivalent, so whoever holds a stored token writes both halves of anything
//!   compared across the two. The nonce is the case that matters: it does its job at the moment the
//!   party that generated it fetches the token, and a reader years later cannot recover that. The
//!   checks this module prints say so rather than implying otherwise.
//!
//! The pin is the same idea as a Roughtime server's long-term key: a thing you decided to trust
//! before you asked, so that the answer cannot talk you into trusting it. The certificate travels
//! inside the token, so a receipt stays checkable by anybody holding the same pin, and by anybody
//! who would rather chain the certificate to a root themselves.

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256};

use super::der::{self, Reader};
use super::{Checked, EvidenceError};
use crate::hash::{HashFunction, OID_SHA256};
use crate::time::{Nanos, UnixNanos, NANOS_PER_SEC};

/// The scheme name the receipt format uses for this evidence.
pub const SCHEME: &str = "rfc3161";

/// `id-signedData`, 1.2.840.113549.1.7.2.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// `id-ct-TSTInfo`, 1.2.840.113549.1.9.16.1.4.
const OID_TST_INFO: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// `id-contentType`, 1.2.840.113549.1.9.3.
const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// `id-messageDigest`, 1.2.840.113549.1.9.4.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11, and its two siblings.
const OID_SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];

/// A timestamp authority, and the certificate its answers are checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    /// A name for a person reading a receipt.
    pub name: String,
    /// Where to ask, as a plain HTTP address.
    pub url: String,
    /// The SHA-256 of every signing certificate this authority is expected to use.
    ///
    /// A list rather than one value, because an authority may run several signing units behind one
    /// address and answer from whichever is free. Two consecutive requests to one of the four tried
    /// on 2026-09-07 came back signed by different certificates, so a single pin would have refused
    /// half of them.
    ///
    /// Pinned rather than chained, and the module comment says what that does and does not buy. A
    /// certificate rotates, so a pin goes stale for fetching new tokens; tokens already issued stay
    /// checkable, because the certificate travels inside them.
    pub accepted_certificates: Vec<[u8; 32]>,
    /// What this reader allows for the authority's own clock, where the token states no accuracy.
    ///
    /// Added 2026-09-19. A token that states no accuracy puts no number on how
    /// wrong the authority's clock could be, so nothing in it supports an edge in UTC. RFC 3161
    /// section 2.4.2 says where that field is absent "the accuracy may be available through other
    /// means, e.g., the TSAPolicyId", which is to say from the authority's published practice
    /// rather than from the token. That is a thing a reader decides in advance about an authority,
    /// exactly as a pin is, so it sits on the anchor and never in the bytes.
    ///
    /// `None` on both authorities that ship, because this product has not read either one's
    /// practice statement and will not write a figure it cannot source. A reader who has read one
    /// sets it here, and the verifier prints the number as that reader's rather than as the
    /// authority's.
    ///
    /// It is never applied where the token does state an accuracy. The authority's own statement
    /// wins, and a reader who thinks a stated accuracy is optimistic is asking a different
    /// question from the one this answers.
    pub accuracy_where_the_token_states_none: Option<Nanos>,
}

/// The eight bytes a stored token starts with.
const BLOB_MAGIC: &[u8; 8] = b"TWTSEVD0";

fn malformed(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Malformed(what.into())
}

/// Pack a request and a reply into the blob a receipt carries.
///
/// The request is kept because it says what was asked, and a stored pair that disagrees with itself
/// is worth catching. It is not kept for the reason the Roughtime request is kept: that one is
/// hashed into the leaf the server signs, and this one is signed by nobody, so it corroborates the
/// reply no more than a note beside it would. Both are DER documents and both are stored whole.
#[must_use]
pub fn pack_blob(request: &[u8], reply: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + request.len() + reply.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&(request.len() as u32).to_le_bytes());
    out.extend_from_slice(&(reply.len() as u32).to_le_bytes());
    out.extend_from_slice(request);
    out.extend_from_slice(reply);
    out
}

/// What a stored token holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored<'a> {
    /// The request as it went out.
    pub request: &'a [u8],
    /// The reply as it arrived.
    pub reply: &'a [u8],
}

/// Split a stored token back into the request and the reply.
pub fn unpack_blob(blob: &[u8]) -> Result<Stored<'_>, EvidenceError> {
    if blob.len() < 16 {
        return Err(malformed(format!(
            "a stored token of {} bytes, and the header alone is sixteen",
            blob.len()
        )));
    }
    if &blob[..8] != BLOB_MAGIC {
        return Err(malformed(
            "a stored token that is not in the form this scheme stores",
        ));
    }
    let request_len = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let reply_len = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let total = request_len
        .checked_add(reply_len)
        .and_then(|x| x.checked_add(16))
        .ok_or_else(|| malformed("section lengths that do not add up to a length"))?;
    if total != blob.len() {
        return Err(malformed(format!(
            "sections adding to {total} bytes in a stored token of {}",
            blob.len()
        )));
    }
    Ok(Stored {
        request: &blob[16..16 + request_len],
        reply: &blob[16 + request_len..],
    })
}

/// Build a timestamp request for a hash.
///
/// `certReq` is set, so the authority returns the certificate it signed with and the token stays
/// checkable by somebody who has never spoken to that authority.
///
/// The nonce is the caller's, and it stops an authority answering with a token it prepared earlier.
/// That protection belongs to the caller and to the moment: the caller knows it chose these bytes
/// just now and can hold the reply to them. It does not travel with the receipt, because nothing
/// signs the request.
#[must_use]
pub fn build_request(hash_oid_sha256: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let algorithm = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_OID, OID_SHA256),
            der::encode(der::TAG_NULL, &[]),
        ]
        .concat(),
    );
    let imprint = der::encode(
        der::TAG_SEQUENCE,
        &[
            algorithm,
            der::encode(der::TAG_OCTET_STRING, hash_oid_sha256),
        ]
        .concat(),
    );

    // An integer with the high bit set needs a leading zero, or it reads as negative.
    let mut nonce_bytes = Vec::with_capacity(17);
    if nonce[0] & 0x80 != 0 {
        nonce_bytes.push(0);
    }
    nonce_bytes.extend_from_slice(nonce);

    der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_INTEGER, &[1]),
            imprint,
            der::encode(der::TAG_INTEGER, &nonce_bytes),
            // certReq, so the certificate comes back with the token.
            der::encode(der::TAG_BOOLEAN, &[0xff]),
        ]
        .concat(),
    )
}

/// What one token said, once it has been checked.
#[derive(Clone, Debug)]
struct Token<'a> {
    hashed_message: &'a [u8],
    hash: HashFunction,
    generated_at: UnixNanos,
    /// What the authority states about its own error, where it states anything at all.
    ///
    /// `None` is an authority that stated no accuracy, and it is a different fact from a stated
    /// zero. The field is optional in the specification and an authority leaving it out has said
    /// nothing about how wrong its own clock could be. Carrying that as zero and printing "0 ns"
    /// reads as the authority vouching for a perfect time, which is the opposite of what happened;
    /// a tester read it exactly that way on 2026-09-15 and was right to.
    accuracy: Option<Nanos>,
    /// How finely the token wrote that time, in nanoseconds.
    ///
    /// A second where the authority wrote whole seconds, a millisecond where it wrote three digits
    /// of fraction, and so on down. It is not the authority's error and it is not its accuracy; it
    /// is the width of the thing the token actually names.
    resolution: Nanos,
    /// What the authority says about ordering its own tokens by the times they state.
    ordering: bool,
    nonce: Option<Vec<u8>>,
    serial: Vec<u8>,
}

/// The SHA-256 of every certificate the stored reply carries, in the order it carries them.
///
/// A pin is matched against these, so a reader whose pins name none of them holds nothing this
/// token can be checked against. That is read here, before any signature is looked at, so the
/// validator can say so rather than trying every authority it holds and reading a token that fits
/// none of them as a fault in the receipt, which is what it did until 2026-09-15. A reply carrying
/// no certificate at all comes back as an empty list for the same reason: there is nothing in it a
/// pin could name.
pub fn certificate_digests(blob: &[u8]) -> Result<Vec<[u8; 32]>, EvidenceError> {
    let stored = unpack_blob(blob)?;
    let reply = read_reply(stored.reply)?;
    Ok(digests_of(&reply.certificates))
}

/// The SHA-256 of each certificate, in the order they are carried.
fn digests_of(certificates: &[&[u8]]) -> Vec<[u8; 32]> {
    certificates
        .iter()
        .map(|c| {
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&Sha256::digest(c));
            digest
        })
        .collect()
}

/// A stored token, read and held to itself and to the subject with no pin at all.
///
/// Nearly the whole of a token can be checked by somebody holding no certificate: that the reply is
/// a granted timestamp response, that the token is about the hash it was asked about and that hash
/// is this receipt's subject, that the request and the token carry the same nonce, that the signed
/// attributes carry the digest of the token they are attached to, and what moment the token states
/// and how finely. What the pin decides is which of the carried certificates the signature is
/// checked under, and that check is the one thing left for [`Inspected::under`].
///
/// A token for another document behind a renamed certificate was accepted, exit 0, until
/// 2026-09-15, because the validator matched pins first and read nothing where none matched.
#[derive(Clone, Debug)]
pub struct Inspected<'a> {
    reply: Reply<'a>,
    token: Token<'a>,
}

impl Inspected<'_> {
    /// The SHA-256 of every certificate the reply carries, which is what a pin is matched against.
    #[must_use]
    pub fn certificate_digests(&self) -> Vec<[u8; 32]> {
        digests_of(&self.reply.certificates)
    }

    /// The latest instant the time this token writes can name.
    ///
    /// **This is what the token states, not what it supports about UTC.** The two were one number
    /// until 2026-09-19 and they answer different questions. A token writes a time to some
    /// resolution: whole seconds, or three digits of fraction, or nine. Nothing in it says whether
    /// the authority truncated or rounded, so the moment it names is somewhere inside that
    /// resolution either way, and the last instant it can name is the written time plus the
    /// resolution.
    ///
    /// Every part of that comes off the token's own signed bytes. It is the same for every reader
    /// whatever trust material they hold, and nothing a receipt writer controls can move it, which
    /// is why it is the value a receipt prints beside a witness entry and the value the verifier
    /// ties that entry to before it has looked at a key.
    ///
    /// What it is not is an instant in UTC. The authority's clock could be wrong by any amount the
    /// authority has not told us about, and [`Inspected::supports`] is where that is answered.
    #[must_use]
    pub fn stated_instant(&self) -> UnixNanos {
        UnixNanos(self.token.generated_at.as_nanos() + self.token.resolution)
    }

    /// The interval in UTC this token supports, where it supports one at all.
    ///
    /// Two widths added rather than one taken for the other. The resolution says how finely the
    /// time was written, per [`Inspected::stated_instant`]. The accuracy is the authority's own
    /// account of how wrong its clock could be, and it is the half that turns a reading of that
    /// authority's clock into a statement about UTC.
    ///
    /// **An authority that states no accuracy has put no number on its own error, so there is no
    /// edge to compute and this answers `None`.** Until 2026-09-19 it answered as though the
    /// authority had said zero, which is the narrowest reading the token could possibly bear and
    /// is the tightening direction. Both authorities that ship state no accuracy, read that day
    /// off the two captured tokens, so this was every not-later-than edge the product produced.
    /// RFC 3161 section 2.4.2 is explicit about both halves of it: a missing sub-field of a
    /// present accuracy is taken as zero, and where the field itself is absent "the accuracy may
    /// be available through other means, e.g., the TSAPolicyId". The same section refuses the
    /// other shortcut, that the accuracy "is not to be inferred from the syntax", so the
    /// resolution is not an accuracy either.
    ///
    /// `allowance` is what the reader has decided to allow for this authority's clock where the
    /// token says nothing, per [`Authority::accuracy_where_the_token_states_none`]. It is the
    /// reader's number and it is used only where the token states none.
    ///
    /// **This was a live fault rather than a tidying, and the resolution half of it is why.** Both
    /// edges were once taken as though the stated time were exact. While the agent's own bound was
    /// seconds wide that was invisible, because a second of truncation sat well inside it. On
    /// 2026-09-09 the bound came down to about 240 ms on a build runner, and the same free
    /// authority, writing whole seconds as it always had, produced a token dated 437.345 ms before
    /// the earliest time the receipt claimed. The Action refused its own receipt on a real
    /// repository. Neither the token nor the receipt was wrong; the comparison was.
    #[must_use]
    pub fn supports(&self, allowance: Option<Nanos>) -> Option<(UnixNanos, UnixNanos)> {
        let accuracy = self.token.accuracy.or(allowance)?;
        let width = accuracy + self.token.resolution;
        Some((
            UnixNanos(self.token.generated_at.as_nanos() - width),
            UnixNanos(self.token.generated_at.as_nanos() + width),
        ))
    }

    /// Whether the authority put a number on its own error inside the token.
    #[must_use]
    pub const fn states_an_accuracy(&self) -> bool {
        self.token.accuracy.is_some()
    }

    /// The nonce inside the signed token, as a value.
    #[must_use]
    pub fn nonce(&self) -> Option<&[u8]> {
        self.token.nonce.as_deref()
    }

    /// Check the token's signature under the certificate the reader pinned for an authority.
    ///
    /// The certificate is found by the pin rather than by anything the token says about itself.
    /// Everything else about the token was established by [`inspect`], and the list of checks
    /// this returns names all of it in the order a reader would want to follow.
    pub fn under(&self, authority: &Authority) -> Result<Checked, EvidenceError> {
        let mut checks: Vec<String> = Vec::new();
        let token = &self.token;
        let signer = &self.reply.signer;

        checks.push(format!(
            "the token's own imprint is the {} byte hash this check was given, byte for byte, and \
             the {} the token names produces a hash of that length",
            token.hashed_message.len(),
            token.hash.name()
        ));
        if let Some(returned) = &token.nonce {
            // What this holds and what it does not. The token's nonce is inside the signature, so
            // the authority did answer a request carrying it. The stored request is signed by
            // nobody, so a holder writes both sides of this comparison and it cannot show that the
            // nonce was fresh when the token was fetched. The party that generated the nonce can
            // show that, at the moment it fetched, and nobody afterwards can.
            checks.push(format!(
                "the token carries a signed {} byte nonce and the stored request asks with the \
                 same one, which makes the stored pair agree; a request carries no signature, so \
                 this cannot show the nonce was fresh when the token was fetched",
                returned.len()
            ));
        }

        let certificate = self
            .reply
            .certificates
            .iter()
            .find(|c| {
                let digest = Sha256::digest(c);
                authority
                    .accepted_certificates
                    .iter()
                    .any(|pin| pin == digest.as_slice())
            })
            .ok_or_else(|| {
                EvidenceError::BadSignature(format!(
                    "none of the {} certificates in this token is one of the {} pinned for {}",
                    self.reply.certificates.len(),
                    authority.accepted_certificates.len(),
                    authority.name
                ))
            })?;
        checks.push(format!(
            "the token carries a certificate pinned for {}, matched by its SHA-256",
            authority.name
        ));
        checks.push(format!(
            "the digest inside the signed attributes is the {} hash of the token itself",
            signer.digest.name()
        ));

        verify_with(certificate, signer).map_err(|_| {
            EvidenceError::BadSignature(format!(
                "the token's signature does not check against the key in the certificate pinned \
                 for {}",
                authority.name
            ))
        })?;
        checks.push(format!(
            "the signature over those attributes checks against that certificate's key, {} with \
             RSA",
            signer.signature_hash.name()
        ));

        checks.push(what_the_token_states(
            &authority.name,
            token.generated_at.as_nanos() / NANOS_PER_SEC,
            token.accuracy,
            token.resolution,
            authority.accuracy_where_the_token_states_none,
        ));

        // The ordering flag, which this product has more reason to read than most. The claim here
        // is unbroken order, and the flag is an authority speaking to exactly that. Neither line
        // below is worth more than it says: the strong one is the authority's own account of its
        // own practice, it covers only tokens this same authority issued, and no verifier can test
        // it. The weak one is the ordinary case and is not a fault.
        if token.ordering {
            checks.push(format!(
                "{} states that its own tokens are ordered by the times they state, whatever \
                 accuracy each one states. That is the authority's account of its own practice, \
                 it holds only between tokens {} issued, and nothing here can check it",
                authority.name, authority.name
            ));
        } else {
            checks.push(format!(
                "the token makes no claim that the time it states is enough to order it, so two \
                 tokens from {} are in a known order only where their stated times differ by \
                 more than the two stated accuracies added together",
                authority.name
            ));
        }

        let signer = format!("{} serial {}", authority.name, hex(&token.serial));
        let stated = self.stated_instant();
        match self.supports(authority.accuracy_where_the_token_states_none) {
            Some((earliest, latest)) => Checked::over(
                SCHEME,
                signer,
                earliest,
                latest,
                token.nonce.clone(),
                checks,
            )
            .map(|checked| checked.stating(stated)),
            // The signature holds and the authority has still put no number on its own clock, so
            // there is no edge in UTC to hand back. Answering with the stated time would say the
            // authority vouched for a perfect clock, which is the one thing it declined to do.
            None => Ok(
                Checked::with_no_interval(SCHEME, signer, token.nonce.clone(), checks)
                    .stating(stated),
            ),
        }
    }
}

/// Read a stored token and hold it to itself and to the subject, with no pin.
///
/// `subject_hash` is what the caller believes the token is about. It is compared against the
/// imprint the token itself carries, because a token about somebody else's document is perfectly
/// valid and perfectly useless as evidence for this one.
pub fn inspect<'a>(blob: &'a [u8], subject_hash: &[u8]) -> Result<Inspected<'a>, EvidenceError> {
    let stored = unpack_blob(blob)?;

    // What we asked, so that what came back can be held to it.
    let (asked_hash, sent_nonce) = read_request(stored.request)?;
    if asked_hash != subject_hash {
        return Err(EvidenceError::Inconsistent(
            "the stored request asked about a different hash from the one this check was given"
                .to_string(),
        ));
    }

    let reply = read_reply(stored.reply)?;
    let token = read_token(reply.token)?;

    if token.hashed_message != subject_hash {
        return Err(EvidenceError::Inconsistent(format!(
            "the token is about a {} byte hash that is not the one asked about, so it is evidence \
             for a different document",
            token.hashed_message.len()
        )));
    }

    match (&token.nonce, &sent_nonce) {
        (Some(returned), Some(sent)) if returned == sent => {}
        (Some(_), Some(_)) => {
            return Err(EvidenceError::WrongNonce(
                "the token carries a different nonce from the one the request sent, so it was not \
                 made for this request"
                    .to_string(),
            ))
        }
        _ => {
            return Err(EvidenceError::WrongNonce(
                "the token carries no nonce, so nothing rules out an authority answering with one \
                 it prepared earlier"
                    .to_string(),
            ))
        }
    }

    let expected_digest = reply.signer.digest.digest(reply.token);
    if reply.signer.message_digest != expected_digest {
        return Err(EvidenceError::Inconsistent(
            "the signed attributes carry a digest that is not the digest of the token they are \
             attached to"
                .to_string(),
        ));
    }
    if reply.signer.content_type != OID_TST_INFO {
        return Err(EvidenceError::Inconsistent(
            "the signed attributes say this is not a timestamp token".to_string(),
        ));
    }

    Ok(Inspected { reply, token })
}

/// Check a stored timestamp token against a pinned certificate and the hash it should be about.
///
/// [`inspect`] followed by [`Inspected::under`], and nothing else, so a validator that runs the two
/// apart runs exactly what the agent runs together.
pub fn check(
    blob: &[u8],
    authority: &Authority,
    subject_hash: &[u8],
) -> Result<Checked, EvidenceError> {
    inspect(blob, subject_hash)?.under(authority)
}

/// Check one signature against one certificate's key.
///
/// The signature is over the signed attributes re-tagged as a set. That re-tagging is in the
/// specification and is easy to leave out; leaving it out makes every signature fail, so it is the
/// one place here where being wrong is loud rather than silent.
fn verify_with(certificate: &[u8], signer: &Signer<'_>) -> Result<(), EvidenceError> {
    let key = read_public_key(certificate)?;
    let signed = der::encode(der::TAG_SET, signer.signed_attributes);
    let digest = signer.signature_hash.digest(&signed);
    let digest_info = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(
                der::TAG_SEQUENCE,
                &[
                    der::encode(der::TAG_OID, signer.signature_hash.oid()),
                    der::encode(der::TAG_NULL, &[]),
                ]
                .concat(),
            ),
            der::encode(der::TAG_OCTET_STRING, &digest),
        ]
        .concat(),
    );
    key.verify(
        Pkcs1v15Sign::new_unprefixed(),
        &digest_info,
        signer.signature,
    )
    .map_err(|_| EvidenceError::BadSignature("the signature does not check out".to_string()))
}

/// Find which certificate inside a token actually signed it, and hash it.
///
/// **This is not a check and must never be used as one.** It answers "who signed this", which is
/// the question you ask once, deliberately, when deciding whether to trust an authority at all. It
/// is what produces the value that then goes into [`Authority::accepted_certificates`]. Using it at
/// verification time would mean accepting whichever key the token brought with it, which is the
/// same as accepting anything at all.
pub fn discover_signing_certificate(blob: &[u8]) -> Result<[u8; 32], EvidenceError> {
    let stored = unpack_blob(blob)?;
    let reply = read_reply(stored.reply)?;
    for certificate in reply.certificates {
        if verify_with(certificate, &reply.signer).is_ok() {
            let mut out = [0u8; 32];
            out.copy_from_slice(&Sha256::digest(certificate));
            return Ok(out);
        }
    }
    Err(EvidenceError::BadSignature(
        "none of the certificates in this token signed it".to_string(),
    ))
}

/// The hash and the nonce a request asked about.
///
/// The fields after the imprint are `reqPolicy`, `nonce`, `certReq` and `extensions`, all optional
/// and all in that order, and this reads them in it. A loop that took whichever integer it saw last
/// would accept a document with two of them, and would take the second, which is not a
/// `TimeStampReq` in any reading of the grammar. Nobody signs a request, so the loosest possible
/// parse of one is the loosest thing in the module.
fn read_request(bytes: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>), EvidenceError> {
    let mut outer = Reader::new(bytes);
    let mut request = outer.sequence("the request")?;
    outer.finished("the request document")?;

    let _version = request.integer("the request version")?;
    let mut imprint = request.sequence("the message imprint")?;
    let mut algorithm = imprint.sequence("the imprint's hash algorithm")?;
    let _oid = algorithm.oid("the hash algorithm")?;
    let hash = imprint.octets("the hashed message")?.to_vec();

    if request.peek_tag() == Some(der::TAG_OID) {
        let _policy = request.oid("the requested policy")?;
    }
    let nonce = if request.peek_tag() == Some(der::TAG_INTEGER) {
        let mut trimmed = request.integer("the nonce")?;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        Some(trimmed.to_vec())
    } else {
        None
    };
    if request.peek_tag() == Some(der::TAG_BOOLEAN) {
        let _cert_req = request.expect(der::TAG_BOOLEAN, "the certificate request flag")?;
    }
    if request.peek_tag() == Some(TAG_REQUEST_EXTENSIONS) {
        let _extensions = request.expect(TAG_REQUEST_EXTENSIONS, "the request extensions")?;
    }
    request.finished("the request")?;

    Ok((hash, nonce))
}

/// `[0] IMPLICIT Extensions`, the last field a `TimeStampReq` may carry.
const TAG_REQUEST_EXTENSIONS: u8 = 0xa0;

/// A reply, split into the three parts a check needs from it.
#[derive(Clone, Debug)]
struct Reply<'a> {
    /// The signed content, which is the token's own information.
    token: &'a [u8],
    /// Every certificate the authority chose to include.
    certificates: Vec<&'a [u8]>,
    /// What the one signer said.
    signer: Signer<'a>,
}

/// What a signer info says, once read.
#[derive(Clone, Debug)]
struct Signer<'a> {
    signed_attributes: &'a [u8],
    message_digest: Vec<u8>,
    content_type: &'a [u8],
    digest: HashFunction,
    signature_hash: HashFunction,
    signature: &'a [u8],
}

/// Pull the token, the certificates and the signer out of a reply.
fn read_reply(bytes: &[u8]) -> Result<Reply<'_>, EvidenceError> {
    let mut outer = Reader::new(bytes);
    let mut response = outer.sequence("the response")?;
    outer.finished("the response document")?;

    // PKIStatusInfo. Zero is granted, one is granted with a change of parameters, and anything else
    // means the authority declined and there is no token to read.
    let mut status_info = response.sequence("the status")?;
    let status = status_info.integer("the status code")?;
    // Read as the signed number the encoding says it is. Folding the bytes into a `u32` meant a
    // five byte status wrapped, so a value chosen to end in four zero bytes read as granted.
    let status_value = der::signed_value(status)?;
    if !(0..=1).contains(&status_value) {
        return Err(EvidenceError::Inconsistent(format!(
            "the authority declined, with status {status_value}"
        )));
    }

    let content_info = response.expect(der::TAG_SEQUENCE, "the token")?;
    let mut ci = response.inner(content_info.value);
    let content_type = ci.oid("the token's content type")?;
    if content_type != OID_SIGNED_DATA {
        return Err(malformed("the token is not signed data"));
    }
    let wrapper = ci.expect(der::context(0), "the signed data wrapper")?;
    let mut wrapped = ci.inner(wrapper.value);
    let mut signed_data = wrapped.sequence("the signed data")?;

    let _version = signed_data.integer("the signed data version")?;
    let _digest_algorithms = signed_data.set("the digest algorithms")?;

    let encapsulated = signed_data.expect(der::TAG_SEQUENCE, "the encapsulated content")?;
    let mut encap = signed_data.inner(encapsulated.value);
    let encap_type = encap.oid("the encapsulated content type")?;
    if encap_type != OID_TST_INFO {
        return Err(malformed(
            "the signed content is not a timestamp token's information",
        ));
    }
    let content_wrapper = encap.expect(der::context(0), "the content wrapper")?;
    let mut content = encap.inner(content_wrapper.value);
    let token_bytes = content.octets("the token information")?;

    let mut certificates = Vec::new();
    let mut signer = None;
    while !signed_data.is_empty() {
        let element = signed_data.take()?;
        if element.tag == der::context(0) {
            let mut list = signed_data.inner(element.value);
            while !list.is_empty() {
                let certificate = list.take()?;
                if certificate.tag == der::TAG_SEQUENCE {
                    certificates.push(certificate.whole);
                }
            }
        } else if element.tag == der::TAG_SET {
            let mut infos = signed_data.inner(element.value);
            let info = infos.sequence("a signer")?;
            signer = Some(read_signer(info)?);
        }
    }

    let signer = signer.ok_or_else(|| malformed("a token with nobody's signature on it"))?;
    Ok(Reply {
        token: token_bytes,
        certificates,
        signer,
    })
}

fn read_signer(mut info: Reader<'_>) -> Result<Signer<'_>, EvidenceError> {
    let _version = info.integer("the signer version")?;
    // The signer identifier: either issuer and serial, or a key identifier. Neither is used to
    // choose the certificate, because the pin does that, so it is stepped over rather than parsed.
    let _identifier = info.take()?;
    let mut digest_algorithm = info.sequence("the signer's digest algorithm")?;
    let digest = HashFunction::from_oid(digest_algorithm.oid("the digest algorithm")?)
        .ok_or_else(|| malformed("a digest algorithm this code does not implement"))?;

    let attributes = info.expect(der::context(0), "the signed attributes")?;
    let signed_attributes = attributes.value;

    let mut message_digest = None;
    let mut content_type = None;
    let mut attrs = info.inner(signed_attributes);
    while !attrs.is_empty() {
        let mut attribute = {
            let element = attrs.expect(der::TAG_SEQUENCE, "an attribute")?;
            attrs.inner(element.value)
        };
        let oid = attribute.oid("an attribute type")?;
        let mut values = attribute.set("an attribute value")?;
        if oid == OID_MESSAGE_DIGEST {
            message_digest = Some(values.octets("the message digest")?.to_vec());
        } else if oid == OID_CONTENT_TYPE {
            content_type = Some(values.oid("the content type")?);
        }
    }

    let mut signature_algorithm = info.sequence("the signature algorithm")?;
    let signature_oid = signature_algorithm.oid("the signature algorithm")?;
    let signature_hash =
        match signature_oid {
            o if o == OID_SHA256_RSA => HashFunction::Sha256,
            o if o == OID_SHA384_RSA => HashFunction::Sha384,
            o if o == OID_SHA512_RSA => HashFunction::Sha512,
            // Plain rsaEncryption is what most authorities put here, and it names no hash at all. In
            // that case the hash is the one the signer already declared for the digest, which is what
            // the enveloping specification says and is easy to miss, because the other spelling names
            // both halves in one identifier.
            o if o == OID_RSA => digest,
            _ => return Err(malformed(
                "a signature algorithm this code does not implement. It knows RSA with SHA-256, \
                 SHA-384 and SHA-512, which is what every authority tried on 2026-09-07 used",
            )),
        };
    let signature = info.octets("the signature")?;

    Ok(Signer {
        signed_attributes,
        message_digest: message_digest
            .ok_or_else(|| malformed("signed attributes with no digest in them"))?,
        content_type: content_type
            .ok_or_else(|| malformed("signed attributes that do not say what was signed"))?,
        digest,
        signature_hash,
        signature,
    })
}

/// The line a reader is shown about what the token states of itself.
///
/// Two sentences rather than one with a number spliced into it, and its own function because the
/// one thing it has to get right is the difference between a figure the authority wrote and a
/// figure nobody wrote. Until 2026-09-19 an unstated accuracy was printed as "0 ns", which reads
/// as an authority vouching for a perfect time when what it did was decline to say anything.
fn what_the_token_states(
    authority: &str,
    saw_it_at: i128,
    accuracy: Option<Nanos>,
    resolution: Nanos,
    allowance: Option<Nanos>,
) -> String {
    match (accuracy, allowance) {
        (Some(stated), _) => format!(
            "{authority} states it saw this hash at {saw_it_at} s, to a stated accuracy of \
             {stated} ns and written to the nearest {resolution} ns, so the document existed no \
             later than that"
        ),
        (None, Some(allowed)) => format!(
            "{authority} states it saw this hash at {saw_it_at} s, written to the nearest \
             {resolution} ns, and states no accuracy of its own, so the {allowed} ns allowed for \
             its clock here is this reader's figure from the authority's published practice and \
             is not anything the authority signed"
        ),
        (None, None) => format!(
            "{authority} states it saw this hash at {saw_it_at} s, written to the nearest \
             {resolution} ns, with its accuracy not stated, so the token puts the document no \
             later than that on the authority's own clock, and nothing here puts a number on how \
             wrong that clock could be, so it bounds nothing in UTC"
        ),
    }
}

/// Read a token's own information, holding it to the field order the specification fixes.
///
/// The order after the time it was made is accuracy, then the ordering flag, then the nonce, then
/// the authority's own name, then extensions, and every one of them is optional. Walking whatever
/// is left and taking the last integer as the nonce reads a different document from the one that
/// was signed: a second integer sitting after the first becomes the nonce, and a tag the walk does
/// not recognise disappears without anything being said about it. So each field is taken where it
/// belongs and the rest is refused, which is the same shape the request reader was put into.
fn read_token(bytes: &[u8]) -> Result<Token<'_>, EvidenceError> {
    let mut outer = Reader::new(bytes);
    let mut token = outer.sequence("the token information")?;
    outer.finished("the token document")?;

    let _version = token.integer("the token version")?;
    let _policy = token.oid("the policy")?;

    let mut imprint = token.sequence("the message imprint")?;
    let mut algorithm = imprint.sequence("the imprint's hash algorithm")?;
    let hash = HashFunction::from_oid(algorithm.oid("the hash algorithm")?)
        .ok_or_else(|| malformed("an imprint hashed with an algorithm this code does not know"))?;
    let hashed_message = imprint.octets("the hashed message")?;
    // A name is free to write and a length is arithmetic, so the two are held to each other here,
    // before anything is printed about either. A token naming SHA-512 over a thirty-two byte
    // imprint is saying something impossible about itself, and it says it inside the signature, so
    // the authority signed the contradiction rather than a forger inserting it later.
    if hashed_message.len() != hash.length() {
        return Err(EvidenceError::Inconsistent(format!(
            "the token names {} and carries an imprint of {} bytes, and {} produces {}",
            hash.name(),
            hashed_message.len(),
            hash.name(),
            hash.length()
        )));
    }

    let serial = token.integer("the serial number")?.to_vec();
    let generalized = token.expect(der::TAG_GENERALIZED_TIME, "the time it was made")?;
    let (generated_at, resolution) = read_generalized_time(generalized.value)?;

    let accuracy = if token.peek_tag() == Some(der::TAG_SEQUENCE) {
        let stated = token.expect(der::TAG_SEQUENCE, "the stated accuracy")?;
        read_accuracy(&token, stated.value)?
    } else {
        // The field is absent, so the authority said nothing about its own error. That is not the
        // same statement as an accuracy of zero and it is no longer carried as one.
        None
    };
    let ordering = if token.peek_tag() == Some(der::TAG_BOOLEAN) {
        let flag = token.expect(der::TAG_BOOLEAN, "the ordering flag")?;
        read_boolean(flag.value)?
    } else {
        false
    };
    let nonce = if token.peek_tag() == Some(der::TAG_INTEGER) {
        let mut trimmed = token.integer("the nonce")?;
        while trimmed.len() > 1 && trimmed[0] == 0 {
            trimmed = &trimmed[1..];
        }
        Some(trimmed.to_vec())
    } else {
        None
    };
    if token.peek_tag() == Some(TAG_TOKEN_AUTHORITY_NAME) {
        let _tsa = token.expect(TAG_TOKEN_AUTHORITY_NAME, "the authority's own name")?;
    }
    if token.peek_tag() == Some(TAG_TOKEN_EXTENSIONS) {
        let _extensions = token.expect(TAG_TOKEN_EXTENSIONS, "the token extensions")?;
    }
    token.finished("the token information")?;

    Ok(Token {
        hashed_message,
        hash,
        generated_at,
        accuracy,
        resolution,
        ordering,
        nonce,
        serial,
    })
}

/// `[0] GeneralName`, the authority's own idea of what it is called. Carried and not read: the
/// certificate the signature checks against is what says who signed, and a name inside the token is
/// the signer describing itself.
const TAG_TOKEN_AUTHORITY_NAME: u8 = der::context(0);

/// `[1] IMPLICIT Extensions`, the last field a `TSTInfo` may carry.
const TAG_TOKEN_EXTENSIONS: u8 = der::context(1);

/// Read a DER boolean, which is one byte and has exactly two spellings.
///
/// The looser encoding treats any non-zero byte as true, and that gives a document two spellings of
/// the same statement. Here the statement moves what the receipt prints about ordering, so it is
/// read strictly and a byte that is neither is refused rather than guessed at.
///
/// A flag written out as false is accepted even though the strict encoding would leave it out
/// altogether. It says the same thing as its absence, some authorities write it, and refusing a
/// token over it would throw away evidence that is signed and correct in every way that matters.
fn read_boolean(value: &[u8]) -> Result<bool, EvidenceError> {
    match value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(malformed(
            "a flag that is neither true nor false as this encoding spells them",
        )),
    }
}

/// Whether a stored token's authority claims its own tokens are ordered by their stated times.
///
/// Reads the flag out of a blob that has already been checked, so the caller can put the claim in
/// front of a person reading the receipt. It says nothing about whether the claim is true.
pub fn orders_by_stated_time(blob: &[u8]) -> Result<bool, EvidenceError> {
    let stored = unpack_blob(blob)?;
    let reply = read_reply(stored.reply)?;
    Ok(read_token(reply.token)?.ordering)
}

/// The accuracy an authority states, in nanoseconds, taken as the whole of it.
///
/// Three optional fields, seconds, milliseconds and microseconds, and an authority that states none
/// of them is saying it will not put a number on its own error. That comes back as `None`, which is
/// the absence itself rather than a guess at what it is worth, so a caller printing the figure has
/// something to print other than a zero nobody wrote. An authority that does write a zero into one
/// of the three fields has stated a figure, and it comes back as `Some(0)`: it is a strange thing
/// for an authority to say, and it said it.
///
/// Two things here are refusals rather than corrections, and both are because this figure only ever
/// moves the not-later-than edge inwards.
///
/// A negative accuracy is refused by name. An authority cannot be accurate to less than nothing, so
/// a token stating minus one hour is a token stating something impossible, and clamping it to zero
/// would take a document that says something impossible and quietly make it say something usable.
/// That is the tightening direction, which is the one the rules on evidence forbid.
///
/// An accuracy too large for the arithmetic is refused rather than saturated, for the same reason
/// in reverse: a saturated figure is a number nobody wrote, presented as one the authority signed.
fn read_accuracy(parent: &Reader<'_>, bytes: &[u8]) -> Result<Option<Nanos>, EvidenceError> {
    let mut reader = parent.inner(bytes);
    let mut total: Nanos = 0;
    // Whether any of the three fields was there at all. An empty sequence, and a sequence holding
    // only tags this code does not read, are both an authority stating no accuracy, and they are
    // answered the same way as the field being absent altogether.
    let mut stated = false;
    while !reader.is_empty() {
        let element = reader.take()?;
        let scale: Nanos = match element.tag {
            der::TAG_INTEGER => NANOS_PER_SEC,
            t if t == der::context_primitive(0) => 1_000_000,
            t if t == der::context_primitive(1) => 1_000,
            _ => continue,
        };
        let value = der::signed_value(element.value)?;
        if value < 0 {
            return Err(malformed(format!(
                "a stated accuracy of {value}, and an authority cannot be accurate to less than nothing"
            )));
        }
        total = value
            .checked_mul(scale)
            .and_then(|scaled| total.checked_add(scaled))
            .ok_or_else(|| malformed("a stated accuracy too large for any arithmetic to hold"))?;
        stated = true;
    }
    Ok(stated.then_some(total))
}

/// A generalized time, in the one form the specification allows for a token, and how finely it was
/// written.
///
/// `YYYYMMDDHHMMSS[.fff]Z`, always UTC, always with the seconds present. Local time and offsets are
/// not accepted, because a timestamp whose zone has to be guessed at is not a timestamp.
///
/// The second value is the resolution: a second where no fraction was written, and a tenth, a
/// hundredth or a thousandth of that for each digit after the point, down to a nanosecond. It is
/// returned rather than thrown away because the caller is building an interval, and a time written
/// to whole seconds names a second rather than an instant.
fn read_generalized_time(bytes: &[u8]) -> Result<(UnixNanos, Nanos), EvidenceError> {
    let text =
        core::str::from_utf8(bytes).map_err(|_| malformed("a time that is not even text"))?;
    let text = text
        .strip_suffix('Z')
        .ok_or_else(|| malformed(format!("a time {text:?} that is not stated in UTC")))?;
    let (date_time, fraction) = match text.split_once('.') {
        Some((a, b)) => (a, b),
        None => (text, ""),
    };
    if date_time.len() != 14 || !date_time.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(format!(
            "a time {date_time:?} that is not fourteen digits of date and time"
        )));
    }
    let number = |from: usize, to: usize| -> i64 { date_time[from..to].parse().unwrap_or(0) };
    let (year, month, day) = (number(0, 4), number(4, 6), number(6, 8));
    let (hour, minute, second) = (number(8, 10), number(10, 12), number(12, 14));
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(malformed(format!(
            "a time {date_time:?} that is not a time anybody could have"
        )));
    }

    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;

    // A fraction of a second, to at most nanoseconds. Anything finer is dropped rather than rounded,
    // which moves the stated moment earlier, and earlier is the direction that does not weaken a
    // not-later-than edge.
    let mut nanos: i128 = 0;
    let mut digits = 0u32;
    for (i, digit) in fraction.bytes().take(9).enumerate() {
        if !digit.is_ascii_digit() {
            return Err(malformed("a fraction of a second that is not digits"));
        }
        nanos += i128::from(digit - b'0') * 10i128.pow(8 - i as u32);
        digits = u32::try_from(i).unwrap_or(0) + 1;
    }

    // A fraction longer than nine digits is read to nanoseconds and no further, so the resolution
    // stops at one nanosecond rather than claiming something the arithmetic cannot hold.
    let resolution = 10i128.pow(9 - digits.min(9));

    Ok((
        UnixNanos(i128::from(seconds) * NANOS_PER_SEC + nanos),
        resolution,
    ))
}

/// Days from the Unix epoch to a civil date, by Howard Hinnant's algorithm.
///
/// Written out rather than pulled in, because it is twelve lines and a date library is a dependency
/// on somebody else's idea of what a calendar is.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Pull the RSA public key out of a certificate.
///
/// Only the subject public key information is read. Everything else in a certificate is about who
/// the holder is and what they are allowed to do, and this code makes no claim about either: it says
/// the token was signed by the key in the certificate you pinned, which is a statement about a key.
fn read_public_key(certificate: &[u8]) -> Result<RsaPublicKey, EvidenceError> {
    let mut outer = Reader::new(certificate);
    let mut cert = outer.sequence("the certificate")?;
    let mut body = cert.sequence("the certificate body")?;

    // Version is optional and tagged; skip it where it is there.
    if body.peek_tag() == Some(der::context(0)) {
        let _ = body.take()?;
    }
    let _serial = body.integer("the certificate serial")?;
    let _signature_algorithm = body.sequence("the certificate's signature algorithm")?;
    let _issuer = body.take()?;
    let _validity = body.take()?;
    let _subject = body.take()?;

    let mut spki = body.sequence("the subject public key information")?;
    let mut algorithm = spki.sequence("the key's algorithm")?;
    let algorithm_oid = algorithm.oid("the key algorithm")?;
    if algorithm_oid != OID_RSA {
        return Err(malformed(
            "a certificate holding a key that is not RSA. This code implements RSA, which is what \
             every authority tried on 2026-09-07 used",
        ));
    }
    let bits = spki.expect(der::TAG_BIT_STRING, "the key")?;
    if bits.value.first() != Some(&0) {
        return Err(malformed(
            "a key whose bit string is not a whole number of bytes",
        ));
    }
    let mut key_reader = spki.inner(&bits.value[1..]);
    let mut key = key_reader.sequence("the key")?;
    let modulus = key.integer("the modulus")?;
    let exponent = key.integer("the exponent")?;

    RsaPublicKey::new(
        BigUint::from_bytes_be(modulus),
        BigUint::from_bytes_be(exponent),
    )
    .map_err(|e| malformed(format!("a certificate whose key will not load: {e}")))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The timestamp authorities whose signing certificates ship with this code.
///
/// Two free authorities, each proved end to end on 2026-09-07. Two others were tried and are not
/// here: one signs with ECDSA, which this code does not implement and refuses by name rather than
/// skipping, and one answered from three different signing certificates in four requests.
///
/// Pinned rather than chained to a commercial root, which is narrower than trusted and is the
/// honest description of what this code does. A pin goes stale for fetching new tokens when a
/// certificate rotates; tokens already issued stay checkable, because the certificate travels
/// inside them.
///
/// They are here rather than beside the client for the same reason the Roughtime keys are: a
/// verifier needs them and may not import the client that fetches.
///
/// **None of these is a qualified trust service and none of these tokens carries legal weight.**
/// A timestamp from a free authority is a third party's signed statement about what it saw and
/// when, which is what the not-later-than role needs. It is not a legal instrument and no legal
/// weight is claimed.
#[must_use]
pub fn published_authorities() -> Vec<Authority> {
    vec![
        Authority {
            name: "DigiCert".to_string(),
            url: "http://timestamp.digicert.com".to_string(),
            accepted_certificates: vec![[
                0x2d, 0xa0, 0x9d, 0xa7, 0xf4, 0x13, 0x1f, 0x9f, 0xe7, 0x2d, 0xb6, 0xc5, 0xe6, 0xe9,
                0xc9, 0x65, 0x67, 0x55, 0xaf, 0x04, 0x3f, 0x1e, 0xa7, 0x42, 0xcc, 0x0d, 0x21, 0x20,
                0xe1, 0x41, 0xeb, 0xfc,
            ]],
            accuracy_where_the_token_states_none: None,
        },
        Authority {
            name: "Sectigo".to_string(),
            url: "http://timestamp.sectigo.com".to_string(),
            accepted_certificates: vec![[
                0xd1, 0x47, 0x51, 0xba, 0x71, 0xcd, 0x88, 0x83, 0xe5, 0x60, 0x16, 0x64, 0x06, 0xcf,
                0x62, 0xcd, 0x22, 0x9a, 0x5f, 0xe9, 0x1e, 0x30, 0x8d, 0x30, 0x19, 0x76, 0xfe, 0xb2,
                0x3e, 0xa9, 0x01, 0x56,
            ]],
            accuracy_where_the_token_states_none: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::OID_SHA512;

    #[test]
    fn the_blob_round_trips_and_a_wrong_length_is_refused() {
        let packed = pack_blob(b"ask", b"answer");
        let stored = unpack_blob(&packed).expect("what we packed unpacks");
        assert_eq!(stored.request, b"ask");
        assert_eq!(stored.reply, b"answer");
        let mut truncated = packed;
        truncated.pop();
        assert!(matches!(
            unpack_blob(&truncated),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn a_request_this_code_builds_reads_back_as_the_hash_and_nonce_it_was_given() {
        let hash = [3u8; 32];
        let nonce = [0x9au8; 16];
        let request = build_request(&hash, &nonce);
        let (read_hash, read_nonce) = read_request(&request).expect("our own request parses");
        assert_eq!(read_hash, hash);
        assert_eq!(read_nonce.as_deref(), Some(&nonce[..]));
    }

    #[test]
    fn a_request_carrying_two_nonces_is_refused_rather_than_read_to_the_last_one() {
        // Nobody signs a request, so a holder writes whatever it likes into one. What that must not
        // buy is a second nonce sitting after the first and being the one that gets compared.
        let imprint = der::encode(
            der::TAG_SEQUENCE,
            &[
                der::encode(
                    der::TAG_SEQUENCE,
                    &[
                        der::encode(der::TAG_OID, OID_SHA256),
                        der::encode(der::TAG_NULL, &[]),
                    ]
                    .concat(),
                ),
                der::encode(der::TAG_OCTET_STRING, &[3u8; 32]),
            ]
            .concat(),
        );
        let two_nonces = der::encode(
            der::TAG_SEQUENCE,
            &[
                der::encode(der::TAG_INTEGER, &[1]),
                imprint.clone(),
                der::encode(der::TAG_INTEGER, &[0xaau8; 16]),
                der::encode(der::TAG_BOOLEAN, &[0xff]),
                der::encode(der::TAG_INTEGER, &[0x11u8; 16]),
            ]
            .concat(),
        );
        assert!(
            read_request(&two_nonces).is_err(),
            "a document with two integers after the imprint is not a timestamp request"
        );

        // Every field the grammar allows, in the order it allows them, still reads.
        let full = der::encode(
            der::TAG_SEQUENCE,
            &[
                der::encode(der::TAG_INTEGER, &[1]),
                imprint,
                der::encode(der::TAG_OID, OID_SHA256),
                der::encode(der::TAG_INTEGER, &[0x11u8; 16]),
                der::encode(der::TAG_BOOLEAN, &[0xff]),
                der::encode(TAG_REQUEST_EXTENSIONS, &[]),
            ]
            .concat(),
        );
        let (hash, nonce) = read_request(&full).expect("a request using every optional field");
        assert_eq!(hash, [3u8; 32]);
        assert_eq!(nonce.as_deref(), Some(&[0x11u8; 16][..]));
    }

    #[test]
    fn a_token_naming_one_hash_and_carrying_another_length_is_refused_with_both_numbers() {
        // The imprint is thirty-two bytes and the token says SHA-512, which is sixty-four. The
        // bytes are the ones a real SHA-256 subject hash would be, so byte equality with the
        // subject holds and only the arithmetic catches it.
        let algorithm = der::encode(der::TAG_SEQUENCE, &der::encode(der::TAG_OID, OID_SHA512));
        let mut imprint = algorithm;
        imprint.extend(der::encode(der::TAG_OCTET_STRING, &[7u8; 32]));

        let mut info = der::encode(der::TAG_INTEGER, &[1]);
        info.extend(der::encode(der::TAG_OID, OID_SHA256));
        info.extend(der::encode(der::TAG_SEQUENCE, &imprint));
        info.extend(der::encode(der::TAG_INTEGER, &[0x2a]));
        info.extend(der::encode(der::TAG_GENERALIZED_TIME, b"20260907174532Z"));
        let bytes = der::encode(der::TAG_SEQUENCE, &info);

        let said = match read_token(&bytes) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a SHA-512 label over thirty-two bytes was accepted"),
        };
        assert!(
            said.contains("32") && said.contains("64") && said.contains("SHA-512"),
            "the refusal has to name both numbers and it says {said:?}"
        );

        // And the three lengths this code knows are the receipt format's own lengths, rather than a
        // second table written out beside them.
        for f in [
            HashFunction::Sha256,
            HashFunction::Sha384,
            HashFunction::Sha512,
        ] {
            assert_eq!(f.digest(b"whatever").len(), f.length());
        }
    }

    #[test]
    fn the_calendar_agrees_with_dates_anybody_can_check() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 9, 7), 20_703);
    }

    #[test]
    fn a_generalized_time_reads_as_the_instant_it_names() {
        let (t, _) = read_generalized_time(b"20260907174532Z").expect("a plain time");
        assert_eq!(t.as_nanos() / NANOS_PER_SEC, 1_788_803_132);
        let (with_fraction, _) = read_generalized_time(b"20260907174532.25Z").expect("a fraction");
        assert_eq!(
            with_fraction.as_nanos() - t.as_nanos(),
            250_000_000,
            "a quarter of a second"
        );
    }

    /// A time is read with the width of the thing it names, not only with its value.
    ///
    /// The whole of the whole-seconds fault in one function. A token written to whole seconds names
    /// a second, and taking it for an instant put a not-later-than edge up to a second earlier than
    /// anything the authority committed to. That was invisible while our own bound was seconds wide
    /// and it refused a real receipt on a real repository the day the bound came down to 240 ms.
    #[test]
    fn a_time_carries_how_finely_it_was_written() {
        let cases: [(&[u8], i128); 6] = [
            (b"20260907174532Z", 1_000_000_000),
            (b"20260907174532.5Z", 100_000_000),
            (b"20260907174532.25Z", 10_000_000),
            (b"20260907174532.250Z", 1_000_000),
            (b"20260907174532.250000000Z", 1),
            // Finer than the arithmetic holds. The extra digits are dropped, so the resolution
            // stops at a nanosecond rather than claiming something that was not kept.
            (b"20260907174532.2500000009Z", 1),
        ];
        for (text, expected) in cases {
            let (_, resolution) = read_generalized_time(text).expect("a time");
            assert_eq!(
                resolution,
                expected,
                "{:?} was read as naming {resolution} ns",
                core::str::from_utf8(text).unwrap_or("")
            );
        }
    }

    /// A whole timestamp token with whatever accuracy the caller wants stated in it.
    ///
    /// Nothing here is signed and nothing needs to be. `read_token` runs before the certificate pin
    /// and before the signature is verified, so everything it does with these bytes is done for a
    /// stranger holding no key at all, which is what makes this the reachable half of the surface.
    fn token_stating_accuracy(accuracy: &[u8]) -> Vec<u8> {
        token_with(accuracy, &[])
    }

    /// The same token with the optional accuracy field left out altogether, which is what an
    /// authority that will not put a number on its own error actually sends.
    fn token_with_no_accuracy_field() -> Vec<u8> {
        let mut info = token_head();
        info.extend(der::encode(der::TAG_INTEGER, &[0x2a]));
        info.extend(der::encode(der::TAG_GENERALIZED_TIME, b"20260907174532Z"));
        der::encode(der::TAG_SEQUENCE, &info)
    }

    /// Everything a token carries before its serial number, which the two builders share.
    fn token_head() -> Vec<u8> {
        let algorithm = der::encode(der::TAG_SEQUENCE, &der::encode(der::TAG_OID, OID_SHA256));
        let mut imprint = algorithm;
        imprint.extend(der::encode(der::TAG_OCTET_STRING, &[7u8; 32]));

        let mut info = der::encode(der::TAG_INTEGER, &[1]);
        // Any policy identifier will do; the reader carries it and does not look at it.
        info.extend(der::encode(der::TAG_OID, OID_SHA256));
        info.extend(der::encode(der::TAG_SEQUENCE, &imprint));
        info
    }

    /// The same token, with whatever the caller wants written after the accuracy.
    ///
    /// The specification fixes what may follow and in what order, so this is where a token that
    /// breaks the order, repeats a field or carries a tag nobody expected gets built.
    fn token_with(accuracy: &[u8], trailing: &[u8]) -> Vec<u8> {
        let mut info = token_head();
        info.extend(der::encode(der::TAG_INTEGER, &[0x2a]));
        info.extend(der::encode(der::TAG_GENERALIZED_TIME, b"20260907174532Z"));
        info.extend(der::encode(der::TAG_SEQUENCE, accuracy));
        info.extend_from_slice(trailing);

        der::encode(der::TAG_SEQUENCE, &info)
    }

    #[test]
    fn a_token_carrying_two_nonces_is_refused_rather_than_read_to_the_last_one() {
        // The same defect the request reader had, on the half of the pair that is signed. A signed
        // field can still be read wrongly: the authority put its name to one nonce, and a reader
        // that walks to the end and keeps the last integer it saw prints whichever one a holder
        // appended. That the bytes are signed says who wrote them, not that they were read right.
        let mut trailing = der::encode(der::TAG_INTEGER, &[0xaau8; 16]);
        trailing.extend(der::encode(der::TAG_INTEGER, &[0x11u8; 16]));
        let bytes = token_with(&[], &trailing);
        assert!(
            read_token(&bytes).is_err(),
            "a second nonce after the first was accepted"
        );

        // And one nonce still reads as itself.
        let one = token_with(&[], &der::encode(der::TAG_INTEGER, &[0xaau8; 16]));
        let token = read_token(&one).expect("one nonce");
        assert_eq!(token.nonce.as_deref(), Some(&[0xaau8; 16][..]));
    }

    #[test]
    fn a_token_whose_fields_run_out_of_order_is_refused() {
        // Nonce before the ordering flag, which is the order the specification does not allow.
        let mut backwards = der::encode(der::TAG_INTEGER, &[0xaau8; 16]);
        backwards.extend(der::encode(der::TAG_BOOLEAN, &[0xff]));
        assert!(
            read_token(&token_with(&[], &backwards)).is_err(),
            "fields out of order were accepted"
        );

        // A tag no field of a token uses, which the walking reader dropped in silence.
        assert!(
            read_token(&token_with(
                &[],
                &der::encode(der::TAG_OCTET_STRING, &[1, 2])
            ))
            .is_err(),
            "a tag no token field uses was accepted and thrown away"
        );
    }

    #[test]
    fn what_an_authority_says_about_ordering_its_own_tokens_is_kept() {
        // Absent, which is the ordinary case and is the weaker of the two statements.
        let silent = token_with(&[], &[]);
        assert!(
            !read_token(&silent)
                .expect("a token stating nothing")
                .ordering
        );

        // Written out as false, which says the same thing and which some authorities write.
        let says_false = token_with(&[], &der::encode(der::TAG_BOOLEAN, &[0x00]));
        assert!(
            !read_token(&says_false)
                .expect("a token stating false")
                .ordering
        );

        // And set, which is the claim worth carrying into the receipt.
        let mut ordered = der::encode(der::TAG_BOOLEAN, &[0xff]);
        ordered.extend(der::encode(der::TAG_INTEGER, &[0xaau8; 16]));
        let says_true = token_with(&[], &ordered);
        let token = read_token(&says_true).expect("a token stating true");
        assert!(token.ordering);
        assert_eq!(token.nonce.as_deref(), Some(&[0xaau8; 16][..]));

        // A byte that is neither spelling is refused rather than read as true.
        assert!(
            read_token(&token_with(&[], &der::encode(der::TAG_BOOLEAN, &[0x01]))).is_err(),
            "a flag that is neither true nor false was accepted"
        );
    }

    #[test]
    fn a_wide_status_does_not_wrap_into_granted() {
        // Five bytes ending in four zeroes. Folded into a `u32` the top byte shifts out and the
        // authority's refusal reads as a grant.
        let refusal = der::encode(
            der::TAG_SEQUENCE,
            &der::encode(
                der::TAG_SEQUENCE,
                &der::encode(der::TAG_INTEGER, &[0x01, 0, 0, 0, 0]),
            ),
        );
        let said = match read_reply(&refusal) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a five byte status was read as a grant"),
        };
        assert!(
            said.contains("declined"),
            "the refusal should say the authority declined and it says {said:?}"
        );
    }

    #[test]
    fn a_token_stating_a_negative_accuracy_is_refused_by_name() {
        // Minus one second, written the way an authority would have to write it to get past a
        // reader folding the body as a magnitude: sixteen bytes of two's complement.
        let seconds = der::encode(der::TAG_INTEGER, &[0xffu8; 16]);
        let bytes = token_stating_accuracy(&seconds);
        let said = match read_token(&bytes) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an accuracy of minus one second is not a smaller accuracy"),
        };
        assert!(
            said.contains("accuracy"),
            "the refusal should name the accuracy and it says {said:?}"
        );

        // And an authority stating a negative figure in any of the three fields, not only seconds.
        for tag in [der::context_primitive(0), der::context_primitive(1)] {
            let field = der::encode(tag, &[0xffu8; 16]);
            assert!(
                read_token(&token_stating_accuracy(&field)).is_err(),
                "a negative figure in the field tagged {tag:#04x} was accepted"
            );
        }
    }

    #[test]
    fn a_token_stating_an_accuracy_too_large_to_hold_is_refused_rather_than_wrapped() {
        // A sixteen byte seconds figure multiplied by a thousand million overflows an i128. In a
        // debug build that was a panic and in a release build it wrapped silently into a negative
        // accuracy, which is the worst of both.
        let mut huge = vec![0x7fu8];
        huge.extend([0xffu8; 15]);
        let seconds = der::encode(der::TAG_INTEGER, &huge);
        assert!(
            read_token(&token_stating_accuracy(&seconds)).is_err(),
            "an accuracy no arithmetic can hold was accepted"
        );
    }

    #[test]
    fn an_ordinary_accuracy_still_reads_as_the_figure_it_states() {
        // Two hundred and fifty is written with a leading zero, because DER integers are signed
        // and a bare 0xfa is minus six.
        let mut stated = der::encode(der::TAG_INTEGER, &[1]);
        stated.extend(der::encode(der::context_primitive(0), &[0x00, 250]));
        stated.extend(der::encode(der::context_primitive(1), &[100]));
        let bytes = token_stating_accuracy(&stated);
        let token = read_token(&bytes).expect("an honest accuracy");
        assert_eq!(token.accuracy, Some(NANOS_PER_SEC + 250_000_000 + 100_000));
    }

    #[test]
    fn an_authority_stating_no_accuracy_at_all_is_not_answered_with_zero() {
        // The field is there and says nothing. Until 2026-09-19 this read as an accuracy of zero,
        // and zero is a figure: a reader was shown "0 ns" where the authority had put no number on
        // its own error at all. The absence is carried as itself now.
        let bytes = token_stating_accuracy(&[]);
        let token = read_token(&bytes).expect("no accuracy stated");
        assert_eq!(token.accuracy, None);
    }

    #[test]
    fn a_token_with_no_accuracy_field_at_all_reads_the_same_way() {
        // The other spelling of the same statement, and the one a real authority uses: the optional
        // field is simply not written. Both come back as nothing stated, because both are.
        let bytes = token_with_no_accuracy_field();
        let token = read_token(&bytes).expect("no accuracy field");
        assert_eq!(token.accuracy, None);
    }

    #[test]
    fn an_unstated_accuracy_is_printed_as_words_and_never_as_a_figure() {
        let line = what_the_token_states("DigiCert", 1_788_979_279, None, NANOS_PER_SEC, None);
        assert!(
            line.contains("accuracy not stated"),
            "the line should say the accuracy was not stated and it says {line:?}"
        );
        assert!(
            !line.contains("accuracy of 0 ns"),
            "a figure nobody wrote is still in the line: {line:?}"
        );
    }

    #[test]
    fn a_stated_accuracy_is_still_printed_as_the_figure_the_authority_wrote() {
        let line = what_the_token_states(
            "DigiCert",
            1_788_979_279,
            Some(250_000_000),
            1_000_000,
            None,
        );
        assert!(
            line.contains("to a stated accuracy of 250000000 ns"),
            "the stated figure should be shown and the line says {line:?}"
        );
        assert!(
            !line.contains("not stated"),
            "an authority that stated a figure is not shown as silent: {line:?}"
        );
    }

    #[test]
    fn an_authority_writing_a_zero_into_a_field_has_stated_a_figure() {
        // The one case the two states have to be told apart on. An authority that writes seconds
        // of zero has said something, strange as it is, and it comes back as the figure it wrote
        // rather than as silence.
        let stated = der::encode(der::TAG_INTEGER, &[0]);
        let bytes = token_stating_accuracy(&stated);
        let token = read_token(&bytes).expect("a stated zero");
        assert_eq!(token.accuracy, Some(0));
    }

    #[test]
    fn a_time_without_a_zone_is_refused_rather_than_assumed_to_be_utc() {
        assert!(read_generalized_time(b"20260907174532").is_err());
        assert!(read_generalized_time(b"20260907174532+0200").is_err());
        assert!(read_generalized_time(b"2026090717Z").is_err());
        assert!(read_generalized_time(b"20261307174532Z").is_err());
    }

    #[test]
    fn no_input_of_any_length_takes_the_parser_down() {
        let authority = Authority {
            name: "nobody".to_string(),
            url: "http://127.0.0.1:1".to_string(),
            accepted_certificates: vec![[0u8; 32]],
            accuracy_where_the_token_states_none: None,
        };
        let mut seed = 0x2026_0907_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for length in 0..400usize {
            let bytes: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
            let _ = unpack_blob(&bytes);
            let _ = check(&bytes, &authority, &[0u8; 32]);
            let _ = read_request(&bytes);
            let _ = read_token(&bytes);
            let _ = read_public_key(&bytes);
        }
    }
}
