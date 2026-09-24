//! A stored token held to one spelling, so that no byte of it is free.
//!
//! A token's own signature covers the token's information and the signed attributes, and nothing
//! else. The reply it arrives in carries a good deal more: a status, version numbers, the names of
//! algorithms, the signer's identifier and the certificates, and the request stored beside it is
//! signed by nobody at all. Inside a receipt's signed body none of that matters, because the
//! receipt's own signature covers the whole stored token. The witness over a receipt's signature
//! sits outside that signature, so there each of those bytes was free: on 2026-09-24, 5,078 of
//! 16,012 one-bit changes to a fresh receipt still verified, and every one of them was inside the
//! witness.
//!
//! So a witness is held to the one spelling its bound parts allow. The parts a signature or a hash
//! covers are read out of the stored token, the token is written again around them in a fixed form,
//! and the two have to be the same bytes. What binds each part:
//!
//! - The token's information, by the digest inside the signed attributes.
//! - The signed attributes, by the signature, which is checked here under the certificate they
//!   name. That is the token held to itself and not trust in the authority: whether a reader trusts
//!   that certificate is still the pin's question, and is still answered by the pin.
//! - Every certificate, by its hash in the signed attributes. The signing certificate attribute
//!   names the signer first and may name the rest of the chain after it. A certificate it does not
//!   name is refused, with the one exception below, and so is one it names that is not there.
//!   Where it names more than one, they are carried in the order it names them.
//! - The signer's identifier, by being written from the named certificate's own issuer and serial.
//! - The request, by being written again from the hash it has to ask about and the nonce inside
//!   the signed token.
//! - Everything else, the status, the versions, the algorithm names and every length, by having one
//!   allowed value.
//!
//! **The exception, and why it is closed.** DigiCert names only its signing certificate, and sends
//! two more beside it: the authority that issued it, and a root cross-signed by an older root whose
//! certificate it does not send. Nothing in the token binds those two, and nothing a reader holds
//! could check the second. Every DigiCert witness written so far came from the one DigiCert signing
//! certificate this code pins, with those two beside it. So for that signer, and no other, the two
//! are part of the one spelling, by their SHA-256 and in that order after the signer: a witness it
//! signed carries both, and a witness any other certificate signed carries what its signature names
//! and nothing else. That keeps every witness already issued as it was and still gives each witness
//! exactly one spelling. When DigiCert moves to another signing certificate, the list does not move
//! with it, and the stamp stores only what the new one names.

use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::{
    build_request, pack_blob, read_reply, read_token, unpack_blob, verify_with, Reply, OID_RSA,
    OID_SIGNED_DATA, OID_TST_INFO,
};
use crate::evidence::der::{self, Reader};
use crate::evidence::EvidenceError;
use crate::hash::HashFunction;

/// `id-aa-signingCertificate`, 1.2.840.113549.1.9.16.2.12, which names certificates by SHA-1.
const OID_SIGNING_CERTIFICATE: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0c,
];
/// `id-aa-signingCertificateV2`, 1.2.840.113549.1.9.16.2.47, which names them by a hash it states.
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x2f,
];

/// The status of a granted reply, in the one form it takes: granted, and nothing said beside it.
const GRANTED: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x00];

/// The DigiCert signing certificate this code pins, `DigiCert SHA256 RSA4096 Timestamp Responder
/// 2026 1`, by SHA-256. It is the only signer whose witnesses carry certificates their signature
/// does not name: see the module comment.
const DIGICERT_RESPONDER: [u8; 32] = [
    0x2d, 0xa0, 0x9d, 0xa7, 0xf4, 0x13, 0x1f, 0x9f, 0xe7, 0x2d, 0xb6, 0xc5, 0xe6, 0xe9, 0xc9, 0x65,
    0x67, 0x55, 0xaf, 0x04, 0x3f, 0x1e, 0xa7, 0x42, 0xcc, 0x0d, 0x21, 0x20, 0xe1, 0x41, 0xeb, 0xfc,
];

/// The two certificates DigiCert sends unnamed beside that signing certificate, by SHA-256.
///
/// Its issuing authority, `DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1`, then
/// `DigiCert Trusted Root G4` as cross-signed by `DigiCert Assured ID Root CA`. Read on 2026-09-24
/// off the witness in `crates/verify/tests/data/a-version-1-stamp` and off two live DigiCert
/// replies the same day, which carried the same two in the same order.
const DIGICERT_UNNAMED: [[u8; 32]; 2] = [
    [
        0xca, 0x0b, 0x15, 0x54, 0xec, 0xd9, 0x01, 0xea, 0x19, 0xdc, 0xad, 0x87, 0x49, 0xe9, 0xf2,
        0x64, 0x8c, 0x8d, 0x6d, 0xfc, 0xea, 0x1a, 0xdd, 0x9d, 0x2c, 0x21, 0x09, 0x41, 0x5b, 0xb8,
        0x2c, 0xcd,
    ],
    [
        0x33, 0x84, 0x6b, 0x54, 0x5a, 0x49, 0xc9, 0xbe, 0x49, 0x03, 0xc6, 0x0e, 0x01, 0x71, 0x3c,
        0x1b, 0xd4, 0xe4, 0xef, 0x31, 0xea, 0x65, 0xcd, 0x95, 0xd6, 0x9e, 0x62, 0x79, 0x4f, 0x30,
        0xb9, 0x41,
    ],
];

fn malformed(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Malformed(what.into())
}

fn inconsistent(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Inconsistent(what.into())
}

/// Hold a stored token to the one spelling its bound parts allow.
///
/// `hashed` is what the token has to be about, which for the witness over a receipt's signature is
/// the SHA-256 of the 64 signature bytes. Every byte of `blob` is then either inside what a
/// signature or a hash covers, or is the one value the form allows; anything else is refused and
/// the error says which part it was.
pub fn held_to_one_spelling(blob: &[u8], hashed: &[u8; 32]) -> Result<(), EvidenceError> {
    let parts = read(blob, hashed)?;
    let stored = unpack_blob(blob)?;
    if stored.request != parts.request.as_slice() {
        return Err(inconsistent(
            "the stored request is not the one written for this hash and the nonce the token \
             signs, and nobody signs a request, so any other spelling of it is free",
        ));
    }

    let certificates = in_the_one_spelling(&parts)?;
    if parts
        .reply
        .certificates
        .iter()
        .any(|carried| !certificates.contains(carried))
    {
        return Err(inconsistent(
            "the token carries a certificate its signed attributes do not name, so nothing binds \
             its bytes",
        ));
    }
    if written(&parts.reply, &certificates, parts.signer)? == stored.reply {
        Ok(())
    } else {
        Err(inconsistent(
            "the reply is not in the one form its signed parts allow: something outside the \
             token's signature is spelled differently from the way it has to be",
        ))
    }
}

/// The same token written in the one spelling [`held_to_one_spelling`] accepts.
///
/// This is what the stamp stores. It keeps the certificates the signed attributes name, and DigiCert's
/// two beside its pinned signer, and drops anything else a reply carries. Nothing signed changes: the
/// status, the versions, the algorithm names, the signer's identifier and the choice of
/// certificates are all outside the authority's signature, and the token checks under a pin
/// exactly as the reply that came back did. A reply that cannot be written in this form is refused,
/// and the stamp then writes no witness and says why.
pub fn in_one_spelling(blob: &[u8], hashed: &[u8; 32]) -> Result<Vec<u8>, EvidenceError> {
    let parts = read(blob, hashed)?;
    let reply = written(&parts.reply, &in_the_one_spelling(&parts)?, parts.signer)?;
    let respelled = pack_blob(&parts.request, &reply);
    held_to_one_spelling(&respelled, hashed)?;
    Ok(respelled)
}

/// What a stored token is made of, once every bound part has been checked against what binds it.
struct Parts<'a> {
    /// The request as this code writes it for the hash and the token's own nonce.
    request: Vec<u8>,
    reply: Reply<'a>,
    /// The certificates the signed attributes name, as carried, in the order they are named.
    named: Vec<&'a [u8]>,
    /// The first of them, which is the one that signed.
    signer: &'a [u8],
}

fn read<'a>(blob: &'a [u8], hashed: &[u8; 32]) -> Result<Parts<'a>, EvidenceError> {
    let stored = unpack_blob(blob)?;

    let mut outer = Reader::new(stored.reply);
    let mut response = outer.sequence("the response")?;
    let status = response.expect(der::TAG_SEQUENCE, "the status")?;
    if status.whole != GRANTED {
        return Err(inconsistent(
            "the reply's status is not a plain grant, and the status is outside the token's \
             signature",
        ));
    }

    let reply = read_reply(stored.reply)?;
    let token = read_token(reply.token)?;
    if token.hashed_message != hashed {
        return Err(inconsistent(
            "the token is about a different hash from the one it has to be about",
        ));
    }
    if reply.signer.content_type != OID_TST_INFO {
        return Err(inconsistent(
            "the signed attributes say this is not a timestamp token",
        ));
    }
    if reply.signer.message_digest != reply.signer.digest.digest(reply.token) {
        return Err(inconsistent(
            "the signed attributes carry a digest that is not the digest of the token they are \
             attached to",
        ));
    }
    if reply.signer.signature_hash != reply.signer.digest {
        return Err(malformed(
            "a signature made with a different hash from the one the signer states for the digest, \
             which the one spelling has no way to write",
        ));
    }

    // The request, written again from the two things that fix it. The nonce is read out of the
    // signed token rather than out of the stored request, so the request is bound to signed bytes
    // and not to itself. This code asks with sixteen bytes; the token writes the number without
    // leading zeros, so they are put back.
    let nonce = token.nonce.as_deref().ok_or_else(|| {
        inconsistent("the token carries no nonce, so the request beside it is bound to nothing")
    })?;
    if nonce.len() > 16 {
        return Err(inconsistent(
            "the token carries a nonce longer than the sixteen bytes this code asks with",
        ));
    }
    let mut padded = [0u8; 16];
    padded[16 - nonce.len()..].copy_from_slice(nonce);
    let request = build_request(hashed, &padded);

    let names = named_certificates(reply.signer.signed_attributes)?;
    let mut named: Vec<&[u8]> = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let certificate = reply
            .certificates
            .iter()
            .find(|c| name.names(c))
            .ok_or_else(|| {
                inconsistent(format!(
                    "the signed attributes name {} certificate{} and the token does not carry \
                     number {}",
                    names.len(),
                    if names.len() == 1 { "" } else { "s" },
                    i + 1
                ))
            })?;
        if named.contains(certificate) {
            return Err(inconsistent(
                "the signed attributes name one certificate twice",
            ));
        }
        named.push(certificate);
    }
    let signer = named[0];

    verify_with(signer, &reply.signer).map_err(|_| {
        EvidenceError::BadSignature(
            "the token's signature does not check against the certificate its own signed \
             attributes name as the signer"
                .to_string(),
        )
    })?;

    Ok(Parts {
        request,
        reply,
        named,
        signer,
    })
}

/// The certificates the one spelling carries, in order: the ones the signed attributes name, then
/// for DigiCert's pinned signer the two it sends beside them.
fn in_the_one_spelling<'a>(parts: &Parts<'a>) -> Result<Vec<&'a [u8]>, EvidenceError> {
    let mut certificates = parts.named.clone();
    if Sha256::digest(parts.signer).as_slice() == DIGICERT_RESPONDER {
        for digest in &DIGICERT_UNNAMED {
            let certificate = parts
                .reply
                .certificates
                .iter()
                .find(|c| Sha256::digest(c).as_slice() == digest)
                .ok_or_else(|| {
                    inconsistent(
                        "a token from DigiCert's pinned signer without the two certificates \
                         DigiCert sends beside it, which are part of its one spelling",
                    )
                })?;
            certificates.push(certificate);
        }
    }
    Ok(certificates)
}

/// The reply written out in the one form, around the parts that are bound.
fn written(
    reply: &Reply<'_>,
    certificates: &[&[u8]],
    signer: &[u8],
) -> Result<Vec<u8>, EvidenceError> {
    let digest_algorithm = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_OID, reply.signer.digest.oid()),
            der::encode(der::TAG_NULL, &[]),
        ]
        .concat(),
    );
    let (issuer, serial) = issuer_and_serial(signer)?;
    let signer_info = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_INTEGER, &[1]),
            der::encode(der::TAG_SEQUENCE, &[issuer, serial].concat()),
            digest_algorithm.clone(),
            der::encode(der::context(0), reply.signer.signed_attributes),
            der::encode(
                der::TAG_SEQUENCE,
                &[
                    der::encode(der::TAG_OID, OID_RSA),
                    der::encode(der::TAG_NULL, &[]),
                ]
                .concat(),
            ),
            der::encode(der::TAG_OCTET_STRING, reply.signer.signature),
        ]
        .concat(),
    );
    let signed_data = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_INTEGER, &[3]),
            der::encode(der::TAG_SET, &digest_algorithm),
            der::encode(
                der::TAG_SEQUENCE,
                &[
                    der::encode(der::TAG_OID, OID_TST_INFO),
                    der::encode(
                        der::context(0),
                        &der::encode(der::TAG_OCTET_STRING, reply.token),
                    ),
                ]
                .concat(),
            ),
            der::encode(der::context(0), &certificates.concat()),
            der::encode(der::TAG_SET, &signer_info),
        ]
        .concat(),
    );
    let content_info = der::encode(
        der::TAG_SEQUENCE,
        &[
            der::encode(der::TAG_OID, OID_SIGNED_DATA),
            der::encode(der::context(0), &signed_data),
        ]
        .concat(),
    );
    Ok(der::encode(
        der::TAG_SEQUENCE,
        &[GRANTED, content_info.as_slice()].concat(),
    ))
}

/// A certificate's issuer and serial number, each as the whole element it is written as.
fn issuer_and_serial(certificate: &[u8]) -> Result<(&[u8], &[u8]), EvidenceError> {
    let mut outer = Reader::new(certificate);
    let mut cert = outer.sequence("the signing certificate")?;
    let mut body = cert.sequence("the signing certificate's body")?;
    if body.peek_tag() == Some(der::context(0)) {
        let _version = body.take()?;
    }
    let serial = body.expect(der::TAG_INTEGER, "the signing certificate's serial")?;
    let _algorithm = body.expect(der::TAG_SEQUENCE, "the signing certificate's algorithm")?;
    let issuer = body.expect(der::TAG_SEQUENCE, "the signing certificate's issuer")?;
    Ok((issuer.whole, serial.whole))
}

/// How the signed attributes name one certificate.
enum Name {
    /// By SHA-1, which is all the first version of the attribute can say.
    Sha1([u8; 20]),
    /// By a hash the second version states, SHA-256 where it states none.
    Stated(HashFunction, Vec<u8>),
}

impl Name {
    fn names(&self, certificate: &[u8]) -> bool {
        match self {
            // SHA-1 is broken for collisions and is not being asked to resist one. The certificate
            // it names was written by the authority before anybody could see it, so matching it
            // is a second preimage, which nobody can find for SHA-1.
            Name::Sha1(hash) => Sha1::digest(certificate).as_slice() == hash,
            Name::Stated(function, hash) => function.digest(certificate) == *hash,
        }
    }
}

/// The certificates the signed attributes name, the signer first.
///
/// The second version of the attribute is read where it is there, and the first where it is not,
/// which is the order RFC 5035 gives them. A token naming no certificate at all is refused: the one
/// it carries would then be bound by nothing but a pin, and a reader holding no pin for it would be
/// reading bytes anybody could change.
fn named_certificates(signed_attributes: &[u8]) -> Result<Vec<Name>, EvidenceError> {
    let mut first = None;
    let mut second = None;
    let mut attributes = Reader::new(signed_attributes);
    while !attributes.is_empty() {
        let mut attribute = attributes.sequence("an attribute")?;
        let oid = attribute.oid("an attribute type")?;
        let values = attribute.expect(der::TAG_SET, "an attribute's values")?;
        attribute.finished("an attribute")?;
        let slot = if oid == OID_SIGNING_CERTIFICATE {
            &mut first
        } else if oid == OID_SIGNING_CERTIFICATE_V2 {
            &mut second
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(inconsistent(
                "the signed attributes name the signing certificate twice over",
            ));
        }
        *slot = Some(values.value);
    }

    let names =
        match (second, first) {
            (Some(values), _) => read_names(values, true)?,
            (None, Some(values)) => read_names(values, false)?,
            (None, None) => return Err(inconsistent(
                "the signed attributes name no certificate, so nothing binds the one the token \
                 carries",
            )),
        };
    if names.is_empty() {
        return Err(inconsistent(
            "the signing certificate attribute names no certificate",
        ));
    }
    Ok(names)
}

/// Read the list of names out of one signing certificate attribute's single value.
fn read_names(values: &[u8], second_version: bool) -> Result<Vec<Name>, EvidenceError> {
    let mut set = Reader::new(values);
    let mut value = set.sequence("the signing certificate")?;
    set.finished("the signing certificate attribute's values")?;
    let mut ids = value.sequence("the certificates it names")?;
    let mut names = Vec::new();
    while !ids.is_empty() {
        let mut id = ids.sequence("a named certificate")?;
        let name = if second_version {
            let function = if id.peek_tag() == Some(der::TAG_SEQUENCE) {
                let mut algorithm = id.sequence("the hash a certificate is named by")?;
                HashFunction::from_oid(algorithm.oid("the hash a certificate is named by")?)
                    .ok_or_else(|| {
                        malformed("a certificate named by a hash this code does not implement")
                    })?
            } else {
                HashFunction::Sha256
            };
            let hash = id.octets("a certificate's hash")?;
            if hash.len() != function.length() {
                return Err(inconsistent(format!(
                    "a certificate named by {} with {} bytes, and {} produces {}",
                    function.name(),
                    hash.len(),
                    function.name(),
                    function.length()
                )));
            }
            Name::Stated(function, hash.to_vec())
        } else {
            let hash = id.octets("a certificate's hash")?;
            let hash: [u8; 20] = hash.try_into().map_err(|_| {
                inconsistent("a certificate named by SHA-1 with other than twenty bytes")
            })?;
            Name::Sha1(hash)
        };
        // What follows the hash, where anything does, is the issuer and serial. It is inside the
        // signature, so it cannot be changed, and the hash has already said which certificate.
        names.push(name);
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed version 1 receipt, whose witness is DigiCert's as it came back on 2026-09-21.
    const DIGICERT_RECEIPT: &str =
        include_str!("../../../../verify/tests/data/a-version-1-stamp/receipt.hex");
    /// The same receipt witnessed again by Sectigo on 2026-09-24.
    const SECTIGO_RECEIPT: &str =
        include_str!("../../../../verify/tests/data/a-version-1-stamp-witnessed-again/sectigo.hex");

    fn from_hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => b - b'A' + 10,
            })
            .collect();
        digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
    }

    /// The witness out of a receipt, and the hash of the signature it is about.
    ///
    /// The witness is the first stored token in the file, because the unprotected header comes
    /// before the payload, and the signature is the last 64 bytes.
    fn witness_of(hex: &str) -> (Vec<u8>, [u8; 32]) {
        let receipt = from_hex(hex);
        let at = receipt
            .windows(8)
            .position(|w| w == b"TWTSEVD0")
            .expect("the receipt carries a stored token");
        let header = &receipt[at..at + 16];
        let request = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let reply = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let blob = receipt[at..at + 16 + request + reply].to_vec();
        let signature = &receipt[receipt.len() - 64..];
        (blob, Sha256::digest(signature).into())
    }

    fn certificates_in(blob: &[u8]) -> usize {
        read_reply(unpack_blob(blob).unwrap().reply)
            .unwrap()
            .certificates
            .len()
    }

    #[test]
    fn digicerts_witness_as_it_came_back_is_the_one_spelling() {
        let (blob, hashed) = witness_of(DIGICERT_RECEIPT);
        held_to_one_spelling(&blob, &hashed).expect("the committed witness holds");
        assert_eq!(certificates_in(&blob), 3);
        assert_eq!(in_one_spelling(&blob, &hashed).unwrap(), blob);
    }

    #[test]
    fn sectigos_reply_is_already_in_the_one_spelling() {
        let (blob, hashed) = witness_of(SECTIGO_RECEIPT);
        held_to_one_spelling(&blob, &hashed).expect("the Sectigo witness holds");
        assert_eq!(
            certificates_in(&blob),
            3,
            "Sectigo names all three it sends"
        );
        assert_eq!(in_one_spelling(&blob, &hashed).unwrap(), blob);
    }

    /// Write a witness around the bound parts of `blob` with a chosen list of certificates, the way
    /// a holder with no key could.
    fn with_certificates(blob: &[u8], hashed: &[u8; 32], pick: &[&[u8]]) -> Vec<u8> {
        let parts = read(blob, hashed).unwrap();
        pack_blob(
            &parts.request,
            &written(&parts.reply, pick, parts.signer).unwrap(),
        )
    }

    #[test]
    fn a_certificate_nobody_names_is_refused() {
        let (digicert, hashed) = witness_of(DIGICERT_RECEIPT);
        let (sectigo, _) = witness_of(SECTIGO_RECEIPT);
        let stranger = read_reply(unpack_blob(&sectigo).unwrap().reply)
            .unwrap()
            .certificates[1]
            .to_vec();
        let mut carried = read_reply(unpack_blob(&digicert).unwrap().reply)
            .unwrap()
            .certificates;
        carried.push(&stranger);
        let forged = with_certificates(&digicert, &hashed, &carried);
        let refused = held_to_one_spelling(&forged, &hashed).expect_err("an unnamed certificate");
        assert!(refused.to_string().contains("do not name"), "{refused}");
    }

    #[test]
    fn digicerts_two_are_carried_both_and_in_the_order_they_came() {
        let (blob, hashed) = witness_of(DIGICERT_RECEIPT);
        let reply = read_reply(unpack_blob(&blob).unwrap().reply).unwrap();
        let [signer, issuer, root] = reply.certificates[..] else {
            panic!("three certificates")
        };
        for other in [
            vec![signer],
            vec![signer, issuer],
            vec![signer, root, issuer],
            vec![issuer, root, signer],
            vec![signer, issuer, root, root],
        ] {
            let forged = with_certificates(&blob, &hashed, &other);
            assert!(held_to_one_spelling(&forged, &hashed).is_err());
        }
        let as_it_came = with_certificates(&blob, &hashed, &[signer, issuer, root]);
        assert_eq!(as_it_came, blob);
    }

    #[test]
    fn digicerts_two_are_not_accepted_beside_any_other_signer() {
        let (digicert, _) = witness_of(DIGICERT_RECEIPT);
        let (sectigo, hashed) = witness_of(SECTIGO_RECEIPT);
        let pair = read_reply(unpack_blob(&digicert).unwrap().reply)
            .unwrap()
            .certificates[1..]
            .to_vec();
        let mut longer = read_reply(unpack_blob(&sectigo).unwrap().reply)
            .unwrap()
            .certificates;
        longer.extend(pair);
        let forged = with_certificates(&sectigo, &hashed, &longer);
        let refused =
            held_to_one_spelling(&forged, &hashed).expect_err("DigiCert's pair on Sectigo");
        assert!(refused.to_string().contains("do not name"), "{refused}");
    }

    #[test]
    fn a_named_certificate_left_out_is_refused() {
        let (blob, hashed) = witness_of(SECTIGO_RECEIPT);
        let reply = read_reply(unpack_blob(&blob).unwrap().reply).unwrap();
        let shorter = with_certificates(&blob, &hashed, &reply.certificates[..2]);
        let refused = held_to_one_spelling(&shorter, &hashed).expect_err("a named one missing");
        assert!(refused.to_string().contains("does not carry"), "{refused}");
    }

    #[test]
    fn a_request_in_any_other_spelling_is_refused() {
        let (blob, hashed) = witness_of(DIGICERT_RECEIPT);
        let stored = unpack_blob(&blob).unwrap();
        let other = build_request(&hashed, &[0x5a; 16]);
        let forged = pack_blob(&other, stored.reply);
        let refused = held_to_one_spelling(&forged, &hashed).expect_err("another request");
        assert!(refused.to_string().contains("stored request"), "{refused}");
    }

    #[test]
    fn a_grant_with_modifications_is_not_the_one_spelling() {
        let (blob, hashed) = witness_of(DIGICERT_RECEIPT);
        let stored = unpack_blob(&blob).unwrap();
        let mut reply = stored.reply.to_vec();
        let at = reply
            .windows(GRANTED.len())
            .position(|w| w == GRANTED)
            .unwrap();
        reply[at + 4] = 1;
        let forged = pack_blob(stored.request, &reply);
        assert!(held_to_one_spelling(&forged, &hashed).is_err());
    }

    #[test]
    fn a_witness_about_another_signature_is_refused() {
        let (blob, _) = witness_of(DIGICERT_RECEIPT);
        assert!(held_to_one_spelling(&blob, &[7u8; 32]).is_err());
    }
}
