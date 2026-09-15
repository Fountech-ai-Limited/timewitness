//! Roughtime, checked from the bytes up.
//!
//! **Which specification this is.** `draft-ietf-ntp-roughtime-19`, dated 17 March 2026. It is an
//! Internet-Draft with intended status Experimental, not an RFC, and **it expires on 18 September
//! 2026**. The draft has been reissued roughly every two months for two years and each revision so
//! far has kept the wire format, so an expiry is a document going stale rather than a protocol
//! changing. What breaks when it lapses is the reference, not the code: the public servers keep
//! answering, this module keeps verifying them, and nothing in a receipt already issued stops being
//! checkable. What whoever maintains this has to do is read whatever revision replaced it and
//! compare the four things this file depends on, which are the packet framing, the message
//! encoding, the two signature context strings, and the Merkle rule. If any of those move, this
//! file moves with them and the version constant below changes.
//!
//! **The version on the wire is not 1.** The draft carries a note to the RFC editor naming
//! `0x8000000c` as the version number to use while it is a draft, and that is the number every
//! public server was answering on when this was written. Version 1 is reserved for the published
//! RFC. Offering only `0x8000000c` is what gets an answer today: on 2026-09-07 two of the three
//! reachable servers ignored a request whose version list also contained 1.
//!
//! **What a verified response proves, and what it does not.** It proves that the holder of a named
//! long-term key signed a statement covering a nonce we chose, and that the statement says the
//! server's own clock read a midpoint plus or minus a radius at the moment it signed. It does not
//! prove the server's clock is right. The draft says so itself in its section on validity, and this
//! module does not say more than the draft does. The radius is a whole number of seconds and the
//! three public servers reachable on 2026-09-07 were reporting one, three and five, so a corridor
//! is seconds wide. It authenticates the bound. It does not tighten it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use super::{Checked, EvidenceError};
use crate::time::{UnixNanos, NANOS_PER_SEC};

/// The draft revision this module implements.
pub const DRAFT_REVISION: u32 = 19;

/// The date that revision expires, as a plain string for anything that reports it.
pub const DRAFT_EXPIRY: &str = "2026-09-18";

/// The version number to put in a request and to expect in a response.
///
/// The draft names this as the number to use while it remains a draft.
pub const WIRE_VERSION: u32 = 0x8000_000c;

/// The scheme name the receipt format uses for this evidence.
pub const SCHEME: &str = "roughtime";

/// The eight bytes every Roughtime packet starts with.
const PACKET_MAGIC: &[u8; 8] = b"ROUGHTIM";

/// The context string prefixed to the delegation signature. The trailing zero is part of it.
const DELEGATION_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\x00";

/// The context string prefixed to the response signature. The trailing zero is part of it.
const RESPONSE_CONTEXT: &[u8] = b"RoughTime v1 response signature\x00";

/// The most (tag, value) pairs this parser will read out of one message.
///
/// The draft's own tag registry is shorter than this and the deepest message in a response carries
/// five pairs. A cap is here because the pair count comes off the wire ahead of the bytes that
/// would justify it, and an allocation sized from an unchecked field is how a parser is turned into
/// a denial of service.
const MAX_PAIRS: usize = 64;

/// The most hash values a Merkle path may carry, from the draft.
const MAX_PATH_ENTRIES: usize = 32;

/// The smallest a request message should be, so that a response can never be larger than what
/// provoked it.
const MIN_REQUEST_MESSAGE: usize = 1024;

const fn tag(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

const TAG_SIG: u32 = tag(b"SIG\x00");
const TAG_VER: u32 = tag(b"VER\x00");
const TAG_SRV: u32 = tag(b"SRV\x00");
const TAG_NONC: u32 = tag(b"NONC");
const TAG_TYPE: u32 = tag(b"TYPE");
const TAG_PATH: u32 = tag(b"PATH");
const TAG_DELE: u32 = tag(b"DELE");
const TAG_SREP: u32 = tag(b"SREP");
const TAG_CERT: u32 = tag(b"CERT");
const TAG_ZZZZ: u32 = tag(b"ZZZZ");
const TAG_RADI: u32 = tag(b"RADI");
const TAG_MIDP: u32 = tag(b"MIDP");
const TAG_ROOT: u32 = tag(b"ROOT");
const TAG_PUBK: u32 = tag(b"PUBK");
const TAG_MINT: u32 = tag(b"MINT");
const TAG_MAXT: u32 = tag(b"MAXT");

/// A request carries this in TYPE, a response carries one.
const TYPE_REQUEST: u32 = 0;
/// A response carries this in TYPE.
const TYPE_RESPONSE: u32 = 1;

fn malformed(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Malformed(what.into())
}

/// The first 32 bytes of the SHA-512 of the input, which is the only hash Roughtime uses.
fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// The SRV value for a server's long-term key, which tells the server which key to answer with.
#[must_use]
pub fn server_key_hash(long_term_public_key: &[u8; 32]) -> [u8; 32] {
    h(&[&[0xff], long_term_public_key])
}

/// A parsed Roughtime message: tags in ascending order, each with a slice of the value section.
struct Message<'a> {
    tags: Vec<u32>,
    values: Vec<&'a [u8]>,
}

impl<'a> Message<'a> {
    /// Read a message, refusing anything that is not the one encoding the draft allows.
    ///
    /// Every bound here is checked against the length of the bytes in hand rather than against the
    /// number the header claims. The header is attacker-controlled: it arrives over UDP from
    /// whoever answered first, and a parser that sizes a buffer from it has handed that attacker
    /// the allocator.
    fn parse(bytes: &'a [u8]) -> Result<Self, EvidenceError> {
        if bytes.len() < 4 {
            return Err(malformed("a message shorter than its own pair count"));
        }
        let n = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if n == 0 {
            return Err(malformed("a message with no pairs in it"));
        }
        if n > MAX_PAIRS {
            return Err(malformed(format!(
                "a message claiming {n} pairs, and no Roughtime message has more than {MAX_PAIRS}"
            )));
        }

        // 4 for the count, 4 per offset with the zeroth implied, 4 per tag. n is capped above, so
        // this cannot overflow.
        let header_len = 4 + 4 * (n - 1) + 4 * n;
        if bytes.len() < header_len {
            return Err(malformed(format!(
                "a header claiming {n} pairs needs {header_len} bytes and the message has {}",
                bytes.len()
            )));
        }
        let values_section = &bytes[header_len..];

        let mut offsets = Vec::with_capacity(n + 1);
        offsets.push(0usize);
        for i in 0..n - 1 {
            let at = 4 + 4 * i;
            let o = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
                as usize;
            if o % 4 != 0 {
                return Err(malformed(format!(
                    "an offset of {o}, and every offset is a multiple of four"
                )));
            }
            if o < offsets[offsets.len() - 1] {
                return Err(malformed("offsets that go backwards"));
            }
            if o > values_section.len() {
                return Err(malformed(format!(
                    "an offset of {o} into a value section of {} bytes",
                    values_section.len()
                )));
            }
            offsets.push(o);
        }
        offsets.push(values_section.len());

        let tags_at = 4 + 4 * (n - 1);
        let mut tags = Vec::with_capacity(n);
        for i in 0..n {
            let at = tags_at + 4 * i;
            let t = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            if let Some(previous) = tags.last() {
                if t <= *previous {
                    return Err(malformed(
                        "tags that are not in ascending order, or a tag appearing twice",
                    ));
                }
            }
            tags.push(t);
        }

        let values = (0..n)
            .map(|i| &values_section[offsets[i]..offsets[i + 1]])
            .collect();

        Ok(Self { tags, values })
    }

    fn get(&self, t: u32) -> Option<&'a [u8]> {
        self.tags
            .iter()
            .position(|x| *x == t)
            .map(|i| self.values[i])
    }

    fn need(&self, t: u32) -> Result<&'a [u8], EvidenceError> {
        self.get(t)
            .ok_or_else(|| malformed(format!("no {} tag", tag_name(t))))
    }

    fn need_u32(&self, t: u32) -> Result<u32, EvidenceError> {
        let v = self.need(t)?;
        if v.len() != 4 {
            return Err(malformed(format!(
                "a {} of {} bytes, and it is a 32-bit number",
                tag_name(t),
                v.len()
            )));
        }
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }

    fn need_u64(&self, t: u32) -> Result<u64, EvidenceError> {
        let v = self.need(t)?;
        if v.len() != 8 {
            return Err(malformed(format!(
                "a {} of {} bytes, and it is a 64-bit number",
                tag_name(t),
                v.len()
            )));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(v);
        Ok(u64::from_le_bytes(b))
    }

    fn need_fixed<const N: usize>(&self, t: u32) -> Result<[u8; N], EvidenceError> {
        let v = self.need(t)?;
        if v.len() != N {
            return Err(malformed(format!(
                "a {} of {} bytes, and it is {N}",
                tag_name(t),
                v.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(v);
        Ok(out)
    }
}

/// A tag as a person reads it, for an error message.
fn tag_name(t: u32) -> String {
    let bytes = t.to_le_bytes();
    let trimmed: Vec<u8> = bytes.iter().copied().take_while(|b| *b != 0).collect();
    String::from_utf8(trimmed).unwrap_or_else(|_| format!("{t:#010x}"))
}

/// Encode a message from pairs. Sorts them, because the encoding requires ascending tags.
fn encode(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut pairs = pairs.to_vec();
    pairs.sort_by_key(|(t, _)| *t);

    let n = pairs.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(n as u32).to_le_bytes());
    let mut running = 0u32;
    for (_, v) in pairs.iter().take(n.saturating_sub(1)) {
        running += v.len() as u32;
        out.extend_from_slice(&running.to_le_bytes());
    }
    for (t, _) in &pairs {
        out.extend_from_slice(&t.to_le_bytes());
    }
    for (_, v) in &pairs {
        out.extend_from_slice(v);
    }
    out
}

/// Wrap a message in the packet framing every Roughtime packet carries.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + message.len());
    out.extend_from_slice(PACKET_MAGIC);
    out.extend_from_slice(&(message.len() as u32).to_le_bytes());
    out.extend_from_slice(message);
    out
}

/// Take the message out of a packet, checking the framing rather than trusting it.
fn unframe(packet: &[u8]) -> Result<&[u8], EvidenceError> {
    if packet.len() < 12 {
        return Err(malformed(format!(
            "a packet of {} bytes, and the framing alone is twelve",
            packet.len()
        )));
    }
    if &packet[..8] != PACKET_MAGIC {
        return Err(malformed("a packet that does not begin ROUGHTIM"));
    }
    let len = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]) as usize;
    let body = &packet[12..];
    if len != body.len() {
        return Err(malformed(format!(
            "a packet claiming a {len} byte message and carrying {}",
            body.len()
        )));
    }
    Ok(body)
}

/// Build the request packet for a nonce, ready to put on a socket.
///
/// The nonce is the caller's. This function never invents one, because the whole value of the
/// response is that we chose what it was signed over and can show what we chose.
#[must_use]
pub fn build_request(nonce: &[u8; 32], long_term_public_key: &[u8; 32]) -> Vec<u8> {
    let srv = server_key_hash(long_term_public_key);
    let base = |padding: usize| {
        encode(&[
            (TAG_VER, WIRE_VERSION.to_le_bytes().to_vec()),
            (TAG_NONC, nonce.to_vec()),
            (TAG_TYPE, TYPE_REQUEST.to_le_bytes().to_vec()),
            (TAG_SRV, srv.to_vec()),
            (TAG_ZZZZ, vec![0u8; padding]),
        ])
    };
    let unpadded = base(0);
    let message = if unpadded.len() < MIN_REQUEST_MESSAGE {
        base(MIN_REQUEST_MESSAGE - unpadded.len())
    } else {
        unpadded
    };
    frame(&message)
}

/// The context the nonce binding is hashed under, so the derivation cannot collide with anything
/// else that hashes the same bytes.
pub const NONCE_BINDING_CONTEXT: &[u8] = b"TimeWitness Roughtime nonce v0\x00";

/// Derive a nonce from a binding, so a verifier can recompute it rather than take our word.
///
/// A random nonce proves the response is not a replay and says nothing about what was stamped. A
/// nonce derived from the hash of the subject ties the two together: a verifier recomputes this
/// from the binding carried in the receipt and sees that the server signed over a value that could
/// only have been produced from this subject.
///
/// The binding is `subject_hash || salt`, hashed as one run of bytes, and it is stored whole so
/// there is nothing to reassemble. The salt is there because a binding that is only the subject
/// hash is predictable to anybody who knows what is about to be stamped, and a predictable nonce
/// can be asked for in advance.
#[must_use]
pub fn bind_nonce(binding: &[u8]) -> [u8; 32] {
    h(&[NONCE_BINDING_CONTEXT, binding])
}

/// The eight bytes the stored evidence blob starts with.
const BLOB_MAGIC: &[u8; 8] = b"TWRTEVD0";

/// Pack the request, the response and the nonce binding into the blob a receipt carries.
///
/// **The request packet has to be in here and it is easy to think it does not.** A Roughtime
/// server does not sign the nonce. It signs the root of a Merkle tree whose leaf is the SHA-512 of
/// the client's whole request packet, so a verifier that holds only the response cannot get from
/// the nonce to the root and cannot check the signature covers anything of ours. Storing the
/// response alone would give a receipt that looks portable and is not.
///
/// The binding may be empty, which says the nonce was random rather than derived from a subject.
#[must_use]
pub fn pack_blob(binding: &[u8], request: &[u8], response: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + binding.len() + request.len() + response.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&(binding.len() as u32).to_le_bytes());
    out.extend_from_slice(&(request.len() as u32).to_le_bytes());
    out.extend_from_slice(&(response.len() as u32).to_le_bytes());
    out.extend_from_slice(binding);
    out.extend_from_slice(request);
    out.extend_from_slice(response);
    out
}

/// The three sections of a stored blob, still borrowing the blob they came out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stored<'a> {
    /// What the nonce was derived from, or empty where it was random.
    pub binding: &'a [u8],
    /// The request packet exactly as it went out, which is what the Merkle leaf is taken over.
    pub request: &'a [u8],
    /// The reply packet exactly as it arrived.
    pub reply: &'a [u8],
}

/// Split a stored blob back into the binding, the request packet and the response packet.
pub fn unpack_blob(blob: &[u8]) -> Result<Stored<'_>, EvidenceError> {
    if blob.len() < 20 {
        return Err(malformed(format!(
            "a stored response of {} bytes, and the header alone is twenty",
            blob.len()
        )));
    }
    if &blob[..8] != BLOB_MAGIC {
        return Err(malformed(
            "a stored response that is not in the form this scheme stores",
        ));
    }
    let read = |at: usize| {
        u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]]) as usize
    };
    let (a, b, c) = (read(8), read(12), read(16));
    let total = a
        .checked_add(b)
        .and_then(|x| x.checked_add(c))
        .and_then(|x| x.checked_add(20))
        .ok_or_else(|| malformed("section lengths that do not add up to a length"))?;
    if total != blob.len() {
        return Err(malformed(format!(
            "sections adding to {total} bytes in a stored response of {}",
            blob.len()
        )));
    }
    Ok(Stored {
        binding: &blob[20..20 + a],
        request: &blob[20 + a..20 + a + b],
        reply: &blob[20 + a + b..],
    })
}

fn verifying_key(bytes: &[u8; 32], whose: &str) -> Result<VerifyingKey, EvidenceError> {
    VerifyingKey::from_bytes(bytes).map_err(|e| {
        EvidenceError::BadSignature(format!("the {whose} key is not a point on the curve: {e}"))
    })
}

fn signature(bytes: &[u8], whose: &str) -> Result<Signature, EvidenceError> {
    if bytes.len() != 64 {
        return Err(EvidenceError::BadSignature(format!(
            "the {whose} signature is {} bytes and an Ed25519 signature is 64",
            bytes.len()
        )));
    }
    let mut b = [0u8; 64];
    b.copy_from_slice(bytes);
    Ok(Signature::from_bytes(&b))
}

/// The hash of the long-term key the stored request asked its answer to be signed under.
///
/// This is the one fact about who signed a corridor that needs no key to read, and a reader
/// compares their own list against it before checking anything. A request names its server by
/// this hash, so a reader holding no key that hashes to it has nothing to check the response
/// against, which is a fact about the reader. Until 2026-09-15 the validator had no way to ask
/// this: it tried every key it held and read a response that fitted none of them as a receipt
/// contradicting itself, so a reader holding two of the three published keys was told an intact
/// receipt was a lie.
pub fn requested_key_hash(blob: &[u8]) -> Result<[u8; 32], EvidenceError> {
    Ok(inspect(blob)?.requested_key_hash)
}

/// A stored Roughtime blob, read and held to itself with no key at all.
///
/// Everything a reader can establish about a corridor before choosing whose key to check it under.
/// That is nearly all of it: the framing, the encoding, the nonce and its binding, the delegation
/// window, the signed part of the response under the key the delegation names, the version, the
/// radius, and the Merkle path from the stored request to the signed root. Two things are left for
/// the key, and only two: that the request named that key, and that the delegation is signed by
/// it.
///
/// This type exists because of what happened when those two questions were asked first. The
/// validator read who signed a corridor off the request, found no key for them, and reported the
/// entry not checked before reading anything past the outer blob. The name sits in bytes whoever
/// wrote the receipt controls, so renaming it moved a reply of zeros past every check below. What
/// runs here runs on every corridor whatever the reader holds, so a name decides only whether the
/// signature is checked and never whether the bytes are read.
#[derive(Clone, Copy, Debug)]
pub struct Inspected<'a> {
    stored: Stored<'a>,
    nonce: [u8; 32],
    requested_key_hash: [u8; 32],
    delegation: &'a [u8],
    delegation_signature: &'a [u8],
    min_time: u64,
    max_time: u64,
    midpoint: u64,
    radius: u32,
    steps: usize,
}

impl Inspected<'_> {
    /// The hash of the long-term key the request asked to be answered under.
    #[must_use]
    pub const fn requested_key_hash(&self) -> [u8; 32] {
        self.requested_key_hash
    }

    /// The nonce the request carried, which the response echoes and the Merkle leaf covers.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// What the nonce was derived from, or empty where it was random.
    #[must_use]
    pub const fn binding(&self) -> &[u8] {
        self.stored.binding
    }

    /// The moment the response states, in nanoseconds.
    #[must_use]
    pub fn midpoint(&self) -> UnixNanos {
        UnixNanos(i128::from(self.midpoint) * NANOS_PER_SEC)
    }

    /// The radius the response states, in nanoseconds.
    #[must_use]
    pub fn radius(&self) -> crate::time::Nanos {
        i128::from(self.radius) * NANOS_PER_SEC
    }

    /// Check what only the server's published long-term key can check.
    ///
    /// Two things: that the request asked for this key, and that the delegation inside the
    /// response is signed by it. Everything else about the blob was established by [`inspect`],
    /// and the list of checks this returns names all of it in the order a reader would want to
    /// follow, from the request to the signed root.
    pub fn under(
        &self,
        long_term_public_key: &[u8; 32],
        server_name: &str,
    ) -> Result<Checked, EvidenceError> {
        let mut checks: Vec<String> = Vec::new();

        if self.requested_key_hash != server_key_hash(long_term_public_key) {
            return Err(EvidenceError::OutsideDelegation(format!(
                "the request asked {server_name} to answer with a different long-term key from \
                 the one this check was given, so the response is about somebody else's key"
            )));
        }
        checks.push(format!(
            "the request names the long-term key of {server_name} and carries a 32 byte nonce"
        ));

        if self.stored.binding.is_empty() {
            checks.push("the nonce is random and is bound to no subject".to_string());
        } else {
            checks.push(format!(
                "the nonce is derived from a {} byte binding and the derivation was recomputed",
                self.stored.binding.len()
            ));
        }

        let long_term = verifying_key(long_term_public_key, "long-term")?;
        let cert_signature = signature(self.delegation_signature, "delegation")?;
        let mut delegation_signed =
            Vec::with_capacity(DELEGATION_CONTEXT.len() + self.delegation.len());
        delegation_signed.extend_from_slice(DELEGATION_CONTEXT);
        delegation_signed.extend_from_slice(self.delegation);
        long_term
            .verify(&delegation_signed, &cert_signature)
            .map_err(|_| {
                EvidenceError::BadSignature(format!(
                    "the delegation in this response was not signed by the published long-term \
                     key of {server_name}"
                ))
            })?;
        checks.push(format!(
            "the delegation is signed by the published long-term key of {server_name}"
        ));
        checks.push("the signed part of the response checks against the delegated key".to_string());
        checks.push(format!(
            "the moment it states, {}, is inside the window {} to {} the delegation allows",
            self.midpoint, self.min_time, self.max_time
        ));
        checks.push(format!(
            "the path from our own request reaches the signed root in {} steps",
            self.steps
        ));

        Checked::over(
            SCHEME,
            server_name.to_string(),
            UnixNanos(self.midpoint().as_nanos() - self.radius()),
            UnixNanos(self.midpoint().as_nanos() + self.radius()),
            Some(self.nonce.to_vec()),
            checks,
        )
    }
}

/// Read a stored Roughtime blob and hold it to itself, with no key.
///
/// Every refusal here is one anybody can make from the bytes alone, so a validator makes all of
/// them before asking whose key to try, and a blob that fails one is refused whatever the reader
/// holds. The one check that reads a key from the blob rather than from the reader is the response
/// signature under the delegated key: that key is inside the response, so a forger can write both
/// halves, and passing it says only that the response agrees with itself. A forger who does that
/// work gets an entry reported as not checked, which is what an intact attestation by a party the
/// reader holds no key for is. A forger who does not gets a refusal.
pub fn inspect(blob: &[u8]) -> Result<Inspected<'_>, EvidenceError> {
    let stored = unpack_blob(blob)?;
    let (binding, request_packet, response_packet) = (stored.binding, stored.request, stored.reply);

    // The request first, because everything the response says is about a nonce, and the nonce is
    // only ours if the request in front of us is the one that carried it.
    let request = Message::parse(unframe(request_packet)?)?;
    if request.need_u32(TAG_TYPE)? != TYPE_REQUEST {
        return Err(malformed(
            "a stored request that is not marked as a request",
        ));
    }
    let nonce = request.need_fixed::<32>(TAG_NONC)?;
    let requested_key_hash = request.need_fixed::<32>(TAG_SRV)?;

    if !binding.is_empty() && bind_nonce(binding) != nonce {
        return Err(EvidenceError::WrongNonce(
            "the stored binding does not produce the nonce in the request, so the response is \
             not about this subject"
                .to_string(),
        ));
    }

    let response = Message::parse(unframe(response_packet)?)?;
    if response.need_u32(TAG_TYPE)? != TYPE_RESPONSE {
        return Err(malformed(
            "a stored response that is not marked as a response",
        ));
    }
    if response.need_fixed::<32>(TAG_NONC)? != nonce {
        return Err(EvidenceError::WrongNonce(
            "the response echoes a different nonce from the one the request sent".to_string(),
        ));
    }

    // The certificate: the long-term key delegating to an online key for a window of time. The
    // signature over it is the key's to check and is kept for `under`; the window is read here.
    let cert = Message::parse(response.need(TAG_CERT)?)?;
    let delegation_bytes = cert.need(TAG_DELE)?;
    let delegation_signature = cert.need(TAG_SIG)?;
    let delegation = Message::parse(delegation_bytes)?;
    let online_key_bytes = delegation.need_fixed::<32>(TAG_PUBK)?;
    let min_time = delegation.need_u64(TAG_MINT)?;
    let max_time = delegation.need_u64(TAG_MAXT)?;
    if min_time > max_time {
        return Err(EvidenceError::Inconsistent(
            "the delegation window ends before it starts".to_string(),
        ));
    }

    // The response itself, signed by the key the certificate delegates to.
    let signed_response_bytes = response.need(TAG_SREP)?;
    let online_key = verifying_key(&online_key_bytes, "delegated")?;
    let response_signature = signature(response.need(TAG_SIG)?, "response")?;
    let mut response_signed =
        Vec::with_capacity(RESPONSE_CONTEXT.len() + signed_response_bytes.len());
    response_signed.extend_from_slice(RESPONSE_CONTEXT);
    response_signed.extend_from_slice(signed_response_bytes);
    online_key
        .verify(&response_signed, &response_signature)
        .map_err(|_| {
            EvidenceError::BadSignature(
                "the signed part of the response does not check against the key the delegation \
                 names"
                    .to_string(),
            )
        })?;

    let signed_response = Message::parse(signed_response_bytes)?;
    let midpoint = signed_response.need_u64(TAG_MIDP)?;
    let radius = signed_response.need_u32(TAG_RADI)?;
    let root = signed_response.need_fixed::<32>(TAG_ROOT)?;
    let version = signed_response.need_u32(TAG_VER)?;

    if version != WIRE_VERSION {
        return Err(EvidenceError::Inconsistent(format!(
            "the response is version {version:#010x} and this code implements {WIRE_VERSION:#010x}"
        )));
    }
    if radius == 0 {
        // The draft forbids it. A server claiming a radius of zero is claiming a perfect clock,
        // and an interval of no width would let a corridor pass an overlap check it should fail.
        return Err(EvidenceError::Inconsistent(
            "the response states a radius of zero, which the draft forbids and which would claim a \
             clock with no error at all"
                .to_string(),
        ));
    }
    if midpoint < min_time || midpoint > max_time {
        return Err(EvidenceError::OutsideDelegation(format!(
            "the response is dated {midpoint} and the key that signed it was only delegated for \
             {min_time} to {max_time}"
        )));
    }

    // The Merkle proof, which is what ties the signature to our own request rather than to
    // somebody else's that the server batched alongside it.
    let path = response.need(TAG_PATH)?;
    if path.len() % 32 != 0 {
        return Err(malformed(format!(
            "a Merkle path of {} bytes, which is not a whole number of hashes",
            path.len()
        )));
    }
    let steps = path.len() / 32;
    if steps > MAX_PATH_ENTRIES {
        return Err(malformed(format!(
            "a Merkle path of {steps} hashes, and the draft allows {MAX_PATH_ENTRIES}"
        )));
    }
    let index = response.need_u32(TAG_INDX)?;
    let mut current = h(&[&[0x00], request_packet]);
    for step in 0..steps {
        let node = &path[step * 32..(step + 1) * 32];
        current = if (index >> step) & 1 == 0 {
            h(&[&[0x01], &current, node])
        } else {
            h(&[&[0x01], node, &current])
        };
    }
    if steps < 32 && (index >> steps) != 0 {
        return Err(EvidenceError::Inconsistent(format!(
            "the response places our request at index {index} and gives a path of {steps} steps, \
             which cannot reach it"
        )));
    }
    if current != root {
        return Err(EvidenceError::WrongNonce(
            "the path from our own request does not reach the root the server signed, so the \
             signature is over somebody else's request"
                .to_string(),
        ));
    }

    Ok(Inspected {
        stored,
        nonce,
        requested_key_hash,
        delegation: delegation_bytes,
        delegation_signature,
        min_time,
        max_time,
        midpoint,
        radius,
        steps,
    })
}

/// Check a stored Roughtime blob against the server's published long-term key.
///
/// This is every check the draft's own validity section lists, and two more that belong to us
/// rather than to Roughtime: that the request in the blob carries the nonce it claims, and that a
/// binding, where there is one, really produces that nonce. It is [`inspect`] followed by
/// [`Inspected::under`], and nothing else, so a validator that runs the two apart runs exactly
/// what the agent runs together.
///
/// It runs in the agent the moment a response arrives and in a verifier years later on the same
/// bytes. There is no second, looser path.
pub fn check(
    blob: &[u8],
    long_term_public_key: &[u8; 32],
    server_name: &str,
) -> Result<Checked, EvidenceError> {
    inspect(blob)?.under(long_term_public_key, server_name)
}

// The server half of the same wire format.
//
// It is in this file rather than in a crate of its own for the reason the module heading gives for
// everything else here: two halves of a format that disagree are a fault nobody sees until a
// stranger's verifier refuses a receipt. `check` above reads a response and `build_response` below
// writes one. They share the tag constants, the encoding, the framing, the two signature contexts
// and the Merkle rule, and the tests at the bottom of this file run one into the other. A server in
// another crate would need every one of those made public, which is the same as making them
// changeable from a distance.
//
// What is not here is the socket, the key on disk, the rate limit and the address to answer on.
// Those are facts about running a server and they live with the binary that runs one. Nothing in
// this section reads a clock, opens a file or allocates a port.

/// The longest a delegation window may be, in seconds.
///
/// Seven days. The online key is the one that sits in a running process and can be stolen; the
/// long-term key signs a delegation and then goes back in the safe. The window is how long a theft
/// is worth anything, so it wants to be short, and it is bounded from the other side by how often
/// somebody is willing to take the long-term key out. Seven days is what the public servers use and
/// it is what this refuses to exceed, because a server that delegates for a year has an online key
/// with the authority of a long-term one and none of the protection.
pub const MAX_DELEGATION_SECONDS: u64 = 7 * 24 * 60 * 60;

/// The narrowest radius a server may honestly state, in seconds.
///
/// One, and it is the floor the wire format sets rather than a policy of ours. `RADI` is a `u32` of
/// seconds, the draft forbids zero, and `check` above refuses a zero. So one second is the
/// narrowest interval any Roughtime server can state, ours included, and a Roughtime corridor is
/// two seconds wide at best whoever runs it.
///
/// **This is the answer to the question a reader asks about running our own servers: they do not
/// narrow the bound.** They cannot. What they buy is a corridor that is there when three
/// volunteers' servers are not, and a key we publish and can be held to. Anybody writing that our
/// own servers tightened a number has read this constant backwards.
pub const MIN_RADIUS_SECONDS: u32 = 1;

/// A long-term key's delegation of signing authority to an online key, for a window of time.
///
/// Made once off the long-term key and then used for every response until it expires. The signed
/// bytes are kept whole rather than rebuilt per response: re-encoding the same values could produce
/// a different encoding of them, and the signature would then be over something the client never
/// sees.
#[derive(Clone, Debug)]
pub struct Delegation {
    /// The encoded DELE message, exactly as it was signed and exactly as it must travel.
    delegation: Vec<u8>,
    /// The long-term key's signature over the delegation context and those bytes.
    signature: [u8; 64],
    /// The first second the online key may date a response.
    min_time: u64,
    /// The last second the online key may date a response.
    max_time: u64,
}

impl Delegation {
    /// The window this delegation allows, as the two seconds it runs between.
    #[must_use]
    pub const fn window(&self) -> (u64, u64) {
        (self.min_time, self.max_time)
    }

    /// Whether a moment, in whole seconds, falls inside the window.
    #[must_use]
    pub const fn covers(&self, seconds: u64) -> bool {
        seconds >= self.min_time && seconds <= self.max_time
    }

    /// The encoded certificate this delegation travels in.
    fn certificate(&self) -> Vec<u8> {
        encode(&[
            (TAG_DELE, self.delegation.clone()),
            (TAG_SIG, self.signature.to_vec()),
        ])
    }
}

/// Sign a delegation from a long-term key to an online key, for a window.
///
/// The caller supplies the window rather than a duration and a clock, because nothing in this file
/// reads a clock. Both ends are whole seconds since the Unix epoch, as `MIDP` is.
///
/// # Errors
///
/// A window that ends before it starts, and one longer than [`MAX_DELEGATION_SECONDS`]. Both are
/// refused rather than clamped: a caller that asked for a year has a bug or a misunderstanding, and
/// quietly handing it a week would leave it believing it had a year.
pub fn delegate(
    long_term: &ed25519_dalek::SigningKey,
    online_public_key: &[u8; 32],
    min_time: u64,
    max_time: u64,
) -> Result<Delegation, EvidenceError> {
    if max_time < min_time {
        return Err(EvidenceError::Inconsistent(format!(
            "a delegation window from {min_time} to {max_time}, which ends before it starts"
        )));
    }
    let span = max_time - min_time;
    if span > MAX_DELEGATION_SECONDS {
        return Err(EvidenceError::Inconsistent(format!(
            "a delegation window of {span} seconds, and this refuses anything over \
             {MAX_DELEGATION_SECONDS}, because an online key delegated for longer has the authority \
             of a long-term one and none of the protection"
        )));
    }

    let delegation = encode(&[
        (TAG_PUBK, online_public_key.to_vec()),
        (TAG_MINT, min_time.to_le_bytes().to_vec()),
        (TAG_MAXT, max_time.to_le_bytes().to_vec()),
    ]);

    let mut signed = Vec::with_capacity(DELEGATION_CONTEXT.len() + delegation.len());
    signed.extend_from_slice(DELEGATION_CONTEXT);
    signed.extend_from_slice(&delegation);
    let signature = ed25519_dalek::Signer::sign(long_term, &signed);

    Ok(Delegation {
        delegation,
        signature: signature.to_bytes(),
        min_time,
        max_time,
    })
}

/// What a server read out of a request before deciding to answer it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The nonce the client chose, which the response must echo.
    pub nonce: [u8; 32],
    /// The long-term key hash the client asked to be answered with.
    pub server_key_hash: [u8; 32],
}

/// Read a request packet and say whether it is one this server should answer.
///
/// Every refusal here is a packet dropped rather than an error sent back. A Roughtime server has no
/// error message to send: anything it puts on the wire goes to a spoofed source address as readily
/// as to a real one, so the only safe answer to a bad request is silence.
///
/// # Errors
///
/// The framing, the encoding, a missing tag, a wrong version, a request marked as a response, a
/// request naming a different server's key, and a request under the draft's minimum size.
///
/// **The size check is the one that is easy to leave out and it is the whole of the amplification
/// defence.** A response is a few hundred bytes. The draft requires a request of at least
/// [`MIN_REQUEST_MESSAGE`] bytes so that a reply can never be larger than what provoked it, which is
/// what stops a server being a lever for pointing traffic at somebody else's address. A server that
/// answers a short request is a reflector whatever else it gets right.
pub fn read_request(
    packet: &[u8],
    long_term_public_key: &[u8; 32],
) -> Result<Request, EvidenceError> {
    let message = unframe(packet)?;
    if message.len() < MIN_REQUEST_MESSAGE {
        return Err(malformed(format!(
            "a request message of {} bytes, and the draft requires at least {MIN_REQUEST_MESSAGE} \
             so that a reply can never be larger than what asked for it",
            message.len()
        )));
    }
    let request = Message::parse(message)?;
    if request.need_u32(TAG_TYPE)? != TYPE_REQUEST {
        return Err(malformed("a request that is not marked as a request"));
    }
    let version = request.need_u32(TAG_VER)?;
    if version != WIRE_VERSION {
        return Err(EvidenceError::Inconsistent(format!(
            "a request at version {version:#010x} and this server speaks {WIRE_VERSION:#010x}"
        )));
    }
    let nonce = request.need_fixed::<32>(TAG_NONC)?;
    let asked_for = request.need_fixed::<32>(TAG_SRV)?;
    let ours = server_key_hash(long_term_public_key);
    if asked_for != ours {
        return Err(EvidenceError::OutsideDelegation(
            "a request naming a different server's long-term key, which this server has no \
             authority to answer"
                .to_string(),
        ));
    }
    Ok(Request {
        nonce,
        server_key_hash: ours,
    })
}

/// Build the response packet for one request.
///
/// `midpoint` and `radius` are whole seconds, as the wire format states them. `midpoint` is what
/// the server's own clock read. `radius` is how wrong the server says that reading could be, and it
/// is a statement about itself rather than a number chosen to look good.
///
/// # One request per tree, said plainly
///
/// The draft lets a server batch many requests under one signature and prove each one's place with
/// a Merkle path. This answers one request per tree: the root is the leaf, the path is empty and
/// the index is nought. That is a valid tree of one, and `check` above verifies it by the same rule
/// it verifies a path of thirty-two by, which the tests demonstrate rather than assert.
///
/// It costs a signature per request where a batching server costs one per batch. That is the right
/// trade at the load two servers of ours will see and the wrong one at the load a public server
/// sees, so it is written here as a decision rather than left as an implementation detail: a
/// deployment that outgrows it needs the tree, not a bigger machine.
///
/// # Errors
///
/// A radius under [`MIN_RADIUS_SECONDS`], a midpoint outside the delegation's window, and anything
/// wrong with the request packet itself.
pub fn build_response(
    request_packet: &[u8],
    online: &ed25519_dalek::SigningKey,
    certificate: &Delegation,
    midpoint: u64,
    radius: u32,
) -> Result<Vec<u8>, EvidenceError> {
    if radius < MIN_RADIUS_SECONDS {
        return Err(EvidenceError::Inconsistent(format!(
            "a radius of {radius} seconds, and the narrowest a Roughtime server may honestly state \
             is {MIN_RADIUS_SECONDS}, because the field is a whole number of seconds and zero \
             claims a clock with no error at all"
        )));
    }
    if !certificate.covers(midpoint) {
        let (min_time, max_time) = certificate.window();
        return Err(EvidenceError::OutsideDelegation(format!(
            "a response dated {midpoint} and a delegation good for {min_time} to {max_time}, so \
             signing it would produce a response this server's own checker refuses"
        )));
    }

    // The request is parsed rather than trusted: the nonce that goes in the reply comes out of it,
    // and so does the leaf that goes in the tree.
    let message = unframe(request_packet)?;
    let request = Message::parse(message)?;
    let nonce = request.need_fixed::<32>(TAG_NONC)?;

    // A tree of one. The leaf is the hash of the whole request packet under the leaf prefix, and
    // that leaf is the root. `check` recomputes exactly this from the request it holds.
    let root = h(&[&[0x00], request_packet]);

    let signed_response = encode(&[
        (TAG_VER, WIRE_VERSION.to_le_bytes().to_vec()),
        (TAG_RADI, radius.to_le_bytes().to_vec()),
        (TAG_MIDP, midpoint.to_le_bytes().to_vec()),
        (TAG_ROOT, root.to_vec()),
    ]);

    let mut signed = Vec::with_capacity(RESPONSE_CONTEXT.len() + signed_response.len());
    signed.extend_from_slice(RESPONSE_CONTEXT);
    signed.extend_from_slice(&signed_response);
    let signature = ed25519_dalek::Signer::sign(online, &signed);

    let response = encode(&[
        (TAG_VER, WIRE_VERSION.to_le_bytes().to_vec()),
        (TAG_NONC, nonce.to_vec()),
        (TAG_TYPE, TYPE_RESPONSE.to_le_bytes().to_vec()),
        (TAG_SREP, signed_response),
        (TAG_SIG, signature.to_bytes().to_vec()),
        (TAG_CERT, certificate.certificate()),
        (TAG_PATH, Vec::new()),
        (TAG_INDX, 0u32.to_le_bytes().to_vec()),
    ]);

    Ok(frame(&response))
}

const TAG_INDX: u32 = tag(b"INDX");

/// A Roughtime server's published long-term key, with a name for the person reading a report.
///
/// A key without an address, which is the whole of what checking a stored response needs. The
/// address is a fact about reaching a server and lives with the client that reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedKey {
    /// The server's usual name.
    pub name: &'static str,
    /// Its published long-term Ed25519 key.
    pub long_term_public_key: [u8; 32],
}

/// The public servers whose keys ship with this code.
///
/// The keys come from the ecosystem list the Roughtime community maintains, at
/// `github.com/cloudflare/roughtime`, `ecosystem.json`, read on 2026-09-07. Each of the three
/// answered a real request from this machine on that date and every part of each response verified.
/// A fourth entry on that list, `roughtime.cloudflare.com:2003`, answered nothing on either
/// transport on the same day and is deliberately absent.
///
/// They are here rather than beside the client because two callers need them and one of the two is
/// a verifier that may not import the client. Shipping a key is not the same as being the root of
/// trust for it: every one of these is published by somebody else, a reader can compare each
/// against that public list, and a reader who would rather not can supply their own.
///
/// This is a starting list and not a trust store. A deployment picks its own servers.
#[must_use]
pub fn published_keys() -> Vec<PublishedKey> {
    vec![
        // AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=
        PublishedKey {
            name: "roughtime.int08h.com",
            long_term_public_key: [
                0x01, 0x6e, 0x6e, 0x02, 0x84, 0xd2, 0x4c, 0x37, 0xc6, 0xe4, 0xd7, 0xd8, 0xd5, 0xb4,
                0xe1, 0xd3, 0xc1, 0x94, 0x9c, 0xea, 0xa5, 0x45, 0xbf, 0x87, 0x56, 0x16, 0xc9, 0xdc,
                0xe0, 0xc9, 0xbe, 0xc1,
            ],
        },
        // S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
        PublishedKey {
            name: "roughtime.se",
            long_term_public_key: [
                0x4b, 0x70, 0x33, 0x7d, 0x92, 0x79, 0x0a, 0x34, 0x9d, 0x90, 0x9d, 0xb5, 0x64, 0x91,
                0x9b, 0xc6, 0xa7, 0x58, 0x3f, 0xf4, 0xa8, 0x13, 0xc7, 0xd7, 0x29, 0x8d, 0x3e, 0x6a,
                0x27, 0x2c, 0x7a, 0x12,
            ],
        },
        // iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=
        PublishedKey {
            name: "time.txryan.com",
            long_term_public_key: [
                0x88, 0x15, 0x63, 0xc6, 0x0f, 0xf5, 0x8f, 0xbc, 0xb5, 0xfa, 0x44, 0x14, 0x4c, 0x16,
                0x1d, 0x4d, 0xa6, 0xf1, 0x0a, 0x9a, 0x5e, 0xb1, 0x4f, 0xf4, 0xec, 0x3e, 0x0f, 0x30,
                0x32, 0x64, 0xd9, 0x60,
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_the_little_endian_reading_of_its_letters() {
        // The draft gives these two worked out, so they are the check on the whole convention.
        assert_eq!(TAG_NONC, 0x434e_4f4e);
        assert_eq!(TAG_VER, 0x0052_4556);
    }

    #[test]
    fn tags_come_out_in_ascending_order_and_the_request_is_padded() {
        let packet = build_request(&[7u8; 32], &[9u8; 32]);
        let message = unframe(&packet).expect("the request frames itself");
        assert!(
            message.len() >= MIN_REQUEST_MESSAGE,
            "a short request lets a server answer with more bytes than it received"
        );
        let parsed = Message::parse(message).expect("our own request parses");
        let mut sorted = parsed.tags.clone();
        sorted.sort_unstable();
        assert_eq!(parsed.tags, sorted);
        assert_eq!(parsed.need_u32(TAG_TYPE).unwrap(), TYPE_REQUEST);
        assert_eq!(parsed.need_fixed::<32>(TAG_NONC).unwrap(), [7u8; 32]);
    }

    #[test]
    fn a_binding_reproduces_the_same_nonce_every_time() {
        let binding = b"a subject hash and a salt".to_vec();
        assert_eq!(bind_nonce(&binding), bind_nonce(&binding));
        assert_ne!(bind_nonce(&binding), bind_nonce(b"something else"));
    }

    #[test]
    fn the_blob_container_round_trips_and_refuses_a_wrong_length() {
        let packed = pack_blob(b"bind", b"request", b"response");
        let stored = unpack_blob(&packed).expect("what we packed unpacks");
        assert_eq!(stored.binding, b"bind");
        assert_eq!(stored.request, b"request");
        assert_eq!(stored.reply, b"response");

        let mut truncated = packed.clone();
        truncated.pop();
        assert!(matches!(
            unpack_blob(&truncated),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn a_message_with_an_offset_past_its_own_values_is_refused() {
        // Two pairs, and the first value claims to be longer than the whole value section.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&1000u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            Message::parse(&bytes),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn a_message_claiming_more_pairs_than_it_carries_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&40u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            Message::parse(&bytes),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn repeated_tags_are_refused_rather_than_taking_the_first() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&TAG_NONC.to_le_bytes());
        bytes.extend_from_slice(&TAG_NONC.to_le_bytes());
        assert!(matches!(
            Message::parse(&bytes),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn no_input_of_any_length_takes_the_parser_down() {
        // The response arrives over UDP from whoever answered first, so every prefix of a real
        // packet and every run of rubbish reaches this parser at some point.
        let mut seed = 0x2026_0907_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for length in 0..600usize {
            let bytes: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
            let _ = Message::parse(&bytes);
            let _ = unframe(&bytes);
            let _ = unpack_blob(&bytes);
            let _ = check(&bytes, &[0u8; 32], "nobody");
        }
    }
    // The server half, run into the checker above. Every test here builds a response with
    // `build_response` and hands it to `check`, because the two agreeing is the only property that
    // matters and asserting bytes would let them drift apart while both still passed.

    fn key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    /// A long-term key, an online key delegated for a day around `midpoint`, and a request for it.
    fn a_server(
        midpoint: u64,
    ) -> (
        ed25519_dalek::SigningKey,
        ed25519_dalek::SigningKey,
        Delegation,
        [u8; 32],
        Vec<u8>,
    ) {
        let long_term = key(7);
        let online = key(9);
        let long_term_public = long_term.verifying_key().to_bytes();
        let certificate = delegate(
            &long_term,
            &online.verifying_key().to_bytes(),
            midpoint - 43_200,
            midpoint + 43_200,
        )
        .expect("a day either side is inside the maximum window");
        let nonce = [0x5a; 32];
        let request = build_request(&nonce, &long_term_public);
        (long_term, online, certificate, long_term_public, request)
    }

    #[test]
    fn a_response_this_server_builds_is_one_this_checker_accepts() {
        let midpoint = 1_800_000_000u64;
        let (_, online, certificate, long_term_public, request) = a_server(midpoint);

        let response =
            build_response(&request, &online, &certificate, midpoint, 1).expect("a valid response");
        let blob = pack_blob(&[], &request, &response);
        let checked = check(&blob, &long_term_public, "a server of ours").expect("it checks out");

        // The interval is the midpoint plus and minus the radius, and a radius of one second is the
        // narrowest the wire format can state, so two seconds is the narrowest a Roughtime corridor
        // ever is. This assertion is the one that stops anybody claiming our own servers made the
        // bound tighter.
        assert_eq!(checked.radius(), NANOS_PER_SEC);
        assert_eq!(
            checked.latest().0 - checked.earliest().0,
            2 * NANOS_PER_SEC,
            "a Roughtime corridor is two seconds wide at its narrowest, whoever runs the server"
        );
        assert_eq!(checked.scheme, SCHEME);
    }

    #[test]
    fn the_tree_of_one_is_verified_by_the_same_merkle_rule_as_a_longer_path() {
        // `build_response` gives an empty path and an index of nought. The checker walks nought
        // steps and compares the leaf with the root, which is the general rule at its smallest
        // rather than a special case anybody wrote.
        let midpoint = 1_800_000_000u64;
        let (_, online, certificate, long_term_public, request) = a_server(midpoint);
        let response = build_response(&request, &online, &certificate, midpoint, 3).unwrap();

        let message = Message::parse(unframe(&response).unwrap()).unwrap();
        assert!(message.need(TAG_PATH).unwrap().is_empty());
        assert_eq!(message.need_u32(TAG_INDX).unwrap(), 0);
        assert_eq!(
            Message::parse(message.need(TAG_SREP).unwrap())
                .unwrap()
                .need_fixed::<32>(TAG_ROOT)
                .unwrap(),
            h(&[&[0x00], request.as_slice()]),
            "the root of a tree of one is the leaf itself"
        );

        check(
            &pack_blob(&[], &request, &response),
            &long_term_public,
            "a server of ours",
        )
        .expect("the checker walks a path of no steps by the general rule");
    }

    #[test]
    fn a_response_bound_to_a_subject_survives_the_round_trip() {
        let midpoint = 1_800_000_000u64;
        let long_term = key(7);
        let online = key(9);
        let long_term_public = long_term.verifying_key().to_bytes();
        let certificate = delegate(
            &long_term,
            &online.verifying_key().to_bytes(),
            midpoint - 10,
            midpoint + 10,
        )
        .unwrap();

        let binding = b"a subject hash and a salt, stored whole".to_vec();
        let nonce = bind_nonce(&binding);
        let request = build_request(&nonce, &long_term_public);
        let response = build_response(&request, &online, &certificate, midpoint, 1).unwrap();

        let checked = check(
            &pack_blob(&binding, &request, &response),
            &long_term_public,
            "a server of ours",
        )
        .expect("the binding recomputes to the nonce the server echoed");
        assert_eq!(checked.nonce.as_deref(), Some(nonce.as_slice()));
    }

    #[test]
    fn a_server_refuses_to_state_a_radius_of_zero() {
        // The checker refuses one and so does this, which means a server of ours cannot build a
        // response its own verifier would throw out. The two refusals are deliberate duplication:
        // the checker's protects a reader from somebody else's server and this one protects us
        // from ourselves.
        let midpoint = 1_800_000_000u64;
        let (_, online, certificate, _, request) = a_server(midpoint);
        let refused = build_response(&request, &online, &certificate, midpoint, 0);
        assert!(
            matches!(refused, Err(EvidenceError::Inconsistent(ref d)) if d.contains("radius of 0")),
            "expected a refusal naming the radius, got {refused:?}"
        );
    }

    #[test]
    fn a_server_refuses_to_date_a_response_outside_its_own_delegation() {
        let midpoint = 1_800_000_000u64;
        let long_term = key(7);
        let online = key(9);
        let certificate = delegate(
            &long_term,
            &online.verifying_key().to_bytes(),
            midpoint,
            midpoint + 60,
        )
        .unwrap();
        let request = build_request(&[1u8; 32], &long_term.verifying_key().to_bytes());

        let refused = build_response(&request, &online, &certificate, midpoint + 61, 1);
        assert!(
            matches!(refused, Err(EvidenceError::OutsideDelegation(_))),
            "a moment one second past the window is outside it, got {refused:?}"
        );
        build_response(&request, &online, &certificate, midpoint + 60, 1)
            .expect("the last second of the window is inside it");
    }

    #[test]
    fn a_delegation_longer_than_a_week_is_refused_rather_than_clamped() {
        let long_term = key(7);
        let online = key(9).verifying_key().to_bytes();
        let start = 1_800_000_000u64;

        delegate(&long_term, &online, start, start + MAX_DELEGATION_SECONDS)
            .expect("exactly a week is allowed");
        let refused = delegate(
            &long_term,
            &online,
            start,
            start + MAX_DELEGATION_SECONDS + 1,
        );
        assert!(
            matches!(refused, Err(EvidenceError::Inconsistent(_))),
            "a second over a week is refused, got {refused:?}"
        );
        assert!(delegate(&long_term, &online, start + 1, start).is_err());
    }

    #[test]
    fn a_request_under_the_minimum_size_is_refused_so_a_server_is_never_a_reflector() {
        // The whole of the amplification defence. A request that is one byte short gets nothing,
        // and the message says why rather than dropping silently, because this is the server's own
        // check on itself and not the answer it sends.
        let long_term_public = key(7).verifying_key().to_bytes();
        let nonce = [3u8; 32];

        let proper = build_request(&nonce, &long_term_public);
        read_request(&proper, &long_term_public).expect("a padded request is answerable");

        let short = frame(&encode(&[
            (TAG_VER, WIRE_VERSION.to_le_bytes().to_vec()),
            (TAG_NONC, nonce.to_vec()),
            (TAG_TYPE, TYPE_REQUEST.to_le_bytes().to_vec()),
            (TAG_SRV, server_key_hash(&long_term_public).to_vec()),
        ]));
        assert!(
            short.len() < proper.len(),
            "the unpadded request is the short one"
        );
        let refused = read_request(&short, &long_term_public);
        assert!(
            matches!(refused, Err(EvidenceError::Malformed(ref d)) if d.contains("larger than what asked for it")),
            "expected the amplification refusal, got {refused:?}"
        );
    }

    #[test]
    fn a_request_naming_another_servers_key_is_refused() {
        let ours = key(7).verifying_key().to_bytes();
        let somebody_else = key(11).verifying_key().to_bytes();
        let asking_elsewhere = build_request(&[4u8; 32], &somebody_else);

        let refused = read_request(&asking_elsewhere, &ours);
        assert!(
            matches!(refused, Err(EvidenceError::OutsideDelegation(_))),
            "a request for another server's key is not ours to answer, got {refused:?}"
        );
    }

    #[test]
    fn a_response_from_the_wrong_online_key_does_not_check_out() {
        // The delegation names one online key and a different one signs. This is the theft case:
        // holding the long-term key's signed delegation is no use without the key it delegated to.
        let midpoint = 1_800_000_000u64;
        let (_, _, certificate, long_term_public, request) = a_server(midpoint);
        let impostor = key(13);

        let response = build_response(&request, &impostor, &certificate, midpoint, 1).unwrap();
        let refused = check(
            &pack_blob(&[], &request, &response),
            &long_term_public,
            "a server of ours",
        );
        assert!(
            matches!(refused, Err(EvidenceError::BadSignature(_))),
            "expected the response signature to fail, got {refused:?}"
        );
    }

    #[test]
    fn a_response_built_for_one_request_does_not_check_against_another() {
        // The Merkle root is over the whole request packet, so a response lifted from one exchange
        // and stapled to another fails on the path rather than on the nonce.
        let midpoint = 1_800_000_000u64;
        let (_, online, certificate, long_term_public, request) = a_server(midpoint);
        let response = build_response(&request, &online, &certificate, midpoint, 1).unwrap();

        let another = build_request(&[0xa5; 32], &long_term_public);
        let refused = check(
            &pack_blob(&[], &another, &response),
            &long_term_public,
            "a server of ours",
        );
        assert!(
            matches!(refused, Err(EvidenceError::WrongNonce(_))),
            "expected a refusal tying the response to the other request, got {refused:?}"
        );
    }

    #[test]
    fn a_response_is_never_larger_than_the_request_that_provoked_it() {
        // The size check in `read_request` is only half of the amplification argument. The other
        // half is that the reply really is smaller, and that is a fact about this encoding rather
        // than an assumption, so it is measured.
        let midpoint = 1_800_000_000u64;
        let (_, online, certificate, _, request) = a_server(midpoint);
        let response = build_response(&request, &online, &certificate, midpoint, 1).unwrap();
        assert!(
            response.len() < request.len(),
            "a {} byte reply to a {} byte request would make this server a reflector",
            response.len(),
            request.len()
        );
    }
}
