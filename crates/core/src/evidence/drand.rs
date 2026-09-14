//! drand, checked from the bytes up.
//!
//! **What a drand round is.** A group of independent operators holds one signing key between them,
//! split so that no single operator has it. Every period they jointly sign the number of the round,
//! and publish the signature. Nobody outside the group can produce that signature early, so a
//! document containing it cannot have been finished before the round was published. That is the
//! whole of the not-earlier-than argument and it is the only thing this evidence is for.
//!
//! **What it is not.** It is not a statement about the time. Nobody signs a clock reading here. The
//! moment a round belongs to is arithmetic on the chain's published genesis and period, which are
//! part of the chain definition a verifier holds, the same way it holds a server's public key. The
//! signature covers the round number and nothing else, so a verifier that disagrees about the
//! chain's genesis gets a different answer and the signature will not tell it so.
//!
//! **The assumption it rests on, stated once.** A coalition holding enough of the shares could
//! compute any future round today, and on the unchained scheme used here it could do so
//! arbitrarily far ahead. Not-earlier-than therefore rests on that coalition not existing, not on
//! mathematics. That belongs in what this product says it cannot prove, and it is written down
//! rather than left as a footnote nobody reads.
//!
//! **Why the transport does not matter.** A round can be fetched over plain HTTP from any relay, or
//! read out of a newspaper, because the signature is checked here against a key pinned in advance.
//! A relay that lies is caught by the pairing check. Nothing about the fetch is trusted.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine};
use sha2::{Digest, Sha256};

use super::{Checked, EvidenceError};
use crate::time::{UnixNanos, NANOS_PER_SEC};

/// The scheme name the receipt format uses for this evidence.
pub const SCHEME: &str = "drand";

/// The domain separation tag for the signature scheme this chain uses.
///
/// It is part of what is hashed, so a tag that does not match the chain's produces a point that no
/// signature will ever verify against. It comes from the chain's own scheme identifier and is
/// written out here rather than assembled, because a typo in it fails in a way that looks like a
/// bad signature.
const QUICKNET_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// A drand chain: the key its rounds are checked against, and the schedule its rounds sit on.
///
/// The three together are the trust anchor. A chain hash on its own says nothing, a public key on
/// its own cannot be dated, and a schedule on its own can be anybody's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The chain's name, for a person reading a receipt.
    pub name: &'static str,
    /// The chain hash, which the fetched round names and which is compared here.
    pub hash: [u8; 32],
    /// The group public key, 96 bytes on the second curve group.
    pub public_key: [u8; 96],
    /// Seconds between rounds.
    pub period_seconds: u64,
    /// The Unix second round one was published at.
    pub genesis_time: u64,
}

impl Chain {
    /// The chain this client was built against.
    ///
    /// Read from `api.drand.sh/52db9b.../info` on 2026-09-07. Its scheme identifier is
    /// `bls-unchained-g1-rfc9380`: signatures on the first curve group, the group key on the
    /// second, the message the round number alone, and the hash to the curve done the way RFC 9380
    /// sets out. Three second rounds, so a round pins a receipt to within three seconds of when the
    /// value became public.
    #[must_use]
    pub fn quicknet() -> Self {
        Self {
            name: "drand quicknet",
            hash: [
                0x52, 0xdb, 0x9b, 0xa7, 0x0e, 0x0c, 0xc0, 0xf6, 0xea, 0xf7, 0x80, 0x3d, 0xd0, 0x74,
                0x47, 0xa1, 0xf5, 0x47, 0x77, 0x35, 0xfd, 0x3f, 0x66, 0x17, 0x92, 0xba, 0x94, 0x60,
                0x0c, 0x84, 0xe9, 0x71,
            ],
            public_key: [
                0x83, 0xcf, 0x0f, 0x28, 0x96, 0xad, 0xee, 0x7e, 0xb8, 0xb5, 0xf0, 0x1f, 0xca, 0xd3,
                0x91, 0x22, 0x12, 0xc4, 0x37, 0xe0, 0x07, 0x3e, 0x91, 0x1f, 0xb9, 0x00, 0x22, 0xd3,
                0xe7, 0x60, 0x18, 0x3c, 0x8c, 0x4b, 0x45, 0x0b, 0x6a, 0x0a, 0x6c, 0x3a, 0xc6, 0xa5,
                0x77, 0x6a, 0x2d, 0x10, 0x64, 0x51, 0x0d, 0x1f, 0xec, 0x75, 0x8c, 0x92, 0x1c, 0xc2,
                0x2b, 0x0e, 0x17, 0xe6, 0x3a, 0xaf, 0x4b, 0xcb, 0x5e, 0xd6, 0x63, 0x04, 0xde, 0x9c,
                0xf8, 0x09, 0xbd, 0x27, 0x4c, 0xa7, 0x3b, 0xab, 0x4a, 0xf5, 0xa6, 0xe9, 0xc7, 0x6a,
                0x4b, 0xc0, 0x9e, 0x76, 0xea, 0xe8, 0x99, 0x1e, 0xf5, 0xec, 0xe4, 0x5a,
            ],
            period_seconds: 3,
            genesis_time: 1_692_803_367,
        }
    }

    /// The Unix second a round is scheduled for.
    ///
    /// Round one is at the genesis, so round `n` is `n - 1` periods after it. Arithmetic on the
    /// chain definition, not a signed statement, and the caller is told so.
    #[must_use]
    pub fn time_of(&self, round: u64) -> Option<u64> {
        round
            .checked_sub(1)?
            .checked_mul(self.period_seconds)?
            .checked_add(self.genesis_time)
    }

    /// Which round covers a Unix second, being the last round published at or before it.
    #[must_use]
    pub fn round_at(&self, unix_seconds: u64) -> u64 {
        if unix_seconds <= self.genesis_time || self.period_seconds == 0 {
            return 1;
        }
        (unix_seconds - self.genesis_time) / self.period_seconds + 1
    }
}

/// The eight bytes a stored drand round starts with.
const BLOB_MAGIC: &[u8; 8] = b"TWDREVD0";

fn malformed(what: impl Into<String>) -> EvidenceError {
    EvidenceError::Malformed(what.into())
}

/// Pack a round into the blob a receipt carries.
///
/// The round number, the chain it belongs to and the signature are everything a verifier needs. The
/// message is the round number, so there is nothing else to keep, and the randomness the relay
/// publishes alongside is the hash of the signature and is therefore not stored: keeping a value
/// that can be recomputed invites somebody to read it rather than recompute it.
#[must_use]
pub fn pack_blob(chain_hash: &[u8; 32], round: u64, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(52 + signature.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(chain_hash);
    out.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

/// What a stored drand round holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored<'a> {
    /// Which round.
    pub round: u64,
    /// Which chain it claims to be from.
    pub chain_hash: [u8; 32],
    /// The group signature over that round.
    pub signature: &'a [u8],
}

/// Split a stored round back into its parts.
pub fn unpack_blob(blob: &[u8]) -> Result<Stored<'_>, EvidenceError> {
    if blob.len() < 52 {
        return Err(malformed(format!(
            "a stored round of {} bytes, and the header alone is fifty two",
            blob.len()
        )));
    }
    if &blob[..8] != BLOB_MAGIC {
        return Err(malformed(
            "a stored round that is not in the form this scheme stores",
        ));
    }
    let mut round_bytes = [0u8; 8];
    round_bytes.copy_from_slice(&blob[8..16]);
    let mut chain_hash = [0u8; 32];
    chain_hash.copy_from_slice(&blob[16..48]);
    let length = u32::from_le_bytes([blob[48], blob[49], blob[50], blob[51]]) as usize;
    if length != blob.len() - 52 {
        return Err(malformed(format!(
            "a stored round claiming a {length} byte signature and carrying {}",
            blob.len() - 52
        )));
    }
    Ok(Stored {
        round: u64::from_le_bytes(round_bytes),
        chain_hash,
        signature: &blob[52..],
    })
}

/// The message a round's signature is made over.
///
/// On the unchained scheme it is the round number alone, big endian, hashed once with SHA-256. On
/// the older chained scheme it also covers the previous round's signature; this code implements the
/// unchained one and refuses to guess at the other.
#[must_use]
pub fn message_for(round: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(round.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// The value a relay publishes as the round's randomness.
///
/// It is the hash of the signature and carries no information the signature does not. It is here so
/// a caller comparing what this code checked against what a relay printed has something to compare.
#[must_use]
pub fn randomness_of(signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(signature);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Check a stored drand round against a chain's group key.
///
/// The pairing is the whole check. Everything else here is bookkeeping that stops the pairing being
/// done against the wrong thing.
pub fn check(blob: &[u8], chain: &Chain) -> Result<Checked, EvidenceError> {
    let stored = unpack_blob(blob)?;

    if stored.chain_hash != chain.hash {
        return Err(EvidenceError::Inconsistent(format!(
            "the stored round names a chain this check was not given, so it would have been \
             verified against the wrong group key. Wanted {}, found {}",
            hex(&chain.hash),
            hex(&stored.chain_hash)
        )));
    }

    let signature_bytes: [u8; 48] = stored.signature.try_into().map_err(|_| {
        malformed(format!(
            "a signature of {} bytes, and a compressed point in this group is 48",
            stored.signature.len()
        ))
    })?;
    let signature = Option::<G1Affine>::from(G1Affine::from_compressed(&signature_bytes))
        .ok_or_else(|| {
            EvidenceError::BadSignature(
                "the signature is not a point on the curve at all".to_string(),
            )
        })?;
    let group_key = Option::<G2Affine>::from(G2Affine::from_compressed(&chain.public_key))
        .ok_or_else(|| {
            EvidenceError::BadSignature(
                "the chain's group key is not a point on the curve at all".to_string(),
            )
        })?;

    let point = <G1Projective as HashToCurve<ExpandMsgXmd<sha2_for_bls::Sha256>>>::hash_to_curve(
        message_for(stored.round),
        QUICKNET_DST,
    );
    let hashed_message = G1Affine::from(point);

    // A signature is the group's secret applied to the hashed message, and the group key is the
    // same secret applied to the generator. Pairing both ways round therefore gives the same value
    // when, and only when, the same secret made both.
    if pairing(&hashed_message, &group_key) != pairing(&signature, &G2Affine::generator()) {
        return Err(EvidenceError::BadSignature(format!(
            "round {} does not check against the group key of {}",
            stored.round, chain.name
        )));
    }

    let seconds = chain.time_of(stored.round).ok_or_else(|| {
        EvidenceError::Inconsistent(format!(
            "round {} is not on this chain's schedule at all",
            stored.round
        ))
    })?;
    let at = UnixNanos(i128::from(seconds) * NANOS_PER_SEC);

    // A round is an instant and not an interval. It pins a lower edge and asserts nothing about an
    // upper one, which is what a not-earlier-than entry is for.
    Ok(Checked::at_instant(
        SCHEME,
        chain.name.to_string(),
        at,
        None,
        vec![
            format!(
                "round {} carries a signature from the group key of {}, checked by pairing",
                stored.round, chain.name
            ),
            format!(
                "the message that signature covers is the round number and nothing else, so the \
                 value could not have been published before round {}",
                stored.round
            ),
            format!(
                "round {} falls at {seconds} on the schedule this chain publishes, which is \
                 arithmetic on its genesis and period rather than anything signed",
                stored.round
            ),
        ],
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schedule_runs_from_round_one_at_the_genesis() {
        let chain = Chain::quicknet();
        assert_eq!(chain.time_of(1), Some(chain.genesis_time));
        assert_eq!(chain.time_of(2), Some(chain.genesis_time + 3));
        assert_eq!(chain.round_at(chain.genesis_time), 1);
        assert_eq!(chain.round_at(chain.genesis_time + 3), 2);
        assert_eq!(chain.round_at(chain.genesis_time + 5), 2);
        assert_eq!(chain.round_at(0), 1);
    }

    #[test]
    fn the_blob_round_trips_and_a_wrong_length_is_refused() {
        let packed = pack_blob(&[7u8; 32], 42, &[9u8; 48]);
        let stored = unpack_blob(&packed).expect("what we packed unpacks");
        assert_eq!(stored.round, 42);
        assert_eq!(stored.chain_hash, [7u8; 32]);
        assert_eq!(stored.signature.len(), 48);

        let mut truncated = packed;
        truncated.pop();
        assert!(matches!(
            unpack_blob(&truncated),
            Err(EvidenceError::Malformed(_))
        ));
    }

    #[test]
    fn no_input_of_any_length_takes_the_parser_down() {
        let chain = Chain::quicknet();
        let mut seed = 0x2026_0907_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for length in 0..200usize {
            let bytes: Vec<u8> = (0..length).map(|_| (next() & 0xff) as u8).collect();
            let _ = unpack_blob(&bytes);
            let _ = check(&bytes, &chain);
        }
    }
}
