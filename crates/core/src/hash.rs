//! The hash functions this product names, and the facts about them that more than one place needs.
//!
//! There are two of those facts and they are easy to hold apart in the head and easy to confuse in
//! code. A hash function has a name, which anybody can write down, and it has a length, which is
//! arithmetic. A token that names SHA-512 and carries thirty-two bytes is telling us both, and the
//! two do not agree; the only way to notice is to have the length written down somewhere the
//! checker can reach.
//!
//! It is written down here, once. The receipt validator needs it to test a payload, and the RFC
//! 3161 checker needs it to test a token's own imprint, and those two live in different crates. A
//! second copy of the table is a second thing to keep right.

use sha2::{Digest, Sha256, Sha384, Sha512};

/// SHA-256, 2.16.840.1.101.3.4.2.1, as the bytes inside a DER object identifier.
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// SHA-384, 2.16.840.1.101.3.4.2.2.
pub const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// SHA-512, 2.16.840.1.101.3.4.2.3.
pub const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// One of the three hash functions this code implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA-256, which is what everything of ours uses.
    Sha256,
    /// SHA-384, accepted where somebody else chose it.
    Sha384,
    /// SHA-512, accepted where somebody else chose it.
    Sha512,
}

impl HashFunction {
    /// Read one from the bytes of a DER object identifier.
    #[must_use]
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            o if o == OID_SHA256 => Some(HashFunction::Sha256),
            o if o == OID_SHA384 => Some(HashFunction::Sha384),
            o if o == OID_SHA512 => Some(HashFunction::Sha512),
            _ => None,
        }
    }

    /// Read one from the spelling a receipt's payload uses, `sha-256` and its two siblings.
    #[must_use]
    pub fn from_receipt_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(HashFunction::Sha256),
            "sha-384" => Some(HashFunction::Sha384),
            "sha-512" => Some(HashFunction::Sha512),
            _ => None,
        }
    }

    /// The bytes of its DER object identifier.
    #[must_use]
    pub fn oid(self) -> &'static [u8] {
        match self {
            HashFunction::Sha256 => OID_SHA256,
            HashFunction::Sha384 => OID_SHA384,
            HashFunction::Sha512 => OID_SHA512,
        }
    }

    /// The spelling a receipt's payload uses.
    #[must_use]
    pub fn receipt_name(self) -> &'static str {
        match self {
            HashFunction::Sha256 => "sha-256",
            HashFunction::Sha384 => "sha-384",
            HashFunction::Sha512 => "sha-512",
        }
    }

    /// The spelling a person reads.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            HashFunction::Sha256 => "SHA-256",
            HashFunction::Sha384 => "SHA-384",
            HashFunction::Sha512 => "SHA-512",
        }
    }

    /// How many bytes a hash from this function is.
    ///
    /// This is the fact a label cannot be checked without.
    #[must_use]
    pub fn length(self) -> usize {
        match self {
            HashFunction::Sha256 => 32,
            HashFunction::Sha384 => 48,
            HashFunction::Sha512 => 64,
        }
    }

    /// Hash some bytes with it.
    #[must_use]
    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            HashFunction::Sha256 => Sha256::digest(bytes).to_vec(),
            HashFunction::Sha384 => Sha384::digest(bytes).to_vec(),
            HashFunction::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_function_agrees_with_itself_on_how_long_its_hash_is() {
        // The point of the table is that a name and a length can be checked against each other, so
        // the one test worth having is that the table's own two halves match the arithmetic.
        for f in [
            HashFunction::Sha256,
            HashFunction::Sha384,
            HashFunction::Sha512,
        ] {
            assert_eq!(
                f.digest(b"anything at all").len(),
                f.length(),
                "{}",
                f.name()
            );
            assert_eq!(HashFunction::from_oid(f.oid()), Some(f));
            assert_eq!(HashFunction::from_receipt_name(f.receipt_name()), Some(f));
        }
    }

    #[test]
    fn a_name_this_code_does_not_know_reads_back_as_nothing() {
        assert_eq!(HashFunction::from_receipt_name("sha-1"), None);
        assert_eq!(HashFunction::from_receipt_name("SHA-256"), None);
        assert_eq!(HashFunction::from_oid(&[0x2a, 0x03]), None);
    }
}
