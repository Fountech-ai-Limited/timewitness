//! The public log of agent keys, and the proofs a stranger checks it with.
//!
//! # The problem it exists for
//!
//! A receipt carries the agent's public key and a signature by it. That proves the agent held the
//! key. It does not prove the key is one of ours, and the verifier says so in those words: the step
//! `is that key one of ours` has read `nothing here can say` since the verifier was written. A
//! reader who knows the key can compare it themselves and a reader who does not learns nothing.
//!
//! The answer is a log: every agent key we issue, appended, publicly readable, and shaped so that
//! removing or reordering an entry is something a reader can catch rather than something they have
//! to trust us not to do.
//!
//! # What a log of ours can and cannot prove, said before the code rather than after it
//!
//! **It can prove append-only, to anybody who has seen an earlier head.** Two tree heads, the older
//! smaller, have a consistency proof between them or they do not. If we remove an entry, reorder
//! two, or change one, no consistency proof exists from any head anybody already holds, and every
//! reader who kept one sees it. That is the whole of what a Merkle log buys and it is worth having.
//!
//! **It cannot prove anything at all to somebody seeing it for the first time.** A reader with one
//! head and no history is looking at a list we signed, and we could have signed a different list
//! for them than for everybody else. That is the split-view attack and no amount of hashing inside
//! a log we alone sign will touch it. The fixes are other people: a witness that co-signs heads, a
//! gossip protocol between readers, or anchoring each head into something we do not control. None
//! of those is here and this file does not pretend otherwise.
//!
//! So the honest sentence, and it belongs on every surface that mentions this log: **it makes a key
//! we published something we cannot quietly unpublish. It does not make us trustworthy to a
//! stranger, and our own word is still never third-party evidence: the weight of a receipt rests on
//! the third-party signatures in it, never on ours.**
//!
//! # The tree
//!
//! RFC 6962's shape, which is the one every transparency log uses and the one readers already have
//! implementations of. A leaf is hashed under a `0x00` prefix and an interior node under `0x01`, so
//! no interior node can be mistaken for a leaf, and the tree is built by splitting at the largest
//! power of two below the size rather than by padding to one. The hash is SHA-256 rather than
//! Roughtime's truncated SHA-512: this is our own format and picking the one everybody's tooling
//! already has costs nothing.

pub mod file;

use core::fmt;

use sha2::{Digest, Sha256};

use crate::time::UnixNanos;

/// The prefix a leaf is hashed under.
const LEAF_PREFIX: u8 = 0x00;
/// The prefix an interior node is hashed under.
const NODE_PREFIX: u8 = 0x01;

/// One agent key, as the log records it.
///
/// # Why a window and not just a date
///
/// Agent keys are short-lived and rotate, which is the design's own answer to a key being
/// extracted: a stolen key is worth what is left of its window. A reader checking a receipt from
/// last March needs to know the key was ours *then*, so the entry states when the key was valid
/// rather than when it was written down. A log that recorded only "this key is ours" would say
/// nothing about a receipt signed after the key was retired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    /// The agent's public key, as it appears in a receipt.
    pub public_key: [u8; 32],
    /// Which deployment this key belonged to, as a name a person reads.
    ///
    /// Not an identity claim about a person or a company. It is a label, it is chosen by whoever
    /// runs the agent, and two deployments may choose the same one. A reader who needs to know
    /// whose machine signed something needs more than a log, and this field is not it.
    pub deployment: String,
    /// The first moment a receipt signed by this key should be believed to be ours.
    pub valid_from: UnixNanos,
    /// The last such moment, where the key has been retired.
    ///
    /// `None` means still in use at the moment the entry was written. It is never edited in place:
    /// retiring a key appends a new entry, because a log whose old entries change is not a log.
    pub valid_until: Option<UnixNanos>,
}

impl KeyEntry {
    /// The bytes this entry is hashed over.
    ///
    /// Written out by hand rather than serialised through a general encoder, because the leaf hash
    /// is what every proof is built on: a change in how this is laid out silently invalidates every
    /// proof anybody has ever been given. Each field is length-prefixed so that no two different
    /// entries can produce the same bytes by moving a boundary, which is the classic way a log is
    /// made to hold two entries that hash alike.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.public_key);
        let name = self.deployment.as_bytes();
        out.extend_from_slice(&(name.len() as u64).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&self.valid_from.0.to_le_bytes());
        match self.valid_until {
            Some(until) => {
                out.push(1);
                out.extend_from_slice(&until.0.to_le_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// This entry's leaf hash.
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        hash(&[&[LEAF_PREFIX], &self.canonical()])
    }

    /// Whether this entry vouches for the key at a moment.
    #[must_use]
    pub fn covers(&self, at: UnixNanos) -> bool {
        at >= self.valid_from
            && match self.valid_until {
                Some(until) => at <= until,
                None => true,
            }
    }
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn interior(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(&[&[NODE_PREFIX], left, right])
}

/// The largest power of two strictly below `n`, for `n` above one.
///
/// RFC 6962 splits a tree of `n` leaves at this point rather than in the middle, which is what makes
/// every prefix of the log a subtree of every longer one, which is what makes a consistency proof
/// possible at all. Splitting in the middle would give a perfectly good Merkle tree with no
/// append-only property.
fn split(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The root of a tree over these leaf hashes.
///
/// An empty log hashes to the SHA-256 of nothing, which is RFC 6962's rule and is stated rather
/// than invented: an empty log still has a head, and a head that could not exist until the first
/// entry would mean nobody could hold a head from before the first key was issued.
#[must_use]
pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => hash(&[]),
        1 => leaves[0],
        n => {
            let k = split(n);
            interior(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// A signed statement of what the log held at a moment.
///
/// The signature is ours. See the heading: it makes the log something we cannot quietly rewrite for
/// a reader who kept an old head, and it is not a reason for a stranger to believe anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeHead {
    /// How many entries the log held.
    pub size: usize,
    /// The root over those entries.
    pub root: [u8; 32],
    /// When we said so.
    pub at: UnixNanos,
}

impl TreeHead {
    /// The bytes a head is signed over.
    ///
    /// Length-prefixed and fixed-width for the same reason [`KeyEntry::canonical`] is: two heads
    /// that could produce the same bytes would let a signature be moved between them.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 16);
        out.extend_from_slice(&(self.size as u64).to_le_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.at.0.to_le_bytes());
        out
    }
}

/// Why a proof did not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogError {
    /// The proof does not reach the root it was offered against.
    DoesNotReach(String),
    /// The proof is the wrong shape for the tree it claims to be about.
    Malformed(String),
    /// The two heads cannot be compared in the direction asked.
    NotComparable(String),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogError::DoesNotReach(d) => write!(f, "the proof does not reach the root: {d}"),
            LogError::Malformed(d) => write!(f, "the proof is the wrong shape: {d}"),
            LogError::NotComparable(d) => write!(f, "these two heads cannot be compared: {d}"),
        }
    }
}

/// The hashes proving one leaf is in a tree of a given size.
#[must_use]
pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut leaves = leaves;
    let mut index = index;
    while leaves.len() > 1 {
        let k = split(leaves.len());
        if index < k {
            path.push(root(&leaves[k..]));
            leaves = &leaves[..k];
        } else {
            path.push(root(&leaves[..k]));
            leaves = &leaves[k..];
            index -= k;
        }
    }
    path.reverse();
    path
}

/// Check that a leaf sits at `index` in a tree of `size` leaves with this root.
///
/// # Errors
///
/// A path that cannot reach the index it claims, and a path that reaches a different root.
pub fn check_inclusion(
    leaf: &[u8; 32],
    index: usize,
    size: usize,
    path: &[[u8; 32]],
    root_hash: &[u8; 32],
) -> Result<(), LogError> {
    if index >= size {
        return Err(LogError::Malformed(format!(
            "a proof for entry {index} in a log of {size} entries, which has no such entry"
        )));
    }

    // Walk down recording which side each step is on, then fold back up. Doing it in one pass the
    // other way needs the tree shape, which the verifier does not have and must not need.
    let mut sides = Vec::new();
    let (mut lo, mut hi, mut idx) = (0usize, size, index);
    while hi - lo > 1 {
        let k = split(hi - lo);
        if idx < k {
            sides.push(true);
            hi = lo + k;
        } else {
            sides.push(false);
            lo += k;
            idx -= k;
        }
    }
    if sides.len() != path.len() {
        return Err(LogError::Malformed(format!(
            "a path of {} hashes where a log of {size} needs {} to reach entry {index}",
            path.len(),
            sides.len()
        )));
    }

    let mut current = *leaf;
    for (step, on_the_left) in sides.iter().rev().enumerate() {
        let sibling = &path[step];
        current = if *on_the_left {
            interior(&current, sibling)
        } else {
            interior(sibling, &current)
        };
    }

    if current == *root_hash {
        Ok(())
    } else {
        Err(LogError::DoesNotReach(format!(
            "entry {index} of {size} does not reach the root this head states"
        )))
    }
}

/// The hashes proving a log of `old` entries is a prefix of one of `new` entries.
///
/// This is the proof the whole file is for. Without it a log is a list somebody publishes and can
/// edit; with it, editing is something every reader who kept an old head can catch.
#[must_use]
pub fn consistency_proof(leaves: &[[u8; 32]], old: usize) -> Vec<[u8; 32]> {
    let new = leaves.len();
    if old == 0 || old >= new {
        return Vec::new();
    }
    subtree_proof(leaves, old, true)
}

/// The walk both proofs share. `whole` says the old tree is still a complete subtree here, which is
/// the case where its own root is already known to the verifier and need not be sent.
fn subtree_proof(leaves: &[[u8; 32]], old: usize, whole: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if old == n {
        return if whole {
            Vec::new()
        } else {
            vec![root(leaves)]
        };
    }
    let k = split(n);
    if old <= k {
        let mut proof = subtree_proof(&leaves[..k], old, whole);
        proof.push(root(&leaves[k..]));
        proof
    } else {
        let mut proof = subtree_proof(&leaves[k..], old - k, false);
        proof.push(root(&leaves[..k]));
        proof
    }
}

/// Check that the log of `old.size` entries is a prefix of the log of `new.size` entries.
///
/// This is RFC 6962's own verification algorithm rather than one written for this file. The first
/// attempt here was a hand-rolled fold over the same tree walk the proof generator uses, and it was
/// wrong for every log whose old size was a power of two: it demanded a hash the proof deliberately
/// omits. The published algorithm is the one every other implementation runs, so a proof this code
/// accepts is one somebody else's verifier accepts too, which for a log whose whole purpose is
/// being checkable by strangers is the point rather than a convenience.
///
/// # Errors
///
/// Heads in the wrong order, a proof of the wrong length or shape, and a proof that reaches either
/// the wrong old root or the wrong new one. Both roots are checked. A proof that reached the new
/// root while reaching a different old root would be saying the new log extends a log nobody holds,
/// which is exactly the answer a rewritten log would like to give.
pub fn check_consistency(
    old: &TreeHead,
    new: &TreeHead,
    proof: &[[u8; 32]],
) -> Result<(), LogError> {
    if old.size > new.size {
        return Err(LogError::NotComparable(format!(
            "a log of {} entries cannot be a prefix of one of {}",
            old.size, new.size
        )));
    }
    if old.size == new.size {
        return if old.root == new.root && proof.is_empty() {
            Ok(())
        } else if old.root != new.root {
            Err(LogError::DoesNotReach(
                "two heads of the same size with different roots, so one of them is not this log"
                    .to_string(),
            ))
        } else {
            Err(LogError::Malformed(
                "a proof offered between two heads of the same size, where there is nothing to \
                 prove"
                    .to_string(),
            ))
        };
    }
    if old.size == 0 {
        // Every log extends the empty one and there is nothing to prove. Said explicitly because
        // the walk below divides by the old size.
        return Ok(());
    }

    // The proof omits the old tree's own root exactly when the old size is a power of two, because
    // in that case the old tree is a complete left subtree of the new one and the verifier already
    // holds its root. This is the case a hand-rolled implementation gets wrong, because the sizes
    // people test with are usually not powers of two.
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if old.size.is_power_of_two() {
        hashes.push(old.root);
    }
    hashes.extend_from_slice(proof);

    let mut fn_ = old.size - 1;
    let mut sn = new.size - 1;
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut it = hashes.iter();
    let Some(seed) = it.next() else {
        return Err(LogError::Malformed(
            "a consistency proof with nothing in it, between two logs of different sizes"
                .to_string(),
        ));
    };
    let mut old_root = *seed;
    let mut new_root = *seed;

    for node in it {
        if sn == 0 {
            return Err(LogError::Malformed(
                "a consistency proof with more hashes in it than the two sizes can use".to_string(),
            ));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            old_root = interior(node, &old_root);
            new_root = interior(node, &new_root);
            while fn_ != 0 && fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            new_root = interior(&new_root, node);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if sn != 0 {
        return Err(LogError::Malformed(
            "a consistency proof that ran out of hashes before it reached the top".to_string(),
        ));
    }
    if old_root != old.root {
        return Err(LogError::DoesNotReach(
            "the proof reaches a different old root, so it is about a log nobody here holds"
                .to_string(),
        ));
    }
    if new_root != new.root {
        return Err(LogError::DoesNotReach(
            "the proof does not reach the new root this head states".to_string(),
        ));
    }
    Ok(())
}

/// What a reader concluded about one key, from the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The log vouches for this key at that moment.
    Published,
    /// The key is in the log and the moment is outside every window it names.
    OutsideItsWindow,
    /// The key is not in this log.
    NotInTheLog,
}

/// Whether these entries vouch for a key at a moment.
///
/// A reader with the whole log calls this. A reader with only a receipt and one entry checks the
/// entry's inclusion proof first and then asks this of the one entry, which is the same answer by a
/// cheaper route.
#[must_use]
pub fn standing(entries: &[KeyEntry], key: &[u8; 32], at: UnixNanos) -> Standing {
    let mut found = false;
    for entry in entries {
        if entry.public_key != *key {
            continue;
        }
        found = true;
        if entry.covers(at) {
            return Standing::Published;
        }
    }
    if found {
        Standing::OutsideItsWindow
    } else {
        Standing::NotInTheLog
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: u8, from: i128, until: Option<i128>) -> KeyEntry {
        KeyEntry {
            public_key: [key; 32],
            deployment: format!("deployment-{key}"),
            valid_from: UnixNanos(from),
            valid_until: until.map(UnixNanos),
        }
    }

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| entry(u8::try_from(i).unwrap(), 0, None).leaf_hash())
            .collect()
    }

    #[test]
    fn the_same_bytes_hash_differently_as_a_leaf_and_as_a_node() {
        // The whole of what the two prefixes buy, and it has to be tested at the hashing rather
        // than by comparing a leaf with a node built from it: those differ whatever the prefixes
        // are, so that test passes with the prefixes made equal and proves nothing. This one does
        // not. With one prefix, a reader could be handed an interior node as a leaf and shown a
        // shorter tree than the log really holds.
        let body = [7u8; 64];
        assert_ne!(
            hash(&[&[LEAF_PREFIX], &body]),
            hash(&[&[NODE_PREFIX], &body]),
            "a leaf and an interior node over the same bytes must not be the same hash"
        );

        let e = entry(1, 0, None);
        assert_eq!(e.leaf_hash(), hash(&[&[LEAF_PREFIX], &e.canonical()]));
    }

    #[test]
    fn two_different_entries_never_hash_alike_however_the_fields_are_moved() {
        // What the length prefix on the deployment name is for, built as the collision it prevents
        // rather than asserted as a principle.
        //
        // Without the prefix the fields run together, and an entry with a long name and no end
        // date can be laid out to produce exactly the same bytes as an entry with a short name, a
        // different start and an end date. The two entries below are that pair: one is a key that
        // never expires and the other is a key that was retired, and a log that could not tell them
        // apart could show a reader either one.
        //
        // The first attempt at this test compared the names "ab" and "a" with every other field
        // equal, which differ in length and so could never have collided. It passed with the length
        // prefix taken out, which is why the construction is here in full.
        let key = [5u8; 32];
        let long_name: [u8; 17] = *b"abcdefghijklmnopq";

        // The entry with the long name and no end date.
        let mut from_a = [0u8; 16];
        from_a[0] = 0x01; // becomes the "there is an end date" flag in the other reading
        for (i, b) in from_a.iter_mut().enumerate().skip(1) {
            *b = u8::try_from(i).unwrap();
        }
        let a = KeyEntry {
            public_key: key,
            deployment: String::from_utf8(long_name.to_vec()).unwrap(),
            valid_from: UnixNanos(i128::from_le_bytes(from_a)),
            valid_until: None,
        };

        // The same bytes read with the name one character long: the next sixteen become the start
        // date, the byte after that becomes the flag, and the rest becomes the end date.
        let mut from_b = [0u8; 16];
        from_b.copy_from_slice(&long_name[1..17]);
        let mut until_b = [0u8; 16];
        until_b[..15].copy_from_slice(&from_a[1..16]);
        let b = KeyEntry {
            public_key: key,
            deployment: String::from_utf8(long_name[..1].to_vec()).unwrap(),
            valid_from: UnixNanos(i128::from_le_bytes(from_b)),
            valid_until: Some(UnixNanos(i128::from_le_bytes(until_b))),
        };

        assert_ne!(a, b, "these are two different entries");
        assert_eq!(
            a.canonical().len(),
            b.canonical().len(),
            "and the construction only works if they are the same length"
        );
        assert_ne!(
            a.canonical(),
            b.canonical(),
            "two different entries must not encode to the same bytes"
        );
        assert_ne!(a.leaf_hash(), b.leaf_hash());
    }

    #[test]
    fn every_entry_of_every_log_up_to_thirty_two_proves_its_own_inclusion() {
        for size in 1..=32usize {
            let l = leaves(size);
            let r = root(&l);
            for index in 0..size {
                let path = inclusion_proof(&l, index);
                check_inclusion(&l[index], index, size, &path, &r)
                    .unwrap_or_else(|e| panic!("entry {index} of {size}: {e}"));
            }
        }
    }

    #[test]
    fn an_inclusion_proof_for_one_entry_does_not_prove_another() {
        let l = leaves(9);
        let r = root(&l);
        let path = inclusion_proof(&l, 3);

        assert!(check_inclusion(&l[4], 3, 9, &path, &r).is_err());
        assert!(check_inclusion(&l[3], 4, 9, &path, &r).is_err());
        // A stated size reaches this check only through the shape of the path to that index, so a
        // different size with the same shape is indistinguishable from the right one: entry 3 sits
        // four steps down in a log of 9 and in a log of 16 alike, and the same siblings rebuild the
        // same root. A size whose shape differs is caught, and 5 is one. This is written out
        // because it is easy to believe an inclusion proof pins the size of the log, and it does
        // not; what pins the size is the head the root came from.
        assert!(check_inclusion(&l[3], 3, 5, &path, &r).is_err());
        assert!(check_inclusion(&l[3], 9, 9, &path, &r).is_err());

        let mut bent = path.clone();
        bent[0][0] ^= 1;
        assert!(check_inclusion(&l[3], 3, 9, &bent, &r).is_err());
    }

    #[test]
    fn every_prefix_of_every_log_up_to_thirty_two_proves_its_own_consistency() {
        for new in 1..=32usize {
            let l = leaves(new);
            let new_head = TreeHead {
                size: new,
                root: root(&l),
                at: UnixNanos(0),
            };
            for old in 0..=new {
                let old_head = TreeHead {
                    size: old,
                    root: root(&l[..old]),
                    at: UnixNanos(0),
                };
                let proof = consistency_proof(&l, old);
                check_consistency(&old_head, &new_head, &proof)
                    .unwrap_or_else(|e| panic!("{old} into {new}: {e}"));
            }
        }
    }

    #[test]
    fn a_log_that_changed_an_old_entry_cannot_prove_consistency() {
        // The property the whole file is for. A reader holding the head of a nine entry log is
        // handed a twelve entry log whose fourth entry is different, and there is no proof.
        let honest = leaves(9);
        let old_head = TreeHead {
            size: 9,
            root: root(&honest),
            at: UnixNanos(0),
        };

        let mut rewritten = leaves(12);
        rewritten[3] = entry(99, 0, None).leaf_hash();
        let new_head = TreeHead {
            size: 12,
            root: root(&rewritten),
            at: UnixNanos(1),
        };

        let proof = consistency_proof(&rewritten, 9);
        let refused = check_consistency(&old_head, &new_head, &proof);
        assert!(
            matches!(refused, Err(LogError::DoesNotReach(_))),
            "a rewritten entry has to be catchable, got {refused:?}"
        );
    }

    #[test]
    fn a_log_that_removed_an_entry_cannot_prove_consistency() {
        let honest = leaves(9);
        let old_head = TreeHead {
            size: 9,
            root: root(&honest),
            at: UnixNanos(0),
        };

        let mut shortened = leaves(12);
        shortened.remove(3);
        let new_head = TreeHead {
            size: shortened.len(),
            root: root(&shortened),
            at: UnixNanos(1),
        };

        let proof = consistency_proof(&shortened, 9);
        assert!(check_consistency(&old_head, &new_head, &proof).is_err());
    }

    #[test]
    fn a_log_that_reordered_two_entries_cannot_prove_consistency() {
        let honest = leaves(9);
        let old_head = TreeHead {
            size: 9,
            root: root(&honest),
            at: UnixNanos(0),
        };

        let mut swapped = leaves(12);
        swapped.swap(2, 5);
        let new_head = TreeHead {
            size: 12,
            root: root(&swapped),
            at: UnixNanos(1),
        };

        assert!(check_consistency(&old_head, &new_head, &consistency_proof(&swapped, 9)).is_err());
    }

    #[test]
    fn a_head_cannot_be_a_prefix_of_a_smaller_one() {
        let l = leaves(9);
        let big = TreeHead {
            size: 9,
            root: root(&l),
            at: UnixNanos(0),
        };
        let small = TreeHead {
            size: 4,
            root: root(&l[..4]),
            at: UnixNanos(0),
        };
        assert!(matches!(
            check_consistency(&big, &small, &[]),
            Err(LogError::NotComparable(_))
        ));
    }

    #[test]
    fn two_heads_of_one_size_with_different_roots_are_two_different_logs() {
        let a = TreeHead {
            size: 4,
            root: root(&leaves(4)),
            at: UnixNanos(0),
        };
        let b = TreeHead {
            size: 4,
            root: [7; 32],
            at: UnixNanos(0),
        };
        assert!(check_consistency(&a, &b, &[]).is_err());
    }

    #[test]
    fn a_key_is_vouched_for_inside_its_window_and_not_outside_it() {
        let entries = vec![
            entry(1, 100, Some(200)),
            entry(2, 150, None),
            entry(1, 300, Some(400)),
        ];

        assert_eq!(
            standing(&entries, &[1; 32], UnixNanos(150)),
            Standing::Published
        );
        assert_eq!(
            standing(&entries, &[1; 32], UnixNanos(350)),
            Standing::Published,
            "a key reissued later is vouched for in the second window too"
        );
        assert_eq!(
            standing(&entries, &[1; 32], UnixNanos(250)),
            Standing::OutsideItsWindow,
            "and not in the gap between them"
        );
        assert_eq!(
            standing(&entries, &[2; 32], UnixNanos(10_000)),
            Standing::Published,
            "an entry with no end is still current"
        );
        assert_eq!(
            standing(&entries, &[3; 32], UnixNanos(150)),
            Standing::NotInTheLog
        );
    }

    #[test]
    fn a_retired_key_is_a_new_entry_rather_than_an_edit() {
        // Stated as a test because it is the rule that makes the log a log. Retiring key 1 appends
        // an entry with an end on it; the original entry is untouched, so every proof anybody was
        // given for it still holds.
        let original = entry(1, 100, None);
        let retired = KeyEntry {
            valid_until: Some(UnixNanos(200)),
            ..original.clone()
        };
        assert_ne!(original.leaf_hash(), retired.leaf_hash());

        let l = vec![original.leaf_hash()];
        let before = root(&l);
        let after_leaves = vec![original.leaf_hash(), retired.leaf_hash()];

        check_inclusion(
            &original.leaf_hash(),
            0,
            1,
            &inclusion_proof(&l, 0),
            &before,
        )
        .expect("the old proof still holds against the old head");
        check_consistency(
            &TreeHead {
                size: 1,
                root: before,
                at: UnixNanos(0),
            },
            &TreeHead {
                size: 2,
                root: root(&after_leaves),
                at: UnixNanos(1),
            },
            &consistency_proof(&after_leaves, 1),
        )
        .expect("and the log that grew is consistent with it");
    }

    #[test]
    fn an_empty_log_still_has_a_head() {
        // So that a reader can hold one from before the first key was ever issued, and check
        // everything since against it.
        assert_eq!(root(&[]), hash(&[]));
        let empty = TreeHead {
            size: 0,
            root: root(&[]),
            at: UnixNanos(0),
        };
        let l = leaves(5);
        let five = TreeHead {
            size: 5,
            root: root(&l),
            at: UnixNanos(1),
        };
        check_consistency(&empty, &five, &consistency_proof(&l, 0))
            .expect("every log extends the empty one");
    }

    #[test]
    fn a_head_signs_over_all_three_of_its_fields() {
        let a = TreeHead {
            size: 4,
            root: [1; 32],
            at: UnixNanos(5),
        };
        for b in [
            TreeHead {
                size: 5,
                ..a.clone()
            },
            TreeHead {
                root: [2; 32],
                ..a.clone()
            },
            TreeHead {
                at: UnixNanos(6),
                ..a.clone()
            },
        ] {
            assert_ne!(
                a.canonical(),
                b.canonical(),
                "a signature over a head must not move to a different one"
            );
        }
    }
}
