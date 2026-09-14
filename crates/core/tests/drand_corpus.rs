//! Real drand rounds, and every way of spoiling one.
//!
//! Three rounds from the quicknet chain, fetched on 2026-09-07 and checked here with no network at
//! all. One is round one from 2023, one is a round from the middle of the chain, and one is from
//! the day they were captured, so the schedule arithmetic is exercised over three years rather than
//! over one point.
//!
//! There is no fake server in this file and there cannot be, because building one would mean
//! holding the group's signing key. Everything hostile here is therefore done to a real round: the
//! signature spoiled, the round number moved under the signature, the chain swapped, the point
//! taken off the curve. That is the right shape anyway. A forged drand round is not something an
//! attacker can make either.

use timewitness_core::evidence::drand::{self, Chain};
use timewitness_core::evidence::EvidenceError;
use timewitness_core::time::NANOS_PER_SEC;

const ROUNDS: &str = include_str!("data/drand/rounds.txt");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

struct Round {
    number: u64,
    signature: Vec<u8>,
    randomness: Vec<u8>,
}

fn rounds() -> Vec<Round> {
    ROUNDS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            Round {
                number: parts.next().expect("a round").parse().expect("a number"),
                signature: unhex(parts.next().expect("a signature")),
                randomness: unhex(parts.next().expect("a randomness")),
            }
        })
        .collect()
}

fn blob(chain: &Chain, r: &Round) -> Vec<u8> {
    drand::pack_blob(&chain.hash, r.number, &r.signature)
}

#[test]
fn every_captured_round_verifies_with_no_network_at_all() {
    let chain = Chain::quicknet();
    let all = rounds();
    assert_eq!(all.len(), 3, "three rounds were captured");
    for r in &all {
        let checked = drand::check(&blob(&chain, r), &chain).unwrap_or_else(|e| {
            panic!(
                "round {} was captured verified and no longer is: {e}",
                r.number
            )
        });
        assert_eq!(checked.scheme, "drand");
        assert_eq!(
            checked.earliest(),
            checked.latest(),
            "a round is an instant and must not be given a width"
        );
        assert_eq!(checked.nonce, None, "a beacon signs nothing of ours");
        assert_eq!(
            checked.earliest().as_nanos() / NANOS_PER_SEC,
            i128::from(chain.time_of(r.number).expect("on the schedule"))
        );
    }
}

#[test]
fn the_randomness_a_relay_prints_is_the_hash_of_the_signature_and_nothing_more() {
    // Worth proving rather than assuming, because it is the reason the randomness is not stored:
    // a value anybody can recompute from what is stored is a value that should be recomputed.
    for r in rounds() {
        assert_eq!(
            drand::randomness_of(&r.signature).to_vec(),
            r.randomness,
            "round {} does not hash to the randomness the relay printed",
            r.number
        );
    }
}

#[test]
fn the_schedule_puts_the_three_rounds_where_the_chain_says_they_are() {
    let chain = Chain::quicknet();
    assert_eq!(chain.time_of(1), Some(1_692_803_367));
    assert_eq!(chain.time_of(1_000_000), Some(1_692_803_367 + 999_999 * 3));
    assert_eq!(chain.time_of(32_000_388), Some(1_788_804_528));
    // The last one is on the day the corpus was captured, which is the only part of this a person
    // can sanity check by looking at it.
    assert!(chain.time_of(32_000_388).expect("on the schedule") > 1_788_700_000);
}

#[test]
fn a_flipped_bit_in_the_signature_is_refused() {
    let chain = Chain::quicknet();
    for r in rounds() {
        for at in [0usize, 1, 17, 30, 47] {
            let mut spoiled = r.signature.clone();
            spoiled[at] ^= 0x01;
            let packed = drand::pack_blob(&chain.hash, r.number, &spoiled);
            assert!(
                drand::check(&packed, &chain).is_err(),
                "round {} accepted a signature with byte {at} flipped",
                r.number
            );
        }
    }
}

#[test]
fn moving_the_round_number_under_a_real_signature_is_refused() {
    // The round number is the whole message. Changing it and keeping the signature is the exact
    // shape of a lie about when a value became public.
    let chain = Chain::quicknet();
    for r in rounds() {
        for shift in [1i64, -1, 1000, -1000] {
            let moved = (r.number as i64 + shift).max(1) as u64;
            if moved == r.number {
                continue;
            }
            let packed = drand::pack_blob(&chain.hash, moved, &r.signature);
            let err = drand::check(&packed, &chain)
                .expect_err("a signature carried across to a different round");
            assert!(matches!(err, EvidenceError::BadSignature(_)), "{err}");
        }
    }
}

#[test]
fn swapping_two_real_signatures_is_refused_both_ways() {
    let chain = Chain::quicknet();
    let all = rounds();
    for i in 0..all.len() {
        let other = &all[(i + 1) % all.len()];
        let packed = drand::pack_blob(&chain.hash, all[i].number, &other.signature);
        assert!(
            drand::check(&packed, &chain).is_err(),
            "round {} accepted round {}'s signature",
            all[i].number,
            other.number
        );
    }
}

#[test]
fn a_round_offered_under_a_different_chain_is_refused_before_any_pairing() {
    let chain = Chain::quicknet();
    let r = &rounds()[0];
    let mut other = chain.hash;
    other[0] ^= 0x01;
    let packed = drand::pack_blob(&other, r.number, &r.signature);
    let err = drand::check(&packed, &chain).expect_err("a round claiming another chain");
    assert!(matches!(err, EvidenceError::Inconsistent(_)), "{err}");
}

#[test]
fn a_signature_that_is_not_a_point_on_the_curve_is_refused() {
    let chain = Chain::quicknet();
    // All ones is not a valid compressed point in this encoding.
    let packed = drand::pack_blob(&chain.hash, 1, &[0xffu8; 48]);
    let err = drand::check(&packed, &chain).expect_err("48 bytes that are not a point");
    assert!(matches!(err, EvidenceError::BadSignature(_)), "{err}");
}

#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let chain = Chain::quicknet();
    for length in [0usize, 1, 47, 49, 96] {
        let packed = drand::pack_blob(&chain.hash, 1, &vec![0u8; length]);
        assert!(
            drand::check(&packed, &chain).is_err(),
            "a {length} byte signature was accepted"
        );
    }
}

#[test]
fn round_zero_is_not_on_the_schedule_and_is_refused() {
    let chain = Chain::quicknet();
    assert_eq!(chain.time_of(0), None);
    let r = &rounds()[0];
    let packed = drand::pack_blob(&chain.hash, 0, &r.signature);
    assert!(drand::check(&packed, &chain).is_err());
}

#[test]
fn a_truncated_round_is_refused_at_every_length() {
    let chain = Chain::quicknet();
    let full = blob(&chain, &rounds()[0]);
    for length in 0..full.len() {
        assert!(
            drand::check(&full[..length], &chain).is_err(),
            "a round cut to {length} bytes still verified"
        );
    }
}
