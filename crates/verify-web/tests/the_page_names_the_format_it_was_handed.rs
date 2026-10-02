//! The page names the format of the receipt in hand, and the formats it reads, off the checking code.
//!
//! It printed "Receipt format v0" as a constant under its form until 2026-09-24, while the module
//! behind it had read version 1 since `v0.2`. Nothing held the words to the code, so the words kept
//! saying what was true on the day they were written. These hold both to the code: the list of
//! formats the page prints is the list the verifier reads, and the version the page prints beside a
//! receipt is the one written in that receipt's own bytes.

use std::path::Path;

use timewitness_receipt::READS;
use timewitness_verify_web::{formats_json, json_for};

fn data(path: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/verify/tests/data")
        .join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn from_hex(text: &[u8]) -> Vec<u8> {
    let digits: Vec<u8> = text.iter().copied().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// One CBOR item's head: its major type, its argument, and where the bytes after the head start.
/// Definite lengths only, which is all deterministic CBOR has.
fn head(bytes: &[u8], at: usize) -> (u8, u64, usize) {
    let first = bytes[at];
    let (major, low) = (first >> 5, first & 0x1f);
    let (argument, after) = match low {
        0..=23 => (u64::from(low), at + 1),
        24..=27 => {
            let width = 1usize << (low - 24);
            let mut n = 0u64;
            for byte in &bytes[at + 1..at + 1 + width] {
                n = (n << 8) | u64::from(*byte);
            }
            (n, at + 1 + width)
        }
        _ => panic!("an indefinite or reserved length at byte {at}"),
    };
    (major, argument, after)
}

/// Where the item starting at `at` ends.
fn skip(bytes: &[u8], at: usize) -> usize {
    let (major, argument, after) = head(bytes, at);
    let count = usize::try_from(argument).expect("a length that fits");
    match major {
        0 | 1 | 7 => after,
        2 | 3 => after + count,
        4 => (0..count).fold(after, |next, _| skip(bytes, next)),
        5 => (0..count * 2).fold(after, |next, _| skip(bytes, next)),
        6 => skip(bytes, after),
        _ => unreachable!("a major type is three bits"),
    }
}

/// The version the receipt's own bytes carry, read by hand rather than by anything of ours: a
/// COSE_Sign1 array whose third element is a byte string holding a map with the text key `v`.
fn version_in_the_bytes(receipt: &[u8]) -> i128 {
    let (major, count, mut at) = head(receipt, 0);
    assert_eq!((major, count), (4, 4), "not a four element array");
    at = skip(receipt, at);
    at = skip(receipt, at);
    let (major, length, start) = head(receipt, at);
    assert_eq!(major, 2, "the payload is not a byte string");
    let payload = &receipt[start..start + usize::try_from(length).expect("fits")];
    let (major, entries, mut at) = head(payload, 0);
    assert_eq!(major, 5, "the payload is not a map");
    for _ in 0..entries {
        let key_end = skip(payload, at);
        let is_v = payload[at..key_end] == [0x61, b'v'];
        if is_v {
            let (major, value, _) = head(payload, key_end);
            assert_eq!(major, 0, "the version is not an unsigned integer");
            return i128::from(value);
        }
        at = skip(payload, key_end);
    }
    panic!("no key v in the payload")
}

/// The version the checking code tells the page, which is what the page prints beside a receipt.
fn version_the_page_is_given(receipt: &[u8]) -> i128 {
    let text = json_for(receipt, None);
    text.split("\"format_version\":")
        .nth(1)
        .and_then(|rest| rest.split([',', '}']).next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("the page was given no format version: {text}"))
}

#[test]
fn the_page_is_given_the_version_a_version_1_receipt_carries() {
    let receipt = from_hex(&data("a-version-1-stamp/receipt.hex"));
    assert_eq!(version_in_the_bytes(&receipt), 1);
    assert_eq!(version_the_page_is_given(&receipt), 1);
}

#[test]
fn the_page_is_given_the_version_a_version_0_receipt_carries() {
    let receipt = data("a-real-stamp/receipt.cbor");
    assert_eq!(version_in_the_bytes(&receipt), 0);
    assert_eq!(version_the_page_is_given(&receipt), 0);
}

#[test]
fn the_formats_the_page_lists_are_the_ones_the_verifier_reads() {
    let listed: Vec<String> = READS.iter().map(i128::to_string).collect();
    let said: String = formats_json().split_whitespace().collect();
    assert_eq!(said, format!("{{\"reads\":[{}]}}", listed.join(",")));
}
