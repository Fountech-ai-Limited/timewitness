//! Every single-bit change anywhere in a receipt is refused.
//!
//! This is acceptance item A-01 held in the suite: each committed receipt is checked as it is, then
//! every bit of it is changed in turn and each changed copy has to be refused. No bit is skipped,
//! including the witness over the signature, which sits outside the agent's signature and until
//! 2026-09-24 was where 5,078 of 16,012 one-bit changes to a fresh receipt still verified. On the
//! committed version 1 receipt, before the witness was held to one spelling, 40,606 of its 128,136
//! changes verified.
//!
//! `scripts/every-bit-refused.sh` holds the same property to the shipped command line, one process
//! per change and with the network taken away. This is the same sweep in one process, so it runs on
//! every machine the suite runs on and names the byte and bit that got through.
//!
//! A receipt of your own can be swept the same way. Set `TW_EVERY_BIT_RECEIPT` to its path and
//! `TW_EVERY_BIT_SUBJECT` to what it stamps, and run this test on its own. It is ignored unless asked
//! for, so a run without the two set says it was skipped rather than counting as a pass:
//!
//! ```text
//! cargo test -p timewitness-verify --test every_bit_of_a_receipt -- --ignored a_receipt_named_in_the_environment
//! ```

use std::thread;

use timewitness_verify::{anchor_file, verify, Floor, Subject};

const VERSION_1_SUBJECT: &[u8] = include_bytes!("data/a-version-1-stamp/subject.bin");

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

/// Change every bit of `receipt` in turn and return where a changed copy was still accepted.
///
/// Split across the machine's cores, because one receipt is a hundred thousand verifications or more
/// and a test that slow gets skipped by whoever is waiting for it.
fn sweep(receipt: &[u8], subject: Subject<'_>) -> (usize, Vec<(usize, u8)>) {
    let anchors = anchor_file::published();
    let floor = Floor::default();
    let whole = verify(receipt, subject, &anchors, &floor);
    assert!(
        whole.accepted(),
        "the receipt under test is refused as it is, so every change below would be refused for \
         the wrong reason: {:?}",
        whole.refusal()
    );

    let bits = receipt.len() * 8;
    let workers = thread::available_parallelism().map_or(1, |n| n.get());
    let share = bits.div_ceil(workers);
    let mut accepted: Vec<(usize, u8)> = thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let (anchors, floor) = (&anchors, &floor);
                scope.spawn(move || {
                    let mut through = Vec::new();
                    let mut changed = receipt.to_vec();
                    for index in (worker * share)..((worker + 1) * share).min(bits) {
                        let (at, bit) = (index / 8, (index % 8) as u8);
                        changed[at] ^= 1 << bit;
                        if verify(&changed, subject, anchors, floor).accepted() {
                            through.push((at, bit));
                        }
                        changed[at] ^= 1 << bit;
                    }
                    through
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("a sweep worker ran to the end"))
            .collect()
    });
    accepted.sort_unstable();
    (bits, accepted)
}

fn every_bit_is_refused(name: &str, receipt: &[u8], subject: Subject<'_>) {
    let (tried, accepted) = sweep(receipt, subject);
    assert!(
        accepted.is_empty(),
        "{name}: {} of {tried} single-bit changes still verify, the first at byte and bit {:?}",
        accepted.len(),
        &accepted[..accepted.len().min(8)]
    );
    println!("{name}: all {tried} single-bit changes refused");
}

#[test]
fn every_bit_of_the_committed_version_0_receipt() {
    every_bit_is_refused(
        "a-real-stamp",
        include_bytes!("data/a-real-stamp/receipt.cbor"),
        Subject::Bytes(include_bytes!("data/a-real-stamp/subject.bin")),
    );
}

#[test]
fn every_bit_of_the_backdated_receipt() {
    every_bit_is_refused(
        "a-backdated-receipt",
        &from_hex(include_str!("data/a-backdated-receipt/receipt.hex")),
        Subject::Bytes(include_bytes!("data/a-real-stamp/subject.bin")),
    );
}

#[test]
fn every_bit_of_the_runner_receipt_of_2026_09_14() {
    every_bit_is_refused(
        "a-runner-receipt-2026-09-14",
        &from_hex(include_str!("data/a-runner-receipt-2026-09-14/receipt.hex")),
        Subject::NotSupplied,
    );
}

#[test]
fn every_bit_of_the_committed_version_1_receipt_and_its_witness() {
    every_bit_is_refused(
        "a-version-1-stamp",
        &from_hex(include_str!("data/a-version-1-stamp/receipt.hex")),
        Subject::Bytes(VERSION_1_SUBJECT),
    );
}

#[test]
fn every_bit_of_a_sectigo_witness_named_by_sha_1() {
    every_bit_is_refused(
        "a-version-1-stamp-witnessed-again/sectigo",
        &from_hex(include_str!(
            "data/a-version-1-stamp-witnessed-again/sectigo.hex"
        )),
        Subject::Bytes(VERSION_1_SUBJECT),
    );
}

#[test]
fn every_bit_of_a_digicert_witness_as_the_stamp_now_stores_it() {
    every_bit_is_refused(
        "a-version-1-stamp-witnessed-again/digicert",
        &from_hex(include_str!(
            "data/a-version-1-stamp-witnessed-again/digicert.hex"
        )),
        Subject::Bytes(VERSION_1_SUBJECT),
    );
}

#[test]
#[ignore = "sweeps the receipt TW_EVERY_BIT_RECEIPT names, stamping TW_EVERY_BIT_SUBJECT; run it with --ignored"]
fn a_receipt_named_in_the_environment() {
    let path = std::env::var("TW_EVERY_BIT_RECEIPT")
        .expect("TW_EVERY_BIT_RECEIPT names the receipt to sweep");
    let receipt = std::fs::read(&path).expect("TW_EVERY_BIT_RECEIPT names a file");
    let subject = std::env::var("TW_EVERY_BIT_SUBJECT")
        .map(|p| std::fs::read(p).expect("TW_EVERY_BIT_SUBJECT names a file"))
        .expect("TW_EVERY_BIT_SUBJECT says what the receipt stamps");
    every_bit_is_refused(&path, &receipt, Subject::Bytes(&subject));
}
