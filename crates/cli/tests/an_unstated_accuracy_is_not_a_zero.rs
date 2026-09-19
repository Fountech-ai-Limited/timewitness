//! What a reader is told when the authority said nothing about its own accuracy.
//!
//! An RFC 3161 token may leave the accuracy field out, and the one on the committed real receipt
//! does. Until 2026-09-19 the command line answered that with "to a stated accuracy of 0 ns", which
//! a reader takes as the authority vouching for a perfect time. It is the opposite: the authority
//! put no number on its own error at all. A tester reported it in those words on 2026-09-15.
//!
//! This runs the shipped binary over the receipt three real third parties signed, so it holds the
//! surface a person actually reads rather than the function under it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Everything `timewitness verify` prints for a receipt, both streams together.
fn verify(receipt: &Path) -> String {
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(receipt)
        .output()
        .expect("the binary runs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    )
}

/// The line about what the token states, whichever authority it names.
fn the_token_line(printed: &str) -> String {
    printed
        .lines()
        .find(|line| line.contains("states it saw this hash at"))
        .unwrap_or_else(|| panic!("nothing in the output says what the token states:\n{printed}"))
        .trim()
        .to_string()
}

#[test]
fn the_real_receipt_says_the_accuracy_was_not_stated() {
    let printed = verify(&repository().join("crates/verify/tests/data/a-real-stamp/receipt.cbor"));
    let line = the_token_line(&printed);
    assert!(
        line.contains("accuracy not stated"),
        "the line should say the authority stated none and it says {line:?}"
    );
}

#[test]
fn and_never_prints_a_figure_the_authority_did_not_write() {
    let printed = verify(&repository().join("crates/verify/tests/data/a-real-stamp/receipt.cbor"));
    assert!(
        !printed.contains("accuracy of 0 ns"),
        "a zero is still being shown for an accuracy nobody stated:\n{printed}"
    );
}
