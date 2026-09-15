//! The line under the verdict, through the shipped command line.
//!
//! The verdict counts the attestations that were checked, and a reader who stops there takes the
//! width beside it for something a third party vouched for. Until 2026-09-15 nothing on the first
//! two lines said otherwise: the committed receipt and one backdated three years on genuine
//! evidence printed the same first line and nothing under it. These hold the second line to saying
//! how wide the checked outside evidence brackets the moment and whose the width is, and each was
//! watched failing on the command line as it stood before that date.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The first two lines `timewitness verify --quiet` prints, and the exit code.
fn first_two(receipt: &Path, extra: &[&str]) -> (i32, String, String) {
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(receipt)
        .arg("--quiet")
        .args(extra)
        .output()
        .expect("the binary runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default().to_string();
    let second = lines.next().unwrap_or_default().to_string();
    (run.status.code().expect("an exit code"), first, second)
}

fn real() -> PathBuf {
    repository().join("crates/verify/tests/data/a-real-stamp/receipt.cbor")
}

/// The backdated receipt, written out from the hex it is kept as. The tree holds one binary file and
/// holds it on purpose, so every other receipt in it is text a grep can read.
fn backdated() -> PathBuf {
    let hex = std::fs::read_to_string(
        repository().join("crates/verify/tests/data/a-backdated-receipt/receipt.hex"),
    )
    .expect("the backdated receipt's hex");
    let digits: Vec<u8> = hex
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    let bytes: Vec<u8> = digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect();
    let path = std::env::temp_dir().join(format!(
        "timewitness-backdated-{}-{}.cbor",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("main")
            .replace("::", "-")
    ));
    std::fs::write(&path, bytes).expect("the backdated receipt is written out");
    path
}

#[test]
fn the_committed_receipt_says_its_outside_evidence_brackets_the_moment_to_two_seconds() {
    let (code, first, second) = first_two(&real(), &[]);
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert_eq!(
        second,
        "The checked outside signatures bracket the moment to 2 s. The 153.875 ms width is the \
         signer's own claim."
    );
}

#[test]
fn a_receipt_backdated_on_genuine_evidence_says_the_bracket_is_years_and_that_it_has_no_corridor() {
    let (code, first, second) = first_two(&backdated(), &[]);
    // Accepted, because nothing in it is false about the evidence. The point is what it says.
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert!(second.contains("93175916 s, about 2.95 years"), "{second}");
    assert!(second.contains("is the signer's own claim."), "{second}");
    assert!(
        second.ends_with("It carries no Roughtime corridor."),
        "{second}"
    );
}

#[test]
fn a_reader_holding_nothing_is_told_nothing_outside_brackets_the_moment() {
    let (code, first, second) = first_two(&real(), &["--no-anchors"]);
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("none of its 3 attestations was checked"),
        "{first}"
    );
    assert!(
        second.starts_with("No outside signature that bounds the moment was checked"),
        "{second}"
    );
    assert!(
        second.contains("The 153.875 ms width is the signer's own claim."),
        "{second}"
    );
    assert!(
        second.ends_with("Its Roughtime corridor was not checked."),
        "{second}"
    );
}

/// The committed receipt with its basis rewritten to a sandwich and re-signed under a key of this
/// test's own, which is what a stranger with no key log takes as the agent.
///
/// With `widen` false it is the deep-test case `s0` of 2026-09-15: 153.875 ms claimed as resting
/// on outside signatures that enclose 2 s. With it true the claim is widened to the bracket, edge
/// to edge, and the parts of the width moved to match, which is the least a receipt resting on a
/// sandwich may claim.
fn claiming_a_sandwich(widen: bool) -> PathBuf {
    use timewitness_core::EpsilonBasis;
    use timewitness_receipt::schema::{BreakdownRecord, Role};
    use timewitness_receipt::{open, AgentKey};

    let bytes = std::fs::read(real()).expect("the committed receipt");
    let mut receipt = open(&bytes).expect("the committed receipt opens");
    receipt.claim.basis = EpsilonBasis::ThirdPartySandwich;
    if widen {
        let edge = |role: Role| {
            receipt
                .evidence
                .iter()
                .find(|e| e.role == role)
                .expect("the committed receipt carries every role")
                .at
        };
        let earliest = edge(Role::NotEarlierThan);
        let latest = edge(Role::NotLaterThan);
        receipt.claim.earliest = earliest;
        receipt.claim.latest = latest;
        // The parts have to add to the width, to within the two nanoseconds the format allows.
        let half = ((latest - earliest) + 1) / 2;
        receipt.claim.breakdown = BreakdownRecord {
            intersection_half: half,
            network_half: 0,
            scheduling: 0,
            oscillator_holdover: 0,
            model_residual: 0,
            safety_margin: 0,
        };
        assert!(
            receipt.utc_estimate >= earliest && receipt.utc_estimate <= latest,
            "the reading sits inside the bracket, or the evidence would have been refused"
        );
    }
    let key = AgentKey::from_seed(&[0x42u8; 32]);
    receipt.agent_public_key = key.public_key_bytes();
    let signed = key.sign(&receipt).expect("a receipt of any shape signs");
    let path = std::env::temp_dir().join(format!(
        "timewitness-sandwich-{}-{}.cbor",
        if widen { "covering" } else { "narrow" },
        std::process::id()
    ));
    std::fs::write(&path, signed).expect("the receipt is written out");
    path
}

/// A sandwich claimed over a width narrower than its bracket is refused on the command line, and
/// one covering its bracket is granted with the width and the bracket in the same line.
///
/// Added 2026-09-15. On `2e683e6` the narrow one exited 0 and its second line read "Its
/// 153.875 ms width rests on outside signatures, and the checked ones bracket the moment to 2 s.",
/// which is our own width presented as third-party evidence by the verifier itself, on the command
/// line, the page and the Action's summary alike. The summary quotes these two lines, so holding
/// them here holds it.
#[test]
fn a_sandwich_narrower_than_its_bracket_is_refused_and_one_covering_it_is_granted() {
    let narrow = claiming_a_sandwich(false);
    let (code, first, second) = first_two(&narrow, &[]);
    assert_eq!(code, 1, "{first}\n{second}");
    assert_eq!(first, "REFUSED.");
    assert!(
        second.contains("is every claim in the right place"),
        "{second}"
    );
    assert!(!second.contains("rests on outside signatures"), "{second}");
    let _ = std::fs::remove_file(&narrow);

    let covering = claiming_a_sandwich(true);
    let (code, first, second) = first_two(&covering, &[]);
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert_eq!(
        second,
        "Its 2.000 s width rests on outside signatures, and the checked ones bracket the moment \
         to 2 s."
    );
    let _ = std::fs::remove_file(&covering);
}

#[test]
fn a_refused_receipt_has_no_bracket_line_and_keeps_its_refusal_under_the_verdict() {
    let mut bytes = std::fs::read(real()).expect("the committed receipt");
    bytes[4882] ^= 0x01;
    let path = std::env::temp_dir().join(format!(
        "timewitness-bracket-flip-{}.cbor",
        std::process::id()
    ));
    std::fs::write(&path, &bytes).expect("the altered copy is written");
    let (code, first, second) = first_two(&path, &[]);
    assert_eq!(code, 1, "{first}\n{second}");
    assert_eq!(first, "REFUSED.");
    assert!(!second.contains("bracket"), "{second}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_fields_carry_the_bracket_as_a_number_or_none() {
    for (receipt, extra, want) in [
        (real(), &[][..], "outside_bracket_ns=2000000000"),
        (backdated(), &[][..], "outside_bracket_ns=93175916000000000"),
        (real(), &["--no-anchors"][..], "outside_bracket_ns=none"),
    ] {
        let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
            .arg("verify")
            .arg(&receipt)
            .arg("--fields")
            .args(extra)
            .output()
            .expect("the binary runs");
        let text = String::from_utf8_lossy(&run.stdout);
        assert!(
            text.lines().any(|line| line == want),
            "{want} not in:\n{text}"
        );
    }
}
