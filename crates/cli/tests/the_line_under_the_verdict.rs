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

/// The anchors that ship, written out as a file, with a figure allowed for DigiCert's own clock.
///
/// Added 2026-09-19. Both authorities that ship state no accuracy in their
/// tokens, so on the material that ships nothing bounds a receipt from above. RFC 3161 section
/// 2.4.2 says an absent accuracy "may be available through other means, e.g., the TSAPolicyId",
/// meaning the authority's published practice, and a reader who has read that practice says what
/// they allow. The figure here is this test's and stands for nobody's practice statement: what it
/// proves is the route, that a reader's own allowance restores the edge and that the verifier then
/// reports it.
fn anchors_allowing(nanos: i128) -> PathBuf {
    let published = timewitness_verify::anchor_file::published();
    let hex =
        |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect::<String>() };
    // The file separates fields on whitespace and some of the shipped names carry a space, so a
    // name goes in with hyphens. A name is a label for a person reading the output on all four
    // kinds of anchor; nothing is matched on it.
    let label = |name: &str| name.replace(' ', "-");
    let mut out = String::new();
    for server in &published.roughtime_servers {
        out.push_str(&format!(
            "roughtime {} {}\n",
            label(&server.name),
            hex(&server.long_term_public_key)
        ));
    }
    for chain in &published.drand_chains {
        out.push_str(&format!(
            "drand {} {} {} {} {}\n",
            label(chain.name),
            hex(&chain.hash),
            hex(&chain.public_key),
            chain.period_seconds,
            chain.genesis_time
        ));
    }
    for authority in &published.timestamp_authorities {
        out.push_str(&format!("rfc3161 {}", label(&authority.name)));
        for pin in &authority.accepted_certificates {
            out.push(' ');
            out.push_str(&hex(pin));
        }
        out.push_str(&format!(" allow={nanos}\n"));
    }
    for signer in &published.key_log_signers {
        out.push_str(&format!(
            "keylog {} {}\n",
            label(&signer.name),
            hex(&signer.public_key)
        ));
    }
    let path = std::env::temp_dir().join(format!(
        "timewitness-anchors-allowing-{nanos}-{}.txt",
        std::process::id()
    ));
    std::fs::write(&path, out).expect("the anchors file is written out");
    path
}

/// The committed receipt's witness states no accuracy, so nothing outside bounds it from above.
///
/// This read "The checked outside signatures bracket the moment to 2 s" until 2026-09-19, and the
/// 2 s was arithmetic that took DigiCert's unstated accuracy for a stated nought.
/// Both authorities that ship state no accuracy, so this is the ordinary case rather than a corner,
/// and the line has to say that a witness was checked and bounded nothing rather than that no
/// witness was checked. The two are different facts and a reader shown the second reads the
/// receipt as carrying less evidence than it does.
#[test]
fn the_committed_receipt_says_its_witness_states_no_accuracy_and_bounds_nothing_above() {
    let (code, first, second) = first_two(&real(), &[]);
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert_eq!(
        second,
        "A not-later-than signature was checked and its authority states no accuracy of its own, \
         so nothing outside bounds the moment from above. The 153.875 ms width is the signer's \
         own claim."
    );
    assert!(
        !second.contains("bracket the moment to 2 s"),
        "a width computed from an accuracy nobody stated is back: {second}"
    );
}

/// The backdated receipt, and what is left of the warning once the witness bounds nothing.
///
/// It said "93175916 s, about 2.95 years" until 2026-09-19, and that width was the 2023 beacon
/// against a 2026 token whose authority states no accuracy. The token cannot bound the moment from
/// above at all, so the width is gone and what replaces it is the plainer statement: one edge was
/// checked, the other was checked and bounds nothing, and the receipt has no corridor either. A
/// reader told that nothing bounds the moment from above has been told more than a reader handed a
/// width that rested on an assumed-perfect clock.
#[test]
fn a_receipt_backdated_on_genuine_evidence_says_nothing_bounds_it_above_and_it_has_no_corridor() {
    let (code, first, second) = first_two(&backdated(), &[]);
    // Accepted, because nothing in it is false about the evidence. The point is what it says.
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert!(
        second.starts_with(
            "A not-later-than signature was checked and its authority states no accuracy of its \
             own, so nothing outside bounds the moment from above."
        ),
        "{second}"
    );
    assert!(!second.contains("2.95 years"), "{second}");
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
fn claiming_a_sandwich(widen: bool, allowance: i128) -> PathBuf {
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
        // The instant printed beside a witness is what the token states, and the edge it supports
        // is that instant widened by whatever the reader allows for the authority's own clock. The
        // two were the same number until the change of 2026-09-19, so this used to be the entry's
        // own `at` and it no longer is.
        let latest =
            timewitness_core::time::UnixNanos(edge(Role::NotLaterThan).as_nanos() + allowance);
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
            unclaimed_rate: None,
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
        "timewitness-sandwich-{}-{allowance}-{}.cbor",
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
    // The reader has to allow something for the authority's clock for a sandwich to be possible at
    // all after the change of 2026-09-19, because the token itself states no accuracy. One second, this
    // reader's own figure, puts the not-later edge at 1788979281 and the beacon puts the
    // not-earlier edge at 1788979278, so the bracket is three seconds.
    let anchors = anchors_allowing(1_000_000_000);
    let anchors = anchors.to_str().expect("a path").to_string();
    let with_allowance: Vec<&str> = vec!["--anchors", &anchors];

    let narrow = claiming_a_sandwich(false, 1_000_000_000);
    let (code, first, second) = first_two(&narrow, &with_allowance);
    assert_eq!(code, 1, "{first}\n{second}");
    assert_eq!(first, "REFUSED.");
    assert!(
        second.contains("is every claim in the right place"),
        "{second}"
    );
    assert!(!second.contains("rests on outside signatures"), "{second}");
    let _ = std::fs::remove_file(&narrow);

    let covering = claiming_a_sandwich(true, 1_000_000_000);
    let (code, first, second) = first_two(&covering, &with_allowance);
    assert_eq!(code, 0, "{first}\n{second}");
    assert!(
        first.contains("all 3 of its attestations were checked"),
        "{first}"
    );
    assert_eq!(
        second,
        "Its 3.000 s width rests on outside signatures, and the checked ones bracket the moment \
         to 3 s."
    );
    let _ = std::fs::remove_file(&covering);
}

/// The same receipt, claiming a sandwich, against the anchors that ship: refused, and it says why.
///
/// Added 2026-09-19. Before that date this exact receipt was granted a sandwich
/// on a bracket of 2 s, and the 2 s existed because an authority that had put no number on its own
/// clock was read as having put nought. That is our own narrowness presented as somebody else's
/// signature, which is the thing the evidence rules exist against. The refusal names the reason
/// rather than reporting the not-later-than role as unchecked, because it was checked.
#[test]
fn a_sandwich_on_a_token_stating_no_accuracy_is_refused_and_the_refusal_says_why() {
    let covering = claiming_a_sandwich(true, 0);
    let (code, first, second) = first_two(&covering, &[]);
    assert_eq!(code, 1, "{first}\n{second}");
    assert_eq!(first, "REFUSED.");
    assert!(
        second.contains("is every claim in the right place"),
        "{second}"
    );
    let full = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(&covering)
        .output()
        .expect("the binary runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&full.stdout),
        String::from_utf8_lossy(&full.stderr)
    );
    assert!(
        text.contains("states no accuracy of its own"),
        "the refusal does not say why: {text}"
    );
    assert!(
        text.contains("A sandwich needs two edges and this one has one"),
        "the refusal does not say why: {text}"
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
    let allowing = anchors_allowing(1_000_000_000);
    let allowing = [allowing.to_str().expect("a path")];
    for (receipt, extra, want) in [
        // No allowance held for the authority, so no edge above and no width. Both of these read a
        // number until 2026-09-19, and both numbers took an unstated accuracy
        // for a stated nought.
        (real(), &[][..], "outside_bracket_ns=none"),
        (backdated(), &[][..], "outside_bracket_ns=none"),
        (real(), &["--no-anchors"][..], "outside_bracket_ns=none"),
        // With a second allowed for DigiCert's clock, which is this reader's figure and not the
        // authority's, the edge comes back and the bracket is a number again.
        (
            real(),
            &["--anchors", allowing[0]][..],
            "outside_bracket_ns=3000000000",
        ),
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

#[test]
fn the_fields_say_what_each_source_was_speaking() {
    // The validator reads each source's timescale and smear, and a receipt is refused on them, but
    // until 2026-09-21 a script reading the fields could not see either. Counted the way the kinds
    // are, so nine sources on UTC with no smear read as one entry each.
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(real())
        .arg("--fields")
        .output()
        .expect("the binary runs");
    let fields = String::from_utf8_lossy(&run.stdout).into_owned();
    let read = |name: &str| -> String {
        fields
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} in {fields}"))
            .to_string()
    };
    assert_eq!(read("source_timescales"), "utc:9");
    let smears = read("source_smears");
    let counted: usize = smears
        .split(',')
        .map(|entry| {
            entry
                .rsplit_once(':')
                .and_then(|(_, n)| n.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("{entry} is not a spelling and a count"))
        })
        .sum();
    assert_eq!(counted, 9, "{smears}");
}
