//! What the evidence list says of a receipt refused before its evidence is listed, through the
//! shipped command line.
//!
//! An empty list and no list are two different facts. A receipt read to the end that carries no
//! evidence entry is told so in one sentence. A receipt refused before its evidence is listed has
//! no list to report, and telling it that it carries no third-party evidence would be a claim the
//! verifier never made. Until 2026-10-01 the verifier page said exactly that of both receipts kept
//! under `refused-before-its-evidence-is-listed`, each of which carries three real attestations.
//! These hold the command line to the same rule, and the page is held to it by
//! `scripts/the-served-verifier-page.mjs` on the same three receipts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{EpsilonBasis, UnixNanos};
use timewitness_receipt::schema::{
    AgentClaim, BreakdownRecord, Payload, PolicyRecord, Receipt, SourceRecord, TakenBy,
};
use timewitness_receipt::{AgentKey, CARRIES_NO_EVIDENCE};

const NOON: Nanos = 1_788_800_000 * NANOS_PER_SEC;
const HALF: Nanos = 60 * NANOS_PER_MILLI;

/// The SHA-256 of `a-receipt-with-no-evidence/subject.txt`, which is what that receipt stamps.
const SUBJECT_SHA256: &str = "aa72e4487f3f22ae43cec20b5f0d9096290f85413de88358e5a4ea4538a314c5";

fn data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../verify/tests/data")
}

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

fn to_hex(bytes: &[u8]) -> String {
    let flat: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut out = String::new();
    for line in flat.as_bytes().chunks(100) {
        out.push_str(std::str::from_utf8(line).expect("hex is ascii"));
        out.push('\n');
    }
    out
}

/// A receipt read to the end that carries no evidence entry, signed by a key of its own.
///
/// It is built here and also kept in the tree as hex, so the page check can read the same bytes,
/// and the test below holds the two to each other. The key is from a fixed seed, so the bytes come
/// out the same every time.
fn with_no_evidence() -> Vec<u8> {
    let key = AgentKey::from_seed(&[0x46; 32]);
    let hash = from_hex(SUBJECT_SHA256);
    let receipt = Receipt {
        version: 1,
        sequence: 1,
        chain_previous: None,
        payload: Payload {
            algorithm: "sha-256".to_string(),
            hash,
        },
        monotonic: 1_000_000_000,
        utc_estimate: UnixNanos(NOON),
        claim: AgentClaim {
            earliest: UnixNanos(NOON - HALF),
            latest: UnixNanos(NOON + HALF),
            basis: EpsilonBasis::LocalModelOnly,
            fusion: "marzullo-then-inverse-square".to_string(),
            sources_offered: 3,
            sources_kept: 3,
            breakdown: BreakdownRecord {
                intersection_half: 30 * NANOS_PER_MILLI,
                network_half: 0,
                scheduling: 0,
                oscillator_holdover: 30 * NANOS_PER_MILLI,
                model_residual: 0,
                safety_margin: 0,
                unclaimed_rate: Some(12 * NANOS_PER_MILLI),
            },
            since_last_sync: 30 * NANOS_PER_SEC,
            frequency_ppb: 0,
            boot_generation: 1,
            resume_generation: 0,
            sources: (0..3)
                .map(|i| SourceRecord {
                    id: format!("source-{i}"),
                    operator: Some(format!("operator-{i}.example")),
                    kind: "ntp".to_string(),
                    timescale: "utc".to_string(),
                    smear: "none".to_string(),
                    leap: "none".to_string(),
                    kept: true,
                    first_party: false,
                })
                .collect(),
            policy: PolicyRecord {
                max_bound_width: 5 * NANOS_PER_SEC,
                min_sources: 3,
                min_operators: Some(3),
                max_holdover: Some(3_600 * NANOS_PER_SEC),
                source_interval_floor: Some(100_000),
                frequency_slew_ppb_per_s: Some(1_000),
                frequency_span_ppb: Some(100_000),
            },
            taken_by: Some(TakenBy::OneShot),
        },
        evidence: Vec::new(),
        agent_public_key: key.public_key_bytes(),
    };
    key.sign(&receipt)
        .expect("a receipt with no evidence entry signs")
}

/// The receipt kept as hex at `name` under the test data, written out where the binary can read it.
fn written_out(name: &str) -> PathBuf {
    let hex = fs::read_to_string(data().join(name)).expect("the receipt's hex");
    let dir = std::env::temp_dir().join(format!("tw-evidence-list-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a directory to write into");
    let path = dir
        .join(name.replace(['/', '\\'], "-"))
        .with_extension("cbor");
    fs::write(&path, from_hex(&hex)).expect("the receipt is written out");
    path
}

/// Everything `timewitness verify` prints, and its exit code.
fn verify(receipt: &Path, extra: &[&str]) -> (i32, String) {
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(receipt)
        .args(extra)
        .output()
        .expect("the binary this test was built alongside runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    (run.status.code().expect("an exit code"), text)
}

/// The two receipts, and the SHA-256 of each as the binary reports it, so a file cut short or
/// changed in the tree is not taken for the receipt its README describes.
const REFUSED_BEFORE_THE_LIST: [(&str, &str); 2] = [
    (
        "refused-before-its-evidence-is-listed/a-field-carrying-a-newline.hex",
        "8e8b238919e4934ecbdea09939e4a878eac734e9a3dfa0f2bf2416111066c44f",
    ),
    (
        "refused-before-its-evidence-is-listed/a-sandwich-on-one-edge.hex",
        "9d3fd37245eb9f2aa547f12812ce35d79aaa867dc87b544c7bba63793193eeaa",
    ),
];

#[test]
fn a_receipt_refused_before_its_evidence_is_listed_is_not_told_it_carries_none() {
    for (name, sha256) in REFUSED_BEFORE_THE_LIST {
        let receipt = written_out(name);
        let (code, said) = verify(&receipt, &[]);
        assert_eq!(code, 1, "{name} is refused: {said}");
        assert!(said.starts_with("REFUSED."), "{name}: {said}");
        assert!(
            !said.contains(CARRIES_NO_EVIDENCE),
            "{name} was refused before its evidence was listed and is told it carries none: {said}"
        );
        // Nothing at all is said about evidence that was not listed, so the section is not there.
        assert!(
            !said.contains("The evidence, one role at a time"),
            "{name}: {said}"
        );

        // And the fields a script reads say the same: no list, rather than an empty one.
        let (_, json) = verify(&receipt, &["--json"]);
        assert!(json.contains("\"accepted\": false"), "{name}: {json}");
        assert!(!json.contains("\"evidence\""), "{name}: {json}");
        assert!(
            json.contains(&format!("\"receipt_sha256\": \"{sha256}\"")),
            "{name} is not the receipt its README describes: {json}"
        );
    }
}

#[test]
fn a_receipt_read_to_the_end_with_no_evidence_is_told_it_carries_none() {
    let kept = fs::read_to_string(data().join("a-receipt-with-no-evidence/receipt.hex"))
        .expect("the receipt's hex");
    let built = with_no_evidence();
    assert!(
        from_hex(&kept) == built,
        "the receipt kept in the tree is not the one this test builds, which is:\n{}",
        to_hex(&built)
    );

    let receipt = written_out("a-receipt-with-no-evidence/receipt.hex");
    let subject = data().join("a-receipt-with-no-evidence/subject.txt");
    let (code, said) = verify(&receipt, &["--subject", &subject.to_string_lossy()]);
    assert_eq!(code, 0, "{said}");
    assert!(said.contains(CARRIES_NO_EVIDENCE), "{said}");
    assert!(
        said.starts_with(
            "This receipt holds up as far as it was checked, and it carries no third-party \
             attestation."
        ),
        "{said}"
    );

    let (_, json) = verify(
        &receipt,
        &["--json", "--subject", &subject.to_string_lossy()],
    );
    assert!(json.contains("\"evidence\": []"), "{json}");
}

#[test]
fn a_receipt_refused_after_its_evidence_was_read_still_lists_it() {
    // The committed receipt against a file it does not stamp: refused, and refused after its three
    // attestations were read, so they are listed and nothing says there are none.
    let receipt = data().join("a-real-stamp/receipt.cbor");
    let subject = data().join("a-receipt-with-no-evidence/subject.txt");
    let (code, said) = verify(&receipt, &["--subject", &subject.to_string_lossy()]);
    assert_eq!(code, 1, "{said}");
    assert!(said.starts_with("REFUSED."), "{said}");
    assert!(!said.contains(CARRIES_NO_EVIDENCE), "{said}");
    for role in [
        "authenticated-utc-corridor by roughtime",
        "not-earlier-than by drand",
        "not-later-than by rfc3161",
    ] {
        assert!(said.contains(role), "no {role} in: {said}");
    }
}
