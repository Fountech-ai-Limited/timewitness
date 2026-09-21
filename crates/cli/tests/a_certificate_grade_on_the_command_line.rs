//! The certificate grade through the shipped command line: the line printed first and the exit code.
//!
//! What ships holds no cutoff, so a reader reaches the grade only by naming one in their own trust
//! material. These runs do that against the committed receipt, which was signed in September 2026.
//! The grade itself is tested against built key logs in `crates/verify/tests/certificates.rs`; what
//! is held here is what the command prints and what it exits with.

use std::path::{Path, PathBuf};
use std::process::Command;

/// DigiCert's signing certificate, which the committed receipt's witness was signed under.
const DIGICERT: &str =
    "rfc3161 DigiCert 2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc";

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file of this run's own, named so no other run can name it.
fn anchors_file(name: &str, lines: &[&str]) -> PathBuf {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock past 1970")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "timewitness-certificate-grade-{name}-{}-{since}.anchors",
        std::process::id()
    ));
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("written");
    path
}

fn verify(anchors: &Path, extra: &[&str]) -> (i32, String) {
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(fixture.join("receipt.cbor"))
        .arg("--subject")
        .arg(fixture.join("subject.bin"))
        .arg("--anchors")
        .arg(anchors)
        .args(extra)
        .output()
        .expect("the binary runs");
    let _ = std::fs::remove_file(anchors);
    (
        run.status.code().expect("an exit code"),
        format!(
            "{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        ),
    )
}

#[test]
fn a_receipt_witnessed_before_certification_began_prints_its_version_0_verdict_first_and_exits_0() {
    let anchors = anchors_file("before", &[DIGICERT, "certification 1820000000000000000"]);
    let (code, text) = verify(&anchors, &[]);
    assert_eq!(code, 0, "{text}");
    let first = text.lines().next().expect("a first line");
    assert!(first.starts_with("This receipt holds up"), "{text}");
    assert!(text.contains("Signed before certification began"), "{text}");
    assert!(!text.contains("TimeWitness certificate"), "{text}");

    let anchors = anchors_file(
        "before-fields",
        &[DIGICERT, "certification 1820000000000000000"],
    );
    let (_, fields) = verify(&anchors, &["--fields"]);
    assert!(
        fields.contains("certificate=before-certification\n"),
        "{fields}"
    );
    assert!(fields.contains("holds=true\n"), "{fields}");
}

#[test]
fn a_receipt_witnessed_after_certification_began_with_no_key_log_prints_so_first_and_exits_1() {
    let anchors = anchors_file("after", &[DIGICERT, "certification 1000000000000000000"]);
    let (code, text) = verify(&anchors, &[]);
    assert_eq!(code, 1, "{text}");
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some(
            "Not a TimeWitness certificate: nothing outside this receipt places when it was signed"
        ),
        "{text}"
    );
    // The receipt's own verdict still follows, with the witness it carries still checked.
    assert!(
        lines
            .next()
            .is_some_and(|l| l.starts_with("This receipt holds up")),
        "{text}"
    );
    assert!(text.contains("checked against DigiCert"), "{text}");
}

#[test]
fn a_cutoff_named_twice_is_refused_as_trust_material() {
    let anchors = anchors_file(
        "twice",
        &[
            "certification 1000000000000000000",
            "certification 1000000000000000001",
        ],
    );
    let (code, _) = verify(&anchors, &[]);
    assert_eq!(code, 2);
}
