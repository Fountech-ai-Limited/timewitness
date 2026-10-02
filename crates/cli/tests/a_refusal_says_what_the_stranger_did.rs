//! Refusals that name what the person at the keyboard did, rather than what the machine said.
//!
//! Level 5 of 2026-09-25 found four: a file that is not an agent endpoint answered with a token
//! length, a value too short to be a digest compared as one and called a different thing, every
//! file error ending in an operating system code, and a folder given as a receipt reading "Access
//! is denied" on Windows. Each is held here, and each was watched failing first.

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn real_receipt() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../verify/tests/data/a-real-stamp/receipt.cbor")
        .to_string_lossy()
        .into_owned()
}

fn scratch(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("tw-refusal-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

#[test]
fn a_file_that_is_not_an_endpoint_is_called_that() {
    let folder = scratch("endpoint");
    let garbage = folder.join("garbage-endpoint.txt");
    std::fs::write(&garbage, "not an endpoint file\n").unwrap();
    let garbage = garbage.to_string_lossy().into_owned();
    let subject = folder.join("subject");
    std::fs::write(&subject, b"x").unwrap();
    let key = folder.join("key.bin").to_string_lossy().into_owned();
    let out = folder.join("r.cbor").to_string_lossy().into_owned();

    for output in [
        run(&["status", "--agent", &garbage]),
        run(&[
            "stamp",
            "--subject",
            &subject.to_string_lossy(),
            "--key",
            &key,
            "--out",
            &out,
            "--agent",
            &garbage,
        ]),
    ] {
        let words = said(&output);
        assert_ne!(output.status.code(), Some(0), "{words}");
        assert!(
            words.contains("not one `timewitness agent` wrote"),
            "{words}"
        );
        assert!(!words.contains("characters and a token is"), "{words}");
    }
}

#[test]
fn a_digest_of_the_wrong_length_is_refused_as_that() {
    let output = run(&["verify", &real_receipt(), "--digest", "abcd"]);
    let words = said(&output);
    assert_eq!(output.status.code(), Some(2), "{words}");
    assert!(words.contains("--digest is 2 bytes"), "{words}");
    assert!(!words.contains("a different thing"), "{words}");
}

#[test]
fn a_missing_file_and_a_folder_are_called_what_they_are_with_no_code() {
    let folder = scratch("files");
    let missing = folder
        .join("no-such-file.cbor")
        .to_string_lossy()
        .into_owned();

    let output = run(&["verify", &missing]);
    let words = said(&output);
    assert!(words.contains("there is no file at"), "{words}");
    assert!(!words.contains("os error"), "{words}");

    let output = run(&["verify", &folder.to_string_lossy()]);
    let words = said(&output);
    assert!(
        words.contains("is a folder, and a file is needed there"),
        "{words}"
    );
    assert!(!words.contains("os error"), "{words}");
    assert!(!words.contains("denied"), "{words}");

    let output = run(&["order", &missing, &real_receipt()]);
    let words = said(&output);
    assert!(words.contains("there is no file at"), "{words}");
    assert!(!words.contains("os error"), "{words}");
}
