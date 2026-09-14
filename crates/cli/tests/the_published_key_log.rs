//! The key log we serve, built the way it is built for serving and read the way a stranger reads
//! it.
//!
//! `crates/verify/tests/the_key_log.rs` proves the verifier's step against logs it assembles in
//! memory. This proves the other half, which is the half a published log is wrong in: that the
//! entries this repository holds, signed by the shipped binary, come back through the shipped
//! binary as a log whose head checks, and that the two edits a log exists to catch are caught on
//! the bytes a reader would actually be handed.
//!
//! **What a pass does not say.** The committed receipt was signed by an agent key and this log holds
//! the keys of two Roughtime servers of ours, so the verifier's answer for that receipt is that no
//! entry names its key. That is the right answer and every test here expects it. The point is
//! where the answer comes from: a log it read, under a head it checked, rather than a file it could
//! not make sense of.

use std::path::{Path, PathBuf};
use std::process::Command;

use timewitness_core::keylog::file::{parse, sign_head, KeyLog};
use timewitness_core::time::UnixNanos;

/// A key made up for these tests. The real one is never in this repository.
const SIGNING_KEY: [u8; 32] = [7u8; 32];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn entries() -> PathBuf {
    repository().join("deploy/key-log/entries.txt")
}

/// A folder of this test's own, so two tests running at once never share a log.
fn work(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "timewitness-published-key-log-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a folder to work in");
    dir
}

/// The committed entries, signed by the shipped binary, which is what `scripts/key-log.sh` does.
fn a_fresh_copy(dir: &Path) -> PathBuf {
    let log = dir.join("key-log.txt");
    let key = dir.join("signing-key");
    std::fs::copy(entries(), &log).expect("the committed entries");
    std::fs::write(&key, SIGNING_KEY).expect("a signing key");

    let signed = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(["key-log", "--log"])
        .arg(&log)
        .arg("--sign")
        .arg(&key)
        .output()
        .expect("the binary runs");
    assert!(
        signed.status.success(),
        "key-log refused to sign the committed entries: {}",
        String::from_utf8_lossy(&signed.stdout)
    );
    log
}

/// `timewitness verify --key-log` on the committed receipt, as a script would run it.
fn verify_against(log: &Path) -> (i32, String) {
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(fixture.join("receipt.cbor"))
        .arg("--subject")
        .arg(fixture.join("subject.bin"))
        .arg("--key-log")
        .arg(log)
        .arg("--fields")
        .output()
        .expect("the binary runs");
    let mut text = String::from_utf8_lossy(&run.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&run.stderr));
    (run.status.code().expect("an exit code"), text)
}

fn read(log: &Path) -> KeyLog {
    parse(&std::fs::read_to_string(log).expect("the log")).expect("a key log")
}

fn short_hex(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_fresh_copy_is_read_and_its_head_checks() {
    let dir = work("fresh");
    let log = a_fresh_copy(&dir);
    let signed = read(&log);
    let head = signed.head.as_ref().expect("the copy carries a head");

    let (code, text) = verify_against(&log);

    assert_eq!(code, 1, "judged, and refused on the key step: {text}");
    assert!(
        text.contains("refused_at=is that key one of ours"),
        "the one step a server log cannot answer yes to for an agent's receipt: {text}"
    );
    assert!(
        text.contains(&format!(
            "refusal=the log states {} entries under a head signed by {}",
            signed.entries.len(),
            short_hex(&head.signed_by)
        )),
        "the answer has to come from the log under a head the verifier checked: {text}"
    );
    assert!(text.contains("none of them names this key"), "{text}");
}

#[test]
fn an_entry_edited_under_the_head_refuses_the_run() {
    let dir = work("edited");
    let log = a_fresh_copy(&dir);
    let original = std::fs::read_to_string(&log).expect("the log");
    let first = read(&log).entries[0].valid_from.0;

    // The window of the first key opened a second earlier than the log says. It is the edit that
    // would let a key vouch for something signed before it was ours, and it changes nothing a person
    // skimming the file would notice.
    let edited = original.replacen(
        &format!(" {first} "),
        &format!(" {} ", first - 1_000_000_000),
        1,
    );
    assert_ne!(edited, original, "the edit has to have happened");
    std::fs::write(&log, edited).expect("written back");

    let (code, text) = verify_against(&log);
    assert_eq!(
        code, 2,
        "a log whose entries no longer hash to its head is refused before anything is judged: {text}"
    );
    assert!(text.contains("is not readable"), "{text}");
    assert!(text.contains("do not hash to the root"), "{text}");
}

#[test]
fn a_head_carrying_a_signature_over_another_head_fails_the_step() {
    let dir = work("moved");
    let log = a_fresh_copy(&dir);
    let honest = read(&log);

    // A real signature by the real key, over a log holding only the first entry. Moved onto the
    // head of the full log, the file still parses: the size and the root on the head line are the
    // right ones. Only the signature says otherwise.
    let shorter = KeyLog {
        entries: honest.entries[..1].to_vec(),
        head: None,
    };
    let elsewhere = sign_head(&shorter, &SIGNING_KEY, UnixNanos(1_800_000_000_000_000_000));
    let moved: String = elsewhere
        .signature
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let text = std::fs::read_to_string(&log).expect("the log");
    let rewritten: Vec<String> = text
        .lines()
        .map(|line| {
            if line.starts_with("head ") {
                let mut parts: Vec<&str> = line.split(' ').collect();
                parts[4] = &moved;
                parts.join(" ")
            } else {
                line.to_string()
            }
        })
        .collect();
    std::fs::write(&log, rewritten.join("\n") + "\n").expect("written back");
    assert_eq!(
        read(&log).head.expect("still a head").head,
        honest.head.expect("a head").head,
        "the head line states the same size, root and moment as before"
    );

    let (code, text) = verify_against(&log);
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("is not signed by the key the head itself names"),
        "{text}"
    );
}

/// The committed entries are the servers `deploy/roughtime/` stands up, and nothing else.
#[test]
fn every_committed_entry_names_a_server_this_repository_deploys() {
    let committed = read(&entries());
    assert!(
        committed.head.is_none(),
        "the committed file is the log with no head; a head is signed at build and served, never committed"
    );
    assert_eq!(committed.entries.len(), 2);

    for entry in &committed.entries {
        let address = entry
            .deployment
            .rsplit(' ')
            .next()
            .expect("a deployment ends in the address it answers on");
        let app = address
            .split('.')
            .next()
            .expect("an address begins with the app's own name");
        assert!(
            repository()
                .join(format!("deploy/roughtime/{app}.toml"))
                .is_file(),
            "{} names {app}, and nothing under deploy/roughtime stands it up",
            entry.deployment
        );
        assert!(address.ends_with(":2002"), "{address}");
    }
}
