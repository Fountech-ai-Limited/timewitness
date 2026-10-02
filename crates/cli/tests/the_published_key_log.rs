//! The key log we serve, built the way it is built for serving and read the way a stranger reads
//! it.
//!
//! `crates/verify/tests/the_key_log.rs` proves the verifier's step against logs it assembles in
//! memory. This proves the other half, which is the half a published log is wrong in: that the
//! entries this repository holds, signed by the shipped binary, come back through the shipped
//! binary as a log whose head checks, and that the two edits a log exists to catch are caught on
//! the bytes a reader would actually be handed.
//!
//! **What a pass says.** The committed receipt was signed by an agent key and this log holds the
//! keys of two Roughtime servers of ours, so the verifier's answer for that receipt is that the log
//! has nothing to say about an agent key: not checked, and not a refusal. Until 2026-09-15 it was
//! a refusal, and every test here expected it. The point is where the answer comes from: a log it
//! read, under a head it checked against a key it holds, rather than a file it could not make
//! sense of.

use std::path::{Path, PathBuf};
use std::process::Command;

use timewitness_core::keylog::file::{parse, sign_head, KeyLog};
use timewitness_core::keylog::Role;
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
/// A folder of this test's own, named so that no other run can ever name the same one.
///
/// **It was keyed on the process id until 2026-09-19, and a process id is reused.** The folder was
/// not deleted at the end of a run, so a later run of the same test binary that happened to be
/// given the same process id found the old folder there, deleted it and created it again under the
/// name. On Windows a directory with any handle still open on it is deleted lazily rather than at
/// once, and an indexer or a scanner holding one is the ordinary case, so the new folder could go
/// away underneath the test that had just made it. That is what
/// `a_kept_copy_holds_the_served_log_to_it_through_the_command_line` did on 2026-09-19 at 17:35:
/// it read `timewitness-published-key-log-kept-62016/key-log.txt` back as "the system cannot find
/// the path specified", exit 2 where 1 was expected, with the whole suite green minutes before and
/// green again on the next run.
///
/// So the name carries the clock and a counter as well, no run may name a folder another run could
/// own, and nothing here deletes a folder it did not make. A name already taken is a fault worth
/// failing on rather than something to tidy away, because the only way it happens now is that two
/// runs really have collided and a test that tidies that away is a test that will lie later.
///
/// The folder is removed at the end of the test that made it, through [`Work`], so the next run
/// does not meet it at all.
fn work(name: &str) -> Work {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock that is past 1970")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "timewitness-published-key-log-{name}-{}-{since}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("a folder of this run's own, under a name nobody else has");
    Work(dir)
}

/// A folder a test owns, removed when the test is done with it.
///
/// Held as a value rather than cleaned up by hand, because a test that fails part way through
/// would otherwise leave its folder behind and the next run would meet it. A panicking test drops
/// this the same as a passing one.
struct Work(PathBuf);

/// So a test writes `dir.join("key-log.txt")` and `&dir` where it wants a path, and nothing about
/// the folder having an owner reaches the test itself.
impl std::ops::Deref for Work {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

/// The public half of the test signing key, which the reader passes as the key it holds for us.
fn signer() -> String {
    hex(&sign_head(&KeyLog::default(), &SIGNING_KEY, UnixNanos(0)).signed_by)
}

/// `timewitness verify --key-log`, as a script would run it, holding the test key for our head.
fn verify_against(log: &Path) -> (i32, String) {
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(fixture.join("receipt.cbor"))
        .arg("--subject")
        .arg(fixture.join("subject.bin"))
        .arg("--key-log")
        .arg(log)
        .arg("--key-log-signer")
        .arg(signer())
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_fresh_copy_is_read_and_its_head_checks() {
    let dir = work("fresh");
    let log = a_fresh_copy(&dir);
    let signed = read(&log);

    let (code, text) = verify_against(&log);

    assert_eq!(code, 0, "a log of server keys has nothing to say about an agent's receipt and does not refuse it: {text}");
    assert!(text.contains("accepted=true"), "{text}");
    assert!(
        text.contains(&format!("key_log_entries={}", signed.entries.len())),
        "{text}"
    );
    assert!(text.contains("key_log_agent_entries=0"), "{text}");
    assert!(
        text.contains("key_log_head=checked"),
        "the head has to be checked under the key this reader holds for us: {text}"
    );
    assert!(
        text.contains(&format!("key_log_head_signed_by={}", signer())),
        "{text}"
    );
    assert!(text.contains("key_log_step=not-checked"), "{text}");
}

#[test]
fn a_fresh_copy_read_by_a_reader_holding_the_published_key_is_not_ours() {
    // The published default holds the real head key, and this copy is signed by a test key. That
    // reader is told the head is somebody's, and the step answers nothing.
    let dir = work("published-reader");
    let log = a_fresh_copy(&dir);
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(fixture.join("receipt.cbor"))
        .arg("--key-log")
        .arg(&log)
        .arg("--fields")
        .output()
        .expect("the binary runs");
    let text = String::from_utf8_lossy(&run.stdout).into_owned();
    assert_eq!(run.status.code(), Some(0), "{text}");
    assert!(text.contains("key_log_head=signer-not-held"), "{text}");
    assert!(text.contains("key_log_step=not-checked"), "{text}");
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
    let moved = hex(&elsewhere.signature);

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
    assert!(text.contains("key_log_head=bad-signature"), "{text}");
    assert!(
        text.contains("is not signed by the key the head itself names"),
        "{text}"
    );
}

#[test]
fn a_kept_copy_holds_the_served_log_to_it_through_the_command_line() {
    // The check docs/verifier.md promises: a reader who kept the log we served last time passes it
    // beside the new one, and a rewrite is a refusal.
    let dir = work("kept");
    let kept = a_fresh_copy(&dir);
    let grown = dir.join("grown.txt");
    let key = dir.join("signing-key");
    std::fs::copy(&kept, &grown).expect("a copy to grow");
    let added = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(["key-log", "--log"])
        .arg(&grown)
        // A third server key rather than an agent key, so the key step's answer for the committed
        // receipt stays what it is and this test reads only the kept-log step.
        .args([
            "--add",
            &hex(&[9u8; 32]),
            "--role",
            "server",
            "--label",
            "a third server",
            "--sign",
        ])
        .arg(&key)
        .output()
        .expect("the binary runs");
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stdout)
    );

    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let run = |log: &Path, kept: &Path| {
        // Both files are read back before the binary is asked to read them, because this test lost
        // its own folder between two runs of that binary on 2026-09-19 and what it reported was
        // exit 2 where 1 was expected. That is the verifier saying it could not open a file, and it
        // reads as the check under test having gone wrong. A missing file is named here instead, so
        // the next occurrence is a diagnosis rather than a report of the same thing again.
        for (what, path) in [("the served log", log), ("the kept copy", kept)] {
            assert!(
                path.is_file(),
                "{what} at {} is gone before the binary was asked to read it, and nothing in                  this test removes it",
                path.display()
            );
        }
        let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
            .arg("verify")
            .arg(fixture.join("receipt.cbor"))
            .arg("--key-log")
            .arg(log)
            .arg("--kept-log")
            .arg(kept)
            .arg("--key-log-signer")
            .arg(signer())
            .arg("--fields")
            .output()
            .expect("the binary runs");
        let mut text = String::from_utf8_lossy(&run.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&run.stderr));
        (run.status.code().expect("an exit code"), text)
    };

    let (code, text) = run(&grown, &kept);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("kept_log=held"), "{text}");

    // The served log shrank back to what was kept minus its last entry: a removal.
    let (code, text) = run(&kept, &grown);
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("kept_log=failed"), "{text}");
    assert!(
        text.contains("refused_at=is this log an extension of the one you kept"),
        "{text}"
    );

    // Without --key-log, --kept-log has nothing to hold.
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("verify")
        .arg(fixture.join("receipt.cbor"))
        .arg("--kept-log")
        .arg(&kept)
        .output()
        .expect("the binary runs");
    assert_eq!(run.status.code(), Some(2));
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
    assert_eq!(committed.agent_entries(), 0);

    for entry in &committed.entries {
        assert_eq!(entry.role, Role::Server, "{}", entry.deployment);
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
