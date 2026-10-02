//! Three faults the key log had before its first head was served, each driven through the shipped
//! command line the way a reader would hit it.
//!
//! All three were reproduced on 2026-09-15 against the `v0` verify path: a head signed by any key
//! read as a list we signed, a key retired by an appended entry stayed current, and the log of our
//! two server keys refused the receipt this repository commits. A served head freezes the leaf
//! under it, so these had to be settled before anything was served, and each test here was watched
//! failing on the tree as it stood before the fix went in.

use std::path::{Path, PathBuf};
use std::process::Command;

use timewitness_core::keylog::file::sign_head;
use timewitness_core::keylog::file::KeyLog;
use timewitness_core::time::UnixNanos;

/// The key that signed the committed receipt, and the reading it carries.
const AGENT_KEY: &str = "07de4306352562a212928f5f8228b4f027af4856ae0b17ea25c7de14a61639ec";
const READING: i128 = 1_788_979_278_918_450_302;

/// A signing key that is not the one our published default holds.
const SOMEBODY_ELSES: [u8; 32] = [42u8; 32];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A folder of this test's own, named so that no other run can ever name the same one.
///
/// **It was keyed on the process id until 2026-09-19, and a process id is reused.** The folder was
/// not deleted at the end of a run, so a later run of the same test binary that happened to be
/// given the same process id found the old folder there, deleted it and created it again under the
/// name. On Windows a directory with any handle still open on it is deleted lazily rather than at
/// once, and an indexer or a scanner holding one is the ordinary case, so the new folder could go
/// away underneath the test that had just made it. That is what
/// `a_kept_copy_holds_the_served_log_to_it_through_the_command_line` did on 2026-09-19 at 17:35:
/// it read `timewitness-published-key-log-kept-62016\key-log.txt` back as "the system cannot find
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
        "timewitness-key-log-faults-{name}-{}-{since}-{}",
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

fn key_log(args: &[&str]) -> (bool, String) {
    let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .arg("key-log")
        .args(args)
        .output()
        .expect("the binary runs");
    let mut text = String::from_utf8_lossy(&run.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&run.stderr));
    (run.status.success(), text)
}

/// `timewitness verify --key-log`, with the field output and the human one together.
fn verify(log: &Path, extra: &[&str]) -> (i32, String) {
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let mut text = String::new();
    let mut code = 0;
    for mode in [&["--fields"][..], &[][..]] {
        let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
            .arg("verify")
            .arg(fixture.join("receipt.cbor"))
            .arg("--subject")
            .arg(fixture.join("subject.bin"))
            .arg("--key-log")
            .arg(log)
            .args(extra)
            .args(mode)
            .output()
            .expect("the binary runs");
        text.push_str(&String::from_utf8_lossy(&run.stdout));
        text.push_str(&String::from_utf8_lossy(&run.stderr));
        code = run.status.code().expect("an exit code");
    }
    (code, text)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The public half of a signing key, read off a head it signed.
fn public_half(secret: &[u8; 32]) -> String {
    hex(&sign_head(&KeyLog::default(), secret, UnixNanos(0)).signed_by)
}

#[test]
fn a_head_signed_by_somebody_else_does_not_read_as_a_list_we_signed() {
    let dir = work("any-signer");
    let log = dir.join("log.txt");
    let key = dir.join("signing-key");
    std::fs::write(&key, SOMEBODY_ELSES).expect("a key");
    let log_s = log.to_string_lossy().into_owned();
    let key_s = key.to_string_lossy().into_owned();
    let from = (READING - 1_000_000_000).to_string();

    let (ok, text) = key_log(&[
        "--log", &log_s, "--add", AGENT_KEY, "--label", "a runner", "--from", &from,
    ]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&["--log", &log_s, "--sign", &key_s]);
    assert!(ok, "{text}");

    let (code, text) = verify(&log, &[]);
    // The fault: this read `[held] ... This is a list we signed`, exit 0, on a log signed a moment
    // ago by a key nobody holds for us.
    assert!(
        !text.contains("a list we signed"),
        "a head signed by a key the reader does not hold for us is not our word: {text}"
    );
    assert_eq!(
        code, 0,
        "the receipt itself is not refused by a log that is not ours: {text}"
    );
    assert!(text.contains("[----] is that key one of ours"), "{text}");
    assert!(
        text.contains("key_log_head=signer-not-held"),
        "the field output has to say whose head it was not: {text}"
    );
    assert!(
        text.contains(&format!(
            "key_log_head_signed_by={}",
            public_half(&SOMEBODY_ELSES)
        )),
        "{text}"
    );
}

#[test]
fn the_same_key_appended_with_an_end_is_refused_by_the_writer_rather_than_read_as_retired() {
    // The procedure `key-log --help` and `deploy/key-log/entries.txt` prescribed until 2026-09-15,
    // which left the open entry above covering every later moment. The writer now refuses it and
    // names the edit that does retire a key.
    let dir = work("old-procedure");
    let log = dir.join("log.txt");
    let log_s = log.to_string_lossy().into_owned();
    let from = (READING - 1_000_000_000).to_string();
    let until = (READING - 1).to_string();

    let (ok, text) = key_log(&[
        "--log", &log_s, "--add", AGENT_KEY, "--label", "a runner", "--from", &from,
    ]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&[
        "--log", &log_s, "--add", AGENT_KEY, "--label", "a runner", "--from", &from, "--until",
        &until,
    ]);
    assert!(
        !ok,
        "the fault: a second entry with an end was written and retired nothing: {text}"
    );
    assert!(text.contains("--retire"), "{text}");
}

#[test]
fn a_key_retired_by_an_appended_entry_refuses_every_later_reading() {
    let dir = work("retired");
    let log = dir.join("log.txt");
    let key = dir.join("signing-key");
    std::fs::write(&key, SOMEBODY_ELSES).expect("a key");
    let log_s = log.to_string_lossy().into_owned();
    let key_s = key.to_string_lossy().into_owned();
    let from = (READING - 1_000_000_000).to_string();
    let at = (READING - 1).to_string();
    let signer = public_half(&SOMEBODY_ELSES);

    let (ok, text) = key_log(&[
        "--log", &log_s, "--add", AGENT_KEY, "--label", "a runner", "--from", &from,
    ]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&["--log", &log_s, "--retire", AGENT_KEY, "--at", &at]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&["--log", &log_s, "--sign", &key_s]);
    assert!(ok, "{text}");

    // Held for us by this reader, so the answer comes from the log rather than stopping at the head.
    let (code, text) = verify(&log, &["--key-log-signer", &signer]);
    assert_eq!(
        code, 1,
        "the fault: a retired key stayed current, exit 0: {text}"
    );
    assert!(
        text.contains("refused_at=is that key one of ours"),
        "{text}"
    );
    assert!(text.contains("retired"), "{text}");

    // And a moment before the retirement, the same log holds.
    let (ok, text) = key_log(&["--log", &log_s]);
    assert!(ok, "{text}");
    let (_holds_the_folder, before) = read_and_retire_later(&log_s, &key_s, READING + 1);
    let (code, text) = verify(&before, &["--key-log-signer", &signer]);
    assert_eq!(
        code, 0,
        "a retirement after the reading changes nothing about it: {text}"
    );
    assert!(text.contains("key_log_step=held"), "{text}");
}

/// A second log for the same key, retired at a later moment, so the reading falls before it.
/// The folder comes back with the path, because the folder is removed when it is dropped and a
/// path handed out of a function whose folder has gone is a path to nothing. That is not
/// hypothetical: written to return the path alone on 2026-09-19, this deleted its own folder on
/// the way out and the caller read "the system cannot find the path specified" every run.
fn read_and_retire_later(_log: &str, key: &str, at: i128) -> (Work, PathBuf) {
    let dir = work("retired-later");
    let log = dir.join("log.txt");
    let log_s = log.to_string_lossy().into_owned();
    let from = (READING - 1_000_000_000).to_string();
    let at = at.to_string();
    let (ok, text) = key_log(&[
        "--log", &log_s, "--add", AGENT_KEY, "--label", "a runner", "--from", &from,
    ]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&["--log", &log_s, "--retire", AGENT_KEY, "--at", &at]);
    assert!(ok, "{text}");
    let (ok, text) = key_log(&["--log", &log_s, "--sign", key]);
    assert!(ok, "{text}");
    (dir, log)
}

#[test]
fn the_log_of_our_own_server_keys_does_not_refuse_our_own_receipt() {
    // The log we serve first holds two server keys and no agent key. Until 2026-09-15 that log
    // refused the committed receipt, "none of them names this key", exit 1, while the verifier's
    // documentation told a reader to pass it.
    let dir = work("server-only");
    let log = dir.join("log.txt");
    let key = dir.join("signing-key");
    std::fs::copy(repository().join("deploy/key-log/entries.txt"), &log).expect("the entries");
    std::fs::write(&key, SOMEBODY_ELSES).expect("a key");
    let log_s = log.to_string_lossy().into_owned();
    let key_s = key.to_string_lossy().into_owned();
    let signer = public_half(&SOMEBODY_ELSES);

    let (ok, text) = key_log(&["--log", &log_s, "--sign", &key_s]);
    assert!(ok, "{text}");

    // With nothing said about the signer, the head is somebody's and the step is not checked.
    let (code, text) = verify(&log, &[]);
    assert_eq!(
        code, 0,
        "the fault: our own log refused our own receipt: {text}"
    );

    // With the signer held, the head is checked and the log still has nothing to say about an
    // agent key, which is the honest answer and not a refusal.
    let (code, text) = verify(&log, &["--key-log-signer", &signer]);
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("key_log_head=checked"), "{text}");
    assert!(text.contains("key_log_step=not-checked"), "{text}");
    assert!(
        text.contains("no agent entry"),
        "the step says why it could not answer: {text}"
    );
}
