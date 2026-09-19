//! A reader who supplies their own trust material, through the shipped command line.
//!
//! `docs/verifier.md` offers `--anchors <file>` to a reader who would rather not take the shipped
//! keys. Until 2026-09-15 that reader was told the committed receipt "contradicts itself", exit 1,
//! whenever their file lacked the key of one party the receipt carries an attestation from, and the
//! only way past it was to hold every key the shipped set holds. These three files are the seeds the
//! test run of 2026-09-15 wrote, run against the committed receipt exactly as that run ran them, and
//! each was watched exiting 1 before the fix.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The three shipped Roughtime keys, of which the committed receipt's corridor names the first.
const INT08H: &str = "roughtime roughtime.int08h.com 016e6e0284d24c37c6e4d7d8d5b4e1d3c1949ceaa545bf875616c9dce0c9bec1";
const ROUGHTIME_SE: &str =
    "roughtime roughtime.se 4b70337d92790a349d909db564919bc6a7583ff4a813c7d7298d3e6a272c7a12";
const TXRYAN: &str =
    "roughtime time.txryan.com 881563c60ff58fbcb5fa44144c161d4da6f10a9a5eb14ff4ec3e0f303264d960";
/// A pin for an authority the receipt's token was not signed by.
const SOMEBODY_ELSE: &str =
    "rfc3161 somebody-else 1111111111111111111111111111111111111111111111111111111111111111";
/// A chain the receipt's round is not from, with quicknet's own group key and schedule behind it.
const ANOTHER_CHAIN: &str = "drand another-chain 8cca2414419d094f993c14bad1c53bf61ce9848b09d7d9d3599bbd2beb75bc03 9daf3cc5be607dbf47b21d218f6e7648b0700ebc2055d6bb0d4052bea89a6a479f555e603db6318aefcb01ef8c9c3e42e3eaf4fb38b4e25c63a4e44a7aebfe3b28537eceb59f16713fd3bfe18ce227995733f31bd34461acef0dcc10eba210e9 3 1692803367";

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
        "timewitness-own-anchors-{name}-{}-{since}-{}",
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

/// `timewitness verify --anchors <file>` on the committed receipt, with the JSON and the human
/// output together, because the JSON says what was checked and the words say why.
fn verify(anchors: &Path) -> (i32, String) {
    let fixture = repository().join("crates/verify/tests/data/a-real-stamp");
    let mut text = String::new();
    let mut code = 0;
    for mode in [&["--json"][..], &[][..]] {
        let run = Command::new(env!("CARGO_BIN_EXE_timewitness"))
            .arg("verify")
            .arg(fixture.join("receipt.cbor"))
            .arg("--subject")
            .arg(fixture.join("subject.bin"))
            .arg("--anchors")
            .arg(anchors)
            .args(mode)
            .output()
            .expect("the binary runs");
        text.push_str(&String::from_utf8_lossy(&run.stdout));
        text.push_str(&String::from_utf8_lossy(&run.stderr));
        code = run.status.code().expect("an exit code");
    }
    (code, text)
}

/// Whether the JSON says the entry of this scheme was checked, read off the printed entry.
fn checked(text: &str, scheme: &str) -> bool {
    let entry = text
        .find(&format!("\"scheme\": \"{scheme}\""))
        .unwrap_or_else(|| panic!("no {scheme} entry in the JSON: {text}"));
    let rest = &text[entry..];
    let at = rest
        .find("\"checked\": ")
        .unwrap_or_else(|| panic!("the {scheme} entry says nothing about checked: {rest}"));
    rest[at + "\"checked\": ".len()..].starts_with("true")
}

fn anchors_file(dir: &Path, name: &str, lines: &[&str]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("the anchors file is written");
    path
}

#[test]
fn holding_two_of_the_three_shipped_roughtime_keys_is_not_a_contradiction() {
    let dir = work("rt2b");
    let anchors = anchors_file(&dir, "rt2b.anchors", &[ROUGHTIME_SE, TXRYAN]);
    let (code, text) = verify(&anchors);
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("contradicts itself"), "{text}");
    assert!(!checked(&text, "roughtime"), "{text}");
    assert!(text.contains("holds no"), "{text}");
    assert!(text.contains("holds up as far as it was checked"), "{text}");
}

#[test]
fn a_pin_for_another_authority_beside_every_shipped_roughtime_key_is_not_a_contradiction() {
    let dir = work("fakepin");
    let anchors = anchors_file(
        &dir,
        "rt3-fakepin.anchors",
        &[INT08H, ROUGHTIME_SE, TXRYAN, SOMEBODY_ELSE],
    );
    let (code, text) = verify(&anchors);
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("contradicts itself"), "{text}");
    assert!(checked(&text, "roughtime"), "{text}");
    assert!(!checked(&text, "rfc3161"), "{text}");
    assert!(text.contains("holds no"), "{text}");
}

#[test]
fn a_drand_chain_the_round_is_not_from_is_not_a_contradiction() {
    let dir = work("fakedrand");
    let anchors = anchors_file(
        &dir,
        "rt3-fakedrand.anchors",
        &[INT08H, ROUGHTIME_SE, TXRYAN, ANOTHER_CHAIN],
    );
    let (code, text) = verify(&anchors);
    assert_eq!(code, 0, "{text}");
    assert!(!text.contains("contradicts itself"), "{text}");
    assert!(!checked(&text, "drand"), "{text}");
    assert!(text.contains("holds no"), "{text}");
}

#[test]
fn the_three_shipped_roughtime_keys_alone_still_check_the_corridor() {
    let dir = work("rt3");
    let anchors = anchors_file(&dir, "rt3.anchors", &[INT08H, ROUGHTIME_SE, TXRYAN]);
    let (code, text) = verify(&anchors);
    assert_eq!(code, 0, "{text}");
    assert!(checked(&text, "roughtime"), "{text}");
}
