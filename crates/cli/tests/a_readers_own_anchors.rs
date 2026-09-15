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

fn work(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "timewitness-own-anchors-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a folder to work in");
    dir
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
