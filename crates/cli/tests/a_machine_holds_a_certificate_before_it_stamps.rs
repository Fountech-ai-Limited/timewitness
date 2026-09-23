//! A machine enrols its key and holds a certificate before it stamps, and a stamp asks the app for
//! nothing.
//!
//! `enrol` and `certificate` run against a stand-in for the app on this machine, which answers the
//! way the app does and hands back what it was sent, so each test reads the request off the wire.
//! `stamp` runs against no app at all: where a certificate is asked for and not held, it refuses
//! before it makes a key or asks a time source anything, and writes no receipt.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use timewitness_receipt::AgentKey;

const CREDENTIAL: &str = "TIMEWITNESS_MACHINE_CREDENTIAL";
const ORGANISATION: &str = "0f6e0c5e-3c1a-4a55-9d4a-2f0b1c9e8a77";
const CHALLENGE: &str = "c2lnbiB0aGlzIGFuZCBub3RoaW5nIGVsc2U";
const SEED: [u8; 32] = [0x42; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn public() -> String {
    hex(&AgentKey::from_seed(&SEED).public_key_bytes())
}

/// A folder of this run's own, with the test's key written into it.
fn scratch(name: &str) -> PathBuf {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "timewitness-certificate-{name}-{}-{since}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("agent.key"), SEED).unwrap();
    dir
}

/// The value of a JSON string field in a request body, as the stand-in reads it.
fn field(request: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\"");
    let at = request.find(&needle)? + needle.len();
    let rest = request[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

/// A stand-in for the app that answers each request in turn with what `answer` says, and hands every
/// request back through the channel.
fn stand_in(
    answers: usize,
    answer: impl Fn(&str) -> (&'static str, String) + Send + 'static,
) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        for _ in 0..answers {
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = socket.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let length = text[..split]
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= split + 4 + length {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&request).to_string();
            let (status, body) = answer(&text);
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(reply.as_bytes());
            let _ = sent.send(text);
        }
    });
    (address, received)
}

/// The statement the app asks a key to sign, as JSON escapes it.
fn statement(key: &str) -> String {
    format!(
        "timewitness enrols this key\\norganisation {ORGANISATION}\\nkey {key}\\nchallenge {CHALLENGE}\\n"
    )
}

fn run(args: &[&str], credential: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_timewitness"));
    command.args(args).env_remove(CREDENTIAL);
    if let Some(credential) = credential {
        command.env(CREDENTIAL, credential);
    }
    command.output().expect("the binary runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn enrolling_signs_the_statement_built_here_over_the_apps_challenge() {
    let dir = scratch("enrol");
    let (address, received) = stand_in(2, |request| {
        if request.starts_with("POST /api/machine/keys/challenge/ ") {
            let key = field(request, "publicKey").unwrap_or_default();
            (
                "201 Created",
                format!(
                    r#"{{"challenge":"{CHALLENGE}","sign":"{}","expires":"2026-09-23T12:05:00Z"}}"#,
                    statement(&key)
                ),
            )
        } else {
            (
                "201 Created",
                format!(r#"{{"organisation":"{ORGANISATION}","publicKey":"x"}}"#),
            )
        }
    });
    let key = dir.join("agent.key");
    let output = run(
        &[
            "enrol",
            "--key",
            path(&key),
            "--label",
            "runner",
            "--to",
            &address,
        ],
        Some("twm_a-credential"),
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));

    let asked = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(asked.contains("\r\nAuthorization: Bearer twm_a-credential\r\n"));
    assert_eq!(field(&asked, "publicKey"), Some(public()));
    let enrolled = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        enrolled.starts_with("POST /api/machine/keys/ HTTP/1.1\r\n"),
        "{enrolled}"
    );
    assert_eq!(field(&enrolled, "challenge").as_deref(), Some(CHALLENGE));
    // Ed25519 signs one message one way, so the signature the app was sent is the one this key
    // makes over the statement built from the three parts, and nothing else.
    let expected = AgentKey::from_seed(&SEED)
        .sign_enrolment(ORGANISATION, CHALLENGE)
        .unwrap();
    assert_eq!(field(&enrolled, "signature"), Some(hex(&expected)));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn enrolling_signs_nothing_the_app_wrote_that_is_not_the_statement() {
    let dir = scratch("enrol-hostile");
    let (address, received) = stand_in(2, |_| {
        (
            "201 Created",
            format!(
                r#"{{"challenge":"{CHALLENGE}","sign":"Signature1 and anything a server wants signed\norganisation {ORGANISATION}\n"}}"#
            ),
        )
    });
    let key = dir.join("agent.key");
    let output = run(
        &["enrol", "--key", path(&key), "--to", &address],
        Some("twm_a-credential"),
    );
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(
        said(&output).contains("something other than the statement"),
        "{}",
        said(&output)
    );
    received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "a second request went to the app after it asked for something else to be signed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_certificate_is_kept_beside_the_key_and_one_for_another_key_is_not() {
    let dir = scratch("certificate");
    let key = dir.join("agent.key");
    let (address, received) = stand_in(1, |request| {
        let key = field(request, "publicKey").unwrap_or_default();
        (
            "201 Created",
            format!(
                r#"{{"organisation":"{ORGANISATION}","method":"machine-credential","publicKey":"{key}","validFromNanos":"1","validUntilNanos":"99999999999999999999","leafHash":"ab"}}"#
            ),
        )
    });
    let output = run(
        &[
            "certificate",
            "--key",
            path(&key),
            "--kind",
            "action",
            "--to",
            &address,
        ],
        Some("twm_a-credential"),
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    let asked = received.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(
        asked.starts_with("POST /api/machine/certificates/ HTTP/1.1\r\n"),
        "{asked}"
    );
    assert_eq!(field(&asked, "kind").as_deref(), Some("action"));
    let kept =
        std::fs::read_to_string(dir.join("agent.key.certificate")).expect("kept beside the key");
    assert!(kept.contains(&public()), "{kept}");

    let other = dir.join("other.certificate");
    let (address, _received) = stand_in(1, |_| {
        (
            "201 Created",
            format!(
                r#"{{"organisation":"{ORGANISATION}","method":"machine-credential","publicKey":"{}","validFromNanos":"1","validUntilNanos":"99999999999999999999","leafHash":"ab"}}"#,
                "11".repeat(32)
            ),
        )
    });
    let output = run(
        &[
            "certificate",
            "--key",
            path(&key),
            "--out",
            path(&other),
            "--to",
            &address,
        ],
        Some("twm_a-credential"),
    );
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(!other.exists(), "a certificate for another key was written");
    let _ = std::fs::remove_dir_all(dir);
}

/// A stamp holding `certificate` for the test's key, which has to refuse before anything else.
fn stamp_with(dir: &Path, certificate: &Path) -> (Output, PathBuf) {
    let subject = dir.join("subject.bin");
    std::fs::write(&subject, b"a build").unwrap();
    let out = dir.join("receipt.cbor");
    let output = run(
        &[
            "stamp",
            "--subject",
            path(&subject),
            "--key",
            path(&dir.join("agent.key")),
            "--out",
            path(&out),
            "--certificate",
            path(certificate),
            "--no-evidence",
        ],
        None,
    );
    (output, out)
}

#[test]
fn a_stamp_with_no_certificate_writes_no_receipt_and_says_what_to_fetch() {
    let dir = scratch("stamp-none");
    let (output, out) = stamp_with(&dir, &dir.join("nothing-here.certificate"));
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    let text = said(&output);
    assert!(text.contains("no receipt was written"), "{text}");
    assert!(text.contains("there is no certificate"), "{text}");
    assert!(text.contains("timewitness certificate --key"), "{text}");
    assert!(!out.exists(), "a receipt was written with no certificate");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_stamp_with_under_an_hour_of_its_window_left_or_another_keys_certificate_is_refused() {
    let dir = scratch("stamp-windows");
    let now = i128::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let minute: i128 = 60_000_000_000;
    let certificate = |key: &str, until: i128| {
        format!(
            r#"{{"organisation":"{ORGANISATION}","method":"machine-credential","publicKey":"{key}","validFromNanos":"{}","validUntilNanos":"{until}","leafHash":"ab"}}"#,
            now - 60 * minute
        )
    };

    let ending = dir.join("ending.certificate");
    std::fs::write(&ending, certificate(&public(), now + 20 * minute)).unwrap();
    let (output, out) = stamp_with(&dir, &ending);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(
        said(&output).contains("minutes of its window left"),
        "{}",
        said(&output)
    );
    assert!(!out.exists());

    let others = dir.join("others.certificate");
    std::fs::write(&others, certificate(&"11".repeat(32), now + 600 * minute)).unwrap();
    let (output, out) = stamp_with(&dir, &others);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(
        said(&output).contains("is for the key"),
        "{}",
        said(&output)
    );
    assert!(!out.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_statement_is_the_bytes_the_app_checks() {
    // The app builds the same bytes in `enrolmentMessage`, `lib/accounts.ts`, and its own test holds
    // them to this literal. A change on one side alone turns one of the two red.
    let key = "07de4306352562a212928f5f8228b4f027af4856ae0b17ea25c7de14a61639ec";
    assert_eq!(
        timewitness_receipt::enrolment_message(ORGANISATION, key, CHALLENGE).unwrap(),
        format!(
            "timewitness enrols this key\norganisation {ORGANISATION}\nkey {key}\nchallenge {CHALLENGE}\n"
        )
        .into_bytes()
    );
    assert!(timewitness_receipt::enrolment_message("org\nkey x", key, CHALLENGE).is_err());
    assert!(timewitness_receipt::enrolment_message(ORGANISATION, key, "a b").is_err());
}
