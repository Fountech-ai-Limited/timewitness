//! `timewitness send`, against a stand-in for the app on this machine.
//!
//! What is held here is the producer's half of keeping receipts: what travels, under what, and what
//! a send that fails does to the receipt, which is nothing. The stand-in answers the way the app
//! does and records what it was sent, so each test reads the request off the wire rather than
//! trusting the command's own account of it.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const CREDENTIAL: &str = "TIMEWITNESS_MACHINE_CREDENTIAL";

/// The committed real receipt, and the figures `timewitness verify --fields` reads off it.
fn real_receipt() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../verify/tests/data/a-real-stamp/receipt.cbor")
}
const REAL_KEY: &str = "07de4306352562a212928f5f8228b4f027af4856ae0b17ea25c7de14a61639ec";
const REAL_PAYLOAD: &str = "c3857f437414da8b13ace74960f0ee3d717765beddb9e6caff350d8c8a3ecbd5";

/// A stand-in for the app: it takes one request, hands it back through the channel, and answers.
fn stand_in(status: &'static str, body: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 8192];
        // Read the head, then as much body as it said it had.
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
        let answer = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(answer.as_bytes());
        let _ = sent.send(String::from_utf8_lossy(&request).to_string());
    });
    (address, received)
}

fn send(args: &[&str], credential: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_timewitness"));
    command.arg("send").args(args).env_remove(CREDENTIAL);
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

#[test]
fn a_receipt_travels_with_its_own_figures_under_a_bearer_and_never_its_subject() {
    let (address, received) = stand_in(
        "201 Created",
        r#"{"id":"x","receiptHash":"y","alreadyHeld":false,"interval":{"from":"receipt"}}"#,
    );
    let receipt = real_receipt();
    let output = send(
        &[
            receipt.to_str().unwrap(),
            "--event",
            "build",
            "--repository",
            "Fountech-ai-Limited/timewitness",
            "--to",
            &address,
        ],
        Some("twm_a-credential"),
    );
    assert_eq!(output.status.code(), Some(0), "{}", said(&output));
    assert!(said(&output).contains("read the interval off the receipt"));

    let request = received
        .recv_timeout(Duration::from_secs(10))
        .expect("the stand-in was sent something");
    assert!(
        request.starts_with("POST /api/machine/receipts/ HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nAuthorization: Bearer twm_a-credential\r\n"));
    for (field, value) in [
        ("publicKey", REAL_KEY),
        ("payloadHash", REAL_PAYLOAD),
        ("sequence", "1"),
        ("reading", "1788979278918450302"),
        ("lower", "1788979278845210129"),
        ("upper", "1788979278999084899"),
        ("event", "build"),
        ("repository", "Fountech-ai-Limited/timewitness"),
    ] {
        assert!(
            request.contains(&format!("\"{field}\": \"{value}\"")),
            "{field} is not {value} in {request}"
        );
    }
    // The receipt's own bytes, as the app reads them.
    let bytes = std::fs::read(&receipt).unwrap();
    assert!(request.contains("\"receipt\": \""));
    assert!(
        request.len() > bytes.len() * 4 / 3,
        "the whole receipt did not travel"
    );
    for never in ["subject", "\"file\"", "content"] {
        assert!(!request.contains(never), "{never} travelled");
    }
}

#[test]
fn a_refusal_is_said_with_the_apps_own_words_and_the_receipt_is_untouched() {
    let (address, _received) = stand_in(
        "422 Unprocessable Entity",
        r#"{"error":"The lower end of the interval this filing states is not the receipt's own"}"#,
    );
    let receipt = real_receipt();
    let before = std::fs::read(&receipt).unwrap();
    let output = send(
        &[receipt.to_str().unwrap(), "--to", &address],
        Some("twm_x"),
    );
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    let words = said(&output);
    assert!(words.contains("422"), "{words}");
    assert!(words.contains("not the receipt's own"), "{words}");
    assert!(words.contains("The receipt is unaffected"), "{words}");
    assert_eq!(std::fs::read(&receipt).unwrap(), before);
}

#[test]
fn an_app_that_cannot_be_reached_fails_this_step_quickly_and_nothing_else() {
    // A port with nothing on it: bound, then let go.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let receipt = real_receipt();
    let started = std::time::Instant::now();
    let output = send(
        &[
            receipt.to_str().unwrap(),
            "--to",
            &format!("http://127.0.0.1:{port}"),
        ],
        Some("twm_x"),
    );
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(said(&output).contains("was not sent"));
    assert!(started.elapsed() < Duration::from_secs(20));
}

#[test]
fn nothing_is_sent_without_a_credential_or_over_plain_http_to_anywhere_else() {
    let receipt = real_receipt();
    let path = receipt.to_str().unwrap();

    let none = send(&[path, "--to", "http://127.0.0.1:9"], None);
    assert_eq!(none.status.code(), Some(2), "{}", said(&none));
    assert!(said(&none).contains(CREDENTIAL));

    let clear = send(&[path, "--to", "http://app.timewitness.dev"], Some("twm_x"));
    assert_eq!(clear.status.code(), Some(1), "{}", said(&clear));
    assert!(
        said(&clear).contains("never sent in the clear"),
        "{}",
        said(&clear)
    );
}

#[test]
fn a_file_that_is_not_a_receipt_that_holds_is_not_sent() {
    let (address, received) = stand_in("201 Created", "{}");
    let dir = std::env::temp_dir().join(format!("tw-send-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut bent = std::fs::read(real_receipt()).unwrap();
    bent[4000] ^= 1;
    let file = dir.join("bent.cbor");
    std::fs::write(&file, &bent).unwrap();

    let output = send(&[file.to_str().unwrap(), "--to", &address], Some("twm_x"));
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(said(&output).contains("not a receipt that holds"));
    assert!(
        received.recv_timeout(Duration::from_millis(500)).is_err(),
        "something was sent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
