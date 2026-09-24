//! `timewitness status`, against a stand-in agent on this machine.
//!
//! The stand-in speaks the agent's own boundary with the agent's own encoder, so what is held here is
//! the command's reading of a real answer, a real refusal and a missing agent, and nothing about how
//! an agent keeps its model, which `crates/agent` holds.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_agent::wire::{
    encode_reading, encode_refusal, encode_refusal_past_ceiling, Endpoint, TOKEN_BYTES,
};
use timewitness_core::UnixNanos;
use timewitness_receipt::open;

/// The committed version 1 receipt, which is the format an agent of this release answers in.
fn a_version_1_receipt() -> Vec<u8> {
    let hex = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../verify/tests/data/a-version-1-stamp/receipt.hex"),
    )
    .expect("the committed receipt");
    let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tw-status-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("agent.endpoint")
}

/// A stand-in agent that answers one caller with `reply`, and the endpoint file that finds it.
fn stand_in(name: &str, reply: Vec<u8>) -> PathBuf {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = Endpoint::fresh(listener.local_addr().unwrap().to_string()).unwrap();
    let path = scratch(name);
    endpoint.write(&path).unwrap();
    thread::spawn(move || {
        if let Ok((mut socket, _)) = listener.accept() {
            let mut token = [0u8; TOKEN_BYTES];
            if socket.read_exact(&mut token).is_ok() && token == endpoint.token {
                let _ = socket.write_all(&reply);
            }
        }
    });
    path
}

fn status(endpoint: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(["status", "--agent", endpoint.to_str().unwrap()])
        .output()
        .expect("the binary runs")
}

fn said(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn an_agent_that_answers_is_described_by_its_bound_and_its_sources() {
    // A real receipt's reading, moved to now so it is not wildly apart from this machine's clock,
    // and carried the way the agent carries one.
    let mut carrier = open(&a_version_1_receipt()).expect("the committed receipt opens");
    let now = i128::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    )
    .unwrap();
    let below = carrier.utc_estimate.as_nanos() - carrier.claim.earliest.as_nanos();
    let above = carrier.claim.latest.as_nanos() - carrier.utc_estimate.as_nanos();
    carrier.utc_estimate = UnixNanos(now);
    carrier.claim.earliest = UnixNanos(now - below);
    carrier.claim.latest = UnixNanos(now + above);

    let endpoint = stand_in("answers", encode_reading(&carrier));
    let output = status(&endpoint);
    let words = said(&output);
    assert_eq!(output.status.code(), Some(0), "{words}");
    assert!(words.contains("is up and answering"), "{words}");
    // 186.008 ms from the receipt, and a little more for the crossing, which the status says.
    assert!(
        words.contains(" ms wide, on 9 of 9 sources, run by "),
        "{words}"
    );
    assert!(words.contains("last heard"), "{words}");
    assert!(words.contains("left alone"), "{words}");
    assert!(words.contains("not how right it is"), "{words}");
    // The plain sentence, which is what somebody new reads first.
    assert!(
        words.contains("Right now the time it gives could be wrong by as much as "),
        "{words}"
    );
    assert!(
        words.contains("A stamp taken now would carry that bound."),
        "{words}"
    );
    for never in ["accurate", "accuracy"] {
        assert!(!words.to_lowercase().contains(never), "{never}: {words}");
    }
}

#[test]
fn an_agent_that_refuses_is_said_to_be_up_and_refusing_with_its_reason() {
    let endpoint = stand_in(
        "refuses",
        encode_refusal("the model has not heard from enough sources yet"),
    );
    let output = status(&endpoint);
    let words = said(&output);
    assert_eq!(output.status.code(), Some(1), "{words}");
    assert!(words.contains("would not give a reading"), "{words}");
    assert!(
        words.contains("not heard from enough sources yet"),
        "{words}"
    );
    // An agent this young is told to be still on its way to a first bound, and when to ask again.
    assert!(words.contains("still asking its sources"), "{words}");
}

#[test]
fn a_bound_past_the_ceiling_is_stated_in_a_plain_sentence_and_still_refused() {
    // A fresh agent's first minutes: the model has a bound and it is wider than the agent will sign
    // for. The status says the width, in words somebody new can read, and exits as a refusal does.
    let endpoint = stand_in(
        "past",
        encode_refusal_past_ceiling(
            1_203_645_522,
            250_000_000,
            "the bound has grown to 1203.645522 ms, past the 250 ms ceiling this model will sign \
             for",
        ),
    );
    let output = status(&endpoint);
    let words = said(&output);
    assert_eq!(output.status.code(), Some(1), "{words}");
    assert!(
        words.contains("Right now the time it gives could be wrong by as much as 1.204 s."),
        "{words}"
    );
    assert!(
        words.contains("past the 250.000 ms it will sign for"),
        "{words}"
    );
    assert!(
        words.contains("a stamp taken now would be refused"),
        "{words}"
    );
    // The endpoint file was written a moment ago, so this reads as an agent still settling.
    assert!(words.contains("It started "), "{words}");
    assert!(
        words.contains("the agent said  the bound has grown to"),
        "{words}"
    );
    for never in ["accurate", "accuracy"] {
        assert!(!words.to_lowercase().contains(never), "{never}: {words}");
    }
}

#[test]
fn a_bound_too_wide_to_state_is_said_to_be_more_than_an_hour() {
    let endpoint = stand_in(
        "widest",
        encode_refusal_past_ceiling(i128::MAX, 250_000_000, "the bound has grown past anything"),
    );
    let output = status(&endpoint);
    let words = said(&output);
    assert_eq!(output.status.code(), Some(1), "{words}");
    assert!(
        words.contains("Right now the time it gives could be wrong by more than an hour."),
        "{words}"
    );
}

#[test]
fn no_agent_is_said_plainly_whether_the_file_is_missing_or_nothing_listens() {
    let missing = scratch("missing").with_file_name("never-written.endpoint");
    let output = status(&missing);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(
        said(&output).contains("no agent is running"),
        "{}",
        said(&output)
    );

    // An endpoint file whose address nothing answers at any more, as a stopped agent leaves one.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = scratch("stopped");
    Endpoint::fresh(format!("127.0.0.1:{port}"))
        .unwrap()
        .write(&path)
        .unwrap();
    let output = status(&path);
    assert_eq!(output.status.code(), Some(1), "{}", said(&output));
    assert!(said(&output).contains("not answering"), "{}", said(&output));
}
