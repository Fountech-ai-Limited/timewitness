//! `timewitness send`: hand a receipt this machine signed to the app that keeps them.
//!
//! A company that has to produce a receipt years later wants a copy somewhere other than the runner
//! that made it. The app keeps one, and this is how a machine gives it one: the receipt's own bytes,
//! with the key, the hash it stamps, its sequence and its interval beside them, under a machine
//! credential. The thing that was stamped never travels; the receipt carries its hash.
//!
//! **Sending is never part of stamping.** It is its own command, run after the stamp, so a stamp
//! never waits on us and a send that fails leaves the receipt exactly where it was. A workflow
//! runs it as a step that cannot fail the job. The architecture check holds `stamp` and `agent`
//! away from the module that names the app.
//!
//! The figures sent beside the bytes are read off the receipt here, by the reader that made it, so
//! they are the receipt's own. The app reads them again where the verifier it pins can, and refuses
//! a filing whose figures disagree; where its verifier is older than this receipt, what it keeps is
//! these figures, marked as the sender's.

use std::fs;

use timewitness_receipt::{chain_link, json, open, Value};
use timewitness_sources::http::json_field;

use crate::app;
use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// The environment variable a machine credential is read from.
///
/// Never an option on the command line, where every other process on the machine can read it.
pub const CREDENTIAL: &str = "TIMEWITNESS_MACHINE_CREDENTIAL";

pub fn run(args: &Args) -> Outcome {
    let Some(receipt_path) = args.positional.first() else {
        return refuse("send takes the receipt to send", 2);
    };
    // A missing credential is a setting rather than a mistyped command, so it is said without the
    // usage under it: in a job log the usage would bury the one line that matters.
    let Ok(credential) = std::env::var(CREDENTIAL) else {
        return Outcome {
            text: render::failure(&format!(
                "{CREDENTIAL} is not set. It holds a machine credential the app issued to this \
                 organisation. Nothing was sent, and the receipt is unaffected"
            )),
            code: 2,
        };
    };
    let credential = credential.trim();
    if credential.is_empty() || credential.contains(char::is_whitespace) {
        return Outcome {
            text: render::failure(&format!("{CREDENTIAL} does not hold a credential")),
            code: 2,
        };
    }

    let bytes = match fs::read(receipt_path) {
        Ok(bytes) => bytes,
        Err(e) => return refuse(&format!("{receipt_path} could not be read: {e}"), 2),
    };
    let receipt = match open(&bytes) {
        Ok(receipt) => receipt,
        Err(e) => {
            return refuse(
                &format!("{receipt_path} is not a receipt that holds, so it was not sent: {e}"),
                1,
            )
        }
    };

    let mut fields: Vec<(&'static str, Value)> = vec![
        ("receipt", Value::text(base64(&bytes))),
        (
            "publicKey",
            Value::text(render::hex(&receipt.agent_public_key)),
        ),
        (
            "payloadHash",
            Value::text(render::hex(&receipt.payload.hash)),
        ),
        ("sequence", Value::text(receipt.sequence.to_string())),
        (
            "reading",
            Value::text(receipt.utc_estimate.as_nanos().to_string()),
        ),
        (
            "lower",
            Value::text(receipt.claim.earliest.as_nanos().to_string()),
        ),
        (
            "upper",
            Value::text(receipt.claim.latest.as_nanos().to_string()),
        ),
    ];
    if let Some(event) = args.value("--event") {
        fields.push(("event", Value::text(event)));
    }
    if let Some(repository) = args.value("--repository") {
        fields.push(("repository", Value::text(repository)));
    }
    let body = json::render(&Value::map(fields));

    let address = args.value("--to").unwrap_or(app::APP);
    let hash = render::hex(&chain_link(&bytes));
    match app::post_json(address, app::RECEIPTS, credential, &body) {
        Ok(answer) if answer.status == 200 || answer.status == 201 => {
            let held = if answer.status == 200 {
                "It already held this receipt, so it is still one entry."
            } else {
                "It keeps it for the organisation's plan period."
            };
            let interval = match json_field(answer.body.as_bytes(), "from").as_deref() {
                Some("receipt") => {
                    "The app read the interval off the receipt's own bytes.".to_string()
                }
                Some("sender") => format!(
                    "The app could not read this receipt, so it keeps the interval this machine \
                     sent, marked as that: {}",
                    json_field(answer.body.as_bytes(), "note")
                        .unwrap_or_else(|| "it gave no reason".to_string())
                ),
                _ => "The app did not say where the interval it keeps came from.".to_string(),
            };
            Outcome {
                text: format!(
                    "Sent receipt {hash} to {address}. {held} {interval}\n\n\
                     Sending changes nothing about the receipt. It checks the same with the free \
                     verifier whether or not the app holds a copy."
                ),
                code: 0,
            }
        }
        Ok(answer) => refuse(
            &format!(
                "{address} did not keep receipt {hash}: it answered {}, {}. The receipt is \
                 unaffected and is still at {receipt_path}",
                answer.status,
                in_its_words(&answer.body)
            ),
            1,
        ),
        Err(why) => refuse(
            &format!(
                "receipt {hash} was not sent: {why}. The receipt is unaffected and is still at \
                 {receipt_path}"
            ),
            1,
        ),
    }
}

/// What the app said when it did not keep a receipt: its own sentence where it gave one, and a
/// plain account of the answer where it did not. A page of HTML is not an answer from the app, and
/// the likeliest reason for one is an address that is not the app or a build that has no such route.
fn in_its_words(body: &str) -> String {
    let body = body.trim();
    if let Some(error) = json_field(body.as_bytes(), "error") {
        return format!("\"{error}\"");
    }
    if body.starts_with('{') {
        return body.chars().take(400).collect();
    }
    if body.is_empty() {
        return "with nothing".to_string();
    }
    "with a page rather than an answer, so that address is not an app build that takes receipts"
        .to_string()
}

/// A refusal, without the usage beneath it where the command line itself was fine.
fn refuse(why: &str, code: i32) -> Outcome {
    Outcome {
        text: if code == 2 {
            format!("{}\n\n{}", render::failure(why), render::usage())
        } else {
            render::failure(why)
        },
        code,
    }
}

/// Standard base64 with padding, which is what the app reads a receipt as.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= group.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64;

    #[test]
    fn base64_is_the_standard_alphabet_with_padding() {
        // RFC 4648 section 10.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain}");
        }
        assert_eq!(base64(&[0xfb, 0xff]), "+/8=");
    }
}
