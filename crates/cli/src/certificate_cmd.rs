//! `timewitness enrol` and `timewitness certificate`: what a machine does with the app before it
//! stamps, so that a stamp never has to.
//!
//! A receipt is a TimeWitness certificate when the app certified the key that signed it. So a
//! machine enrols its key once, proving it holds the secret half, and fetches a certificate for it
//! ahead of stamping, which `stamp` then reads from disk. Neither command is on the path of a stamp,
//! and the architecture check holds `stamp` away from the module that talks to the app.
//!
//! **What the key signs is built here.** The app answers a challenge with the text it wants signed,
//! and this command signs nothing it did not build itself from the organisation, the key and the
//! challenge. Where the app's text is not that, byte for byte, it refuses: a key that signs whatever
//! a server hands it is a key a server can use.

use std::fs;

use timewitness_receipt::{enrolment_message, json, Value};
use timewitness_sources::http::json_field;

use crate::app;
use crate::args::Args;
use crate::certificate_file;
use crate::render;
use crate::send_cmd::CREDENTIAL;
use crate::verify_cmd::Outcome;

fn refuse(what: &str, code: i32) -> Outcome {
    Outcome {
        text: render::failure(what),
        code,
    }
}

/// The machine credential, from the environment and never the command line.
fn credential() -> Result<String, Outcome> {
    let Ok(credential) = std::env::var(CREDENTIAL) else {
        return Err(refuse(
            &format!(
                "{CREDENTIAL} is not set. It holds a machine credential the app issued to this \
                 organisation"
            ),
            2,
        ));
    };
    let credential = credential.trim().to_string();
    if credential.is_empty() || credential.contains(char::is_whitespace) {
        return Err(refuse(
            &format!("{CREDENTIAL} does not hold a credential"),
            2,
        ));
    }
    Ok(credential)
}

/// The app's statement as the text it is. It is lines of letters, digits, hyphens and underscores,
/// so the only escape JSON gives it is the newline, and any other is refused rather than read.
fn unescaped(text: &str) -> Option<String> {
    let plain = text.replace("\\n", "\n");
    (!plain.contains('\\')).then_some(plain)
}

/// The organisation an enrolment statement names, read off the app's text only to rebuild it.
fn organisation_in(statement: &str) -> Option<&str> {
    statement
        .lines()
        .find_map(|line| line.strip_prefix("organisation "))
}

pub fn run_enrol(args: &Args) -> Outcome {
    let key_path = match args.required("--key") {
        Ok(path) => path,
        Err(e) => return refuse(&e.0, 2),
    };
    let credential = match credential() {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    let key = match crate::key_file::key_or_new(key_path) {
        Ok(key) => key,
        Err(text) => return refuse(&text, 1),
    };
    let public = render::hex(&key.public_key_bytes());
    let address = args.value("--to").unwrap_or(app::APP);
    if let Some(why) = app::not_open(address) {
        return refuse(&format!("nothing was enrolled: {why}"), 1);
    }

    let body = json::render(&Value::map(vec![(
        "publicKey",
        Value::text(public.clone()),
    )]));
    let asked = match app::post_json(address, app::KEY_CHALLENGE, &credential, &body) {
        Ok(answer) if answer.status == 201 => answer,
        Ok(answer) => {
            return refuse(
                &format!(
                    "the app would not give a challenge for this key, and answered {}: {}",
                    answer.status,
                    json_field(answer.body.as_bytes(), "error").unwrap_or(answer.body)
                ),
                1,
            )
        }
        Err(e) => return refuse(&format!("nothing was enrolled: {e}"), 1),
    };
    let (Some(challenge), Some(statement)) = (
        json_field(asked.body.as_bytes(), "challenge"),
        json_field(asked.body.as_bytes(), "sign"),
    ) else {
        return refuse("the app's answer carries no challenge to sign", 1);
    };
    let Some(statement) = unescaped(&statement) else {
        return refuse("the app's statement carries an escape no statement has", 1);
    };
    let Some(organisation) = organisation_in(&statement) else {
        return refuse("the app's statement names no organisation", 1);
    };
    // Built here, and compared with the app's text rather than taken from it.
    match enrolment_message(organisation, &public, &challenge) {
        Ok(ours) if ours == statement.as_bytes() => {}
        Ok(_) | Err(_) => return refuse(
            "the app asked this key to sign something other than the statement that enrols it, \
                 so nothing was signed and nothing was enrolled",
            1,
        ),
    }
    let signature = match key.sign_enrolment(organisation, &challenge) {
        Ok(signature) => signature,
        Err(e) => return refuse(&format!("nothing was signed: {e}"), 1),
    };

    let label = args.value("--label").unwrap_or("unnamed machine");
    let body = json::render(&Value::map(vec![
        ("publicKey", Value::text(public.clone())),
        ("label", Value::text(label)),
        ("challenge", Value::text(challenge)),
        ("signature", Value::text(render::hex(&signature))),
    ]));
    match app::post_json(address, app::KEYS, &credential, &body) {
        Ok(answer) if answer.status == 201 => Outcome {
            text: format!(
                "Enrolled the key {public} with organisation {organisation} at {address}, on proof \
                 this machine holds it. Fetch a certificate for it with `timewitness certificate \
                 --key {key_path}` before stamping.\n"
            ),
            code: 0,
        },
        Ok(answer) => refuse(
            &format!(
                "the app did not enrol the key, and answered {}: {}",
                answer.status,
                json_field(answer.body.as_bytes(), "error").unwrap_or(answer.body)
            ),
            1,
        ),
        Err(e) => refuse(&format!("nothing was enrolled: {e}"), 1),
    }
}

pub fn run_certificate(args: &Args) -> Outcome {
    let key_path = match args.required("--key") {
        Ok(path) => path,
        Err(e) => return refuse(&e.0, 2),
    };
    let kind = args.value("--kind").unwrap_or("agent");
    if kind != "agent" && kind != "action" {
        return refuse("--kind is agent or action", 2);
    }
    let credential = match credential() {
        Ok(c) => c,
        Err(outcome) => return outcome,
    };
    // A key is never made here: a certificate for a key nobody enrolled is not one the app gives.
    let key = match crate::key_file::key_at(key_path) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return refuse(
                &format!("there is no key at {key_path}. Enrol one first with `timewitness enrol`"),
                1,
            )
        }
        Err(text) => return refuse(&text, 1),
    };
    let public = render::hex(&key.public_key_bytes());
    let address = args.value("--to").unwrap_or(app::APP);
    let out = args.value("--out").map_or_else(
        || certificate_file::beside(key_path),
        std::path::PathBuf::from,
    );

    let body = json::render(&Value::map(vec![
        ("publicKey", Value::text(public.clone())),
        ("kind", Value::text(kind)),
    ]));
    if let Some(why) = app::not_open(address) {
        return refuse(
            &format!("no certificate was issued: {why}. Nothing was written"),
            1,
        );
    }
    let answer = match app::post_json(address, app::CERTIFICATES, &credential, &body) {
        Ok(answer) if answer.status == 201 => answer,
        Ok(answer) => {
            return refuse(
                &format!(
                    "no certificate was issued, and the app answered {}: {}. Nothing was written",
                    answer.status,
                    json_field(answer.body.as_bytes(), "error").unwrap_or(answer.body)
                ),
                1,
            )
        }
        Err(e) => return refuse(&format!("no certificate was fetched: {e}"), 1),
    };
    let kept = match certificate_file::from_the_app(answer.body.as_bytes(), &public) {
        Ok(kept) => kept,
        Err(e) => return refuse(&format!("{e}. Nothing was written"), 1),
    };
    if let Err(e) = fs::write(&out, &kept) {
        return refuse(&timewitness_platform::files::unwritable(&out, &e), 1);
    }
    Outcome {
        text: format!(
            "A certificate for the key {public} is kept at {}. A stamp reads it from there and \
             asks the app for nothing.\n",
            out.display()
        ),
        code: 0,
    }
}
