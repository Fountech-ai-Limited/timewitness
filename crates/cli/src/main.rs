//! The command line entry point.
//!
//! It wires the clock model, the receipt issuer and the verifier together and does no work of its
//! own. Two subcommands carry the product: `verify`, which a consumer runs and which needs nothing
//! of ours, and `stamp`, which a producer runs and which does. `countersign` is the third of that
//! kind: it reads one half of an exchange off the command line and needs no network either.

#![forbid(unsafe_code)]

mod agent_cmd;
mod app;
mod args;
mod as_json;
mod certificate_cmd;
mod certificate_file;
mod countersign_cmd;
mod key_file;
mod key_log_cmd;
mod order_cmd;
mod render;
mod roughtime_serve_cmd;
mod send_cmd;
mod service_cmd;
mod stamp_cmd;
mod status_cmd;
mod verify_cmd;

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // A command line that cannot be read gets the usage beside the refusal, the same as one naming
    // an option its subcommand does not have. Refused bare, the reader was told what was wrong and
    // not what would have been right.
    let parsed = match args::parse(&argv) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!(
                "{}

{}",
                render::failure(&e.0),
                render::usage()
            );
            return ExitCode::from(2);
        }
    };

    // Nothing a subcommand does not have gets past here. It used to be read as a flag nobody
    // looked at, so `verify --min-sources 9` printed that the receipt held and exited zero.
    if let Err(e) = parsed.check_accepted() {
        eprintln!(
            "{}

{}",
            render::failure(&e.0),
            render::usage()
        );
        return ExitCode::from(2);
    }

    if parsed.wants_help() {
        println!("{}", render::usage());
        return ExitCode::SUCCESS;
    }

    if parsed.wants_version() {
        println!("{}", render::version());
        return ExitCode::SUCCESS;
    }

    let outcome = match parsed.command.as_deref() {
        Some("verify") => verify_cmd::run(&parsed),
        Some("stamp") => stamp_cmd::run(&parsed),
        Some("agent") => agent_cmd::run(&parsed),
        Some("roughtime-serve") => roughtime_serve_cmd::run(&parsed),
        Some("key-log") => key_log_cmd::run(&parsed),
        Some("countersign") => countersign_cmd::run(&parsed),
        Some("order") => order_cmd::run(&parsed),
        Some("send") => send_cmd::run(&parsed),
        Some("enrol") => certificate_cmd::run_enrol(&parsed),
        Some("certificate") => certificate_cmd::run_certificate(&parsed),
        Some("status") => status_cmd::run(&parsed),
        Some("cannot-prove") => verify_cmd::Outcome {
            text: render::cannot_prove_document(),
            code: 0,
        },
        Some(other) => verify_cmd::Outcome {
            text: format!(
                "{}\n\n{}",
                render::failure(&format!("{other:?} is not something this does")),
                render::usage()
            ),
            code: 2,
        },
        None => verify_cmd::Outcome {
            text: render::usage(),
            code: 0,
        },
    };

    if outcome.code == 0 {
        println!("{}", outcome.text);
    } else {
        eprintln!("{}", outcome.text);
    }
    ExitCode::from(u8::try_from(outcome.code).unwrap_or(2))
}
