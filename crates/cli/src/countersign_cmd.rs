//! `timewitness countersign`, which reads one half of an exchange and says what it establishes.
//!
//! There is no network call in this path and no account, the same as `verify`. A reader who unplugs
//! the machine gets the same answer, because everything the check needs travels in the value itself.
//!
//! What it prints is deliberately narrow. A verified signature says the party holding that key
//! signed that statement about its own clock. It does not say the clock was right, and where a
//! second half arrives it will not say anything about the first party's clock either. The evidence
//! for the interval is in the receipt the claim came from, which this form names by hash and does
//! not carry, so the reader is told to go and get it rather than left to assume.

use std::fs;

use timewitness_countersign::{Exchange, Role, Signed};

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let value = match (args.positional.first(), args.value("--from")) {
        (Some(_), Some(_)) => {
            return refuse("give the header value or --from, not both");
        }
        (Some(given), None) => given.clone(),
        (None, Some(path)) => match fs::read_to_string(path) {
            Ok(text) => text.trim().to_string(),
            Err(e) => return refuse(&format!("{path} could not be read: {e}")),
        },
        (None, None) => {
            return refuse(
                "countersign needs the header value, or --from naming a file holding it",
            );
        }
    };

    let signed = match Signed::from_wire(&value) {
        Ok(signed) => signed,
        Err(why) => {
            // A refusal is not an error in this tool: the receiver's own answer to one is to carry
            // on as though no exchange happened. It is still a non-zero exit, because somebody
            // asking this question at a command line wants to know the answer was no.
            return Outcome {
                text: format!(
                    "{}\n\n{}",
                    render::failure(&format!("this is not an exchange this can read: {why}")),
                    "Nothing follows from it. A receiver would carry on as though no exchange \
                     happened, which is what this product does instead of enforcing.",
                ),
                code: 1,
            };
        }
    };

    Outcome {
        text: describe(&signed.exchange, &value),
        code: 0,
    }
}

fn describe(exchange: &Exchange, value: &str) -> String {
    let half = match exchange.role {
        Role::Request => "the sender's half",
        Role::Response => "the receiver's half",
    };
    let width = exchange.interval.latest_ns - exchange.interval.earliest_ns;
    let mut out = String::new();
    out.push_str(&format!(
        "This is {half} of a countersign exchange and its signature holds.\n\n"
    ));
    out.push_str(&format!("  signed by      {}\n", hex(&exchange.key)));
    out.push_str(&format!("  payload        {}\n", hex(&exchange.payload)));
    out.push_str(&format!("  sequence       {}\n", exchange.sequence));
    out.push_str(&format!(
        "  earliest UTC   {} ns\n  latest UTC     {} ns\n  the interval   {} ns wide\n",
        exchange.interval.earliest_ns, exchange.interval.latest_ns, width
    ));
    out.push_str(&format!("  from receipt   {}\n", hex(&exchange.receipt)));
    if let Some(answers) = exchange.answers {
        out.push_str(&format!("  answering      {}\n", hex(&answers)));
    }
    out.push_str(&format!(
        "  it is          {} characters\n",
        value.chars().count()
    ));

    out.push_str(
        "\nWhat that establishes, and it is less than it looks. The party holding that key signed \
         that statement about its own clock. It is not evidence that the clock was right, and \
         nothing here is third-party evidence for anybody: the evidence for the interval is in the \
         receipt named above, which this form does not carry. Fetch that receipt and run \
         `timewitness verify` on it to see what bounds the interval, and check its hash against the \
         one here.\n",
    );
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn refuse(why: &str) -> Outcome {
    Outcome {
        text: format!("{}\n\n{}", render::failure(why), render::usage()),
        code: 2,
    }
}
