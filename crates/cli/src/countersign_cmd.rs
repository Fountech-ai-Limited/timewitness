//! `timewitness countersign`, which reads an exchange and says what it establishes.
//!
//! One value is one half of an exchange. Two values are a request and the response that answers it,
//! and those are checked against each other as well as each on its own: the response has to name
//! the request by the hash of the bytes the request travelled as, and the two halves have to be
//! signed by two different keys.
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

use timewitness_countersign::{Countersigned, Exchange, Ordering, Role, Signed};

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let values = match gather(args) {
        Ok(values) => values,
        Err(outcome) => return outcome,
    };

    let as_fields = args.flag("--fields");
    match values.as_slice() {
        [one] => read_one(one),
        [request, response] => read_pair(request, response, as_fields),
        _ => refuse(
            "countersign takes one half of an exchange, or a request and the response to it, \
             and no more than two",
        ),
    }
}

/// The values to read: from the command line, or from a file holding one to a line.
///
/// A request and the response to it sit in one file the way they sit in a log, so a reader handed
/// two lines runs the same command as a reader handed one.
fn gather(args: &Args) -> Result<Vec<String>, Outcome> {
    match (args.positional.is_empty(), args.value("--from")) {
        (false, Some(_)) => Err(refuse("give the header values or --from, not both")),
        (false, None) => Ok(args.positional.clone()),
        (true, Some(path)) => match fs::read_to_string(path) {
            Ok(text) => {
                let lines: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(ToString::to_string)
                    .collect();
                if lines.is_empty() {
                    Err(refuse(&format!("{path} holds no header value")))
                } else {
                    Ok(lines)
                }
            }
            Err(e) => Err(refuse(&format!("{path} could not be read: {e}"))),
        },
        (true, None) => Err(refuse(
            "countersign needs the header value, or --from naming a file holding it",
        )),
    }
}

fn read_pair(request: &str, response: &str, as_fields: bool) -> Outcome {
    match Countersigned::read(request, response) {
        Ok(pair) => Outcome {
            text: if as_fields {
                fields_of(&pair)
            } else {
                describe_pair(&pair, request, response)
            },
            code: 0,
        },
        Err(why) => unreadable(&format!("these two are not one exchange: {why}")),
    }
}

/// The pair as lines a script reads, in the same shape `verify --fields` uses.
///
/// The verdict is one word. The number beside it is the clear space where there is an order and the
/// overlap where there is not, and they are named differently so that a script cannot read one as
/// the other.
fn fields_of(pair: &Countersigned) -> String {
    let ordering = pair.ordering();
    let mut out = String::new();
    out.push_str(&format!("halves=2\norder={}\n", ordering.word()));
    match ordering {
        Ordering::Established { gap_ns } | Ordering::Contradicted { gap_ns } => {
            out.push_str(&format!("gap_ns={gap_ns}\n"));
        }
        Ordering::Undecided { overlap_ns } => {
            out.push_str(&format!("overlap_ns={overlap_ns}\n"));
        }
        Ordering::NotSayable => {}
    }
    for (which, half) in [("request", pair.request()), ("response", pair.response())] {
        let e = &half.exchange;
        out.push_str(&format!("{which}_key={}\n", hex(&e.key)));
        out.push_str(&format!("{which}_payload={}\n", hex(&e.payload)));
        out.push_str(&format!("{which}_sequence={}\n", e.sequence));
        out.push_str(&format!("{which}_earliest_ns={}\n", e.interval.earliest_ns));
        out.push_str(&format!("{which}_latest_ns={}\n", e.interval.latest_ns));
        out.push_str(&format!(
            "{which}_width_ns={}\n",
            e.interval.latest_ns - e.interval.earliest_ns
        ));
        out.push_str(&format!("{which}_receipt={}\n", hex(&e.receipt)));
        out.push_str(&format!("{which}_sha256={}\n", hex(&half.envelope_hash())));
    }
    out
}

fn read_one(value: &str) -> Outcome {
    let signed = match Signed::from_wire(value) {
        Ok(signed) => signed,
        Err(why) => {
            return unreadable(&format!("this is not an exchange this can read: {why}"));
        }
    };

    Outcome {
        text: describe(&signed.exchange, value),
        code: 0,
    }
}

/// A value, or a pair, this cannot read.
///
/// A refusal is not an error in this tool: the receiver's own answer to one is to carry on as
/// though no exchange happened. It is still a non-zero exit, because somebody asking this question
/// at a command line wants to know the answer was no.
fn unreadable(why: &str) -> Outcome {
    Outcome {
        text: format!(
            "{}\n\n{}",
            render::failure(why),
            "Nothing follows from it. A receiver would carry on as though no exchange happened, \
             which is what this product does instead of enforcing.",
        ),
        code: 1,
    }
}

fn describe_pair(pair: &Countersigned, request: &str, response: &str) -> String {
    let mut out = String::from(
        "These two are one countersigned exchange. Both signatures hold, the response names the \
         request by the bytes the request travelled as, and the two halves were signed by two \
         different keys.\n\n",
    );
    out.push_str("The sender's half.\n\n");
    out.push_str(&describe_half(&pair.request().exchange, request));
    out.push_str("\nThe receiver's half.\n\n");
    out.push_str(&describe_half(&pair.response().exchange, response));
    out.push_str("\nWhich came first.\n\n");
    out.push_str(&order_said(&pair.ordering()));
    out.push_str(
        "\nWhat that establishes. Two parties who each hold a key each signed a statement about \
         its own clock, and those two statements are the whole of what you have. Neither interval \
         is evidence for the other party, and countersigning does not make it so: the evidence for \
         each interval is in the receipt that half names above, which this form does not carry. \
         Fetch each receipt, run `timewitness verify` on it, and check its hash against the one \
         here.\n",
    );
    out
}

fn describe(exchange: &Exchange, value: &str) -> String {
    let half = match exchange.role {
        Role::Request => "the sender's half",
        Role::Response => "the receiver's half",
    };
    let mut out = format!("This is {half} of a countersign exchange and its signature holds.\n\n");
    out.push_str(&describe_half(exchange, value));
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

/// The ordering verdict in words, with what it does and does not mean underneath it.
///
/// The undecided case gets the most words on purpose. It is the one a reader is most likely to
/// misread as the tool having failed, and it is the one the product exists to be willing to say.
fn order_said(ordering: &Ordering) -> String {
    let mut out = format!("  {ordering}\n\n");
    out.push_str(match ordering {
        Ordering::Established { .. } => {
            "  The two intervals do not touch, so every moment the request could have been is \
             before\n  every moment the response could have been. That holds whatever either \
             clock was\n  really doing inside its own stated bound. It is a claim about order and \
             not about\n  accuracy.\n"
        }
        Ordering::Undecided { .. } => {
            "  The request was made before the response, in the world. What these two claims do \
             not\n  do is establish it: each agent's own bound is wider than the distance between \
             the two\n  readings, so the two moments could have fallen either way round inside \
             them, or at\n  the same instant. Nothing here narrows one bound with the other to \
             reach an answer,\n  because two claims about two different clocks are not evidence \
             about each other.\n"
        }
        Ordering::Contradicted { .. } => {
            "  A response names its request by the hash of bytes that had to exist before the\n  \
             response was made, so a receive moment wholly before the send moment cannot be true. \
             At\n  least one of the two claims is wrong: a clock is outside the bound its own \
             agent\n  stated, or a party is lying. Which of those it is cannot be told from the \
             pair, and\n  this does not guess.\n"
        }
        Ordering::NotSayable => {
            "  One half has its edges the wrong way round, so nothing follows from the pair.\n"
        }
    });
    out
}

/// The fields of one half, the same way in a single read and in a pair.
fn describe_half(exchange: &Exchange, value: &str) -> String {
    let width = exchange.interval.latest_ns - exchange.interval.earliest_ns;
    let mut out = String::new();
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
