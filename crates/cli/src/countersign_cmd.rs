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

use timewitness_countersign::{
    Countersigned, Digest32, Exchange, Interval, Ordering, Role, Signed,
};
use timewitness_receipt::{chain_link, open, AgentKey};

use crate::args::Args;
use crate::key_file::key_at;
use crate::render;
use crate::verify_cmd::Outcome;

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let as_fields = args.flag("--fields");

    // The make-a-half options are read before anything is gathered, because they take no exchange
    // value and gather refuses where there is none.
    if args.flag("--ask") {
        if args.flag("--answer") {
            return refuse(
                "--ask makes the sender's half and --answer makes the receiver's half, so it is \
                 one or the other",
            );
        }
        if !args.positional.is_empty() || args.value("--from").is_some() {
            return refuse(
                "--ask makes a half rather than reading one, so it takes no exchange value",
            );
        }
        return ask(args, as_fields);
    }

    let values = match gather(args) {
        Ok(values) => values,
        Err(outcome) => return outcome,
    };

    if args.flag("--answer") {
        return match values.as_slice() {
            [request] => answer(args, request, as_fields),
            _ => refuse("--answer takes the one request being answered and nothing else"),
        };
    }

    match values.as_slice() {
        [one] => read_one(one),
        [request, response] => read_pair(request, response, as_fields),
        _ => refuse(
            "countersign takes one half of an exchange, or a request and the response to it, \
             and no more than two",
        ),
    }
}

/// The receive half, made here, from a receipt this machine's own agent already signed.
///
/// **Everything the response says about this party's clock comes out of that receipt**, and none of
/// it can be given on the command line. That is the whole of why this exists: the library call
/// takes an interval, a sequence and a receipt hash, and a command line that took those three as
/// arguments would let a receiver state an interval no clock of its ever read. So the interval is
/// the receipt's interval, the sequence is the receipt's place in its own chain, the hash is the
/// hash of those exact signed bytes, and the payload is what the receipt is a receipt for.
///
/// **Receiver-only mode is this command and nothing else.** No account, no key of ours, no network
/// call, and nothing here asks whether the sender has paid for anything. The receipt it reads is
/// one the receiver made for itself with `timewitness stamp`, and the exchange is between the two
/// parties with nothing of ours in it.
fn answer(args: &Args, request: &str, as_fields: bool) -> Outcome {
    let Claim {
        key,
        payload,
        sequence,
        interval,
        link,
    } = match own_claim(args, Half::Receiver) {
        Ok(claim) => claim,
        Err(outcome) => return outcome,
    };

    let pair = match Countersigned::answer_wire(request, payload, sequence, interval, link, &key) {
        Ok(pair) => pair,
        Err(why) => {
            return Outcome {
                text: format!(
                    "{}\n\n{}",
                    render::failure(&format!("this request was not answered: {why}")),
                    "Nothing was signed. A receiver that will not countersign carries on as though \
                     no exchange happened, which is what this product does instead of enforcing.",
                ),
                code: 1,
            }
        }
    };

    // What is handed back is read back, through the same reader a stranger runs, before a word of
    // it is printed. A writer that keeps its own list of what a valid pair looks like is a second
    // answer waiting to disagree with the first.
    let response = pair.response().to_wire();
    let mut text = match Countersigned::read(request, &response) {
        Ok(read) => {
            if as_fields {
                return Outcome {
                    text: format!("{}\n{}", fields_of(&read), one_field("response", &response)),
                    code: 0,
                };
            }
            format!(
                "{}\n\n{}\n\n",
                "The response. Send this back as the X-Bounded-Time header on the reply.", response
            )
        }
        Err(why) => {
            return refuse(&format!(
                "the response this built is one our own reader refuses, which is a fault in this \
                 build rather than in the request: {why}"
            ))
        }
    };
    text.push_str(&describe_pair(&pair, request, &response));
    Outcome { text, code: 0 }
}

/// The send half, made here, from a receipt this machine's own agent already signed.
///
/// This is the other side of `--answer` and it exists for the same reason. Until it was built the
/// command line could answer an exchange and not start one, so two machines could only countersign
/// each other through a program somebody wrote against the library, and a claim that two machines
/// countersign each other with the shipped binary was a claim about code that did not exist.
///
/// **Every number in the half comes out of the receipt**, exactly as it does on the answering side:
/// the interval is the receipt's interval, the sequence is the receipt's place in this agent's own
/// chain, the hash is the hash of those signed bytes, and the payload is what the receipt is a
/// receipt for. None of the four can be given as an argument, so there is no way here to state an
/// interval this machine's clock never read.
///
/// **Nothing of ours is in it.** No account, no key of ours and no network call, the same as the
/// answering side, which is what lets two machines in a fleet exchange these with our app switched
/// off, unreachable or never deployed.
fn ask(args: &Args, as_fields: bool) -> Outcome {
    let Claim {
        key,
        payload,
        sequence,
        interval,
        link,
    } = match own_claim(args, Half::Sender) {
        Ok(claim) => claim,
        Err(outcome) => return outcome,
    };

    let exchange = Exchange {
        role: Role::Request,
        payload,
        sequence,
        interval,
        receipt: link,
        key: key.public_key_bytes(),
        answers: None,
    };
    let signed = match Signed::new(&exchange, &key) {
        Ok(signed) => signed,
        Err(why) => {
            return Outcome {
                text: format!(
                    "{}\n\n{}",
                    render::failure(&format!("this request was not made: {why}")),
                    "Nothing was signed. A sender that cannot make its half sends the request it \
                     would have sent with no header at all, which is what this product does \
                     instead of enforcing.",
                ),
                code: 1,
            }
        }
    };

    // What is handed back is read back, through the same reader a stranger runs, before a word of
    // it is printed. The answering side does this and so does this one, for the same reason: a
    // writer keeping its own list of what a valid half looks like is a second answer waiting to
    // disagree with the first.
    let request = signed.to_wire();
    let read = match Signed::from_wire(&request) {
        Ok(read) => read,
        Err(why) => {
            return refuse(&format!(
                "the request this built is one our own reader refuses, which is a fault in this \
                 build rather than in the receipt: {why}"
            ))
        }
    };
    if as_fields {
        return Outcome {
            text: format!(
                "{}{}",
                half_fields("request", &read),
                one_field("request", &request)
            ),
            code: 0,
        };
    }

    let mut text = String::from(
        "The request. Send this as the X-Bounded-Time header on what you are sending.\n\n",
    );
    text.push_str(&request);
    text.push_str("\n\n");
    text.push_str(&describe(&read.exchange, &request));
    text.push_str(
        "\nWhat happens next is the other machine's to decide. It answers with `timewitness \
         countersign --answer`, or it does not, and a request that is not answered is the request \
         it would have been with no header on it. Nothing here obliges anybody to countersign.\n",
    );
    Outcome { text, code: 0 }
}

/// Which half of an exchange is being made here.
#[derive(Clone, Copy)]
enum Half {
    /// The sender's, under `--ask`.
    Sender,
    /// The receiver's, under `--answer`.
    Receiver,
}

impl Half {
    /// The word for the half itself, for a refusal a person reads once.
    const fn half(self) -> &'static str {
        match self {
            Half::Sender => "a request",
            Half::Receiver => "a response",
        }
    }
}

/// What one party says about its own clock, every field of it taken from its own receipt.
struct Claim {
    key: AgentKey,
    payload: Digest32,
    sequence: u64,
    interval: Interval,
    link: Digest32,
}

/// Read the receipt and the key, and take the claim out of the receipt.
///
/// Both halves are made from this one function on purpose. The property that matters is not that
/// each side refuses to be told an interval, it is that neither side can be, and two copies of the
/// same reading are two places for that to stop being true.
fn own_claim(args: &Args, half: Half) -> Result<Claim, Outcome> {
    let receipt_path = args.required("--receipt").map_err(|e| refuse(&e.0))?;
    let bytes = fs::read(receipt_path)
        .map_err(|e| refuse(&format!("{receipt_path} could not be read: {e}")))?;
    let receipt = open(&bytes).map_err(|e| {
        refuse(&format!(
            "{receipt_path} is not a receipt this can read: {e}"
        ))
    })?;

    let key_path = args.required("--key").map_err(|e| refuse(&e.0))?;
    let key = match key_at(key_path) {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Err(refuse(&format!(
                "{key_path} is not there. Making {} means signing with the key that signed the \
                 receipt being named, so this reads a key and never makes one",
                half.half()
            )))
        }
        Err(text) => return Err(refuse(&text)),
    };

    // A half names a receipt by hash, and a reader who fetches that receipt finds the key that
    // signed it. If that is not the key that signed the half, the reader is holding the claims of
    // two different parties and nothing here would have told them. It is refused at the one place
    // that can see both, which is here, in the party that holds them.
    if key.public_key_bytes() != receipt.agent_public_key {
        return Err(refuse(&format!(
            "the key in {key_path} did not sign the receipt in {receipt_path}, so {} signed with \
             it would name a receipt of somebody else's",
            half.half()
        )));
    }

    let payload: Digest32 = receipt.payload.hash.clone().try_into().map_err(|_| {
        refuse(&format!(
            "the receipt in {receipt_path} stamps a hash that is not 32 bytes, and the exchange \
             carries a sha-256"
        ))
    })?;
    let link: Digest32 = chain_link(&bytes)
        .try_into()
        .map_err(|_| refuse("a sha-256 hash is 32 bytes"))?;

    Ok(Claim {
        key,
        payload,
        sequence: receipt.sequence,
        interval: Interval {
            earliest_ns: receipt.claim.earliest.as_nanos(),
            reading_ns: receipt.utc_estimate.as_nanos(),
            latest_ns: receipt.claim.latest.as_nanos(),
        },
        link,
    })
}

/// The half's own fields, for the surface a script reads.
///
/// One function, used for a pair and for a half made on its own, so a script that learned the names
/// from one reads the other without being taught again.
fn half_fields(which: &str, half: &Signed) -> String {
    let e = &half.exchange;
    let mut out = String::new();
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
    out
}

/// One `name=value` line, for the field surface.
fn one_field(name: &str, value: &str) -> String {
    let mut out = String::new();
    render::write_field(&mut out, name, value);
    out
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

/// Read a pair and say what it establishes.
///
/// The exit follows the verdict the way `order`'s does. A contradicted pair is read and described,
/// because saying it is what the reader is for, and it still exits 1, because a script that reads
/// only the exit code must not take a pair its own reader calls impossible as a good one.
fn read_pair(request: &str, response: &str, as_fields: bool) -> Outcome {
    match Countersigned::read(request, response) {
        Ok(pair) => Outcome {
            text: if as_fields {
                fields_of(&pair)
            } else {
                describe_pair(&pair, request, response)
            },
            code: match pair.ordering() {
                Ordering::Established { .. } | Ordering::Undecided { .. } => 0,
                Ordering::Contradicted { .. } | Ordering::NotSayable => 1,
            },
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
        out.push_str(&half_fields(which, half));
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
