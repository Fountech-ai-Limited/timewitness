//! `timewitness order`, which reads two receipts and says which came first.
//!
//! It is the second question a reader asks and it needs the first one answered, so both receipts go
//! through the same verification `timewitness verify` runs before either interval is used for
//! anything. An order between two documents nobody checked is not an order between two moments.
//!
//! There is no network call in this path and no account, the same as `verify`. Both receipts carry
//! everything the check needs, and a reader who unplugs the machine gets the same answer.
//!
//! What it prints is deliberately careful in one place. The two intervals often overlap, because
//! each one is wider than the distance between two stamps a program makes in the ordinary course of
//! its work, and the answer there is that nobody can say. That is the product working. A tool that
//! answered every ordering question would be wrong a share of the time nobody could measure
//! afterwards, which is worse than no answer.

use std::fs;

use timewitness_verify::order::{Link, PairReading, Verdict, Which};
use timewitness_verify::{order_of_receipts, verify_with_key_log, Assessment, Subject};

use crate::args::Args;
use crate::render;
use crate::verify_cmd::{anchors_from, floor_from, Outcome};

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let [first_path, second_path] = match args.positional.as_slice() {
        [first, second] => [first, second],
        _ => {
            return refuse("order needs the paths to two receipts");
        }
    };

    let mut bytes = Vec::new();
    for path in [first_path, second_path] {
        match fs::read(path) {
            Ok(read) => bytes.push(read),
            Err(e) => {
                return refuse(&timewitness_platform::files::unreadable(
                    std::path::Path::new(path),
                    &e,
                ))
            }
        }
    }

    let anchors = match anchors_from(args) {
        Ok(a) => a,
        Err(text) => return refuse(&text),
    };
    let floor = match floor_from(args) {
        Ok(floor) => floor,
        Err(text) => return refuse(&text),
    };

    let checked: Vec<Assessment> = bytes
        .iter()
        .map(|receipt| verify_with_key_log(receipt, Subject::NotSupplied, &anchors, &floor, None))
        .collect();
    let reading = order_of_receipts(&checked[0], &checked[1]);

    // Zero where the two receipts could be read and taken at face value together, whatever the
    // answer then was. An undecided pair is a sound pair and a sound answer, so it exits zero and
    // its report goes where a person reading it expects to find it, the same as `countersign` does
    // with a pair whose intervals overlap.
    //
    // What does not exit zero is a pair that cannot be reasoned from: a receipt this reader
    // refused, a receipt it could not read, or two claims of one agent that cannot both be true.
    // Those are refusals and they print as refusals.
    //
    // A chain the reader names as broken, a fork at one sequence number or a link against the
    // agent's own sequence, is two claims of one agent that cannot both be true as well, so it
    // exits 1 however far apart the two intervals are.
    //
    // A script that needs to know whether it may rely on an order reads `stands` under `--fields`,
    // because zero here means the question was answered rather than that the answer was yes.
    let answered = reading.first_held
        && reading.second_held
        && !reading.link.is_a_fault()
        && !matches!(
            reading.verdict,
            Verdict::Contradicted { .. } | Verdict::NotSayable
        );
    let code = i32::from(!answered);
    let text = if args.flag("--fields") {
        fields_of(&reading, &checked)
    } else {
        describe(&reading, &checked, [first_path, second_path])
    };

    Outcome { text, code }
}

/// The reading as lines a script reads, in the same shape `verify --fields` uses.
///
/// The verdict is one word and the number beside it is named for what it is: clear space where
/// there is an order, shared width where there is not. A script that read one as the other would
/// have the two cases exactly backwards, which is why they are never the same field.
fn fields_of(reading: &PairReading, checked: &[Assessment]) -> String {
    let mut out = String::new();
    render::write_field(&mut out, "receipts", 2);
    render::write_field(&mut out, "order", reading.verdict.word());
    match reading.verdict {
        Verdict::Established { earlier, gap_ns } => {
            render::write_field(&mut out, "earlier", word_for(earlier));
            render::write_field(&mut out, "gap_ns", gap_ns);
        }
        Verdict::Undecided { overlap_ns } => {
            render::write_field(&mut out, "overlap_ns", overlap_ns);
        }
        // The chain's own answer is written once, below, for every verdict. Writing it here as
        // well would give a script two lines of one name and whichever it read last.
        Verdict::Contradicted { gap_ns, .. } => {
            render::write_field(&mut out, "gap_ns", gap_ns);
        }
        Verdict::NotSayable => {}
    }
    render::write_field(&mut out, "stands", reading.stands());
    render::write_field(&mut out, "chain", reading.link.word());
    render::write_field(
        &mut out,
        "chain_signed_first",
        reading
            .link
            .signed_first()
            .map_or("none", |which| word_for(which)),
    );
    render::write_field(
        &mut out,
        "chain_rests_on_a_hash",
        reading.link.rests_on_a_hash(),
    );
    if let Link::SameAgentApart { apart, .. } = reading.link {
        render::write_field(&mut out, "chain_apart", apart);
    }

    for (which, assessment) in [("first", &checked[0]), ("second", &checked[1])] {
        render::write_field(&mut out, &format!("{which}_held"), assessment.accepted());
        render::write_field(
            &mut out,
            &format!("{which}_sha256"),
            render::hex(&assessment.link),
        );
        if let Some(receipt) = &assessment.receipt {
            render::write_field(&mut out, &format!("{which}_sequence"), receipt.sequence);
            render::write_field(
                &mut out,
                &format!("{which}_earliest_ns"),
                receipt.claim.earliest.as_nanos(),
            );
            render::write_field(
                &mut out,
                &format!("{which}_latest_ns"),
                receipt.claim.latest.as_nanos(),
            );
            render::write_field(
                &mut out,
                &format!("{which}_width_ns"),
                receipt.claim.latest.as_nanos() - receipt.claim.earliest.as_nanos(),
            );
            render::write_field(
                &mut out,
                &format!("{which}_key"),
                render::hex(&receipt.agent_public_key),
            );
        }
    }
    out
}

/// The word for one of the two, the same in a field and in a sentence.
const fn word_for(which: Which) -> &'static str {
    match which {
        Which::First => "first",
        Which::Second => "second",
    }
}

/// How wide the words are set.
const WIDTH: usize = 92;

/// A paragraph, wrapped, with every line under the same indent.
///
/// The report is read in a terminal by somebody deciding whether to rely on an order, so a
/// paragraph that runs off the right of the window and a paragraph that is never read are close to
/// the same thing.
fn paragraph(indent: &str, text: &str) -> String {
    let mut out = String::new();
    for line in render::wrap(text, WIDTH - indent.len()) {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn describe(reading: &PairReading, checked: &[Assessment], paths: [&String; 2]) -> String {
    let mut out = String::new();
    out.push_str(&paragraph("", &chain_said(reading.link)));
    out.push('\n');

    for (label, path, assessment) in [
        ("The first receipt.", paths[0], &checked[0]),
        ("The second receipt.", paths[1], &checked[1]),
    ] {
        out.push_str(&format!("{label}\n\n"));
        out.push_str(&describe_one(path, assessment));
        out.push('\n');
    }

    out.push_str("Which moment came first.\n\n");
    if reading.link == Link::OneReceiptTwice {
        // One receipt has one moment. The two intervals are the same interval, so the arithmetic
        // gives undecided, and the words for undecided are about two moments that exist.
        out.push_str(&paragraph(
            "  ",
            "Neither. This is one receipt given twice, so there is one moment and nothing to \
             put before or after it.",
        ));
    } else {
        out.push_str(&format!("  {}\n\n", reading.verdict));
        out.push_str(what_the_verdict_means(reading.verdict));
    }

    if reading.link.is_a_fault() {
        out.push('\n');
        out.push_str(&paragraph(
            "  ",
            "And the chain these two sit in is broken, as the opening says. Both intervals are \
             claims of an agent whose own record does not hold together, so whatever they say \
             about each other there is no order here to rely on.",
        ));
    }

    if !(reading.first_held && reading.second_held) {
        out.push('\n');
        out.push_str(&paragraph(
            "  ",
            "And this rests on a receipt this reader refused. Whatever the two intervals say \
             about each other, one of them is a claim that did not hold, so there is no order \
             here to rely on. The refusal is above, beside the receipt it belongs to.",
        ));
    }

    out.push_str("\nWhat this does not establish.\n\n");
    out.push_str(&paragraph(
        "  ",
        "Each interval is its own agent's claim about its own clock, and neither is evidence \
         about the other. Nothing here narrows either of them, and an order that follows from two \
         claims is exactly as good as those two claims. What backs each of them is the evidence \
         inside each receipt: run `timewitness verify` on each one to see which of it was checked \
         and against whose key.",
    ));
    out
}

/// What the two receipts are to each other, before any clock is looked at.
///
/// It opens the report rather than closing it, because it is the sentence that says whether the
/// reader is holding a chain at all, and every answer below it is read differently depending on
/// the answer to that.
fn chain_said(link: Link) -> String {
    match link {
        Link::OneReceiptTwice => {
            "These two files are one receipt. There is one moment here rather \
                                  than two, so there is no order to establish."
                .to_string()
        }
        Link::Names { earlier } => format!(
            "These two receipts are one chain, and the {} was signed first. The other names it by \
             the sha256 of the bytes it was signed as, so those bytes existed at the moment that \
             link was signed. That is an argument about which receipt was made first. It says \
             nothing about UTC, and the question below is a different one.",
            word_for(earlier)
        ),
        Link::NamesAgainstItsOwnSequence { earlier } => format!(
            "These two receipts are one chain and the agent has contradicted itself inside it. The \
             {} is named by the other as the receipt before it, which is a hash and cannot be \
             faked, and the two sequence numbers say the opposite. The hash is what is believed \
             here, and the disagreement is a fault in whatever produced the pair.",
            word_for(earlier)
        ),
        Link::SameAgentApart { earlier, apart } => format!(
            "These two receipts carry one agent key and sit {apart} apart in its chain, with the \
             receipts between them not here. Neither names the other, so the links cannot be \
             walked: what says the {} was made first is the agent's own signed word about where \
             each sits in its chain, rather than a hash.",
            word_for(earlier)
        ),
        Link::TwoAtOneSequence => "These two receipts carry one agent key and the same sequence \
                                   number, and they are not the same receipt. The chain has \
                                   forked. That says nothing about which came first and a great \
                                   deal about the agent: a sequence number exists so that exactly \
                                   this is visible."
            .to_string(),
        Link::TwoAgents => "These two receipts were signed by two different keys, so they are not \
                            two receipts of one chain. There is no link to read, and the two \
                            intervals are the whole of what there is to go on."
            .to_string(),
        Link::Unreadable => "One of these two could not be read as a receipt, so there is nothing \
                             to relate them by."
            .to_string(),
    }
}

/// One receipt's own facts, and whether it held.
fn describe_one(path: &str, assessment: &Assessment) -> String {
    let mut out = format!("  file           {path}\n");
    out.push_str(&format!(
        "  it is          {}\n",
        render::hex(&assessment.link)
    ));
    if let Some(receipt) = &assessment.receipt {
        let width = receipt.claim.latest.as_nanos() - receipt.claim.earliest.as_nanos();
        out.push_str(&format!(
            "  signed by      {}\n",
            render::hex(&receipt.agent_public_key)
        ));
        out.push_str(&format!("  sequence       {}\n", receipt.sequence));
        out.push_str(&format!(
            "  earliest UTC   {} ns\n  latest UTC     {} ns\n  the interval   {width} ns wide\n",
            receipt.claim.earliest.as_nanos(),
            receipt.claim.latest.as_nanos()
        ));
        if let Some(previous) = &receipt.chain_previous {
            out.push_str(&format!("  follows        {}\n", render::hex(previous)));
        } else {
            out.push_str("  follows        nothing: it says it is the first of its chain\n");
        }
    }
    match assessment.refusal() {
        None => out.push_str("  checked        it held, as far as this reader could check\n"),
        Some(step) => out.push_str(&format!(
            "  checked        refused at: {}\n                 {}\n",
            step.question,
            step.state.detail()
        )),
    }
    out
}

/// What the verdict means, with the undecided case given the most words.
///
/// It is the one a reader is most likely to take for the tool having failed, and it is the one this
/// product exists to be willing to say.
const fn what_the_verdict_means(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Established { .. } => {
            "  The two intervals do not touch, so every moment the earlier one could have been is\n  \
             before every moment the later one could have been. That holds whatever either clock\n  \
             was really doing inside the bound its own agent stated. It is a claim about order and\n  \
             not about accuracy.\n"
        }
        Verdict::Undecided { .. } => {
            "  Nobody can say, and that is an answer rather than a failure. One of the two moments\n  \
             did come first; what these two receipts do not do is establish which, because the\n  \
             bound on each reading is wider than the distance between the two readings. Nothing\n  \
             here narrows one bound with the other to reach an answer, and nothing reaches for the\n  \
             two readings and compares those: a midpoint comparison would answer every question of\n  \
             this kind and would be wrong a share of the time nobody could measure afterwards.\n\n  \
             What would change the answer is a narrower bound on either side, which is a better\n  \
             clock or more sources rather than a better comparison.\n"
        }
        Verdict::Contradicted { .. } => {
            "  Both of these are the same agent's signed claims and they cannot both be true. It\n  \
             signed a link saying which of the two receipts it made first, and it signed two\n  \
             intervals that put those two moments the other way round. Either its clock was\n  \
             outside a bound it stated, or the pair was built rather than issued. Which of those\n  \
             it is cannot be told from the two receipts, and this does not guess.\n"
        }
        Verdict::NotSayable => {
            "  One of the two could not be read as a claim about a moment. Nothing follows from\n  \
             the pair, and the receipt above says what was wrong with it.\n"
        }
    }
}

fn refuse(why: &str) -> Outcome {
    Outcome {
        text: format!("{}\n\n{}", render::failure(why), render::usage()),
        code: 2,
    }
}
