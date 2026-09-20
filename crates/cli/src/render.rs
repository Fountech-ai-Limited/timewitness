//! Everything the command line prints, kept in one place.
//!
//! Presentation is separated from the first line, so that when the brand arrives it drops in here
//! and touches no logic. Nothing in this file decides anything and nothing outside it formats
//! anything for a person to read.
//!
//! Two rules bind what goes through here and neither is a matter of taste.
//!
//! Resolution is never written as accuracy. A reading is nanoseconds because it is a local counter
//! read, and a bound is milliseconds because the path it was measured over is not symmetric. They
//! are different quantities. Nothing here prints one in the other's units or lets a reader take the
//! tight number for the true one.
//!
//! Every claim ships beside what the product cannot prove, as a section rather than a footnote. So
//! a verification result is not printed without it.

use std::collections::BTreeMap;

use timewitness_core::SourceKind;
use timewitness_receipt::schema::Receipt;
use timewitness_verify::{
    cannot_prove, width_in_words, Assessment, State, Subject, KEPT_LOG_QUESTION, KEY_LOG_QUESTION,
};

/// The tool's own name, as it appears to a person.
pub const TOOL_NAME: &str = "timewitness";

/// What to say when somebody runs the tool with nothing to do.
#[must_use]
pub fn usage() -> String {
    let mut out = String::new();
    out.push_str("timewitness: proves when something happened, inside a bound, with evidence a\n");
    out.push_str("stranger can check.\n\n");
    out.push_str("  timewitness verify <receipt> [options]\n");
    out.push_str(
        "      Check a receipt. Needs nothing of ours and no account, and works with no\n",
    );
    out.push_str("      network at all.\n\n");
    out.push_str("      --subject <file>    the thing the receipt is supposed to stamp, hashed\n");
    out.push_str("                          here and never sent anywhere\n");
    out.push_str("      --digest <hex>      that hash, where you took it yourself\n");
    out.push_str("      --anchors <file>    your own trust material, instead of the keys that\n");
    out.push_str("                          ship. The format is in docs/verifier.md\n");
    out.push_str("      --no-anchors        trust nothing, and report an attestation as\n");
    out.push_str("                          unchecked rather than checking it. A blob that\n");
    out.push_str("                          is not an attestation at all still fails, since\n");
    out.push_str("                          that needs no key to see\n");
    out.push_str("      --min-width <ns>    the narrowest bound you will accept\n");
    out.push_str("      --fields            the result as one field per line, for a script\n");
    out.push_str("      --json              the same result as JSON\n");
    out.push_str(
        "      --key-log <file>    a key log you were handed, to answer whether the agent's\n",
    );
    out.push_str(
        "                          key is one of ours. It is a list we signed, so it is\n",
    );
    out.push_str(
        "                          not third-party evidence: what it buys is that a key\n",
    );
    out.push_str("                          we published is one we cannot quietly unpublish.\n");
    out.push_str(
        "                          Its head is checked under the key that ships for it,\n",
    );
    out.push_str("                          and a head by any other key answers nothing\n");
    out.push_str(
        "      --kept-log <file>   the copy of that log you kept from before. Holds the new\n",
    );
    out.push_str(
        "                          log to it: every old entry still there, in order, under\n",
    );
    out.push_str("                          a head we signed, or the run says what moved\n");
    out.push_str(
        "      --key-log-signer <hex>\n                          the key you hold for our log's head, instead of the\n",
    );
    out.push_str("                          one that ships. --anchors replaces it too\n");
    out.push_str(
        "      --quiet             the verdict, the line under it and the refusal only\n\n",
    );
    out.push_str("  timewitness stamp --subject <file> --key <file> --out <file> [options]\n");
    out.push_str("      Take a bounded-time receipt over the hash of a file. This one does use\n");
    out.push_str("      the network, because it has to ask the sources what time it is.\n\n");
    out.push_str("      --rounds <n>        how many times to poll the sources, and a longer\n");
    out.push_str("                          wait. Below three the model cannot fit a line, so\n");
    out.push_str("                          the scatter of its own measurements is never\n");
    out.push_str("                          measured: the third round widens the bound, and it\n");
    out.push_str("                          narrows again from there as the rounds pile up.\n");
    out.push_str("                          Measured 2026-09-08 against three public Roughtime\n");
    out.push_str("                          servers, before the operator floor that now refuses\n");
    out.push_str("                          a round of those three alone: 6.2 s at one round,\n");
    out.push_str("                          17.4 s at three, 12.0 s at sixteen, 10.4 s at\n");
    out.push_str("                          thirty-two\n");
    out.push_str("      --max-width <ns>    the widest bound this agent will sign for, 2 s by\n");
    out.push_str(
        "                          default, the narrowest corridor Roughtime states. With\n",
    );
    out.push_str("                          --agent it is the widest this run will accept from\n");
    out.push_str("                          the agent, whatever the agent says its own is\n");
    out.push_str("      --gap <s>           seconds to wait between polling rounds, none by\n");
    out.push_str("                          default and at most 300. A longer cadence is the\n");
    out.push_str("                          agent's, `timewitness agent --interval`\n");
    out.push_str("      --sequence <n>      where this receipt sits in a chain\n");
    out.push_str("      --previous <file>   the receipt before it in that chain\n");
    out.push_str(
        "      --no-evidence       skip the third-party attestations, for a run with no\n",
    );
    out.push_str("                          outbound HTTP\n\n");
    out.push_str(
        "      --agent <file>      ask a resident agent for the reading instead of polling\n",
    );
    out.push_str(
        "                          here. The file is the one `timewitness agent` wrote.\n",
    );
    out.push_str(
        "                          Whoever can write that file chooses what answers, so\n",
    );
    out.push_str(
        "                          this run refuses an answer more than five minutes from\n",
    );
    out.push_str(
        "                          this machine's own clock. That is a sanity check and\n",
    );
    out.push_str(
        "                          not evidence; the third-party corridor is what catches\n",
    );
    out.push_str("                          a careful forgery, and --no-evidence skips it\n\n");
    out.push_str("  timewitness agent --endpoint <file> [options]\n");
    out.push_str("      Discipline this machine's clock continuously and answer readings to\n");
    out.push_str("      `stamp --agent`. It runs in the foreground until it is stopped. It\n");
    out.push_str("      installs no service, starts at no boot, and never sets the clock.\n\n");
    out.push_str("      --endpoint <file>   where to write the address and the token a caller\n");
    out.push_str("                          presents. Readable only by the account this runs as\n");
    out.push_str(
        "      --interval <s>      how long to leave between polling rounds. Thirty-two\n",
    );
    out.push_str("                          seconds by default: longer costs width, because a\n");
    out.push_str("                          reading is extrapolated over the whole gap, and\n");
    out.push_str("                          shorter costs somebody else's public servers\n");
    out.push_str("      --max-width <ns>    the widest bound this agent will answer with\n\n");
    out.push_str("  timewitness roughtime-serve [options]\n");
    out.push_str(
        "      Answer Roughtime requests, off a clock model disciplined the same way the\n",
    );
    out.push_str("      agent's is. A Roughtime radius is a whole number of seconds with zero\n");
    out.push_str("      forbidden, so the corridor this states is two seconds wide however good\n");
    out.push_str("      its clock is: running one narrows nobody's bound. What it buys is a\n");
    out.push_str("      signed corridor that is there when somebody else's server is not.\n\n");
    out.push_str("      --bind <addr>       address and port to read, 0.0.0.0:2002 by default\n");
    out.push_str("      --key <file>        the long-term key, 32 bytes. Without it the key is\n");
    out.push_str("                          read from TIMEWITNESS_ROUGHTIME_KEY as 64 hex\n");
    out.push_str(
        "                          characters. It generates none: a key made at startup\n",
    );
    out.push_str("                          is an identity nobody published\n");
    out.push_str("      --interval <s>      how long to leave between its own polling rounds\n");
    out.push_str("      --max-width <ns>    the widest bound it will answer from. A model that\n");
    out.push_str(
        "                          will not stand behind one gets silence, not a guess\n\n",
    );
    out.push_str("  timewitness key-log --log <file> [options]\n");
    out.push_str("      Write the public log of our keys. Appending is the only edit there is:\n");
    out.push_str("      a log whose old entries change is not a log, and retiring a key is an\n");
    out.push_str("      entry that says so rather than an edit to the one before it.\n\n");
    out.push_str("      --add <hex>         a 32-byte public key to append\n");
    out.push_str("      --role <word>       what the key is: agent, which signs receipts, or\n");
    out.push_str("                          server, a Roughtime server's. Agent by default\n");
    out.push_str("      --label <name>      which deployment that key belongs to. A label a\n");
    out.push_str(
        "                          person chose, and not an identity claim about anybody\n",
    );
    out.push_str("      --from <ns>         when the key started being used. Now by default\n");
    out.push_str("      --until <ns>        when it will stop, where that is known when the\n");
    out.push_str("                          entry is written. Not how a key is retired\n");
    out.push_str("      --retire <hex>      append the entry that retires a key already in the\n");
    out.push_str("                          log, for every moment from --at on. Permanent: a\n");
    out.push_str("                          retired key is never added again\n");
    out.push_str("      --at <ns>           the moment the retirement takes effect. Now by\n");
    out.push_str("                          default\n");
    out.push_str("      --sign <file>       sign the head over what the log now holds\n\n");
    out.push_str("  timewitness countersign <value> [<response>] | --from <file>\n");
    out.push_str("      Read a countersign exchange and say what it establishes. One value is\n");
    out.push_str("      one half of one. Two values are a request and the response to it, and\n");
    out.push_str("      the response has to name that request by the bytes it travelled as.\n");
    out.push_str("      Given both, it also says which moment came first, or that the two\n");
    out.push_str("      claims do not settle it. No network and no account, the same as\n");
    out.push_str("      verify. A verified signature says the party holding that key signed\n");
    out.push_str("      that statement about its own clock, and nothing about whether the\n");
    out.push_str("      clock was right.\n\n");
    out.push_str("      --from <file>       read the header values out of a file rather than\n");
    out.push_str("                          taking them on the command line, one to a line\n");
    out.push_str("      --fields            the pair as lines a script reads, rather than as\n");
    out.push_str("                          words. Both halves and one of established,\n");
    out.push_str("                          undecided or contradicted\n\n");
    out.push_str("  timewitness order <receipt> <receipt> [options]\n");
    out.push_str("      Read two receipts and say which moment came first. Both are checked the\n");
    out.push_str("      way verify checks one, and then the two bounds are compared. No network\n");
    out.push_str("      and no account. Where the two bounds overlap the answer is that nobody\n");
    out.push_str("      can say, which is an answer: it means the two stamps are closer\n");
    out.push_str("      together than the bound on either of them. Where the two receipts are\n");
    out.push_str("      of one chain it also says which was signed first, which is a different\n");
    out.push_str("      statement, resting on a hash rather than on a clock, and it never\n");
    out.push_str("      settles the question the bounds left open.\n\n");
    out.push_str("      --anchors <file>    your own trust material, as verify takes it\n");
    out.push_str("      --no-anchors        trust nothing, and report an attestation as\n");
    out.push_str("                          unchecked rather than checking it\n");
    out.push_str("      --min-width <ns>    the narrowest bound you will accept, applied to\n");
    out.push_str("                          both of them\n");
    out.push_str("      --fields            the reading as one field per line, for a script.\n");
    out.push_str("                          One of established, undecided, contradicted or\n");
    out.push_str("                          not-sayable, and whether it stands\n\n");
    out.push_str("  timewitness cannot-prove\n");
    out.push_str("      What this product cannot prove, in full. It ships with the claim rather\n");
    out.push_str("      than under it.\n\n");
    out.push_str("  timewitness --version\n");
    out.push_str("      Which build this is, and the receipt format it reads.\n\n");
    out.push_str("  timewitness --help\n");
    out.push_str("      This, which is also what the tool prints with nothing after it.\n");
    out
}

/// What `timewitness --version` prints: the build, and the one receipt format it reads.
///
/// Cargo writes the version from the manifest, which is in the tree the verify-path check reads, so
/// nothing of the building machine's own environment comes in through it.
#[must_use]
pub fn version() -> String {
    format!(
        "timewitness {}\nreads receipt format v{}",
        env!("CARGO_PKG_VERSION"),
        timewitness_receipt::FORMAT_VERSION
    )
}

/// The whole of what a verifier found, as a person reads it.
///
/// The order is deliberate. The verdict is first because that is what somebody came for. The steps
/// are next, each saying whether it held, failed or could not be run, because a check nobody could
/// run is not a check that passed. The evidence comes after that with its three roles kept apart.
/// The bound and the reading come last of the numbers, each in the unit that fits it. Then what the
/// product cannot prove, which is part of the result and not an appendix to it.
#[must_use]
pub fn assessment(a: &Assessment, subject: Subject<'_>, quiet: bool) -> String {
    let mut out = String::new();

    out.push_str(&a.verdict());
    out.push('\n');
    // Directly under the verdict, and under `--quiet` too, because this is the line that stops the
    // one above being read as outside parties vouching for the width. One line, unwrapped like the
    // verdict, so a script taking the first two lines takes both whole.
    if let Some(bracket) = a.bracket() {
        out.push_str(&bracket);
        out.push('\n');
    }
    if let Some(step) = a.refusal() {
        out.push_str(&format!("  {}\n  {}\n", step.question, step.state.detail()));
    }

    if quiet {
        return out;
    }

    out.push_str("\nWhat was checked\n");
    for step in &a.steps {
        out.push_str(&format!("  [{}] {}\n", step.state.mark(), step.question));
        for wrapped in wrap(step.state.detail(), 88) {
            out.push_str(&format!("        {wrapped}\n"));
        }
    }

    if let Some(receipt) = &a.receipt {
        out.push_str("\nWhat it claims\n");
        out.push_str(&format!(
            "  The reading is {} ns since the Unix epoch, at nanosecond resolution because it is a\n",
            receipt.utc_estimate.as_nanos()
        ));
        out.push_str(
            "  local counter read. Through the resident agent no network call is in the read; \
             through the\n  one-shot command the polling that produced it is part of the same few \
             seconds.\n",
        );
        out.push_str(&format!(
            "  UTC was somewhere in an interval {} wide, from {} ns to {} ns. That width is the\n",
            width_in_words(receipt.width()),
            receipt.claim.earliest.as_nanos(),
            receipt.claim.latest.as_nanos()
        ));
        out.push_str("  claim. The reading is a point inside it and is not the answer.\n");
        out.push_str(&format!(
            "  {} sources answered and {} survived selection, combined by {}.\n",
            receipt.claim.sources_offered, receipt.claim.sources_kept, receipt.claim.fusion
        ));
        // The count the majority actually rests on, printed beside the count of names and never
        // instead of it. Several addresses at one company are several sources and one chance to be
        // wrong, so a reader given only the first number is given the flattering one. The counting
        // is done here from the labels the receipt carries rather than read out of a field, which
        // is the point of carrying labels: a reader can do the same arithmetic and get a different
        // answer if ours is wrong.
        out.push_str(&operators_line(receipt));
        // What each kind in the round can and cannot be shown to a stranger for. The three evidence
        // roles are not interchangeable, and until this line a reader of a receipt had the kinds in
        // the source list and no statement anywhere of what any of them proves. Leaving that to be
        // inferred is how a source that improves the clock gets read as evidence for the bound.
        out.push_str(&kinds_line(receipt));
        // Said as the age of the exchange rather than as the age of a synchronisation, because
        // those were the same sentence until 2026-09-08 and were not the same fact: a selection
        // round takes whatever is already in the window.
        match receipt.claim.policy.max_holdover {
            Some(ceiling) => out.push_str(&format!(
                "  The newest exchange behind this interval was {} old at the reading, and the \
                 agent\n  that issued it will not extrapolate past {}.\n",
                width_in_words(receipt.claim.since_last_sync),
                width_in_words(ceiling)
            )),
            None => out.push_str(&format!(
                "  The newest exchange behind this interval was {} old at the reading. This \
                 receipt states\n  no limit on how long its agent would extrapolate, so there is \
                 nothing to hold it to.\n",
                width_in_words(receipt.claim.since_last_sync)
            )),
        }

        out.push_str("\nWhere the width comes from, part by part\n");
        let b = &receipt.claim.breakdown;
        for (name, value) in [
            ("the sources overlapping, halved", b.intersection_half),
            ("the local read", b.scheduling),
            ("the oscillator since the last sync", b.oscillator_holdover),
            ("the model's own residual", b.model_residual),
            ("a fixed safety margin", b.safety_margin),
        ] {
            out.push_str(&format!("  {:>12}  {name}\n", width_in_words(value)));
        }
        out.push_str(&format!(
            "  {:>12}  the widest source round trip, halved. Reported, and already inside the\n",
            width_in_words(b.network_half)
        ));
        out.push_str("                first line rather than added to it\n");
    }

    if let Some(evidence) = &a.evidence {
        out.push_str("\nThe evidence, one role at a time\n");
        out.push_str(
            "  Three roles and none of them does another's job. A corridor puts a signed interval\n\
             \x20 round the moment that a stranger can check, and does not tighten the bound. A\n\
             \x20 beacon says not earlier. A witness says not later. The agent's own bound is a\n\
             \x20 claim and is not on this list.\n",
        );
        for reported in evidence.lines() {
            out.push_str(&format!("  {reported}\n"));
        }
        out.push_str(&format!(
            "  This reader was holding {} pieces of trust material and checked {} of {} entries.\n",
            a.anchors_held,
            evidence.checked(),
            evidence.entries.len()
        ));
    }

    out.push_str("\nWhat this reader judged it against\n");
    for rule in a.floor.lines() {
        out.push_str(&format!("  {rule}\n"));
    }
    out.push_str(&format!(
        "  The receipt as handed over is {} bytes and hashes to {}.\n",
        a.encoded_bytes,
        hex(&a.link)
    ));
    if matches!(subject, Subject::NotSupplied) {
        out.push_str("  No subject was supplied, so this bounds a moment and not a moment for\n");
        out.push_str("  anything in particular.\n");
    }

    out.push_str("\nWhat TimeWitness cannot prove\n");
    out.push_str(
        "  This is a section of the result rather than a note under it, and every item on\n",
    );
    out.push_str("  it is a thing somebody might reasonably expect and will not get.\n");
    for reported in cannot_prove::lines() {
        out.push_str(&format!("{reported}\n"));
    }
    out.push_str("\n  The whole list, with the reasoning: timewitness cannot-prove\n");

    out
}

/// One `name=value` line of the fields report, with the value held to one line.
///
/// Every value in that report goes through here, and that is the point of it. The report is a
/// format, one field per line, and `scripts/action-stamp.sh` reads it with `sed` and puts what it
/// finds into a workflow's outputs. A value carrying a newline is two lines, and the second one was
/// written by whoever wrote the receipt. On 2026-09-19 a signed receipt whose first source had
/// `kind` set to a string carrying two newlines put `earliest_ns=1` and a width of its own choosing
/// into this report, above the report's real ones.
///
/// `validate` refuses such a receipt outright now, and that is the fix. This is here as well, and
/// it is not the same job. The refusal is a rule about what a receipt may carry, held in one place
/// for every surface. This is the format keeping its own promise: a report written a line at a time
/// stays a line at a time whatever is handed to it, rather than every value having to remember.
///
/// **Measured, so that it is not read as more than it is.** On the tree of 2026-09-19 nothing
/// reaches here that the refusal has not already stopped. A receipt whose strings carry a control
/// character is refused in `open_with`, and a refused receipt is not attached to the assessment, so
/// the only values left are this reader's own words and its own numbers. What this stops is the
/// next value somebody adds.
///
/// A control character is replaced rather than dropped, with U+FFFD, the character whose job is to
/// say that a character could not be represented. Dropping would quietly turn one value into
/// another that reads as sound; replacing leaves something on the line that is obviously neither a
/// number nor a word, and keeps every field on the line it belongs to.
pub(crate) fn write_field(out: &mut String, name: &str, value: impl core::fmt::Display) {
    let written = value.to_string();
    let held: String = written
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    out.push_str(&format!("{name}={held}\n"));
}

/// The result as `name=value` lines, for a shell.
///
/// A workflow step wants five numbers and a verdict, and reaching them through a JSON tool would put
/// a dependency in the way of the one thing this Action promises to be, which is one line to install.
/// Every value here is a whole number or a single word, so nothing needs quoting and nothing has to
/// be parsed twice.
#[must_use]
pub fn fields(a: &Assessment) -> String {
    let mut out = String::new();
    write_field(&mut out, "accepted", a.accepted());
    if let Some(step) = a.refusal() {
        write_field(&mut out, "refused_at", &step.question);
        write_field(&mut out, "refusal", step.state.detail());
    }
    write_field(&mut out, "receipt_bytes", a.encoded_bytes);
    write_field(&mut out, "receipt_sha256", hex(&a.link));
    write_field(&mut out, "anchors_held", a.anchors_held);
    // The key log, where one was supplied, as the two facts a script wants before it reads the
    // words: whether the head was checked under a key this reader holds for us, and by which key.
    // `scripts/key-log.sh` refuses to serve a log on anything less than `checked`.
    if let Some(log) = &a.key_log {
        write_field(&mut out, "key_log_entries", log.entries);
        write_field(&mut out, "key_log_agent_entries", log.agent_entries);
        write_field(&mut out, "key_log_head", log.head.word());
        write_field(
            &mut out,
            "key_log_head_signed_by",
            log.head
                .signed_by()
                .map_or_else(|| "none".to_string(), |key| hex(&key)),
        );
        for (name, question) in [
            ("key_log_step", KEY_LOG_QUESTION),
            ("kept_log", KEPT_LOG_QUESTION),
        ] {
            if let Some(step) = a.step(question) {
                write_field(
                    &mut out,
                    name,
                    match step.state {
                        State::Held(_) => "held",
                        State::Failed(_) => "failed",
                        State::NotChecked(_) => "not-checked",
                    },
                );
            }
        }
    }
    if let Some(receipt) = &a.receipt {
        write_field(&mut out, "earliest_ns", receipt.claim.earliest.as_nanos());
        write_field(&mut out, "latest_ns", receipt.claim.latest.as_nanos());
        write_field(&mut out, "width_ns", receipt.width());
        write_field(&mut out, "reading_ns", receipt.utc_estimate.as_nanos());
        write_field(&mut out, "width_in_words", width_in_words(receipt.width()));
        write_field(&mut out, "sequence", receipt.sequence);
        write_field(&mut out, "payload_algorithm", &receipt.payload.algorithm);
        write_field(&mut out, "payload_hash", hex(&receipt.payload.hash));
        write_field(&mut out, "sources_offered", receipt.claim.sources_offered);
        write_field(&mut out, "sources_kept", receipt.claim.sources_kept);
        // The two counts a script needs to tell nine names at one company from nine at nine, and
        // the kinds behind them. Without these a caller reading this output has only the flattering
        // number, which is how several addresses at one company pass for several independent
        // parties.
        let operators = receipt.claim.operators();
        write_field(&mut out, "operators_offered", operators.offered);
        write_field(&mut out, "operators_kept", operators.kept);
        let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
        for source in &receipt.claim.sources {
            *kinds.entry(source.kind.as_str()).or_default() += 1;
        }
        write_field(
            &mut out,
            "source_kinds",
            kinds
                .iter()
                .map(|(kind, count)| format!("{kind}:{count}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(evidence) = &a.evidence {
        // The span the checked outside evidence brackets the moment to, or `none` where nothing
        // checked bounds it on both sides. A whole number or one word, like everything here.
        write_field(
            &mut out,
            "outside_bracket_ns",
            evidence
                .bracket()
                .width()
                .map_or_else(|| "none".to_string(), |span| span.to_string()),
        );
        write_field(&mut out, "attestations_carried", evidence.entries.len());
        write_field(&mut out, "attestations_checked", evidence.checked());
        write_field(&mut out, "basis_granted", evidence.basis_granted);
    }
    out
}

/// The cannot-prove list in full, which is the document itself.
#[must_use]
pub fn cannot_prove_document() -> String {
    cannot_prove::DOCUMENT.to_string()
}

/// What a stamp produced, for the person watching a build.
#[must_use]
pub fn stamped(
    path: &str,
    bytes: usize,
    width: i128,
    sources: (u32, u32),
    evidence: usize,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("Receipt written to {path}, {bytes} bytes.\n"));
    out.push_str(&format!(
        "UTC was somewhere in an interval {} wide. That is the claim; it is not an accuracy.\n",
        width_in_words(width)
    ));
    out.push_str(&format!(
        "{} sources answered, {} survived selection, and {} third-party attestations are carried.\n",
        sources.0, sources.1, evidence
    ));
    out
}

/// How many distinct operators stood behind a receipt, in a line a person reads.
///
/// Silent on a receipt that names no operator for any of its sources, which is a receipt written
/// before the field existed. Saying "0 operators" about one of those would report the format's age
/// as a fault in the round.
///
/// A source the receipt leaves unnamed is counted with every other unnamed source as one party
/// between them rather than one each. That is the merging direction and it can only lower the
/// number; `timewitness_core::Operator` carries why the doubt is resolved that way.
fn operators_line(receipt: &Receipt) -> String {
    if receipt.claim.names_no_operator() {
        return String::new();
    }
    // The same counting the validator and the reader's own floor use, rather than a third copy of
    // it here. A number printed beside a verdict that was reached with a different number is worse
    // than no number, and this line was that third copy until 2026-09-10.
    let operators = receipt.claim.operators();

    let mut line = format!(
        "  Those sources are run by {} operators and {} of them had a source kept. Several\n  \
         addresses at one operator are one chance to be wrong rather than several, so this is\n  \
         the count the majority rests on",
        operators.offered, operators.kept
    );
    // A party that is the issuer itself is left out of both counts above, so it has to be named
    // here or the line reads as though those sources were never there. They were: they disciplined
    // the clock and their intervals are in the arithmetic. What they are not is a chance to be
    // wrong separately from the agent that issued this.
    if operators.first_party > 0 {
        line.push_str(&format!(
            ".
  A further {} of the parties behind these sources is the one that issued this
  receipt, so it is left out of both counts above rather than trusted twice",
            operators.first_party
        ));
    }
    match receipt.claim.policy.min_operators {
        Some(floor) => {
            line.push_str(&format!(
                ", and this agent will not sign on fewer than {floor}.\n"
            ));
        }
        None => line.push_str(", and this agent states no floor on it.\n"),
    }
    line
}

/// What kinds of source stood behind a bound, and what each kind can be shown to a stranger for.
///
/// The rule that our own word is never third-party evidence, said in the one place a reader of a
/// receipt actually looks. The three evidence roles are not interchangeable and only one of them is
/// carried by anything on this list: a Roughtime server signs over a nonce the agent generated, so
/// its response is portable, and plain NTP and NTS are not, NTS because its keys are symmetric and
/// this machine could compose any reply it can then check. Nothing here says a receipt carries that
/// evidence. Whether it does is the evidence section below, and the two are kept apart on purpose:
/// a source that could sign and a signature in the file are different facts, and reading the first
/// as the second is the central dishonesty available to a product in this field.
///
/// A kind this code has never heard of is counted and reported as one whose worth this reader
/// cannot judge, rather than being folded into the ones it knows. Reading an unknown kind as plain
/// NTP would be a guess that happens to be conservative today and stops being conservative the
/// moment the format gains a kind that signs.
fn kinds_line(receipt: &Receipt) -> String {
    if receipt.claim.sources.is_empty() {
        return String::new();
    }
    let mut counted: BTreeMap<&str, usize> = BTreeMap::new();
    for source in &receipt.claim.sources {
        *counted.entry(source.kind.as_str()).or_default() += 1;
    }

    let each: Vec<String> = counted
        .iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect();
    let mut line = format!(
        "  {} of source answered: {}. ",
        if counted.len() == 1 {
            "One kind".to_string()
        } else {
            format!("{} kinds", counted.len())
        },
        each.join(", ")
    );

    let signing: Vec<&str> = counted
        .keys()
        .filter(|k| SourceKind::from_wire(k).is_some_and(SourceKind::carries_third_party_signature))
        .copied()
        .collect();
    let unknown: Vec<&str> = counted
        .keys()
        .filter(|k| SourceKind::from_wire(k).is_none())
        .copied()
        .collect();

    if signing.is_empty() {
        line.push_str(
            "None of them signs\n  anything a stranger can check, so every one of them improves \
             this machine's clock and\n  proves nothing to anybody who was not here.\n",
        );
    } else {
        line.push_str(&format!(
            "Only {} signs anything a\n  stranger can check. The rest improve this machine's clock \
             and prove nothing to\n  anybody who was not here, and a signature that could be shown \
             is not the same as one\n  carried here, which is the evidence section below.\n",
            signing.join(" and ")
        ));
    }
    if !unknown.is_empty() {
        line.push_str(&format!(
            "  This reader does not know {}, so it is counted and judged as proving\n  nothing.\n",
            unknown.join(" or ")
        ));
    }
    line
}

/// What an agent is about to run as, for the line it prints when it starts.
///
/// One value rather than six arguments, because six of anything in a row is six chances to pass them
/// in the wrong order and the compiler would not notice: they are two counts, a floor, an interval
/// and two nanosecond figures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentStart {
    /// How many source clients it will poll.
    pub sources: usize,
    /// How many distinct operators those sources reach.
    pub operators: usize,
    /// The fewest operators it will sign on.
    pub min_operators: usize,
    /// How long it leaves between polling rounds, in seconds.
    pub interval_seconds: u64,
    /// How finely this machine's counter was measured to tick, in nanoseconds.
    pub granularity: i128,
    /// The widest interval it will answer with, in nanoseconds.
    pub max_bound_width: i128,
}

/// What a resident agent says once, at the moment it starts.
///
/// Every number here is a setting rather than a measurement. The line about the clock is the one
/// that matters: an agent quietly fighting whatever else disciplines this machine would be doing the
/// thing the measure-and-vouch default exists to avoid, so it says out loud that it is not.
#[must_use]
pub fn agent_started(endpoint_path: &str, address: &str, at: AgentStart) -> String {
    let AgentStart {
        sources,
        operators,
        min_operators,
        interval_seconds,
        granularity,
        max_bound_width,
    } = at;
    let mut out = String::new();
    out.push_str(&format!(
        "Agent running. Listening on {address}, and {endpoint_path} carries the address and the\n"
    ));
    out.push_str("token a caller presents. Stop it with Ctrl-C.\n");
    out.push_str(&format!(
        "{sources} sources, polled every {interval_seconds} s. The system clock is measured and\n"
    ));
    out.push_str("left alone, so nothing here fights whatever else disciplines this machine.\n");
    // The count a majority rests on, said at the moment somebody chooses what to point this at.
    // A person adding servers to a configuration is the person most able to add an operator instead,
    // and the first they would otherwise hear of the difference is a refusal.
    out.push_str(&format!(
        "Those sources are run by {operators} operators, and this agent will not sign on fewer\n"
    ));
    out.push_str(&format!(
        "than {min_operators}. Several addresses at one operator are one chance to be wrong.\n"
    ));
    out.push_str(&format!(
        "This machine's counter was measured to tick every {granularity} ns, and the widest\n"
    ));
    out.push_str(&format!(
        "interval this agent will answer with is {}.\n",
        width_in_words(max_bound_width)
    ));
    out.push_str(
        "Nothing is stamped here. It hands over readings and a caller builds the receipt.\n",
    );
    out
}

/// What a Roughtime server of ours is about to run as, for the line it prints when it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoughtimeStart<'a> {
    /// The address it reads its socket on.
    pub bind: &'a str,
    /// The long-term public key, which is the whole of what a client has to be told.
    pub public_key: &'a [u8; 32],
    /// How many source clients discipline the model it answers from.
    pub sources: usize,
    /// How long it leaves between polling rounds, in seconds.
    pub interval_seconds: u64,
    /// The widest bound it will answer from, in nanoseconds.
    pub max_bound_width: i128,
    /// How long each delegation to an online key runs for, in seconds.
    pub delegation_seconds: u64,
    /// The first second the current delegation covers.
    pub delegation_from: u64,
    /// The last one.
    pub delegation_to: u64,
}

/// What a Roughtime server of ours says once, at the moment it starts.
///
/// The key is first and in full, because it is the only thing somebody pointing a client at this
/// server actually needs and a truncated one is no use to them. The sentence about the radius is
/// here rather than in a document because this is where somebody standing a server up reads it, and
/// it is the reading the whole exercise invites: two of these do not make anybody's bound narrower,
/// and they are one party whatever the count of addresses says.
#[must_use]
pub fn roughtime_serving(at: RoughtimeStart<'_>) -> String {
    let RoughtimeStart {
        bind,
        public_key,
        sources,
        interval_seconds,
        max_bound_width,
        delegation_seconds,
        delegation_from,
        delegation_to,
    } = at;
    let mut out = String::new();
    out.push_str(&format!(
        "Roughtime server running. Reading {bind}, over UDP. Stop it with Ctrl-C.\n"
    ));
    out.push_str(&format!(
        "Its long-term public key, which is what a client is told:\n  {}\n",
        hex(public_key)
    ));
    out.push_str(&format!(
        "It signs with an online key it delegates to for {} h at a time, and the current \
         delegation\n",
        delegation_seconds / 3600
    ));
    out.push_str(&format!(
        "runs from {delegation_from} to {delegation_to} in seconds since the Unix epoch.\n"
    ));
    out.push_str(&format!(
        "Its own clock is disciplined against {sources} sources every {interval_seconds} s, and it \
         answers\n"
    ));
    out.push_str(
        "from that model rather than from this machine's clock. A round where the model will not \
         stand\n",
    );
    out.push_str(&format!(
        "behind a bound, or one wider than {}, gets silence rather than a guess.\n",
        width_in_words(max_bound_width)
    ));
    out.push_str(
        "A Roughtime radius is a whole number of seconds and zero is forbidden, so the corridor \
         this\n",
    );
    out.push_str(
        "states is two seconds wide however good its clock is. Running it narrows nobody's bound.\n",
    );
    out
}

/// What a key log holds, after something was added to it.
///
/// The root is printed because it is the one thing a reader can compare against a head they were
/// given elsewhere, and the sentence about what the log proves is printed every time rather than
/// once in a document, because this is where somebody publishing one is looking.
#[must_use]
pub fn key_log_written(path: &str, entries: usize, added: usize, root: Option<[u8; 32]>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{path} holds {entries} entries, {added} of them added just now.\n"
    ));
    match root {
        Some(root) => {
            out.push_str(&format!("Signed head over root {}.\n", hex(&root)));
            out.push_str(
                "A signed head makes this a log we cannot quietly rewrite for anybody who kept an \
                 earlier\none. It is not third-party evidence and it never becomes any: we sign \
                 it, so a reader\nseeing it for the first time is trusting us about our own keys.\n",
            );
        }
        None => out.push_str(
            "No head, so nobody has put their name to what this holds. Sign one with --sign.\n",
        ),
    }
    out
}

/// Something went wrong, said in a way somebody can act on.
#[must_use]
pub fn failure(what: &str) -> String {
    format!("{TOOL_NAME}: {what}")
}

/// Lower case hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Break a long line at spaces, so a terminal does not do it in the middle of a number.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use timewitness_receipt::schema::SourceRecord;

    /// A source record with the two fields these tests turn on and nothing else set apart.
    fn source(id: &str, operator: &str, kind: &str, kept: bool) -> SourceRecord {
        SourceRecord {
            id: id.to_string(),
            operator: Some(operator.to_string()),
            kind: kind.to_string(),
            timescale: "utc".to_string(),
            smear: "none".to_string(),
            leap: "none".to_string(),
            kept,
            first_party: false,
        }
    }

    /// The claim a rendering test needs, which is the source list and nothing else.
    fn claim_over(sources: Vec<SourceRecord>) -> timewitness_receipt::schema::AgentClaim {
        timewitness_receipt::schema::AgentClaim {
            earliest: timewitness_core::UnixNanos(0),
            latest: timewitness_core::UnixNanos(1),
            basis: timewitness_core::EpsilonBasis::LocalModelOnly,
            fusion: "marzullo-then-inverse-square".to_string(),
            sources_offered: sources.len() as u32,
            sources_kept: sources.iter().filter(|s| s.kept).count() as u32,
            breakdown: timewitness_receipt::schema::BreakdownRecord {
                intersection_half: 0,
                network_half: 0,
                scheduling: 0,
                oscillator_holdover: 0,
                model_residual: 0,
                safety_margin: 0,
            },
            since_last_sync: 0,
            frequency_ppb: 0,
            boot_generation: 0,
            resume_generation: 0,
            sources,
            policy: timewitness_receipt::schema::PolicyRecord {
                max_bound_width: 1,
                min_sources: 1,
                min_operators: None,
                max_holdover: None,
            },
        }
    }

    #[test]
    fn the_kinds_line_says_which_kind_could_ever_be_shown_to_a_stranger() {
        // The nine this product polls: three protocols, six parties, and only one protocol whose
        // answer carries a signature somebody who was not here can check. A reader given the source
        // count alone cannot see any of that, and whether a receipt carries third-party evidence
        // turns on this distinction.
        let mut sources = Vec::new();
        for (kind, names) in [
            ("roughtime", ["a", "b", "c"]),
            ("ntp", ["a", "d", "e"]),
            ("nts", ["a", "f", "e"]),
        ] {
            for name in names {
                sources.push(source(&format!("{kind}-{name}"), name, kind, true));
            }
        }
        let line = kinds_line(&Receipt {
            claim: claim_over(sources),
            ..blank_receipt()
        });
        assert!(line.contains("3 kinds of source answered"));
        assert!(line.contains("3 ntp"));
        assert!(line.contains("3 nts"));
        assert!(line.contains("3 roughtime"));
        assert!(line.contains("Only roughtime signs"));
        // And it never lets a source that could sign be read as a signature in the file.
        assert!(line.contains("is not the same as one"));
    }

    #[test]
    fn a_round_where_nothing_could_sign_says_so_rather_than_saying_nothing() {
        let line = kinds_line(&Receipt {
            claim: claim_over(vec![
                source("one", "a", "ntp", true),
                source("two", "b", "nts", true),
            ]),
            ..blank_receipt()
        });
        assert!(line.contains("2 kinds of source answered"));
        assert!(line.contains("None of them signs"));
    }

    #[test]
    fn a_kind_this_reader_has_never_heard_of_is_judged_as_proving_nothing() {
        // The direction that stays honest when the format gains a kind that does sign. Reading it
        // as plain NTP would be a guess that happens to be conservative today.
        let line = kinds_line(&Receipt {
            claim: claim_over(vec![
                source("one", "a", "roughtime", true),
                source("two", "b", "pulse-per-second-over-carrier-pigeon", true),
            ]),
            ..blank_receipt()
        });
        assert!(line.contains("does not know pulse-per-second-over-carrier-pigeon"));
        assert!(line.contains("proving"));
    }

    #[test]
    fn the_operator_line_counts_what_the_validator_counts() {
        // Nine names at two companies. The line a person reads has to carry the two, because the
        // nine is the flattering number and it is the one already on the line above.
        let mut sources = Vec::new();
        for i in 0..9 {
            let party = if i < 5 { "one.example" } else { "two.example" };
            sources.push(source(&format!("name-{i}"), party, "ntp", true));
        }
        let receipt = Receipt {
            claim: claim_over(sources),
            ..blank_receipt()
        };
        let line = operators_line(&receipt);
        assert!(line.contains("run by 2 operators"));
        assert_eq!(receipt.claim.operators().kept, 2);
    }

    /// A receipt with everything but the claim at a resting value, for the two rendering tests
    /// above. Nothing here is read by either of them.
    fn blank_receipt() -> Receipt {
        Receipt {
            version: timewitness_receipt::schema::FORMAT_VERSION,
            utc_estimate: timewitness_core::UnixNanos(0),
            monotonic: 0,
            payload: timewitness_receipt::schema::Payload {
                algorithm: "sha-256".to_string(),
                hash: vec![0; 32],
            },
            claim: claim_over(Vec::new()),
            evidence: Vec::new(),
            sequence: 0,
            chain_previous: None,
            agent_public_key: vec![0; 32],
        }
    }

    #[test]
    fn a_long_line_breaks_at_spaces_and_loses_nothing() {
        let text = "the signature does not match the receipt, so either the receipt was altered \
                    after it was signed or it was signed by a different key";
        let lines = wrap(text, 40);
        assert!(lines.len() > 2);
        assert!(lines.iter().all(|l| l.len() <= 40));
        assert_eq!(
            lines.join(" "),
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        );
    }

    #[test]
    fn the_usage_names_every_option_the_tool_accepts() {
        // Now that an option the tool does not have is refused by name, this text is the list a
        // reader works from. An accepted option missing from it is a flag nobody can find.
        let text = usage();
        for (command, options, _) in crate::args::ACCEPTED {
            assert!(text.contains(command), "the usage does not name {command}");
            for option in *options {
                assert!(
                    text.contains(option),
                    "{command} accepts {option} and the usage does not say so"
                );
            }
        }
    }

    #[test]
    fn the_usage_names_both_things_the_tool_does() {
        let text = usage();
        assert!(text.contains("timewitness verify"));
        assert!(text.contains("timewitness stamp"));
        assert!(text.contains("no account"));
    }
}
