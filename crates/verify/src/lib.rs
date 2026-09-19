//! The verifier.
//!
//! It is a separate crate from the first commit because it ships as a thing that runs with none of
//! our infrastructure and no account. A verifier only we can run is not evidence, it is a request to
//! be trusted, and this product's whole argument is that a stranger who trusts neither party can
//! check a receipt for themselves.
//!
//! What that means in code, and each of these is a rule rather than a preference:
//!
//! - **No network, anywhere in this crate or anything it imports.** There is no socket to reach us
//!   with and no key to fetch. Every signature a receipt rests on is carried inside the receipt, and
//!   the keys those signatures are checked against are published by third parties and either
//!   compiled in or supplied by the reader.
//! - **Nothing is uploaded to check it.** The thing being stamped is hashed where it sits. A
//!   verifier that sent a confidential file somewhere to have its digest taken would leak the file
//!   to prove something about its timestamp.
//! - **The verifier holds its own floor.** Checking a receipt only against the numbers it carries is
//!   checking a document against its own opinion of itself. See [`floor`].
//! - **The answer is never one word.** Three evidence roles do three different jobs, and a report
//!   that collapses them into a badge has hidden the only thing a careful reader wants. Every entry
//!   comes back with its label intact and with whether anybody checked it.
//! - **What the product cannot prove is part of the output.** See [`cannot_prove`].
//!
//! The checking of the signatures themselves is not here. It is in `timewitness-core`, because the
//! agent runs the same check the moment a response lands and a stranger runs it years later on the
//! same bytes, and the two are on opposite sides of the module boundary.

#![forbid(unsafe_code)]

pub mod anchor_file;
pub mod cannot_prove;
pub mod floor;

use timewitness_core::keylog::file::{HeadCheck, KeyLog};
use timewitness_core::keylog::{check_consistency, consistency_proof, KeyEntry, Standing};
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::report::Verified;
use timewitness_receipt::schema::Role;
use timewitness_receipt::{chain_link, open_with, sha256_payload, Receipt, ReceiptError};

pub use floor::Floor;

/// What the reader supplied as the thing the receipt is supposed to be about.
#[derive(Clone, Copy, Debug)]
pub enum Subject<'a> {
    /// Nothing. The receipt is checked for everything except what it is a receipt for.
    ///
    /// A legitimate state and a common one: a receipt is often read by somebody who has the receipt
    /// and not the artefact. It is reported as unchecked rather than passed over, because a receipt
    /// nobody has tied to a subject proves a time and not a time for anything in particular.
    NotSupplied,
    /// The bytes themselves, hashed here.
    Bytes(&'a [u8]),
    /// A digest the reader took somewhere else, for an artefact too large to hold in memory.
    Digest(&'a [u8]),
}

/// How one step of the verification came out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// It was checked and it held.
    Held(String),
    /// It was checked and it did not.
    Failed(String),
    /// It was not checked, and this says why.
    ///
    /// Never a pass. A reader has to be able to tell a check that ran from one that could not, and a
    /// verifier that reports the two the same way is the failure this whole type exists to stop.
    NotChecked(String),
}

impl State {
    /// Whether this step refuses the receipt.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        matches!(self, State::Failed(_))
    }

    /// The words, whichever state it is.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            State::Held(d) | State::Failed(d) | State::NotChecked(d) => d,
        }
    }

    /// A four character mark for the front of a line.
    #[must_use]
    pub const fn mark(&self) -> &'static str {
        match self {
            State::Held(_) => "held",
            State::Failed(_) => "FAIL",
            State::NotChecked(_) => "----",
        }
    }
}

/// One thing the verifier looked at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// What was being asked.
    pub question: String,
    /// What came back.
    pub state: State,
}

impl Step {
    fn held(question: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            question: question.into(),
            state: State::Held(detail.into()),
        }
    }

    fn failed(question: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            question: question.into(),
            state: State::Failed(detail.into()),
        }
    }

    fn not_checked(question: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            question: question.into(),
            state: State::NotChecked(detail.into()),
        }
    }
}

/// Everything one reader established about one receipt.
#[derive(Clone, Debug)]
pub struct Assessment {
    /// Every step, in the order it ran.
    pub steps: Vec<Step>,
    /// The receipt, where it could be read at all.
    pub receipt: Option<Receipt>,
    /// What was established about the evidence entries, where the receipt could be read.
    pub evidence: Option<Verified>,
    /// The SHA-256 of the bytes exactly as they were handed over.
    ///
    /// This is what a chain link is taken over today, so it is printed: two readers comparing what
    /// they hold are comparing this. A holder can restate a receipt as different bytes carrying the
    /// same claim, which changes this value and changes nothing else, and that question is not
    /// settled.
    pub link: Vec<u8>,
    /// How large the receipt was.
    pub encoded_bytes: usize,
    /// The numbers this reader judged it against.
    pub floor: Floor,
    /// How many anchors the reader was holding.
    pub anchors_held: usize,
    /// What was established about the key log, where the reader supplied one.
    pub key_log: Option<KeyLogReport>,
}

/// What a reader established about the key log they supplied, for a script reading fields.
///
/// The step itself carries the words. This carries the two facts a script wants without parsing
/// them: whether the head was checked under a key the reader holds for us, and by which key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogReport {
    /// How many entries the log carries.
    pub entries: usize,
    /// How many of them say an agent key was ours.
    pub agent_entries: usize,
    /// What was established about the head.
    pub head: HeadCheck,
}

/// The question the key log step answers.
pub const KEY_LOG_QUESTION: &str = "is that key one of ours";

/// The question the kept log step answers.
pub const KEPT_LOG_QUESTION: &str = "is this log an extension of the one you kept";

impl Assessment {
    /// Whether every check that ran held.
    ///
    /// A step nobody could run does not make this false, and it does not make it true either: a
    /// reader has to look at the steps. That is the whole reason the answer is not a boolean in the
    /// first place, and this exists for an exit code rather than for a verdict.
    #[must_use]
    pub fn accepted(&self) -> bool {
        !self.steps.iter().any(|s| s.state.is_failure())
    }

    /// The step that refused it, where one did.
    #[must_use]
    pub fn refusal(&self) -> Option<&Step> {
        self.steps.iter().find(|s| s.state.is_failure())
    }

    /// The one line a reader stops at, and it carries how many attestations were checked.
    ///
    /// Until 2026-09-15 this read "This receipt holds up as far as it was checked." for a receipt
    /// with three attestations checked and, word for word, for one with none: a forger who renamed
    /// every signer got the same sentence a genuine receipt gets, and a reader who stops at the
    /// first line, which is most readers, could not tell the two apart. Not-checked is never a
    /// pass, and this is where that rule has to hold, because it is the line every route prints.
    ///
    /// The count is on the line rather than under it, so the page and the command line say the
    /// same thing and a reader has the number before the sentence they would otherwise take for a
    /// pass. A refusal is one word and the step that refused it follows.
    #[must_use]
    pub fn verdict(&self) -> String {
        if !self.accepted() {
            return "REFUSED.".to_string();
        }
        let Some(evidence) = &self.evidence else {
            return "This receipt holds up as far as it was checked.".to_string();
        };
        let carried = evidence.entries.len();
        let checked = evidence.checked();
        let unchecked = carried - checked;
        match (carried, unchecked) {
            (0, _) => "This receipt holds up as far as it was checked, and it carries no \
                       third-party attestation."
                .to_string(),
            (_, 0) => format!(
                "This receipt holds up as far as it was checked, and all {carried} of its \
                 attestations were checked."
            ),
            (_, n) if n == carried => format!(
                "This receipt holds up as far as it was checked, and none of its {carried} \
                 attestations was checked."
            ),
            (_, 1) => format!(
                "This receipt holds up as far as it was checked, and 1 of its {carried} \
                 attestations was not checked."
            ),
            (_, n) => format!(
                "This receipt holds up as far as it was checked, and {n} of its {carried} \
                 attestations were not checked."
            ),
        }
    }

    /// The line under the verdict: how wide the checked outside evidence brackets the moment, and
    /// whose the width is.
    ///
    /// Added 2026-09-15. The verdict line counts the attestations that were checked, and a reader
    /// who stops there takes the width beside it for something the attestations vouched for. They
    /// vouch for less. On the receipt committed in this repository they bracket the moment to 2 s
    /// round a width of 153.875 ms, and a receipt backdated three years on genuine evidence passed
    /// every check with the same first line and a bracket of 2.95 years that nothing printed. So the
    /// bracket goes directly under the verdict on every route that prints one, and on a receipt
    /// resting on its own model the width is named as the signer's claim in the same breath.
    ///
    /// None where the receipt was refused, because a refusal's second line is the step that
    /// refused it.
    #[must_use]
    pub fn bracket(&self) -> Option<String> {
        if !self.accepted() {
            return None;
        }
        let (Some(receipt), Some(evidence)) = (&self.receipt, &self.evidence) else {
            return None;
        };
        let width = width_in_words(receipt.width());
        let bracket = evidence.bracket();

        if evidence.basis_granted {
            return Some(match bracket.width() {
                Some(span) => format!(
                    "Its {width} width rests on outside signatures, and the checked ones bracket \
                     the moment to {}.",
                    span_in_words(span)
                ),
                None => format!("Its {width} width rests on outside signatures."),
            });
        }

        let ours = format!("The {width} width is the signer's own claim.");
        let corridors: Vec<bool> = evidence
            .entries
            .iter()
            .filter(|e| e.role == Role::AuthenticatedUtcCorridor)
            .map(|e| e.outcome.is_checked())
            .collect();
        let corridor = if corridors.is_empty() {
            " It carries no Roughtime corridor."
        } else if !corridors.iter().any(|checked| *checked) {
            " Its Roughtime corridor was not checked."
        } else {
            ""
        };

        let first = if evidence.entries.is_empty() {
            "It carries no outside signature, so nothing outside brackets the moment.".to_string()
        } else {
            match (bracket.not_earlier, bracket.not_later, bracket.width()) {
                (_, _, Some(span)) if span < 0 => format!(
                    "The checked outside signatures contradict each other: the latest \
                     not-earlier-than is {} after the earliest not-later-than, so they bracket \
                     nothing.",
                    span_in_words(-span)
                ),
                (_, _, Some(span)) => format!(
                    "The checked outside signatures bracket the moment to {}.",
                    span_in_words(span)
                ),
                (Some(_), None, None) => "Only a not-earlier-than signature was checked, so \
                                          nothing outside bounds the moment from above."
                    .to_string(),
                (None, Some(_), None) => "Only a not-later-than signature was checked, so \
                                          nothing outside bounds the moment from below."
                    .to_string(),
                _ => "No outside signature that bounds the moment was checked, so nothing \
                      outside brackets it."
                    .to_string(),
            }
        };
        Some(format!("{first} {ours}{corridor}"))
    }

    /// How many checks were made against material chosen in advance.
    #[must_use]
    pub fn checked_entries(&self) -> usize {
        self.evidence.as_ref().map_or(0, Verified::checked)
    }

    /// The step that asked a question, where it was asked.
    #[must_use]
    pub fn step(&self, question: &str) -> Option<&Step> {
        self.steps.iter().find(|s| s.question == question)
    }
}

/// Check a receipt, with nothing but the bytes, the reader's own anchors and the reader's own floor.
///
/// This never returns an error. A receipt that cannot be read is an assessment whose first step
/// failed, because the reader wants to know what was wrong with it and at which point, and a bare
/// error type would throw that away.
#[must_use]
pub fn verify(
    signed_receipt: &[u8],
    subject: Subject<'_>,
    anchors: &TrustAnchors,
    floor: &Floor,
) -> Assessment {
    verify_with_key_log(signed_receipt, subject, anchors, floor, None)
}

/// The same, with a key log the reader was handed.
///
/// Separate from [`verify`] rather than a fifth argument on it because the ordinary case is a reader
/// who has a receipt and nothing else, and that reader should not have to pass a `None` to say so.
/// The key log is the one input to this crate that most readers will never have.
#[must_use]
pub fn verify_with_key_log(
    signed_receipt: &[u8],
    subject: Subject<'_>,
    anchors: &TrustAnchors,
    floor: &Floor,
    key_log: Option<&KeyLog>,
) -> Assessment {
    assess(signed_receipt, subject, anchors, floor, key_log, None)
}

/// The same, with the log the reader was handed and the copy of it they kept from before.
///
/// This is the check the log exists for. A log we alone sign proves nothing to a reader seeing it
/// for the first time; what it proves, to a reader who kept an earlier head, is that nothing they
/// held has been removed, changed or reordered since. That reader passes both, and the step
/// [`KEPT_LOG_QUESTION`] says whether the new log extends the old one under a head we signed.
#[must_use]
pub fn verify_with_kept_log(
    signed_receipt: &[u8],
    subject: Subject<'_>,
    anchors: &TrustAnchors,
    floor: &Floor,
    key_log: &KeyLog,
    kept: &KeyLog,
) -> Assessment {
    assess(
        signed_receipt,
        subject,
        anchors,
        floor,
        Some(key_log),
        Some(kept),
    )
}

fn assess(
    signed_receipt: &[u8],
    subject: Subject<'_>,
    anchors: &TrustAnchors,
    floor: &Floor,
    key_log: Option<&KeyLog>,
    kept: Option<&KeyLog>,
) -> Assessment {
    let mut steps = Vec::new();
    let link = chain_link(signed_receipt);
    let encoded_bytes = signed_receipt.len();
    let held = anchors.key_log_signer_keys();

    let mut assessment = Assessment {
        steps: Vec::new(),
        receipt: None,
        evidence: None,
        link,
        encoded_bytes,
        floor: *floor,
        anchors_held: anchors.count(),
        key_log: key_log.map(|log| KeyLogReport {
            entries: log.entries.len(),
            agent_entries: log.agent_entries(),
            head: log.check_head(&held),
        }),
    };

    // Size first, because everything after it allocates from what the file says about itself.
    steps.push(if encoded_bytes > floor.max_encoded_bytes {
        Step::failed(
            "is this a receipt or an unbounded file",
            format!(
                "{encoded_bytes} bytes, and this verifier reads no more than {}",
                floor.max_encoded_bytes
            ),
        )
    } else {
        Step::held(
            "is this a receipt or an unbounded file",
            format!("{encoded_bytes} bytes"),
        )
    });
    if steps[0].state.is_failure() {
        assessment.steps = steps;
        return assessment;
    }

    // One call, so there is no window in which a caller could act on a receipt whose signature has
    // not been looked at.
    let (receipt, evidence) = match open_with(signed_receipt, anchors) {
        Ok(pair) => pair,
        Err(e) => {
            steps.push(Step::failed(question_for(&e), e.to_string()));
            assessment.steps = steps;
            return assessment;
        }
    };

    steps.push(Step::held(
        "was this signed by the key it names, over exactly these bytes",
        format!(
            "an Ed25519 signature by {}, over the protected header and the payload together",
            short_hex(&receipt.agent_public_key)
        ),
    ));
    steps.push(against_the_key_log(&receipt, key_log, &held));
    if let (Some(log), Some(kept)) = (key_log, kept) {
        steps.push(against_the_kept_log(log, kept, &held));
    }
    steps.push(Step::held(
        "do the receipt's own numbers support each other",
        "the reading falls inside the interval, the parts of the width add to the width, a majority \
         of the sources that answered were kept, and the agent kept to the policy it states",
    ));

    steps.push(check_floor(&receipt, floor));
    steps.push(check_subject(&receipt, subject));
    steps.push(check_order(&receipt));

    assessment.steps = steps;
    assessment.receipt = Some(receipt);
    assessment.evidence = Some(evidence);
    assessment
}

/// `is that key one of ours`, answered off a key log where the reader has one.
///
/// # Why the answer is never better than "a list we signed says so"
///
/// This step asks whether the key that signed the receipt is one of ours. A log of ours can say yes
/// and cannot make the yes worth more than we are worth: we sign the log, so a reader seeing it for
/// the first time is trusting us about our own keys. What the log does buy is that a key we
/// published is one we cannot quietly unpublish, because anybody who kept an earlier head can prove
/// the log was rewritten. That is worth having and it is not third-party evidence, so the detail
/// says which it is. Our own word is never third-party evidence: the weight of a receipt rests on
/// the third-party signatures in it.
///
/// # Whose list it is
///
/// "A list we signed" is only true of a list we signed. The head is checked under a key the reader
/// holds for us, and a head by any other key answers nothing: the step is not checked and the
/// detail says whose it was not. Until 2026-09-15 the head was checked against the key it named
/// itself, so a log anybody made a minute ago read as ours, exit 0.
///
/// # What refuses and what does not
///
/// A key the log names as an agent key outside its window, a key the log has retired, and a key
/// missing from a log that does name agent keys all **fail** rather than going unchecked: a reader
/// who supplied a log is asking the question, and "the log you gave me does not have this key" is
/// an answer to it. A log with no agent entry has nothing to say about the key that signed a
/// receipt and says so, because the log we serve first holds our two server keys and nothing else,
/// and a verifier that refused our own receipts against our own log would be wrong in the way that
/// matters most.
fn against_the_key_log(receipt: &Receipt, key_log: Option<&KeyLog>, held: &[[u8; 32]]) -> Step {
    let question = KEY_LOG_QUESTION;

    let Some(log) = key_log else {
        return Step::not_checked(
            question,
            "nothing here can say. The receipt proves the agent that signed it held that key, and \
             no key log was supplied to check it against. A reader who knows the key can compare it \
             themselves; a reader who does not learns that one key signed this and says so",
        );
    };

    let Ok(key) = <[u8; 32]>::try_from(receipt.agent_public_key.as_slice()) else {
        return Step::failed(
            question,
            format!(
                "the receipt names a {}-byte agent key, and a key log carries 32-byte Ed25519 keys",
                receipt.agent_public_key.len()
            ),
        );
    };

    let head = match log.check_head(held) {
        HeadCheck::Checked(signer) => format!(
            "the log states {} entries under a head signed by {}, a key this reader holds for us",
            log.entries.len(),
            short_hex(&signer)
        ),
        HeadCheck::BadSignature => {
            return Step::failed(
                question,
                "the head on this key log is not signed by the key the head itself names, so the \
                 log has been edited or the signature was moved onto it from somewhere else. \
                 Nothing in it is worth reading",
            )
        }
        HeadCheck::SignerNotHeld(signer) => {
            return Step::not_checked(
                question,
                format!(
                    "the log carries {} entries under a head signed by {}, and that is not a key \
                     this reader holds for us{}. Whatever the list says, it is not us saying it, so \
                     it answers nothing about this key",
                    log.entries.len(),
                    short_hex(&signer),
                    if held.is_empty() {
                        " (this reader holds none)"
                    } else {
                        ""
                    }
                ),
            )
        }
        HeadCheck::None => {
            return Step::not_checked(
                question,
                format!(
                    "the log carries {} entries and no signed head, so it is signed by nobody. A \
                     list nobody has put their name to answers nothing about whose keys these are",
                    log.entries.len()
                ),
            )
        }
    };

    // Judged on the receipt's own reading, which whoever holds the key wrote. A window checked
    // against that catches a receipt that says it was signed outside the window; it does not catch
    // one that lies about when, and the words below say so rather than implying a stolen key is
    // caught here. Judging the window on outside evidence is later work.
    let judged = "This window is judged on the receipt's own reading, which whoever holds the key \
                  wrote, so it catches a receipt that says it was signed outside the window and \
                  not one that lies about when";

    match log.standing(&key, receipt.utc_estimate) {
        Standing::Published => Step::held(
            question,
            format!(
                "{head}, and one of them names this key as an agent key over a window the reading \
                 falls in. **This is a list we signed and not third-party evidence.** It makes a \
                 key we published one we cannot quietly unpublish, to a reader who kept an earlier \
                 head; it does not make us trustworthy to a stranger, and the weight of this receipt \
                 still rests on the third-party signatures in it. {judged}"
            ),
        ),
        Standing::Retired(at) => Step::failed(
            question,
            format!(
                "{head}, and one of them retired this key at {} ns, before this reading. A retired \
                 key is retired for every later moment whatever window an earlier entry names. \
                 {judged}",
                at.as_nanos()
            ),
        ),
        Standing::OutsideItsWindow => Step::failed(
            question,
            format!(
                "{head}, and the entries naming this key as an agent key all name a window this \
                 reading falls outside. {judged}"
            ),
        ),
        Standing::AServerKey => Step::failed(
            question,
            format!(
                "{head}, and the only entries naming this key say it is a server key. A server key \
                 signs no receipt, so a receipt signed by one was not signed by an agent of ours"
            ),
        ),
        Standing::NotInTheLog if log.agent_entries() == 0 => Step::not_checked(
            question,
            format!(
                "{head}, and no agent entry: every entry is a server key or a retirement, so the \
                 log has nothing to say about the key that signed this receipt. It is not a \
                 refusal. The receipt proves the agent that signed it held that key, and this log \
                 says which server keys are ours, not which agent keys"
            ),
        ),
        Standing::NotInTheLog => Step::failed(
            question,
            format!(
                "{head}, {} of them agent keys, and none of them names this key",
                log.agent_entries()
            ),
        ),
    }
}

/// `is this log an extension of the one you kept`, for a reader holding an earlier copy.
///
/// The only thing a log we alone sign proves, and it proves it only to this reader: nothing they
/// held has been removed, changed or reordered. Three checks, in order, and each stops the run of
/// them. Both heads have to be ours, because an old copy signed by nobody, or by somebody else,
/// pins nothing. The old entries have to be the first entries of the new log, compared as entries
/// rather than as hashes so the reader is told which one moved. And the consistency proof between
/// the two heads has to hold, run through the same RFC 6962 algorithm a reader with somebody
/// else's tooling would run, so that a proof this accepts is one they can rebuild.
fn against_the_kept_log(log: &KeyLog, kept: &KeyLog, held: &[[u8; 32]]) -> Step {
    let question = KEPT_LOG_QUESTION;

    let kept_check = kept.check_head(held);
    if kept_check == HeadCheck::BadSignature {
        return Step::failed(
            question,
            "the head on the log you kept is not signed by the key it names, so what you kept was \
             edited after it was signed and pins nothing",
        );
    }
    if let HeadCheck::SignerNotHeld(signer) = kept_check {
        return Step::not_checked(
            question,
            format!(
                "the log you kept is signed by {}, which is not a key this reader holds for us, so \
                 it pins nothing of ours and there is nothing to hold the new log to",
                short_hex(&signer)
            ),
        );
    }
    if kept_check == HeadCheck::None {
        return Step::not_checked(
            question,
            "the log you kept carries no head, so nobody signed what it held and there is nothing \
             to hold the new log to",
        );
    }
    let kept_head = kept.head.as_ref().expect("a checked head is a head");

    if !matches!(log.check_head(held), HeadCheck::Checked(_)) {
        return Step::not_checked(
            question,
            "the new log's head is not one this reader holds for us, which the step above says in \
             full, so there is nothing to hold to the log you kept",
        );
    }
    let new_head = log.head.as_ref().expect("a checked head is a head");

    if kept.entries.len() > log.entries.len() {
        return Step::failed(
            question,
            format!(
                "you kept {} entries and this log carries {}. A log that got shorter is a log that \
                 removed something you were told",
                kept.entries.len(),
                log.entries.len()
            ),
        );
    }
    for (index, (old, new)) in kept.entries.iter().zip(&log.entries).enumerate() {
        if old != new {
            return Step::failed(
                question,
                format!(
                    "entry {index} of the log you kept is not entry {index} of this one: {}. A \
                     log whose old entries change is not a log, and this is the change",
                    describe_difference(old, new)
                ),
            );
        }
    }

    let leaves: Vec<[u8; 32]> = log.entries.iter().map(KeyEntry::leaf_hash).collect();
    let proof = consistency_proof(&leaves, kept.entries.len());
    if let Err(e) = check_consistency(&kept_head.head, &new_head.head, &proof) {
        return Step::failed(
            question,
            format!(
                "the entries match as a prefix and the consistency proof between the two heads \
                 does not hold: {e}. One of the two heads does not describe its own entries"
            ),
        );
    }

    Step::held(
        question,
        format!(
            "the {} entries you kept are the first {} of these {}, the head you kept is over \
             exactly them, and the consistency proof between the two heads holds. Nothing you \
             were told has been removed, changed or reordered. That is the whole of what a log \
             we sign can prove, and it proves it to you and not to a stranger",
            kept.entries.len(),
            kept.entries.len(),
            log.entries.len()
        ),
    )
}

/// Which field moved between two entries at the same index, for a reader told their copy differs.
fn describe_difference(old: &KeyEntry, new: &KeyEntry) -> String {
    if old.public_key != new.public_key {
        return format!(
            "the key was {} and is now {}",
            short_hex(&old.public_key),
            short_hex(&new.public_key)
        );
    }
    if old.role != new.role {
        return format!(
            "the role was {} and is now {}",
            old.role.word(),
            new.role.word()
        );
    }
    if old.valid_from != new.valid_from {
        return format!(
            "the window opened at {} ns and now opens at {} ns",
            old.valid_from.as_nanos(),
            new.valid_from.as_nanos()
        );
    }
    if old.valid_until != new.valid_until {
        return "the window's end moved".to_string();
    }
    format!(
        "the name was {:?} and is now {:?}",
        old.deployment, new.deployment
    )
}

/// The verifier's own floor, applied to the numbers rather than to what the receipt says about them.
fn check_floor(receipt: &Receipt, floor: &Floor) -> Step {
    let question = "does the bound clear this reader's own floor";
    let width = receipt.width();

    if width < floor.min_interval_width {
        return Step::failed(
            question,
            format!(
                "the interval is {width} ns wide and this verifier will not accept one narrower \
                 than {} ns. A receipt keeping to its own stated policy still has to clear a floor \
                 the reader set",
                floor.min_interval_width
            ),
        );
    }
    if width > floor.max_interval_width {
        return Step::failed(
            question,
            format!(
                "the interval is {width} ns wide and this verifier will not accept one wider than \
                 {} ns, past which an interval says nothing a calendar would not",
                floor.max_interval_width
            ),
        );
    }
    // Counted over the sources that could have disagreed with somebody rather than over everything
    // that answered, and the counting is `AgentClaim::candidates`, shared with the receipt crate's
    // own tests so the two cannot drift. The floor's own reason is a majority, and a source that
    // told the agent its clock was wrong cannot be in one: it was read out of `sources_offered`
    // until that field was corrected to mean how many answered, which would have let four sources
    // saying nothing usable carry a receipt over a floor set at three.
    let candidates = receipt.claim.candidates() as u32;
    if candidates < floor.min_candidate_sources {
        return Step::failed(
            question,
            format!(
                "{candidates} sources answered with a clock they stood behind and this verifier \
                 will not accept fewer than {}. With three, a majority beats one bad clock; with \
                 fewer there is no majority to take",
                floor.min_candidate_sources
            ),
        );
    }

    // Counted from the labels rather than read out of the receipt, because a stated count would be
    // the agent's arithmetic and the reader would be checking it against itself. The counting is
    // `AgentClaim::operators`, shared with the receipt crate's own test so the two cannot drift.
    let operators = receipt.claim.operators();
    if (operators.kept as u32) < floor.min_operators_kept {
        let seen = if receipt.claim.names_no_operator() {
            "this receipt names no operator for any of its sources, so nothing in it shows that \
             the sources failing would be separate events"
                .to_string()
        } else if operators.first_party > 0 {
            // The case this sentence exists for is a receipt that would have cleared the floor on
            // its issuer's own servers. Saying only that the count fell short would send a reader
            // looking for a source that failed, when what happened is that a source was never
            // independent in the first place.
            format!(
                "the sources that were kept are run by {} distinct operators independent of the \
                 party that issued this receipt, and a further {} of the parties behind it are \
                 that party itself",
                operators.kept, operators.first_party
            )
        } else {
            format!(
                "the sources that were kept are run by {} distinct operators",
                operators.kept
            )
        };
        return Step::failed(
            question,
            format!(
                "{seen}, and this verifier will not accept fewer than {}. Several addresses at one \
                 operator are one chance to be wrong rather than several, so a count of sources is \
                 not the count a majority rests on",
                floor.min_operators_kept
            ),
        );
    }

    // What a reader can do with the width, rather than how it compares to a floor they did not
    // choose. The old line here said the width was some number of times the narrowest this verifier
    // accepts, which is true and tells nobody anything: the floor is a backstop set two orders of
    // magnitude below anything this product claims, so every honest receipt is a huge multiple of
    // it. The two facts worth having are what the interval is good for and what its issuer signed
    // for, and the second is inside the signature so a reader can check it.
    // Named rather than silently excluded. A reader comparing the source count with the operator
    // count and finding a gap has to be able to tell a company answering twice from the issuer
    // answering itself, and only one of those two is a party the reader is trusting twice.
    let own = if operators.first_party == 1 {
        ", one of them the issuer's own and not counted among them".to_string()
    } else if operators.first_party > 1 {
        format!(
            ", {} of them the issuer's own and not counted among them",
            operators.first_party
        )
    } else {
        String::new()
    };

    Step::held(
        question,
        format!(
            "{} wide, on {} sources run by {} operators{own}. Two moments further apart than that \
             can be put in order by receipts of this width and two closer together cannot, and the \
             agent that issued it signed for nothing wider than {}",
            human_width(width),
            // The sources that were kept, because the operator count beside it is over the same
            // set. Printing what answered next to the operators behind what was kept invites the
            // two to be read as one figure, and since that field was corrected the first of them
            // can include sources that told the agent their own clocks were wrong.
            receipt.claim.sources_kept,
            operators.kept,
            human_width(receipt.claim.policy.max_bound_width)
        ),
    )
}

/// A width in units a person holds, with the nanoseconds kept beside it.
///
/// Every interval in this product is nanoseconds on the wire, because that is the resolution of the
/// reading and rounding it away in the format would be throwing away the one quantity that is
/// exact. A person reading a verdict cannot hold eleven digits, so the verdict carries both.
pub(crate) fn human_width(nanos: Nanos) -> String {
    let (value, unit) = if nanos >= NANOS_PER_SEC {
        (nanos as f64 / NANOS_PER_SEC as f64, "s")
    } else if nanos >= NANOS_PER_MILLI {
        (nanos as f64 / NANOS_PER_MILLI as f64, "ms")
    } else if nanos >= NANOS_PER_MICRO {
        (nanos as f64 / NANOS_PER_MICRO as f64, "us")
    } else {
        return format!("{nanos} ns");
    };
    format!("{value:.3} {unit} ({nanos} ns)")
}

/// Whether the thing the reader has is the thing the receipt is about.
fn check_subject(receipt: &Receipt, subject: Subject<'_>) -> Step {
    let question = "is the thing you have the thing this receipt stamps";
    let expected = &receipt.payload.hash;

    let (supplied, how): (Vec<u8>, &str) = match subject {
        Subject::NotSupplied => {
            return Step::not_checked(
                question,
                format!(
                    "you supplied nothing to compare. This receipt stamps something whose {} is {}, \
                     and a receipt nobody has tied to a subject bounds a moment rather than a \
                     moment for anything in particular",
                    receipt.payload.algorithm,
                    short_hex(expected)
                ),
            );
        }
        Subject::Bytes(bytes) => {
            if receipt.payload.algorithm != "sha-256" {
                return Step::not_checked(
                    question,
                    format!(
                        "the receipt names {}, and this verifier hashes with sha-256. Take the \
                         digest yourself and supply it",
                        receipt.payload.algorithm
                    ),
                );
            }
            (sha256_payload(bytes).hash, "hashed here, on this machine")
        }
        Subject::Digest(digest) => (digest.to_vec(), "a digest you took yourself"),
    };

    if supplied == *expected {
        Step::held(
            question,
            format!(
                "{}, {how}, and nothing was sent anywhere to establish it",
                short_hex(expected)
            ),
        )
    } else {
        Step::failed(
            question,
            format!(
                "the receipt stamps {} and what you supplied is {}. This is a real receipt for a \
                 different thing",
                short_hex(expected),
                short_hex(&supplied)
            ),
        )
    }
}

/// What the chain fields say, and what nothing here checks about them.
fn check_order(receipt: &Receipt) -> Step {
    let question = "does this receipt sit where it says in a chain";
    match &receipt.chain_previous {
        None => Step::not_checked(
            question,
            format!(
                "it is number {} and names no previous receipt, so there is nothing to place it \
                 against",
                receipt.sequence
            ),
        ),
        Some(prev) => Step::not_checked(
            question,
            format!(
                "it is number {} and names {} as the one before it. Nothing here checks that: \
                 placing two receipts in order needs both of them, and this verifier was given one",
                receipt.sequence,
                short_hex(prev)
            ),
        ),
    }
}

/// Which question a refusal from the receipt crate was the answer to.
///
/// The reader is told where in the reading it went wrong, not only what the message said.
fn question_for(e: &ReceiptError) -> String {
    match e {
        ReceiptError::Encoding(_) => "are these bytes one receipt",
        ReceiptError::Signature(_) => {
            "was this signed by the key it names, over exactly these bytes"
        }
        ReceiptError::UnknownVersion(_) => "is this a version this verifier reads",
        ReceiptError::Field(_) => {
            "does the receipt carry every field the format needs, in a shape it can read"
        }
        ReceiptError::MislabelledEvidence { .. } | ReceiptError::OurClaimAsEvidence(_) => {
            "is every claim in the right place"
        }
        ReceiptError::Inconsistent(_) => "do the receipt's own numbers support each other",
    }
    .to_string()
}

/// The first eight bytes of something, which is enough for a person comparing two by eye.
fn short_hex(bytes: &[u8]) -> String {
    let shown: String = bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("");
    if bytes.len() > 8 {
        format!("{shown}... ({} bytes)", bytes.len())
    } else {
        shown
    }
}

/// How far apart two outside signatures are, in words a person holds.
///
/// Whole seconds where the span is whole seconds, which is what a beacon's schedule and a token's
/// stated second give, and the figure a reader can check against the evidence lines below it. Past a
/// day the seconds stay and a rougher unit follows, because 93175915 s means nothing to anybody and
/// "about 2.95 years" is the whole point of printing it.
#[must_use]
pub fn span_in_words(ns: Nanos) -> String {
    if ns < NANOS_PER_SEC {
        return width_in_words(ns);
    }
    let seconds = if ns % NANOS_PER_SEC == 0 {
        format!("{} s", ns / NANOS_PER_SEC)
    } else {
        format!("{:.3} s", ns as f64 / NANOS_PER_SEC as f64)
    };
    let secs = ns as f64 / NANOS_PER_SEC as f64;
    let rough = if secs >= 365.25 * 86_400.0 {
        format!(", about {:.2} years", secs / (365.25 * 86_400.0))
    } else if secs >= 86_400.0 {
        format!(", about {:.1} days", secs / 86_400.0)
    } else if secs >= 3_600.0 {
        format!(", about {:.1} hours", secs / 3_600.0)
    } else if secs >= 120.0 {
        format!(", about {:.1} minutes", secs / 60.0)
    } else {
        String::new()
    };
    format!("{seconds}{rough}")
}

/// Nanoseconds rendered as a figure a person can read, in the unit that fits the size of it.
///
/// A bound is milliseconds and a reading is nanoseconds, and printing both in the same unit is how
/// the two get confused. This never rounds a width down.
#[must_use]
pub fn width_in_words(ns: Nanos) -> String {
    let abs = ns.abs();
    if abs >= 1_000_000_000 {
        format!("{:.3} s", ns as f64 / 1e9)
    } else if abs >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1e6)
    } else if abs >= 1_000 {
        format!("{:.3} us", ns as f64 / 1e3)
    } else {
        format!("{ns} ns")
    }
}
