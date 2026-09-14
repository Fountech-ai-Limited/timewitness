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

use timewitness_core::keylog::file::KeyLog;
use timewitness_core::keylog::Standing;
use timewitness_core::time::{Nanos, NANOS_PER_MICRO, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::report::Verified;
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
}

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

    /// How many checks were made against material chosen in advance.
    #[must_use]
    pub fn checked_entries(&self) -> usize {
        self.evidence.as_ref().map_or(0, Verified::checked)
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
    let mut steps = Vec::new();
    let link = chain_link(signed_receipt);
    let encoded_bytes = signed_receipt.len();

    let mut assessment = Assessment {
        steps: Vec::new(),
        receipt: None,
        evidence: None,
        link,
        encoded_bytes,
        floor: *floor,
        anchors_held: anchors.count(),
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
    steps.push(against_the_key_log(&receipt, key_log));
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
/// A key the log does not carry, or carries outside the window the reading falls in, **fails**
/// rather than going unchecked. A reader who supplied a log is asking the question, and "the log
/// you gave me does not have this key" is an answer to it.
fn against_the_key_log(receipt: &Receipt, key_log: Option<&KeyLog>) -> Step {
    let question = "is that key one of ours";

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

    let head =
        match log.head_is_signed_by_the_key_it_names() {
            Some(true) => {
                let signed = log.head.as_ref().expect("a checked head is a head");
                format!(
                    "the log states {} entries under a head signed by {}",
                    signed.head.size,
                    short_hex(&signed.signed_by)
                )
            }
            Some(false) => return Step::failed(
                question,
                "the head on this key log is not signed by the key the head itself names, so the \
                 log has been edited or the signature was moved onto it from somewhere else. \
                 Nothing in it is worth reading",
            ),
            None => format!(
                "the log carries {} entries and no signed head, so nobody has put their name to it",
                log.entries.len()
            ),
        };

    match log.standing(&key, receipt.utc_estimate) {
        Standing::Published => Step::held(
            question,
            format!(
                "{head}, and one of them names this key over a window the reading falls in. **This \
                 is a list we signed and not third-party evidence.** It makes a key we published \
                 one we cannot quietly unpublish, to a reader who kept an earlier head; it does not \
                 make us trustworthy to a stranger, and the weight of this receipt still rests on \
                 the third-party signatures in it"
            ),
        ),
        Standing::OutsideItsWindow => Step::failed(
            question,
            format!(
                "{head}, and one of them names this key over a window this reading falls outside. \
                 An agent key is short-lived on purpose, so a receipt signed after the key was \
                 retired is what a stolen key produces"
            ),
        ),
        Standing::NotInTheLog => Step::failed(
            question,
            format!("{head}, and none of them names this key"),
        ),
    }
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
        ReceiptError::Field(_) => "does the receipt carry everything the format requires",
        ReceiptError::MislabelledEvidence { .. } | ReceiptError::OurClaimAsEvidence(_) => {
            "is every claim in the right place"
        }
        ReceiptError::Inconsistent(_) => "do the receipt's own numbers support each other",
    }
    .to_string()
}

/// The first four bytes of something, which is enough for a person comparing two by eye.
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
