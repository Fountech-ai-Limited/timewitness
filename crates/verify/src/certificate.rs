//! Whether a receipt is a TimeWitness certificate: its key certified by the app, at a moment placed
//! by outside evidence alone.
//!
//! # What this grades, and on what
//!
//! Every check the verifier already made still runs and still prints. This adds one verdict above
//! them, and it is judged on two instants a reader verified against keys they chose in advance: the
//! latest beacon round inside the receipt's signature, which the signing cannot have come before,
//! and the earliest witness after it. The receipt's reading, its interval and our agent's bound are
//! never used, because whoever holds a key writes those, and a grade that read them would certify a
//! backdated receipt for anybody holding the public code.
//!
//! The later instant is the witness over the receipt's own signature where the receipt carries one,
//! because that is the only witness that places the signing. Where it carries none, the witness
//! over the subject stands in, and the verifier says it places only the subject: a key used after its
//! window can sign over a subject whose evidence was gathered inside it, and nothing here can tell.
//!
//! A timestamp authority that states no accuracy puts no edge in UTC round its token, and none of
//! the ones that ship states one. For this grade the instant the token states is used, on that
//! authority's own clock, and the verifier names the clock. The question here is which side of a
//! date the signing fell, not how wide a bound is, and a certificate window is a day or a week.
//!
//! # The cutoff
//!
//! Certification began at one instant, C. It is trust material the reader holds, published beside
//! the key log signer and replaceable the same way, and it is stated in the log by a cutoff entry
//! whose first head carries a beacon round at or after C and a timestamp token over the head. A log
//! stating a different C is refused, and so is a log certifying a window that starts before C.
//!
//! A receipt carrying a verified witness over its own signature dated before C was signed before
//! certification began. It is graded as version 0 grades it, and the verifier says nothing about
//! whose key signed it. A witness over the subject never counts for this, because it dates the
//! subject and the signer chose the subject; a beacon never counts either, because an old round is
//! available to anybody at any time, and a checked beacon at or after C refuses it outright. So a
//! receipt with no witness over its signature, which is every version 0 receipt, is graded on the
//! key log once certification has begun, and a key that was never certified reads as not a
//! TimeWitness certificate.
//!
//! # Whose statement it is
//!
//! A certificate is a statement of the TimeWitness app, in a log we sign. It is not third-party
//! evidence and never becomes part of it. The weight of the receipt still rests on the outside
//! signatures, and the verifier says so beside the grade.

use timewitness_core::evidence::{drand, rfc3161};
use timewitness_core::keylog::file::{KeyLog, SignedHead};
use timewitness_core::keylog::{certified, Certified, Role};
use timewitness_core::UnixNanos;
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::report::{EntryReport, Outcome, Verified};
use timewitness_receipt::schema::Role as EvidenceRole;
use timewitness_receipt::Receipt;

/// Who a certificate is issued by, as the verifier names it.
///
/// Named and not addressed. No source on the verify path may carry an address of ours, which
/// `crates/architecture/tests/verify_path_needs_nothing_of_ours.rs` holds to the letter, so the
/// verifier says whose statement a certificate is and leaves where to find the app to the pages
/// that are allowed to know.
pub const ISSUER: &str = "the TimeWitness app";

/// Which thing the later outside instant is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Places {
    /// A witness over the receipt's own signature, so the signing itself.
    TheSigning,
    /// A witness over the subject only, so the signing is placed only where the subject is new.
    TheSubject,
}

/// One outside instant and whose clock it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Instant {
    /// The instant.
    pub at: UnixNanos,
    /// An authority that states no accuracy put it there, on its own clock.
    pub on_its_own_clock: bool,
}

/// Why a receipt is not a certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotCertified {
    /// No certificate names the key, or none holds the span, or the key was retired first.
    NotCertifiedThen(String),
    /// Nothing outside the receipt places when it was signed.
    NothingPlacesIt,
}

/// Why the question was not answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotChecked {
    /// No key log was given.
    NoCopy,
    /// The copy ends before the receipt was signed.
    Stale,
    /// The copy is not one we signed, as far as this reader knows.
    NotOurs,
}

/// The grade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grade {
    /// A verified witness dates the receipt before certification began.
    BeforeCertification {
        /// The witness's instant.
        witnessed: Instant,
        /// When certification began, as this reader holds it.
        began: UnixNanos,
    },
    /// Held as a TimeWitness certificate.
    Held {
        /// Where the certificate sits in the log.
        entry: usize,
        /// The organisation the key was certified to.
        organisation: String,
        /// How it was certified.
        method: String,
        /// The window.
        from: UnixNanos,
        /// The window's end.
        until: UnixNanos,
        /// The latest beacon inside the signature.
        not_earlier: UnixNanos,
        /// The earliest witness after it.
        not_later: Instant,
        /// What that witness is about.
        places: Places,
    },
    /// Not a TimeWitness certificate.
    Not(NotCertified),
    /// Not checked as one.
    Unchecked(NotChecked),
}

impl Grade {
    /// Whether the receipt stands, as far as this grade goes: held as a certificate, or signed
    /// before there were any.
    #[must_use]
    pub const fn stands(&self) -> bool {
        matches!(self, Grade::Held { .. } | Grade::BeforeCertification { .. })
    }

    /// One word for a script.
    #[must_use]
    pub const fn word(&self) -> &'static str {
        match self {
            Grade::BeforeCertification { .. } => "before-certification",
            Grade::Held { .. } => "held",
            Grade::Not(_) => "not-a-certificate",
            Grade::Unchecked(_) => "not-checked",
        }
    }

    /// The line printed first, where the grade changes what a reader stops at.
    ///
    /// None for a receipt signed before certification began, whose first line is the one version 0
    /// prints.
    #[must_use]
    pub fn first_line(&self) -> Option<String> {
        match self {
            Grade::BeforeCertification { .. } => None,
            Grade::Held { .. } => Some(format!("Held as a TimeWitness certificate issued by {ISSUER}.")),
            Grade::Not(NotCertified::NotCertifiedThen(_)) => Some(format!(
                "Not a TimeWitness certificate: this key was not certified by {ISSUER}"
            )),
            Grade::Not(NotCertified::NothingPlacesIt) => Some(
                "Not a TimeWitness certificate: nothing outside this receipt places when it was signed"
                    .to_string(),
            ),
            Grade::Unchecked(NotChecked::NoCopy) => Some(
                "Not checked as a TimeWitness certificate: no copy of the key log was given"
                    .to_string(),
            ),
            Grade::Unchecked(NotChecked::Stale) => Some(
                "Not checked as a TimeWitness certificate: this copy of the key log ends before \
                 the receipt was signed. Fetch a newer copy"
                    .to_string(),
            ),
            Grade::Unchecked(NotChecked::NotOurs) => Some(
                "Not checked as a TimeWitness certificate: this copy of the key log is not signed \
                 by a key this reader holds for us"
                    .to_string(),
            ),
        }
    }

    /// What the grade rests on, in a sentence or two, printed under the verdict.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Grade::BeforeCertification { witnessed, began } => format!(
                "Signed before certification began: a witness checked against a key this reader \
                 holds dates it at {} ns{}, before {} ns. It is graded as version 0 grades it, and \
                 nothing here says whose key signed it.",
                witnessed.at.as_nanos(),
                clock(*witnessed),
                began.as_nanos()
            ),
            Grade::Held {
                entry: _,
                organisation,
                method,
                from,
                until,
                not_earlier,
                not_later,
                places,
            } => {
                let about = match places {
                    Places::TheSigning => "the witness over the receipt's own signature",
                    Places::TheSubject => {
                        "the witness over its subject, which places the subject and not the \
                         signing, since this receipt carries no witness over its signature"
                    }
                };
                format!(
                    "The key was certified to organisation {organisation} by {method} for {} ns to \
                     {} ns, and the signing sits between a beacon at {} ns and {about} at {} ns{}, \
                     both inside that window. The certificate is a statement of {ISSUER} in a log \
                     it signs. It is not third-party evidence, and the weight of this receipt still \
                     rests on the outside signatures below.",
                    from.as_nanos(),
                    until.as_nanos(),
                    not_earlier.as_nanos(),
                    not_later.at.as_nanos(),
                    clock(*not_later)
                )
            }
            Grade::Not(NotCertified::NotCertifiedThen(why)) => format!(
                "{why}. The receipt still carries every outside signature below, and each still \
                 checks; nobody can say whose key signed it."
            ),
            Grade::Not(NotCertified::NothingPlacesIt) => {
                "It needs a checked beacon inside the signature and a checked witness after it, \
                 and the receipt's own reading is never used in their place. The outside \
                 signatures it does carry are below."
                    .to_string()
            }
            Grade::Unchecked(NotChecked::NoCopy) => format!(
                "Give a copy of the key log {ISSUER} publishes with --key-log. Reading it needs no \
                 account and no network."
            ),
            Grade::Unchecked(NotChecked::Stale) => {
                "The key is not certified in this copy, and its newest head is older than the \
                 witness after the signing, so a newer copy may certify it."
                    .to_string()
            }
            Grade::Unchecked(NotChecked::NotOurs) => {
                "A list anybody signed says nothing about what the app certified.".to_string()
            }
        }
    }
}

fn clock(instant: Instant) -> &'static str {
    if instant.on_its_own_clock {
        ", on the authority's own clock, which states no accuracy"
    } else {
        ""
    }
}

/// An attestation's later edge where it states one, or the instant it states on its own clock.
fn later_instant(report: &EntryReport) -> Option<Instant> {
    match &report.outcome {
        Outcome::Checked {
            latest: Some(latest),
            ..
        } => Some(Instant {
            at: *latest,
            on_its_own_clock: false,
        }),
        Outcome::Checked {
            latest: None,
            stated: Some(stated),
            ..
        } => Some(Instant {
            at: *stated,
            on_its_own_clock: true,
        }),
        _ => None,
    }
}

/// The earliest checked witness, preferring the one over the signature.
fn not_later(evidence: &Verified) -> Option<(Instant, Places)> {
    if let Some(instant) = evidence.signature_witness.as_ref().and_then(later_instant) {
        return Some((instant, Places::TheSigning));
    }
    evidence
        .entries
        .iter()
        .filter(|e| e.role == EvidenceRole::NotLaterThan)
        .filter_map(later_instant)
        .min_by_key(|i| i.at)
        .map(|i| (i, Places::TheSubject))
}

/// Whether a checked witness over the receipt's own signature dates the signing before C.
///
/// Only that witness places the signing. A witness over the subject says the subject existed by
/// then, and whoever holds a key chooses the subject: until 2026-09-23 this counted one, so an old
/// timestamp token over a payload let a key nobody certified sign that payload after C and be graded
/// as signed before it. And a checked beacon at or after C refuses the grade outright, whatever any
/// witness says, because its value is inside the signature and the signing cannot have come before it.
fn witnessed_before(evidence: &Verified, began: UnixNanos) -> Option<Instant> {
    if evidence.bracket().not_earlier.is_some_and(|at| at >= began) {
        return None;
    }
    evidence
        .signature_witness
        .iter()
        .filter_map(later_instant)
        .filter(|i| i.at < began)
        .min_by_key(|i| i.at)
}

/// Grade a receipt that passed every version 0 check.
///
/// `log` is the copy the reader was handed, already held to [`check_the_log`] where there is one.
#[must_use]
pub fn grade(
    receipt: &Receipt,
    evidence: &Verified,
    log: Option<&KeyLog>,
    held: &[[u8; 32]],
    began: UnixNanos,
) -> Grade {
    if let Some(witnessed) = witnessed_before(evidence, began) {
        return Grade::BeforeCertification { witnessed, began };
    }

    let not_earlier = evidence.bracket().not_earlier;
    let (Some(not_earlier), Some((not_later, places))) = (not_earlier, not_later(evidence)) else {
        return Grade::Not(NotCertified::NothingPlacesIt);
    };

    let Some(log) = log else {
        return Grade::Unchecked(NotChecked::NoCopy);
    };
    let ours = log
        .head
        .as_ref()
        .is_some_and(|signed| held.contains(&signed.signed_by))
        && log.head_is_signed_by_the_key_it_names() == Some(true)
        && log.checkpoints_are_ours(held);
    if !ours {
        return Grade::Unchecked(NotChecked::NotOurs);
    }

    let Ok(key) = <[u8; 32]>::try_from(receipt.agent_public_key.as_slice()) else {
        return Grade::Not(NotCertified::NotCertifiedThen(
            "the receipt names a key that is not a 32-byte Ed25519 key".to_string(),
        ));
    };

    let newest = log.head.as_ref().map(|signed| signed.head.at);
    match certified(&log.entries, &key, not_earlier, not_later.at) {
        Certified::Held(index) => {
            let entry = &log.entries[index];
            match (&entry.issued, entry.valid_until) {
                (Some(issued), Some(until)) => Grade::Held {
                    entry: index,
                    organisation: issued.organisation.clone(),
                    method: issued.method.clone(),
                    from: entry.valid_from,
                    until,
                    not_earlier,
                    not_later,
                    places,
                },
                // The format refuses both on the way in, so a log read off a file never gets here.
                _ => Grade::Not(NotCertified::NotCertifiedThen(
                    "the certificate that names this key names no organisation or no end"
                        .to_string(),
                )),
            }
        }
        Certified::NotCertified if newest.is_some_and(|at| at < not_later.at) => {
            Grade::Unchecked(NotChecked::Stale)
        }
        Certified::NotCertified => Grade::Not(NotCertified::NotCertifiedThen(
            "no certificate in this log names this key".to_string(),
        )),
        Certified::Retired(at) => Grade::Not(NotCertified::NotCertifiedThen(format!(
            "the key was retired at {} ns, at or before the witness after the signing",
            at.as_nanos()
        ))),
        Certified::OutsideItsWindow => Grade::Not(NotCertified::NotCertifiedThen(format!(
            "no certificate for this key holds the whole span from the beacon at {} ns to the \
             witness at {} ns",
            not_earlier.as_nanos(),
            not_later.at.as_nanos()
        ))),
    }
}

/// Hold a key log to the cutoff this reader holds, before any receipt is graded against it.
///
/// A log refused here refuses the receipt read against it, because a reader who supplied it asked
/// the question and the answer is that the list is not one that could certify anything. Four
/// refusals: a cutoff other than the reader's, more than one cutoff, a certificate window starting
/// before C, and a cutoff whose first head carries no checked beacon at or after C and no checked
/// witness over itself. A log with no cutoff at all is an older copy and is not refused: it
/// certifies nothing, and the grade says whether that is because it is stale.
///
/// # Errors
///
/// The refusal, in words.
pub fn check_the_log(log: &KeyLog, anchors: &TrustAnchors, began: UnixNanos) -> Result<(), String> {
    let cutoffs: Vec<(usize, UnixNanos)> = log
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.role == Role::Cutoff)
        .map(|(i, e)| (i, e.valid_from))
        .collect();
    let Some(&(index, stated)) = cutoffs.first() else {
        return Ok(());
    };
    if cutoffs.len() > 1 {
        return Err(format!(
            "this key log states certification began {} times, and it began once",
            cutoffs.len()
        ));
    }
    if stated != began {
        return Err(format!(
            "this key log states certification began at {} ns, and this reader holds {} ns. \
             Certification begins once and does not move, so this is not the log that reader \
             was given the verifier for",
            stated.as_nanos(),
            began.as_nanos()
        ));
    }
    if let Some(early) = log
        .entries
        .iter()
        .find(|e| e.role == Role::Certificate && e.valid_from < began)
    {
        return Err(format!(
            "this key log certifies a key from {} ns, before certification began at {} ns",
            early.valid_from.as_nanos(),
            began.as_nanos()
        ));
    }

    let head = log
        .first_head_covering(index)
        .ok_or_else(|| "the cutoff sits under no head, so nobody signed it".to_string())?;
    let round = beacon_time(head, anchors).map_err(|why| {
        format!("the head that first carried the cutoff has no beacon this reader can check: {why}")
    })?;
    if round < began {
        return Err(format!(
            "the head that first carried the cutoff carries a beacon from {} ns, before \
             certification began at {} ns, so nothing shows the moment was fixed after it passed",
            round.as_nanos(),
            began.as_nanos()
        ));
    }
    witness_checks(head, anchors).map_err(|why| {
        format!(
            "the head that first carried the cutoff has no witness this reader can check: {why}"
        )
    })?;
    Ok(())
}

/// Hold the certificate a receipt is graded on to the head that first published it.
///
/// A head is dated by our own clock, so a certificate for a past window could be appended by
/// whoever holds the log key. The beacon inside the head it first appeared under is the one date a
/// stranger can check, and no window may start before it.
///
/// # Errors
///
/// The refusal, in words.
pub fn check_the_certificate(
    log: &KeyLog,
    index: usize,
    anchors: &TrustAnchors,
) -> Result<(), String> {
    let entry = &log.entries[index];
    let head = log
        .first_head_covering(index)
        .ok_or_else(|| "the certificate sits under no head".to_string())?;
    let round = beacon_time(head, anchors).map_err(|why| {
        format!("the head that first carried this certificate has no beacon this reader can check: {why}")
    })?;
    if entry.valid_from < round {
        return Err(format!(
            "this certificate's window starts at {} ns and the head that first carried it was \
             signed after a beacon at {} ns, so it certifies a window that had already begun \
             when it was written",
            entry.valid_from.as_nanos(),
            round.as_nanos()
        ));
    }
    Ok(())
}

/// When the beacon a head signed over was published, checked against a chain the reader holds.
fn beacon_time(head: &SignedHead, anchors: &TrustAnchors) -> Result<UnixNanos, String> {
    let blob = head
        .head
        .beacon
        .as_deref()
        .ok_or_else(|| "it carries none".to_string())?;
    let named = drand::named_chain(blob).map_err(|e| e.to_string())?;
    let chain = anchors
        .drand_chains
        .iter()
        .find(|c| c.hash == named)
        .ok_or_else(|| "it names a drand chain this reader holds no key for".to_string())?;
    let checked = drand::check(blob, chain).map_err(|e| e.to_string())?;
    checked
        .earliest()
        .ok_or_else(|| "the round states no time".to_string())
}

/// Whether the witness on a head checks, over the head and its signature, under an authority the
/// reader holds.
fn witness_checks(head: &SignedHead, anchors: &TrustAnchors) -> Result<(), String> {
    let blob = head
        .witness
        .as_deref()
        .ok_or_else(|| "it carries none".to_string())?;
    let inspected = rfc3161::inspect(blob, &head.witness_digest()).map_err(|e| e.to_string())?;
    let mut last = "this reader holds no timestamp authority".to_string();
    for authority in &anchors.timestamp_authorities {
        match inspected.under(authority) {
            Ok(_) => return Ok(()),
            Err(e) => last = format!("{}: {e}", authority.name),
        }
    }
    Err(last)
}
