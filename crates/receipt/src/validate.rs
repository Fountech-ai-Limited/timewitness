//! The validator, which is where the rule that our own word is never third-party evidence stops
//! being a policy and becomes a check.
//!
//! A receipt can be perfectly well formed and still be a lie. The lie available to a product in this
//! field is always the same one: put the agent's own bound, which is the tightest number in the
//! receipt and the only one that rests on trusting the agent, where a third party's signature is
//! supposed to go. Nobody reading the receipt casually would notice, because both are numbers about
//! time with a label beside them.
//!
//! So the checks below refuse three separate versions of that. A scheme that cannot support the role
//! it claims. A scheme that names something of ours rather than a third party's, network time
//! security in particular. And a claim of a third-party sandwich by a receipt that does not carry
//! the three pieces a sandwich is made of, which today means any receipt at all, because nothing
//! here can verify a signed response yet and a basis that cannot be checked is not granted.
//!
//! The rest of the checks are arithmetic: a receipt whose own numbers do not support each other is
//! refused rather than half believed. That is a longer list than it looks, and every item on it was
//! built as a correctly signed receipt and accepted before the check went in. A bound narrower than
//! its own parts. A majority of no sources. A width past the ceiling the receipt states for itself.
//! A corridor dated a year away from the reading it is offered as support for. None of those is
//! malformed and none has a bad signature; each is a false claim in a well-formed file, which is the
//! only kind this format is really up against.

use crate::anchors::{RoughtimeServerKey, TrustAnchors};
use crate::error::ReceiptError;
use crate::report::{Bracket, EntryReport, Outcome, Verified};
use crate::schema::{AgentClaim, Evidence, Payload, Receipt, Role, FORMAT_VERSION, LEAP_VALUES};
use crate::value::Value;
use timewitness_core::evidence::{drand, rfc3161, roughtime, Checked};
use timewitness_core::time::{Nanos, UnixNanos, NANOS_PER_SEC};
use timewitness_core::EpsilonBasis;

/// The widest a third-party sandwich may be before it stops supporting anything.
///
/// An agent fetches its beacon and its witness around the moment it stamps, so a real sandwich is
/// seconds wide. An hour is three orders of magnitude of slack and still refuses evidence lifted
/// from a different part of the day, which is the shape the fraud takes: a genuine beacon and a
/// genuine token, both real, both signed, and neither of them about this reading.
pub const SANDWICH_WIDTH_CEILING: Nanos = 3_600 * NANOS_PER_SEC;

/// Check everything about a receipt except its signature.
///
/// The signature is checked in [`crate::cose`], because the two failures are different questions:
/// this one asks whether the receipt says something allowable, and that one asks whether the agent
/// really said it.
pub fn validate(receipt: &Receipt) -> Result<(), ReceiptError> {
    validate_with(receipt, &TrustAnchors::none()).map(|_| ())
}

/// Check a receipt against what the verifier has decided to trust.
///
/// This is the same function as [`validate`] with one difference, and it is the difference
/// everything about third-party evidence turns on. Every check a receipt can be held to on its own
/// is run either way. What the anchors decide is whether the receipt is allowed to say its bound
/// rests on third-party evidence, and it is allowed to say that only where this code has verified,
/// against a key chosen in advance, one signature in each of the three roles.
///
/// The report it returns says which entries were checked and how. That is not decoration: a
/// verifier that answers with a single word has hidden the only thing a careful reader wants.
pub fn validate_with(receipt: &Receipt, anchors: &TrustAnchors) -> Result<Verified, ReceiptError> {
    check_strings(receipt)?;
    check_version(receipt)?;
    check_payload(receipt)?;
    check_chain(receipt)?;
    check_interval(receipt)?;
    check_breakdown(receipt)?;
    check_sources(receipt)?;
    check_against_its_own_policy(receipt)?;
    for entry in &receipt.evidence {
        check_evidence_entry(entry)?;
    }
    check_evidence_against_the_interval(receipt)?;

    let entries = examine(receipt, anchors)?;
    let (granted, reason) = decide_basis(receipt, &entries)?;

    Ok(Verified {
        entries,
        basis_granted: granted,
        basis_reason: reason,
        anchors_held: anchors.count(),
    })
}

/// Refuse a receipt whose strings carry a character a line of a report cannot.
///
/// This runs before every other check because it is about what the other checks are allowed to put
/// in front of a reader. A receipt is a file a stranger hands us, and every string in it was
/// written by whoever signed it. Those strings reach people through reports, and a report is a
/// format: `timewitness verify --fields` is one `name=value` per line, and `scripts/action-stamp.sh`
/// reads it with `sed` and puts the answers into a workflow's outputs.
///
/// Measured 2026-09-19: a correctly signed receipt whose first source had `kind` set to `ntp`, a
/// newline, `earliest_ns=1`, a newline, `width_ns=1` verified clean, saying the receipt held up, and
/// its own `--fields` report carried `earliest_ns=1` and `width_ns=1:1,nts:3,roughtime:3` above the
/// report's real ones. Two intended lines became four in `$GITHUB_OUTPUT` with attacker-chosen
/// content on two of them.
///
/// **Refused here rather than escaped at the report, and the reason is that there is more than one
/// report.** An escape belongs to whichever format does the escaping, so it has to be got right in
/// the fields report, in the human one, in anything written later, and in whatever a consumer
/// builds on top. A control character in a source's name or a hash algorithm is not a thing an
/// honest agent writes, in any of them. So the answer is that such a receipt is not well formed,
/// which is one rule in one place, and the reader is told which field and what was in it.
///
/// The value is printed escaped, or the refusal would plant the lines the refusal is about, and it
/// is cut to what a person reads, because a receipt may carry sixty kilobytes in one string and a
/// refusal nobody can read is a refusal that gets skipped.
///
/// **What the rule is, said plainly so nobody reads it as more.** It refuses the Unicode control
/// characters, which is every ASCII control and every C1 one, and that is what breaks a line in a
/// report, in a shell variable and in anything reading a value as a C string. It does not refuse
/// U+2028 and U+2029, which are separators rather than controls and which some readers treat as
/// line breaks. Nothing in this product puts a receipt's strings anywhere those two would split a
/// line: the fields report is read by `sed`, and neither verifier page writes a string into HTML.
/// The day one of them does, this is the rule to widen.
///
/// This does not stand alone and it was never meant to. `render::fields` holds every value it
/// prints to one line as well, because a receipt refused here still reaches that report through the
/// refusal path.
fn check_strings(receipt: &Receipt) -> Result<(), ReceiptError> {
    /// How much of the offending string the refusal shows.
    const SHOWN: usize = 120;

    for (at, value) in receipt.strings() {
        if let Some(bad) = value.chars().find(|c| c.is_control()) {
            let short: String = value.chars().take(SHOWN).collect();
            let cut = if short.chars().count() < value.chars().count() {
                format!("{short:?} and more")
            } else {
                format!("{short:?}")
            };
            return Err(ReceiptError::Field(format!(
                "{at} is {cut}, which carries the control character {bad:?}. Nothing an agent \
                 names carries one, and a report is written a line at a time, so a receipt that \
                 could write its own lines into one is refused rather than read"
            )));
        }
    }
    Ok(())
}

/// Check the shape of a receipt as a raw value tree, before it has been read into fields.
///
/// This exists for the one thing the typed form cannot express: a receipt that has moved the
/// agent's own claim into an evidence slot, or dressed an evidence entry up as a claim. Once the
/// bytes are parsed into a `Receipt` those are gone, so the check has to happen on the tree.
pub fn validate_shape(value: &Value) -> Result<(), ReceiptError> {
    let claim = value
        .get("claim")
        .ok_or_else(|| ReceiptError::Field("there is no claim".into()))?;

    if claim.has("role") {
        return Err(ReceiptError::OurClaimAsEvidence(
            "the agent's own claim carries a role, and only third-party evidence has a role"
                .to_string(),
        ));
    }
    if claim.has("blob") {
        return Err(ReceiptError::OurClaimAsEvidence(
            "the agent's own claim carries a signed blob, and there is nothing of anybody else's \
             in it to sign"
                .to_string(),
        ));
    }

    let evidence = value
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| ReceiptError::Field("there is no evidence list".into()))?;

    for entry in evidence {
        if entry.has("kind") {
            let kind = entry.get("kind").and_then(Value::as_text).unwrap_or("");
            return Err(ReceiptError::OurClaimAsEvidence(format!(
                "an evidence entry carries the discriminant {kind:?}, which belongs to the agent's \
                 own claim"
            )));
        }
        for required in ["role", "scheme", "at_ns", "blob"] {
            if !entry.has(required) {
                return Err(ReceiptError::Field(format!(
                    "an evidence entry has no {required}"
                )));
            }
        }
        if entry.has("earliest_ns") || entry.has("latest_ns") || entry.has("breakdown") {
            return Err(ReceiptError::OurClaimAsEvidence(
                "an evidence entry carries the fields of the agent's own bound".to_string(),
            ));
        }
    }

    Ok(())
}

fn check_version(receipt: &Receipt) -> Result<(), ReceiptError> {
    if receipt.version != FORMAT_VERSION {
        return Err(ReceiptError::UnknownVersion(receipt.version));
    }
    Ok(())
}

fn check_payload(receipt: &Receipt) -> Result<(), ReceiptError> {
    match receipt.payload.expected_length() {
        None => Err(ReceiptError::Field(format!(
            "the payload was hashed with {:?}, which this code does not know, so it cannot say \
             whether the hash is the right length",
            receipt.payload.algorithm
        ))),
        Some(n) if receipt.payload.hash.len() != n => Err(ReceiptError::Inconsistent(format!(
            "the payload hash is {} bytes and {} produces {n}",
            receipt.payload.hash.len(),
            receipt.payload.algorithm
        ))),
        Some(_) => Ok(()),
    }
}

fn check_chain(receipt: &Receipt) -> Result<(), ReceiptError> {
    if let Some(prev) = &receipt.chain_previous {
        if prev.len() != 32 {
            return Err(ReceiptError::Inconsistent(format!(
                "the chain link is {} bytes and a receipt hash is 32",
                prev.len()
            )));
        }
    }
    Ok(())
}

fn check_interval(receipt: &Receipt) -> Result<(), ReceiptError> {
    let c = &receipt.claim;
    if c.earliest > c.latest {
        return Err(ReceiptError::Inconsistent(
            "the earliest possible time is after the latest possible time".into(),
        ));
    }
    if receipt.utc_estimate < c.earliest || receipt.utc_estimate > c.latest {
        return Err(ReceiptError::Inconsistent(
            "the reading sits outside the interval the receipt claims for it".into(),
        ));
    }
    Ok(())
}

fn check_breakdown(receipt: &Receipt) -> Result<(), ReceiptError> {
    let b = &receipt.claim.breakdown;
    for (name, part) in [
        ("intersection_half_ns", b.intersection_half),
        ("network_half_ns", b.network_half),
        ("scheduling_ns", b.scheduling),
        ("oscillator_holdover_ns", b.oscillator_holdover),
        ("model_residual_ns", b.model_residual),
        ("safety_margin_ns", b.safety_margin),
    ] {
        if part < 0 {
            return Err(ReceiptError::Inconsistent(format!(
                "{name} is negative, and no part of a width can be"
            )));
        }
    }

    // The stated parts have to account for the width the receipt claims, and they have to account
    // for no more than it either. Both directions matter and the second one matters most.
    //
    // Parts adding to less than the interval describe a bound that was not computed from them.
    // Parts adding to more than the interval are worse: that receipt is claiming precision its own
    // arithmetic does not support, which is the overclaim this product exists to refuse, and it is
    // the direction a product is tempted in rather than the direction it drifts in.
    //
    // The slack is two nanoseconds. The model rounds the half intersection up, so a whole width of
    // odd length comes back one nanosecond over, and one more is left for a term that starts
    // rounding the same way. Anything further apart than that is a receipt whose own numbers do not
    // describe each other.
    let parts = 2 * b.half_width();
    let width = receipt.width();
    if parts < width || parts > width + 2 {
        return Err(ReceiptError::Inconsistent(format!(
            "the parts of the bound add to {parts} ns and the interval is {width} ns wide"
        )));
    }
    Ok(())
}

fn check_sources(receipt: &Receipt) -> Result<(), ReceiptError> {
    let c = &receipt.claim;
    if c.sources_kept > c.sources_offered {
        return Err(ReceiptError::Inconsistent(format!(
            "{} sources were kept out of {} offered",
            c.sources_kept, c.sources_offered
        )));
    }
    if c.sources_offered as usize != c.sources.len() {
        return Err(ReceiptError::Inconsistent(format!(
            "the receipt says {} sources answered and lists {}",
            c.sources_offered,
            c.sources.len()
        )));
    }
    let listed_kept = c.sources.iter().filter(|s| s.kept).count() as u32;
    if listed_kept != c.sources_kept {
        return Err(ReceiptError::Inconsistent(format!(
            "the receipt says {} sources were kept and marks {listed_kept}",
            c.sources_kept
        )));
    }
    // A leap value this format cannot read is refused here, before anything reads it. `leap` is the
    // field the majority test below turns on, and the honest answer about a string nothing here
    // knows is that the verifier cannot tell what the source said. Answering that as though the
    // source had said its clock was fine is the fault corrected here on 2026-09-19: one capital
    // letter and nine
    // sources that had all declared their own clocks wrong read as nine sound ones. Refusing here
    // means a reader is told which source and which value rather than being told the receipt
    // contradicts itself, which would be a different and untrue thing to say about it.
    if let Some(s) = c.unreadable_leap() {
        return Err(ReceiptError::Field(format!(
            "source {} says its leap indicator is {:?} and this format knows {}, so nothing here \
             can tell whether it could have disagreed with anybody",
            s.id,
            s.leap,
            LEAP_VALUES.join(", ")
        )));
    }
    // A source cannot be kept and also have told the agent its own clock was wrong. The agent drops
    // such a source before the intersection is taken, so a receipt marking one as kept describes a
    // round the shipped code cannot have run.
    if let Some(s) = c
        .sources
        .iter()
        .find(|s| s.kept && !AgentClaim::was_a_candidate(s))
    {
        return Err(ReceiptError::Inconsistent(format!(
            "source {} said its own clock was not synchronised and the receipt marks it as kept",
            s.id
        )));
    }
    // The majority is over the sources that could have disagreed with somebody, which is every
    // source that answered less the ones that said their own clock was wrong. That is the set
    // Marzullo's guarantee is about and the set the agent applies its own floors to, so it is the
    // one a reader has to apply this test over as well.
    //
    // It was `sources_offered` until that field was corrected to mean what it has always said it
    // means, which is how many answered. Taking the majority over that number would have refused an
    // honest round in which half the sources reported themselves unsynchronised: they cannot be in
    // the denominator of a test about disagreement when nothing they said could disagree with
    // anybody.
    //
    // No exemption for a receipt with no candidates at all. Zero is not a special case that escapes
    // the test, it is the case the whole design refuses: a bound derived from nothing at all, with
    // no clock but ours behind it.
    let candidates = c.candidates();
    if 2 * (c.sources_kept as usize) <= candidates {
        return Err(ReceiptError::Inconsistent(format!(
            "{} of {candidates} sources that could disagree agreed, which is not a majority, so \
             this bound should never have been issued",
            c.sources_kept
        )));
    }
    check_operators(receipt)
}

/// The same majority test, over the parties behind the sources rather than over the names.
///
/// A count of sources counts names and names are free: one company answering on nine addresses is
/// nine entries in the list above, a clean majority, and one chance to be wrong. Marzullo's
/// guarantee is about faults, a fault happens to a party, so this is the arithmetic the guarantee
/// actually rests on. The agent refuses such a round; this is the same rule applied from the outside
/// by somebody who was not there, which is the only version of it a stranger can rely on.
///
/// **The count is recomputed here and never read out of the receipt, because the receipt does not
/// carry one.** A stated count would be the agent's arithmetic and a reader would be checking it
/// against itself. The operator labels are what the agent observed, and the counting is the reader's
/// to do, exactly as with the source list beside `sources_kept`.
///
/// A receipt naming operators for some sources and not others is read with every unnamed source
/// sharing one unknown party between them, which lowers the count rather than raising it: a gap in
/// the labels can only ever cost a receipt this test, never win it.
///
/// **A receipt naming nobody at all is read the same way and is not excused.** It was until
/// 2026-09-10: the test returned early for any such receipt, on the grounds that it predated the
/// field and should not be held to a format it came before. What that reached was not only the old
/// receipt. It reached any receipt at all with the labels left off, and such a receipt skipped both
/// this majority test and the agent's own stated floor, so an agent could state that it signs
/// nothing under three parties, name none, and be judged to have kept its word.
///
/// The old receipt does not need the carve-out and never did. The floor field and the labels went
/// in together, in one commit on 2026-09-09, so a receipt written before the labels states no floor
/// either. It has one unknown party behind it, no floor to fall short of, and it passes here on its
/// own merits with nothing set aside for it.
///
/// This is still the agent-kept-its-word question and not the reader's. `timewitness_verify` asks
/// the reader's, which is whether they should believe the sources failed separately, and it refuses
/// an unlabelled receipt outright because nothing in one gives them anything to believe it on.
///
/// Added 2026-09-09.
fn check_operators(receipt: &Receipt) -> Result<(), ReceiptError> {
    let c = &receipt.claim;

    // The counting itself is `AgentClaim::operators`, so this test and the verifier's own floor
    // cannot drift apart. What each of them does with the answer is different and stays here.
    let operators = c.operators();

    if 2 * operators.kept <= operators.offered {
        return Err(ReceiptError::Inconsistent(format!(
            "the sources that agreed are run by {} of the {} operators that answered, which is \
             not a majority of them, so this bound should never have been issued",
            operators.kept, operators.offered
        )));
    }

    if let Some(floor) = c.policy.min_operators {
        if (operators.kept as u32) < floor {
            // Two sentences for the same arithmetic, because a receipt that named nobody and one
            // that named one party are different things and a reader deciding what to do next
            // needs to know which they are holding.
            return Err(ReceiptError::Inconsistent(if c.names_no_operator() {
                format!(
                    "this receipt names no operator for any of its sources and this agent says it \
                     needs {floor} operators before it will sign at all, so nothing in it shows \
                     that the agent kept to its own word"
                )
            } else {
                format!(
                    "{} operators stood behind this bound and this agent says it needs {floor} \
                     before it will sign at all",
                    operators.kept
                )
            }));
        }
    }

    Ok(())
}

/// Check the receipt against the policy it states for itself.
///
/// Every receipt carries the widest interval its agent said it would sign for and the fewest
/// sources it said it would answer on. Checking a receipt against its own stated numbers is what
/// the rest of this file does, and these two were being carried and read by nothing.
///
/// This is not a check that the policy is a good one. A receipt stating a lax policy and keeping to
/// it passes here and is judged on the numbers instead, against the floor the reader brought, which
/// is `crates/verify`. What this catches is an agent that broke its own word, which is a different
/// and simpler question.
///
/// One value is refused outright rather than judged, and it is zero. A ceiling of zero was read as
/// an absent ceiling, so a receipt stating it was held to no width at all. Zero is also what the
/// field holds when nobody filled it in, which makes the deliberate reading and the oversight the
/// same value, and an unset field is not a permission. Read as written it says the agent would sign
/// no interval of any width, and the receipt in front of the reader is one it signed.
fn check_against_its_own_policy(receipt: &Receipt) -> Result<(), ReceiptError> {
    let c = &receipt.claim;
    if c.policy.max_bound_width <= 0 {
        return Err(ReceiptError::Inconsistent(format!(
            "the agent states there is no interval it would sign, a ceiling of {} ns, and then \
             signed one {} ns wide",
            c.policy.max_bound_width,
            receipt.width()
        )));
    }
    if receipt.width() > c.policy.max_bound_width {
        return Err(ReceiptError::Inconsistent(format!(
            "the interval is {} ns wide and this agent says it will not sign one wider than {} ns",
            receipt.width(),
            c.policy.max_bound_width
        )));
    }
    // Counted over the candidates, because that is the count the agent applies this floor to. It
    // was over `sources_offered` until that field was corrected to mean how many answered, which
    // let a round clear the agent's own stated floor on sources that had told it their clocks were
    // wrong.
    let candidates = c.candidates();
    if candidates < c.policy.min_sources as usize {
        return Err(ReceiptError::Inconsistent(format!(
            "{candidates} sources answered with a clock they stood behind and this agent says it \
             needs {} before it will answer at all",
            c.policy.min_sources
        )));
    }
    // The holdover ceiling, checked the same way and for the same reason. `since_last_sync` is the
    // age of the newest exchange the interval rests on, so a receipt whose age is past its own
    // stated ceiling is one the agent's own rules say it should have refused. Nothing outside the
    // receipt is needed to see it, which is what makes it worth carrying.
    if let Some(ceiling) = c.policy.max_holdover {
        if ceiling <= 0 {
            return Err(ReceiptError::Inconsistent(format!(
                "the agent states it will extrapolate for {ceiling} ns and then signed a reading \
                 it took {} ns after the last it heard from a source",
                c.since_last_sync
            )));
        }
        if c.since_last_sync > ceiling {
            return Err(ReceiptError::Inconsistent(format!(
                "the newest exchange behind this interval is {} ns old and this agent says it \
                 will not extrapolate past {ceiling} ns",
                c.since_last_sync
            )));
        }
    }
    Ok(())
}

fn check_evidence_entry(entry: &Evidence) -> Result<(), ReceiptError> {
    // Our own word as third-party evidence, refused in its sharpest form. Network time security
    // improves a clock and can never be portable evidence, because its keys are symmetric and a
    // client holding one could forge a response to itself.
    if entry.scheme.is_ours_rather_than_a_third_partys() {
        return Err(ReceiptError::OurClaimAsEvidence(format!(
            "an evidence entry carries a {} response, which authenticates with a key we also hold, \
             so a stranger has no signature to check",
            entry.scheme.as_str()
        )));
    }

    match entry.scheme.proves() {
        None => Err(ReceiptError::MislabelledEvidence {
            role: entry.role.as_str().to_string(),
            scheme: entry.scheme.as_str().to_string(),
            why: "this format does not know that scheme, and it will not assume a scheme it has \
                  never heard of proves anything"
                .to_string(),
        }),
        Some(actual) if actual != entry.role => Err(ReceiptError::MislabelledEvidence {
            role: entry.role.as_str().to_string(),
            scheme: entry.scheme.as_str().to_string(),
            why: format!(
                "a {} response proves {}",
                entry.scheme.as_str(),
                actual.as_str()
            ),
        }),
        Some(_) => {
            if entry.blob.is_empty() {
                return Err(ReceiptError::Field(format!(
                    "the {} entry carries no signed response, so there is nothing to check",
                    entry.scheme.as_str()
                )));
            }
            if let Some(r) = entry.radius {
                if r < 0 {
                    return Err(ReceiptError::Inconsistent(format!(
                        "the {} entry states a radius of {r} ns, and no half width can be negative",
                        entry.scheme.as_str()
                    )));
                }
            }
            if entry.role == Role::AuthenticatedUtcCorridor {
                if entry.nonce.is_none() {
                    return Err(ReceiptError::Field(
                        "a corridor entry has no nonce, and without one the response could have \
                         been signed for somebody else at some other time"
                            .to_string(),
                    ));
                }
                if entry.radius.is_none() {
                    // A corridor is the role that gives the bound its outside support, so it is the
                    // one role whose own interval has to be checkable against the interval it
                    // supports. A response stating a midpoint and no radius says nothing testable.
                    return Err(ReceiptError::Field(
                        "a corridor entry states an instant and no radius, so it does not say what \
                         interval it proves and nothing can check it against this reading"
                            .to_string(),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Look at every evidence entry against what the verifier trusts.
///
/// An entry with a matching anchor is verified. An entry with no matching anchor is reported as
/// unchecked, which is a fact about the verifier rather than a fault in the receipt, and which is
/// said out loud rather than glossed. An entry that has an anchor and fails against it refuses the
/// whole receipt: a receipt carrying a signature that does not check out is not a receipt with a
/// weaker claim, it is a receipt that is wrong.
fn examine(receipt: &Receipt, anchors: &TrustAnchors) -> Result<Vec<EntryReport>, ReceiptError> {
    let mut reports = Vec::with_capacity(receipt.evidence.len());
    for entry in &receipt.evidence {
        let outcome = match entry.scheme.as_str() {
            roughtime::SCHEME => examine_corridor(entry, &receipt.payload, anchors)?,
            drand::SCHEME => examine_beacon(entry, anchors)?,
            rfc3161::SCHEME => examine_witness(entry, &receipt.payload, anchors)?,
            other => Outcome::NotChecked(format!(
                "this code knows how to check a roughtime response, a drand round and an rfc3161 \
                 token, and {other} is none of them"
            )),
        };
        reports.push(EntryReport {
            role: entry.role,
            scheme: entry.scheme.as_str().to_string(),
            detail: entry.detail.clone(),
            outcome,
        });
    }
    Ok(reports)
}

/// A refusal under a key the reader holds for the party the entry names.
fn refused(scheme: &str, signer: &str, why: &str) -> ReceiptError {
    ReceiptError::Inconsistent(format!(
        "the {scheme} entry offered as evidence does not check out against {signer}: {why}"
    ))
}

/// A refusal anybody can make from the receipt alone, whatever keys they hold.
///
/// Added 2026-09-08 for the outer blob and widened on 2026-09-15 to everything inside it. Each of
/// the three arms below returned `NotChecked` the moment the reader held no anchor for the party
/// an entry named, before it had looked at the bytes past the outer blob, so a receipt whose blob
/// was four bytes of `deadbeef` was refused by the default verifier and accepted under
/// `--no-anchors`, and then, once the signer's name was read off the attestation first, a reply of
/// zeros behind a renamed server was accepted by the default verifier as well, exit 0, on every
/// route. The name sits in bytes whoever wrote the receipt controls.
///
/// So the rule is that the set of checks that run never depends on anything the receipt says. Every
/// check whose inputs are all inside the receipt runs on every entry, and what the reader holds
/// decides one thing only: whether the signature is checked. A well-formed attestation nobody holds
/// a key for is `not checked`, which is a fact about the reader and not a fault in the receipt. An
/// attestation that fails on its own bytes is a failure at every setting.
fn on_its_own(scheme: &str, why: &str) -> ReceiptError {
    ReceiptError::Inconsistent(format!(
        "the {scheme} entry offered as evidence fails a check that needs no key to see: {why}"
    ))
}

fn into_outcome(checked: Checked) -> Outcome {
    let (earliest, latest) = (checked.earliest(), checked.latest());
    Outcome::Checked {
        signer: checked.signer,
        checks: checked.checks,
        earliest,
        latest,
    }
}

/// The interval the receipt prints beside an entry, against the one the attestation supports.
///
/// Added 2026-09-08, when the verifier shipped. `examine_corridor` compared the printed instant and
/// the printed radius against the response, and the other two arms compared the instant alone and
/// never the radius. `check_evidence_against_the_interval` then builds `at` plus or minus `radius`
/// out of the receipt's own numbers, so a not-later-than entry dated a year before the claim passed
/// the interval test by declaring a two-year radius, on a real token signed by a real authority.
///
/// The rule is one sentence and it fits all three roles: an entry may not print an interval
/// reaching outside the one the signed content supports. Printing a narrower one is allowed and is
/// the ordinary case, a beacon and a token each printing the single instant their scheme states,
/// because a narrower claim is a weaker one.
///
/// Returns the reason rather than the error, because whether it needed a key depends on the
/// scheme: a token states its own moment and a round's moment is arithmetic on the chain.
fn printed_interval_is_supported(
    entry: &Evidence,
    earliest: UnixNanos,
    latest: UnixNanos,
) -> Result<(), &'static str> {
    let radius = entry.radius.unwrap_or(0).max(0);
    if entry.at.as_nanos() - radius < earliest.as_nanos()
        || entry.at.as_nanos() + radius > latest.as_nanos()
    {
        return Err(
            "the receipt prints an interval beside this entry that reaches outside the one the \
             signature supports",
        );
    }
    Ok(())
}

/// A nonce as a value rather than as bytes, which means leading zeros dropped.
///
/// RFC 3161 carries the nonce as a DER integer, and an integer has no leading zeros. So a sixteen
/// byte nonce whose first byte happens to be zero comes back from the token as fifteen bytes with
/// the same value, one time in two hundred and fifty-six, while the receipt stores the sixteen the
/// agent generated. Comparing those as written would refuse a perfectly good receipt on a coin toss.
/// Roughtime carries a fixed thirty-two byte nonce and neither side of that comparison is an
/// integer, but the same reduction is applied to both, so nothing there changes.
fn nonce_value(bytes: &[u8]) -> &[u8] {
    let mut value = bytes;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    value
}

/// The nonce the receipt prints beside an entry, against the one the attestation was made over.
///
/// The other half of the same rule as the interval above, and it was the half left open. A nonce is
/// the field that answers "could this response have been fetched in advance", a reader looks at it,
/// and nothing tied it to the response at all: it was a `bstr` the receipt asserted and the
/// validator carried through untouched.
///
/// What the three schemes give is worth writing down, because the check cannot be right by accident
/// and two plausible comparisons are wrong. A Roughtime corridor reports the thirty-two byte nonce
/// out of the stored request, which is what the receipt prints, and it is neither the binding that
/// nonce was derived from nor the payload hash inside that binding. An RFC 3161 token reports the
/// nonce inside the signed token. A drand round reports none, because a public beacon has nothing
/// of ours in it, so a receipt printing a nonce beside one is printing a value that rests on
/// nothing. All three are read off the stored bytes, so this needs no key for any of them.
fn printed_nonce_is_the_signed_one(entry: &Evidence, signed: Option<&[u8]>) -> Result<(), String> {
    let printed = match &entry.nonce {
        // A receipt that prints no nonce claims nothing about one. Quieter than the evidence is
        // allowed; louder is what this refuses.
        None => return Ok(()),
        Some(printed) => printed,
    };
    match signed {
        Some(signed) if nonce_value(printed) == nonce_value(signed) => Ok(()),
        Some(signed) => Err(format!(
            "the receipt prints a {} byte nonce beside this entry and the response was made over \
             a different {} byte one",
            printed.len(),
            signed.len()
        )),
        None => Err(format!(
            "the receipt prints a {} byte nonce beside this entry and this scheme signs over no \
             nonce at all, so the printed value rests on nothing",
            printed.len()
        )),
    }
}

/// The first sixteen hex digits of a key hash, which is how a reader will look it up in a list.
fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// What to say about a label the receipt prints beside an entry the reader could not check.
///
/// The label is the receipt's own word for who signed, and the report prints it beside the
/// outcome. Where the reader holds a key under that very name and the attestation names some other
/// key, saying only "this reader holds no key with that hash" leaves the label doing the work of an
/// identity: a reader holding the shipped keys was shown "from roughtime.int08h.com: not checked"
/// beside a request that named nobody int08h. So the sentence says whose word the label is.
fn about_the_label(entry: &Evidence, held_under_that_name: bool) -> String {
    match (&entry.detail, held_under_that_name) {
        (Some(label), true) => format!(
            ". The receipt labels this entry {label:?}, and the key this reader holds under that \
             name is not the one the attestation names, so the label is the receipt's word and not \
             this reader's"
        ),
        _ => String::new(),
    }
}

/// A corridor entry: everything the bytes can be held to, then the key the reader holds for the
/// server the request names.
///
/// The instant and radius the receipt printed have to be the ones the response actually carries,
/// because a reader looks at the printed numbers, and a verifier that checks a signature and then
/// believes a different number beside it has checked nothing useful. Where the nonce was derived
/// from a subject, that subject has to be this receipt's payload, or the response is a genuine
/// signature about somebody else's document. Both are read off the stored bytes, so both run
/// whatever the reader holds.
///
/// Who signed the corridor is written in the request as the hash of the server's long-term key,
/// and the keys the reader holds under that hash are the only ones tried. A reader holding none has
/// not checked the entry, and the report says so. Until 2026-09-15 every key held was tried in turn
/// and a response fitting none of them was read as the receipt contradicting itself, so a reader
/// holding two of the three published keys was told an intact receipt was a lie.
fn examine_corridor(
    entry: &Evidence,
    payload: &Payload,
    anchors: &TrustAnchors,
) -> Result<Outcome, ReceiptError> {
    let inspected =
        roughtime::inspect(&entry.blob).map_err(|e| on_its_own("roughtime", &e.to_string()))?;
    if inspected.midpoint() != entry.at {
        return Err(on_its_own(
            "roughtime",
            "the response states a different moment from the one the receipt prints beside it",
        ));
    }
    if entry.radius != Some(inspected.radius()) {
        return Err(on_its_own(
            "roughtime",
            "the response states a different radius from the one the receipt prints beside it",
        ));
    }
    printed_nonce_is_the_signed_one(entry, Some(inspected.nonce()))
        .map_err(|why| on_its_own("roughtime", &why))?;
    if !inspected.binding().is_empty() && !inspected.binding().starts_with(&payload.hash) {
        return Err(on_its_own(
            "roughtime",
            "the nonce was bound to a subject, and that subject is not what this receipt is \
             stamping",
        ));
    }

    let named = inspected.requested_key_hash();
    let holders: Vec<&RoughtimeServerKey> = anchors
        .roughtime_servers
        .iter()
        .filter(|server| roughtime::server_key_hash(&server.long_term_public_key) == named)
        .collect();
    if holders.is_empty() {
        let label_held = entry.detail.as_deref().is_some_and(|label| {
            anchors
                .roughtime_servers
                .iter()
                .any(|server| server.name == label)
        });
        return Ok(Outcome::NotChecked(format!(
            "the request names a server whose long-term key hashes to {}, and this reader holds \
             no Roughtime key with that hash; it holds {}, so nothing here can check the \
             signature{}",
            short_hex(&named),
            anchors.roughtime_servers.len(),
            about_the_label(entry, label_held)
        )));
    }
    let mut last = (String::new(), String::new());
    for server in holders {
        match inspected.under(&server.long_term_public_key, &server.name) {
            Ok(checked) => return Ok(into_outcome(checked)),
            Err(e) => last = (server.name.clone(), e.to_string()),
        }
    }
    // The reader holds the key the request names and the response does not verify under it. That
    // is not a fact about the reader: the receipt put forward a signature that does not check out.
    Err(refused(
        "roughtime",
        &format!("the key this reader holds for {}", last.0),
        &last.1,
    ))
}

/// A beacon entry: the shape of the round, then the chain the reader holds for the one it names.
///
/// A round signs over no nonce, so one printed beside it rests on nothing whatever chain it names.
/// Which moment the round falls at is arithmetic on the chain's schedule, which is part of the
/// anchor, so the printed moment is held to the round only where the reader holds the chain.
fn examine_beacon(entry: &Evidence, anchors: &TrustAnchors) -> Result<Outcome, ReceiptError> {
    let inspected = drand::inspect(&entry.blob).map_err(|e| on_its_own("drand", &e.to_string()))?;
    printed_nonce_is_the_signed_one(entry, None).map_err(|why| on_its_own("drand", &why))?;

    let named = inspected.named_chain();
    let holders: Vec<&drand::Chain> = anchors
        .drand_chains
        .iter()
        .filter(|chain| chain.hash == named)
        .collect();
    if holders.is_empty() {
        let label_held = entry
            .detail
            .as_deref()
            .is_some_and(|label| anchors.drand_chains.iter().any(|chain| chain.name == label));
        return Ok(Outcome::NotChecked(format!(
            "the round names a chain whose hash begins {}, and this reader holds no drand chain \
             with that hash; it holds {}, so nothing here can check the signature{}",
            short_hex(&named),
            anchors.drand_chains.len(),
            about_the_label(entry, label_held)
        )));
    }
    let mut last = (String::new(), String::new());
    for chain in holders {
        match inspected.under(chain) {
            Ok(checked) => {
                if checked.earliest() != entry.at {
                    return Err(refused(
                        "drand",
                        chain.name,
                        "the round falls at a different moment from the one the receipt prints \
                         beside it",
                    ));
                }
                printed_interval_is_supported(entry, checked.earliest(), checked.latest())
                    .map_err(|why| refused("drand", chain.name, why))?;
                return Ok(into_outcome(checked));
            }
            Err(e) => last = (chain.name.to_string(), e.to_string()),
        }
    }
    Err(refused(
        "drand",
        &format!("the group key this reader holds for {}", last.0),
        &last.1,
    ))
}

/// A witness entry: everything the token can be held to, then the authority whose certificate the
/// reader pinned.
///
/// The token has to be about this receipt's payload, a token about anything else being a real
/// signature by a real authority and evidence for a different document, and the moment, interval
/// and nonce the receipt prints beside it have to be the ones the token states. All of that is in
/// the token, so all of it runs whatever the reader holds. The token also carries the certificates
/// it was signed under and a pin names one of them by digest, so an authority is tried only where
/// one of its pins is in the token.
fn examine_witness(
    entry: &Evidence,
    payload: &Payload,
    anchors: &TrustAnchors,
) -> Result<Outcome, ReceiptError> {
    let inspected = rfc3161::inspect(&entry.blob, &payload.hash)
        .map_err(|e| on_its_own("rfc3161", &e.to_string()))?;
    if inspected.latest() != entry.at {
        return Err(on_its_own(
            "rfc3161",
            "the token states a different moment from the one the receipt prints beside it",
        ));
    }
    printed_interval_is_supported(entry, inspected.earliest(), inspected.latest())
        .map_err(|why| on_its_own("rfc3161", why))?;
    printed_nonce_is_the_signed_one(entry, inspected.nonce())
        .map_err(|why| on_its_own("rfc3161", &why))?;

    let carried = inspected.certificate_digests();
    let holders: Vec<&rfc3161::Authority> = anchors
        .timestamp_authorities
        .iter()
        .filter(|authority| {
            authority
                .accepted_certificates
                .iter()
                .any(|pin| carried.contains(pin))
        })
        .collect();
    if holders.is_empty() {
        let pinned: usize = anchors
            .timestamp_authorities
            .iter()
            .map(|authority| authority.accepted_certificates.len())
            .sum();
        let label_held = entry.detail.as_deref().is_some_and(|label| {
            anchors
                .timestamp_authorities
                .iter()
                .any(|authority| authority.name == label)
        });
        return Ok(Outcome::NotChecked(format!(
            "the token carries {} certificate{} and this reader holds no pin naming any of them; \
             it holds {pinned}, so nothing here can check the signature{}",
            carried.len(),
            if carried.len() == 1 { "" } else { "s" },
            about_the_label(entry, label_held)
        )));
    }
    let mut last = (String::new(), String::new());
    for authority in holders {
        match inspected.under(authority) {
            Ok(checked) => return Ok(into_outcome(checked)),
            Err(e) => last = (authority.name.clone(), e.to_string()),
        }
    }
    Err(refused(
        "rfc3161",
        &format!("the certificate this reader pinned for {}", last.0),
        &last.1,
    ))
}

/// Whether the receipt may claim its bound rests on outside signatures.
///
/// This is the rule that our own word is never third-party evidence, as arithmetic. Until the
/// evidence clients existed the answer was no for every receipt, because nothing in this tree could
/// verify a signed response of any kind and three entries carrying the right words were being taken
/// as proof of cryptography. Three entries reading "not a roughtime response", "not a beacon" and
/// "not a token", correctly signed by the agent, were accepted with the strongest claim the format
/// can make.
///
/// What replaced that refusal is a precondition with five parts, and all five have to hold.
///
/// 1. One entry in each of the three roles.
/// 2. Every one of those three verified by this code against a key chosen in advance. An entry
///    nobody checked supports nothing, however honest it is.
/// 3. The sandwich the right way round, so the witness is not dated before the beacon.
/// 4. The sandwich narrow enough to be about this reading. A genuine beacon from the morning and a
///    genuine token from the evening are both real and both signed, and between them they say
///    nothing about a stamp taken at noon that a calendar would not.
/// 5. The interval the receipt claims covers the whole of what the two signatures enclose. They say
///    the moment was inside the bracket and nothing about where inside it, so a claim narrower than
///    the bracket, or one hanging over either edge of it, rests on the signer's own model whatever
///    the receipt calls it. Until 2026-09-15 this was not asked, and the committed receipt with its
///    basis rewritten was granted a sandwich on a 153.875 ms width inside a 2 s bracket, then told
///    the reader the width rested on outside signatures.
fn decide_basis(
    receipt: &Receipt,
    entries: &[EntryReport],
) -> Result<(bool, String), ReceiptError> {
    let claims_a_sandwich = receipt.claim.basis == EpsilonBasis::ThirdPartySandwich;
    let refuse_or_report = |reason: String| -> Result<(bool, String), ReceiptError> {
        if claims_a_sandwich {
            Err(ReceiptError::OurClaimAsEvidence(reason))
        } else {
            Ok((false, reason))
        }
    };

    let find = |role: Role| {
        entries
            .iter()
            .find(|e| e.role == role && e.outcome.is_checked())
    };
    let corridor = find(Role::AuthenticatedUtcCorridor);
    let beacon = find(Role::NotEarlierThan);
    let witness = find(Role::NotLaterThan);

    // The same bracket the verifier prints under its verdict, so the figure a sandwich is judged on
    // and the figure a reader is shown are one number: the latest checked beacon against the
    // earliest checked witness, rather than whichever of each the receipt happened to list first.
    let bracket = Bracket::of(entries);
    let (Some(not_earlier), Some(not_later), true) =
        (bracket.not_earlier, bracket.not_later, corridor.is_some())
    else {
        return refuse_or_report(format!(
            "of the three roles a sandwich is made of, this verifier checked corridor: {}, \
             not-earlier-than: {}, not-later-than: {}. A basis that cannot be checked is not \
             granted, so the bound rests on the agent's own model",
            corridor.is_some(),
            beacon.is_some(),
            witness.is_some()
        ));
    };
    let width = not_later - not_earlier;

    if width < 0 {
        return refuse_or_report(format!(
            "the not-later-than attestation is dated {} ns before the not-earlier-than value, so \
             the two do not enclose anything",
            -width
        ));
    }
    if width > SANDWICH_WIDTH_CEILING {
        return refuse_or_report(format!(
            "the two outside signatures are {} s apart, which is wider than the {} s this format \
             will call a sandwich, so they say nothing about this reading that a calendar would not",
            width / NANOS_PER_SEC,
            SANDWICH_WIDTH_CEILING / NANOS_PER_SEC
        ));
    }

    // The claim has to cover the bracket, edge to edge. The signatures put the moment somewhere
    // inside it and say nothing about where, so any part of the bracket the claim leaves out is a
    // part the signer ruled out on its own model, and any part of the claim outside the bracket
    // is one the signatures never spoke to. The width itself is not compared, because a claim as
    // wide as the bracket and shifted off it would pass a width test and still rest on the signer.
    let claim = &receipt.claim;
    let covers = claim.earliest <= not_earlier && claim.latest >= not_later;
    if claims_a_sandwich && !covers {
        return Err(ReceiptError::OurClaimAsEvidence(format!(
            "the two outside signatures enclose {width} ns and the interval this receipt claims \
             is {} ns wide and does not cover them, so they say the moment was inside those \
             {width} ns and nothing about which {} ns of them; the width rests on the signer's own \
             model and this receipt puts it where outside evidence goes",
            receipt.width(),
            receipt.width()
        )));
    }

    // Two different things can be true here and the report has to say which. The receipt may claim a
    // sandwich, in which case the claim is granted. Or it may claim its bound rests on the agent's
    // own model, in which case the sandwich holds up but the receipt is not resting on it, and a
    // reader told "does not rest on third-party evidence" followed by a reason that reads like it
    // does has been handed a contradiction to resolve on their own.
    if claims_a_sandwich {
        return Ok((
            true,
            format!(
                "all three roles were checked against keys chosen in advance, the two outside \
                 signatures enclose {} s, and the interval this receipt claims covers them",
                width / NANOS_PER_SEC
            ),
        ));
    }
    Ok((
        false,
        format!(
            "this receipt says its bound rests on the agent's own model, and it is judged on that. \
             All three roles were checked anyway, against keys chosen in advance, and the two \
             outside signatures enclose {} s, so the moment is pinned from outside {}",
            width / NANOS_PER_SEC,
            if covers {
                "and the interval it claims covers them, which it did not rest on"
            } else {
                "even though the width is not"
            }
        ),
    ))
}

/// Check each entry against the interval it is offered as support for.
///
/// An entry states an instant and, where it has one, a radius around it. The comparison always
/// takes the end of that interval which is hardest on the entry, so a wide radius never buys an
/// entry a pass it would not have had as a point.
fn check_evidence_against_the_interval(receipt: &Receipt) -> Result<(), ReceiptError> {
    for e in &receipt.evidence {
        let radius = e.radius.unwrap_or(0).max(0);
        let earliest = e.at - radius;
        let latest = e.at + radius;

        match e.role {
            Role::NotEarlierThan => {
                if earliest > receipt.claim.latest {
                    return Err(ReceiptError::Inconsistent(format!(
                        "a not-earlier-than value was published after the latest time this receipt \
                         claims, by {} ns, so it cannot be evidence for this reading",
                        earliest - receipt.claim.latest
                    )));
                }
            }
            Role::NotLaterThan => {
                if latest < receipt.claim.earliest {
                    return Err(ReceiptError::Inconsistent(format!(
                        "a not-later-than attestation is dated before the earliest time this \
                         receipt claims, by {} ns, so it cannot be evidence for this reading",
                        receipt.claim.earliest - latest
                    )));
                }
            }
            // A corridor supports the reading only if the interval it asserts and the interval the
            // receipt claims have some instant in common. Two intervals that never meet cannot both
            // hold the same event, so one of them is wrong and the receipt does not get to say
            // which. A corridor with no radius was refused earlier, so there is always a width here.
            Role::AuthenticatedUtcCorridor => {
                if latest < receipt.claim.earliest || earliest > receipt.claim.latest {
                    return Err(ReceiptError::Inconsistent(format!(
                        "an authenticated corridor asserts {} ns to {} ns and the receipt claims \
                         {} ns to {} ns. The two do not overlap, so the corridor is not evidence \
                         for this reading",
                        earliest.as_nanos(),
                        latest.as_nanos(),
                        receipt.claim.earliest.as_nanos(),
                        receipt.claim.latest.as_nanos()
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::nonce_value;

    #[test]
    fn a_nonce_is_compared_as_a_value_and_not_as_a_run_of_bytes() {
        // The case this exists for, and it arrives one stamp in two hundred and fifty-six. The
        // agent generates sixteen random bytes; where the first is zero, the DER integer in the
        // token is fifteen bytes with the same value, and comparing the two as written would refuse
        // a receipt that is entirely honest.
        let generated = [0x00u8, 0x9a, 0x14, 0x7c];
        let read_back = [0x9au8, 0x14, 0x7c];
        assert_eq!(nonce_value(&generated), nonce_value(&read_back));

        // Two different values stay different, which is the whole point of the comparison.
        assert_ne!(nonce_value(&[0x01u8, 0x02]), nonce_value(&[0x01u8, 0x03]));

        // A nonce of nothing but zeros reduces to one zero rather than to nothing at all, so it
        // still compares as a value rather than as an empty slice matching everything.
        assert_eq!(nonce_value(&[0u8; 32]), &[0u8]);
        assert_eq!(nonce_value(&[]), &[] as &[u8]);
    }
}
