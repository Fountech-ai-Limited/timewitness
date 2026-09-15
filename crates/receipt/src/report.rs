//! What a verifier says it checked, entry by entry.
//!
//! This type exists because of a specific failure this product is built to avoid. A verifier that
//! prints "valid" has told a reader nothing about which of a receipt's claims were tested and which
//! were taken on trust, and those are very different receipts. So the answer to "is this receipt
//! good" is not a boolean here. It is a list of what was looked at, what each thing was checked
//! against, and which of them the strongest claim in the receipt actually rests on.
//!
//! A reader who never spoke to us can therefore see the shape of the answer: three entries checked
//! against three named keys, or two checked and one unchecked because the verifier does not hold
//! that server's key, or none checked at all.

use crate::schema::Role;
use timewitness_core::time::Nanos;
use timewitness_core::UnixNanos;

/// What happened when one evidence entry was looked at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The blob was verified against an anchor the verifier holds.
    Checked {
        /// Who the anchor says signed it.
        signer: String,
        /// What was checked, one line each.
        checks: Vec<String>,
        /// The earliest instant the signed content supports.
        earliest: UnixNanos,
        /// The latest.
        latest: UnixNanos,
    },
    /// The verifier holds nothing to check this entry against.
    ///
    /// Not a fault in the receipt. It is a fact about the verifier, and it is reported rather than
    /// glossed over, because an entry nobody checked supports nothing.
    NotChecked(String),
}

impl Outcome {
    /// Whether this entry was actually verified.
    #[must_use]
    pub fn is_checked(&self) -> bool {
        matches!(self, Outcome::Checked { .. })
    }
}

/// One line of a verifier's report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryReport {
    /// What the entry claims to prove.
    pub role: Role,
    /// What it is.
    pub scheme: String,
    /// Which server or round, where the receipt said.
    pub detail: Option<String>,
    /// What happened when it was looked at.
    pub outcome: Outcome,
}

/// Everything a verifier established about one receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// One line per evidence entry, in the order the receipt carries them.
    pub entries: Vec<EntryReport>,
    /// Whether the receipt's claim to rest on third-party evidence was granted.
    pub basis_granted: bool,
    /// Why, in words, whether it was granted or not.
    pub basis_reason: String,
    /// How many anchors the verifier was holding when it read this.
    pub anchors_held: usize,
}

/// What the checked outside evidence says about when, and nothing the receipt says about itself.
///
/// The latest moment a checked not-earlier-than entry puts the receipt after, and the earliest
/// moment a checked not-later-than entry puts the thing it stamps before. A reader who trusts
/// neither party can hold a receipt to this and to nothing narrower: the width inside it is the
/// signer's own claim unless the receipt rests on a sandwich and the sandwich was granted.
///
/// One computation for two readers. The basis decision sizes a sandwich with it and the verifier's
/// line under the verdict prints it, so the figure a reader sees there and the figure the grant was
/// judged on cannot come apart. Until 2026-09-15 the decision took the first checked entry of each
/// role, so a receipt carrying an old beacon beside a fresh one was sized on the old one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bracket {
    /// The latest not-earlier-than edge among the checked entries, where there is one.
    pub not_earlier: Option<UnixNanos>,
    /// The earliest not-later-than edge among the checked entries, where there is one.
    pub not_later: Option<UnixNanos>,
}

impl Bracket {
    /// The bracket the checked entries of one receipt put round its moment.
    ///
    /// A corridor is left out on purpose. It is a signed interval about the moment its server
    /// answered, and the receipt is held to overlap it rather than to sit inside it, so it is
    /// reported beside the bracket and never narrows it.
    #[must_use]
    pub fn of(entries: &[EntryReport]) -> Self {
        let mut bracket = Bracket::default();
        for entry in entries {
            let Outcome::Checked {
                earliest, latest, ..
            } = &entry.outcome
            else {
                continue;
            };
            match entry.role {
                Role::NotEarlierThan => {
                    bracket.not_earlier = Some(
                        bracket
                            .not_earlier
                            .map_or(*earliest, |at| at.max(*earliest)),
                    );
                }
                Role::NotLaterThan => {
                    bracket.not_later =
                        Some(bracket.not_later.map_or(*latest, |at| at.min(*latest)));
                }
                Role::AuthenticatedUtcCorridor => {}
            }
        }
        bracket
    }

    /// How far apart the two edges are, where both were checked. Negative where the two contradict
    /// each other, which is a thing a reader has to be told rather than a width.
    #[must_use]
    pub fn width(&self) -> Option<Nanos> {
        match (self.not_earlier, self.not_later) {
            (Some(earlier), Some(later)) => Some(later - earlier),
            _ => None,
        }
    }
}

impl Verified {
    /// The bracket the checked outside evidence puts round this receipt's moment.
    #[must_use]
    pub fn bracket(&self) -> Bracket {
        Bracket::of(&self.entries)
    }

    /// How many entries were actually checked.
    #[must_use]
    pub fn checked(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.outcome.is_checked())
            .count()
    }

    /// The report as lines a person reads, which is what the verifier prints.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.entries.is_empty() {
            out.push("This receipt carries no third-party evidence at all.".to_string());
        }
        for entry in &self.entries {
            let what = entry.detail.as_deref().unwrap_or("no detail given");
            match &entry.outcome {
                Outcome::Checked { signer, checks, .. } => {
                    out.push(format!(
                        "{} by {} from {what}: checked against {signer}",
                        entry.role.as_str(),
                        entry.scheme
                    ));
                    for check in checks {
                        out.push(format!("    {check}"));
                    }
                }
                Outcome::NotChecked(why) => {
                    out.push(format!(
                        "{} by {} from {what}: not checked, {why}",
                        entry.role.as_str(),
                        entry.scheme
                    ));
                }
            }
        }
        out.push(format!(
            "The bound in this receipt {} rest on third-party evidence: {}",
            if self.basis_granted {
                "does"
            } else {
                "does not"
            },
            self.basis_reason
        ));
        out
    }
}
