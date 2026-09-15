//! Receipt format v0: the fields, and what each one is allowed to say.
//!
//! A receipt is a long-lived thing. It has to keep meaning what it meant to a verifier that never
//! spoke to us, years after it was issued, so the format is frozen and carries its own version
//! number from the first release.
//!
//! The shape of it is the point, more than the field list. There are two separate places a
//! statement about time can sit, and they are not interchangeable:
//!
//! - `claim` holds the agent's own bound. It is the most precise number in the receipt and the only
//!   one that rests on trusting us. It carries a fixed discriminant saying exactly that, and it has
//!   no role field and no signed blob, so nothing about its shape lets it pass for evidence.
//!
//! - `evidence` holds third-party attestations, each labelled with what it proves and each carrying
//!   the raw signed response in full so a stranger can check the signature themselves.
//!
//! Presenting the first as the second is the central dishonesty available to a product in this
//! field. Here it is not a policy anybody has to remember: the two are different shapes, and the
//! validator refuses a receipt that blurs them.

use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, HashFunction, LeapIndicator,
    MonotonicNanos, Nanos, Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState,
    Stamp, Timescale, UnixNanos,
};

use crate::error::ReceiptError;
use crate::value::Value;

/// The version this code writes and reads.
pub const FORMAT_VERSION: i128 = 0;

/// The fixed discriminant on the agent's own claim.
pub const CLAIM_KIND: &str = "agent-bound";

/// What a piece of evidence proves.
///
/// Three roles, and they do different jobs. Nothing in this format lets one stand in for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// An authenticated corridor of UTC. It pins the moment from outside and never narrows the
    /// bound, which is the signer's own claim whatever the corridor says.
    AuthenticatedUtcCorridor,
    /// Proof the receipt cannot have been made before some public moment.
    NotEarlierThan,
    /// Proof the receipt cannot have been made after some public moment.
    NotLaterThan,
}

impl Role {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::AuthenticatedUtcCorridor => "authenticated-utc-corridor",
            Role::NotEarlierThan => "not-earlier-than",
            Role::NotLaterThan => "not-later-than",
        }
    }

    /// A role from its wire spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authenticated-utc-corridor" => Some(Role::AuthenticatedUtcCorridor),
            "not-earlier-than" => Some(Role::NotEarlierThan),
            "not-later-than" => Some(Role::NotLaterThan),
            _ => None,
        }
    }
}

/// What kind of thing a piece of evidence actually is.
///
/// Held as a string rather than a closed list so that an unknown or a forbidden scheme reaches the
/// validator and gets refused with a reason, instead of failing to parse with a shrug.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scheme(String);

impl Scheme {
    /// A scheme from its wire spelling.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The wire spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Which role this scheme is able to support, if any.
    ///
    /// This is the table the whole format turns on, so it is written once, here.
    #[must_use]
    pub fn proves(&self) -> Option<Role> {
        match self.0.as_str() {
            // The server signs over a nonce we generated, so a stranger can check it.
            "roughtime" => Some(Role::AuthenticatedUtcCorridor),
            // A value nobody could have known before its round was published.
            "drand" | "nist-beacon" | "uchile-beacon" => Some(Role::NotEarlierThan),
            // An outside party's own public record that it saw this.
            "rfc3161" | "rfc9921" | "transparency-log" | "opentimestamps" => {
                Some(Role::NotLaterThan)
            }
            _ => None,
        }
    }

    /// Whether this names something of ours rather than a third party's.
    ///
    /// Network time security belongs on this list and the reason is worth stating plainly. It
    /// improves the clock and it can never be portable evidence, because it authenticates packets
    /// with a symmetric key that the client also holds. A client holding that key could forge a
    /// response to itself, and a stranger has no signature to check. So an evidence entry claiming
    /// to carry one is refused, by name.
    #[must_use]
    pub fn is_ours_rather_than_a_third_partys(&self) -> bool {
        matches!(
            self.0.as_str(),
            "nts" | "ntp" | "agent-bound" | "local-model" | "shadow-clock"
        )
    }
}

/// One third-party attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// What this entry claims to prove.
    pub role: Role,
    /// What it actually is.
    pub scheme: Scheme,
    /// The instant it pins, in nanoseconds from the Unix epoch.
    pub at: UnixNanos,
    /// Half the width of the interval this entry asserts, where it asserts an interval.
    ///
    /// A Roughtime response is a midpoint and a radius, and the radius is the whole of what makes
    /// it checkable: without it a corridor entry cannot say what interval it proves and nothing can
    /// test it against the interval the receipt claims. A corridor entry must carry one. A beacon
    /// and a timestamp authority assert an instant, so theirs is `None`, and where one does carry a
    /// radius the check takes the conservative end of it.
    pub radius: Option<Nanos>,
    /// The raw signed response, in full, so a stranger can check it without asking us for anything.
    pub blob: Vec<u8>,
    /// The nonce we generated, where the scheme signs over one.
    pub nonce: Option<Vec<u8>>,
    /// Which server or round this came from, for a person reading the receipt.
    pub detail: Option<String>,
}

/// What each source was doing when the reading was taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRecord {
    /// The source's name.
    pub id: String,
    /// Who runs it, where the agent said.
    ///
    /// The count of independent operators is deliberately not a field of its own. A count is our
    /// arithmetic and a reader would have to take it on trust; the labels are what the agent
    /// observed, and a reader who has them can do the counting and get a different answer if ours is
    /// wrong. That is the same reason the source list is carried in full beside `sources_kept`.
    ///
    /// `None` on a receipt written before the field existed, and on a source whose operator the
    /// agent could not name. Absent is not the same as unknown-and-stated, and it is not the same as
    /// nought: a validator that cannot tell them apart cannot tell an old receipt from one hiding
    /// how few parties stood behind it. Every absent operator in one receipt is read as one shared
    /// unknown party rather than as one party each, which is the direction that refuses.
    ///
    /// Added 2026-09-09.
    pub operator: Option<String>,
    /// What it speaks.
    pub kind: String,
    /// The timescale it answers on.
    pub timescale: String,
    /// What it does with a leap second.
    pub smear: String,
    /// What it said about an upcoming leap second.
    pub leap: String,
    /// Whether the selection kept it.
    pub kept: bool,
    /// Whether the party running it is the one that issued this receipt.
    ///
    /// `true` for a time server the issuing deployment runs itself. Such a source disciplines the
    /// clock like any other and its interval is a real measurement; what it is not is an
    /// independent chance to be wrong, because its faults and the agent's are the same party's. So
    /// it is left out of both operator counts, and this field is how a reader sees that it was
    /// there at all rather than having to take the count on trust.
    ///
    /// It exists because our own word is never third-party evidence. A deployment running its own
    /// Roughtime servers and not saying so would put its own word inside the number that is
    /// supposed to be free of it, and every signature would still verify.
    ///
    /// **Absent on the wire when false**, which is every receipt written before 2026-09-12 and
    /// every receipt from a deployment that runs no servers of its own. Absent reads as `false`,
    /// and that is the one place in this struct where absent and a stated value are the same
    /// thing: a receipt that could not have said so was issued by a deployment that had no
    /// first-party sources to declare. Reading absent as `true` would refuse every receipt ever
    /// issued, and reading it as unknown would make the counts unanswerable.
    ///
    /// Added 2026-09-12.
    pub first_party: bool,
}

impl SourceRecord {
    fn from_state(s: &SourceState) -> Self {
        Self {
            id: s.id.as_str().to_string(),
            first_party: s.operator.is_first_party(),
            operator: match s.operator.as_str() {
                "" => None,
                named => Some(named.to_string()),
            },
            kind: s.kind.as_wire().to_string(),
            timescale: match s.timescale {
                Timescale::Utc => "utc".to_string(),
                Timescale::Tai { offset_seconds } => format!("tai+{offset_seconds}"),
                Timescale::Unknown => "unknown".to_string(),
            },
            smear: match s.smear {
                SmearPolicy::None => "none".to_string(),
                SmearPolicy::Linear { window_seconds } => format!("linear/{window_seconds}"),
                SmearPolicy::Unknown => "unknown".to_string(),
            },
            leap: match s.leap {
                LeapIndicator::None => "none",
                LeapIndicator::AddSecond => "add-second",
                LeapIndicator::DeleteSecond => "delete-second",
                LeapIndicator::Unsynchronised => "unsynchronised",
            }
            .to_string(),
            kept: s.kept,
        }
    }
}

/// The agent's own bound, and everything about how it was arrived at.
///
/// Structurally its own thing. It has a `kind` and no `role`, and it has no `blob`, because there is
/// nothing signed by anybody else in here. That is what stops it being read as evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentClaim {
    /// The earliest UTC the reading could correspond to.
    pub earliest: UnixNanos,
    /// The latest UTC the reading could correspond to.
    pub latest: UnixNanos,
    /// Whether this interval rests on a third-party sandwich or on our own model alone.
    pub basis: EpsilonBasis,
    /// How the sources were combined.
    pub fusion: String,
    /// How many sources answered.
    pub sources_offered: u32,
    /// How many survived selection.
    pub sources_kept: u32,
    /// Where the width came from, part by part.
    pub breakdown: BreakdownRecord,
    /// How long since the last good synchronisation.
    pub since_last_sync: Nanos,
    /// The measured frequency error, in parts per billion, so it stays a whole number.
    pub frequency_ppb: i64,
    /// Which boot of the machine this was.
    pub boot_generation: u64,
    /// Which resume within that boot.
    pub resume_generation: u64,
    /// What every source was doing.
    pub sources: Vec<SourceRecord>,
    /// The parts of the agent's own policy a stranger can hold it to.
    pub policy: PolicyRecord,
}

impl AgentClaim {
    /// Whether one listed source was a candidate for the intersection.
    ///
    /// A source that told the agent its own clock was not synchronised answered and was never a
    /// candidate. It stays in the list, marked as not kept, so a reader can see that it answered
    /// and see why the counts are what they are.
    ///
    /// **Written once because three tests in two crates turn on it.** The operator count below, the
    /// majority test in `validate`, and the reader's own floor over in `timewitness_verify` all ask
    /// which sources could have disagreed with anybody, and a rule written three times is a rule
    /// that drifts. That has happened once already, when one of them counted every source that
    /// answered.
    #[must_use]
    pub fn was_a_candidate(source: &SourceRecord) -> bool {
        source.leap != "unsynchronised"
    }

    /// How many of the sources that answered were candidates for the intersection.
    ///
    /// `sources_offered` is how many answered, which is the length of the list beside it. This is
    /// the smaller number the majority is taken over, and it is counted from the list rather than
    /// stated in the receipt, for the same reason the operator count is: a stated count is the
    /// agent's arithmetic and a reader would be checking it against itself.
    #[must_use]
    pub fn candidates(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| Self::was_a_candidate(s))
            .count()
    }

    /// The distinct parties behind the sources that answered, and behind the sources that were
    /// kept, counted from the labels in that order.
    ///
    /// **Counted here once because two shells of this product ask the same question.** The receipt
    /// crate asks whether the agent kept to its own stated floor; the verifier asks whether the
    /// receipt clears a floor the reader brought. Those are different questions with the same
    /// arithmetic behind them, and an arithmetic written twice is an arithmetic that drifts. Two
    /// shells of one product refusing each other's artefacts is a lesson this product has already
    /// paid for once, and this is the same boundary.
    ///
    /// Three rules are in the counting and each of them lowers the answer rather than raising it.
    /// A source that told the agent its own clock was not synchronised was never a candidate, so it
    /// is neither offered nor kept here, though it stays in the list so a reader can see why the
    /// counts are what they are. A source whose operator the receipt does not name is read as the
    /// same unknown party as every other unnamed source, so a gap in the labels can only ever cost
    /// a receipt a test and never win it. And a receipt naming no operator anywhere counts one
    /// unknown party rather than none, because it did have sources; what it does not have is any
    /// way to show they were run by different people.
    /// **A party that is us is in neither count and is reported on its own.** The same rule the
    /// model applies when it decides whether to sign, applied again here by a reader who has only
    /// the receipt. A name is treated as ours the moment any source under it says so, which is the
    /// merging direction: it can only ever lower the independent count and refuse.
    #[must_use]
    pub fn operators(&self) -> Operators {
        let candidate = |s: &&SourceRecord| Self::was_a_candidate(s);
        let named = |s: &SourceRecord| s.operator.clone().unwrap_or_default();
        let ours: std::collections::BTreeSet<String> = self
            .sources
            .iter()
            .filter(|s| s.first_party)
            .map(named)
            .collect();
        let independent = |s: &&SourceRecord| !ours.contains(&named(s));
        Operators {
            offered: self
                .sources
                .iter()
                .filter(candidate)
                .filter(independent)
                .map(named)
                .collect::<std::collections::BTreeSet<String>>()
                .len(),
            kept: self
                .sources
                .iter()
                .filter(candidate)
                .filter(independent)
                .filter(|s| s.kept)
                .map(named)
                .collect::<std::collections::BTreeSet<String>>()
                .len(),
            first_party: ours.len(),
        }
    }

    /// The source list as a value tree, for a reader that is a program rather than a person.
    ///
    /// Both machine-readable surfaces this product ships, the command line's `--json` and the
    /// verifier page, carried the two source counts and nothing else until 2026-09-10. A count of
    /// names is the flattering number, so a caller reading either of them could not tell nine
    /// addresses at one company from nine at nine, and could not see which kinds answered. Written
    /// here once because two surfaces rendering the same thing twice is two surfaces that drift.
    ///
    /// It is a view and never a format. Nothing is parsed back from it and nothing is signed over
    /// it; the receipt bytes are the artefact and this is what a script reads instead of grepping
    /// prose.
    #[must_use]
    pub fn sources_as_value(&self) -> Value {
        Value::Array(
            self.sources
                .iter()
                .map(|s| {
                    Value::map([
                        ("id", Value::text(s.id.clone())),
                        (
                            "operator",
                            match &s.operator {
                                Some(named) => Value::text(named.clone()),
                                None => Value::Null,
                            },
                        ),
                        ("kind", Value::text(s.kind.clone())),
                        ("kept", Value::Bool(s.kept)),
                        ("first_party", Value::Bool(s.first_party)),
                        ("leap", Value::text(s.leap.clone())),
                    ])
                })
                .collect(),
        )
    }

    /// Whether this receipt names an operator for any of its sources at all.
    ///
    /// Absent everywhere means the receipt predates the field, which is one receipt in this
    /// repository and none anybody else holds because nothing has been released. It is kept apart
    /// from a count of one because the two deserve different sentences: a receipt that could not
    /// have named a party is a different thing from a receipt that named one.
    #[must_use]
    pub fn names_no_operator(&self) -> bool {
        self.sources.iter().all(|s| s.operator.is_none())
    }
}

/// How many distinct parties stood behind a receipt's sources.
///
/// Both numbers, because either alone is misleading. `kept` on its own does not say whether the
/// selection threw away a party's worth of disagreement, and `offered` on its own is the flattering
/// figure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Operators {
    /// Distinct independent parties among the sources that answered and were candidates.
    pub offered: usize,
    /// Distinct independent parties among the sources selection kept.
    pub kept: usize,
    /// Distinct parties among the sources that were the issuer itself.
    ///
    /// Reported, never enforced. It is here so that a reader can see the difference between a
    /// round of three strangers and a round of two strangers and one of our own, which the other
    /// two numbers alone cannot show.
    pub first_party: usize,
}

/// The agent's own limits, carried so a reader can hold the agent to its own word.
///
/// These are not a claim that the policy is a good one. A reader judges the numbers against a floor
/// they brought themselves. What the block is for is the simpler question of whether the agent kept
/// to what it said, and that question can only be asked about limits the receipt states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyRecord {
    /// The widest interval this agent would have signed for.
    pub max_bound_width: Nanos,
    /// How many sources this agent requires before it will answer at all.
    pub min_sources: u32,
    /// How many distinct operators this agent requires among the sources that survived selection.
    ///
    /// A floor on parties rather than on names, which is the only version of the number that means
    /// anything: several addresses at one company clear a floor on sources without adding a single
    /// chance to disagree. `None` where the receipt predates the field, read as absent rather than
    /// as nought for the same reason `max_holdover` is.
    ///
    /// Added 2026-09-09.
    pub min_operators: Option<u32>,
    /// The longest this agent will extrapolate from an exchange before it refuses instead.
    ///
    /// `None` where the receipt predates the field, which is one receipt in this repository and no
    /// receipt anybody else holds, because nothing has been released. It is an `Option` rather than
    /// a zero because zero is a value the field could honestly hold, and a reader that cannot tell
    /// an absent limit from a stated one is the fault this whole block exists to close.
    ///
    /// Added 2026-09-08. Without it a reader can see `since_last_sync` and has no way to know
    /// whether the agent thought that was inside its own ceiling.
    pub max_holdover: Option<Nanos>,
}

/// The parts of the width, as the receipt carries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BreakdownRecord {
    /// Half the Marzullo intersection at the last synchronisation.
    pub intersection_half: Nanos,
    /// The largest half round trip among the surviving sources. Reported, not part of the sum.
    pub network_half: Nanos,
    /// The allowance for the local read.
    pub scheduling: Nanos,
    /// Growth since the last synchronisation.
    pub oscillator_holdover: Nanos,
    /// The regression's own standard error, carried through.
    pub model_residual: Nanos,
    /// A fixed allowance for what the model does not describe.
    pub safety_margin: Nanos,
}

impl BreakdownRecord {
    fn from_core(b: &BoundBreakdown) -> Self {
        Self {
            intersection_half: b.intersection_half,
            network_half: b.widest_source_network_half,
            scheduling: b.scheduling,
            oscillator_holdover: b.oscillator_holdover,
            model_residual: b.model_residual,
            safety_margin: b.safety_margin,
        }
    }

    /// The parts that make up half the width. The network figure is excluded, because it already
    /// sits inside the intersection term.
    #[must_use]
    pub const fn half_width(&self) -> Nanos {
        self.intersection_half
            + self.scheduling
            + self.oscillator_holdover
            + self.model_residual
            + self.safety_margin
    }
}

/// What is being stamped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Which hash function was used.
    pub algorithm: String,
    /// The hash of the thing.
    pub hash: Vec<u8>,
}

impl Payload {
    /// The length in bytes the named algorithm produces, if this code knows the algorithm.
    ///
    /// The table itself is in `timewitness_core::hash`, because the evidence checker tests a
    /// token's own imprint against the same numbers and two copies of a table is two things to
    /// keep right.
    #[must_use]
    pub fn expected_length(&self) -> Option<usize> {
        HashFunction::from_receipt_name(&self.algorithm).map(HashFunction::length)
    }
}

/// A receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// Which version of this format the receipt is written in.
    pub version: i128,
    /// Where this receipt sits in a chain of them.
    pub sequence: u64,
    /// The hash of the previous receipt in the chain, where there is one.
    pub chain_previous: Option<Vec<u8>>,
    /// What is being stamped.
    pub payload: Payload,
    /// The raw monotonic counter value, in nanoseconds.
    pub monotonic: u64,
    /// The point estimate of UTC. Display only; the claim is the interval.
    pub utc_estimate: UnixNanos,
    /// The agent's own bound.
    pub claim: AgentClaim,
    /// Third-party attestations.
    pub evidence: Vec<Evidence>,
    /// The agent's public key, so a receipt is self-contained.
    pub agent_public_key: Vec<u8>,
}

impl Receipt {
    /// Build a receipt from a stamp the clock model produced.
    ///
    /// No evidence is attached here. The evidence clients fetch their own and add it, which keeps
    /// the two apart in the code as well as in the format.
    #[must_use]
    pub fn from_stamp(
        stamp: &Stamp,
        sequence: u64,
        chain_previous: Option<Vec<u8>>,
        payload: Payload,
        agent_public_key: Vec<u8>,
        policy: PolicyRecord,
    ) -> Self {
        let (offered, kept) = match stamp.bound.breakdown.fusion {
            FusionRule::MarzulloThenInverseSquare { offered, kept } => {
                (offered as u32, kept as u32)
            }
        };

        Self {
            version: FORMAT_VERSION,
            sequence,
            chain_previous,
            payload,
            monotonic: stamp.reading.monotonic.as_nanos(),
            utc_estimate: stamp.reading.utc_estimate,
            claim: AgentClaim {
                earliest: stamp.bound.earliest,
                latest: stamp.bound.latest,
                basis: stamp.bound.basis,
                fusion: "marzullo-then-inverse-square".to_string(),
                sources_offered: offered,
                sources_kept: kept,
                breakdown: BreakdownRecord::from_core(&stamp.bound.breakdown),
                since_last_sync: stamp.since_last_sync,
                // Zero is the wire spelling for "no rate is claimed", which is what the model
                // reports before it has fitted anything and after a fit its own baseline could not
                // support. The format document says so beside the field. Nothing is hidden by it:
                // whatever the fit allowed is already in the width.
                frequency_ppb: stamp
                    .frequency_ppm
                    .map_or(0, |ppm| (ppm * 1_000.0).round() as i64),
                boot_generation: stamp.generations.boot,
                resume_generation: stamp.generations.resume,
                sources: stamp.sources.iter().map(SourceRecord::from_state).collect(),
                policy,
            },
            evidence: Vec::new(),
            agent_public_key,
        }
    }

    /// The stamp this receipt carries, as the clock model's own types.
    ///
    /// Useful to a verifier that wants to work with the interval rather than with the wire fields.
    #[must_use]
    pub fn as_stamp(&self) -> Stamp {
        Stamp {
            reading: Reading {
                monotonic: MonotonicNanos(self.monotonic),
                utc_estimate: self.utc_estimate,
            },
            bound: Bound {
                earliest: self.claim.earliest,
                latest: self.claim.latest,
                basis: self.claim.basis,
                breakdown: BoundBreakdown {
                    fusion: FusionRule::MarzulloThenInverseSquare {
                        offered: self.claim.sources_offered as usize,
                        kept: self.claim.sources_kept as usize,
                    },
                    intersection_half: self.claim.breakdown.intersection_half,
                    widest_source_network_half: self.claim.breakdown.network_half,
                    scheduling: self.claim.breakdown.scheduling,
                    oscillator_holdover: self.claim.breakdown.oscillator_holdover,
                    model_residual: self.claim.breakdown.model_residual,
                    safety_margin: self.claim.breakdown.safety_margin,
                },
            },
            sources: self
                .claim
                .sources
                .iter()
                .map(|s| SourceState {
                    id: SourceId::new(s.id.clone()),
                    // A source the receipt does not name an operator for reads as the empty
                    // identity, and every such source in one receipt shares it, so they count as
                    // one party between them rather than one each. That is the merging direction,
                    // which refuses; see `timewitness_core::Operator`.
                    operator: Operator::new(s.operator.clone().unwrap_or_default()),
                    kind: match s.kind.as_str() {
                        "nts" => SourceKind::Nts,
                        "roughtime" => SourceKind::Roughtime,
                        "local-hardware" => SourceKind::LocalHardware,
                        _ => SourceKind::Ntp,
                    },
                    timescale: Timescale::Utc,
                    smear: SmearPolicy::Unknown,
                    leap: LeapIndicator::None,
                    kept: s.kept,
                })
                .collect(),
            generations: Generations {
                boot: self.claim.boot_generation,
                resume: self.claim.resume_generation,
            },
            since_last_sync: self.claim.since_last_sync,
            frequency_ppm: (self.claim.frequency_ppb != 0)
                .then(|| self.claim.frequency_ppb as f64 / 1_000.0),
        }
    }

    /// The width of the claimed interval.
    #[must_use]
    pub fn width(&self) -> Nanos {
        self.claim.latest - self.claim.earliest
    }

    /// The receipt as a value tree, ready to be encoded or rendered.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut top: Vec<(&'static str, Value)> = vec![
            ("v", Value::Int(self.version)),
            ("seq", Value::Int(i128::from(self.sequence))),
            (
                "payload",
                Value::map([
                    ("alg", Value::text(self.payload.algorithm.clone())),
                    ("hash", Value::Bytes(self.payload.hash.clone())),
                ]),
            ),
            (
                "reading",
                Value::map([
                    ("mono_ns", Value::Int(i128::from(self.monotonic))),
                    ("utc_ns", Value::Int(self.utc_estimate.as_nanos())),
                    // Named so that nobody has to be told twice. The interval is the claim.
                    ("midpoint_display_only", Value::Bool(true)),
                ]),
            ),
            ("claim", self.claim_value()),
            (
                "evidence",
                Value::Array(self.evidence.iter().map(evidence_value).collect()),
            ),
            (
                "agent",
                Value::map([("public_key", Value::Bytes(self.agent_public_key.clone()))]),
            ),
        ];

        if let Some(prev) = &self.chain_previous {
            top.push(("prev", Value::Bytes(prev.clone())));
        }

        Value::map(top)
    }

    fn claim_value(&self) -> Value {
        let c = &self.claim;
        Value::map([
            // The discriminant. A reader that finds this knows it is looking at our own model's
            // output and not at anybody else's signature.
            ("kind", Value::text(CLAIM_KIND)),
            ("earliest_ns", Value::Int(c.earliest.as_nanos())),
            ("latest_ns", Value::Int(c.latest.as_nanos())),
            (
                "basis",
                Value::text(match c.basis {
                    EpsilonBasis::ThirdPartySandwich => "third-party-sandwich",
                    EpsilonBasis::LocalModelOnly => "local-model-only",
                }),
            ),
            ("fusion", Value::text(c.fusion.clone())),
            ("sources_offered", Value::Int(i128::from(c.sources_offered))),
            ("sources_kept", Value::Int(i128::from(c.sources_kept))),
            (
                "breakdown",
                Value::map([
                    (
                        "intersection_half_ns",
                        Value::Int(c.breakdown.intersection_half),
                    ),
                    ("network_half_ns", Value::Int(c.breakdown.network_half)),
                    ("scheduling_ns", Value::Int(c.breakdown.scheduling)),
                    (
                        "oscillator_holdover_ns",
                        Value::Int(c.breakdown.oscillator_holdover),
                    ),
                    ("model_residual_ns", Value::Int(c.breakdown.model_residual)),
                    ("safety_margin_ns", Value::Int(c.breakdown.safety_margin)),
                ]),
            ),
            ("since_last_sync_ns", Value::Int(c.since_last_sync)),
            ("frequency_ppb", Value::Int(i128::from(c.frequency_ppb))),
            ("boot_generation", Value::Int(i128::from(c.boot_generation))),
            (
                "resume_generation",
                Value::Int(i128::from(c.resume_generation)),
            ),
            (
                "sources",
                Value::Array(
                    c.sources
                        .iter()
                        .map(|s| {
                            let mut fields = vec![
                                ("id", Value::text(s.id.clone())),
                                ("kind", Value::text(s.kind.clone())),
                                ("operator", operator_to_value(s.operator.as_deref())),
                                ("timescale", Value::text(s.timescale.clone())),
                                ("smear", Value::text(s.smear.clone())),
                                ("leap", Value::text(s.leap.clone())),
                                ("kept", Value::Bool(s.kept)),
                            ];
                            // Written only when it is true. A deployment that runs none of its own
                            // servers encodes to exactly the bytes it encoded to before this field
                            // existed, which is what keeps the committed fixture and every receipt
                            // already issued verifying unchanged. The absent case is read back as
                            // false below, and the field's own documentation says why that is the
                            // one place in this struct where absent and stated are the same thing.
                            if s.first_party {
                                fields.push(("first_party", Value::Bool(true)));
                            }
                            Value::map(fields)
                        })
                        .collect(),
                ),
            ),
            ("policy", policy_to_value(&c.policy)),
        ])
    }

    /// Read a receipt back out of a value tree.
    pub fn from_value(value: &Value) -> Result<Self, ReceiptError> {
        let version = int(value, "v")?;
        if version != FORMAT_VERSION {
            return Err(ReceiptError::UnknownVersion(version));
        }

        let sequence = u64::try_from(int(value, "seq")?)
            .map_err(|_| ReceiptError::Field("seq is not a sequence number".into()))?;

        let chain_previous = match value.get("prev") {
            None => None,
            Some(Value::Bytes(b)) => Some(b.clone()),
            Some(other) => {
                return Err(ReceiptError::Field(format!(
                    "prev should be a byte string and is {}",
                    other.kind_name()
                )))
            }
        };

        let payload_map = field(value, "payload")?;
        let payload = Payload {
            algorithm: text(payload_map, "alg")?.to_string(),
            hash: bytes(payload_map, "hash")?.to_vec(),
        };

        let reading = field(value, "reading")?;
        let monotonic = u64::try_from(int(reading, "mono_ns")?)
            .map_err(|_| ReceiptError::Field("mono_ns is not a counter value".into()))?;
        let utc_estimate = UnixNanos(int(reading, "utc_ns")?);

        let claim_map = field(value, "claim")?;
        let claim = claim_from_value(claim_map)?;

        let evidence_list = field(value, "evidence")?
            .as_array()
            .ok_or_else(|| ReceiptError::Field("evidence should be a list".into()))?;
        let mut evidence = Vec::with_capacity(evidence_list.len());
        for entry in evidence_list {
            evidence.push(evidence_from_value(entry)?);
        }

        let agent = field(value, "agent")?;
        let agent_public_key = bytes(agent, "public_key")?.to_vec();

        Ok(Self {
            version,
            sequence,
            chain_previous,
            payload,
            monotonic,
            utc_estimate,
            claim,
            evidence,
            agent_public_key,
        })
    }
}

fn evidence_value(e: &Evidence) -> Value {
    let mut pairs: Vec<(&'static str, Value)> = vec![
        // A role, which the agent's own claim never has, and a scheme naming what this actually is.
        ("role", Value::text(e.role.as_str())),
        ("scheme", Value::text(e.scheme.as_str().to_string())),
        ("at_ns", Value::Int(e.at.as_nanos())),
        // The signed response in full. A verifier checks this itself and never asks us.
        ("blob", Value::Bytes(e.blob.clone())),
    ];
    if let Some(r) = e.radius {
        pairs.push(("radius_ns", Value::Int(r)));
    }
    if let Some(n) = &e.nonce {
        pairs.push(("nonce", Value::Bytes(n.clone())));
    }
    if let Some(d) = &e.detail {
        pairs.push(("detail", Value::text(d.clone())));
    }
    Value::map(pairs)
}

fn evidence_from_value(value: &Value) -> Result<Evidence, ReceiptError> {
    let role_text = text(value, "role")?;
    let role = Role::parse(role_text).ok_or_else(|| ReceiptError::MislabelledEvidence {
        role: role_text.to_string(),
        scheme: value
            .get("scheme")
            .and_then(Value::as_text)
            .unwrap_or("nothing")
            .to_string(),
        why: "this format has three roles and that is not one of them".to_string(),
    })?;

    Ok(Evidence {
        role,
        scheme: Scheme::new(text(value, "scheme")?),
        at: UnixNanos(int(value, "at_ns")?),
        radius: match value.get("radius_ns") {
            Some(Value::Int(n)) => Some(*n),
            _ => None,
        },
        blob: bytes(value, "blob")?.to_vec(),
        nonce: match value.get("nonce") {
            Some(Value::Bytes(b)) => Some(b.clone()),
            _ => None,
        },
        detail: value
            .get("detail")
            .and_then(Value::as_text)
            .map(str::to_string),
    })
}

fn claim_from_value(value: &Value) -> Result<AgentClaim, ReceiptError> {
    let kind = text(value, "kind")?;
    if kind != CLAIM_KIND {
        return Err(ReceiptError::Field(format!(
            "the claim says its kind is {kind:?} and the only kind this format has is {CLAIM_KIND:?}"
        )));
    }

    let breakdown_map = field(value, "breakdown")?;
    let breakdown = BreakdownRecord {
        intersection_half: int(breakdown_map, "intersection_half_ns")?,
        network_half: int(breakdown_map, "network_half_ns")?,
        scheduling: int(breakdown_map, "scheduling_ns")?,
        oscillator_holdover: int(breakdown_map, "oscillator_holdover_ns")?,
        model_residual: int(breakdown_map, "model_residual_ns")?,
        safety_margin: int(breakdown_map, "safety_margin_ns")?,
    };

    let basis = match text(value, "basis")? {
        "third-party-sandwich" => EpsilonBasis::ThirdPartySandwich,
        "local-model-only" => EpsilonBasis::LocalModelOnly,
        other => {
            return Err(ReceiptError::Field(format!(
                "the basis of the bound is {other:?}, and this format knows two"
            )))
        }
    };

    let sources_list = field(value, "sources")?
        .as_array()
        .ok_or_else(|| ReceiptError::Field("the source list should be a list".into()))?;
    let mut sources = Vec::with_capacity(sources_list.len());
    for s in sources_list {
        sources.push(SourceRecord {
            id: text(s, "id")?.to_string(),
            operator: match s.get("operator") {
                None | Some(Value::Null) => None,
                Some(_) => Some(text(s, "operator")?.to_string()),
            },
            kind: text(s, "kind")?.to_string(),
            timescale: text(s, "timescale")?.to_string(),
            smear: text(s, "smear")?.to_string(),
            leap: text(s, "leap")?.to_string(),
            kept: s.get("kept").and_then(Value::as_bool).ok_or_else(|| {
                ReceiptError::Field("a source does not say whether it was kept".into())
            })?,
            first_party: match s.get("first_party") {
                None | Some(Value::Null) => false,
                Some(_) => s
                    .get("first_party")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        ReceiptError::Field(
                        "a source states whether its operator is the issuer and the value is not a \
                         boolean"
                            .into(),
                    )
                    })?,
            },
        });
    }

    let policy = field(value, "policy")?;

    Ok(AgentClaim {
        earliest: UnixNanos(int(value, "earliest_ns")?),
        latest: UnixNanos(int(value, "latest_ns")?),
        basis,
        fusion: text(value, "fusion")?.to_string(),
        sources_offered: small(int(value, "sources_offered")?, "sources_offered")?,
        sources_kept: small(int(value, "sources_kept")?, "sources_kept")?,
        breakdown,
        since_last_sync: int(value, "since_last_sync_ns")?,
        frequency_ppb: i64::try_from(int(value, "frequency_ppb")?)
            .map_err(|_| ReceiptError::Field("frequency_ppb is out of range".into()))?,
        boot_generation: u64::try_from(int(value, "boot_generation")?)
            .map_err(|_| ReceiptError::Field("boot_generation is out of range".into()))?,
        resume_generation: u64::try_from(int(value, "resume_generation")?)
            .map_err(|_| ReceiptError::Field("resume_generation is out of range".into()))?,
        sources,
        policy: PolicyRecord {
            max_bound_width: int(policy, "max_bound_width_ns")?,
            min_sources: small(int(policy, "min_sources")?, "min_sources")?,
            // Absent on a receipt written before the field existed, which is one receipt in this
            // repository and none outside it. Read as absent rather than as nought, so the
            // validator can tell a limit nobody stated from a limit of nothing.
            max_holdover: match policy.get("max_holdover_ns") {
                None => None,
                Some(_) => Some(int(policy, "max_holdover_ns")?),
            },
            min_operators: match policy.get("min_operators") {
                None => None,
                Some(_) => Some(small(int(policy, "min_operators")?, "min_operators")?),
            },
        },
    })
}

/// The policy block, as the receipt carries it.
///
/// A limit the agent does not state is left out of the map rather than written as a zero. Absent
/// and nought are different facts about what the agent promised, and a format that spells them the
/// same way makes an oversight indistinguishable from a promise.
fn policy_to_value(p: &PolicyRecord) -> Value {
    let mut pairs: Vec<(&'static str, Value)> = vec![
        ("max_bound_width_ns", Value::Int(p.max_bound_width)),
        ("min_sources", Value::Int(i128::from(p.min_sources))),
    ];
    if let Some(holdover) = p.max_holdover {
        pairs.push(("max_holdover_ns", Value::Int(holdover)));
    }
    if let Some(operators) = p.min_operators {
        pairs.push(("min_operators", Value::Int(i128::from(operators))));
    }
    Value::map(pairs)
}

/// One source's operator, as the receipt carries it.
///
/// A source whose operator the agent could not name is written as null rather than left out, so
/// every source in the list has the same set of keys and a reader can see the difference between an
/// agent that had nothing to say and a format that predates the field. The whole map is absent on an
/// old receipt; a null inside it is a present statement of ignorance.
fn operator_to_value(operator: Option<&str>) -> Value {
    match operator {
        Some(named) => Value::text(named.to_string()),
        None => Value::Null,
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, ReceiptError> {
    value
        .get(key)
        .ok_or_else(|| ReceiptError::Field(format!("there is no {key}")))
}

fn int(value: &Value, key: &str) -> Result<i128, ReceiptError> {
    field(value, key)?
        .as_int()
        .ok_or_else(|| ReceiptError::Field(format!("{key} should be a whole number")))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ReceiptError> {
    field(value, key)?
        .as_text()
        .ok_or_else(|| ReceiptError::Field(format!("{key} should be text")))
}

fn bytes<'a>(value: &'a Value, key: &str) -> Result<&'a [u8], ReceiptError> {
    field(value, key)?
        .as_bytes()
        .ok_or_else(|| ReceiptError::Field(format!("{key} should be a byte string")))
}

fn small(v: i128, key: &str) -> Result<u32, ReceiptError> {
    u32::try_from(v).map_err(|_| ReceiptError::Field(format!("{key} is out of range")))
}
