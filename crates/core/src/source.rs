//! What the model records about each time source it listens to.
//!
//! Two of these fields exist because of faults that would otherwise be silent. A source that smears
//! a leap second across a day and a source that steps it disagree by a second for that day, so
//! blending them without noticing corrupts the interval. And a machine that suspended between two
//! stamps has no idea how long it was away, so the receipt carries a generation count a verifier
//! can read.

use core::fmt;
use std::net::IpAddr;

/// A name for one time source, stable across restarts.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(String);

impl SourceId {
    /// A source identifier from any string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Who runs a source, which is the one axis of independence this product enforces.
///
/// # What independence has to mean before a count of sources means anything
///
/// Marzullo's guarantee holds while fewer than half the sources are wrong, and that needs them to
/// be wrong *separately*. Nine names at three companies are not nine chances to be wrong; they are
/// three. So the selection counts operators and not names, and the number in the policy is a floor
/// on operators. Everything about that rests on this type being right, so what it can and cannot
/// see is worth reading before trusting it.
///
/// # What this enforces
///
/// One thing: two sources under the same operator are one source as far as a majority is concerned.
/// An operator is whoever runs the server and holds its keys, and it is the axis chosen because it
/// is the only one that is a fact about a decision we made rather than a guess about a network we
/// cannot see. We chose who to ask.
///
/// # What it cannot enforce, and none of this is hypothetical
///
/// Four kinds of shared fate survive an operator count, and no protocol in this product's design
/// states any of them:
///
/// - **A shared upstream.** Two operators disciplined from the same national laboratory move
///   together when it moves. NTP's reference identifier hints at this and is four bytes of
///   free text; NTS and Roughtime say nothing at all.
/// - **A shared path.** Two servers reached over the same transit are one on-path attacker, whoever
///   owns them. A route is not stated by anybody and changes between packets.
/// - **A shared physical reference.** Most stratum-1 servers in the world are disciplined by GPS.
///   One spoofed constellation moves every operator that trusts it, and nothing in a reply says
///   what disciplines the server that sent it.
/// - **A shared implementation.** A defect in one widely deployed server program is one fault
///   across every operator running it.
///
/// So the count this product enforces is an upper bound on how independent a round really was, and
/// it says so on every surface rather than in this comment alone. What it buys is that the obvious
/// and cheapest way to manufacture a majority, asking one company several times, stops working.
///
/// # Where the identity comes from, and which way it errs
///
/// Declared where a deployment states it, and derived from the server's registrable domain where it
/// does not. The derivation is the last two labels of the host, so `time.cloudflare.com` and
/// `nts.cloudflare.com` are one operator without anybody saying so.
///
/// The derivation errs by merging, not by splitting, which is the direction that can only ever
/// refuse. Two unrelated servers under one country-code domain come out as one operator, the count
/// drops, and a round that would have been signed is refused instead. A reader sees that and a
/// deployment fixes it with one line of configuration. The opposite error, splitting one operator
/// into two, is invisible and inflates the very number the floor is made of.
///
/// **Where it is in doubt, merge.** Two names that might be one company are treated as one company
/// until somebody can show otherwise, for the same reason: assuming they are separate is the
/// assumption that costs nothing to make and everything to be wrong about.
/// # The one thing this type carries beside a name, and why it is not part of the name
///
/// **Whether the party is us.** A deployment may run its own time servers, and this product is
/// about to do exactly that. A server of ours answers like any other and its signature checks like
/// any other, and it is not an independent chance to be wrong, because the party behind it is the
/// party issuing the receipt. Counting it among the independent operators would put our own word
/// inside the number that is supposed to be free of it, which quietly breaks the rule that our own
/// word is never third-party evidence, with every signature still verifying.
///
/// So the flag rides on this type and it is deliberately **not** part of the identity. Two
/// operators with the same name are the same operator whichever constructor made them, which is
/// what `PartialEq`, `Ord` and `Hash` below say by hand rather than by derive. The alternative,
/// letting the flag into the identity, would make one company count twice the moment two sources
/// disagreed about whether it was us, and the count it would inflate is the one the floor is made
/// of. That is the invisible error this type's own documentation calls the worse one.
///
/// Where two sources under one name disagree about the flag, the party is treated as us. That is
/// the merging direction again: it can only ever lower the independent count and refuse a round,
/// never raise one and sign it.
///
/// The word is "first party" and not "ours", because "ours" is already spoken for. The receipt
/// format uses it for the agent's own claim sitting where third-party evidence belongs, which is a
/// different distinction: a Roughtime server of ours is a third party by that test and is not an
/// independent one by this test, and the two words have to stay apart or the format's central
/// separation blurs.
#[derive(Clone)]
pub struct Operator {
    name: String,
    first_party: bool,
}

impl Operator {
    /// An operator identity from a name a deployment states.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            first_party: false,
        }
    }

    /// An operator identity for a party that is us.
    ///
    /// Everything `new` gives, and the source is left out of the independent count. Use it for a
    /// server this deployment runs and holds the keys for, and for nothing else: a server run by
    /// somebody we merely know is an independent party and calling it first party throws away a
    /// real chance to be wrong separately.
    pub fn first_party(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            first_party: true,
        }
    }

    /// Whether the party behind this operator is the one issuing the receipt.
    #[must_use]
    pub const fn is_first_party(&self) -> bool {
        self.first_party
    }

    /// The same identity, marked as a party that is us.
    #[must_use]
    pub fn as_first_party(mut self) -> Self {
        self.first_party = true;
        self
    }

    /// The identity as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The operator a host belongs to, where nobody has said.
    ///
    /// The last two labels of the host, lowercased, with any port and any trailing dot removed. A
    /// host with one label or none is its own operator, because there is nothing left to group it
    /// by and inventing a group would be worse than admitting there is not one.
    ///
    /// **An address is its own operator, whole.** It is not a name, it has no registrable domain,
    /// and there is nothing in it to group two of them by. Taking the last two labels of one made
    /// `10.0.0.1` and `10.0.0.2` the operators `0.1` and `0.2`, so three addresses of a single
    /// appliance cleared a floor of three between them. That is the splitting error, which the
    /// type's own documentation above calls the invisible one for exactly this reason: it inflates
    /// the number the floor is made of and nothing goes red. So a v4 or v6 literal comes back as
    /// the literal itself, written the same way whether it arrived bare, bracketed or with a port
    /// on it, and two addresses in one subnet count as two operators only where a deployment says
    /// in so many words that they are.
    ///
    /// This is a derivation and not a lookup. It has no list of public suffixes in it and it is not
    /// going to acquire one: a suffix list is a dependency that goes stale, and being wrong with it
    /// merges two operators that a reader can then separate by hand, which is the same failure this
    /// already has and the same cheap fix. See the type's own documentation for why merging is the
    /// safe direction to be wrong in.
    #[must_use]
    pub fn from_host(host: &str) -> Self {
        // Three shapes reach this. A v6 literal in brackets, which is the only way one can carry a
        // port at all, because the colons are otherwise ambiguous. A bare v6 literal, which has
        // more than one colon in it and never has a port. And everything else, which is a name or
        // a v4 address and may have one port after one colon.
        let bare = match host.strip_prefix('[') {
            Some(rest) => rest.split(']').next().unwrap_or(rest),
            None if host.matches(':').count() > 1 => host,
            None => host.split(':').next().unwrap_or(host),
        };
        let trimmed = bare.trim_end_matches('.').to_ascii_lowercase();

        if trimmed.parse::<IpAddr>().is_ok() {
            return Self::new(trimmed);
        }

        let labels: Vec<&str> = trimmed.split('.').filter(|l| !l.is_empty()).collect();
        match labels.len() {
            0 => Self::new(trimmed),
            1 => Self::new(labels[0]),
            n => Self::new(format!("{}.{}", labels[n - 2], labels[n - 1])),
        }
    }
}

// Identity is the name and nothing else. These five are written out rather than derived because
// `Operator` carries a flag that must not take part in any of them: see the type's own heading.
// A derive here would silently make one company two the moment two sources disagreed about it.
impl PartialEq for Operator {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Operator {}

impl PartialOrd for Operator {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Operator {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl core::hash::Hash for Operator {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl fmt::Debug for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first_party {
            write!(f, "{} (first party)", self.name)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// What kind of protocol a source speaks.
///
/// This decides what a source is allowed to be used for, and the two uses are not the same. Every
/// kind here can discipline the clock. Only some of them produce something a stranger can check,
/// and the receipt crate is where that rule is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    /// Plain NTP. Unauthenticated, so it disciplines the clock and proves nothing.
    Ntp,
    /// NTP with network time security. It disciplines the clock and it is never portable evidence:
    /// the keys are symmetric, so a client holding one could forge a response to itself, and a
    /// stranger has no signature to check.
    Nts,
    /// Roughtime. The server signs over a nonce we generated, so the response is portable evidence
    /// as well as a discipline input.
    Roughtime,
    /// A source driven by local hardware, such as a pulse per second from a receiver.
    LocalHardware,
}

impl SourceKind {
    /// Whether a response from this kind of source carries a signature a third party can check.
    ///
    /// This is the reason the enum exists. Answering yes for NTS would be the central dishonesty
    /// available to a product in this field, so the answer is written once, here.
    #[must_use]
    pub const fn carries_third_party_signature(self) -> bool {
        match self {
            SourceKind::Roughtime => true,
            SourceKind::Ntp | SourceKind::Nts | SourceKind::LocalHardware => false,
        }
    }

    /// How this kind is spelled in a receipt.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            SourceKind::Ntp => "ntp",
            SourceKind::Nts => "nts",
            SourceKind::Roughtime => "roughtime",
            SourceKind::LocalHardware => "local-hardware",
        }
    }

    /// The kind a receipt named, where this code knows the spelling.
    ///
    /// `None` rather than a default, and the difference matters at exactly one question. A reader
    /// meeting a kind this code has never heard of cannot say whether a response from it carries a
    /// signature a stranger could check, and answering no would be a guess that happens to be
    /// conservative today. Saying it does not know is the answer that stays true when a later
    /// version of this format adds a kind that does sign.
    #[must_use]
    pub fn from_wire(named: &str) -> Option<Self> {
        match named {
            "ntp" => Some(SourceKind::Ntp),
            "nts" => Some(SourceKind::Nts),
            "roughtime" => Some(SourceKind::Roughtime),
            "local-hardware" => Some(SourceKind::LocalHardware),
            _ => None,
        }
    }
}

/// The timescale a source answers on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Timescale {
    /// UTC, with leap seconds inserted as leap seconds.
    #[default]
    Utc,
    /// TAI, with the stated offset from UTC in seconds.
    Tai {
        /// Seconds TAI runs ahead of UTC at the time of the reading.
        offset_seconds: i32,
    },
    /// The source did not say. Treated as a fault near a leap event rather than assumed to be UTC.
    Unknown,
}

/// How a source handles a leap second.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum SmearPolicy {
    /// The leap second is inserted as a leap second, so the clock repeats or skips a value.
    #[default]
    None,
    /// The leap second is spread across a window, so the clock runs slightly wrong for that long.
    Linear {
        /// The width of the smear window, in seconds.
        window_seconds: u32,
    },
    /// The source did not say what it does.
    Unknown,
}

impl SmearPolicy {
    /// Whether two policies would disagree about the reading across a leap event.
    ///
    /// Anything unknown counts as a disagreement. Assuming a source behaves like its neighbours is
    /// how a second of error gets into an interval that claims milliseconds.
    #[must_use]
    pub const fn conflicts_with(self, other: SmearPolicy) -> bool {
        match (self, other) {
            (SmearPolicy::Unknown, _) | (_, SmearPolicy::Unknown) => true,
            (SmearPolicy::None, SmearPolicy::None) => false,
            (
                SmearPolicy::Linear { window_seconds: a },
                SmearPolicy::Linear { window_seconds: b },
            ) => a != b,
            _ => true,
        }
    }
}

/// What a source says about an upcoming leap second.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum LeapIndicator {
    /// Nothing pending.
    #[default]
    None,
    /// A second will be added at the end of the current day.
    AddSecond,
    /// A second will be removed at the end of the current day.
    DeleteSecond,
    /// The source has not synchronised and says so.
    Unsynchronised,
}

impl LeapIndicator {
    /// Whether this indicator says a leap event is close enough to matter.
    #[must_use]
    pub const fn leap_pending(self) -> bool {
        matches!(self, LeapIndicator::AddSecond | LeapIndicator::DeleteSecond)
    }
}

/// Everything the model knows about one source, in a form a receipt can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceState {
    /// Which source this is.
    pub id: SourceId,
    /// Who runs it. Two sources sharing this are one source as far as a majority is concerned.
    pub operator: Operator,
    /// What it speaks, and so what it may be used for.
    pub kind: SourceKind,
    /// The timescale it answers on.
    pub timescale: Timescale,
    /// What it does with a leap second.
    pub smear: SmearPolicy,
    /// What it last said about an upcoming leap second.
    pub leap: LeapIndicator,
    /// Whether the last selection kept it or discarded it.
    pub kept: bool,
}

/// Counters that let a verifier see that the machine went away and came back.
///
/// A bound says nothing across a suspend, because the machine has no idea how long it was gone.
/// The agent refuses to stamp until it has synchronised again, and these two numbers are how a
/// reader of two receipts can tell that a gap happened at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Generations {
    /// Incremented once per boot of the machine.
    pub boot: u64,
    /// Incremented on every resume from sleep or suspend within one boot.
    pub resume: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nts_is_never_third_party_evidence() {
        assert!(!SourceKind::Nts.carries_third_party_signature());
        assert!(!SourceKind::Ntp.carries_third_party_signature());
        assert!(SourceKind::Roughtime.carries_third_party_signature());
    }

    #[test]
    fn two_hosts_at_one_company_derive_to_one_operator() {
        // The case the whole type exists for. Two of the nine servers this product ships against
        // are the same host on two protocols, and three more are one company on two names.
        assert_eq!(
            Operator::from_host("time.cloudflare.com"),
            Operator::from_host("nts.cloudflare.com")
        );
        assert_eq!(
            Operator::from_host("ptbtime1.ptb.de:123"),
            Operator::from_host("ptbtime2.ptb.de")
        );
        assert_ne!(
            Operator::from_host("time.cloudflare.com"),
            Operator::from_host("time.google.com")
        );
    }

    #[test]
    fn a_derivation_survives_a_port_a_trailing_dot_and_capitals() {
        let plain = Operator::from_host("time.cloudflare.com");
        assert_eq!(Operator::from_host("TIME.Cloudflare.COM:123"), plain);
        assert_eq!(Operator::from_host("time.cloudflare.com."), plain);
        assert_eq!(plain.as_str(), "cloudflare.com");
    }

    #[test]
    fn an_address_is_one_operator_however_it_is_written() {
        // The derivation took the last two labels of anything, so 10.0.0.1 and 10.0.0.2 came out as
        // operators "0.1" and "0.2" and three addresses of one appliance cleared a floor of three
        // on their own. That is the splitting error, and the type's own documentation says it is
        // the invisible one because it inflates the number the floor is made of. An address is not
        // a name and has no registrable domain to group it by, so the whole literal is the operator
        // and two addresses are two operators only where somebody configures them that way.
        assert_eq!(Operator::from_host("10.0.0.1").as_str(), "10.0.0.1");
        assert_eq!(Operator::from_host("10.0.0.2").as_str(), "10.0.0.2");
        assert_ne!(
            Operator::from_host("10.0.0.1"),
            Operator::from_host("10.0.0.2")
        );

        // The same address written four ways is one operator, or a deployment that states a port
        // on one line and not on the next has invented a second company.
        let four = Operator::from_host("10.0.0.1");
        assert_eq!(Operator::from_host("10.0.0.1:123"), four);
        assert_eq!(Operator::from_host("10.0.0.1."), four);
        assert_eq!(Operator::from_host("10.0.0.1:2002"), four);

        // A v6 literal survived the old derivation by accident: splitting on the colon left one
        // label, and one label is its own operator, so every v6 address in the world was the
        // operator "2001". That merges rather than splits, which is the safe direction, and it is
        // still wrong. Written plain, bracketed, and bracketed with a port.
        let six = Operator::from_host("2001:db8::1");
        assert_eq!(six.as_str(), "2001:db8::1");
        assert_eq!(Operator::from_host("[2001:db8::1]"), six);
        assert_eq!(Operator::from_host("[2001:db8::1]:123"), six);
        assert_ne!(Operator::from_host("2001:db8::2"), six);
        assert_ne!(Operator::from_host("2001:db9::1"), six);
    }

    #[test]
    fn the_derivation_still_merges_where_it_is_in_doubt() {
        // The promise in the type's documentation, asserted rather than only stated. Anything that
        // is a name goes on being grouped by its last two labels, including the case that costs us
        // a refusal: two unrelated servers under one country-code domain are one operator.
        assert_eq!(
            Operator::from_host("ntp1.example.co.uk"),
            Operator::from_host("ntp2.other.co.uk")
        );
        // A name that looks like neither an address nor a domain is still its own operator.
        assert_eq!(
            Operator::from_host("10.0.0.1.example.com").as_str(),
            "example.com"
        );
        assert_eq!(Operator::from_host("999.999.999.999").as_str(), "999.999");
    }

    /// Equality, ordering and hashing are written out by hand, so nothing but this keeps them saying
    /// the same thing.
    ///
    /// They cannot be derived: a derive would put the first-party flag into all three, and the
    /// type's own heading says why that is the invisible error. So the property is held here
    /// instead, over every pair and every triple of a set of names built to sit near the edges: an
    /// empty name, two cases of one letter, a trailing dot, a name inside another, two addresses and
    /// a character outside ASCII, each made all three ways the flag can be set.
    ///
    /// What it holds. Two operators are equal exactly when their names are, whatever the flag says.
    /// Ordering says equal exactly when equality does, agrees with the partial ordering, reverses
    /// when the two are swapped, is transitive, and orders by the name alone. Two equal operators
    /// hash alike. And a hashed set and an ordered set of all of them hold one operator per name,
    /// which is the count the independence floor is made of.
    #[test]
    fn equality_ordering_and_hashing_agree_and_none_of_them_sees_the_flag() {
        use core::cmp::Ordering;
        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        use std::collections::{BTreeSet, HashSet};

        fn hash_of(operator: &Operator) -> u64 {
            let mut hasher = DefaultHasher::new();
            operator.hash(&mut hasher);
            hasher.finish()
        }

        let names = [
            "",
            "a",
            "A",
            "a.example",
            "a.example.",
            "b.example",
            "cloudflare.com",
            "time.cloudflare.com",
            "10.0.0.1",
            "2001:db8::1",
            "zz",
            "\u{e9}.example",
        ];
        let all: Vec<Operator> = names
            .iter()
            .flat_map(|name| {
                [
                    Operator::new(*name),
                    Operator::first_party(*name),
                    Operator::new(*name).as_first_party(),
                ]
            })
            .collect();

        for a in &all {
            for b in &all {
                let equal = a == b;
                assert_eq!(
                    equal,
                    a.as_str() == b.as_str(),
                    "{a:?} and {b:?}: equal exactly when the names are"
                );
                assert_eq!(
                    equal,
                    a.cmp(b) == Ordering::Equal,
                    "{a:?} and {b:?}: ordering and equality disagree"
                );
                assert_eq!(a.partial_cmp(b), Some(a.cmp(b)), "{a:?} and {b:?}");
                assert_eq!(a.cmp(b), b.cmp(a).reverse(), "{a:?} and {b:?}");
                assert_eq!(
                    a.cmp(b),
                    a.as_str().cmp(b.as_str()),
                    "{a:?} and {b:?}: ordered by name alone"
                );
                if equal {
                    assert_eq!(
                        hash_of(a),
                        hash_of(b),
                        "{a:?} and {b:?} are equal and hash apart"
                    );
                }
                for c in &all {
                    if a <= b && b <= c {
                        assert!(a <= c, "{a:?} <= {b:?} <= {c:?} and not {a:?} <= {c:?}");
                    }
                }
            }
        }

        let hashed: HashSet<Operator> = all.iter().cloned().collect();
        let ordered: BTreeSet<Operator> = all.iter().cloned().collect();
        assert_eq!(hashed.len(), names.len(), "one operator per name, hashed");
        assert_eq!(ordered.len(), names.len(), "one operator per name, ordered");
    }

    #[test]
    fn a_host_with_nothing_to_group_it_by_is_its_own_operator() {
        assert_eq!(Operator::from_host("localhost").as_str(), "localhost");
        assert_eq!(Operator::from_host("roughtime.se").as_str(), "roughtime.se");
    }

    #[test]
    fn unknown_smear_conflicts_with_everything() {
        assert!(SmearPolicy::Unknown.conflicts_with(SmearPolicy::None));
        assert!(SmearPolicy::None.conflicts_with(SmearPolicy::Unknown));
        assert!(SmearPolicy::Unknown.conflicts_with(SmearPolicy::Unknown));
    }

    #[test]
    fn smeared_and_stepped_sources_conflict() {
        let smeared = SmearPolicy::Linear {
            window_seconds: 86_400,
        };
        assert!(smeared.conflicts_with(SmearPolicy::None));
        assert!(!smeared.conflicts_with(SmearPolicy::Linear {
            window_seconds: 86_400
        }));
        assert!(smeared.conflicts_with(SmearPolicy::Linear {
            window_seconds: 3_600
        }));
    }
}
