//! Receipts whose signature is perfect and whose numbers are a lie.
//!
//! The format's first battery, in `receipt_format.rs`, attacks the labels: an entry claiming a role
//! its scheme cannot support, our own bound moved into an evidence slot, a scheme whose keys we also
//! hold. All of that holds.
//!
//! This file attacks the numbers, which is where the same lie is told in arithmetic instead. A
//! receipt is refused here not because it is malformed and not because it is unsigned, but because
//! what it says about itself does not survive being checked: parts that do not add up to the width
//! they are the parts of, a ceiling the receipt states and then exceeds, a majority of no sources,
//! a corridor dated outside the interval it is offered as support for, and the strongest claim in
//! the format granted on three spellings with nothing verified behind them.
//!
//! Every one of these was built, signed correctly, and watched being accepted by `open()` before
//! the check that now refuses it went in.

use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    Operator, Reading, SmearPolicy, SourceId, SourceKind, SourceState, Stamp, Timescale, UnixNanos,
};
use timewitness_receipt::schema::{Role, SourceRecord};
use timewitness_receipt::{
    open, sha256_payload, AgentKey, Evidence, PolicyRecord, Receipt, ReceiptError, Scheme,
};

const MS: i128 = 1_000_000;
const NOW: i128 = 1_757_000_000_000_000_000;
/// Nanoseconds in a year, for dating a piece of evidence well outside the interval.
const YEAR: i128 = 365 * 24 * 3_600 * 1_000_000_000;

fn key() -> AgentKey {
    AgentKey::from_seed(&[7u8; 32])
}

fn source(id: &str, kept: bool) -> SourceState {
    SourceState {
        id: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        kept,
    }
}

/// One source as the receipt carries it, with who runs it stated.
///
/// The tests above build a stamp and let the receipt be made from it. These build the source list
/// directly, because what they are about is the shape of a list a reader is handed rather than the
/// shape of a round the model ran.
fn record(id: &str, operator: &str, kept: bool) -> SourceRecord {
    SourceRecord {
        id: id.to_string(),
        operator: Some(operator.to_string()),
        kind: "ntp".to_string(),
        timescale: "utc".to_string(),
        smear: "none".to_string(),
        leap: "none".to_string(),
        kept,
        first_party: false,
    }
}

/// The same, from a source that told the agent its own clock is not synchronised.
fn unsynchronised(id: &str, operator: &str) -> SourceRecord {
    SourceRecord {
        leap: "unsynchronised".to_string(),
        ..record(id, operator, false)
    }
}

/// The same, from a receipt that names no party at all for any of its sources.
fn unlabelled(id: &str, kept: bool) -> SourceRecord {
    SourceRecord {
        operator: None,
        ..record(id, "unused", kept)
    }
}

fn stamp() -> Stamp {
    Stamp {
        reading: Reading {
            monotonic: MonotonicNanos(4_200_000_000),
            utc_estimate: UnixNanos(NOW),
        },
        bound: Bound {
            earliest: UnixNanos(NOW - 6 * MS),
            latest: UnixNanos(NOW + 6 * MS),
            basis: EpsilonBasis::LocalModelOnly,
            breakdown: BoundBreakdown {
                fusion: FusionRule::MarzulloThenInverseSquare {
                    offered: 5,
                    kept: 4,
                },
                intersection_half: 5 * MS,
                widest_source_network_half: 12 * MS,
                scheduling: 10_000,
                oscillator_holdover: 500_000,
                model_residual: 240_000,
                safety_margin: 250_000,
            },
        },
        sources: vec![
            source("alpha", true),
            source("bravo", true),
            source("charlie", true),
            source("delta", true),
            source("echo", false),
        ],
        generations: Generations { boot: 3, resume: 1 },
        since_last_sync: 64_000_000_000,
        frequency_ppm: Some(4.25),
    }
}

/// An honest receipt, which every test here then damages in one specific way.
fn receipt() -> Receipt {
    Receipt::from_stamp(
        &stamp(),
        1,
        None,
        sha256_payload(b"the artefact being stamped"),
        key().public_key_bytes(),
        PolicyRecord {
            max_bound_width: 250 * MS,
            min_sources: 3,
            min_operators: Some(3),
            max_holdover: Some(3_600 * MS * 1_000),
        },
    )
}

/// Sign a receipt and read it back the way a stranger would.
fn sign_and_open(r: &Receipt) -> Result<Receipt, ReceiptError> {
    let signed = key().sign_value(&r.to_value());
    open(&signed)
}

// ---------------------------------------------------------------------------
// The strongest claim in the format, granted on three spellings
// ---------------------------------------------------------------------------

#[test]
fn a_sandwich_of_blobs_that_are_not_responses_at_all_is_refused() {
    // Three entries with the right roles and the right scheme names, and blobs that are plainly
    // not what they say they are. Nothing in this tree can verify a Roughtime signature, a beacon
    // round or a timestamp token yet, so nothing checked them and the receipt came back claiming
    // the strongest thing the format can say.
    let mut r = receipt();
    r.claim.basis = EpsilonBasis::ThirdPartySandwich;
    r.evidence = vec![
        Evidence {
            role: Role::AuthenticatedUtcCorridor,
            scheme: Scheme::new("roughtime"),
            at: UnixNanos(NOW - MS),
            radius: Some(2 * MS),
            blob: b"not a roughtime response".to_vec(),
            nonce: Some(vec![0x5a; 32]),
            detail: None,
        },
        Evidence {
            role: Role::NotEarlierThan,
            scheme: Scheme::new("drand"),
            at: UnixNanos(NOW - 30 * MS),
            radius: None,
            blob: b"not a beacon".to_vec(),
            nonce: None,
            detail: None,
        },
        Evidence {
            role: Role::NotLaterThan,
            scheme: Scheme::new("rfc3161"),
            at: UnixNanos(NOW + 40 * MS),
            radius: None,
            blob: b"not a token".to_vec(),
            nonce: None,
            detail: None,
        },
    ];

    let refusal = sign_and_open(&r).expect_err("a sandwich nobody checked is not a sandwich");
    // Two refusals are correct here and the reason moved from the second to the first on
    // 2026-09-08. `b"not a roughtime response"` is not a stored attestation of any scheme, and that
    // is visible with no key at all, so it is now refused as a broken blob before anything asks
    // whether the claim outruns the evidence. Either sentence refuses the receipt and neither lets
    // it through, which is what this test is for.
    assert!(
        matches!(
            refusal,
            ReceiptError::OurClaimAsEvidence(_) | ReceiptError::Inconsistent(_)
        ),
        "the refusal has to say the claim is stronger than the evidence behind it, or that the          blobs are not attestations at all, got {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Numbers that do not describe each other
// ---------------------------------------------------------------------------

#[test]
fn a_bound_narrower_than_its_own_parts_is_refused() {
    // Two microseconds wide, with a breakdown whose parts sum to two hundred milliseconds. The
    // check ran one way only, so a receipt claiming a hundred thousand times more precision than
    // its own arithmetic supports was accepted. That is precision claimed where none was measured.
    let mut r = receipt();
    r.claim.earliest = UnixNanos(NOW - 1_000);
    r.claim.latest = UnixNanos(NOW + 1_000);
    r.claim.breakdown.intersection_half = 100 * MS;

    let refusal = sign_and_open(&r).expect_err("a bound cannot be tighter than its own parts");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

#[test]
fn a_bound_wider_than_its_own_parts_is_still_refused() {
    // The direction that was already checked. It stays checked.
    let mut r = receipt();
    r.claim.earliest = UnixNanos(NOW - 500 * MS);
    r.claim.latest = UnixNanos(NOW + 500 * MS);

    let refusal = sign_and_open(&r).expect_err("a bound cannot be wider than its own parts");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

#[test]
fn a_bound_from_no_sources_at_all_is_refused() {
    // The majority test was guarded by "if any sources answered", so answering with none skipped
    // it. No sources is not a special case; it is the case the whole design refuses.
    let mut r = receipt();
    r.claim.sources_offered = 0;
    r.claim.sources_kept = 0;
    r.claim.sources.clear();

    let refusal = sign_and_open(&r).expect_err("nothing was measured, so there is no bound");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

// ---------------------------------------------------------------------------
// The receipt's own stated policy, which it carried and nothing read
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_wider_than_the_ceiling_it_states_for_itself_is_refused() {
    // Every receipt carries the widest interval its agent said it would sign for. Checking a
    // receipt against its own stated numbers is what the rest of the validator does.
    let mut r = receipt();
    r.claim.earliest = UnixNanos(NOW - 500 * MS);
    r.claim.latest = UnixNanos(NOW + 500 * MS);
    // The parts still add to exactly half the new width, so the only thing wrong with this receipt
    // is the ceiling. Widening the interval and leaving the parts alone refuses it for arithmetic
    // instead, which passes this test while proving nothing about the ceiling.
    r.claim.breakdown.intersection_half = 500 * MS
        - r.claim.breakdown.scheduling
        - r.claim.breakdown.oscillator_holdover
        - r.claim.breakdown.model_residual
        - r.claim.breakdown.safety_margin;
    assert!(r.width() > r.claim.policy.max_bound_width);

    let refusal =
        sign_and_open(&r).expect_err("the receipt is wider than the agent said it would go");
    assert!(
        format!("{refusal}").contains("will not sign one wider than"),
        "got {refusal}"
    );
}

#[test]
fn a_receipt_with_fewer_sources_than_its_own_policy_demands_is_refused() {
    let mut r = receipt();
    r.claim.policy.min_sources = 6;

    let refusal = sign_and_open(&r).expect_err("fewer sources answered than the agent requires");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

// ---------------------------------------------------------------------------
// The operators behind the sources, which is the count a majority rests on
// ---------------------------------------------------------------------------

#[test]
fn a_bound_resting_on_a_minority_of_the_operators_that_answered_is_refused() {
    // Five sources kept and every one of them at the same company, against three that answered from
    // three others and were thrown out. Counting names it is a clean majority, five of eight, and
    // every other test in this file passes it. Counting parties it is one of four, and one party
    // agreeing with itself five times corroborated nothing.
    let mut r = receipt();
    r.claim.sources = vec![
        record("loud-1", "loud.example", true),
        record("loud-2", "loud.example", true),
        record("loud-3", "loud.example", true),
        record("loud-4", "loud.example", true),
        record("loud-5", "loud.example", true),
        record("a-1", "a.example", false),
        record("b-1", "b.example", false),
        record("c-1", "c.example", false),
    ];
    r.claim.sources_offered = 8;
    r.claim.sources_kept = 5;

    let refusal = sign_and_open(&r).expect_err("one operator is not a majority of four");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
    assert!(refusal.to_string().contains("operators"), "got {refusal}");
}

#[test]
fn a_receipt_below_its_own_stated_operator_floor_is_refused() {
    let mut r = receipt();
    r.claim.policy.min_operators = Some(9);

    let refusal = sign_and_open(&r).expect_err("the agent broke its own word about operators");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

/// A receipt with no operator labels on it was excused both operator tests, and the reason was
/// unreachable.
///
/// `check_operators` returned early for any receipt naming no operator at all, and its stated
/// reason was that such a receipt predates the field and should not be held to a format it came
/// before. `check_version` refuses every version but the current one, so the only receipt that
/// could reach the carve-out was one written before the field and after the version it belongs to,
/// which is a real window: the labels went into version 0 without a bump.
///
/// What makes the carve-out unnecessary rather than merely misdescribed is that the floor went in
/// with the labels, in one commit on 2026-09-09. A receipt that predates the labels predates the
/// floor as well, so it states no floor, and it passes this test on its own merits with nothing
/// excused. What the carve-out was actually reaching is the case below: an agent that states a
/// floor and then names nobody.
#[test]
fn a_receipt_that_states_an_operator_floor_and_names_nobody_is_refused() {
    let mut r = receipt();
    // Every label gone, and the stated floor left where it is. The agent has said it needs three
    // parties before it will sign and the receipt shows none, so nothing in it says it kept to its
    // own word. That is the only question this crate asks.
    r.claim.sources = vec![
        unlabelled("a-1", true),
        unlabelled("a-2", true),
        unlabelled("b-1", true),
        unlabelled("c-1", false),
    ];
    r.claim.sources_offered = 4;
    r.claim.sources_kept = 3;
    assert!(r.claim.names_no_operator());

    let refusal = sign_and_open(&r).expect_err("no labels cannot meet a floor of three");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
    assert!(refusal.to_string().contains("operators"), "got {refusal}");
}

/// The receipt the carve-out was written for, which never needed it.
#[test]
fn a_receipt_from_before_the_labels_existed_passes_on_its_own_merits() {
    let mut r = receipt();
    r.claim.sources = vec![
        unlabelled("a-1", true),
        unlabelled("a-2", true),
        unlabelled("b-1", true),
        unlabelled("c-1", false),
    ];
    r.claim.sources_offered = 4;
    r.claim.sources_kept = 3;
    // No labels and no floor, which is what a receipt written before 2026-09-09 carries, because
    // both fields arrived in the same commit.
    r.claim.policy.min_operators = None;

    sign_and_open(&r).expect("a receipt that claims no floor is not held to one");
}

/// A source that said its own clock was wrong is not counted among the operators that answered.
///
/// It never was a candidate, so the agent did not count it, and a validator that does is strictly
/// harder than the agent it is checking. That produces the one failure this product cannot afford
/// from a verifier: a receipt the agent was right to sign, refused by the same product's other half.
#[test]
fn a_source_that_says_its_own_clock_is_wrong_is_not_one_of_the_operators() {
    let mut r = receipt();
    r.claim.sources = vec![
        record("a-1", "a.example", true),
        record("a-2", "a.example", true),
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
        unsynchronised("d-1", "d.example"),
        unsynchronised("e-1", "e.example"),
        unsynchronised("f-1", "f.example"),
    ];
    r.claim.sources_offered = 7;
    r.claim.sources_kept = 4;
    r.claim.policy.min_operators = Some(3);

    // Counting every name in the list it is three operators of six, which is not a majority and
    // would be a refusal. Three of the six were never in the round: they said so themselves, the
    // agent set them aside before it combined anything, and a bound resting on the other three is
    // the bound the agent actually signed.
    sign_and_open(&r).expect("three operators agreed and three were never candidates");
}

/// The same set counted the other way round, which is the half corrected when `sources_offered`
/// came to mean how many answered.
///
/// Four kept out of eight that answered is not a majority of the names, and it is a clean majority
/// of the four sources that could have disagreed with anybody. The agent signs this round: it drops
/// the four that reported their own clocks wrong before it intersects anything, and four of four is
/// what it saw. A validator taking the majority over everything that answered refuses it, and a
/// validator refusing what the agent was right to sign is this product's two halves disagreeing
/// about one artefact.
#[test]
fn a_majority_of_the_sources_that_could_disagree_is_a_majority() {
    let mut r = receipt();
    r.claim.sources = vec![
        record("a-1", "a.example", true),
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
        record("d-1", "d.example", true),
        unsynchronised("e-1", "e.example"),
        unsynchronised("f-1", "f.example"),
        unsynchronised("g-1", "g.example"),
        unsynchronised("h-1", "h.example"),
    ];
    r.claim.sources_offered = 8;
    r.claim.sources_kept = 4;
    assert!(2 * r.claim.sources_kept <= r.claim.sources_offered);

    sign_and_open(&r).expect("four of the four that could disagree is a majority");
}

/// A source cannot be set aside for saying its own clock is wrong and kept at the same time.
///
/// This is the lie the correction above opens the door to. Once the majority is taken over the
/// candidates, an agent that wants a smaller denominator marks sources unsynchronised, and marking
/// one it kept is the cheapest version of that. The shipped code cannot produce such a receipt: a
/// source that said so is dropped before the intersection is taken.
#[test]
fn a_source_that_says_its_own_clock_is_wrong_cannot_also_be_kept() {
    let mut r = receipt();
    r.claim.sources = vec![
        record("a-1", "a.example", true),
        record("b-1", "b.example", true),
        SourceRecord {
            kept: true,
            first_party: false,
            ..unsynchronised("c-1", "c.example")
        },
    ];
    r.claim.sources_offered = 3;
    r.claim.sources_kept = 3;

    let refusal = sign_and_open(&r).expect_err("a source cannot be set aside and kept at once");
    assert!(
        format!("{refusal}").contains("marks it as kept"),
        "got {refusal}"
    );
}

// ---------------------------------------------------------------------------
// The corridor, which had no way to say what it proved
// ---------------------------------------------------------------------------

#[test]
fn a_corridor_dated_a_year_outside_the_interval_is_refused() {
    // The role that gives the bound its outside support was the one role nothing checked, because
    // an evidence entry carried a single instant and no width, so there was no interval to compare
    // the claim against.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("roughtime"),
        at: UnixNanos(NOW - YEAR),
        radius: Some(3 * MS),
        blob: vec![0xa1; 96],
        nonce: Some(vec![0x5a; 32]),
        detail: None,
    }];

    let refusal = sign_and_open(&r).expect_err("a corridor from last year supports nothing");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

#[test]
fn a_corridor_that_does_not_say_how_wide_it_is_is_refused() {
    // A Roughtime response is a midpoint and a radius. Without the radius the entry cannot say
    // what interval it proves and nothing downstream can test it, which is how the year-old one
    // above got in.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("roughtime"),
        at: UnixNanos(NOW - MS),
        radius: None,
        blob: vec![0xa1; 96],
        nonce: Some(vec![0x5a; 32]),
        detail: None,
    }];

    let refusal = sign_and_open(&r).expect_err("a corridor with no width proves nothing checkable");
    assert!(matches!(refusal, ReceiptError::Field(_)), "got {refusal}");
}

#[test]
fn a_corridor_that_overlaps_the_interval_is_accepted() {
    // The honest case, so the checks above are refusing something specific rather than everything.
    //
    // A real corridor, captured from roughtime.se on 2026-09-07 about a subject of thirty-two 0x5a
    // bytes, and the receipt moved to sit inside it. Until 2026-09-15 this was a blob of the right
    // outer shape with rubbish inside, which reported as not checked under no key; from that date a
    // stored response that is not a Roughtime exchange is refused whatever the reader holds, and so
    // is a printed moment the response does not state. The reader here still holds no key, so the
    // entry still reports as not checked, and what this test is about is still the interval
    // arithmetic around it rather than the signature.
    let corridor_at = 1_788_806_207 * 1_000 * MS;
    let mut r = receipt();
    r.payload.hash = vec![0x5a; 32];
    r.utc_estimate = UnixNanos(corridor_at - 4 * MS);
    r.claim.earliest = UnixNanos(corridor_at - 10 * MS);
    r.claim.latest = UnixNanos(corridor_at + 2 * MS);
    r.evidence = vec![Evidence {
        role: Role::AuthenticatedUtcCorridor,
        scheme: Scheme::new("roughtime"),
        at: UnixNanos(corridor_at),
        radius: Some(1_000 * MS),
        blob: unhex(include_str!("data/sandwich/roughtime.hex")),
        nonce: Some(unhex(include_str!("data/sandwich/roughtime-nonce.hex"))),
        detail: None,
    }];

    let back = sign_and_open(&r).expect("an honest corridor entry is evidence");
    assert_eq!(back.evidence[0].radius, Some(1_000 * MS));
}

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

#[test]
fn a_beacon_whose_whole_interval_is_after_the_reading_is_refused() {
    // Not-earlier-than with a radius: the earliest instant it is consistent with still has to sit
    // no later than the reading it is offered as a floor for.
    let mut r = receipt();
    r.evidence = vec![Evidence {
        role: Role::NotEarlierThan,
        scheme: Scheme::new("drand"),
        at: UnixNanos(NOW + 60 * MS),
        radius: Some(MS),
        blob: vec![0xb2; 64],
        nonce: None,
        detail: None,
    }];

    let refusal = sign_and_open(&r).expect_err("a beacon drawn after the reading is not a floor");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

#[test]
fn a_receipt_stating_no_ceiling_at_all_is_refused_rather_than_read_as_unlimited() {
    // Zero was read as "this agent set no ceiling", so a receipt stating it had no width ceiling at
    // all. Zero is also what the field holds when nobody filled it in, so the deliberate reading and
    // the oversight are the same value and neither is a permission. Nothing else about this receipt
    // is damaged: it is the honest one with one number cleared.
    let mut r = receipt();
    r.claim.policy.max_bound_width = 0;

    let refusal = sign_and_open(&r).expect_err("a ceiling of zero is not an absent ceiling");
    assert!(
        format!("{refusal}").contains("no interval it would sign"),
        "got {refusal}"
    );
}

// ---------------------------------------------------------------------------
// The holdover ceiling, which the receipt could not state until 2026-09-08
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_older_than_its_own_holdover_ceiling_is_refused() {
    // `since_last_sync` is the age of the newest exchange the interval rests on. An agent that
    // signs a reading taken further from that exchange than its own policy allows has broken its
    // own word, and until the ceiling was carried in the receipt nobody outside could see it.
    let mut r = receipt();
    r.claim.policy.max_holdover = Some(60 * MS * 1_000);
    r.claim.since_last_sync = 61 * MS * 1_000;

    let refusal = sign_and_open(&r).expect_err("the agent extrapolated past its own ceiling");
    assert!(
        format!("{refusal}").contains("will not extrapolate past"),
        "got {refusal}"
    );
}

#[test]
fn a_holdover_ceiling_of_zero_is_refused_rather_than_read_as_unlimited() {
    // The same reasoning as the width ceiling. Absent and nought are different facts and the
    // format spells them differently, so nought read as written says the agent would extrapolate
    // for no time at all and then signed a reading it took after some.
    let mut r = receipt();
    r.claim.policy.max_holdover = Some(0);
    r.claim.since_last_sync = MS;

    let refusal = sign_and_open(&r).expect_err("a ceiling of zero is not an absent ceiling");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
}

#[test]
fn a_receipt_that_states_no_holdover_ceiling_is_read_as_stating_none() {
    // One receipt in this repository predates the field and three real third parties signed it, so
    // it is not re-taken. A reader has to be able to open it and has to be told that there is no
    // ceiling here to hold the agent to, rather than being handed a nought that reads as a promise.
    let mut r = receipt();
    r.claim.policy.max_holdover = None;
    r.claim.since_last_sync = 10 * 3_600 * MS * 1_000;

    let opened = sign_and_open(&r).expect("a receipt that states no ceiling still opens");
    assert_eq!(
        opened.claim.policy.max_holdover, None,
        "an absent ceiling reads back absent and never as nought"
    );
}

/// A leap value this format does not know is refused, and every spelling of it.
///
/// `was_a_candidate` was an exact string match against the one value that refuses, so anything
/// else answered as a source whose own clock it believed was right. The receipt below is the one
/// that was built by hand and accepted: nine sources that had all declared their clocks
/// unsynchronised, spelled with a capital letter, counted as nine sound ones on the CLI and on the
/// served page alike.
#[test]
fn a_leap_value_this_format_does_not_know_is_refused() {
    for spelling in [
        "Unsynchronised",
        "UNSYNCHRONISED",
        "unsynchronized",
        "unsynchronised ",
        "",
        "sound",
    ] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                leap: spelling.to_string(),
                ..record("a-1", "a.example", true)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
        ];
        r.claim.sources_offered = 3;
        r.claim.sources_kept = 3;

        let refusal = sign_and_open(&r)
            .expect_err("a leap value nothing here can read is not a value to decide from");
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "on {spelling:?} got {refusal}"
        );
        assert!(
            refusal.to_string().contains("leap indicator"),
            "on {spelling:?} got {refusal}"
        );
    }
}

/// The four values it does know still read as they always did.
///
/// The three that describe a clock the source believed was right are candidates, and
/// `unsynchronised` is not. This is the other half of the allow-list: a rule that refuses
/// everything is as wrong as one that permits everything, and only running both says which this is.
#[test]
fn the_four_leap_values_this_format_knows_are_read_as_before() {
    for sound in ["none", "add-second", "delete-second"] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                leap: sound.to_string(),
                ..record("a-1", "a.example", true)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
        ];
        r.claim.sources_offered = 3;
        r.claim.sources_kept = 3;
        sign_and_open(&r).unwrap_or_else(|e| panic!("{sound} is a sound source and got {e}"));
    }

    // And the one that refuses still refuses, on the same shape, so the test above is not passing
    // because every receipt in it was malformed for some other reason.
    let mut r = receipt();
    r.claim.sources = vec![
        unsynchronised("a-1", "a.example"),
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
    ];
    r.claim.sources_offered = 3;
    r.claim.sources_kept = 2;
    let refusal = sign_and_open(&r).expect_err("unsynchronised still refuses this receipt");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
    assert!(
        !refusal.to_string().contains("leap indicator"),
        "it should refuse on what the source said and not on being unable to read it, got {refusal}"
    );
}

/// Put a string into the receipt at the place `Receipt::strings` gave that name to.
///
/// Written against the names rather than against field numbers so the test below reads as what it
/// is doing, and so a string added to the format arrives here as a name nothing handles rather than
/// as a case that is quietly skipped.
fn plant(r: &mut Receipt, at: &str, value: &str) {
    if at == "payload.algorithm" {
        r.payload.algorithm = value.to_string();
        return;
    }
    if at == "claim.fusion" {
        r.claim.fusion = value.to_string();
        return;
    }
    let (which, field) = at
        .strip_prefix("claim.sources[")
        .and_then(|rest| rest.split_once("]."))
        .unwrap_or_else(|| panic!("nothing here knows how to plant a string at {at}"));
    let source = &mut r.claim.sources[which.parse::<usize>().expect("a source number")];
    match field {
        "id" => source.id = value.to_string(),
        "kind" => source.kind = value.to_string(),
        "timescale" => source.timescale = value.to_string(),
        "smear" => source.smear = value.to_string(),
        "leap" => source.leap = value.to_string(),
        "operator" => source.operator = Some(value.to_string()),
        _ => panic!("nothing here knows how to plant a string at {at}"),
    }
}

/// A receipt cannot write its own lines into a report that is one field per line.
///
/// Measured 2026-09-19: a correctly signed receipt whose first source had `kind` set to `ntp`, a
/// newline, `earliest_ns=1`, a newline, `width_ns=1` verified clean, and `timewitness verify
/// --fields` carried `earliest_ns=1` and a width of the receipt's own choosing above the report's
/// real ones. `scripts/action-stamp.sh` reads that report with `sed -n 's/^name=//p'`, which takes
/// every matching line, so two intended outputs became four with attacker-chosen content on two.
///
/// Every string the receipt carries is tested, not the one that was found, because each of them
/// reaches a `name=value` line on some surface. The places come from `Receipt::strings`, which is
/// the list `validate` walks, so a string added to the format later arrives in this test as a name
/// `plant` does not know and stops the run.
#[test]
fn no_string_in_a_receipt_may_carry_a_control_character() {
    let planted = "ntp\nearliest_ns=1";

    let mut every = receipt();
    every.claim.sources = vec![
        record("a-1", "a.example", true),
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
    ];
    every.claim.sources_offered = 3;
    every.claim.sources_kept = 3;
    let places: Vec<String> = every.strings().iter().map(|(at, _)| at.clone()).collect();
    assert!(
        places.len() >= 18,
        "three sources carry six strings each beside the payload and the fusion rule, got {}",
        places.len()
    );

    // One at a time, so a refusal cannot be coming from some other field being wrong at the same
    // moment as the one under test.
    for at in &places {
        let mut r = every.clone();
        plant(&mut r, at, planted);
        let refusal = sign_and_open(&r)
            .err()
            .unwrap_or_else(|| panic!("{at} carries a newline and the receipt was accepted"));
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "on {at} got {refusal}"
        );
        let said = refusal.to_string();
        assert!(
            said.contains(at.as_str()),
            "on {at} the refusal does not name it: {said}"
        );
        assert!(
            !said.contains(planted),
            "on {at} the refusal plants the lines it is refusing: {said}"
        );
    }

    // And the same receipt with nothing planted still holds up, so the loop above is not passing
    // because every receipt in it was malformed for some other reason.
    sign_and_open(&every).expect("the same receipt with no control character in it holds up");
}

/// Every control character, not only the newline that was found.
///
/// A carriage return splits a line for a reader on Windows, a form feed and a vertical tab do on
/// some terminals, and a NUL truncates the value for anything reading it as a C string. None of
/// them is a character an agent writes into the name of a source, so the rule is the class rather
/// than the one member of it that was demonstrated.
#[test]
fn the_rule_is_every_control_character_and_not_the_newline_alone() {
    for bad in ['\r', '\u{0}', '\u{b}', '\u{c}', '\u{1b}', '\u{7f}'] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                id: format!("ntp.example{bad}"),
                ..record("a-1", "a.example", true)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
        ];
        r.claim.sources_offered = 3;
        r.claim.sources_kept = 3;
        let refusal = sign_and_open(&r).err().unwrap_or_else(|| {
            panic!("{bad:?} is a control character and the receipt was accepted")
        });
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "on {bad:?} got {refusal}"
        );
    }

    // A character outside ASCII is not a control character and is not refused. An operator name in
    // a language that needs one is a name, and a rule refusing it would be refusing honest receipts
    // to answer an attack that is about where a line ends.
    let mut fine = receipt();
    fine.claim.sources = vec![
        SourceRecord {
            operator: Some("\u{c5}lesund Tid".to_string()),
            ..record("a-1", "a.example", true)
        },
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
    ];
    fine.claim.sources_offered = 3;
    fine.claim.sources_kept = 3;
    sign_and_open(&fine).expect("a name outside ASCII is a name");
}

/// Exactly half of the sources that could disagree is not a majority of them.
///
/// The boundary the test draws, rather than a case well inside it. Every other test here sits
/// comfortably on one side: four kept of four candidates passes, one of three refuses, and both
/// answer the same whether the comparison is `<=` or `<`. Only a receipt sitting exactly on the
/// line tells the two apart, and until 2026-09-19 nothing in this repository did: the whole suite
/// stayed at its own count with that one character changed, and a binary built from it accepted a
/// receipt the shipped one refuses.
///
/// Half is not a majority for the reason the whole test exists. Marzullo's guarantee is that a
/// majority of the sources agreeing bounds the truth, and four against four is two answers with
/// nothing to choose between them.
#[test]
fn exactly_half_of_the_sources_that_could_disagree_is_not_a_majority() {
    let half = |kept: u32| {
        let mut r = receipt();
        r.claim.sources = (0..8)
            .map(|n| {
                record(
                    &format!("s-{n}"),
                    &format!("operator-{n}.example"),
                    (n as u32) < kept,
                )
            })
            .collect();
        r.claim.sources_offered = 8;
        r.claim.sources_kept = kept;
        r
    };

    // Eight answered, all eight could have disagreed, four agreed.
    let refusal = sign_and_open(&half(4)).expect_err("four of eight is not a majority of eight");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("4 of 8 sources that could disagree"),
        "the refusal should be the source majority and name both numbers, got {refusal}"
    );

    // And one more agreeing is a majority, so the refusal above is about the arithmetic and not
    // about something else being wrong with a receipt carrying eight sources.
    sign_and_open(&half(5)).expect("five of eight is a majority of eight");
}

/// A source the issuer runs itself is not one of the parties standing behind the bound.
///
/// `AgentClaim::operators` counts the parties that are not the issuer, which is what makes the
/// operator majority a test about somebody else having agreed. A receipt whose sources are all run
/// by the issuer names no such party, so it is nought of nought and it is refused.
///
/// The exclusion had no test that failed when it was taken out. Measured 2026-09-19: with
/// `.filter(independent)` removed from both counts, the whole suite stayed at its own count and a
/// binary built from it accepted a receipt on which the only parties that agreed were the issuer.
/// That is the one claim this product cannot allow a receipt to make, because it is our own word
/// dressed as several parties'.
#[test]
fn a_source_the_issuer_runs_itself_is_not_one_of_the_operators_behind_the_bound() {
    let issuer_runs_them = |ours: bool| {
        let mut r = receipt();
        r.claim.sources = (0..3)
            .map(|n| SourceRecord {
                first_party: ours,
                ..record(&format!("s-{n}"), &format!("operator-{n}.example"), true)
            })
            .collect();
        r.claim.sources_offered = 3;
        r.claim.sources_kept = 3;
        r
    };

    let refusal = sign_and_open(&issuer_runs_them(true))
        .expect_err("a bound behind which only the issuer stands is not a bound anybody agreed");
    assert!(
        matches!(refusal, ReceiptError::Inconsistent(_)),
        "got {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("run by 0 of the 0 operators that answered"),
        "the refusal should say that nobody outside the issuer answered, got {refusal}"
    );

    // The same three sources run by anybody else hold up, so the refusal above is the exclusion and
    // not the shape of the receipt.
    sign_and_open(&issuer_runs_them(false))
        .expect("three sources run by three other parties is three operators");
}

/// A timescale this format cannot read is refused, and so is a smear policy.
///
/// Both fields were carried on every source and read by nothing until 2026-09-20. A receipt whose
/// sources stated a timescale of `tai+37`, one stating a smear of `linear/86400`, one stating a
/// pending leap second and one whose timescale was a string nobody has ever defined all passed with
/// exit nought, and no line of the report mentioned either field.
///
/// The direction is the one the leap allow-list settled: name the values that permit, so a string
/// this format has never seen refuses rather than being read as whatever is convenient.
#[test]
fn a_timescale_or_a_smear_this_format_cannot_read_is_refused() {
    for stated in [
        "tai",
        "tai+",
        "tai+thirty-seven",
        "tai+37.5",
        "tai+-99999999999999999999",
        // Each of these parses as a number, and none is a spelling the writer produces. Found
        // 2026-09-21: all four were read, so one value had several spellings that hash differently.
        "tai++37",
        "tai+037",
        "tai+-0",
        "TAI+37",
        "UTC",
        "utc ",
        "",
        "gps",
    ] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                timescale: stated.to_string(),
                ..record("a-1", "a.example", false)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
            record("d-1", "d.example", true),
        ];
        r.claim.sources_offered = 4;
        r.claim.sources_kept = 3;

        let refusal = sign_and_open(&r)
            .expect_err("a timescale nothing here can read is not a timescale to measure against");
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "on {stated:?} got {refusal}"
        );
        assert!(
            refusal.to_string().contains("answers on"),
            "on {stated:?} got {refusal}"
        );
    }

    for stated in [
        "linear",
        "linear/",
        "linear/a-day",
        "linear/+86400",
        "linear/086400",
        // A smear spread over no time at all is a step, which is what `none` says.
        "linear/0",
        "Linear/86400",
        "NONE",
        "none ",
        "",
        "smeared",
    ] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                smear: stated.to_string(),
                ..record("a-1", "a.example", false)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
            record("d-1", "d.example", true),
        ];
        r.claim.sources_offered = 4;
        r.claim.sources_kept = 3;

        let refusal = sign_and_open(&r)
            .expect_err("a smear policy nothing here can read says nothing about UTC");
        assert!(
            matches!(refusal, ReceiptError::Field(_)),
            "on {stated:?} got {refusal}"
        );
        assert!(
            refusal.to_string().contains("smears a leap second"),
            "on {stated:?} got {refusal}"
        );
    }
}

/// The shapes it does read still read, so the allow-list is a list and not a wall.
///
/// A rule that refuses everything is as wrong as one that permits everything, and only running both
/// says which this is. A source off UTC is allowed to be in the list; what it may not be is kept,
/// which the test below is about.
#[test]
fn the_timescales_and_smears_this_format_knows_are_read() {
    for timescale in ["utc", "unknown", "tai+37", "tai+0", "tai+-1"] {
        for smear in ["none", "unknown", "linear/86400", "linear/1"] {
            let mut r = receipt();
            r.claim.sources = vec![
                SourceRecord {
                    timescale: timescale.to_string(),
                    smear: smear.to_string(),
                    ..record("a-1", "a.example", false)
                },
                record("b-1", "b.example", true),
                record("c-1", "c.example", true),
                record("d-1", "d.example", true),
            ];
            r.claim.sources_offered = 4;
            r.claim.sources_kept = 3;
            sign_and_open(&r).unwrap_or_else(|e| {
                panic!("{timescale} with a smear of {smear} is a shape this format reads, got {e}")
            });
        }
    }
}

/// A source the selection kept had to have answered on UTC.
///
/// The conversion from anything else is the agent's, made with the offset the source itself stated,
/// and nothing in a receipt lets a reader check it happened. On TAI that is thirty-seven seconds
/// between what a receipt claims and what its sources said, which is the one thing a receipt exists
/// to take out of the signer's hands. Every shipped source client speaks UTC, so this refuses
/// nothing this product writes.
#[test]
fn a_source_the_bound_rests_on_had_to_have_answered_on_utc() {
    for (timescale, said) in [
        ("tai+37", "a conversion the agent made"),
        ("tai+0", "a conversion the agent made"),
        // The agent converts nothing for a source that named no timescale, so the refusal must
        // not say it did. Found 2026-09-21: it said the bound rested on a conversion.
        ("unknown", "named no timescale"),
    ] {
        let mut r = receipt();
        r.claim.sources = vec![
            SourceRecord {
                timescale: timescale.to_string(),
                ..record("a-1", "a.example", true)
            },
            record("b-1", "b.example", true),
            record("c-1", "c.example", true),
        ];
        r.claim.sources_offered = 3;
        r.claim.sources_kept = 3;

        let refusal = sign_and_open(&r)
            .expect_err("a bound resting on a conversion nobody can check is not a bound");
        assert!(
            matches!(refusal, ReceiptError::Inconsistent(_)),
            "on {timescale:?} got {refusal}"
        );
        assert!(
            refusal.to_string().contains(said),
            "on {timescale:?} got {refusal}"
        );
    }

    // The same source, not kept, holds up. So the refusal above is about the bound resting on it
    // and not about the value being in the list at all.
    let mut r = receipt();
    r.claim.sources = vec![
        SourceRecord {
            timescale: "tai+37".to_string(),
            ..record("a-1", "a.example", false)
        },
        record("b-1", "b.example", true),
        record("c-1", "c.example", true),
        record("d-1", "d.example", true),
    ];
    r.claim.sources_offered = 4;
    r.claim.sources_kept = 3;
    sign_and_open(&r)
        .expect("a source on TAI that the selection dropped is a fact about the round");
}
