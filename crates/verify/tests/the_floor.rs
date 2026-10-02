//! Receipts that keep every promise they make and are refused anyway.
//!
//! Each one below is correctly signed, internally consistent, and passes every check the receipt
//! crate can make, because the receipt crate checks a receipt against the policy the receipt states
//! for itself and each of these states a policy it keeps to. They are refused by the reader's own
//! floor instead, which is the difference between checking numbers and checking labels.
//!
//! Every case is watched being accepted first, by the same validator with the floor lifted, so the
//! file records what happens without it rather than asserting that something is now better.

mod common;

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::UnixNanos;
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::schema::{BreakdownRecord, Receipt, SourceRecord};
use timewitness_receipt::AgentKey;
use timewitness_verify::{verify, Floor, Subject};

/// A floor that refuses nothing, for watching a case pass before the real one refuses it.
fn lifted() -> Floor {
    Floor {
        min_interval_width: 0,
        max_interval_width: Nanos::MAX,
        min_candidate_sources: 0,
        min_operators_kept: 0,
        max_encoded_bytes: usize::MAX,
    }
}

/// A receipt whose whole interval is `width` nanoseconds, with the parts adding up to it, and whose
/// own stated ceiling allows it.
fn of_width(width: Nanos) -> Vec<u8> {
    let half = width / 2;
    let mut receipt = common::receipt_local_only();
    receipt.claim.earliest = UnixNanos(common::CORRIDOR_AT - half);
    receipt.claim.latest = UnixNanos(common::CORRIDOR_AT + half);
    receipt.claim.breakdown = BreakdownRecord {
        intersection_half: half,
        network_half: 0,
        scheduling: 0,
        oscillator_holdover: 0,
        model_residual: 0,
        safety_margin: 0,
        unclaimed_rate: None,
    };
    // Its own ceiling allows it, so nothing inside the receipt objects.
    receipt.claim.policy.max_bound_width = width.max(1) * 2;
    sign(&receipt)
}

fn sign(receipt: &Receipt) -> Vec<u8> {
    AgentKey::from_seed(&common::SEED)
        .sign(receipt)
        .expect("the agent signs its own receipt")
}

/// The two questions asked of every case: does it pass without the floor, and does it fail with it.
fn watched(name: &str, signed: &[u8]) {
    let without = verify(
        signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &lifted(),
    );
    assert!(
        without.accepted(),
        "{name}: with the floor lifted this was supposed to be accepted, and it was refused by {:?}. \
         A case the rest of the validator already catches proves nothing about the floor",
        without.refusal()
    );

    let with = verify(
        signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(!with.accepted(), "{name}: the floor let this through");
    let refusal = with.refusal().expect("something refused it");
    assert!(
        refusal.question.contains("floor"),
        "{name}: refused by {:?} rather than by the floor",
        refusal.question
    );
}

#[test]
fn a_bound_zero_nanoseconds_wide_is_refused() {
    // The receipt that started this: every part of the breakdown zero, the interval a single
    // instant, the agent's own stated ceiling satisfied because zero is under anything. It says UTC
    // was at exactly this nanosecond, which is a claim no machine on any path this product is built
    // for can support, and whoever issued it has claimed in our name a precision nothing measured.
    watched("a bound of no width at all", &of_width(0));
}

#[test]
fn a_bound_two_nanoseconds_wide_is_refused() {
    watched("two nanoseconds", &of_width(2));
}

#[test]
fn a_bound_a_hundred_nanoseconds_wide_is_refused() {
    // Nanoseconds is the resolution of the local read and never the accuracy to UTC. The two get
    // confused constantly and that confusion is the problem this product exists to fix.
    watched("a hundred nanoseconds", &of_width(100));
}

#[test]
fn a_bound_at_the_tightest_condition_the_product_quotes_is_accepted() {
    // Two hundred microseconds, being an interval around the hundred microseconds of accuracy the
    // documents quote for a cloud instance with a hypervisor clock. The floor has to sit under this
    // or it refuses the product's own best case, and a refusal there would look exactly like
    // catching a lie.
    let signed = of_width(200_000);
    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(
        assessment.accepted(),
        "the floor refused an honest best case: {:?}",
        assessment.refusal()
    );
}

#[test]
fn a_reader_who_wants_a_tighter_floor_sets_one() {
    // And the way a future receipt from better hardware is read is the same lever the other way: the
    // floor is the reader's, it is printed beside the verdict, and it is not compiled into what a
    // receipt means.
    let signed = of_width(200_000);
    let strict = Floor {
        min_interval_width: NANOS_PER_MILLI,
        ..Floor::default()
    };
    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &strict,
    );
    assert!(!assessment.accepted());
}

#[test]
fn a_bound_wider_than_an_hour_is_refused() {
    // Past an hour an interval says nothing about when something happened that a calendar would not.
    watched("wider than an hour", &of_width(2 * 3_600 * NANOS_PER_SEC));
}

#[test]
fn a_receipt_resting_on_one_source_is_refused_however_honestly_it_says_so() {
    // It states `min_sources: 1` and it answered on one, so it kept its word. One clock is not a
    // majority and there is nothing for a selection rule to discard.
    let mut receipt = common::receipt_local_only();
    receipt.claim.sources_offered = 1;
    receipt.claim.sources_kept = 1;
    receipt.claim.sources = vec![SourceRecord {
        id: "the only one".to_string(),
        operator: Some("the only one".to_string()),
        kind: "ntp".to_string(),
        timescale: "utc".to_string(),
        smear: "none".to_string(),
        leap: "none".to_string(),
        kept: true,
        first_party: false,
    }];
    receipt.claim.policy.min_sources = 1;
    // And an independence floor of one, for the same reason. This receipt is supposed to be one the
    // rest of the validator accepts, so that what refuses it is the reader's own floor and nothing
    // else; a receipt breaking its own word is a different test in a different crate.
    receipt.claim.policy.min_operators = Some(1);
    watched("one source", &sign(&receipt));
}

/// A receipt with `count` sources, all kept, sharing `operators` distinct parties between them.
///
/// The names are handed out round-robin, so nine sources at two operators is what it looks like on
/// the wire: nine entries, nine agreeing, and two parties who could be wrong.
fn of_sources(count: usize, operators: usize) -> Receipt {
    let mut receipt = common::receipt_local_only();
    receipt.claim.sources_offered = count as u32;
    receipt.claim.sources_kept = count as u32;
    receipt.claim.sources = (0..count)
        .map(|i| SourceRecord {
            id: format!("name-{i}.example"),
            operator: Some(format!("operator-{}.example", i % operators.max(1))),
            kind: "ntp".to_string(),
            timescale: "utc".to_string(),
            smear: "none".to_string(),
            leap: "none".to_string(),
            kept: true,
            first_party: false,
        })
        .collect();
    receipt.claim.policy.min_sources = 1;
    // The receipt keeps its own word, so what refuses it is the reader's floor and nothing else.
    receipt.claim.policy.min_operators = Some(operators.max(1) as u32);
    receipt
}

#[test]
fn nine_names_at_two_companies_are_refused_however_many_of_them_agree() {
    // The receipt the operator floor exists for. Nine sources answered, nine were kept, every count
    // in it is honest, and its own stated independence floor is two because two is what it had. It
    // clears the floor on sources with six to spare. Two parties who could both be wrong is not a
    // majority of three, and a reader with only the source count in front of them cannot see that.
    watched("nine names at two companies", &sign(&of_sources(9, 2)));
}

#[test]
fn nine_names_at_one_company_are_refused() {
    // The same shape at its limit: one party, nine chances to say the same wrong thing.
    watched("nine names at one company", &sign(&of_sources(9, 1)));
}

#[test]
fn three_names_at_three_companies_are_accepted() {
    // And the floor has to let this through, or it refuses the arithmetic it exists to protect.
    let signed = sign(&of_sources(3, 3));
    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(
        assessment.accepted(),
        "the operator floor refused an honest three-party receipt: {:?}",
        assessment.refusal()
    );
}

#[test]
fn a_receipt_naming_no_operator_at_all_is_refused_by_the_reader_and_not_by_the_format() {
    // The two questions pulled apart. `timewitness_receipt` asks whether the agent kept its own
    // word and a receipt predating the field kept it, so that crate accepts this. The reader is
    // asked to believe the sources failing would be separate events, and this receipt offers
    // nothing to believe it on, so the reader's floor refuses it.
    let mut receipt = of_sources(9, 9);
    for source in &mut receipt.claim.sources {
        source.operator = None;
    }
    receipt.claim.policy.min_operators = None;
    let signed = sign(&receipt);

    // `open` reads the signature and runs every check the format makes, so this succeeding is the
    // receipt crate saying it has no objection.
    timewitness_receipt::open(&signed)
        .expect("the format accepts a receipt that predates the operator field");

    watched("no operator named anywhere", &signed);

    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    let refusal = assessment.refusal().expect("something refused it");
    assert!(
        refusal.state.detail().contains("names no operator"),
        "the refusal has to say which of the two it is: {:?}",
        refusal.state.detail()
    );
}

#[test]
fn a_source_that_said_its_own_clock_was_unset_is_not_counted_as_a_party() {
    // The counting is shared with the receipt crate's own majority test, and both drop a source
    // that told the agent it was not synchronised. Counting it here would make the reader's test
    // strictly harder than the one the agent ran, and two shells of one product refusing each
    // other's artefacts is a lesson already paid for once, at a new boundary.
    let mut receipt = of_sources(3, 3);
    receipt.claim.sources.push(SourceRecord {
        id: "answered but unset.example".to_string(),
        operator: Some("a fourth party.example".to_string()),
        kind: "ntp".to_string(),
        timescale: "utc".to_string(),
        smear: "none".to_string(),
        leap: "unsynchronised".to_string(),
        kept: false,
        first_party: false,
    });
    receipt.claim.sources_offered = 4;

    let operators = receipt.claim.operators();
    assert_eq!(operators.offered, 3, "the unset source is not a party");
    assert_eq!(operators.kept, 3);

    let assessment = verify(
        &sign(&receipt),
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(
        assessment.accepted(),
        "an unset source dragged an honest receipt under the floor: {:?}",
        assessment.refusal()
    );
}

#[test]
fn a_reader_who_will_take_a_two_party_receipt_says_so_and_gets_it() {
    // The floor is the reader's. Lowering it is a thing they do knowingly and it is printed beside
    // the verdict either way, which is the whole difference between a floor and a rule.
    let signed = sign(&of_sources(9, 2));
    let lenient = Floor {
        min_operators_kept: 2,
        ..Floor::default()
    };
    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &lenient,
    );
    assert!(
        assessment.accepted(),
        "a reader who lowered the floor was refused anyway: {:?}",
        assessment.refusal()
    );
}

#[test]
fn a_receipt_larger_than_this_reader_will_open_is_refused_before_anything_is_parsed() {
    // A label nobody reads carrying a megabyte was accepted at a million bytes when this was found.
    // Refusing on size is what a reader can do about that without settling what a chain link should
    // be taken over, which is a separate question.
    let signed = common::signed_local_only();
    let mut padded = signed.clone();
    padded.extend(std::iter::repeat_n(0u8, 128 * 1024));

    let assessment = verify(
        &padded,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(!assessment.accepted());
    assert_eq!(
        assessment.steps.len(),
        1,
        "it stopped at the first question"
    );
}

#[test]
fn the_floor_the_reader_used_is_printed_beside_the_verdict() {
    // A threshold nobody can see is a threshold nobody can argue with.
    let assessment = verify(
        &common::signed_local_only(),
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    let lines = assessment.floor.lines();
    assert!(lines.iter().any(|l| l.contains("no narrower than")));
    assert!(lines.iter().any(|l| l.contains("sources answering")));
    assert!(lines.iter().any(|l| l.contains("distinct operators")));
}

/// The floor this verifier ships with and the floor the format states are the same floor.
///
/// A floor that lives only in this crate is this verifier's opinion. A second implementation reads
/// `docs/receipt-format-v0.md`, picks its own numbers, and two readers disagree about the same
/// receipt, which is the one thing a portable format cannot afford. So the document states the
/// numbers and this test holds the code to them: changing one without the other turns this red.
#[test]
fn the_document_and_the_code_state_the_same_floor() {
    const FORMAT: &str = include_str!("../../../docs/receipt-format-v0.md");
    let floor = Floor::default();

    // Written the way a person reads them, which is how the document has to carry them, with the
    // nanosecond value each one has to equal beside it.
    let stated = [
        (
            "| Narrowest whole interval | 1 us |",
            floor.min_interval_width,
            1_000,
        ),
        (
            "| Widest whole interval | 1 hour |",
            floor.max_interval_width,
            3_600 * NANOS_PER_SEC,
        ),
    ];
    for (row, shipped, meant) in stated {
        assert!(
            FORMAT.contains(row),
            "the format document no longer states `{row}`"
        );
        assert_eq!(
            shipped, meant,
            "the shipped floor no longer matches `{row}`"
        );
    }

    assert!(FORMAT.contains("| Fewest sources answering | 3 |"));
    assert_eq!(floor.min_candidate_sources, 3);
    assert!(FORMAT.contains("| Fewest operators behind the sources kept | 3 |"));
    assert_eq!(floor.min_operators_kept, 3);
    assert!(FORMAT.contains("| Largest encoded receipt | 64 KiB |"));
    assert_eq!(floor.max_encoded_bytes, 64 * 1024);

    // And the two things the document says about the floor that are not numbers, because a reader
    // meeting a refusal has to find the answer where they are looking.
    assert!(FORMAT.contains("A sound receipt this floor refuses"));
    assert!(FORMAT.contains("only ever refuses"));
}
