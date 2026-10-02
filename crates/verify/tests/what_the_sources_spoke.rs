//! What a source said it was speaking, which a reader was never told.
//!
//! Every source in a receipt carries the timescale it answered on and what it does with a leap
//! second, and until 2026-09-20 no reader anywhere touched either. The agent does read the
//! timescale, in `Sample::from_exchange`, where a source answering on TAI is converted to UTC using
//! the offset that source stated. A reader checking a receipt a stranger handed them was trusting
//! the signer to have done that conversion and had no way to see whether it was done, and on TAI
//! the difference is thirty-seven seconds, wider than either shipped ceiling allows a receipt to
//! state: two seconds for the one-shot command and 250 ms for the agent.
//!
//! The refusals live in the receipt crate, where a value nothing can read belongs, and they are
//! held by `crates/receipt/tests/dishonest_receipts.rs`. What is left for a reader is to be told,
//! and this file is about the telling. A reader given nothing cannot tell a receipt whose sources
//! all spoke UTC from a receipt nobody looked at.

mod common;

use timewitness_receipt::anchors::TrustAnchors;
use timewitness_receipt::schema::{Receipt, SourceRecord};
use timewitness_verify::{verify, Floor, State, Subject};

/// The question this file is about, as the report asks it.
const SPOKEN: &str = "what did each source say it was speaking";

fn signed(receipt: &Receipt) -> Vec<u8> {
    common::key()
        .sign(receipt)
        .expect("the agent signs its own receipt")
}

fn detail(bytes: &[u8]) -> String {
    let assessment = verify(
        bytes,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    let step = assessment
        .steps
        .iter()
        .find(|s| s.question == SPOKEN)
        .unwrap_or_else(|| {
            panic!(
                "the report has no step asking {SPOKEN:?}; it asks {:?}",
                assessment
                    .steps
                    .iter()
                    .map(|s| s.question.clone())
                    .collect::<Vec<_>>()
            )
        });
    match &step.state {
        State::Held(detail) => detail.clone(),
        other => panic!("the step is {other:?}, and it is not a step that grades anything"),
    }
}

#[test]
fn a_receipt_whose_sources_all_spoke_utc_says_so_rather_than_saying_nothing() {
    let said = detail(&signed(&common::receipt_local_only()));
    assert!(
        said.contains("answered on UTC"),
        "a reader is told the ordinary case as well, and got {said:?}"
    );
    assert!(
        said.contains("nothing was converted"),
        "the detail says what the ordinary case means, and got {said:?}"
    );
}

#[test]
fn a_source_that_spreads_a_leap_second_out_is_named_with_its_window() {
    let mut receipt = common::receipt_local_only();
    receipt.claim.sources[0] = SourceRecord {
        smear: "linear/86400".to_string(),
        ..receipt.claim.sources[0].clone()
    };
    let said = detail(&signed(&receipt));

    assert!(
        said.contains("spreads a leap second over 86400 seconds"),
        "the window the source stated is what a reader needs, and got {said:?}"
    );
    assert!(
        said.contains("up to a second from UTC"),
        "and what that costs, and got {said:?}"
    );
}

/// A smear of `unknown` is the ordinary case and is not reported.
///
/// Every shipped source client sets it, because NTP, NTS and Roughtime have no field in which a
/// server says what it does with a leap second. A step that puts a line in front of every reader of
/// every receipt is a step nobody reads, so the reporting is about what a source did say rather
/// than about what it could not.
#[test]
fn a_source_that_did_not_say_what_it_does_with_a_leap_second_is_not_reported_as_unusual() {
    let mut receipt = common::receipt_local_only();
    for source in &mut receipt.claim.sources {
        source.smear = "unknown".to_string();
    }
    let said = detail(&signed(&receipt));
    assert!(
        said.contains("answered on UTC"),
        "nine sources that said nothing about leap seconds is the ordinary case, and got {said:?}"
    );
}

/// A source off UTC that the selection dropped is named, and says it was dropped.
///
/// It cannot be kept: the receipt crate refuses a receipt whose bound rests on a conversion nobody
/// can check. What it can be is in the list, and a reader should see it was there.
#[test]
fn a_source_on_another_timescale_that_was_dropped_is_named_and_said_to_have_been_dropped() {
    let mut receipt = common::receipt_local_only();
    receipt.claim.sources.push(SourceRecord {
        id: "source-on-tai".to_string(),
        timescale: "tai+37".to_string(),
        kept: false,
        ..receipt.claim.sources[0].clone()
    });
    receipt.claim.sources_offered += 1;
    let said = detail(&signed(&receipt));

    assert!(
        said.contains("answered on tai+37"),
        "the timescale the source stated is what a reader needs, and got {said:?}"
    );
    assert!(
        said.contains("was not kept"),
        "and that the bound does not rest on it, and got {said:?}"
    );
    assert!(
        said.contains("no source this bound rests on is one of them"),
        "and the reader is told what that means, and got {said:?}"
    );
}

/// A kept source announcing a leap second is named, with which way the second goes.
///
/// Found 2026-09-21: a receipt whose kept source said a second was about to be added was reported
/// as all nine sources answering on UTC with nothing to say, which is true of the timescale and
/// leaves out the one thing that source did say. Around a leap second a source's answers and
/// another's can differ by the second itself, so a reader should be told it was announced.
#[test]
fn a_source_announcing_a_leap_second_is_named_rather_than_left_out() {
    for (leap, words) in [
        ("add-second", "announced a leap second being added"),
        ("delete-second", "announced a leap second being removed"),
    ] {
        let mut receipt = common::receipt_local_only();
        receipt.claim.sources[0] = SourceRecord {
            leap: leap.to_string(),
            ..receipt.claim.sources[0].clone()
        };
        let id = receipt.claim.sources[0].id.clone();
        let said = detail(&signed(&receipt));
        assert!(said.contains(words), "on {leap}, got {said:?}");
        assert!(said.contains(&id), "the source is named, and got {said:?}");
        assert!(
            !said.contains("nothing was converted"),
            "the ordinary case is not what this is, and got {said:?}"
        );
    }
}
