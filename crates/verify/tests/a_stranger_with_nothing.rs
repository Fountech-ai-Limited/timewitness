//! What a stranger holding nothing but the bytes can establish, and what they cannot.
//!
//! The free public verifier is proved by somebody with neither of our machines and no account
//! verifying a receipt end to end. This file is that person, four times over: holding everything
//! published, holding their own list, holding nothing at all, and holding the wrong thing.
//!
//! Nothing here opens a socket. That is not an accident of how the tests were written: the crate
//! under test may not import anything that can, and the module boundary test fails the build if that
//! ever changes.

mod common;

use timewitness_receipt::anchors::TrustAnchors;
use timewitness_verify::{anchor_file, verify, Floor, State, Subject};

/// The keys that ship, with a figure this reader allows for each authority's own clock.
///
/// Added 2026-09-19. Both authorities that ship state no accuracy in their
/// tokens, so on the shipped material nothing bounds a receipt from above and no sandwich can be
/// granted at all. That is its own test below. These tests are about the sandwich rules rather
/// than about the accuracy rules, so this reader allows nothing, which is a statement a reader may
/// make about an authority and one the code may never make for them.
fn published_allowing_nothing_for_their_clocks() -> TrustAnchors {
    let mut anchors = anchor_file::published();
    for authority in &mut anchors.timestamp_authorities {
        authority.accuracy_where_the_token_states_none = Some(0);
    }
    anchors
}

#[test]
fn a_stranger_holding_the_published_keys_checks_all_three_roles() {
    let signed = common::signed();

    // Nothing of ours is supplied here. `published()` is three Roughtime server keys, one drand
    // chain and two certificate pins, every one of them published by somebody who has never heard
    // of this product, and a reader who would rather not take the shipped copy can supply their own.
    let assessment = verify(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &published_allowing_nothing_for_their_clocks(),
        &Floor::default(),
    );

    assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
    assert_eq!(assessment.checked_entries(), 3);

    let evidence = assessment.evidence.as_ref().expect("a report");
    assert!(evidence.basis_granted, "{}", evidence.basis_reason);

    // Three roles, each named and each kept apart. A verifier that collapsed these into one badge
    // would have hidden the only thing a careful reader wants.
    let roles: Vec<&str> = evidence.entries.iter().map(|e| e.role.as_str()).collect();
    assert_eq!(
        roles,
        vec![
            "authenticated-utc-corridor",
            "not-earlier-than",
            "not-later-than"
        ]
    );
}

#[test]
fn a_stranger_holding_nothing_still_checks_everything_the_receipt_says_about_itself() {
    // The common case, and it is not a degraded one. Every arithmetic claim is checked and every
    // attestation is reported as unchecked rather than glossed, which is what this reader
    // actually knows.
    let signed = common::signed_local_only();
    let assessment = verify(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &TrustAnchors::none(),
        &Floor::default(),
    );

    assert!(assessment.accepted(), "{:?}", assessment.refusal());
    assert_eq!(assessment.anchors_held, 0);
    assert_eq!(assessment.checked_entries(), 0);

    let evidence = assessment.evidence.as_ref().expect("a report");
    assert!(!evidence.basis_granted);
    assert!(
        evidence.basis_reason.contains("cannot be checked"),
        "{}",
        evidence.basis_reason
    );
    assert_eq!(evidence.entries.len(), 3, "the entries are still reported");
}

#[test]
fn a_receipt_claiming_a_sandwich_to_a_reader_who_cannot_check_one_is_refused() {
    // The sharp case. A receipt saying its bound rests on three outside signatures, read by
    // somebody holding nothing, is not a receipt with a weaker claim. It is a claim that could not
    // be granted, and granting it would be presenting our own bound as third-party evidence.
    let signed = common::signed();
    let assessment = verify(
        &signed,
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(!assessment.accepted());
}

#[test]
fn a_sandwich_claimed_over_a_width_narrower_than_its_bracket_is_refused_and_says_why() {
    // The receipt the verifier granted until 2026-09-15: three genuine signatures enclosing four
    // seconds, and a claim of a hundred milliseconds inside them that says it rests on the three.
    // The line under the verdict then read "rests on outside signatures" over a width no outside
    // signature supported. Watched granted on `2e683e6` first.
    let assessment = verify(
        &common::signed_narrower_than_its_bracket(),
        Subject::Digest(&common::SUBJECT),
        &published_allowing_nothing_for_their_clocks(),
        &Floor::default(),
    );
    assert!(
        !assessment.accepted(),
        "a 100 ms width inside a 4 s bracket was granted a sandwich"
    );
    let refusal = assessment.refusal().expect("refused");
    assert_eq!(refusal.question, "is every claim in the right place");
    assert!(
        refusal.state.detail().contains("does not cover"),
        "{}",
        refusal.state.detail()
    );
    assert!(
        assessment.bracket().is_none(),
        "a refused receipt has no line under its verdict"
    );

    // And the receipt that covers its bracket is granted, with the line under the verdict naming a
    // width no narrower than the bracket, because from now on it cannot be.
    let assessment = verify(
        &common::signed(),
        Subject::Digest(&common::SUBJECT),
        &published_allowing_nothing_for_their_clocks(),
        &Floor::default(),
    );
    assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
    assert_eq!(
        assessment.bracket().as_deref(),
        Some("Its 4.000 s width rests on outside signatures, and the checked ones bracket the moment to 4 s.")
    );
}

/// The same receipt against the keys exactly as they ship: accepted, and no sandwich.
///
/// Changed 2026-09-19. Neither authority that ships states an accuracy in its tokens, so
/// neither puts a number on how wrong its own clock could be and neither bounds a receipt from
/// above. Until that day the arithmetic read the absent field as a stated nought and granted this
/// receipt a sandwich on a four second bracket, one edge of which was an assumption of ours. The
/// receipt is still accepted, because nothing in it is false; what it may not do is say its width
/// rests on outside signatures.
#[test]
fn against_the_keys_exactly_as_they_ship_no_sandwich_is_granted_and_it_says_why() {
    let assessment = verify(
        &common::signed(),
        Subject::Digest(&common::SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
    );
    assert!(
        !assessment.accepted(),
        "a receipt claiming a sandwich on an authority that states no accuracy was granted one"
    );
    let refusal = assessment.refusal().expect("refused");
    assert!(
        refusal
            .state
            .detail()
            .contains("states no accuracy of its own"),
        "{}",
        refusal.state.detail()
    );

    // The same receipt resting on its own model is accepted, and the entries were all checked.
    // What changed is that one of them supports no edge, and a reader told the role was unchecked
    // would have been told something false.
    let assessment = verify(
        &common::signed_local_only(),
        Subject::Digest(&common::SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
    );
    assert!(assessment.accepted(), "refused: {:?}", assessment.refusal());
    let evidence = assessment.evidence.as_ref().expect("a report");
    assert_eq!(evidence.checked(), 3);
    let bracket = evidence.bracket();
    assert_eq!(bracket.not_later, None);
    assert!(bracket.not_later_was_checked_and_bounds_nothing);
    assert!(bracket.not_earlier.is_some());
}

#[test]
fn a_stranger_holding_their_own_list_gets_the_same_answer_on_the_key_they_hold() {
    let text = "\
roughtime roughtime.se 4b70337d92790a349d909db564919bc6a7583ff4a813c7d7298d3e6a272c7a12
";
    let anchors = anchor_file::parse(text).expect("one well-formed line");
    let assessment = verify(
        &common::signed_local_only(),
        Subject::Digest(&common::SUBJECT),
        &anchors,
        &Floor::default(),
    );

    assert!(assessment.accepted(), "{:?}", assessment.refusal());
    // One anchor, so one of the three entries is checked and two are reported as unchecked, with
    // the reason being a fact about this reader rather than a fault in the receipt.
    assert_eq!(assessment.checked_entries(), 1);
}

#[test]
fn the_subject_is_hashed_here_and_a_receipt_for_a_different_thing_is_refused() {
    let signed = common::signed_local_only();

    // The bytes go in and are hashed on this machine. Nothing is uploaded to establish a digest,
    // which for a confidential artefact would leak the artefact in order to prove something about
    // its timestamp.
    let assessment = verify(
        &signed,
        Subject::Bytes(b"a different artefact entirely"),
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(!assessment.accepted());
    let refusal = assessment.refusal().expect("refused");
    assert!(
        refusal.state.detail().contains("a different thing"),
        "{}",
        refusal.state.detail()
    );
}

#[test]
fn a_reader_who_supplies_no_subject_is_told_so_rather_than_being_passed() {
    let assessment = verify(
        &common::signed_local_only(),
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    assert!(assessment.accepted());

    let step = assessment
        .steps
        .iter()
        .find(|s| s.question.contains("the thing this receipt stamps"))
        .expect("the subject step is always reported");
    assert!(matches!(step.state, State::NotChecked(_)));
}

#[test]
fn nothing_is_reported_as_checked_that_nobody_checked() {
    // The property the whole report type exists for. Every step is one of three states and there is
    // no fourth that quietly reads as a pass.
    let assessment = verify(
        &common::signed_local_only(),
        Subject::NotSupplied,
        &TrustAnchors::none(),
        &Floor::default(),
    );
    for step in &assessment.steps {
        assert!(
            !step.state.detail().is_empty(),
            "{} said nothing about itself",
            step.question
        );
    }
    let unchecked = assessment
        .steps
        .iter()
        .filter(|s| matches!(s.state, State::NotChecked(_)))
        .count();
    assert!(
        unchecked >= 3,
        "a reader holding nothing and supplying nothing should have several unchecked steps, and \
         this had {unchecked}"
    );
}
