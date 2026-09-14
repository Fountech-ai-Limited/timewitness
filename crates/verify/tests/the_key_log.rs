//! What a reader with a key log can establish about the key that signed a receipt.
//!
//! The verifier's third step has read `nothing here can say` since the verifier was written, and it
//! still does for a reader who has only the receipt. This file is the other reader: somebody handed
//! a log as well, who can now ask whether the key that signed this was one of ours at the moment of
//! the reading, and get a refusal rather than a shrug when it was not.
//!
//! **What none of this makes true.** The log is ours and we sign it, so a reader seeing one for the
//! first time is trusting us about our own keys. Our own word is still not third-party evidence in
//! any test here: the weight of a receipt rests on the third-party signatures in it, and the step
//! says so in the words it answers with.

mod common;

use timewitness_core::keylog::file::{sign_head, KeyLog, SignedHead};
use timewitness_core::keylog::{KeyEntry, TreeHead};
use timewitness_core::time::UnixNanos;
use timewitness_verify::{anchor_file, verify, verify_with_key_log, Floor, State, Subject};

/// The key that signed the committed receipt, and the moment it reads.
fn the_receipt() -> (Vec<u8>, [u8; 32], UnixNanos) {
    let signed = common::signed();
    let assessment = verify(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
    );
    let receipt = assessment
        .receipt
        .expect("the fixture is a readable receipt");
    let key: [u8; 32] = receipt
        .agent_public_key
        .as_slice()
        .try_into()
        .expect("an Ed25519 agent key");
    (signed, key, receipt.utc_estimate)
}

fn entry(key: [u8; 32], from: UnixNanos, until: Option<UnixNanos>) -> KeyEntry {
    KeyEntry {
        public_key: key,
        deployment: "a build runner".to_string(),
        valid_from: from,
        valid_until: until,
    }
}

fn signed_log(entries: Vec<KeyEntry>) -> KeyLog {
    let mut log = KeyLog {
        entries,
        head: None,
    };
    log.head = Some(sign_head(
        &log,
        &[3u8; 32],
        UnixNanos(1_800_000_000_000_000_000),
    ));
    log
}

/// The step in question, off a run with whatever log was supplied.
fn the_step(signed: &[u8], log: Option<&KeyLog>) -> State {
    verify_with_key_log(
        signed,
        Subject::Digest(&common::SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
        log,
    )
    .steps
    .into_iter()
    .find(|step| step.question == "is that key one of ours")
    .expect("the verifier asks this of every receipt")
    .state
}

#[test]
fn without_a_log_the_step_is_unanswered_and_says_so() {
    let (signed, _, _) = the_receipt();
    let state = the_step(&signed, None);
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(
        state.detail().contains("nothing here can say"),
        "the words a reader has had since the verifier was written: {}",
        state.detail()
    );
}

#[test]
fn a_log_naming_the_key_over_the_reading_answers_it_and_says_what_the_answer_is_worth() {
    let (signed, key, at) = the_receipt();
    let log = signed_log(vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Held(_)), "{state:?}");

    // The sentence that keeps our own word from reading as third-party evidence. A step that
    // answered `held` and left a reader thinking a third party had vouched for the key would be
    // worse than the shrug it replaced, because a shrug is at least honest about what nobody
    // checked.
    let detail = state.detail();
    assert!(detail.contains("a list we signed"), "{detail}");
    assert!(detail.contains("not third-party evidence"), "{detail}");
    assert!(
        detail.contains("the third-party signatures in it"),
        "{detail}"
    );
}

#[test]
fn a_log_that_does_not_name_the_key_refuses_rather_than_shrugging() {
    // A reader who supplied a log asked the question. "Your log does not have this key" is an
    // answer to it, and reporting that as unchecked would hide a receipt signed by something the
    // log has never heard of.
    let (signed, _, at) = the_receipt();
    let log = signed_log(vec![entry([9u8; 32], UnixNanos(at.0 - 1), None)]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(state.detail().contains("none of them names this key"));
}

#[test]
fn a_key_retired_before_the_reading_refuses() {
    // The property the window is for, and the reason an entry carries one rather than a date. A
    // stolen agent key is worth what is left of its window, and a receipt signed after it was
    // retired is exactly what a theft produces.
    let (signed, key, at) = the_receipt();
    let log = signed_log(vec![entry(
        key,
        UnixNanos(at.0 - 1_000_000_000),
        Some(UnixNanos(at.0 - 1)),
    )]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("falls outside"),
        "{}",
        state.detail()
    );
}

#[test]
fn a_head_whose_signature_was_moved_onto_it_refuses_and_nothing_under_it_is_read() {
    // Everything about this log is well-formed. The entries hash to the root, the root is on the
    // head, the signature is a real Ed25519 signature by the key the head names, and it is over a
    // different head. A verifier that checked the entries and not the head would report `held` on a
    // log somebody had rewritten and signed the old head of.
    let (signed, key, at) = the_receipt();
    let mut log = signed_log(vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)]);
    let elsewhere = KeyLog {
        entries: vec![entry([4u8; 32], UnixNanos(0), None)],
        head: None,
    };
    let moved: SignedHead = sign_head(&elsewhere, &[3u8; 32], UnixNanos(1_800_000_000_000_000_000));
    log.head = Some(SignedHead {
        head: TreeHead {
            size: log.entries.len(),
            root: log.root(),
            at: moved.head.at,
        },
        signature: moved.signature,
        signed_by: moved.signed_by,
    });

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("not signed by the key"),
        "{}",
        state.detail()
    );
}

#[test]
fn a_log_with_no_head_still_answers_and_says_nobody_signed_it() {
    let (signed, key, at) = the_receipt();
    let log = KeyLog {
        entries: vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)],
        head: None,
    };

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Held(_)), "{state:?}");
    assert!(
        state.detail().contains("nobody has put their name to it"),
        "{}",
        state.detail()
    );
}
