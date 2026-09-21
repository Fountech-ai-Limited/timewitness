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
//!
//! **Whose log it is.** Every log here that is meant to be ours is signed by a key the reader's
//! anchors hold for us, and the tests that turned red on 2026-09-15 are the ones where it is not:
//! until then every test in this file signed its log with an arbitrary key and the verifier called
//! it ours, which is why none of them could see the fault.

mod common;

use timewitness_core::keylog::file::{sign_head, KeyLog, SignedHead};
use timewitness_core::keylog::{KeyEntry, Role, TreeHead};
use timewitness_core::time::UnixNanos;
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_verify::{
    anchor_file, verify, verify_with_kept_log, verify_with_key_log, Floor, State, Subject,
    KEPT_LOG_QUESTION, KEY_LOG_QUESTION,
};

/// The secret half of the key this reader holds for our log's head. Made up for these tests; the
/// real one is never in this repository.
const OUR_SIGNING_KEY: [u8; 32] = [3u8; 32];

/// A key nobody holds for us.
const SOMEBODY_ELSES_KEY: [u8; 32] = [4u8; 32];

/// The key that signed the committed receipt, and the moment it reads.
fn the_receipt() -> (Vec<u8>, [u8; 32], UnixNanos) {
    let signed = common::signed();
    let assessment = verify(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &anchors(),
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

/// The shipped third-party anchors, with the head key this reader holds for us in place of the
/// published one.
///
/// The authorities also carry an allowance for their own clocks, as `common::anchors` does and for
/// the same reason. Both shipped authorities state no accuracy in their tokens, so without a figure
/// this reader has chosen, the fixture claiming a sandwich is refused before a key log is reached
/// and every test here fails on something that is not about key logs. Changed 2026-09-19.
fn anchors() -> TrustAnchors {
    let mut anchors = anchor_file::published();
    for authority in &mut anchors.timestamp_authorities {
        authority.accuracy_where_the_token_states_none = Some(0);
    }
    anchors.key_log_signers.clear();
    let ours = sign_head(&KeyLog::default(), &OUR_SIGNING_KEY, UnixNanos(0)).signed_by;
    anchors.with_key_log_signer("ours, for these tests", ours)
}

fn entry(key: [u8; 32], from: UnixNanos, until: Option<UnixNanos>) -> KeyEntry {
    KeyEntry {
        issued: None,
        public_key: key,
        role: Role::Agent,
        deployment: "a build runner".to_string(),
        valid_from: from,
        valid_until: until,
    }
}

fn server(key: [u8; 32]) -> KeyEntry {
    KeyEntry {
        role: Role::Server,
        deployment: "a roughtime server of ours".to_string(),
        ..entry(key, UnixNanos(0), None)
    }
}

fn retired(key: [u8; 32], at: UnixNanos) -> KeyEntry {
    KeyEntry {
        role: Role::Retired,
        deployment: "retired".to_string(),
        ..entry(key, at, None)
    }
}

fn signed_by(entries: Vec<KeyEntry>, secret: &[u8; 32], at: i128) -> KeyLog {
    let mut log = KeyLog {
        checkpoints: Vec::new(),
        entries,
        head: None,
    };
    log.head = Some(sign_head(&log, secret, UnixNanos(at)));
    log
}

/// A log signed by the key this reader holds for us.
fn our_log(entries: Vec<KeyEntry>) -> KeyLog {
    signed_by(entries, &OUR_SIGNING_KEY, 1_800_000_000_000_000_000)
}

/// The step in question, off a run with whatever log was supplied.
fn the_step(signed: &[u8], log: Option<&KeyLog>) -> State {
    verify_with_key_log(
        signed,
        Subject::Digest(&common::SUBJECT),
        &anchors(),
        &Floor::default(),
        log,
    )
    .steps
    .into_iter()
    .find(|step| step.question == KEY_LOG_QUESTION)
    .expect("the verifier asks this of every receipt")
    .state
}

/// The kept-log step, and whether the run as a whole was accepted.
fn the_kept_step(signed: &[u8], log: &KeyLog, kept: &KeyLog) -> (State, bool) {
    let assessment = verify_with_kept_log(
        signed,
        Subject::Digest(&common::SUBJECT),
        &anchors(),
        &Floor::default(),
        log,
        kept,
    );
    let state = assessment
        .step(KEPT_LOG_QUESTION)
        .expect("asked whenever a kept log is supplied")
        .state
        .clone();
    (state, assessment.accepted())
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
    let log = our_log(vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)]);

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
    assert!(
        detail.contains("a key this reader holds for us"),
        "{detail}"
    );
    // And the window is judged on the receipt's own reading, which the words say rather than
    // implying a stolen key is caught here.
    assert!(detail.contains("the receipt's own reading"), "{detail}");
}

#[test]
fn a_head_signed_by_a_key_this_reader_does_not_hold_answers_nothing() {
    // The fault of 2026-09-15. Everything about this log is well-formed and its head carries a
    // real signature by the key it names. That key is not one the reader holds for us, so it is
    // somebody's list and not ours, and it neither vouches for the key nor refuses it.
    let (signed, key, at) = the_receipt();
    let log = signed_by(
        vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)],
        &SOMEBODY_ELSES_KEY,
        1_800_000_000_000_000_000,
    );

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    let detail = state.detail();
    assert!(!detail.contains("a list we signed"), "{detail}");
    assert!(
        detail.contains("not a key this reader holds for us"),
        "{detail}"
    );
    assert!(detail.contains("it is not us saying it"), "{detail}");

    // A reader holding no key for us at all gets the same answer, and is told so.
    let mut none = anchors();
    none.key_log_signers.clear();
    let state = verify_with_key_log(
        &signed,
        Subject::Digest(&common::SUBJECT),
        &none,
        &Floor::default(),
        Some(&our_log(vec![entry(key, UnixNanos(at.0 - 1), None)])),
    )
    .step(KEY_LOG_QUESTION)
    .expect("asked")
    .state
    .clone();
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(state.detail().contains("holds none"), "{}", state.detail());
}

#[test]
fn a_log_that_does_not_name_the_key_refuses_rather_than_shrugging() {
    // A reader who supplied a log asked the question. "Your log does not have this key" is an
    // answer to it, and reporting that as unchecked would hide a receipt signed by something the
    // log has never heard of. This only holds of a log that names agent keys at all; see the
    // server-only test below for the other case.
    let (signed, _, at) = the_receipt();
    let log = our_log(vec![entry([9u8; 32], UnixNanos(at.0 - 1), None)]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(state.detail().contains("none of them names this key"));
}

#[test]
fn a_log_of_server_keys_only_has_nothing_to_say_and_does_not_refuse() {
    // The log we serve first: two server keys and no agent key. Until 2026-09-15 this refused the
    // committed receipt, "none of them names this key", which made the documented use of our own
    // log a verdict against every receipt we had issued.
    let (signed, _, _) = the_receipt();
    let log = our_log(vec![server([0x6bu8; 32]), server([0x70u8; 32])]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    let detail = state.detail();
    assert!(detail.contains("no agent entry"), "{detail}");
    assert!(detail.contains("not a refusal"), "{detail}");

    // And a receipt signed by one of the server keys themselves is refused, not vouched for.
    let (signed, key, _) = the_receipt();
    let log = our_log(vec![server(key)]);
    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(state.detail().contains("server key"), "{}", state.detail());
}

#[test]
fn a_key_retired_by_an_appended_entry_refuses_every_later_reading() {
    // The property the retired role is for. The key is open from a second before the reading,
    // and a retirement appended below it at a nanosecond before the reading closes it. Until
    // 2026-09-15 the retirement was written as the same key with an end and read as one more
    // window in a union, so the open entry above covered the reading and the step held.
    let (signed, key, at) = the_receipt();
    let log = our_log(vec![
        entry(key, UnixNanos(at.0 - 1_000_000_000), None),
        retired(key, UnixNanos(at.0 - 1)),
    ]);

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("retired this key at"),
        "{}",
        state.detail()
    );

    // The old shape, kept in the log as two windows: the union still holds it, because it is two
    // windows and not a retirement. The writer refuses to produce this shape; the reader reads it
    // as what it says.
    let two_windows = our_log(vec![
        entry(key, UnixNanos(at.0 - 1_000_000_000), None),
        entry(
            key,
            UnixNanos(at.0 - 1_000_000_000),
            Some(UnixNanos(at.0 - 1)),
        ),
    ]);
    assert!(matches!(
        the_step(&signed, Some(&two_windows)),
        State::Held(_)
    ));

    // A retirement after the reading changes nothing about it.
    let later = our_log(vec![
        entry(key, UnixNanos(at.0 - 1_000_000_000), None),
        retired(key, UnixNanos(at.0 + 1)),
    ]);
    assert!(matches!(the_step(&signed, Some(&later)), State::Held(_)));
}

#[test]
fn a_key_whose_window_closed_before_the_reading_refuses() {
    let (signed, key, at) = the_receipt();
    let log = our_log(vec![entry(
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
    assert!(
        !state.detail().contains("stolen"),
        "a window judged on the receipt's own reading does not catch a stolen key, and must not \
         say it does: {}",
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
    let mut log = our_log(vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)]);
    let elsewhere = KeyLog {
        checkpoints: Vec::new(),
        entries: vec![entry([4u8; 32], UnixNanos(0), None)],
        head: None,
    };
    let moved: SignedHead = sign_head(
        &elsewhere,
        &OUR_SIGNING_KEY,
        UnixNanos(1_800_000_000_000_000_000),
    );
    log.head = Some(SignedHead {
        witness: None,
        head: TreeHead {
            beacon: None,
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
fn a_log_with_no_head_answers_nothing_and_says_it_is_signed_by_nobody() {
    // Until 2026-09-15 this read `[held]` with "nobody has put their name to it" and "a list we
    // signed" in one sentence. A list nobody signed is not a list we signed.
    let (signed, key, at) = the_receipt();
    let log = KeyLog {
        checkpoints: Vec::new(),
        entries: vec![entry(key, UnixNanos(at.0 - 1_000_000_000), None)],
        head: None,
    };

    let state = the_step(&signed, Some(&log));
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(
        state.detail().contains("signed by nobody"),
        "{}",
        state.detail()
    );
    assert!(!state.detail().contains("a list we signed"));
}

#[test]
fn a_reader_who_kept_an_earlier_head_can_hold_the_new_log_to_it() {
    // The one thing a log we alone sign proves, and the thing docs/verifier.md promised before
    // anything shipped did it: a reader who kept a head can prove the log was not rewritten under
    // them. Three logs from one history, and the two edits a log exists to catch.
    let (signed, key, at) = the_receipt();
    let first = entry([1u8; 32], UnixNanos(at.0 - 3), None);
    let second = entry(key, UnixNanos(at.0 - 2), None);
    let third = entry([2u8; 32], UnixNanos(at.0 - 1), None);

    let kept = our_log(vec![first.clone(), second.clone()]);
    let grown = our_log(vec![first.clone(), second.clone(), third.clone()]);
    let (state, accepted) = the_kept_step(&signed, &grown, &kept);
    assert!(matches!(state, State::Held(_)), "{state:?}");
    assert!(
        state
            .detail()
            .contains("consistency proof between the two heads holds"),
        "{}",
        state.detail()
    );
    assert!(accepted);

    // Held to itself, too: a reader checking the same copy twice.
    let (state, _) = the_kept_step(&signed, &kept, &kept);
    assert!(matches!(state, State::Held(_)), "{state:?}");

    // An entry changed.
    let changed = our_log(vec![
        first.clone(),
        entry(key, UnixNanos(at.0 - 20), None),
        third.clone(),
    ]);
    let (state, accepted) = the_kept_step(&signed, &changed, &kept);
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("entry 1 of the log you kept"),
        "{}",
        state.detail()
    );
    assert!(
        state.detail().contains("window opened at"),
        "{}",
        state.detail()
    );
    assert!(!accepted, "a rewritten log refuses the run");

    // An entry removed.
    let shortened = our_log(vec![first.clone()]);
    let (state, _) = the_kept_step(&signed, &shortened, &kept);
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(state.detail().contains("got shorter"), "{}", state.detail());

    // Two reordered.
    let swapped = our_log(vec![second.clone(), first.clone(), third.clone()]);
    let (state, _) = the_kept_step(&signed, &swapped, &kept);
    assert!(matches!(state, State::Failed(_)), "{state:?}");
    assert!(
        state.detail().contains("entry 0 of the log you kept"),
        "{}",
        state.detail()
    );
}

#[test]
fn a_kept_log_pins_nothing_unless_we_signed_it() {
    let (signed, key, at) = the_receipt();
    let entries = vec![entry(key, UnixNanos(at.0 - 2), None)];
    let grown = our_log(entries.clone());

    let unsigned = KeyLog {
        checkpoints: Vec::new(),
        entries: entries.clone(),
        head: None,
    };
    let (state, _) = the_kept_step(&signed, &grown, &unsigned);
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(state.detail().contains("no head"), "{}", state.detail());

    let theirs = signed_by(entries.clone(), &SOMEBODY_ELSES_KEY, 1);
    let (state, _) = the_kept_step(&signed, &grown, &theirs);
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(
        state.detail().contains("pins nothing"),
        "{}",
        state.detail()
    );

    // The other way round: a kept head of ours, and a new log signed by somebody else.
    let (state, _) = the_kept_step(&signed, &theirs, &grown);
    assert!(matches!(state, State::NotChecked(_)), "{state:?}");
    assert!(
        state.detail().contains("the new log's head"),
        "{}",
        state.detail()
    );
}
