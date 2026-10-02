//! What happens when a round holds two kinds of source rather than one.
//!
//! Until 2026-09-09 there was one `impl TimeSource` in the tree and it was Roughtime, so every
//! selection this model had ever made was over sources of one kind with radii of the same order.
//! Two things about the selection rule were therefore untested rather than tested and passing.
//!
//! **A Roughtime interval contains an NTP interval whole, every time.** Roughtime states its
//! uncertainty as a radius in whole seconds and an NTP server states a root delay and a dispersion
//! in units of about fifteen microseconds, so the two kinds differ by three orders of magnitude on
//! the axis the selection rule reads. That is exactly the shape the rule of 2026-09-09 is about: a
//! source that could not have disagreed with anybody.
//!
//! **That was read as honest corroboration until 2026-09-10 and half of it was not.** Three
//! Roughtime servers do not contain each other, so the single-source test of 2026-09-09 set none of
//! them aside and all three were counted among the sources deciding who was lying. Three sources
//! that agree with every answer on offer decided which of the narrow ones was in the minority, and
//! they kept a liar 200 ms out. The test is asked of a set now, and the sources that could not have
//! disagreed still vouch for the answer and no longer choose who gives it. Telling the two apart is
//! the whole of the rule, and this file holds the line between them with two kinds in the round
//! rather than one.
//!
//! The widths here are the shape of the two protocols and not a measurement of anything. What the
//! two kinds actually reach on a real path is measured with the real clients and quoted with the
//! conditions it was taken under; see `crates/cli/src/stamp_cmd.rs`.

mod common;

use common::{Path, World};

use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::NANOS_PER_MILLI;
use timewitness_core::{MonotonicNanos, SourceKind, UnixNanos, Validity};

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// A source of `kind` on a symmetric path, stating `stated_ms` about itself.
fn source(id: &'static str, kind: SourceKind, round_trip_ms: i128, stated_ms: i128) -> Path {
    Path {
        kind,
        ..Path::honest(id, round_trip_ms, stated_ms)
    }
}

/// Three Roughtime servers stating a radius of a second each, which is what the protocol gives.
fn three_roughtime() -> Vec<Path> {
    vec![
        source("roughtime-a", SourceKind::Roughtime, 40, 1_000),
        source("roughtime-b", SourceKind::Roughtime, 60, 1_000),
        source("roughtime-c", SourceKind::Roughtime, 80, 3_000),
    ]
}

/// Three NTP servers on ordinary internet paths, stating what an NTP server states.
fn three_ntp() -> Vec<Path> {
    vec![
        source("ntp-a", SourceKind::Ntp, 10, 1),
        source("ntp-b", SourceKind::Ntp, 30, 2),
        source("ntp-c", SourceKind::Ntp, 20, 1),
    ]
}

/// Run one selection round over `paths` and return the model with what it decided.
fn one_round(paths: &[Path]) -> (ClockModel, Validity) {
    let (model, validity, _) = one_round_against_the_truth(paths);
    (model, validity)
}

/// The same, and what UTC actually was while it ran.
fn one_round_against_the_truth(paths: &[Path]) -> (ClockModel, Validity, UnixNanos) {
    let world = World::still(0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(
        Policy {
            // The default ceiling is 250 ms and a round of Roughtime servers cannot reach it, which
            // is the fact this file is about. Raised here so the refusals under test are the
            // selection rule's own rather than the width policy's.
            max_bound_width: 30 * 1_000 * NANOS_PER_MILLI,
            ..common::arithmetic_policy()
        },
        Box::new(ClockHandle(clock.clone())),
        wall,
        0,
    );

    let now = clock.now();
    for path in paths {
        let exchange = world.exchange(path, now);
        model.ingest(&exchange);
    }
    let validity = model.synchronise();
    (model, validity, world.utc(now))
}

/// The narrow kind decides the interval and the wide kind vouches for it.
///
/// Both are kept. This is the ordinary round on a machine with both kinds of source, and the thing
/// worth asserting is that the answer is milliseconds rather than seconds: the reason for adding a
/// second kind of source at all was that a round of Roughtime servers alone cannot support an
/// interval narrower than the radius they state.
///
/// **Kept and could-have-disagreed are two questions from 2026-09-10 onwards.** All six are kept,
/// because all six allow the region and none of them is contradicting anybody. Three of them could
/// not have disagreed with the other three whatever either side said, so they take no part in
/// deciding who is in the minority. Nobody is in the minority here, which is why the answer is the
/// same as it always was.
#[test]
fn the_narrow_sources_decide_the_interval_and_the_wide_ones_still_count() {
    let mut paths = three_roughtime();
    paths.extend(three_ntp());

    let (model, validity) = one_round(&paths);
    assert_eq!(validity, Validity::Valid, "six honest sources agree");

    let stamp = model.read().expect("a valid model reads");
    assert_eq!(
        stamp.sources.iter().filter(|s| s.kept).count(),
        6,
        "nobody in this round contradicted anybody, so nobody should have been thrown out"
    );

    // A Roughtime server here states a second. Anything at that order of magnitude means the narrow
    // sources were not the ones deciding the region.
    assert!(
        stamp.bound.width() < 200 * NANOS_PER_MILLI,
        "the interval came out {} ms wide, which is the wide sources deciding it",
        stamp.bound.width_millis()
    );
    assert!(
        stamp.estimate_within_bound(),
        "the reading has to sit inside its own interval"
    );
}

/// A wide source cannot turn two narrow sources that disagree into an answer.
///
/// The two NTP servers are four hundred milliseconds apart and each states two, so they agree
/// nowhere at all. Textbook Marzullo counts two of the three and signs, because the Roughtime
/// server's radius covers both of them. This product refuses, and the refusal names what happened.
///
/// This is the rule decided on 2026-09-09, exercised across two kinds of source for the first time.
/// It is also the case that will actually occur on a real machine rather than a constructed one:
/// every Roughtime interval contains every NTP interval, so the free agreement the rule is about is
/// the ordinary relationship between the two protocols.
#[test]
fn a_roughtime_radius_cannot_make_a_majority_out_of_two_ntp_servers_that_disagree() {
    let disagreeing = vec![
        source("ntp-near", SourceKind::Ntp, 10, 2),
        source("ntp-far", SourceKind::Ntp, 10, 2).lying_by(400 * NANOS_PER_MILLI),
        source("roughtime-wide", SourceKind::Roughtime, 40, 1_000),
    ];

    let (model, validity) = one_round(&disagreeing);
    assert_eq!(
        validity,
        Validity::FreeMajority {
            present: 3,
            informative: 2
        },
        "the only reason there is a majority is a source that could not have disagreed"
    );
    assert!(
        model.read().is_err(),
        "a model that refused the round must not read"
    );
}

/// Two narrow sources that agree carry the round, whatever the wide ones do.
///
/// The mirror of the test above and the direction that matters more. The dangerous failure is an
/// honest round refused, not a dishonest one signed: an agent that stops signing looks like a
/// network fault. Here the two NTP servers agree with each other, so the survivors of any set-aside
/// reach a majority of their own and the round is signed.
#[test]
fn two_ntp_servers_that_agree_are_signed_however_wide_the_roughtime_servers_are() {
    let mut paths = vec![
        source("ntp-a", SourceKind::Ntp, 10, 2),
        source("ntp-b", SourceKind::Ntp, 12, 2),
    ];
    // One Roughtime server stating an hour, which is far past anything the protocol would say and
    // is here because it is the strongest form of the free agreement the rule sets aside.
    paths.push(source(
        "roughtime-an-hour",
        SourceKind::Roughtime,
        40,
        3_600_000,
    ));

    let (model, validity) = one_round(&paths);
    assert_eq!(
        validity,
        Validity::Valid,
        "the two sources that could have disagreed agreed, so the round stands"
    );

    let stamp = model.read().expect("a valid model reads");
    assert!(
        stamp.bound.width() < 200 * NANOS_PER_MILLI,
        "the interval came out {} ms wide, so the hour-wide source got into the answer",
        stamp.bound.width_millis()
    );
}

/// A liar is discarded by its interval and not by its kind, where the round is narrow sources only.
///
/// Four NTP servers, one of them two hundred milliseconds out. Three of the four agree, the fourth
/// is in the minority, and it is thrown away rather than blended in. This is the case the selection
/// rule was written for and it behaves as it always has.
#[test]
fn a_lying_source_among_its_own_kind_is_discarded_by_its_interval() {
    let mut paths = three_ntp();
    paths.push(source("ntp-liar", SourceKind::Ntp, 10, 1).lying_by(200 * NANOS_PER_MILLI));

    let (model, validity, truth) = one_round_against_the_truth(&paths);
    assert_eq!(validity, Validity::Valid);

    let stamp = model.read().expect("a valid model reads");
    let liar = stamp
        .sources
        .iter()
        .find(|s| s.id.as_str() == "ntp-liar")
        .expect("the liar answered, so it is in the receipt");
    assert!(
        !liar.kept,
        "a source two hundred milliseconds off the others was counted among those that agreed"
    );
    assert!(stamp.bound.contains(truth));
}

/// A wide source buys the round no fault tolerance, so it cannot let a liar in.
///
/// The same liar, in the same round, with three Roughtime servers added. This is the measurement
/// the fix was raised on and until 2026-09-10 it went the other way: seven sources tolerated three
/// faults, the liar plus the three wide servers made four, and the region a majority allowed
/// stretched from the honest cluster to the liar's. The interval went from 69 ms to 223.5 ms and
/// the point estimate moved 82.6 ms, so three more honest servers bought a worse answer.
///
/// **Nothing signed then was untrue and that is what makes this a strictness change.** Marzullo's
/// guarantee is that the region holds the truth while fewer than half the sources are faulty, and it
/// did: the bound contained UTC in both rounds and still does. What was wrong is that the three
/// faults were never earned. A source stating a radius of a second could not have disagreed with an
/// NTP server stating a millisecond whatever either of them said, so it may not raise how many liars
/// the round tolerates.
///
/// The assertion is the property and not the example. Adding sources that could not have disagreed
/// leaves the answer the sources that could have disagreed reached on their own: the same interval,
/// the same point, the same source thrown out.
#[test]
fn wide_sources_cannot_buy_a_liar_into_the_majority() {
    let honest = three_ntp();
    let liar = source("ntp-liar", SourceKind::Ntp, 10, 1).lying_by(200 * NANOS_PER_MILLI);

    let mut narrow_only = honest.clone();
    narrow_only.push(liar.clone());
    let (narrow_model, narrow_validity, truth) = one_round_against_the_truth(&narrow_only);
    assert_eq!(narrow_validity, Validity::Valid);
    let without_the_wide_ones = narrow_model.read().expect("a valid model reads");

    let mut with_wide = three_roughtime();
    with_wide.extend(honest);
    with_wide.push(liar);
    let (wide_model, wide_validity, wide_truth) = one_round_against_the_truth(&with_wide);
    assert_eq!(wide_validity, Validity::Valid);
    let with_the_wide_ones = wide_model.read().expect("a valid model reads");

    let liar_kept = |stamp: &timewitness_core::Stamp| {
        stamp
            .sources
            .iter()
            .any(|s| s.id.as_str() == "ntp-liar" && s.kept)
    };
    assert!(!liar_kept(&without_the_wide_ones));
    assert!(
        !liar_kept(&with_the_wide_ones),
        "three sources that could not have disagreed with anybody carried a liar into the majority"
    );

    // Measured on this file on 2026-09-11, both rounds, and quoted here so the change is a number
    // rather than an adjective. Before the rule the wide sources took the interval to 223.52 ms and
    // moved the point estimate 82.570909 ms. After it the interval is 34.52 ms and the point estimate
    // does not move at all.
    assert_eq!(with_the_wide_ones.bound.width(), 34_520_000);
    assert_eq!(without_the_wide_ones.bound.width(), 12_520_000);
    assert_eq!(
        with_the_wide_ones.reading.utc_estimate, without_the_wide_ones.reading.utc_estimate,
        "the wide sources dragged the point estimate, which is the liar getting into the average"
    );

    // **The half of the fix that is not built, asserted so that it is a figure rather than a
    // sentence somebody has to remember.** The count the region is swept at is still the majority
    // of the round as offered, so three sources that could not have disagreed still buy the width
    // three faults' worth of room: 34.52 ms against the 12.52 ms the sources that could have
    // disagreed reached on their own. Counting that over the same population narrows ordinary
    // honest rounds to no fault tolerance at all, so it is a decision rather than a fix, and it is
    // still an open question.
    assert!(
        with_the_wide_ones.bound.width() > without_the_wide_ones.bound.width(),
        "the width half of the fix has been built and this test is the place that says so"
    );

    // The guarantee that has to hold whatever else happens, in both rounds.
    assert!(without_the_wide_ones.bound.contains(truth));
    assert!(with_the_wide_ones.bound.contains(wide_truth));
}

/// The two kinds are told apart on the one question that matters, and only on that one.
///
/// Nothing in the selection reads the kind. What reads it is the receipt, where an NTP answer can
/// never appear as evidence because there is no signature in it for a stranger to check. The
/// evidence rule, asserted here beside the selection tests because this is the file where somebody
/// adding a third kind of source will be reading.
#[test]
fn only_the_signed_kind_can_ever_be_evidence() {
    assert!(SourceKind::Roughtime.carries_third_party_signature());
    assert!(!SourceKind::Ntp.carries_third_party_signature());
    assert!(!SourceKind::Nts.carries_third_party_signature());
    assert!(!SourceKind::LocalHardware.carries_third_party_signature());
}
