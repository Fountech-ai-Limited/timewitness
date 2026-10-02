//! The whole path, once, with nothing faked in the middle.
//!
//! Four sources answer, the model selects and combines them, a reading comes out with an interval
//! around it, a receipt carries that interval labelled as the agent's own claim, the receipt is
//! signed, and something holding nothing but the bytes reads it back and checks it.
//!
//! This is the test that would catch the two crates drifting apart. Everything else in the suite
//! exercises one of them at a time.

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    EpsilonBasis, LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind,
    Timescale, UnixNanos, Validity,
};
use timewitness_receipt::{open, sha256_payload, AgentKey, PolicyRecord, Receipt};
use timewitness_sources::Exchange;

use std::sync::Arc;

const WALL0: Nanos = 1_757_000_000 * NANOS_PER_SEC;
/// How far the machine's own clock really is from UTC in this test.
const TRUE_OFFSET: Nanos = 9 * NANOS_PER_MILLI;

struct Handle(Arc<TestClock>);

impl MonotonicClock for Handle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// One exchange with a source `round_trip` away on a symmetric path.
fn exchange(id: &str, at: MonotonicNanos, round_trip: Nanos, stated: Nanos) -> Exchange {
    let home = at.advanced(round_trip);
    // What the source saw, on true UTC. The two local ends of the round trip are not here, because
    // the model stamps those itself off the anchor it will report against.
    let server = UnixNanos(WALL0 + at.as_nanos() as Nanos) + round_trip / 2 + TRUE_OFFSET;

    Exchange {
        source: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        t2: server,
        t3: server,
        mono_t1: at,
        mono_t4: home,
        root_delay: 0,
        root_dispersion: stated,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        attestation: None,
    }
}

#[test]
fn a_stamp_becomes_a_receipt_a_stranger_can_check() {
    let clock = Arc::new(TestClock::starting_at(0));
    let mut model = ClockModel::new(
        Policy::default(),
        Box::new(Handle(clock.clone())),
        UnixNanos(WALL0),
        0,
    );

    let sources = [
        ("alpha", 10 * NANOS_PER_MILLI, NANOS_PER_MILLI),
        ("bravo", 18 * NANOS_PER_MILLI, 2 * NANOS_PER_MILLI),
        ("charlie", 6 * NANOS_PER_MILLI, NANOS_PER_MILLI),
        ("delta", 32 * NANOS_PER_MILLI, 3 * NANOS_PER_MILLI),
    ];

    for round in 0..8 {
        if round > 0 {
            clock.advance_seconds(64);
        }
        let now = clock.now();
        for (id, rtt, stated) in sources {
            model.ingest(&exchange(id, now, rtt, stated));
        }
        assert_eq!(model.synchronise(), Validity::Valid);
    }

    let stamp = model.read().expect("a synchronised model answers");

    // The interval holds the truth, which in this test is a number written at the top of the file.
    let truth = UnixNanos(WALL0 + clock.now().as_nanos() as Nanos + TRUE_OFFSET);
    assert!(
        stamp.bound.contains(truth),
        "the bound {:?} does not hold the true time {truth:?}",
        stamp.bound
    );

    let key = AgentKey::from_seed(&[3u8; 32]);
    let artefact = b"a container image nobody has checked the timestamp inside";
    let receipt = Receipt::from_stamp(
        &stamp,
        1,
        None,
        sha256_payload(artefact),
        key.public_key_bytes(),
        PolicyRecord {
            max_bound_width: model.policy().max_bound_width,
            min_sources: model.policy().min_sources as u32,
            min_operators: Some(model.policy().min_operators as u32),
            max_holdover: Some(model.policy().max_holdover),
        },
    );

    let signed = key.sign(&receipt).expect("the agent signs its own receipt");

    // From here on, nothing but the bytes. This is what a stranger has.
    let checked = open(&signed).expect("a well-formed receipt opens");

    assert_eq!(checked.claim.earliest, stamp.bound.earliest);
    assert_eq!(checked.claim.latest, stamp.bound.latest);
    assert_eq!(checked.payload.hash, sha256_payload(artefact).hash);

    // The bound is labelled as ours, because no third party has signed anything here yet.
    assert_eq!(checked.claim.basis, EpsilonBasis::LocalModelOnly);
    assert!(checked.evidence.is_empty());

    // And the reading is nanoseconds while the interval is milliseconds, which is the distinction
    // the whole product turns on.
    assert!(checked.monotonic > 0);
    assert!(checked.width() > NANOS_PER_MILLI);
}

#[test]
fn a_receipt_altered_after_signing_is_refused_by_something_holding_only_the_bytes() {
    let clock = Arc::new(TestClock::starting_at(0));
    let mut model = ClockModel::new(
        Policy::default(),
        Box::new(Handle(clock.clone())),
        UnixNanos(WALL0),
        0,
    );

    for round in 0..4 {
        if round > 0 {
            clock.advance_seconds(64);
        }
        let now = clock.now();
        for id in ["alpha", "bravo", "charlie", "delta"] {
            model.ingest(&exchange(id, now, 10 * NANOS_PER_MILLI, NANOS_PER_MILLI));
        }
        model.synchronise();
    }

    let stamp = model.read().unwrap();
    let key = AgentKey::from_seed(&[4u8; 32]);
    let receipt = Receipt::from_stamp(
        &stamp,
        1,
        None,
        sha256_payload(b"anything"),
        key.public_key_bytes(),
        PolicyRecord {
            max_bound_width: model.policy().max_bound_width,
            min_sources: model.policy().min_sources as u32,
            min_operators: Some(model.policy().min_operators as u32),
            max_holdover: Some(model.policy().max_holdover),
        },
    );
    let signed = key.sign(&receipt).unwrap();

    let mut altered = signed.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0x80;
    assert!(open(&altered).is_err());
}
