//! What one source can do to the answer, when it is willing to lie about itself.
//!
//! A source hands over two of the four timestamps in an exchange and states its own uncertainty.
//! All three of those are things it chooses and none of them is anything the machine can check. So
//! the question this file asks is not whether the arithmetic is right, it is what the arithmetic
//! lets a source get away with.
//!
//! The property being defended is the one `marzullo.rs` states for itself and the one the product's
//! second sentence rests on: while fewer than half the sources are wrong, the reported interval
//! holds true UTC. A source that states no uncertainty is the cheapest lie a server can tell, and
//! before this file existed it was enough to collapse a 22.520 ms bound to 0.520 ms and move it
//! 9 ms off UTC with the model reporting four of four sources kept.
//!
//! Every test here was watched failing against the code as it stood before the fix, and only then
//! allowed to pass.

mod common;

use common::{claiming_no_uncertainty, stating_an_impossible_reply, Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI};
use timewitness_core::{MonotonicNanos, UnixNanos, Validity};
use timewitness_sources::Exchange;

use std::sync::Arc;

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

struct Rig {
    clock: Arc<TestClock>,
    world: World,
    model: ClockModel,
    paths: Vec<Path>,
}

impl Rig {
    fn new(world: World, paths: Vec<Path>, policy: Policy) -> Self {
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
            paths,
        }
    }

    fn now(&self) -> MonotonicNanos {
        self.clock.now()
    }

    /// Poll every honest path, then hand in whatever else the caller wants said this round.
    fn round(&mut self, extra: &[Exchange]) -> Validity {
        let now = self.now();
        for p in &self.paths {
            let e = self.world.exchange(p, now);
            self.model.ingest(&e);
        }
        for e in extra {
            self.model.ingest(e);
        }
        self.model.synchronise()
    }

    fn truth(&self) -> UnixNanos {
        self.world.utc(self.now())
    }
}

/// Three honest sources on a twenty millisecond symmetric path, each stating one millisecond.
fn three_honest() -> Vec<Path> {
    vec![
        Path::honest("alpha", 20, 1),
        Path::honest("bravo", 20, 1),
        Path::honest("charlie", 20, 1),
    ]
}

/// Where the hostile source wants the answer to be.
const LIE: Nanos = 9 * NANOS_PER_MILLI;

// ---------------------------------------------------------------------------
// The reproduction, which is the acceptance test for the fix
// ---------------------------------------------------------------------------

#[test]
fn a_source_stating_no_uncertainty_cannot_take_the_bound_off_utc() {
    // Row one of the table. Three honest sources and nothing else.
    let mut honest = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
    for _ in 0..4 {
        assert_eq!(honest.round(&[]), Validity::Valid);
        honest.clock.advance_seconds(64);
    }
    let clean = honest
        .model
        .read()
        .expect("three honest sources are enough");
    assert!(
        clean.bound.contains(honest.truth()),
        "the honest bound {:?} does not hold the truth {:?}",
        clean.bound,
        honest.truth()
    );

    // Row two. The same three, plus one source that states no uncertainty and places itself nine
    // milliseconds away. Nothing else about the run changes.
    let mut attacked = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
    for _ in 0..4 {
        let now = attacked.now();
        let hostile =
            claiming_no_uncertainty(&attacked.world, "hostile", LIE, now, 20 * NANOS_PER_MILLI);
        assert_eq!(attacked.round(&[hostile]), Validity::Valid);
        attacked.clock.advance_seconds(64);
    }
    let under_attack = attacked.model.read().expect("four sources are enough");

    assert!(
        under_attack.bound.contains(attacked.truth()),
        "one source claiming perfect knowledge moved the bound off UTC: {:?} does not hold {:?}",
        under_attack.bound,
        attacked.truth()
    );
    assert!(
        under_attack.bound.width() >= clean.bound.width(),
        "the hostile source narrowed the bound from {} ns to {} ns, and a source that states \
         nothing it can support may only ever widen the answer",
        clean.bound.width(),
        under_attack.bound.width()
    );
}

#[test]
fn the_lie_does_not_start_working_once_the_sample_has_aged() {
    // The first version of this defect survived ageing: at six hundred seconds the bound had
    // widened to 10.516 ms and still did not hold the truth, because the region it grew from was
    // the attacker's point rather than anything a majority supported.
    let mut rig = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
    for _ in 0..4 {
        let now = rig.now();
        let hostile =
            claiming_no_uncertainty(&rig.world, "hostile", LIE, now, 20 * NANOS_PER_MILLI);
        assert_eq!(rig.round(&[hostile]), Validity::Valid);
        rig.clock.advance_seconds(64);
    }

    for seconds in [1u64, 10, 60, 300, 600] {
        rig.clock.advance_seconds(seconds);
        match rig.model.read() {
            Ok(stamp) => assert!(
                stamp.bound.contains(rig.truth()),
                "after {seconds} s the bound {:?} does not hold the truth",
                stamp.bound
            ),
            // A refusal is a correct answer here. A wrong one is not.
            Err(_) => break,
        }
    }
}

#[test]
fn one_crafted_packet_among_eight_does_not_own_the_source() {
    // The window prefers the sample with the shortest round trip, so a source that sends one
    // crafted reply among seven honest ones has that reply chosen every round for as long as the
    // window holds it. That preference is right for an honest network and it must not be enough.
    let mut rig = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());

    for round in 0..4 {
        let now = rig.now();
        let mut fourth = Vec::new();
        for i in 0..8 {
            fourth.push(if i == 3 {
                claiming_no_uncertainty(&rig.world, "delta", LIE, now, 20 * NANOS_PER_MILLI)
            } else {
                rig.world
                    .exchange(&Path::honest("delta", 20, 1), now.advanced(i))
            });
        }
        assert_eq!(rig.round(&fourth), Validity::Valid, "round {round}");
        rig.clock.advance_seconds(64);
    }

    let stamp = rig.model.read().expect("four sources answered");
    assert!(
        stamp.bound.contains(rig.truth()),
        "one crafted packet in eight took the bound off UTC: {:?}",
        stamp.bound
    );
}

// ---------------------------------------------------------------------------
// The two mechanisms the fix rests on, each tested on its own
// ---------------------------------------------------------------------------

#[test]
fn a_reply_whose_own_timestamps_cannot_both_be_true_is_dropped() {
    // A round trip that computes negative is not a coarse clock rounding the wrong way. It is a
    // source claiming to have spent longer thinking than the whole exchange took, and the honest
    // answer is to drop the sample rather than to clamp it to the narrowest value there is.
    let mut rig = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
    let now = rig.now();
    let impossible = stating_an_impossible_reply(
        &rig.world,
        "hostile",
        LIE,
        now,
        20 * NANOS_PER_MILLI,
        10 * NANOS_PER_MILLI,
    );
    assert_eq!(rig.round(&[impossible]), Validity::Valid);

    let states = rig.model.source_states();
    assert!(
        !states.iter().any(|s| s.id.as_str() == "hostile"),
        "a source whose only reply was impossible should not be a source at all, and the model \
         reports {states:?}"
    );
}

#[test]
fn no_source_may_present_an_interval_narrower_than_the_floor() {
    // The same run at two settings of the one policy field, and nothing else different. A source
    // stating nothing is floored to the policy width, so the model that floors wider reports the
    // wider bound. Sever the floor from the arithmetic and the two runs come out identical.
    fn width_at(floor: Nanos) -> Nanos {
        let policy = Policy {
            source_interval_floor: floor,
            ..common::arithmetic_policy()
        };
        let mut rig = Rig::new(World::still(0), three_honest(), policy);
        for round in 0..4 {
            if round > 0 {
                rig.clock.advance_seconds(64);
            }
            let now = rig.now();
            let hostile =
                claiming_no_uncertainty(&rig.world, "hostile", 0, now, 20 * NANOS_PER_MILLI);
            rig.round(&[hostile]);
        }
        // The hostile source sits at the same offset as everybody else, so it survives the
        // selection and the only thing left for the floor to change is its width.
        rig.model
            .read()
            .expect("four sources answered")
            .bound
            .width()
    }

    let floored = width_at(40 * NANOS_PER_MILLI);
    let unfloored = width_at(0);
    assert!(
        floored > unfloored,
        "the source interval floor changes nothing: {floored} ns against {unfloored} ns"
    );
}

#[test]
fn a_hostile_source_can_neither_narrow_nor_widen_past_what_a_majority_supports() {
    // The region is the smallest interval every point a majority of sources allows sits inside, so
    // one source out of four can move it nowhere at all: it cannot narrow the region, because the
    // three honest sources still agree over the whole of it, and it cannot widen it, because
    // nothing it says on its own reaches a majority.
    let honest_region = {
        let mut rig = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
        for _ in 0..4 {
            rig.round(&[]);
            rig.clock.advance_seconds(64);
        }
        rig.model.read().unwrap().bound.width()
    };

    for lie in [-40, -9, -1, 0, 1, 9, 40] {
        let mut rig = Rig::new(World::still(0), three_honest(), common::arithmetic_policy());
        for _ in 0..4 {
            let now = rig.now();
            let hostile = claiming_no_uncertainty(
                &rig.world,
                "hostile",
                lie * NANOS_PER_MILLI,
                now,
                20 * NANOS_PER_MILLI,
            );
            rig.round(&[hostile]);
            rig.clock.advance_seconds(64);
        }
        let stamp = rig.model.read().expect("four sources answered");
        assert!(
            stamp.bound.contains(rig.truth()),
            "a source lying by {lie} ms took the bound off UTC: {:?}",
            stamp.bound
        );
        assert_eq!(
            stamp.bound.width(),
            honest_region,
            "a source lying by {lie} ms moved the width from {honest_region} ns to {} ns",
            stamp.bound.width()
        );
    }
}

// ---------------------------------------------------------------------------
// Where this product stops following textbook Marzullo, and what that buys
// ---------------------------------------------------------------------------

/// A source that is useless rather than hostile, and the majority it can manufacture.
///
/// Two honest servers 10 s apart, each stating a radius of 3 s, agree nowhere: the model refuses,
/// which is right, because nothing here can say which of the two is the broken one. Add a source
/// that lies about nothing and states a radius of an hour, and a majority appears, because two of
/// the three now allow every point from one server's floor to the other's ceiling. Textbook
/// Marzullo signs a bound 16 s wide where neither honest source supports more than 6 s.
///
/// This product refuses it. Decided on 2026-09-09, and the rule is in `marzullo`: a source whose
/// interval contains every other interval in the round cannot be put in the minority by any answer
/// the others could have given, so its agreement is free; where setting the free agreement aside
/// leaves no majority, there was nothing corroborating anything and the model declines.
///
/// The test asserts both readings, because the departure is only worth having if the difference can
/// be demonstrated. The count in this same case was fixed on 2026-09-08 and the selection rule left
/// alone; this is the other half.
#[test]
fn a_majority_only_one_useless_source_makes_is_refused() {
    let policy = Policy {
        max_bound_width: 60 * timewitness_core::time::NANOS_PER_SEC,
        min_sources: 2,
        ..common::arithmetic_policy()
    };

    // Two honest servers, one of which is 10 s from the other, each stating three seconds.
    let apart = vec![
        Path::honest("alpha", 20, 3_000),
        Path::honest("bravo", 20, 3_000).lying_by(10 * timewitness_core::time::NANOS_PER_SEC),
    ];

    let mut two = Rig::new(World::still(0), apart.clone(), policy);
    assert!(
        matches!(two.round(&[]), Validity::NoMajority { .. }),
        "two servers 10 s apart at a radius of 3 s agree nowhere and the model has to refuse"
    );

    // What the textbook rule does with the same two once a source stating an hour joins them: two
    // of three overlap everywhere between the honest servers, so it signs.
    let intervals = [
        timewitness_core::OffsetInterval::new(-3_000_000_000, 3_000_000_000),
        timewitness_core::OffsetInterval::new(7_000_000_000, 13_000_000_000),
        timewitness_core::OffsetInterval::new(-3_600_000_000_000, 3_600_000_000_000),
    ];
    let found = timewitness_clock::marzullo::intersect(&intervals).expect("three intervals");
    assert!(
        found.has_textbook_majority(),
        "the published algorithm calls this a majority, and that is what we depart from"
    );
    assert!(found.free_majority);
    assert!(!found.has_majority());

    // And what this model does with it.
    let mut with_useless = apart;
    with_useless.push(Path::honest("charlie", 20, 3_600_000));
    let mut three = Rig::new(World::still(0), with_useless, policy);
    assert_eq!(
        three.round(&[]),
        Validity::FreeMajority {
            present: 3,
            informative: 2
        },
        "the only reason there is a majority is a source that could not have disagreed"
    );
    assert!(
        three.model.read().is_err(),
        "a refused round leaves nothing to read"
    );

    // The refusal says why in words a reader who knows Marzullo can act on.
    let said = timewitness_core::Refusal::new(Validity::FreeMajority {
        present: 3,
        informative: 2,
    })
    .to_string();
    assert!(said.contains("corroborated"), "the refusal reads: {said}");
}
