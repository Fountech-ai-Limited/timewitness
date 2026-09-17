//! A fitted frequency the baseline cannot support.
//!
//! The regression fits a line through the last few synchronisations and reports its slope as the
//! machine's frequency error. Over a twenty minute baseline that is a measurement. Over the two
//! seconds a one-shot stamp actually gets, against sources stating their uncertainty in whole
//! seconds, it is the sources' jitter divided by a very short baseline, and it comes out in the
//! thousands of parts per million. A consumer crystal is specified at plus or minus fifty.
//!
//! That figure was signed into every receipt and printed on the first line of the command's own
//! output, which is where a hostile reviewer starts. `-10000.685` ppm from a run on 2026-09-08, and
//! `-30,336.480` ppm from a live stamp the same day. This product's own rule says a figure is
//! quoted with the conditions it was measured under or it is not quoted, and nothing in the receipt
//! says the baseline was two seconds.
//!
//! So the model now reports a rate only where its own fit could tell one rate in the oscillator's
//! band from another. The danger in a change like this is the opposite of the one it fixes: refuse
//! to correct for a rate and the interval gets narrower for free, which would take a real error out
//! of the bound and leave the receipt saying something tighter than the truth. It does not, and
//! `refusing_a_rate_never_narrows_the_interval` is the proof rather than the argument.
//!
//! The other half of the rule, that a good fit is still believed, is
//! `the_regression_recovers_the_frequency_the_machine_is_actually_drifting_at` in `clock_model.rs`
//! and `the_error_does_not_grow_with_the_time_the_agent_has_been_running` in `local_anchor.rs`.
//! Both take a twenty minute baseline and both now unwrap the rate rather than reading a bare
//! float, so a rule that refused everything would turn them red.

mod common;

use common::{Path, World};

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::policy::WIDEST_RATE_PPM;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{Bound, MonotonicNanos, Validity};

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
}

impl Rig {
    fn new(policy: Policy) -> Self {
        let world = World::still(0);
        let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
        let wall = world.system(world.mono0);
        let model = ClockModel::new(policy, Box::new(ClockHandle(clock.clone())), wall, 0);
        Self {
            clock,
            world,
            model,
        }
    }

    /// One round against three servers, each answering `error` away from where it should.
    fn round(&mut self, error: Nanos) -> Validity {
        let now = self.clock.now();
        for path in sources(error) {
            let e = self.world.exchange(&path, now);
            self.model.ingest(&e);
        }
        self.model.synchronise()
    }
}

/// Three servers of the one kind that exists, stating a radius in whole seconds.
///
/// The stated figure is what makes this the real case rather than a contrived one: a Roughtime
/// response carries a radius of one to five seconds, so every source hands the model an interval
/// seconds wide and the model's own arithmetic is what has to sort them out.
fn sources(error: Nanos) -> Vec<Path> {
    vec![
        Path::honest("corridor-a", 40, 1_000).lying_by(error),
        Path::honest("corridor-b", 60, 1_000).lying_by(error / 2),
        Path::honest("corridor-c", 80, 1_000).lying_by(-error / 3),
    ]
}

/// A ceiling wide enough to see a seconds-wide fit at all, thirty seconds, which is what the Action
/// shipped until 2026-09-15. The shipped ceilings, 250 ms and 2 s, refuse every round here outright
/// and there would be no receipt to look at.
fn shipping_policy() -> Policy {
    Policy {
        max_bound_width: 30 * NANOS_PER_SEC,
        // Nothing here is in holdover for long, and switching the slew off keeps the two policies
        // in the containment test different in exactly one field.
        frequency_slew_ppm_per_second: 0.0,
        ..common::arithmetic_policy()
    }
}

/// Four rounds spread over two seconds, which is what a stamp actually gets, with the servers
/// wandering by tens of milliseconds between rounds the way real ones do.
fn a_two_second_run(policy: Policy) -> Rig {
    let mut rig = Rig::new(policy);
    let jitter = [
        0,
        40 * NANOS_PER_MILLI,
        -30 * NANOS_PER_MILLI,
        55 * NANOS_PER_MILLI,
    ];
    for (i, error) in jitter.iter().enumerate() {
        if i > 0 {
            rig.clock.advance(666_666_667);
        }
        assert_eq!(rig.round(*error), Validity::Valid);
    }
    rig
}

#[test]
fn a_two_second_baseline_reports_no_rate() {
    let stamp = a_two_second_run(shipping_policy()).model.read().unwrap();
    assert!(
        stamp.frequency_ppm.is_none(),
        "a two second baseline against second-wide sources reported {:?} parts per million, and \
         the receipt would have signed it",
        stamp.frequency_ppm
    );
}

#[test]
fn the_fit_this_refuses_really_is_a_large_one() {
    // Without this the test above passes on a model that never claims a rate at all, which would be
    // a different and worse product. The magnitude the model refused to stand behind is what the
    // fit was actually saying, and the model reports it: a rate two orders of magnitude past
    // anything a crystal does. Until 2026-09-17 this read it through a band of a thousand million
    // parts per million, which no policy may set now that a rate is held to the whole clock.
    let fit = a_two_second_run(shipping_policy())
        .model
        .fit()
        .expect("the run synchronised");
    assert!(
        fit.frequency_ppm.is_none(),
        "the shipping policy claimed {:?}",
        fit.frequency_ppm
    );
    let rate = fit.unclaimed_frequency_ppm;
    assert!(
        rate > 1_000.0,
        "the fit over two seconds came out at {rate} parts per million, which is not the noise \
         this rule exists to catch"
    );
}

#[test]
fn refusing_a_rate_never_narrows_the_interval() {
    // The two policies differ in one field. One believes the fit and corrects by it, which is what
    // the model did before this rule existed; the other refuses it and carries the magnitude as
    // width. The refusing interval has to contain the believing one at every elapsed time, or the
    // rule has quietly taken a real error out of the bound.
    // The believing band is the widest the validator allows, the whole clock, and at that band the
    // fit here separates it only at one standard error, so the coverage factor comes down to one
    // as well. That makes the believing interval narrower on the residual too, which is the
    // direction that makes containment harder to satisfy rather than easier.
    let refusing = a_two_second_run(shipping_policy());
    let believing = a_two_second_run(Policy {
        frequency_span_ppm: WIDEST_RATE_PPM,
        coverage_factor: 1.0,
        ..shipping_policy()
    });
    assert!(
        believing.model.read().unwrap().frequency_ppm.is_some(),
        "the believing policy has to claim the rate, or there is nothing to compare"
    );

    let mut compared = 0;
    for step in [
        0,
        1,
        10,
        1_000,
        NANOS_PER_MILLI,
        NANOS_PER_SEC,
        10 * NANOS_PER_SEC,
    ] {
        refusing.clock.advance(step as u64);
        believing.clock.advance(step as u64);

        let (Ok(wide), Ok(narrow)) = (refusing.model.read(), believing.model.read()) else {
            // Past the ceiling the refusing model stops answering first, which is the same rule
            // working. There is nothing to compare once either of them has refused.
            break;
        };
        assert!(
            contains(&wide.bound, &narrow.bound),
            "after {} ns the refusing bound {:?} does not contain the believing bound {:?}, so \
             refusing the fit narrowed the interval",
            wide.since_last_sync,
            wide.bound,
            narrow.bound
        );
        compared += 1;
    }
    assert!(
        compared >= 4,
        "only {compared} elapsed times were compared, which is not enough to call this a property"
    );
}

fn contains(outer: &Bound, inner: &Bound) -> bool {
    outer.earliest <= inner.earliest && outer.latest >= inner.latest
}
