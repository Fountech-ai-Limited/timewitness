//! How much the inverse-square weighting tells two sources apart, measured at the shipped policy.
//!
//! The figure is taken off the shipped code path rather than worked out on paper: real `Sample`s,
//! `Policy::default()`, the same `CounterAgeing` the model builds, and the same `weight_of` the
//! combination calls. A number derived in a document agrees with whatever the document's author
//! believed the code did, and that is how this one was wrong twice.
//!
//! Run it with the figures printed:
//!
//! ```text
//! cargo test -p timewitness-clock --test how_much_the_weighting_discriminates -- --nocapture
//! ```

use timewitness_clock::combine::weight_of;
use timewitness_clock::model::{BandReading, CounterAgeing, RateKnowledge};
use timewitness_clock::{Policy, Sample};
use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Nanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
};

/// The cadence the agent ships with, `timewitness agent --interval`.
const SHIPPED_CADENCE_S: u64 = 32;

/// A source whose own answer supports `own_half`, taken at the counter's origin.
fn source(name: &str, own_half: Nanos) -> Sample {
    Sample {
        source: SourceId::new(name),
        operator: Operator::new(name),
        kind: SourceKind::Ntp,
        offset: 0,
        // Half the round trip is one of the two terms the source's own width is made of, and the
        // other is what it said about itself. Splitting it across both is closer to a real answer
        // than putting it all in one.
        round_trip: own_half,
        stated_uncertainty: own_half / 2,
        sent_at: MonotonicNanos(0),
        taken_at: MonotonicNanos(0),
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
    }
}

/// What the model knows about its counter after a fit, at the shipped policy.
fn ageing(policy: &Policy) -> CounterAgeing {
    CounterAgeing::new(
        policy,
        &RateKnowledge {
            frequency_ppm: Some(0.0),
            frequency_stderr_ppm: 0.0,
            unclaimed_frequency_ppm: 0.0,
            band: BandReading::NotRead,
        },
    )
}

#[test]
fn the_ratio_between_a_tight_and_a_loose_source_no_longer_falls_with_the_age_of_the_round() {
    let policy = Policy::default();
    let ageing = ageing(&policy);
    let floor = policy.source_interval_floor;
    let tight = source("tight", NANOS_PER_MILLI);
    let loose = source("loose", 50 * NANOS_PER_MILLI);

    println!(
        "A {} ms source against a {} ms source, at the shipped policy.",
        tight.own_half(floor) as f64 / NANOS_PER_MILLI as f64,
        loose.own_half(floor) as f64 / NANOS_PER_MILLI as f64
    );
    println!(
        "{:>12} {:>16} {:>18}",
        "age", "on own widths", "on aged widths"
    );

    let mut on_own = Vec::new();
    for seconds in [0, 1, 4, SHIPPED_CADENCE_S, 60, 600, 1800, 3600] {
        let now = MonotonicNanos(seconds * NANOS_PER_SEC as u64);
        let own = weight_of(tight.own_half(floor) * 2, policy.weight_floor)
            / weight_of(loose.own_half(floor) * 2, policy.weight_floor);
        let aged = weight_of(
            tight.interval_at(now, &ageing, floor).width(),
            policy.weight_floor,
        ) / weight_of(
            loose.interval_at(now, &ageing, floor).width(),
            policy.weight_floor,
        );
        println!("{seconds:>10} s {own:>16.2} {aged:>18.2}");
        on_own.push(own);
    }

    // The whole claim: the weighting no longer depends on how old the round is.
    assert!(
        on_own.windows(2).all(|w| (w[0] - w[1]).abs() < 1e-9),
        "the ratio moved with age and it must not: {on_own:?}"
    );

    // And it is the ratio the two sources' own numbers support, 50 times tighter squared.
    assert!(
        (on_own[0] - 2500.0).abs() < 1.0,
        "a fifty times tighter source earns two and a half thousand times the weight, not {}",
        on_own[0]
    );
}

#[test]
fn what_the_aged_widths_would_have_given_at_the_shipped_cadence() {
    // Kept as the record of what was wrong rather than as a thing to go back to. The aged ratio is
    // what the combination used until this was fixed, and it falls with the age of the round.
    let policy = Policy::default();
    let ageing = ageing(&policy);
    let floor = policy.source_interval_floor;
    let tight = source("tight", NANOS_PER_MILLI);
    let loose = source("loose", 50 * NANOS_PER_MILLI);

    let at = |seconds: u64| {
        let now = MonotonicNanos(seconds * NANOS_PER_SEC as u64);
        weight_of(
            tight.interval_at(now, &ageing, floor).width(),
            policy.weight_floor,
        ) / weight_of(
            loose.interval_at(now, &ageing, floor).width(),
            policy.weight_floor,
        )
    };

    let fresh = at(0);
    let cadence = at(SHIPPED_CADENCE_S);
    let minute = at(60);
    let ceiling = at((policy.max_holdover / NANOS_PER_SEC as Nanos) as u64);
    println!(
        "aged widths: fresh {fresh:.2}, at the shipped {SHIPPED_CADENCE_S} s cadence {cadence:.2}, \
         at a minute {minute:.2}, at the holdover ceiling {ceiling:.2}"
    );

    assert!(
        fresh > cadence,
        "it fell with age or this is not the old fault"
    );
    assert!(cadence > minute);
    assert!(minute > ceiling);
}
