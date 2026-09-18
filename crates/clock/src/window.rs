//! A window of recent exchanges, one per source.
//!
//! The model keeps the last few exchanges from each source and works from the one whose interval
//! is narrowest once it has been aged to the moment it is used. That is usually the one with the
//! shortest round trip: a packet that took longer than its neighbours spent that extra time queued
//! somewhere, and queuing is almost never symmetric, so the slow sample is the one most likely to
//! have its delay piled onto one leg. Taking the quickest of the recent samples is the oldest trick
//! in NTP's book.
//!
//! It was the whole rule until 2026-09-18, and the cost of it is that the chosen sample may be
//! older than the newest one. While a sample aged at fifteen parts per million that cost nothing
//! worth measuring. Aged at the band, which is what a raw counter can honestly do, an eight-round
//! old sample on a thirty-two second cadence carries 13 ms of half width for its age, and a quick
//! round trip does not buy that back. So the choice is made on the aged interval, which is the
//! quantity the intersection is built from, and the age a candidate carries is bounded by the
//! cadence wherever ageing costs more than the round trip differences do.

use std::collections::VecDeque;

use timewitness_core::{MonotonicNanos, Nanos, OffsetInterval, SourceId, SourceState};

use crate::model::CounterAgeing;
use crate::sample::Sample;

/// The recent history for one source.
#[derive(Clone, Debug)]
pub struct SourceWindow {
    id: SourceId,
    capacity: usize,
    samples: VecDeque<Sample>,
}

impl SourceWindow {
    /// An empty window for one source.
    #[must_use]
    pub fn new(id: SourceId, capacity: usize) -> Self {
        Self {
            id,
            capacity: capacity.max(1),
            samples: VecDeque::new(),
        }
    }

    /// Which source this window belongs to.
    #[must_use]
    pub fn id(&self) -> &SourceId {
        &self.id
    }

    /// How many samples are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the window holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Add a sample, dropping the oldest when the window is full.
    pub fn push(&mut self, sample: Sample) {
        if self.samples.len() == self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// The held sample with the shortest round trip, which is what a source's reported state is
    /// read off. A selection round uses `best_within` instead, because there the age matters.
    ///
    /// Ties go to the more recent one, because between two samples with equally short round trips
    /// the newer one needs less ageing.
    ///
    /// A source that sends one crafted reply among eight has that reply chosen every round for as
    /// long as the window holds it, and this preference is what lets it. Filtering it out here
    /// would buy nothing, because a source controls every one of its own replies and can craft all
    /// eight as easily as one, so the answer to a lying source has to sit where the sources are
    /// compared against each other rather than where one source is compared against itself. It
    /// does: `Sample::from_exchange` refuses a reply whose timestamps cannot both be true, so
    /// nothing impossible reaches this window, `Sample::interval_at` floors what any single source
    /// may claim to know, and `marzullo::intersect` gives the region to the majority rather than
    /// to whoever agrees with everybody.
    #[must_use]
    pub fn best(&self) -> Option<&Sample> {
        self.samples.iter().rev().min_by_key(|s| s.round_trip)
    }

    /// The held sample whose interval is narrowest once aged to `now`, over the samples no older
    /// than `max_age`. This is the sample a selection round uses.
    ///
    /// Ties go to the more recent one. Narrowest after ageing rather than shortest round trip from
    /// 2026-09-18, for the reason at the head of this file: the round trip is what the sample knew
    /// when it was taken and the aged interval is what it knows now.
    ///
    /// The window had no expiry until 2026-09-08, which was half of one fault: a source that
    /// answered once and then went silent went on offering that one answer for as long as the
    /// process lived, and the only thing that grew was the ageing term. The other half is that the
    /// model measured its own age from the selection round rather than from the exchange, and the
    /// two together let a polling loop keep a dead source alive indefinitely.
    ///
    /// A sample exactly at the limit is still taken. The limit is how far the model will
    /// extrapolate, and extrapolating to the edge of what it allows is allowed.
    #[must_use]
    pub fn best_within(
        &self,
        now: MonotonicNanos,
        max_age: Nanos,
        ageing: &CounterAgeing,
        source_floor: Nanos,
    ) -> Option<&Sample> {
        self.samples
            .iter()
            .rev()
            .filter(|s| now.since(s.taken_at) <= max_age)
            .min_by_key(|s| s.interval_at(now, ageing, source_floor).width())
    }

    /// The narrowest interval any held sample supports at `now`, aged forward to it.
    #[must_use]
    pub fn interval_at(
        &self,
        now: MonotonicNanos,
        ageing: &CounterAgeing,
        source_floor: Nanos,
    ) -> Option<OffsetInterval> {
        self.best_within(now, Nanos::MAX, ageing, source_floor)
            .map(|s| s.interval_at(now, ageing, source_floor))
    }

    /// The state of this source, for the receipt to carry.
    #[must_use]
    pub fn state(&self, kept: bool) -> Option<SourceState> {
        let s = self.best()?;
        Some(SourceState {
            id: self.id.clone(),
            operator: s.operator.clone(),
            kind: s.kind,
            timescale: s.timescale,
            smear: s.smear,
            leap: s.leap,
            kept,
        })
    }

    /// Drop every sample. Used when a resume makes the whole history meaningless.
    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BandReading, RateKnowledge};
    use crate::policy::Policy;
    use timewitness_core::time::{NANOS_PER_MILLI, NANOS_PER_SEC};
    use timewitness_core::{LeapIndicator, Operator, SmearPolicy, SourceKind, Timescale};

    /// An ageing that widens at exactly `ppm` over an age and at nothing else, for arithmetic a
    /// test writes down rather than arithmetic a world produced.
    fn ageing_at(ppm: f64) -> CounterAgeing {
        let policy = Policy {
            frequency_floor_ppm: ppm,
            frequency_slew_ppm_per_second: 0.0,
            ..Policy::default()
        };
        let rate = RateKnowledge {
            frequency_ppm: None,
            frequency_stderr_ppm: 0.0,
            unclaimed_frequency_ppm: 0.0,
            band: BandReading::NotRead,
        };
        CounterAgeing::new(&policy, &rate)
    }

    fn sample(offset: Nanos, round_trip: Nanos, at: u64) -> Sample {
        Sample {
            source: SourceId::new("s"),
            operator: Operator::new("s"),
            kind: SourceKind::Ntp,
            offset,
            round_trip,
            stated_uncertainty: 0,
            sent_at: MonotonicNanos(at),
            taken_at: MonotonicNanos(at),
            timescale: Timescale::Utc,
            smear: SmearPolicy::None,
            leap: LeapIndicator::None,
        }
    }

    #[test]
    fn the_quickest_sample_is_the_one_used() {
        let mut w = SourceWindow::new(SourceId::new("s"), 8);
        w.push(sample(1, 40 * NANOS_PER_MILLI, 0));
        w.push(sample(2, 6 * NANOS_PER_MILLI, 1_000));
        w.push(sample(3, 90 * NANOS_PER_MILLI, 2_000));
        assert_eq!(w.best().unwrap().offset, 2);
    }

    #[test]
    fn a_tie_goes_to_the_newer_sample() {
        let mut w = SourceWindow::new(SourceId::new("s"), 8);
        w.push(sample(1, 5 * NANOS_PER_MILLI, 0));
        w.push(sample(2, 5 * NANOS_PER_MILLI, 1_000));
        assert_eq!(w.best().unwrap().offset, 2);
    }

    #[test]
    fn the_window_never_grows_past_its_capacity() {
        let mut w = SourceWindow::new(SourceId::new("s"), 3);
        for i in 0..10 {
            w.push(sample(i as Nanos, 5 * NANOS_PER_MILLI, i as u64));
        }
        assert_eq!(w.len(), 3);
        assert_eq!(w.best().unwrap().offset, 9);
    }

    #[test]
    fn an_old_best_sample_is_aged_before_it_is_used() {
        let mut w = SourceWindow::new(SourceId::new("s"), 8);
        w.push(sample(0, NANOS_PER_MILLI, 0));
        let fresh = w
            .interval_at(MonotonicNanos(0), &ageing_at(15.0), 0)
            .unwrap();
        let aged = w
            .interval_at(
                MonotonicNanos(300 * NANOS_PER_SEC as u64),
                &ageing_at(15.0),
                0,
            )
            .unwrap();
        assert!(aged.width() > fresh.width());
    }

    #[test]
    fn a_quick_old_sample_loses_to_a_fresh_slower_one_once_its_age_costs_more() {
        // Six milliseconds of round trip taken five minutes ago against ten milliseconds taken
        // now. Aged at fifty parts per million the old one carries fifteen milliseconds for its
        // age on top of its three, and the fresh one carries five. The round trip alone would pick
        // the old one, and did until 2026-09-18.
        let mut w = SourceWindow::new(SourceId::new("s"), 8);
        w.push(sample(1, 6 * NANOS_PER_MILLI, 0));
        w.push(sample(2, 10 * NANOS_PER_MILLI, 300 * NANOS_PER_SEC as u64));
        let now = MonotonicNanos(300 * NANOS_PER_SEC as u64);
        let chosen = w.best_within(now, Nanos::MAX, &ageing_at(50.0), 0).unwrap();
        assert_eq!(chosen.offset, 2);
        // And at an age that costs nothing, the quick one is still the one.
        let chosen = w
            .best_within(MonotonicNanos(1), Nanos::MAX, &ageing_at(50.0), 0)
            .unwrap();
        assert_eq!(chosen.offset, 1);
    }

    #[test]
    fn a_sample_past_the_age_limit_is_not_offered_however_narrow() {
        let mut w = SourceWindow::new(SourceId::new("s"), 8);
        w.push(sample(1, NANOS_PER_MILLI, 0));
        w.push(sample(2, 40 * NANOS_PER_MILLI, 200 * NANOS_PER_SEC as u64));
        let now = MonotonicNanos(300 * NANOS_PER_SEC as u64);
        let chosen = w
            .best_within(now, 200 * NANOS_PER_SEC, &ageing_at(15.0), 0)
            .unwrap();
        assert_eq!(chosen.offset, 2);
    }

    #[test]
    fn an_empty_window_supports_nothing() {
        let w = SourceWindow::new(SourceId::new("s"), 8);
        assert!(w.is_empty());
        assert!(w
            .interval_at(MonotonicNanos(0), &ageing_at(15.0), 0)
            .is_none());
        assert!(w.state(true).is_none());
    }
}
