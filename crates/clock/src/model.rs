//! The clock model itself.
//!
//! It holds a window of exchanges per source, turns them into intervals, throws away the sources
//! that disagree with the majority, combines what is left, fits a line through the last few
//! synchronisations, and from all of that keeps one interval of UTC that it is prepared to stand
//! behind.
//!
//! Two properties are worth stating because the rest of the design rests on them.
//!
//! A read does no network work. The model holds no sources and cannot reach one; the caller polls
//! and hands the results in. So a stamp is arithmetic over values already in memory, and there is
//! no code path by which taking a stamp could wait on a packet.
//!
//! A model that cannot support an interval refuses. It never returns the last good interval, and it
//! never returns a very wide one and leaves the caller to notice. Both of those look like working
//! software from the outside, and both of them are how a stamp that means nothing gets signed.

use std::collections::{BTreeMap, VecDeque};

use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    Bound, BoundBreakdown, EpsilonBasis, FusionRule, Generations, LeapIndicator, MonotonicNanos,
    OffsetInterval, Operator, Reading, Refusal, SmearPolicy, SourceId, SourceKind, SourceState,
    Stamp, Timescale, UnixNanos, Validity,
};
use timewitness_sources::Exchange;

use crate::combine;
use crate::independence;
use crate::marzullo;
use crate::monotonic::MonotonicClock;
use crate::policy::{ppm_over, signed_ppm_over, Policy, WIDEST};
use crate::regression::{self, Fit};
use crate::sample::Sample;
use crate::window::SourceWindow;

/// Where the machine's raw clock was when the model started.
///
/// The raw local estimate of UTC at monotonic value `m` is `wall + (m - mono)`. The system clock is
/// read once, here, and never again. Re-reading it would let the operating system's own time
/// service move the model's floor underneath it, which is exactly the fight this design avoids by
/// keeping its own clock over the counter instead.
///
/// This projection is the model's local clock and there is no other. Every offset the model
/// measures is measured against it and every interval the model reports is anchored to it, and
/// those two sentences have to keep describing the same clock or the bound describes nothing. That
/// is why an exchange carries no local timestamp: whatever a source client read would be a
/// different clock, and on a machine where another service is steering the system clock the two
/// walk apart at the oscillator's rate with nothing on either side able to see it happening.
///
/// Wherever the projection started is not a problem. A system clock a hundred milliseconds out at
/// startup makes every measured offset a hundred milliseconds larger, and the reported interval,
/// which is the projection plus the offset, comes out in the same place. The error is absorbed
/// rather than carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Origin {
    mono: MonotonicNanos,
    wall: UnixNanos,
}

impl Origin {
    fn raw_at(&self, now: MonotonicNanos) -> UnixNanos {
        self.wall + now.since(self.mono)
    }
}

/// What the last good synchronisation established.
#[derive(Clone, Debug)]
struct SyncState {
    /// The counter mark on the newest exchange that supported this synchronisation.
    ///
    /// This, and not `at`, is when the model last learned anything about UTC. The two are the same
    /// on a healthy poll and they come apart the moment the sources go quiet, because a selection
    /// round takes whatever is in the window and a poller carries on calling it on its own
    /// schedule. Measuring age from `at` therefore let a loop over frozen samples keep the model
    /// looking fresh for as long as the loop kept running. Everything that asks how long the model
    /// has been extrapolating asks this field.
    newest_exchange: MonotonicNanos,
    /// The Marzullo region, as offsets from the raw local clock.
    intersection: OffsetInterval,
    /// The point estimate, already inside `intersection`.
    offset: Nanos,
    /// The standard error of that offset, from the regression.
    offset_stderr: Nanos,
    /// The frequency error the model will stand behind, in parts per million, positive meaning the
    /// local clock is slow. `None` where the fit could not support one. See `supports_a_rate`.
    frequency_ppm: Option<f64>,
    /// The standard error of that frequency.
    frequency_stderr_ppm: f64,
    /// The magnitude of a fitted rate the model refused to stand behind, in parts per million.
    ///
    /// Zero whenever a rate is claimed, and zero before anything has been fitted. Where a fit is
    /// refused this carries its magnitude into the width, because the correction that would have
    /// removed it is no longer being applied and the true rate could be anywhere the fit allowed.
    /// It is what makes refusing a fit a widening rather than a quiet tightening.
    unclaimed_frequency_ppm: f64,
    /// The largest half round trip among the surviving sources, reported and never added twice.
    widest_network_half: Nanos,
    /// How the sources were combined.
    fusion: FusionRule,
    /// What every source was doing, kept and discarded alike.
    sources: Vec<SourceState>,
}

/// What the last synchronisation fitted, as a caller may read it.
///
/// The same numbers as `SyncState` and none of the model's own bookkeeping. It is a copy rather
/// than a borrow because every field is small and a caller holding a borrow of the model could not
/// then read from it.
#[derive(Clone, Copy, Debug)]
pub struct SyncFit {
    /// The counter mark on the newest exchange behind this synchronisation.
    pub newest_exchange: MonotonicNanos,
    /// The Marzullo region, as offsets from the raw local clock.
    pub intersection: OffsetInterval,
    /// The point estimate, already inside `intersection`.
    pub offset: Nanos,
    /// The standard error of that offset, from the regression.
    pub offset_stderr: Nanos,
    /// The frequency error the model will stand behind, in parts per million.
    pub frequency_ppm: Option<f64>,
    /// The standard error of that frequency.
    pub frequency_stderr_ppm: f64,
    /// The magnitude of a fitted rate the model refused to stand behind.
    pub unclaimed_frequency_ppm: f64,
    /// The largest half round trip among the surviving sources.
    pub widest_network_half: Nanos,
}

/// One source's contribution to a selection round.
#[derive(Clone, Debug)]
struct Candidate {
    id: SourceId,
    operator: Operator,
    kind: SourceKind,
    /// When the exchange behind this candidate came home.
    taken_at: MonotonicNanos,
    interval: OffsetInterval,
    network_half: Nanos,
    timescale: Timescale,
    smear: SmearPolicy,
    leap: LeapIndicator,
}

/// The last leap announcement the model saw, and how long it keeps the guard armed for.
///
/// A leap second is announced in the hours before it happens and the announcement is cleared the
/// moment it has happened. A smearing source starts diverging from a stepping one at that same
/// moment and stays diverged for the whole of its smear window. So the announcement is on while the
/// sources agree and off while they disagree, and arming a guard with it points the guard at the
/// wrong hours. This is what the model latches instead.
#[derive(Clone, Copy, Debug)]
struct LeapWatch {
    /// When a source was last seen announcing a pending leap.
    at: MonotonicNanos,
    /// How long after that the sources may still be spreading the second, in nanoseconds.
    window: Nanos,
}

/// The running model of how wrong this machine's clock is.
pub struct ClockModel {
    policy: Policy,
    clock: Box<dyn MonotonicClock>,
    origin: Origin,
    windows: BTreeMap<SourceId, SourceWindow>,
    history: VecDeque<regression::Point>,
    sync: Option<SyncState>,
    generations: Generations,
    suspended_since_sync: bool,
    stepped_since_sync: Option<Nanos>,
    leap_watch: Option<LeapWatch>,
    scheduling_allowance: Nanos,
    forced: Option<Validity>,
}

impl ClockModel {
    /// Start a model.
    ///
    /// `wall` is the machine's own idea of UTC at the moment of construction, read once by the
    /// caller. `granularity` is how finely the monotonic counter was measured to tick; the model
    /// takes the larger of it and the policy floor as the allowance for the read itself.
    #[must_use]
    pub fn new(
        policy: Policy,
        clock: Box<dyn MonotonicClock>,
        wall: UnixNanos,
        granularity: Nanos,
    ) -> Self {
        let mono = clock.now();
        let scheduling_allowance = granularity.max(policy.scheduling_floor);
        Self {
            policy,
            clock,
            origin: Origin { mono, wall },
            windows: BTreeMap::new(),
            history: VecDeque::new(),
            sync: None,
            generations: Generations::default(),
            suspended_since_sync: false,
            stepped_since_sync: None,
            leap_watch: None,
            scheduling_allowance,
            forced: None,
        }
    }

    /// The policy this model runs on.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The boot and resume counters a receipt has to carry.
    #[must_use]
    pub fn generations(&self) -> Generations {
        self.generations
    }

    /// The allowance for the local read itself, settled once when the model was built.
    #[must_use]
    pub fn scheduling_allowance(&self) -> Nanos {
        self.scheduling_allowance
    }

    /// What the last synchronisation fitted, or `None` before there has been one.
    ///
    /// Everything `read` puts in the width comes from these numbers and the policy, so this is what
    /// somebody needs to work out by hand what the width ought to be and compare it with what came
    /// back. Without it, the widening arithmetic could only be checked against itself, and a bound
    /// that quietly halves looks exactly like a bound that is right.
    #[must_use]
    pub fn fit(&self) -> Option<SyncFit> {
        self.sync.as_ref().map(|sync| SyncFit {
            newest_exchange: sync.newest_exchange,
            intersection: sync.intersection,
            offset: sync.offset,
            offset_stderr: sync.offset_stderr,
            frequency_ppm: sync.frequency_ppm,
            frequency_stderr_ppm: sync.frequency_stderr_ppm,
            unclaimed_frequency_ppm: sync.unclaimed_frequency_ppm,
            widest_network_half: sync.widest_network_half,
        })
    }

    /// What every source is doing, whether it survived the last selection or not.
    #[must_use]
    pub fn source_states(&self) -> Vec<SourceState> {
        match &self.sync {
            Some(s) => s.sources.clone(),
            None => self
                .windows
                .values()
                .filter_map(|w| w.state(false))
                .collect(),
        }
    }

    /// Take one exchange into the window for its source.
    ///
    /// The two ends of the round trip are stamped here, off the model's own anchor and the counter
    /// marks the client took, so the offset this produces is an offset against the clock the bound
    /// will be anchored to. There is no other clock in this function and no way for a caller to
    /// supply one.
    ///
    /// Returns whether the exchange was taken. A reply the source's own two timestamps contradict
    /// is refused here rather than reduced to something usable, so it never becomes a sample and
    /// never becomes a source. A poller that wants to count how often a source answers badly reads
    /// this; one that does not can ignore it, and the sample is gone either way.
    pub fn ingest(&mut self, exchange: &Exchange) -> bool {
        let local_t1 = self.origin.raw_at(exchange.mono_t1);
        let local_t4 = self.origin.raw_at(exchange.mono_t4);
        let Some(sample) = Sample::from_exchange(exchange, local_t1, local_t4) else {
            return false;
        };
        let capacity = self.policy.samples_per_source;
        self.windows
            .entry(sample.source.clone())
            .or_insert_with(|| SourceWindow::new(sample.source.clone(), capacity))
            .push(sample);
        true
    }

    /// Record that the machine has come back from sleep or suspend.
    ///
    /// Everything collected before the machine went away describes a clock that has since been off
    /// on its own for an unknown length of time, so the windows are emptied and the model refuses
    /// until it has synchronised again. Detecting the resume belongs to the platform layer; acting
    /// on it belongs here.
    pub fn note_resume(&mut self) {
        self.generations.resume = self.generations.resume.saturating_add(1);
        self.suspended_since_sync = true;
        for w in self.windows.values_mut() {
            w.clear();
        }
        self.history.clear();
    }

    /// Record that something other than this agent moved the machine's clock.
    ///
    /// The model refuses until it has synchronised again. It does not stop the other discipliner,
    /// it has no way to and it does not claim one: a step is recorded after the fact, and what the
    /// agent controls is whether it puts its name to a reading taken afterwards.
    ///
    /// The refusal is not because the reported interval rests on the system clock, which it does
    /// not: the wall clock is read once at construction and the model works over the monotonic
    /// counter from there. It is because a step is evidence that a second discipliner is active on
    /// this machine, and a discipliner that can move the clock can usually also change the rate of
    /// the counter this model measures against. One more synchronisation costs a poll interval and
    /// replaces the guess.
    ///
    /// Detecting the step belongs to the platform layer; acting on it belongs here.
    pub fn note_system_clock_step(&mut self, by: Nanos) {
        self.stepped_since_sync = Some(by);
    }

    /// Record which boot of the machine this is.
    pub fn set_boot_generation(&mut self, boot: u64) {
        self.generations.boot = boot;
    }

    /// Force the model into an invalid state from outside.
    ///
    /// The environment faults that invalidate a bound are detected by the platform layer, not here.
    /// This is the door it drives the model through, and the refusal path is the same one every
    /// other invalid state uses.
    pub fn force_invalid(&mut self, validity: Validity) {
        self.forced = Some(validity);
    }

    /// Clear a forced invalid state.
    pub fn clear_forced(&mut self) {
        self.forced = None;
    }

    /// Run a selection round over whatever the sources have said so far.
    ///
    /// Returns what this round established. A round that fails leaves the previous synchronisation
    /// in place, so the model carries on in holdover from the last good one rather than losing it.
    pub fn synchronise(&mut self) -> Validity {
        if let Some(detail) = self.policy.fault() {
            return Validity::PolicyRefused { detail };
        }
        let now = self.clock.now();
        let offered = self.candidates_at(now);

        // A source announcing a pending leap arms the guard for the whole of the window over which
        // the sources may then spread the second, rather than only for as long as the announcement
        // stands. See `LeapWatch`.
        if offered.iter().any(|c| c.leap.leap_pending()) {
            self.leap_watch = Some(LeapWatch {
                at: now,
                window: smear_window_of(&offered, self.policy.leap_smear_window),
            });
        }

        // A source that says its own clock is not synchronised is not a candidate. It is still
        // reported, marked as not kept, so a receipt shows that it answered and says why it was not
        // used.
        let eligible: Vec<usize> = (0..offered.len())
            .filter(|i| offered[*i].leap != LeapIndicator::Unsynchronised)
            .collect();
        let candidates: Vec<&Candidate> = eligible.iter().map(|i| &offered[*i]).collect();

        if candidates.len() < self.policy.min_sources {
            return Validity::InsufficientSources {
                present: candidates.len(),
                required: self.policy.min_sources,
            };
        }

        // The second floor, and on the shipped policy it is the binding one. A count of sources is a
        // count of names and names cost nothing; this is the count of parties behind them. Checked
        // before the intervals are combined, because a round that cannot clear it is refused
        // whatever the intervals say and there is no reason to do the arithmetic first.
        let operators: Vec<Operator> = candidates.iter().map(|c| c.operator.clone()).collect();
        let operators_offered = independence::distinct(&operators);
        if operators_offered < self.policy.min_operators {
            return Validity::InsufficientOperators {
                present: operators_offered,
                required: self.policy.min_operators,
            };
        }

        let intervals: Vec<OffsetInterval> = candidates.iter().map(|c| c.interval).collect();
        let Some(selection) = marzullo::select(&intervals) else {
            return Validity::InsufficientSources {
                present: 0,
                required: self.policy.min_sources,
            };
        };
        let found = &selection.found;

        // Two refusals and they are different facts, so they are reported as different facts. The
        // first is Marzullo's own: nothing reached a majority. The second is this product's own rule
        // of 2026-09-09: something did reach a majority and the only reason it did is sources that
        // could not have disagreed with anybody. A reader who knows Marzullo and is handed the same
        // intervals will compute the first answer and has to be able to see why we gave the second.
        if found.free_majority {
            return Validity::FreeMajority {
                present: found.offered,
                informative: found.offered - found.could_not_disagree.len(),
            };
        }

        if !found.has_majority() {
            return Validity::NoMajority {
                present: found.offered,
                agreeing: found.agreeing,
            };
        }

        let (kept, discarded) = (selection.kept.clone(), selection.discarded.clone());

        // The count that goes in the receipt is the count of sources that constrained the region,
        // and from 2026-09-08 that excludes any source swallowing every other one whole. A receipt
        // whose kept sources are not a majority of those offered is refused by
        // `timewitness_receipt::validate`, so the agent has to refuse here rather than sign one its
        // own verifier would turn down. That is an old lesson at a different boundary: two shells
        // of one product disagreeing about the same artefact.
        if 2 * kept.len() <= intervals.len() {
            return Validity::NoMajority {
                present: found.offered,
                agreeing: kept.len(),
            };
        }

        // The same question the line above just asked, asked of the parties rather than of the
        // intervals, and it is the whole of what independence adds. Marzullo's guarantee holds
        // while fewer than half the sources are wrong, and that needs them to be wrong
        // separately; six intervals from one company are one chance to be wrong wearing six
        // coats. So a majority of intervals that rests on a minority of operators is refused, and
        // a round that clears the majority still has to leave enough distinct operators standing
        // to meet the floor.
        //
        // Two tests rather than one, because they refuse different things. The majority catches a
        // large round dominated by one party; the floor catches a small round that is unanimous and
        // has nobody in it. `timewitness_clock::independence` carries the reasoning and the cases.
        let standing = independence::assess(&operators, &kept);
        if !standing.has_majority() {
            return Validity::OperatorMajority {
                present: standing.offered,
                supporting: standing.kept,
            };
        }
        if !standing.meets(self.policy.min_operators) {
            return Validity::InsufficientOperators {
                present: standing.kept,
                required: self.policy.min_operators,
            };
        }

        let survivors: Vec<&Candidate> = kept.iter().map(|i| candidates[*i]).collect();
        let thrown_out: Vec<&Candidate> = discarded.iter().map(|i| candidates[*i]).collect();

        if let Some(detail) = timescale_conflict(&survivors, self.inside_a_smear_window(now)) {
            return Validity::TimescaleConflict { detail };
        }

        if let Some(detail) = smear_split(
            &survivors,
            &thrown_out,
            &selection.region,
            self.policy.leap_divergence_ceiling,
        ) {
            return Validity::TimescaleConflict { detail };
        }

        let survivors: Vec<OffsetInterval> = kept.iter().map(|i| intervals[*i]).collect();
        // The floor below which a source may not claim authority, which is its own number and not
        // the allowance for reading the local counter. See `Policy::weight_floor`.
        let width_floor = self.policy.weight_floor;
        let Some(combined) = combine::combine(&survivors, &selection.region, width_floor) else {
            return Validity::NoMajority {
                present: found.offered,
                agreeing: found.agreeing,
            };
        };

        let widest_network_half = kept
            .iter()
            .map(|i| candidates[*i].network_half)
            .max()
            .unwrap_or(0);

        // When the model last actually heard from a source. Taken over the survivors, because they
        // are the ones holding the interval up; a fresh answer from a source Marzullo threw out
        // says nothing about how well this machine knows UTC.
        let newest_exchange = kept
            .iter()
            .map(|i| candidates[*i].taken_at)
            .max()
            .unwrap_or(now);

        // A round that heard nothing new is not a measurement, so it does not become a regression
        // point. Feeding one in would fit a line through offsets the model has already used, at
        // counter values it has invented, and the line gets flatter and its residual smaller every
        // time round: silence would narrow the bound. That is the same fault as the one this fix is
        // about, arriving through the fit rather than through the ceiling.
        let heard_something_new = self.sync.as_ref().map_or(true, |s| {
            newest_exchange.as_nanos() > s.newest_exchange.as_nanos()
        });
        let half_width = selection.region.width().div_euclid(2).max(1);
        if heard_something_new {
            self.push_history(regression::Point {
                at: newest_exchange,
                offset: combined.offset,
                half_width,
            });
        }

        let history: Vec<regression::Point> = self.history.iter().copied().collect();
        let fitted = regression::fit(&history, self.policy.regression_min_points);

        let (offset, offset_stderr, frequency_ppm, frequency_stderr_ppm, unclaimed_frequency_ppm) =
            match fitted {
                Some(fit) => {
                    // The offset half of the fit is kept either way. It is the scatter of the
                    // measurements themselves and it is honest whatever the baseline was; throwing
                    // it away with the frequency would take the largest term out of the width for
                    // nothing.
                    let offset = fit.offset.clamp(selection.region.lo, selection.region.hi);
                    if supports_a_rate(&fit, &self.policy) {
                        (
                            offset,
                            fit.offset_stderr,
                            Some(fit.frequency_ppm),
                            fit.frequency_stderr_ppm,
                            0.0,
                        )
                    } else {
                        (
                            offset,
                            fit.offset_stderr,
                            None,
                            fit.frequency_stderr_ppm,
                            fit.frequency_ppm.abs(),
                        )
                    }
                }
                // Nothing has been fitted yet, so no frequency has been measured. The honest values
                // are no drift and no extra residual, with the floor carrying the uncertainty.
                None => (
                    combined.offset,
                    0,
                    None,
                    self.policy.frequency_floor_ppm,
                    0.0,
                ),
            };

        // Reported over everything that answered, not over everything that was used. A source
        // dropped for saying its own clock is wrong is in the receipt with `kept` false, because a
        // reader who cannot see that it answered cannot see why the count of sources is what it is.
        let kept_sources: Vec<usize> = kept.iter().map(|k| eligible[*k]).collect();
        let mut sources = Vec::with_capacity(offered.len());
        for (i, c) in offered.iter().enumerate() {
            sources.push(SourceState {
                id: c.id.clone(),
                operator: c.operator.clone(),
                kind: c.kind,
                timescale: c.timescale,
                smear: c.smear,
                leap: c.leap,
                kept: kept_sources.contains(&i),
            });
        }
        debug_assert_eq!(kept.len() + discarded.len(), candidates.len());

        self.sync = Some(SyncState {
            newest_exchange,
            intersection: selection.region,
            offset,
            offset_stderr,
            frequency_ppm,
            frequency_stderr_ppm,
            unclaimed_frequency_ppm,
            widest_network_half,
            // Offered is over everything that answered, which is what the field says it is and what
            // the source list beside it holds. It read `found.offered` until it was corrected,
            // which is the number of intervals Marzullo was given, so a round in which a source
            // reported its own clock unsynchronised put a count of four in a receipt listing five
            // sources, and this product's own validator refused it. Marzullo's own count is not
            // lost: the candidates are the listed sources that did not say their clock was wrong,
            // and both halves derive it the same way rather than being told it.
            fusion: FusionRule::MarzulloThenInverseSquare {
                offered: offered.len(),
                kept: kept.len(),
            },
            sources,
        });
        self.suspended_since_sync = false;
        self.stepped_since_sync = None;

        Validity::Valid
    }

    /// Whether the sources may still be spreading a leap second the model saw announced.
    fn inside_a_smear_window(&self, now: MonotonicNanos) -> bool {
        self.leap_watch.is_some_and(|w| now.since(w.at) <= w.window)
    }

    /// The model's current state, without taking a reading.
    #[must_use]
    pub fn validity(&self) -> Validity {
        self.validity_at(self.clock.now())
    }

    /// Take a local reading and the interval that goes with it.
    ///
    /// One counter read and some arithmetic. No network, no lock, no system time call.
    pub fn read(&self) -> Result<Stamp, Refusal> {
        let now = self.clock.now();

        let state = self.validity_at(now);
        if !state.is_valid() {
            return Err(Refusal::new(state));
        }

        // Checked by `validity_at` immediately above.
        let sync = self.sync.as_ref().expect("a valid model has synchronised");

        // Measured from the newest exchange behind the interval and never from the selection round
        // that used it. The round is when the arithmetic ran; the exchange is when the model last
        // learned anything.
        //
        // The span between the two is paid for twice, once inside the intersection where every
        // source interval was aged at the frequency floor, and once here at the frequency
        // uncertainty the model measured. That is a widening and it is the correct direction: the
        // second figure is never smaller than the floor, and paying it twice over a span the model
        // heard nothing during is cheaper than the alternative, which is a poller keeping a dead
        // window alive.
        let elapsed = now.since(sync.newest_exchange);

        // Two quantities and they are not the same one. The first is how wrong the fitted frequency
        // was at the moment it was fitted, floored at what the hardware can support. The second is
        // how far the rate has moved since, which is what the correction below cannot know about
        // and what the fitted frequency's own standard error says nothing about. They are added
        // rather than maximised, because they are independent and both are present.
        //
        // Holding them as one number was an earlier fault: fifteen parts per million was doing both
        // jobs, and fifteen is NTP's `PHI`, which bounds the total error of an extrapolation that
        // has not been corrected. Correcting first and then applying the same figure to what is
        // left applies it to a different quantity, and an ordinary forty parts per million
        // temperature change then put true UTC 79.669 ms outside a receipt that signed cleanly.
        //
        // A third quantity joins them where the model refused a fitted rate. The correction below
        // is then not applied, so the true rate could be anywhere that fit allowed, and the whole
        // magnitude of it has to be carried as width instead. Adding it to the measurement term
        // rather than taking the larger of the two is what makes this a widening: the interval
        // afterwards is the interval before it plus the fitted magnitude on each side, so it
        // contains the old one at every elapsed time rather than merely resembling it.
        let measurement_ppm = (sync.frequency_stderr_ppm * self.policy.coverage_factor)
            .max(self.policy.frequency_floor_ppm)
            + sync.unclaimed_frequency_ppm;
        let frequency_uncertainty_ppm = measurement_ppm + rate_movement_ppm(&self.policy, elapsed);

        let oscillator_holdover =
            ppm_over(frequency_uncertainty_ppm, elapsed).saturating_add(if elapsed > 0 {
                self.policy.holdover_allowance
            } else {
                0
            });
        let model_residual = scaled(sync.offset_stderr, self.policy.coverage_factor);
        let scheduling = self.scheduling_allowance;
        let safety_margin = self.policy.safety_margin;
        let widen = oscillator_holdover
            .saturating_add(model_residual)
            .saturating_add(scheduling)
            .saturating_add(safety_margin);

        // The interval is the intersection plus the widening on each side, so its width is known
        // before either end is placed. Refusing here rather than after means a term carried at
        // `WIDEST` is refused as too wide rather than overflowing on the way to being measured.
        let width = sync
            .intersection
            .width()
            .saturating_add(widen.saturating_mul(2));
        if width > self.policy.max_bound_width {
            return Err(Refusal::new(Validity::BoundTooWide {
                width,
                ceiling: self.policy.max_bound_width,
            }));
        }

        let drift = signed_ppm_over(sync.frequency_ppm.unwrap_or(0.0), elapsed);
        let lo = sync.intersection.lo + drift - widen;
        let hi = sync.intersection.hi + drift + widen;
        let point = (sync.offset + drift).clamp(lo, hi);

        let raw = self.origin.raw_at(now);

        let breakdown = BoundBreakdown {
            fusion: sync.fusion,
            // Rounded up so the parts never add to less than the whole.
            intersection_half: (sync.intersection.width() + 1).div_euclid(2),
            widest_source_network_half: sync.widest_network_half,
            scheduling,
            oscillator_holdover,
            model_residual,
            safety_margin,
        };

        let bound = Bound {
            earliest: raw + lo,
            latest: raw + hi,
            // Our own model and nothing else. A third-party sandwich needs signed evidence on both
            // sides of the reading, and fetching that is the job of the evidence clients, not of
            // the clock model. The receipt issuer promotes this once it has that evidence in hand.
            basis: EpsilonBasis::LocalModelOnly,
            breakdown,
        };

        debug_assert_eq!(bound.width(), width);

        Ok(Stamp {
            reading: Reading {
                monotonic: now,
                utc_estimate: raw + point,
            },
            bound,
            sources: sync.sources.clone(),
            generations: self.generations,
            since_last_sync: elapsed,
            frequency_ppm: sync.frequency_ppm,
        })
    }

    fn validity_at(&self, now: MonotonicNanos) -> Validity {
        // Ahead of everything else, forced states included: no reading taken under this policy can
        // be stood behind, whatever else is true.
        if let Some(detail) = self.policy.fault() {
            return Validity::PolicyRefused { detail };
        }
        if let Some(forced) = &self.forced {
            return forced.clone();
        }
        if self.suspended_since_sync {
            return Validity::SuspendedSinceLastSync {
                resume_generation: self.generations.resume,
            };
        }
        if let Some(by) = self.stepped_since_sync {
            return Validity::SystemClockStepped { by };
        }
        let Some(sync) = &self.sync else {
            return Validity::NeverSynchronised;
        };
        // The age of the newest exchange, not the age of the last selection round. A poller calling
        // `synchronise()` over a window nothing is refreshing used to reset the second of those on
        // a schedule, so the ceiling never fired at all.
        let elapsed = now.since(sync.newest_exchange);
        if elapsed > self.policy.max_holdover {
            return Validity::HoldoverExceeded {
                elapsed,
                ceiling: self.policy.max_holdover,
            };
        }
        Validity::Valid
    }

    /// The sources that still have something to say at `now`.
    ///
    /// A sample older than the longest holdover the policy allows is not offered. The model is not
    /// prepared to extrapolate its own interval past that ceiling, and an old exchange is
    /// extrapolation with a longer arm and a smaller allowance, since a sample ages at the
    /// frequency floor while a holdover ages at the frequency uncertainty the model actually
    /// measured. One ceiling covers both, so there is one number rather than two that could
    /// disagree.
    fn candidates_at(&self, now: MonotonicNanos) -> Vec<Candidate> {
        let floor = self.policy.frequency_floor_ppm;
        let source_floor = self.policy.source_interval_floor;
        let oldest = self.policy.max_holdover;
        self.windows
            .values()
            .filter_map(|w| {
                let best = w.best_within(now, oldest)?;
                Some(Candidate {
                    id: w.id().clone(),
                    operator: best.operator.clone(),
                    kind: best.kind,
                    taken_at: best.taken_at,
                    interval: best.interval_at(now, floor, source_floor),
                    network_half: best.split_direction_residual(),
                    timescale: best.timescale,
                    smear: best.smear,
                    leap: best.leap,
                })
            })
            .collect()
    }

    fn push_history(&mut self, point: regression::Point) {
        self.history.push_back(point);
        while self.history.len() > self.policy.history_capacity {
            self.history.pop_front();
        }
        let newest = point.at;
        let window = self.policy.regression_window;
        while let Some(front) = self.history.front() {
            if newest.since(front.at) > window && self.history.len() > 2 {
                self.history.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Whether the surviving sources would disagree about a leap second that is near enough to matter.
///
/// Near enough means one of two things, and until 2026-09-08 it meant only the first of them. A
/// source is announcing a leap right now; or the model saw an announcement recently enough that the
/// sources may still be spreading the second, which `inside_a_smear_window` decides.
///
/// The second arm is the one that matters, because the first is armed for the wrong hours. An
/// announcement is cleared the instant the leap happens, and that instant is when a smearing source
/// and a stepping source begin to disagree. So the guard was on while they agreed and off for the
/// whole of the window while they did not.
///
/// Away from a leap altogether a smeared source and a stepped source agree, so refusing then would
/// be refusing for no reason, and neither arm fires.
fn timescale_conflict(survivors: &[&Candidate], inside_a_smear_window: bool) -> Option<String> {
    let announced = survivors.iter().any(|c| c.leap.leap_pending());
    if !announced && !inside_a_smear_window {
        return None;
    }
    let when = if announced {
        "a leap second is pending"
    } else {
        "the sources may still be spreading a leap second that has already happened"
    };

    if let Some(unknown) = survivors.iter().find(|c| c.timescale == Timescale::Unknown) {
        return Some(format!(
            "{} did not say what timescale it answers on and {when}",
            unknown.id
        ));
    }

    for (i, a) in survivors.iter().enumerate() {
        for b in survivors.iter().skip(i + 1) {
            if a.smear.conflicts_with(b.smear) {
                return Some(format!(
                    "{} handles a leap second as {:?} and {} handles it as {:?}, and {when}",
                    a.id, a.smear, b.id, b.smear
                ));
            }
        }
    }

    None
}

/// Whether the sources thrown out were thrown out along the line that separates a smeared source
/// from a stepped one.
///
/// This is the case the model cannot see any other way: an agent started part way through a smear
/// window never saw the announcement, so it has nothing to latch and nothing to arm. What it can
/// still see is the shape of the disagreement. When every source Marzullo threw out disagrees about
/// smearing with every source it kept, at least one of them declares a smear, and the gap between
/// them is small enough to be one second spread over a window, the discard is as likely to be the
/// smear as it is to be a broken clock, and the model has no way to tell which side is UTC.
///
/// So it refuses. That is the conservative direction and it is the only honest one: choosing the
/// majority here is choosing the smeared sources, which are deliberately not on UTC for that day.
///
/// Two limits are deliberate. A gap wider than one second is not a leap smear, whatever the sources
/// declare, and Marzullo's discard stands. And where nothing in the pool declares a smear at all,
/// this never fires, because a source thrown out of a pool that does not smear is an ordinary
/// outlier and throwing it out is what selection is for.
fn smear_split(
    survivors: &[&Candidate],
    thrown_out: &[&Candidate],
    region: &OffsetInterval,
    ceiling: Nanos,
) -> Option<String> {
    if thrown_out.is_empty() || survivors.is_empty() {
        return None;
    }

    let declares_a_smear = |c: &&Candidate| matches!(c.smear, SmearPolicy::Linear { .. });
    if !survivors.iter().any(declares_a_smear) && !thrown_out.iter().any(declares_a_smear) {
        return None;
    }

    for out in thrown_out {
        if !survivors.iter().all(|s| s.smear.conflicts_with(out.smear)) {
            continue;
        }
        let gap = gap_between(&out.interval, region);
        if gap > 0 && gap <= ceiling {
            return Some(format!(
                "{} was {} ms outside what the other sources agreed and handles a leap second as \
                 {:?} where they handle it as {:?}, which is a smear rather than a broken clock as \
                 far as anything here can tell",
                out.id,
                nanos_as_millis(gap),
                out.smear,
                survivors[0].smear,
            ));
        }
    }

    None
}

/// How far an interval sits outside a region, or zero where it reaches it.
fn gap_between(interval: &OffsetInterval, region: &OffsetInterval) -> Nanos {
    if interval.hi < region.lo {
        region.lo - interval.hi
    } else if interval.lo > region.hi {
        interval.lo - region.hi
    } else {
        0
    }
}

/// How long the sources may spend spreading a leap second, from what they declare.
///
/// The widest declared window, with a source that will not say what it does counted at the fallback
/// rather than at nothing. A source that steps contributes no window of its own, because a step has
/// no width; where every source steps, the answer is zero and the guard closes at the leap itself,
/// which is correct, since there is no smear to be inside.
fn smear_window_of(candidates: &[Candidate], fallback: Nanos) -> Nanos {
    candidates
        .iter()
        .map(|c| match c.smear {
            SmearPolicy::None => 0,
            SmearPolicy::Linear { window_seconds } => Nanos::from(window_seconds) * NANOS_PER_SEC,
            SmearPolicy::Unknown => fallback,
        })
        .max()
        .unwrap_or(0)
}

/// A nanosecond quantity as milliseconds, for a message a person reads.
fn nanos_as_millis(n: Nanos) -> f64 {
    n as f64 / NANOS_PER_MILLI as f64
}

/// Whether a fit has actually measured this machine's oscillator, or only its own noise.
///
/// The regression is honest arithmetic and it will fit a line through anything. What it cannot do
/// is know how long a baseline it was given. Four points taken inside two seconds, against sources
/// whose midpoints move by whole seconds, produce a slope of thousands of parts per million: the
/// sources' jitter divided by a very short baseline. A consumer crystal is specified at plus or
/// minus fifty parts per million across its whole temperature range, so a fitted rate of ten
/// thousand is not a fact about the oscillator, and a receipt that signs one is quoting a figure
/// nobody measured. That breaks the rule that a figure is quoted with the conditions it was
/// measured under, in the one artefact this product hands to a stranger.
///
/// Two questions, and a fit has to answer both. Could it separate one rate in the band from
/// another, or is its own error bar wider than the whole band. And does the rate it found lie
/// inside the band a crystal can occupy at all. `Policy::frequency_span_ppm` is the band, from one
/// end to the other, so half of it is the largest magnitude a part may honestly show.
///
/// Refusing costs nothing and is never a tightening: `SyncState::unclaimed_frequency_ppm` carries
/// the magnitude the model has stopped correcting for straight into the width. What it buys is that
/// the number in a signed receipt is either measured or absent, and never noise wearing the label
/// of a measurement.
fn supports_a_rate(fit: &Fit, policy: &Policy) -> bool {
    let band = policy.frequency_span_ppm;
    if !band.is_finite() || band <= 0.0 {
        return false;
    }
    if !fit.frequency_ppm.is_finite() || !fit.frequency_stderr_ppm.is_finite() {
        return false;
    }
    let separates_the_band = fit.frequency_stderr_ppm * policy.coverage_factor <= band;
    let inside_the_band = fit.frequency_ppm.abs() <= band / 2.0;
    separates_the_band && inside_the_band
}

/// How far the oscillator's rate may have moved in `elapsed`, in parts per million.
///
/// A rate does not jump and it does not wander for ever, so the allowance is the smaller of two
/// things: a slew over the time that has passed, and the whole band the part is specified across.
/// Over a poll interval that is a few parts per million and over an outage it is the whole band.
///
/// Both figures are choices and both live in `Policy` with the reasoning attached. Anything not
/// finite is an infinite allowance. This said the opposite until 2026-09-17, on the reasoning that an
/// infinite widening is a refusal dressed as an answer, and what it gave instead was no allowance at
/// all, which narrows the bound. An infinite allowance becomes [`WIDEST`] in `ppm_over`, and a bound
/// holding that is refused by the ceiling, which is the same refusal said plainly.
fn rate_movement_ppm(policy: &Policy, elapsed: Nanos) -> f64 {
    if elapsed <= 0 {
        return 0.0;
    }
    let seconds = elapsed as f64 / NANOS_PER_SEC as f64;
    let slewed = policy.frequency_slew_ppm_per_second * seconds;
    if !slewed.is_finite() || !policy.frequency_span_ppm.is_finite() {
        return f64::INFINITY;
    }
    slewed.min(policy.frequency_span_ppm).max(0.0)
}

/// A nanosecond allowance scaled by a factor, rounded up.
///
/// Used for the coverage factor on the model's own residual. A factor that is not a number, or is
/// nought or below, used to give nought, which took the residual out of the bound. It now gives
/// [`WIDEST`], which the ceiling refuses. `Policy::fault` refuses such a policy before this is
/// reached, so this is the second net and not the first.
fn scaled(value: Nanos, factor: f64) -> Nanos {
    if !factor.is_finite() || factor <= 0.0 {
        return WIDEST;
    }
    let product = ((value as f64) * factor).ceil();
    if !product.is_finite() || product >= WIDEST as f64 {
        return WIDEST;
    }
    product as Nanos
}

/// Seconds as nanoseconds, for callers assembling policy values.
#[must_use]
pub const fn seconds(n: i64) -> Nanos {
    (n as Nanos) * NANOS_PER_SEC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_coverage_factor_nobody_can_use_scales_to_the_widest_and_never_nought() {
        // Nought, negative nought, minus one, not a number and both infinities. Each gave nought until
        // 2026-09-17.
        for factor in [0.0, -0.0, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(scaled(1_000, factor), WIDEST, "factor {factor}");
        }
        assert_eq!(scaled(1_000, 2.0), 2_000);
        assert_eq!(scaled(1_000, 1e300), WIDEST);
    }

    #[test]
    fn a_rate_nobody_can_use_is_an_infinite_allowance_and_never_nought() {
        let policy = Policy {
            frequency_slew_ppm_per_second: f64::NAN,
            ..Policy::default()
        };
        let allowance = rate_movement_ppm(&policy, NANOS_PER_SEC);
        assert!(allowance.is_infinite() && allowance > 0.0, "{allowance}");
    }
}
