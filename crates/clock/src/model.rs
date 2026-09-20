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
use crate::sample::{RejectedExchange, Sample};
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
        // Signed, so a counter reading before the origin projects to a wall time before it rather
        // than to the origin itself. Nothing is measured before the origin: `ingest` refuses an
        // exchange stamped there, and a read there is refused by the holdover ceiling, because the
        // distance from the newest exchange is what the ceiling is held against.
        self.wall + now.signed_since(self.mono)
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
    /// has been extrapolating asks `newest_exchange_sent` below, through `holdover_at`.
    newest_exchange: MonotonicNanos,
    /// The counter mark on which that same exchange went out, which is what every holdover term
    /// is measured from. See `holdover_at` for why it is this mark and not the reply's.
    newest_exchange_sent: MonotonicNanos,
    /// The Marzullo region, as offsets from the raw local clock.
    intersection: OffsetInterval,
    /// The point estimate, already inside `intersection`.
    offset: Nanos,
    /// The standard error of that offset, from the regression.
    offset_stderr: Nanos,
    /// What the width knows about the oscillator's rate. See [`RateKnowledge`].
    rate: RateKnowledge,
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
    /// The counter mark on which that exchange went out.
    pub newest_exchange_sent: MonotonicNanos,
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
    /// The magnitude the model is not correcting for, in parts per million. See
    /// [`RateKnowledge::unclaimed_frequency_ppm`].
    pub unclaimed_frequency_ppm: f64,
    /// What reading that fitted rate back against the band the policy assumes said. See
    /// [`BandReading`].
    pub band: BandReading,
    /// The largest half round trip among the surviving sources.
    pub widest_network_half: Nanos,
}

/// One source's contribution to a selection round.
#[derive(Clone, Debug)]
struct Candidate {
    id: SourceId,
    operator: Operator,
    kind: SourceKind,
    /// When the exchange behind this candidate went out and came home.
    sent_at: MonotonicNanos,
    taken_at: MonotonicNanos,
    interval: OffsetInterval,
    /// The half width the source's own answer supports, before the model's ageing of it. It is
    /// what the weighting is taken on; the interval above carries the ageing too and is what
    /// Marzullo intersects. See `combine`.
    own_half: Nanos,
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
        // The platform's measurement is an input the policy validator never sees, so it is held to
        // the same range here: never below the floor, and never past the widest any term is carried
        // as, which the ceiling then refuses rather than the adds overflowing on the way to it.
        let scheduling_allowance = granularity.max(policy.scheduling_floor).clamp(0, WIDEST);
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
            newest_exchange_sent: sync.newest_exchange_sent,
            intersection: sync.intersection,
            offset: sync.offset,
            offset_stderr: sync.offset_stderr,
            frequency_ppm: sync.rate.frequency_ppm,
            frequency_stderr_ppm: sync.rate.frequency_stderr_ppm,
            unclaimed_frequency_ppm: sync.rate.unclaimed_frequency_ppm,
            band: sync.rate.band,
            widest_network_half: sync.widest_network_half,
        })
    }

    /// What every source is doing, whether it survived the last selection or not.
    ///
    /// After a selection these are the states that selection built, off the samples it used. Before
    /// there has been one there is no chosen sample, so each source is described by the last thing
    /// it said. Both halves read a sample somebody chose; neither picks one of its own, which is
    /// the fault corrected on 2026-09-19.
    #[must_use]
    pub fn source_states(&self) -> Vec<SourceState> {
        match &self.sync {
            Some(s) => s.sources.clone(),
            None => self
                .windows
                .values()
                .filter_map(|w| w.newest().map(|sample| w.state_of(sample, false)))
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
    /// Returns why the exchange was not taken, or `None` where it was. A reply the source's own two
    /// timestamps contradict, a timestamp outside the range the arithmetic carries, an uncertainty
    /// no clock can have, a reply stamped as home before the request left, or a request stamped
    /// before this model existed: each is refused here rather than reduced to something usable, so
    /// it never becomes a sample and never becomes a source. A poller that wants to count how often
    /// a source answers badly reads this; one that does not can ignore it, and the sample is gone
    /// either way.
    ///
    /// The two counter marks are the client's and are held here, because they are the ends the
    /// anchor is applied to. Until 2026-09-17 a reply stamped before its request was read as a
    /// round trip of nought, which is the shortest there is and so the sample the window prefers.
    pub fn ingest(&mut self, exchange: &Exchange) -> Option<RejectedExchange> {
        if exchange.mono_t4 < exchange.mono_t1 {
            return Some(RejectedExchange::HomeBeforeItLeft);
        }
        if exchange.mono_t1 < self.origin.mono {
            return Some(RejectedExchange::BeforeTheModelStarted);
        }
        let local_t1 = self.origin.raw_at(exchange.mono_t1);
        let local_t4 = self.origin.raw_at(exchange.mono_t4);
        let sample = match Sample::from_exchange(exchange, local_t1, local_t4) {
            Ok(sample) => sample,
            Err(why) => return Some(why),
        };
        let capacity = self.policy.samples_per_source;
        self.windows
            .entry(sample.source.clone())
            .or_insert_with(|| SourceWindow::new(sample.source.clone(), capacity))
            .push(sample);
        None
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
        // Each survivor's own half width, in the same order, because the weighting is taken on what
        // the sources said about themselves and not on the ageing term they all share.
        let own_halves: Vec<Nanos> = kept.iter().map(|i| candidates[*i].own_half).collect();
        // The floor below which a source may not claim authority, which is its own number and not
        // the allowance for reading the local counter. See `Policy::weight_floor`.
        let width_floor = self.policy.weight_floor;
        let Some(combined) =
            combine::combine(&survivors, &own_halves, &selection.region, width_floor)
        else {
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
        let newest = kept
            .iter()
            .map(|i| candidates[*i])
            .max_by_key(|c| c.taken_at);
        let newest_exchange = newest.map_or(now, |c| c.taken_at);
        let newest_exchange_sent = newest.map_or(now, |c| c.sent_at);

        // A round that heard nothing new is not a measurement, so it does not become a regression
        // point. Feeding one in would fit a line through offsets the model has already used, at
        // counter values it has invented, and the line gets flatter and its residual smaller every
        // time round: silence would narrow the bound. That is the same fault as the one this fix is
        // about, arriving through the fit rather than through the ceiling.
        let heard_something_new = self.sync.as_ref().map_or(true, |s| {
            newest_exchange.as_nanos() != s.newest_exchange.as_nanos()
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

        let (offset, offset_stderr, rate) = match fitted {
            Some(fit) => {
                // The offset half of the fit is kept either way. It is the scatter of the
                // measurements themselves and it is honest whatever the baseline was; throwing
                // it away with the frequency would take the largest term out of the width for
                // nothing.
                let offset = fit.offset.clamp(selection.region.lo, selection.region.hi);
                (
                    offset,
                    fit.offset_stderr,
                    RateKnowledge::from_fit(&fit, &self.policy),
                )
            }
            // Nothing has been fitted yet. The residual is nought and that is the honest value for
            // it: the residual measures how far the points sit from the fitted line, there is no
            // line, and the intersection this round produced is the whole of what is known about
            // the offset and is carried whole. The rate is a different matter. Nought was the
            // value here until 2026-09-18, with the floor carrying the uncertainty, and the floor
            // bounds how wrong a fitted rate was rather than how wrong an unfitted one can be, so
            // a machine drifting forty parts per million walked out of a signed interval nine
            // seconds after its first round. What is carried instead is in `before_a_fit`.
            None => (
                combined.offset,
                0,
                RateKnowledge::before_a_fit(&self.policy),
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
            newest_exchange_sent,
            intersection: selection.region,
            offset,
            offset_stderr,
            rate,
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
        self.leap_watch.is_some_and(|w| now.apart(w.at) <= w.window)
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

        // Measured from the newest exchange behind the interval, at the moment it went out, and
        // never from the selection round that used it. The round is when the arithmetic ran; the
        // exchange is when the model last learned anything.
        //
        // The span between the two is paid for twice, once inside the intersection where every
        // source interval was aged over the local counter, and once here. That is a widening and it
        // is the correct direction, and paying it twice over a span the model heard nothing during
        // is cheaper than the alternative, which is a poller keeping a dead window alive.
        //
        // The first of the two was the frequency floor alone until 2026-09-18, which is a smaller
        // figure than this one and was the wrong quantity besides: the floor bounds a measurement
        // and a raw counter is not one. `CounterAgeing` is what it is now, and the two are the same
        // knowledge read over different spans. What is still paid only here is the correction: a
        // rate the model will stand behind is applied once, from this instant, and never inside the
        // intersection, where a second reference instant would make it a bias rather than a
        // widening.
        //
        // A reading before the exchange went out is a reading the counter went backwards to, and
        // the model is extrapolating backwards over that distance: the allowances below widen by
        // it and the drift correction runs the other way over it.
        let (elapsed, direction) = holdover_at(now, sync);

        // The whole of the allowance for the oscillator is one function, so the invariant it
        // carries can be asserted on the arithmetic with no world in the test. Its documentation
        // says what the terms are and what the allowance assumes.
        let oscillator_holdover = oscillator_holdover(&self.policy, &sync.rate, elapsed);
        let model_residual = scaled(sync.offset_stderr, self.policy.coverage_factor);
        let scheduling = self.scheduling_allowance;
        let safety_margin = self.policy.safety_margin;
        let widen = oscillator_holdover
            .saturating_add(model_residual)
            .saturating_add(scheduling)
            .saturating_add(safety_margin);

        let drift = signed_ppm_over(sync.rate.frequency_ppm.unwrap_or(0.0), direction);
        let (lo, hi, width) = place(
            &sync.intersection,
            drift,
            widen,
            self.policy.max_bound_width,
        )
        .map_err(Refusal::new)?;
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
            frequency_ppm: sync.rate.frequency_ppm,
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
        if now < self.origin.mono {
            return Validity::CounterBeforeStart {
                by: self.origin.mono.since(now),
            };
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
        let (elapsed, _) = holdover_at(now, sync);
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
    /// extrapolation with a longer arm. It was extrapolation with a *smaller allowance* too until
    /// 2026-09-18, because a sample aged at the frequency floor while a holdover aged at everything
    /// the model knew about the rate; both now age at the same knowledge, through
    /// [`CounterAgeing`]. One ceiling covers both, so there is one number rather than two that
    /// could disagree.
    fn candidates_at(&self, now: MonotonicNanos) -> Vec<Candidate> {
        let ageing = self.counter_ageing();
        let source_floor = self.policy.source_interval_floor;
        let oldest = self.policy.max_holdover;
        self.windows
            .values()
            .filter_map(|w| {
                let best = w.best_within(now, oldest, &ageing, source_floor)?;
                Some(Candidate {
                    id: w.id().clone(),
                    operator: best.operator.clone(),
                    kind: best.kind,
                    sent_at: best.sent_at,
                    taken_at: best.taken_at,
                    interval: best.interval_at(now, &ageing, source_floor),
                    own_half: best.own_half(source_floor),
                    network_half: best.split_direction_residual(),
                    timescale: best.timescale,
                    smear: best.smear,
                    leap: best.leap,
                })
            })
            .collect()
    }

    /// What the model knows about its own counter at this moment, for ageing a source's interval
    /// over it.
    ///
    /// The rate from the last synchronisation, because that is the only measurement there is when a
    /// round is being selected; the round in progress has not been fitted yet. Before there has been
    /// one, nothing has measured this counter and the whole band is carried.
    fn counter_ageing(&self) -> CounterAgeing {
        match &self.sync {
            Some(sync) => CounterAgeing::new(&self.policy, &sync.rate),
            None => CounterAgeing::before_a_fit(&self.policy),
        }
    }

    fn push_history(&mut self, point: regression::Point) {
        self.history.push_back(point);
        while self.history.len() > self.policy.history_capacity {
            self.history.pop_front();
        }
        // The window drops what is older than it and never what the fit needs. It kept two points
        // until 2026-09-17, one short of a fit, so a window shorter than a couple of polls, or a gap
        // in the sources longer than the window, emptied the regression and took the residual out
        // of the width. The capacity above is held to the same minimum by `Policy::fault`.
        let newest = point.at;
        let window = self.policy.regression_window;
        let keep = self.policy.regression_min_points;
        while let Some(front) = self.history.front() {
            if newest.apart(front.at) > window && self.history.len() > keep {
                self.history.pop_front();
            } else {
                break;
            }
        }
    }
}

/// How far the model is extrapolating at `now`, and which way.
///
/// The first figure is the distance the allowances grow over and is never negative. The second is
/// the signed distance a fitted rate is propagated over.
///
/// Both are measured from the moment the newest exchange went out, and not from the moment its
/// reply came home, which is where they were measured from until the evening of 2026-09-17. Two
/// reasons, and each was a bound with the truth outside it. The counter mark on a reply is the
/// client's to write, and one written an hour ahead of its request made every reading inside that
/// hour a reading with no holdover in it. And a reading the counter went backwards to, which is a
/// reading before the exchange, read as no holdover either, because the distance saturated at
/// nought. Measured from the request, a reading after the reply pays one round trip more of
/// allowance than before, which is microseconds on an ordinary path and is the conservative
/// direction; a reading inside the exchange pays for the time since the request left; and a
/// reading before it pays for the distance back, with the fitted rate run the other way over it.
fn holdover_at(now: MonotonicNanos, sync: &SyncState) -> (Nanos, Nanos) {
    let direction = now.signed_since(sync.newest_exchange_sent);
    (direction.abs(), direction)
}

/// The ends of the interval and its width, or the refusal where the width is past the ceiling.
///
/// The width is the intersection plus the widening on each side, so it is known before either end is
/// placed, and it is measured first. Placing the ends first and measuring afterwards was the order
/// until 2026-09-17, and with a term carried at `WIDEST` it overflowed on the way to being refused.
/// The width is summed saturating so that the comparison is reached whatever the terms; the ends are
/// placed only once the width is under a ceiling `Policy::fault` holds to `WIDEST`, so they cannot
/// overflow. The unit test below drives this with a widening the validator would never allow, which
/// is how the order is pinned rather than assumed.
fn place(
    intersection: &OffsetInterval,
    drift: Nanos,
    widen: Nanos,
    ceiling: Nanos,
) -> Result<(Nanos, Nanos, Nanos), Validity> {
    let width = intersection.width().saturating_add(widen.saturating_mul(2));
    if width > ceiling {
        return Err(Validity::BoundTooWide { width, ceiling });
    }
    let lo = intersection.lo + drift - widen;
    let hi = intersection.hi + drift + widen;
    Ok((lo, hi, width))
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

/// What the width knows about this machine's oscillator, as `read` composes it.
///
/// Three numbers, and the allowance for the oscillator is built from all three by
/// [`oscillator_holdover`]. The first is the rate the model corrects a reading by, or `None` where
/// it has none it will stand behind. The second is how wrong that rate was at the moment it was
/// fitted. The third is the magnitude the model is not correcting for at all, which is what makes
/// refusing a fit, or not having one, a widening rather than a quiet tightening.
///
/// The only two ways to build one inside the model are [`RateKnowledge::before_a_fit`] and
/// [`RateKnowledge::from_fit`], and every field is public so the arithmetic can be asserted on
/// values a test writes down rather than only on values a world produced.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RateKnowledge {
    /// The frequency error the model will stand behind, in parts per million, positive meaning the
    /// local clock is slow. `None` where nothing has been fitted or the fit could not be supported.
    pub frequency_ppm: Option<f64>,
    /// The standard error of that frequency, in parts per million. The floor before a fit, so the
    /// measurement term is never below what the hardware can support.
    pub frequency_stderr_ppm: f64,
    /// The magnitude of rate the model is not correcting for, in parts per million.
    ///
    /// Nought whenever a rate is claimed. Wherever no rate is claimed it is at least half the band
    /// the policy states, because that is the largest magnitude a part may honestly show and the
    /// correction that would have removed it is not being applied. Before a fit it is exactly
    /// half the band; for a fit the model refused it is the larger of half the band and the
    /// magnitude the fit found, since a fit outside the band is the machine saying the band was
    /// wrong about it and the larger figure is the one to carry.
    pub unclaimed_frequency_ppm: f64,
    /// What reading the fitted rate back against the band said. See [`BandReading`].
    pub band: BandReading,
}

/// What reading this machine's fitted rate back against the band the policy assumes about it said.
///
/// Every allowance the model derives from the band is sound only while the machine's true rate
/// magnitude stays inside half of it, and until 2026-09-18 nothing in the tree read the fitted rate
/// back against that band to find out. The arithmetic did use the answer, in
/// [`RateKnowledge::from_fit`], which stops claiming a rate outside the band and carries the
/// magnitude it found instead. What it never did was say so, so an operator could not tell a machine
/// the assumption holds for from one it does not.
///
/// Four answers and not two, and the reason is the one this tree keeps relearning: a guard
/// that answers "no finding" where it means "cannot tell" permits. Before a fit the model has not
/// read this machine's rate against anything, which is not the same as having read it and found it
/// inside, and a boolean would have said they were.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BandReading {
    /// Nothing has been fitted, so the rate has not been read against the band at all.
    NotRead,
    /// The fit found a rate inside the band.
    Inside {
        /// The magnitude the fit found, in parts per million, inside half the band.
        magnitude_ppm: f64,
    },
    /// The fit found a rate past half the band, by this many parts per million.
    ///
    /// The machine is saying the band is wrong about it. The model stops claiming the rate and
    /// widens by the magnitude it found rather than by the one it assumed, so the bound still holds
    /// what it measured; what it cannot do is promise the assumption on the next machine.
    Outside {
        /// How far past half the band the fit found this machine, in parts per million.
        by_ppm: f64,
    },
    /// The fitted rate, or the band, is not a number a rate can be read against.
    Unreadable,
}

impl RateKnowledge {
    /// What the model knows before anything has been fitted: nothing measured, and a rate that
    /// could be anywhere in the band.
    ///
    /// The floor stands in for the standard error, as it always did. What changed on 2026-09-18 is
    /// the unclaimed magnitude, which was nought. `Policy::frequency_floor_ppm` bounds how wrong
    /// the model's own measurement of the rate is, and before a fit there is no measurement for it
    /// to bound, so it was being asked to bound the raw counter instead. The raw counter can be
    /// wrong by the whole band a part is specified across, and `crates/agent/src/crossing.rs`
    /// already carries that rule for a caller's counter; this is the same rule at the model's own
    /// first read.
    ///
    /// A band that is not a finite number above nought is a band nobody can read, and the
    /// magnitude is then infinite, which [`ppm_over`] carries as [`WIDEST`] and the ceiling
    /// refuses. `Policy::fault` refuses such a policy first; this is the second net.
    #[must_use]
    pub fn before_a_fit(policy: &Policy) -> Self {
        Self {
            frequency_ppm: None,
            frequency_stderr_ppm: policy.frequency_floor_ppm,
            unclaimed_frequency_ppm: half_band(policy),
            band: BandReading::NotRead,
        }
    }

    /// What the model takes from a fit: the rate where it will stand behind it, and the magnitude
    /// it is not correcting for where it will not.
    #[must_use]
    pub fn from_fit(fit: &Fit, policy: &Policy) -> Self {
        let band = read_against_the_band(fit, policy);
        if supports_a_rate(fit, policy) {
            Self {
                frequency_ppm: Some(fit.frequency_ppm),
                frequency_stderr_ppm: fit.frequency_stderr_ppm,
                unclaimed_frequency_ppm: 0.0,
                band,
            }
        } else {
            Self {
                frequency_ppm: None,
                frequency_stderr_ppm: fit.frequency_stderr_ppm,
                unclaimed_frequency_ppm: readable(fit.frequency_ppm.abs()).max(half_band(policy)),
                band,
            }
        }
    }
}

/// Read a fitted rate back against the band the policy assumes about this machine.
///
/// The reading is reported and never gates: a fit outside the band already stops being claimed, in
/// `supports_a_rate`, and the magnitude it found is carried into the width instead. Refusing on top
/// of that was considered on 2026-09-18 and not built, because a fitted rate outside the band is
/// more often a short baseline than a bad crystal, and an agent that refuses on the first round of
/// a cold start teaches its operator to widen the band, which removes the only thing the reading is
/// for. What the reading buys is that the assumption is visible rather than assumed.
fn read_against_the_band(fit: &Fit, policy: &Policy) -> BandReading {
    let half = half_band(policy);
    if !half.is_finite() || !fit.frequency_ppm.is_finite() {
        return BandReading::Unreadable;
    }
    let magnitude_ppm = fit.frequency_ppm.abs();
    if magnitude_ppm > half {
        BandReading::Outside {
            by_ppm: magnitude_ppm - half,
        }
    } else {
        BandReading::Inside { magnitude_ppm }
    }
}

/// What the model knows about this machine's counter when it ages a source's interval over it.
///
/// A source's answer is an offset at the instant that exchange came home. Using it at any later
/// instant means carrying it over the local counter, and the counter has a rate of its own, so the
/// interval both moves and widens on the way. Until 2026-09-18 it only widened, and it widened at
/// `Policy::frequency_floor_ppm`, fifteen parts per million at the default. That floor bounds how
/// wrong a *fitted* rate was at the moment it was fitted. It has never bounded a raw counter, and
/// the band the same policy states for that counter is a hundred, so the largest magnitude a part
/// may honestly show is fifty. A sample of age `a` on a machine running at `r` is displaced by
/// `r x a` and was widened by `floor x a`, so it stopped holding the truth once `(r - floor) x a`
/// passed the source's own stated half width, and where such samples were the majority clique
/// Marzullo took their intersection and the signed bound missed the truth on a machine drifting
/// legally inside the band. 412 of 17280 cells of
/// `crates/clock/tests/a_round_spread_out_in_time.rs` did exactly that.
///
/// **This widens and it never corrects, and that is a choice with a reason.** The model does correct
/// for a rate it will stand behind, once, in `read`, measured from the moment the newest exchange
/// went out. Correcting here as well would be a second correction from a second reference instant,
/// the counter value the selection round happened to run at, and the two reference instants come
/// apart whenever a poller synchronises later than the round it is synchronising over. A widening
/// applied twice is conservative and the existing comment in `read` says so; a correction applied
/// twice is a bias, and a bias in the direction the machine is already drifting is the fault this
/// is fixing rather than a fix for it. So everything the counter's rate might be is paid for here as
/// width, and the rate itself is claimed in one place only.
///
/// The terms, in parts per million, added rather than maximised because they are independent:
///
/// 1. How wrong the model's own measurement of the rate is, floored at what the hardware supports.
/// 2. The magnitude of the rate the model has fitted and is not correcting for over this span,
///    which is nought before a fit.
/// 3. The magnitude it is not correcting for because it has no fit it will stand behind, which is
///    at least half the band and is nought whenever a rate is claimed. Two and three are never both
///    above nought, and they are separate fields because they are different facts.
/// 4. How far the rate may have moved over the age, which is `rate_movement_ppm`.
///
/// **And the band caps the sum, because the band is what the sum rests on.** The first assumption
/// of this arithmetic is that the counter's true rate magnitude never passes half the band, at any
/// instant. Under that assumption half the band over the age is a widening that holds whatever a
/// fit says, and a fit can narrow it and never needs to widen it. So a fit that puts the machine
/// inside the band carries the smaller of the sum and half the band; a fit that puts the machine
/// outside the band has broken the assumption and carries the sum; and a fit whose error bar is
/// wider than the band, which is the fit the settling rounds produce, has measured nothing about
/// this counter and carries half the band, which is what `before_a_fit` carries.
///
/// **The last two overlap and the third wins, which is a decision rather than the order of two
/// tests.** A fit can be both outside the band and too blunt to tell one rate in the band from
/// another, and every agent start produces one: the settling rounds are a quarter of a second
/// apart, so the fitted rate is the sources' own scatter divided by almost nothing and so is its
/// error bar. Such a fit has not established that this machine is outside anything. Its magnitude
/// is not a measurement of the counter, and neither is the reading of the band taken from it, so
/// nothing it says is carried and the widening is what it was before any fit at all. The test for
/// it comes first in `ppm` for that reason, and the honesty surfaces say the same thing in the
/// same words: a fit widens by the magnitude it measured where it is sharp enough to say so, and
/// by half the band where it is not. Until 2026-09-19 those surfaces promised the magnitude and
/// said nothing about the condition, which made them false on the day the condition went in.
///
/// What this precedence costs is a real machine outside the band whose fit is blunt for some
/// reason other than a short baseline: it is widened by half the band while its own fit says
/// more. That case is inside what the page already says, which is that on a machine outside the
/// band nothing on it is a promise the arithmetic can keep.
///
/// The cap went in on the evening of 2026-09-18, beside the change to how a window picks the
/// sample a round is built from. The defect of that afternoon is what the two of them answer:
/// from 15:09 the sum was carried whole, so the error bar of a fit on a sub-second baseline,
/// which is the sources' scatter divided by almost nothing, widened every source interval on the
/// next round. Wider intervals made a wider intersection, the wider intersection made a
/// regression point with almost no weight against the settling points, the fit stayed on the
/// sub-second baseline, and the next round was wider again. On an ordinary desktop against the
/// nine published servers the agent signed once at 3 s of uptime and then refused every reading,
/// at sixteen to twenty-two seconds of width. The rig is
/// `crates/clock/tests/a_fresh_agent_at_the_shipped_cadence.rs`.
///
/// **What closes that loop is `SourceWindow::best_within` and not this cap, measured 2026-09-19
/// and written here because the record said otherwise.** A binary with the cap removed and
/// nothing else changed was probed for twenty minutes against a control started eight seconds
/// later, on one desktop against the same nine servers: 79 readings each, 74 signed, 5 refused,
/// the last refusal at 94 s on both, and nought refused of 67 from three minutes on both. They
/// are indistinguishable. What this cap does is the other job, which is keeping the widening
/// inside the band the rest of the arithmetic assumes, and it is not what brings a fresh agent
/// back.
///
/// The invariant, and it rests on the same first assumption as `oscillator_holdover`: on a machine
/// whose true rate magnitude never passes `frequency_span_ppm / 2`, a sample that held the truth
/// when it was taken still holds it after ageing. A machine outside the band is [`BandReading`], is
/// stated on the honesty surfaces, and is not something this arithmetic can promise.
///
/// A term that cannot be read is infinite and never nought; see `readable`. `ppm_over` carries an
/// infinite rate as [`WIDEST`] and the ceiling refuses it, which is the same refusal said plainly.
/// The cap is applied only once every term has been read, so an unreadable input is never capped
/// down to the band.
#[derive(Clone, Copy, Debug)]
pub struct CounterAgeing {
    policy: Policy,
    rate: RateKnowledge,
}

impl CounterAgeing {
    /// What the model knows from a rate it has.
    #[must_use]
    pub fn new(policy: &Policy, rate: &RateKnowledge) -> Self {
        Self {
            policy: *policy,
            rate: *rate,
        }
    }

    /// What it knows before anything has been fitted: nothing measured, and a rate that could be
    /// anywhere in the band.
    #[must_use]
    pub fn before_a_fit(policy: &Policy) -> Self {
        Self::new(policy, &RateKnowledge::before_a_fit(policy))
    }

    /// The rate a sample's interval widens at over an age of `age`, in parts per million.
    #[must_use]
    pub fn ppm(&self, age: Nanos) -> f64 {
        let measured = readable(self.rate.frequency_stderr_ppm * self.policy.coverage_factor);
        let floor = readable(self.policy.frequency_floor_ppm);
        // A rate the model claims is a rate it is still not correcting for over this span, so its
        // whole magnitude is carried.
        //
        // The `readable` here is the second net and not the first one, and saying which is the
        // point. A magnitude cannot be negative, so the only input it catches is one that is not a
        // number, and `ppm_over` refuses that on its own at the end. Reverting it on 2026-09-18
        // turned no test red, which was watched rather than assumed. It stays because every rate
        // entering an allowance in this file goes through one door, and a reader checking that they
        // all do should not find one that does not. The doors that are load-bearing are the `max`
        // below, where `f64::max` answers with its other operand on a value that is not a number,
        // and the `readable` on the unclaimed magnitude, which can be negative.
        let claimed = self
            .rate
            .frequency_ppm
            .map_or(0.0, |ppm| readable(ppm.abs()));
        let unclaimed = readable(self.rate.unclaimed_frequency_ppm);
        let half = half_band(&self.policy);

        let everything =
            measured.max(floor) + claimed + unclaimed + rate_movement_ppm(&self.policy, age);
        // Read every term before capping anything: a term that could not be read is infinite, and
        // capping it to the band would be the permitting answer on the input that says the
        // widening cannot be known.
        if !everything.is_finite() || !half.is_finite() {
            return f64::INFINITY;
        }
        // A fit that cannot separate one rate in the band from another has measured nothing about
        // this counter. Its error bar is not knowledge and is not carried.
        if !separates_the_band(measured, &self.policy) {
            return half.max(floor);
        }
        // Inside the band the assumption holds and caps the sum. A magnitude past half the band,
        // claimed or unclaimed, is the machine saying the band is wrong about it, and the sum is
        // carried whole.
        //
        // **The cap never takes the answer below the policy's own floor**, and the `max` is why.
        // `Policy::fault` refuses a floor past half the band from 2026-09-19, so on a policy the
        // validator has passed these two lines change nothing: `everything` is already at least the
        // floor and the cap is at least the floor too. It is here because `Policy` is a public
        // struct with public fields in a published library crate, so a caller reaches this
        // arithmetic without the validator having run, and a guard that only holds where another
        // guard ran is the class this product keeps catching. Measured on a floor of 1000.0 beside
        // a band of 100.0, which answered 50.000 ppm at every age.
        if claimed + unclaimed <= half {
            everything.min(half).max(floor)
        } else {
            everything
        }
    }

    /// How much wider a sample's interval is for having aged `age` over the counter.
    ///
    /// Nought at an age of nought or less, which is what `ppm_over` says of every allowance: a
    /// sample stamped after the instant it is being used at ages by nothing here, and what that can
    /// hide is its own round trip's worth, which the holdover term pays for from the moment the
    /// exchange went out.
    #[must_use]
    pub fn dispersion(&self, age: Nanos) -> Nanos {
        ppm_over(self.ppm(age), age)
    }
}

/// Half the band the policy states, which is the largest magnitude a part may honestly show, or an
/// infinite magnitude where the band cannot be read.
fn half_band(policy: &Policy) -> f64 {
    let band = policy.frequency_span_ppm;
    if band.is_finite() && band > 0.0 {
        band / 2.0
    } else {
        f64::INFINITY
    }
}

/// A rate as an allowance may read it: itself where it is a finite number no less than nought, and
/// infinite otherwise.
///
/// Every rate that enters the allowance goes through this, because the alternative is what stood
/// until 2026-09-18: `f64::max` answers with its other operand when one is not a number, so a
/// standard error that was not a number came out as the floor, which is the permitting value on
/// exactly the input that says the measurement cannot be known. An infinite rate becomes [`WIDEST`]
/// in [`ppm_over`] and is refused by the ceiling, which is the same refusal said plainly.
fn readable(ppm: f64) -> f64 {
    if ppm.is_finite() && ppm >= 0.0 {
        ppm
    } else {
        f64::INFINITY
    }
}

/// The allowance for the oscillator over `elapsed`, in nanoseconds: what goes in the breakdown
/// under that name.
///
/// Three quantities in parts per million, added rather than maximised because they are independent
/// and all three are present, over the elapsed time, plus the fixed holdover allowance whenever the
/// model is extrapolating at all.
///
/// The first is how wrong the fitted rate was at the moment it was fitted, floored at what the
/// hardware can support. The second is the magnitude the model is not correcting for. The third is
/// how far the rate may have moved since, which the correction cannot know about and the fit's own
/// standard error says nothing about. Holding the first and third as one number was an earlier
/// fault: fifteen parts per million was doing both jobs, and fifteen is NTP's `PHI`, which bounds
/// the total error of an extrapolation that has not been corrected. Correcting first and then
/// applying the same figure to what is left applies it to a different quantity, and an ordinary
/// forty parts per million temperature change then put true UTC 79.669 ms outside a receipt that
/// signed cleanly.
///
/// The invariant, and the three assumptions it rests on. Wherever `rate.frequency_ppm` is `None`,
/// this allowance is at least `frequency_span_ppm / 2` parts per million over `elapsed`, for every
/// policy `Policy::fault` accepts and every elapsed time. That holds a truth that started inside
/// the sources' intersection under three assumptions, and a proof without them is not a proof:
///
/// 1. The machine's true rate magnitude never passes `frequency_span_ppm / 2`. A choice about
///    hardware, stated on that field, and never measured on this machine.
/// 2. The rate moves by at most `frequency_slew_ppm_per_second` per second. The same kind of
///    choice, stated on that field.
/// 3. The sources' intersection holds the truth at the moment the newest exchange went out, which
///    is the moment `elapsed` is measured from.
///
/// The first is what the pre-fit branch rests on entirely, since nothing there corrects for any
/// rate and the whole of it has to be covered. A machine outside the band gets a width this
/// arithmetic cannot vouch for, and nothing here can tell. The test that asserts the invariant on
/// the arithmetic alone is `crates/clock/tests/the_band_before_a_fit.rs`.
///
/// A rate that cannot be read, in any of the three or in the fields they are built from, is an
/// infinite allowance and never nought; see `readable`. The term is carried at no more than
/// [`WIDEST`], which is what that constant says of every term, so a fixed allowance on top of an
/// infinite one is still one term the ceiling refuses rather than a sum past what a term may be.
#[must_use]
pub fn oscillator_holdover(policy: &Policy, rate: &RateKnowledge, elapsed: Nanos) -> Nanos {
    let measured = readable(rate.frequency_stderr_ppm * policy.coverage_factor);
    let floor = readable(policy.frequency_floor_ppm);
    let unclaimed = readable(rate.unclaimed_frequency_ppm);
    let ppm = measured.max(floor) + unclaimed + rate_movement_ppm(policy, elapsed);
    let fixed = if elapsed > 0 {
        policy.holdover_allowance
    } else {
        0
    };
    ppm_over(ppm, elapsed).saturating_add(fixed).min(WIDEST)
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
    let inside_the_band = fit.frequency_ppm.abs() <= band / 2.0;
    separates_the_band(fit.frequency_stderr_ppm * policy.coverage_factor, policy) && inside_the_band
}

/// Whether a measurement of the rate, its standard error already scaled by the coverage factor,
/// can tell one rate in the band from another.
///
/// One definition, read by `supports_a_rate` when a fit is taken in and by `CounterAgeing::ppm`
/// when the same knowledge ages a source interval, so the two cannot disagree about which fits are
/// measurements. A measurement that is not a finite number, or a band that is not one above nought,
/// separates nothing.
fn separates_the_band(measured_ppm: f64, policy: &Policy) -> bool {
    let band = policy.frequency_span_ppm;
    band.is_finite() && band > 0.0 && measured_ppm.is_finite() && measured_ppm <= band
}

/// How far the oscillator's rate may have moved in `elapsed`, in parts per million.
///
/// A rate does not jump and it does not wander for ever, so the allowance is the smaller of two
/// things: a slew over the time that has passed, and the whole band the part is specified across.
/// Over a poll interval that is a few parts per million and over an outage it is the whole band.
///
/// Both figures are choices and both live in `Policy` with the reasoning attached. A slew or a band
/// that is not a finite number, or a slew below nought, or a band at or below it, is an infinite
/// allowance. This said the opposite until 2026-09-17, on the reasoning that an infinite widening is
/// a refusal dressed as an answer, and what it gave instead was no allowance at all, which narrows
/// the bound; and until 2026-09-18 a negative slew or a band of nought still came out as no
/// movement. An infinite allowance becomes [`WIDEST`] in `ppm_over`, and a bound holding that is
/// refused by the ceiling, which is the same refusal said plainly.
fn rate_movement_ppm(policy: &Policy, elapsed: Nanos) -> f64 {
    if elapsed <= 0 {
        return 0.0;
    }
    let slew = readable(policy.frequency_slew_ppm_per_second);
    let band = policy.frequency_span_ppm;
    if !slew.is_finite() || !band.is_finite() || band <= 0.0 {
        return f64::INFINITY;
    }
    let seconds = elapsed as f64 / NANOS_PER_SEC as f64;
    (slew * seconds).min(band)
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
    fn a_width_past_the_ceiling_is_refused_before_either_end_is_placed() {
        // A widening the validator would never let through, one short of the integer's ceiling.
        // Measured first it is refused as too wide; placed first it overflows the low end.
        let intersection = OffsetInterval::new(-10 * NANOS_PER_MILLI, 10 * NANOS_PER_MILLI);
        let ceiling = Policy::default().max_bound_width;
        match place(&intersection, 0, i128::MAX - 1, ceiling) {
            Err(Validity::BoundTooWide { width, ceiling: c }) => {
                assert_eq!(width, i128::MAX);
                assert_eq!(c, ceiling);
            }
            other => panic!("expected a refusal as too wide, got {other:?}"),
        }
        // And an honest widening is placed on both sides of the intersection.
        let (lo, hi, width) = place(&intersection, 5, 1_000, ceiling).expect("inside the ceiling");
        assert_eq!(
            (lo, hi, width),
            (
                -10 * NANOS_PER_MILLI + 5 - 1_000,
                10 * NANOS_PER_MILLI + 5 + 1_000,
                20 * NANOS_PER_MILLI + 2_000
            )
        );
    }

    #[test]
    fn a_refused_fit_carries_no_less_than_half_the_band() {
        // Refused for an error bar wider than the band, with a small magnitude. The two reasons a
        // fit is refused for each carry more than half the band on their own, so this floor is not
        // what holds the invariant today; it is what holds it when a third reason is added.
        let fit = Fit {
            offset: 0,
            offset_stderr: 0,
            frequency_ppm: 3.0,
            frequency_stderr_ppm: 200.0,
            points: 3,
        };
        let rate = RateKnowledge::from_fit(&fit, &Policy::default());
        assert_eq!(rate.frequency_ppm, None);
        assert!(
            rate.unclaimed_frequency_ppm >= 50.0,
            "{}",
            rate.unclaimed_frequency_ppm
        );
        // And one outside the band carries its own magnitude, which is the larger.
        let outside = Fit {
            frequency_ppm: -80.0,
            frequency_stderr_ppm: 1.0,
            ..fit
        };
        let rate = RateKnowledge::from_fit(&outside, &Policy::default());
        assert_eq!(rate.frequency_ppm, None);
        assert!(
            rate.unclaimed_frequency_ppm >= 80.0,
            "{}",
            rate.unclaimed_frequency_ppm
        );
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
