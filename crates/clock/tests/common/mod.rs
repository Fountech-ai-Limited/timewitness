//! A simulated network with a known true offset.
//!
//! The point of this harness is that the truth is a number the test wrote down. Every assertion
//! about the bound is then a question about whether the model's interval holds that number, rather
//! than a question about whether the model agrees with itself.
//!
//! It can do the one thing that matters and that a real network will not do on demand: split a
//! round trip unevenly between the way out and the way back, by a controlled amount, including the
//! worst case where the whole of the delay sits on one leg. Path asymmetry is not a software fault
//! and no algorithm can see it from timestamps alone, so the only way to test the model against it
//! is to build a path where the asymmetry is known.

#![allow(dead_code)]

use timewitness_clock::Policy;
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
    UnixNanos,
};
use timewitness_sources::Exchange;

/// One source, and the path to it.
#[derive(Clone, Debug)]
pub struct Path {
    /// What the source is called.
    pub id: &'static str,
    /// Who runs it. Its own name unless a test says otherwise, so a round of distinct sources is a
    /// round of distinct operators and a test about intervals is not also a test about ownership.
    pub operator: &'static str,
    /// Whether the party running it is the deployment under test rather than a stranger.
    pub first_party: bool,
    /// How long a request takes to reach it, in nanoseconds.
    pub out: Nanos,
    /// How long the reply takes to come back.
    pub back: Nanos,
    /// How long the source spends thinking about the request. This should never affect anything.
    pub think: Nanos,
    /// What the source says about its own uncertainty, in nanoseconds.
    pub stated: Nanos,
    /// How wrong the source's own clock is, in nanoseconds. Zero for an honest source.
    pub server_error: Nanos,
    /// What the source speaks.
    pub kind: SourceKind,
    /// What it does with a leap second.
    pub smear: SmearPolicy,
    /// What it says about an upcoming leap second.
    pub leap: LeapIndicator,
    /// The timescale it answers on.
    pub timescale: Timescale,
}

impl Path {
    /// An honest source on a symmetric path.
    pub fn honest(id: &'static str, round_trip_ms: i128, stated_ms: i128) -> Self {
        let rtt = round_trip_ms * NANOS_PER_MILLI;
        Self {
            id,
            operator: id,
            first_party: false,
            out: rtt / 2,
            back: rtt - rtt / 2,
            think: 0,
            stated: stated_ms * NANOS_PER_MILLI,
            server_error: 0,
            kind: SourceKind::Ntp,
            smear: SmearPolicy::None,
            leap: LeapIndicator::None,
            timescale: Timescale::Utc,
        }
    }

    /// The same path with the whole round trip pushed onto one leg.
    ///
    /// `fraction` of one means everything on the way out, zero means everything on the way back.
    pub fn with_split(mut self, fraction: f64) -> Self {
        let rtt = self.out + self.back;
        let out = ((rtt as f64) * fraction.clamp(0.0, 1.0)) as Nanos;
        self.out = out;
        self.back = rtt - out;
        self
    }

    /// The same source, run by somebody named rather than by itself.
    ///
    /// Two paths sharing this are two names at one company, which is one chance to be wrong.
    pub fn operated_by(mut self, operator: &'static str) -> Self {
        self.operator = operator;
        self
    }

    /// The same source, run by the deployment issuing the receipt rather than by a stranger.
    ///
    /// It still answers, it is still selected, and its interval is still in the arithmetic. What it
    /// stops being is a chance to be wrong separately from the agent, so it drops out of the
    /// operator counts the majority and the floor are made of.
    pub fn operated_by_us(mut self, operator: &'static str) -> Self {
        self.operator = operator;
        self.first_party = true;
        self
    }

    /// The same source, lying about the time by `error`.
    pub fn lying_by(mut self, error: Nanos) -> Self {
        self.server_error = error;
        self
    }

    /// The same source, with a smear policy of its own.
    pub fn smearing(mut self, smear: SmearPolicy) -> Self {
        self.smear = smear;
        self
    }

    /// The same source, announcing a leap second.
    pub fn announcing_leap(mut self) -> Self {
        self.leap = LeapIndicator::AddSecond;
        self
    }

    /// The round trip this path produces.
    pub fn round_trip(&self) -> Nanos {
        self.out + self.back
    }

    /// The half width the model should give this source before ageing.
    pub fn expected_half_width(&self) -> Nanos {
        self.round_trip() / 2 + self.stated
    }
}

/// What else on the machine is moving the system clock.
///
/// This is the distinction the harness existed without for its first day, and the reason a whole
/// suite could pass over a bound that did not hold the truth. A machine where nothing else touches
/// the system clock and a machine where another time service holds it at UTC are different
/// machines, and the second one is the ordinary case: a stock Windows box, a stock Linux under
/// chrony or systemd-timesyncd, and every cloud instance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SystemClock {
    /// Nothing else touches it, so it advances with the local oscillator and nothing else.
    FreeRunning,
    /// Another time service holds it at UTC, to within `residual` nanoseconds.
    HeldAtUtc { residual: Nanos },
}

/// A change in the oscillator's rate part way through the run.
///
/// The harness ran on a single `drift_ppm` for its first day, and a single constant cannot express
/// the one condition that breaks an extrapolating model: a rate that is one value while the model
/// is measuring it and another value afterwards. A crystal does that every time the machine warms
/// up, and a virtual machine does it when the host moves it.
#[derive(Clone, Copy, Debug)]
pub struct RateChange {
    /// The counter value at which the rate becomes `ppm`.
    pub at: MonotonicNanos,
    /// The rate from that moment on, in parts per million.
    pub ppm: f64,
}

/// The world the machine is running in.
///
/// The monotonic counter is the reference axis. Three separate quantities hang off it and the
/// harness keeps them apart on purpose.
///
/// `free_running` is the machine's clock left alone: one nanosecond per counter nanosecond, from
/// wherever it started. `utc` is the truth, which advances slightly faster or slower than the
/// counter, and that difference is the machine's frequency error. `system` is what a call to the
/// operating system for the time would actually return, which is the first of those two on a
/// machine running nothing else and the second on a machine where another service is steering.
#[derive(Clone, Copy, Debug)]
pub struct World {
    /// The counter value everything is measured from.
    pub mono0: MonotonicNanos,
    /// What the machine's clock, left alone, said at that moment.
    pub wall0: UnixNanos,
    /// How far from UTC that free-running clock actually was at that moment.
    pub offset0: Nanos,
    /// The machine's true frequency error, positive meaning the local clock runs slow.
    pub drift_ppm: f64,
    /// Who else is moving the system clock.
    pub system_clock: SystemClock,
    /// When, if ever, that frequency error becomes a different number.
    pub rate_change: Option<RateChange>,
}

impl World {
    /// A machine `offset_ms` behind UTC with no drift, running nothing else that touches the clock.
    pub fn still(offset_ms: i128) -> Self {
        Self {
            mono0: MonotonicNanos(1_000_000_000),
            wall0: UnixNanos(1_757_000_000 * NANOS_PER_SEC),
            offset0: offset_ms * NANOS_PER_MILLI,
            drift_ppm: 0.0,
            system_clock: SystemClock::FreeRunning,
            rate_change: None,
        }
    }

    /// The same, with the local oscillator running away at `ppm`.
    pub fn drifting(offset_ms: i128, ppm: f64) -> Self {
        Self {
            drift_ppm: ppm,
            ..Self::still(offset_ms)
        }
    }

    /// A machine drifting at `ppm` whose system clock another time service is holding at UTC.
    ///
    /// The oscillator is genuinely wrong by `ppm` and the operating system is hiding it, which is
    /// the ordinary desktop and the ordinary cloud instance. Anything anchored to a projection over
    /// the counter walks away from UTC at `ppm` while every reading of the system clock stays
    /// right, so the two disagree by more every minute and neither of them looks wrong on its own.
    pub fn disciplined_elsewhere(ppm: f64) -> Self {
        Self {
            drift_ppm: ppm,
            system_clock: SystemClock::HeldAtUtc { residual: 0 },
            ..Self::still(0)
        }
    }

    /// The same, with the other service leaving `residual` nanoseconds of error behind it.
    pub fn with_residual(mut self, residual: Nanos) -> Self {
        self.system_clock = SystemClock::HeldAtUtc { residual };
        self
    }

    /// The same machine, whose oscillator changes rate `after` seconds into the run.
    ///
    /// Everything before that moment runs at `drift_ppm` and everything after it at `ppm`. The
    /// model measures the first rate and extrapolates with it, which is the situation the fixed
    /// allowance in `read()` exists to cover.
    pub fn changing_rate(mut self, after_s: u64, ppm: f64) -> Self {
        self.rate_change = Some(RateChange {
            at: self.mono0.advanced((after_s as Nanos) * NANOS_PER_SEC),
            ppm,
        });
        self
    }

    /// What the machine's clock reads at counter value `m` when nothing is steering it.
    pub fn free_running(&self, m: MonotonicNanos) -> UnixNanos {
        self.wall0 + m.since(self.mono0)
    }

    /// What a call to the operating system for the time returns at counter value `m`.
    pub fn system(&self, m: MonotonicNanos) -> UnixNanos {
        match self.system_clock {
            SystemClock::FreeRunning => self.free_running(m),
            SystemClock::HeldAtUtc { residual } => self.utc(m) + residual,
        }
    }

    /// How far from UTC the free-running clock truly is at counter value `m`.
    ///
    /// The error accumulates at `drift_ppm` up to any rate change and at the new rate afterwards,
    /// so the two segments are integrated separately rather than averaged.
    pub fn true_offset(&self, m: MonotonicNanos) -> Nanos {
        let elapsed = m.since(self.mono0);
        let accumulated = match self.rate_change {
            Some(change) if m.as_nanos() > change.at.as_nanos() => {
                let before = change.at.since(self.mono0);
                let after = m.since(change.at);
                (self.drift_ppm * before as f64) / 1_000_000.0
                    + (change.ppm * after as f64) / 1_000_000.0
            }
            _ => (self.drift_ppm * elapsed as f64) / 1_000_000.0,
        };
        self.offset0 + accumulated as Nanos
    }

    /// True UTC at counter value `m`.
    pub fn utc(&self, m: MonotonicNanos) -> UnixNanos {
        self.free_running(m) + self.true_offset(m)
    }

    /// One exchange with `path`, sent at counter value `send_at`.
    ///
    /// The source reports the two timestamps it took and the machine reports the two counter marks
    /// it took, and that is all. There is no local time here because a source client has no local
    /// time worth reporting: whichever of the machine's clocks it read would be a different clock
    /// from the one the bound is anchored to, and this harness can now tell them apart.
    pub fn exchange(&self, path: &Path, send_at: MonotonicNanos) -> Exchange {
        let arrive = send_at.advanced(path.out);
        let reply = arrive.advanced(path.think);
        let home = reply.advanced(path.back);

        let t2 = self.utc(arrive) + path.server_error;
        let t3 = t2 + path.think;

        let timescale_shift = match path.timescale {
            Timescale::Tai { offset_seconds } => Nanos::from(offset_seconds) * NANOS_PER_SEC,
            Timescale::Utc | Timescale::Unknown => 0,
        };

        Exchange {
            source: SourceId::new(path.id),
            operator: if path.first_party {
                Operator::first_party(path.operator)
            } else {
                Operator::new(path.operator)
            },
            kind: path.kind,
            t2: t2 + timescale_shift,
            t3: t3 + timescale_shift,
            mono_t1: send_at,
            mono_t4: home,
            root_delay: 0,
            root_dispersion: path.stated,
            timescale: path.timescale,
            smear: path.smear,
            leap: path.leap,
            attestation: None,
        }
    }
}

/// A source that states no uncertainty at all and places its answer where it likes.
///
/// Two of the four timestamps in an exchange belong to the source, and both of these are things it
/// chooses rather than things the machine can check.
///
/// It claims to have spent the whole of the real round trip thinking about the request, so the
/// round trip the model computes is zero and the split-direction residual with it. It states a root
/// delay and a root dispersion of zero, so it contributes nothing on that side either. What is left
/// is a single point, sitting at `offset` from the machine's own clock.
///
/// This is a real hostile server writing real fields, not a `Sample` built by hand. Everything here
/// goes on the wire in an ordinary NTP reply.
pub fn claiming_no_uncertainty(
    world: &World,
    id: &'static str,
    offset: Nanos,
    send_at: MonotonicNanos,
    round_trip: Nanos,
) -> Exchange {
    let home = send_at.advanced(round_trip);
    let t1 = world.free_running(send_at);
    let t4 = world.free_running(home);
    let t2 = t1 + offset;

    Exchange {
        source: SourceId::new(id),
        operator: Operator::new(id),
        kind: SourceKind::Ntp,
        t2,
        // The whole of the measured elapsed time, claimed as the source's own processing.
        t3: t2 + (t4 - t1),
        mono_t1: send_at,
        mono_t4: home,
        root_delay: 0,
        root_dispersion: 0,
        timescale: Timescale::Utc,
        smear: SmearPolicy::None,
        leap: LeapIndicator::None,
        attestation: None,
    }
}

/// The same source, claiming more processing time than the exchange took altogether.
///
/// The round trip computes negative, which is not a coarse clock rounding the wrong way: it is a
/// reply whose own two timestamps cannot both be true.
pub fn stating_an_impossible_reply(
    world: &World,
    id: &'static str,
    offset: Nanos,
    send_at: MonotonicNanos,
    round_trip: Nanos,
    excess: Nanos,
) -> Exchange {
    let mut e = claiming_no_uncertainty(world, id, offset, send_at, round_trip);
    e.t3 = e.t3 + excess;
    e
}

/// The shipped policy with the independence floor lowered to two operators.
///
/// Every fixture in this crate is a simulated round of two to four sources, and each of them is its
/// own operator, so the shipped floor of four would refuse most of them before their arithmetic ever
/// ran. Raising every fixture to four sources instead would change the very quantity most of these
/// tests measure: the width of an intersection depends on how many intervals are in it, and a test
/// asserting what a hostile source can do to three honest ones is not the same test with five.
///
/// So the floor is lowered here, once, in something with a name that says what was lowered. Nothing
/// about the floor itself is tested through this: it has its own tests in
/// `timewitness_clock::independence`, in `crates/core/src/source.rs`, and in `four_to_six.rs`, which
/// runs against the shipped policy exactly as it ships.
pub fn arithmetic_policy() -> Policy {
    Policy {
        min_operators: 2,
        ..Policy::default()
    }
}

/// Four honest sources on ordinary internet paths.
pub fn four_honest_sources() -> Vec<Path> {
    vec![
        Path::honest("alpha", 12, 1),
        Path::honest("bravo", 24, 2),
        Path::honest("charlie", 8, 1),
        Path::honest("delta", 40, 3),
    ]
}
