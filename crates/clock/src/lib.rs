//! The clock model.
//!
//! What this crate does, in the order it does it:
//!
//! 1. Turn each four-timestamp exchange into an offset, a round trip and an interval
//!    ([`sample`]).
//! 2. Keep the last few per source and work from the quickest ([`window`]).
//! 3. Find the region a majority of the intervals allow and throw away the sources that do not
//!    reach it ([`marzullo`]). One rule there is stricter than the published algorithm and that
//!    file says so at its head: a majority that exists only because of sources that could not have
//!    disagreed is refused.
//! 4. Ask the same question of the parties behind those intervals rather than of the intervals
//!    ([`independence`]). Nine names at one company are one chance to be wrong, so a majority that
//!    rests on too few operators is refused as well.
//! 5. Weight the survivors by the inverse square of their widths ([`combine`]).
//! 6. Fit a line through the last few rounds for offset and frequency ([`regression`]).
//! 7. Act on the frequency by rate and never by stepping ([`discipline`]).
//! 8. Hold all of it as one interval that widens honestly with time and refuses when it cannot be
//!    supported ([`model`]).
//!
//! [`loss`] is the list of every way a reading can lose UTC and what the model does about each one,
//! widen or refuse. It is the crate's promise written out in one place, with a test per entry, so
//! that a fault in this layer is found as a missing entry rather than one at a time.
//!
//! This crate never learns what a receipt looks like. It hands out a [`timewitness_core::Stamp`]
//! and the receipt crate decides how to carry one.

#![forbid(unsafe_code)]

pub mod combine;
pub mod discipline;
pub mod independence;
pub mod loss;
pub mod marzullo;
pub mod model;
pub mod monotonic;
pub mod policy;
pub mod regression;
pub mod sample;
pub mod window;

pub use discipline::{
    Applied, Discipline, DisciplineError, RateAdjuster, RateDiscipline, ShadowDiscipline,
};
pub use loss::{LossOfUtc, Response};
pub use marzullo::Intersection;
pub use model::{ClockModel, SyncFit};
pub use monotonic::{MonotonicClock, SystemMonotonic, TestClock};
pub use policy::Policy;
pub use sample::Sample;
pub use window::SourceWindow;
