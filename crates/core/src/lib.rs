//! Plain data types shared across TimeWitness.
//!
//! Nothing here does any work. It holds the shapes that the clock model produces and that the
//! receipt and the verifier carry, so neither of those two has to depend on the other.
//!
//! The one distinction this crate exists to keep visible is the distinction the whole product
//! rests on. A reading has nanosecond resolution because it is a local counter read. A bound has
//! millisecond width because the network path it was measured over is not symmetric. They are two
//! different quantities and this crate never lets one stand in for the other.
//!
//! One thing here does do work, and it is here for the same reason the shapes are. [`evidence`]
//! checks a third-party attestation against the bytes it arrived as. The agent runs it the moment a
//! response lands and a stranger's verifier runs it years later on the same bytes, and those two
//! are on opposite sides of the module boundary, so the check that decides whether a signature
//! holds cannot live on either side of it. There is no network anywhere in this crate.

#![forbid(unsafe_code)]

pub mod attestation;
pub mod bound;
pub mod evidence;
pub mod hash;
pub mod interval;
pub mod keylog;
pub mod order;
pub mod refusal;
pub mod source;
pub mod time;

pub use attestation::Attestation;
pub use bound::{Bound, BoundBreakdown, EpsilonBasis, FusionRule, Reading, Stamp};
pub use evidence::{Checked, EvidenceError};
pub use hash::HashFunction;
pub use interval::OffsetInterval;
pub use order::{order_of, MomentInterval, Order};
pub use refusal::{Refusal, Validity};
pub use source::{
    Generations, LeapIndicator, Operator, SmearPolicy, SourceId, SourceKind, SourceState, Timescale,
};
pub use time::{MonotonicNanos, Nanos, UnixNanos};
