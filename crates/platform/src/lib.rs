//! What only the operating system can answer.
//!
//! The clock model works over a counter and some arithmetic, and it is deliberately unable to reach
//! anything else: it cannot see the machine it is running on and it cannot ask the network a
//! question. That is what makes a stamp one counter read. It also means the model cannot notice two
//! things that make its bound a lie, because both of them happen outside the process.
//!
//! The machine sleeps. Everything the model measured before the sleep describes a clock that has
//! since been on its own for a length of time nothing inside the process can measure, and the
//! counter the model stamps from is the counter that stopped, so asking it is asking the thing that
//! failed.
//!
//! And something else moves the clock. On Windows the built-in time service contends with any other
//! discipliner by design, which is why this agent measures and vouches by default rather than
//! taking the clock, and on Linux there is usually a daemon doing the same job. A step is evidence
//! that a second discipliner is active, and a discipliner that can move the clock can usually change
//! the rate of the counter the model measures against as well.
//!
//! This crate reads the counters that can see both, in [`continuous`], and compares them in
//! [`watch`]. It decides nothing. It cannot stop a machine sleeping and it cannot stop another
//! service setting the clock, it has no interface that would let it try, and the agent's whole
//! answer to both is to decline to sign until it has measured the clock again.
//!
//! ## Why this crate is allowed unsafe code and no other is
//!
//! Every other crate in this workspace forbids it. The counters here have no safe interface in the
//! standard library, and the alternative to two calls into the operating system is a dependency that
//! makes the same two calls with more code around them. Both call sites are in `continuous.rs`, both
//! read a counter into a local and return it, neither takes a pointer from a caller or holds one
//! past the call, and both carry the argument for why they are sound beside them. The architecture
//! crate's boundary test fails if a second crate in this workspace ever stops forbidding it.

pub mod continuous;
pub mod watch;

pub use continuous::{ContinuousClock, Elapsed, SystemContinuous};
pub use watch::{EnvironmentWatch, Interruptions, Marks};
