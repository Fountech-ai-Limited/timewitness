//! The resident agent, and the boundary a stamp reaches it over.
//!
//! Everything else in this workspace assumes the clock model and the thing being stamped are in the
//! same process. They are not, once an agent runs continuously, and this crate is the whole of what
//! changes because of it.
//!
//! ## Why a resident agent exists at all
//!
//! The product's own sentence is that a small agent disciplines the machine's clock continuously.
//! What the tree had until now was a command that starts, polls, reads and exits, and the cost of
//! that showed up in one number. On the receipt committed on 2026-09-09 at 15:05, 36.360 ms of the
//! 88.4 ms half width was the model's own regression residual, which is the scatter of a line fitted
//! through 1.714 s of measurements. A line through under two seconds of data is arithmetic on a
//! baseline too short to support it. Nothing a one-shot command can do improves that, because it has
//! nothing to regress against.
//!
//! A process that stays up has a baseline of minutes. That is the whole of the argument for this
//! crate, and [`resident`] is the process.
//!
//! ## What a resident agent has to survive, which is the harder half
//!
//! A model held between stamps is a model that can go wrong between stamps, and the two ways it does
//! are named in the product's own architecture note.
//!
//! **The machine sleeps.** Everything measured before a suspend describes a clock that has since
//! been on its own for a length of time nothing inside the process can measure. A poll schedule of
//! thirty seconds leaves a window of thirty seconds in which a lid can close and the model will
//! still answer, confidently, and be wrong. So the environment watch runs on the read path and not
//! only on the poll path: every reading looks at the operating system's own pair of counters before
//! the model is asked. There is no window. [`resident::Resident::read`] is where that happens and
//! `a_machine_that_slept_between_polls_is_caught_on_the_read_path` is the test of it.
//!
//! **Something else moves the clock.** Same path, same look, same refusal. The agent does not stop
//! the other discipliner and claims nothing about stopping it.
//!
//! ## What crossing a process boundary costs, and where that cost is written down
//!
//! Two things, and both are paid rather than assumed.
//!
//! The reading is taken inside the agent, at a moment the client cannot see. All the client knows is
//! that it happened somewhere between sending the request and receiving the answer. So the client
//! measures that span on its own counter and widens the interval by it, at [`crossing::widen`],
//! which carries the argument. The interval that comes back then holds true UTC at every instant of
//! the client's wait rather than only at the agent's read.
//!
//! The policy that governed the bound is the agent's, not the client's. A receipt carries the
//! agent's own limits so a reader can hold it to its own word, and with two processes the process
//! that held the model is the one whose word it was. So the policy crosses the boundary with the
//! reading and the client records what it was handed. [`wire`] carries both.
//!
//! ## What this crate is not
//!
//! It is not a service interface and phase 2 has not started. One message goes each way: a request
//! for a reading, and a reading or a refusal back. There is no second request, nothing is
//! negotiated, and there is no method to add one to. The agent does not sign anything and does not
//! see what is being stamped; it hands over a reading and the caller builds its own receipt.
//!
//! It installs nothing. What starts the agent at boot is the command line's `agent install`, which
//! hands the same foreground process to the platform's own service manager.

#![forbid(unsafe_code)]

pub mod crossing;
pub mod resident;
pub mod serve;
pub mod wire;

pub use crossing::{ask, widen, Crossed, CrossingError};
pub use resident::{Resident, Surroundings, SystemSurroundings};
pub use serve::{serve, Cadence};
pub use wire::{carrier, Endpoint, WireError};
