//! The verifier core as WebAssembly, so the page and the command line are one implementation.
//!
//! Two shells around one core was the architecture decision, and the reason is that two
//! implementations of the checking logic drift, and the day they drift is the day the page says a
//! receipt is good and the binary says it is not. Nothing in this crate checks anything. It converts
//! bytes to bytes across the boundary and calls [`timewitness_verify`].
//!
//! ## The boundary, and why there is no binding library behind it
//!
//! Four exported functions and a length-prefixed buffer. A binding generator would be a build step,
//! a code generator and a dependency tree, in a page whose whole argument is that a stranger can
//! read what it does. This is thirty lines and the JavaScript side of it is twenty.
//!
//! - `tw_alloc(len)` returns the address of `len` bytes the caller may write into.
//! - `tw_free(address)` gives them back.
//! - `tw_verify(receipt, subject, has_subject)` takes two of those addresses and returns the address
//!   of a buffer whose first four bytes are the length, little endian, of the UTF-8 JSON after them.
//! - `tw_cannot_prove()` returns the same shape, holding the list of what this product cannot prove.
//!
//! The caller frees everything it was given with `tw_free`. Nothing here dereferences a pointer,
//! which is what keeps the crate free of `unsafe`; see [`BUFFERS`].
//!
//! ## What the page does and does not do
//!
//! The receipt and the artefact are read by the browser from the reader's own disk and passed
//! straight into this module. Nothing is uploaded, there is no request of any kind, and the page
//! works with the network off and from a `file://` address. A verifier page that posted a receipt
//! somewhere to be checked would create a permanent address for whatever that receipt is about, and
//! whoever found the link would learn it.

// Every use of this is one of the four exported functions below, and each carries the attribute by
// name. See the manifest for why `forbid` is not possible in a module a page can call.
#![deny(unsafe_code)]

#[cfg(target_arch = "wasm32")]
mod randomness;

use std::sync::{Mutex, PoisonError};

use timewitness_receipt::{json, Value};
use timewitness_verify::{anchor_file, cannot_prove, verify, Floor, State, Subject};

/// Every buffer this module has handed out, kept alive and owned here.
///
/// This is what lets the whole crate stay free of `unsafe`, and it is the only interesting thing
/// about the boundary. The usual way to pass bytes into a WebAssembly module is to hand JavaScript a
/// pointer and then rebuild a slice from it, which needs a raw pointer dereference. Instead the
/// allocation stays a `Vec` this module owns, held in this table under the address JavaScript was
/// given. JavaScript writes into the module's linear memory at that address, which is the same
/// memory the `Vec` holds, and the module reads its own `Vec`. Nothing is dereferenced from a
/// pointer a caller chose, so a caller that invents an address gets nothing back rather than
/// whatever happens to sit there.
///
/// A `Mutex` because a `static` needs one, not because anything here is concurrent: a WebAssembly
/// module in a page runs on one thread.
static BUFFERS: Mutex<Vec<Buffer>> = Mutex::new(Vec::new());

/// One handed-out buffer: where it starts, how many bytes were asked for, and the bytes.
///
/// The asked-for length is held separately from the store because they are allowed to differ, and
/// on 2026-09-08 that difference was a false accept in the published page. A zero-length request
/// has to be backed by at least one byte, since an empty `Vec` has no address to key this table by,
/// and the store was what [`find`] handed back. So the page hashed an empty file as one `0x00` byte
/// and the command line hashed it as the empty string, and against a receipt over a single zero byte
/// the page accepted where the command line refused. `wanted` is what the caller asked for and it is
/// what a reader gets back; `store` is only where those bytes live.
struct Buffer {
    address: usize,
    wanted: usize,
    store: Vec<u8>,
}

fn held<T>(f: impl FnOnce(&mut Vec<Buffer>) -> T) -> T {
    let mut guard = BUFFERS.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut guard)
}

/// Somewhere for the caller to put bytes.
///
/// Returns the address to write at. The allocation itself stays here.
#[allow(
    unsafe_code,
    reason = "exporting a function to WebAssembly is what this crate is for"
)]
#[no_mangle]
pub extern "C" fn tw_alloc(len: usize) -> usize {
    let mut store = vec![0u8; len.max(1)];
    let address = store.as_mut_ptr() as usize;
    held(|buffers| {
        buffers.push(Buffer {
            address,
            wanted: len,
            store,
        });
    });
    address
}

/// Give a buffer back.
#[allow(
    unsafe_code,
    reason = "exporting a function to WebAssembly is what this crate is for"
)]
#[no_mangle]
pub extern "C" fn tw_free(address: usize) {
    held(|buffers| buffers.retain(|buffer| buffer.address != address));
}

/// Check a receipt and answer with JSON.
///
/// Both addresses come from [`tw_alloc`]. Returns the address of a buffer whose first four bytes are
/// the length of the UTF-8 JSON after them, little endian, or zero where an address was not one this
/// module handed out.
///
/// Never a bare failure for a bad receipt: a receipt that could not be read comes back as a result
/// whose first step failed, because the reader wants to know what was wrong and where.
#[allow(
    unsafe_code,
    reason = "exporting a function to WebAssembly is what this crate is for"
)]
#[no_mangle]
pub extern "C" fn tw_verify(receipt: usize, subject: usize, has_subject: u32) -> usize {
    let text = held(|buffers| {
        let receipt_bytes = find(buffers, receipt)?;
        let subject = if has_subject == 0 {
            None
        } else {
            match find(buffers, subject) {
                Some(bytes) => Some(bytes),
                None => return None,
            }
        };
        Some(json_for(receipt_bytes, subject))
    });

    match text {
        Some(text) => answer(&text),
        None => 0,
    }
}

/// Check a receipt and answer with the JSON the page reads, with no addresses in the way.
///
/// [`tw_verify`] is this function plus the buffer bookkeeping the boundary needs, so the two say
/// the same thing by construction. They are apart because the JSON a reader is shown can then be
/// held to by a test that writes to no address, which is what this crate's own rule about pointers
/// asks for: see [`BUFFERS`].
#[must_use]
pub fn json_for(receipt: &[u8], subject: Option<&[u8]>) -> String {
    let subject = match subject {
        Some(bytes) => Subject::Bytes(bytes),
        None => Subject::NotSupplied,
    };
    as_json(&verify(
        receipt,
        subject,
        &anchor_file::published(),
        &Floor::default(),
    ))
}

/// The list of what this product cannot prove, as JSON.
#[allow(
    unsafe_code,
    reason = "exporting a function to WebAssembly is what this crate is for"
)]
#[no_mangle]
pub extern "C" fn tw_cannot_prove() -> usize {
    let items = cannot_prove::limits()
        .into_iter()
        .map(|limit| {
            Value::map([
                ("section", Value::text(limit.section)),
                ("limit", Value::text(limit.headline)),
            ])
        })
        .collect();
    answer(&json::render(&Value::Array(items)))
}

/// One of this module's own buffers, by the address it was handed out under.
///
/// Cut to the length that was asked for, never to the length of the store behind it.
fn find(buffers: &[Buffer], address: usize) -> Option<&[u8]> {
    buffers
        .iter()
        .find(|buffer| buffer.address == address)
        .map(|buffer| &buffer.store[..buffer.wanted])
}

/// Pack a string as a length prefix and its bytes, and hand back where to read it.
fn answer(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(bytes);
    let address = out.as_mut_ptr() as usize;
    let wanted = out.len();
    held(|buffers| {
        buffers.push(Buffer {
            address,
            wanted,
            store: out,
        });
    });
    address
}

/// The assessment as JSON, in the same shape the command line's `--json` produces.
fn as_json(a: &timewitness_verify::Assessment) -> String {
    let mut top: Vec<(&'static str, Value)> = vec![
        ("accepted", Value::Bool(a.accepted())),
        // The one line a person reads. The page prints it as given rather than composing its own,
        // so a reader of the page and a reader of the command line are told the same thing.
        ("verdict", Value::text(a.verdict())),
        // The line under it, with how wide the checked outside evidence brackets the moment and
        // whose the width is. Null where the receipt was refused.
        ("bracket", a.bracket().map_or(Value::Null, Value::text)),
        (
            "steps",
            Value::Array(
                a.steps
                    .iter()
                    .map(|step| {
                        Value::map([
                            ("question", Value::text(step.question.clone())),
                            (
                                "state",
                                Value::text(match step.state {
                                    State::Held(_) => "held",
                                    State::Failed(_) => "failed",
                                    State::NotChecked(_) => "not-checked",
                                }),
                            ),
                            ("detail", Value::text(step.state.detail().to_string())),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("receipt_bytes", Value::Int(a.encoded_bytes as i128)),
        ("receipt_sha256", Value::Bytes(a.link.clone())),
        ("anchors_held", Value::Int(a.anchors_held as i128)),
        (
            "floor",
            Value::Array(a.floor.lines().into_iter().map(Value::text).collect()),
        ),
    ];

    if let Some(receipt) = &a.receipt {
        let operators = receipt.claim.operators();
        top.push((
            "claim",
            Value::map([
                ("earliest_ns", Value::Int(receipt.claim.earliest.as_nanos())),
                ("latest_ns", Value::Int(receipt.claim.latest.as_nanos())),
                ("width_ns", Value::Int(receipt.width())),
                (
                    "width_in_words",
                    Value::text(timewitness_verify::width_in_words(receipt.width())),
                ),
                ("reading_ns", Value::Int(receipt.utc_estimate.as_nanos())),
                (
                    "sources_offered",
                    Value::Int(i128::from(receipt.claim.sources_offered)),
                ),
                (
                    "sources_kept",
                    Value::Int(i128::from(receipt.claim.sources_kept)),
                ),
                // The same two counts and the same labels the command line carries. A page a
                // stranger runs from their own disk and a tool a workflow runs have to answer the
                // same question the same way.
                ("operators_offered", Value::Int(operators.offered as i128)),
                ("operators_kept", Value::Int(operators.kept as i128)),
                // Neither count above includes a party that is the issuer itself, so a script
                // reading only those two would see a round of three strangers where there were two
                // strangers and one of the issuer's own servers.
                (
                    "operators_first_party",
                    Value::Int(operators.first_party as i128),
                ),
                ("sources", receipt.claim.sources_as_value()),
                ("sequence", Value::Int(i128::from(receipt.sequence))),
                (
                    "breakdown",
                    Value::Array(
                        [
                            (
                                "the sources overlapping, halved",
                                receipt.claim.breakdown.intersection_half,
                            ),
                            ("the local read", receipt.claim.breakdown.scheduling),
                            (
                                "the oscillator since the last sync",
                                receipt.claim.breakdown.oscillator_holdover,
                            ),
                            (
                                "the model's own residual",
                                receipt.claim.breakdown.model_residual,
                            ),
                            (
                                "a fixed safety margin",
                                receipt.claim.breakdown.safety_margin,
                            ),
                        ]
                        .into_iter()
                        .map(|(name, value)| {
                            Value::map([
                                ("part", Value::text(name)),
                                ("ns", Value::Int(value)),
                                (
                                    "in_words",
                                    Value::text(timewitness_verify::width_in_words(value)),
                                ),
                            ])
                        })
                        .collect(),
                    ),
                ),
            ]),
        ));
    }

    if let Some(evidence) = &a.evidence {
        top.push((
            "evidence",
            Value::Array(
                evidence
                    .entries
                    .iter()
                    .map(|entry| {
                        let (checked, against, checks) = match &entry.outcome {
                            timewitness_receipt::Outcome::Checked { signer, checks, .. } => (
                                true,
                                signer.clone(),
                                checks.iter().cloned().map(Value::text).collect(),
                            ),
                            timewitness_receipt::Outcome::NotChecked(why) => {
                                (false, why.clone(), Vec::new())
                            }
                        };
                        Value::map([
                            ("role", Value::text(entry.role.as_str())),
                            ("scheme", Value::text(entry.scheme.clone())),
                            (
                                "detail",
                                Value::text(entry.detail.clone().unwrap_or_default()),
                            ),
                            ("checked", Value::Bool(checked)),
                            ("against", Value::text(against)),
                            ("checks", Value::Array(checks)),
                        ])
                    })
                    .collect(),
            ),
        ));
        top.push(("basis_granted", Value::Bool(evidence.basis_granted)));
        top.push(("basis_reason", Value::text(evidence.basis_reason.clone())));
    }

    json::render(&Value::map(top))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this crate shipped on 2026-09-08, at the layer it happened.
    ///
    /// An empty file went in and one `0x00` byte came out, so the page hashed the empty string as
    /// `6e340b9c` where the command line hashed it as `e3b0c442`, and against a receipt over a
    /// single zero byte the page accepted what the command line refused.
    #[test]
    fn a_request_for_no_bytes_reads_back_as_no_bytes() {
        let address = tw_alloc(0);
        assert_eq!(
            held(|buffers| find(buffers, address).map(<[u8]>::to_vec)),
            Some(Vec::new())
        );
        tw_free(address);
    }

    /// And the byte a zero-length request used to return is a real one byte away, so the two cases
    /// have to stay apart rather than both being right by accident.
    #[test]
    fn a_request_for_one_byte_reads_back_as_one_byte() {
        let address = tw_alloc(1);
        assert_eq!(
            held(|buffers| find(buffers, address).map(<[u8]>::to_vec)),
            Some(vec![0u8])
        );
        tw_free(address);
    }

    /// An address this module never handed out gets nothing, which is what keeps the crate free of
    /// `unsafe`.
    #[test]
    fn an_address_nobody_handed_out_reads_back_as_nothing() {
        assert!(held(|buffers| find(buffers, 0x1000).is_none()));
    }

    /// A freed buffer is gone, including a zero-length one, whose store outlives its length.
    #[test]
    fn a_freed_buffer_is_gone() {
        let address = tw_alloc(0);
        tw_free(address);
        assert!(held(|buffers| find(buffers, address).is_none()));
    }
}
