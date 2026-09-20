//! A private key on disk, read.
//!
//! It is a module of its own rather than a function inside `stamp_cmd` because two commands need
//! it and only one of them may reach the stamp path. `timewitness countersign --answer` signs the
//! receive half of an exchange, and that path promises a receiver needs no account and nothing of
//! ours; the stamp path talks to time sources by design and names our own Roughtime servers. The
//! architecture check reads the modules a subcommand reaches, so a shared five lines living in
//! `stamp_cmd` put the whole of the stamp path on the countersign path and turned that promise red.
//! It was caught the same afternoon it was written, by the check rather than by a reading.
//!
//! Making a key is not here. It belongs to the one caller that may do it, which is `stamp`, on a
//! build runner with nobody to ask for a key. A receiver answering a request is signing with the
//! key that already signed the receipt it is naming, so a key made here would be the one key
//! certain to be wrong.

use std::fs;

use timewitness_receipt::AgentKey;

/// The key already on disk at a path, where there is one.
///
/// `Ok(None)` is a file that is not there, which is an answer the two callers do different things
/// with. An unreadable file of the wrong size is an error, because a caller that read it as absent
/// would write over a key and orphan every receipt signed with the old one.
pub(crate) fn key_at(path: &str) -> Result<Option<AgentKey>, String> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{path} is not a 32 byte seed"))?;
    Ok(Some(AgentKey::from_seed(&seed)))
}
