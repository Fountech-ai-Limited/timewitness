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
//! Making a key is here as well, for the two callers that may do it: `stamp`, on a build runner with
//! nobody to ask for a key, and `enrol`, which is where a machine that will hold a certificate makes
//! the key it holds one for. A receiver answering a request never makes one: it is signing with the
//! key that already signed the receipt it is naming, so a key made there would be the one key
//! certain to be wrong, and `countersign` calls `key_at` alone.

use std::fs;
use std::path::Path;

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

/// The key at a path, or a new one written there where the file is absent.
///
/// The file this writes is a private key and not a cache. It is the whole of what an agent is, so
/// deleting it loses nothing that can be recovered and copying it hands somebody the ability to sign
/// as this agent.
pub(crate) fn key_or_new(path: &str) -> Result<AgentKey, String> {
    if let Some(key) = key_at(path)? {
        return Ok(key);
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| format!("this machine would not give us random bytes: {e}"))?;
    write_private(Path::new(path), &seed)
        .map_err(|e| timewitness_platform::files::unwritable(std::path::Path::new(path), &e))?;
    Ok(AgentKey::from_seed(&seed))
}

/// Write a private key, readable and writable by its owner and nobody else.
///
/// The permission goes on at creation rather than after the write, because a `chmod` after the fact
/// leaves a window with the bytes on disk and the world able to read them. On a platform with no
/// mode bits this is an ordinary create and the file inherits whatever the directory gives it, which
/// is stated here rather than left to be discovered.
///
/// `create_new` rather than `create`. Reaching here means the file could not be read, which is
/// usually because it is not there and could be because somebody else is writing it; either way,
/// writing over a key would orphan every receipt already signed with the old one.
pub(crate) fn write_private(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(seed)?;
    file.sync_all()
}
