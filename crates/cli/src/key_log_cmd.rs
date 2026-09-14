//! `timewitness key-log`, which is how a key log gets written at all.
//!
//! The tree, the proofs and the file format are in [`timewitness_core::keylog`]. This is the three
//! things a person does with them: add a key, retire one, and sign what the log now holds.
//!
//! ## Why appending is the only edit
//!
//! There is no command here that removes an entry, retires one in place or corrects a typing
//! mistake, and that is the whole design rather than an omission. A log whose old entries change is
//! not a log: the consistency proof between an old head and a new one is the only thing a reader
//! gets out of this, and an edit anywhere in the history destroys it for every reader who kept a
//! head. Retiring a key is appending an entry that says so, and a wrong entry stays where it is
//! with a right one after it.
//!
//! So this refuses to write a log that is not an extension of the one already at that path. A run
//! that would drop or change an entry stops rather than writing, which is the one protection a file
//! on a disk can have against the hand that holds it.
//!
//! ## Why retiring is its own edit
//!
//! Until 2026-09-15 the way to retire a key was to append the same key again with an end on it,
//! and the verifier read the two entries as a union of windows, so the open entry above went on
//! covering every later moment and nothing was retired. Now `--retire` appends an entry of the
//! retired role, which closes every window of the key from its moment on, and `--add` refuses a
//! key that already has an open entry or a retirement, so the old procedure cannot be followed by
//! mistake.
//!
//! ## What signing a head does and does not buy
//!
//! It makes the log something we cannot quietly rewrite for a reader who kept an earlier head. It
//! does not make the log worth anything to somebody seeing it for the first time, and our own word
//! is still never third-party evidence: a key log of ours is our own party, and the weight of a
//! receipt rests on the third-party signatures in it.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use timewitness_core::keylog::file::{
    parse, sign_head as sign, write as write_log, KeyLog, SignedHead,
};
use timewitness_core::keylog::{KeyEntry, Role};
use timewitness_core::UnixNanos;

use crate::args::Args;
use crate::render;
use crate::verify_cmd::Outcome;

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let path = match args.required("--log") {
        Ok(path) => Path::new(path),
        Err(e) => return fail(&e.0),
    };

    let before = match read_existing(path) {
        Ok(log) => log,
        Err(text) => return fail(&text),
    };
    let mut log = before.clone();

    if args.value("--add").is_some() && args.value("--retire").is_some() {
        return fail("--add and --retire in one run. One edit at a time, so each is its own entry with its own reason");
    }
    if let Some(key) = args.value("--add") {
        let entry = match entry_from(args, key, &log) {
            Ok(entry) => entry,
            Err(text) => return fail(&text),
        };
        log.entries.push(entry);
    }
    if let Some(key) = args.value("--retire") {
        let entry = match retirement_from(args, key, &log) {
            Ok(entry) => entry,
            Err(text) => return fail(&text),
        };
        log.entries.push(entry);
    }

    // Whatever the entries now are, the head describes them or there is no head. A head left over
    // from before an append would state a root the file no longer hashes to, and the format refuses
    // to read that file at all, so leaving one behind would produce a log nobody can use.
    log.head = None;
    if let Some(signing_path) = args.value("--sign") {
        match sign_head(&log, Path::new(signing_path)) {
            Ok(head) => log.head = Some(head),
            Err(text) => return fail(&text),
        }
    }

    if !extends(&before, &log) {
        return fail(
            "this would not be an extension of the log already at that path, and a log whose old \
             entries change is not a log. Retire a key by appending an entry that says so",
        );
    }

    let text = match write_log(&log) {
        Ok(text) => text,
        Err(e) => return fail(&format!("{e}")),
    };
    if let Err(e) = std::fs::write(path, text) {
        return fail(&format!("{} could not be written: {e}", path.display()));
    }

    Outcome {
        text: render::key_log_written(
            &path.display().to_string(),
            log.entries.len(),
            log.entries.len() - before.entries.len(),
            log.head.as_ref().map(|signed| signed.head.root),
        ),
        code: 0,
    }
}

/// Whether `after` holds everything `before` held, in the same order, and then possibly more.
fn extends(before: &KeyLog, after: &KeyLog) -> bool {
    after.entries.len() >= before.entries.len()
        && after.entries[..before.entries.len()] == before.entries[..]
}

/// The log at that path, or an empty one where there is nothing there yet.
fn read_existing(path: &Path) -> Result<KeyLog, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text).map_err(|e| {
            format!(
                "there is a file at {} and it is not a key log: {e}",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KeyLog::default()),
        Err(e) => Err(format!("{} could not be read: {e}", path.display())),
    }
}

/// The entry the command line describes.
fn entry_from(args: &Args, key: &str, log: &KeyLog) -> Result<KeyEntry, String> {
    let public_key = from_hex(key).ok_or_else(|| {
        format!("--add takes a 32-byte public key as 64 hex characters and was given {key:?}")
    })?;
    let role = match args.value("--role") {
        None => Role::Agent,
        Some("retired") => {
            return Err(
                "--role retired is not how a key is retired. Use --retire <key>".to_string(),
            )
        }
        Some(word) => Role::from_word(word)
            .ok_or_else(|| format!("--role is agent or server and was given {word:?}"))?,
    };
    let deployment = args
        .value("--label")
        .ok_or(
            "--label says which deployment this key belongs to, and an entry without one names \
                nothing a reader can check",
        )?
        .to_string();

    // Now, where nobody said otherwise. A key is added at the moment it starts being used, so the
    // default is the ordinary case and `--from` is for writing down a key that was already in use.
    let valid_from = match args.number("--from") {
        Ok(Some(n)) => UnixNanos(n),
        Ok(None) => UnixNanos(now_nanos()?),
        Err(e) => return Err(e.0),
    };
    let valid_until = match args.number("--until") {
        Ok(Some(n)) => Some(UnixNanos(n)),
        Ok(None) => None,
        Err(e) => return Err(e.0),
    };

    if let Some(until) = valid_until {
        if until < valid_from {
            return Err("--until is before --from, which is a window nothing falls in".to_string());
        }
    }

    // The two states of a key that a second `--add` cannot honestly follow. A retirement is
    // permanent, and an open entry above is the old retirement procedure about to be repeated.
    let about_this_key = || log.entries.iter().filter(|e| e.public_key == public_key);
    if let Some(retired) = about_this_key().find(|e| e.role == Role::Retired) {
        return Err(format!(
            "{} was retired at {} ns, and a retirement is permanent. Issue a new key rather than \
             reopening this one",
            short(key),
            retired.valid_from.as_nanos()
        ));
    }
    if let Some(open) = about_this_key().find(|e| e.valid_until.is_none()) {
        return Err(format!(
            "{} already has an open {} entry above, for {:?}. A second entry does not close the \
             first: to retire the key, --retire {key} --at <ns>",
            short(key),
            open.role.word(),
            open.deployment
        ));
    }

    Ok(KeyEntry {
        public_key,
        role,
        deployment,
        valid_from,
        valid_until,
    })
}

/// The retirement the command line describes.
fn retirement_from(args: &Args, key: &str, log: &KeyLog) -> Result<KeyEntry, String> {
    let public_key = from_hex(key).ok_or_else(|| {
        format!("--retire takes a 32-byte public key as 64 hex characters and was given {key:?}")
    })?;
    let at = match args.number("--at") {
        Ok(Some(n)) => UnixNanos(n),
        Ok(None) => UnixNanos(now_nanos()?),
        Err(e) => return Err(e.0),
    };
    if args.value("--from").is_some() || args.value("--until").is_some() {
        return Err("--retire takes its moment as --at, not as a window".to_string());
    }

    let mut named = false;
    for earlier in &log.entries {
        if earlier.public_key != public_key {
            continue;
        }
        if earlier.role == Role::Retired {
            return Err(format!(
                "{} was already retired at {} ns",
                short(key),
                earlier.valid_from.as_nanos()
            ));
        }
        named = true;
    }
    if !named {
        return Err(format!(
            "{} is not in this log, so there is nothing to retire",
            short(key)
        ));
    }

    Ok(KeyEntry {
        public_key,
        role: Role::Retired,
        deployment: args.value("--label").unwrap_or("retired").to_string(),
        valid_from: at,
        valid_until: None,
    })
}

/// The first eight bytes of a key as typed, for a refusal that names it.
fn short(hex: &str) -> String {
    format!("{}...", &hex[..16.min(hex.len())])
}

/// Sign what the log now holds.
fn sign_head(log: &KeyLog, signing_path: &Path) -> Result<SignedHead, String> {
    let bytes = std::fs::read(signing_path).map_err(|e| {
        format!(
            "the signing key at {} could not be read: {e}",
            signing_path.display()
        )
    })?;
    let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        format!(
            "the signing key at {} is {} bytes and a key is 32",
            signing_path.display(),
            bytes.len()
        )
    })?;
    Ok(sign(log, &secret, UnixNanos(now_nanos()?)))
}

/// This machine's clock, which is the honest thing to date a head with.
///
/// A head says when we said the log held this, and that is a statement about us rather than a
/// measurement of anything. It carries no bound and claims none, which is why it is a plain system
/// clock read here and nowhere else in this product.
fn now_nanos() -> Result<i128, String> {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "this machine's clock is before 1970".to_string())?;
    i128::try_from(wall.as_nanos())
        .map_err(|_| "this machine's clock is further from 1970 than this arithmetic".to_string())
}

fn from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn fail(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: u8) -> KeyEntry {
        KeyEntry {
            public_key: [key; 32],
            role: Role::Agent,
            deployment: "a deployment".to_string(),
            valid_from: UnixNanos(100),
            valid_until: None,
        }
    }

    fn args(items: &[&str]) -> Args {
        crate::args::parse(&items.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
            .expect("a well-formed line")
    }

    fn hex32(byte: u8) -> String {
        [byte; 32].iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_key_with_an_open_entry_cannot_be_added_again_and_a_retired_one_never() {
        let open = log(&[1]);
        let again = args(&["key-log", "--add", &hex32(1), "--label", "x"]);
        let err = entry_from(&again, &hex32(1), &open).expect_err("already open above");
        assert!(err.contains("--retire"), "{err}");

        let mut retired = log(&[1]);
        retired.entries.push(KeyEntry {
            role: Role::Retired,
            valid_from: UnixNanos(200),
            ..entry(1)
        });
        let err = entry_from(&again, &hex32(1), &retired).expect_err("retired for good");
        assert!(err.contains("permanent"), "{err}");

        // A closed window above is not an open one, so a later window may follow it.
        let mut closed = log(&[1]);
        closed.entries[0].valid_until = Some(UnixNanos(150));
        let ok =
            entry_from(&again, &hex32(1), &closed).expect("a second window after a closed one");
        assert_eq!(ok.role, Role::Agent);

        let as_server = args(&[
            "key-log",
            "--add",
            &hex32(2),
            "--role",
            "server",
            "--label",
            "x",
        ]);
        assert_eq!(
            entry_from(&as_server, &hex32(2), &open)
                .expect("a server key")
                .role,
            Role::Server
        );
        let as_retired = args(&[
            "key-log",
            "--add",
            &hex32(2),
            "--role",
            "retired",
            "--label",
            "x",
        ]);
        assert!(entry_from(&as_retired, &hex32(2), &open).is_err());
    }

    #[test]
    fn a_retirement_needs_a_key_the_log_names_and_happens_once() {
        let open = log(&[1]);
        let retire = args(&["key-log", "--retire", &hex32(1), "--at", "500"]);
        let entry = retirement_from(&retire, &hex32(1), &open).expect("a key the log names");
        assert_eq!(entry.role, Role::Retired);
        assert_eq!(entry.valid_from, UnixNanos(500));
        assert_eq!(entry.valid_until, None);

        let unknown = retirement_from(&retire, &hex32(9), &open).expect_err("not in the log");
        assert!(unknown.contains("nothing to retire"), "{unknown}");

        let mut twice = open.clone();
        twice.entries.push(entry);
        let err = retirement_from(&retire, &hex32(1), &twice).expect_err("already retired");
        assert!(err.contains("already retired"), "{err}");

        let with_a_window = args(&["key-log", "--retire", &hex32(1), "--until", "9"]);
        assert!(retirement_from(&with_a_window, &hex32(1), &open).is_err());
    }

    fn log(keys: &[u8]) -> KeyLog {
        KeyLog {
            entries: keys.iter().copied().map(entry).collect(),
            head: None,
        }
    }

    #[test]
    fn an_append_extends_and_anything_else_does_not() {
        assert!(extends(&log(&[1, 2]), &log(&[1, 2, 3])), "an append");
        assert!(extends(&log(&[1, 2]), &log(&[1, 2])), "nothing added");
        assert!(extends(&log(&[]), &log(&[1])), "the first entry");

        assert!(!extends(&log(&[1, 2]), &log(&[1])), "an entry removed");
        assert!(!extends(&log(&[1, 2]), &log(&[2, 1])), "two reordered");
        assert!(!extends(&log(&[1, 2]), &log(&[1, 9, 3])), "one changed");
        // The one that reads as an append and is not: the same keys with an earlier entry edited.
        let mut edited = log(&[1, 2, 3]);
        edited.entries[0].valid_until = Some(UnixNanos(500));
        assert!(
            !extends(&log(&[1, 2]), &edited),
            "an old entry retired in place"
        );
    }
}
