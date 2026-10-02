//! `timewitness verify`, which is the whole of what a consumer ever runs.
//!
//! It reads a receipt off disk, reads whatever the reader is checking it against off disk, and says
//! what held. There is no network call anywhere in this path and there is no account. A reader who
//! unplugs the machine gets the same answer, which is the property, not a nice side effect.

use std::fs;
use std::path::Path;

use timewitness_core::keylog::file::{parse as parse_key_log, KeyLog};
use timewitness_receipt::anchors::TrustAnchors;
use timewitness_verify::{anchor_file, verify_with_kept_log, verify_with_key_log, Floor, Subject};

use crate::args::Args;
use crate::{as_json, render};

/// What a run of the verifier ended as.
pub struct Outcome {
    /// What to print.
    pub text: String,
    /// What to exit with. Zero where nothing was refused.
    pub code: i32,
}

/// Run it.
pub fn run(args: &Args) -> Outcome {
    let Some(path) = args.positional.first() else {
        return refuse("verify needs the path to a receipt");
    };

    let receipt_bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return refuse(&timewitness_platform::files::unreadable(
                std::path::Path::new(path),
                &e,
            ))
        }
    };

    // The subject is hashed here, on this machine, out of the file where it already sits. Sending it
    // somewhere to have its digest taken would leak whatever it is in order to prove something about
    // when it was made, and a verifier that does that is worse than no verifier.
    let subject_bytes = match args.value("--subject") {
        None => None,
        Some(subject_path) => match fs::read(Path::new(subject_path)) {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                return refuse(&timewitness_platform::files::unreadable(
                    std::path::Path::new(subject_path),
                    &e,
                ))
            }
        },
    };
    let digest = match args.value("--digest") {
        None => None,
        Some(text) => match unhex(text) {
            // A value too short or too long to be a sha-256 digest names nothing a receipt could
            // stamp, and comparing it would call the receipt one for a different thing.
            Ok(bytes) if bytes.len() != 32 => {
                return refuse(&format!(
                    "--digest is {} bytes, and a sha-256 digest is 32, so it is not the digest of anything; take the sha-256 of the file and give all 64 hex characters",
                    bytes.len()
                ))
            }
            Ok(bytes) => Some(bytes),
            Err(e) => return refuse(&format!("--digest is not hexadecimal: {e}")),
        },
    };
    if subject_bytes.is_some() && digest.is_some() {
        return refuse("--subject and --digest say the same thing two ways; give one");
    }

    let subject = match (&subject_bytes, &digest) {
        (Some(bytes), _) => Subject::Bytes(bytes),
        (_, Some(bytes)) => Subject::Digest(bytes),
        _ => Subject::NotSupplied,
    };

    let mut anchors = match anchors_from(args) {
        Ok(a) => a,
        Err(text) => return refuse(&text),
    };
    // The one anchor that is ours, replaceable on its own because the ordinary reason to replace
    // it is a build that signed a throwaway log to prove the path, and that reader still wants the
    // six third-party keys that ship.
    if let Some(text) = args.value("--key-log-signer") {
        let key = match unhex(text)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        {
            Some(key) => key,
            None => {
                return refuse("--key-log-signer takes a 32-byte Ed25519 key as 64 hex characters")
            }
        };
        anchors.key_log_signers.clear();
        anchors = anchors.with_key_log_signer("the key log signer you named", key);
    }

    let floor = match floor_from(args) {
        Ok(floor) => floor,
        Err(text) => return refuse(&text),
    };

    // The log is read off disk like everything else here. There is no fetch: a verifier that went
    // and got the log would be a verifier that needs us to be reachable, and a reader we can cut
    // off is a reader we can lie to by going quiet.
    let key_log = match key_log_from(args, "--key-log") {
        Ok(log) => log,
        Err(text) => return refuse(&text),
    };
    let kept = match key_log_from(args, "--kept-log") {
        Ok(log) => log,
        Err(text) => return refuse(&text),
    };

    let assessment = match (&key_log, &kept) {
        (Some(log), Some(kept)) => {
            verify_with_kept_log(&receipt_bytes, subject, &anchors, &floor, log, kept)
        }
        (None, Some(_)) => return refuse(
            "--kept-log holds an earlier copy to the log in --key-log, and no --key-log was given",
        ),
        (log, None) => verify_with_key_log(&receipt_bytes, subject, &anchors, &floor, log.as_ref()),
    };
    let code = i32::from(!assessment.holds());

    let text = if args.flag("--fields") {
        render::fields(&assessment)
    } else if args.flag("--json") {
        as_json::render(&assessment)
    } else {
        render::assessment(&assessment, subject, args.flag("--quiet"))
    };

    Outcome { text, code }
}

/// The key log the reader was handed, where they were handed one.
///
/// A file that will not parse refuses the run rather than being read as no log at all. A reader who
/// supplied a log and got back `nothing here can say` would reasonably think the question had been
/// asked and answered, and it would not have been.
fn key_log_from(args: &Args, option: &str) -> Result<Option<KeyLog>, String> {
    let Some(path) = args.value(option) else {
        return Ok(None);
    };
    let text = fs::read_to_string(path).map_err(|e| {
        format!(
            "the key log: {}",
            timewitness_platform::files::unreadable(std::path::Path::new(path), &e)
        )
    })?;
    parse_key_log(&text)
        .map(Some)
        .map_err(|e| format!("the key log at {path} is not readable: {e}"))
}

/// The numbers this reader will not go below, with whatever the reader asked for on top.
///
/// It is here rather than inside the run so that `order` judges two receipts by the same floor
/// `verify` judges one by. Two commands holding two floors would let a receipt be refused by one
/// and used by the other in the same afternoon.
pub(crate) fn floor_from(args: &Args) -> Result<Floor, String> {
    let mut floor = Floor::default();
    match args.number("--min-width") {
        Ok(Some(width)) => floor.min_interval_width = width,
        Ok(None) => {}
        Err(e) => return Err(e.0),
    }
    Ok(floor)
}

/// What the reader decided to trust, before anything was read.
pub(crate) fn anchors_from(args: &Args) -> Result<TrustAnchors, String> {
    if args.flag("--no-anchors") {
        // A legitimate state and not a degraded one. Every arithmetic claim the receipt makes about
        // itself is still checked, and an attestation nobody here holds a key for is reported as
        // unchecked rather than glossed over, which is what a reader holding no keys actually knows.
        //
        // Unchecked is not the same as unread, and it was until 2026-09-08. A blob that is not a
        // stored attestation of its scheme at all is a fault anybody can see without a key, so it
        // fails here as well as under the keys that ship, and the verdict follows it.
        return Ok(TrustAnchors::none());
    }
    match args.value("--anchors") {
        None => Ok(anchor_file::published()),
        Some(path) => {
            let text = fs::read_to_string(path).map_err(|e| {
                format!(
                    "the trust material: {}",
                    timewitness_platform::files::unreadable(std::path::Path::new(path), &e)
                )
            })?;
            anchor_file::parse(&text)
                .map_err(|e| format!("the trust material at {path} is not readable: {e}"))
        }
    }
}

fn refuse(what: &str) -> Outcome {
    Outcome {
        text: render::failure(what),
        code: 2,
    }
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("an odd number of digits".to_string());
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let mut byte = 0u8;
        for (shift, b) in pair.iter().enumerate() {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                other => return Err(format!("{:?} is not a digit", char::from(*other))),
            };
            byte |= digit << (4 * (1 - shift));
        }
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_reads_and_rubbish_refuses() {
        assert_eq!(unhex("deadBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
