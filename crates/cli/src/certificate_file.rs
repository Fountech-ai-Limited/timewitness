//! The certificate a machine holds for its key, on disk beside the key, read with no network.
//!
//! A receipt is a TimeWitness certificate when the app certified the key that signed it, for a
//! window the signing falls inside. So a stamp asks one question of this file before it signs:
//! is there a certificate for this key whose window is open now and has at least an hour left. The
//! file was fetched earlier, by `timewitness certificate`, which is a separate act; a stamp never
//! fetches one, never waits on the app and never names it. The architecture check holds `stamp`
//! away from the module that does talk to the app, and this module is on the stamp's side of that
//! line, so it opens no connection and carries no address.
//!
//! **Until certification begins nothing asks for a certificate.** No key can be certified before
//! the cutoff the verifier holds is set, so a stamp that asked would refuse everything. The stamp
//! asks where that cutoff is set, or where its caller names a certificate file, and the verifier's
//! grade switches on at the same moment, so the two cannot disagree about whether certificates
//! exist yet.

use std::fs;
use std::path::{Path, PathBuf};

use timewitness_receipt::{json, Value};
use timewitness_sources::http::json_field;

/// The least a certificate's window may have left for a stamp to sign under it. A stamp that
/// signed in the last minutes of a window would give a reader a receipt at the edge of what the
/// certificate covers, and the agent renews daily, so an hour is a margin and not a hardship.
pub const LEAST_LEFT_NS: i128 = 3_600 * 1_000_000_000;

/// The fields a certificate carries, as the app answers them and as this file keeps them.
const FIELDS: [&str; 6] = [
    "publicKey",
    "organisation",
    "method",
    "validFromNanos",
    "validUntilNanos",
    "leafHash",
];

/// Where the certificate for a key is kept unless a caller names another place.
#[must_use]
pub fn beside(key_path: &str) -> PathBuf {
    PathBuf::from(format!("{key_path}.certificate"))
}

/// A certificate held, as far as a stamp needs it.
#[derive(Debug, PartialEq, Eq)]
pub struct Held {
    pub organisation: String,
    pub until: i128,
}

/// What a certificate the app answered with says, checked for shape and kept as the app said it.
///
/// Every field is required and each is held to its shape, so a file written from it is one a stamp
/// can read back. The public key has to be the one asked about: a certificate for another key is a
/// certificate this machine cannot sign under.
pub fn from_the_app(answer: &[u8], public_key_hex: &str) -> Result<String, String> {
    let mut pairs = Vec::new();
    for field in FIELDS {
        let value = json_field(answer, field)
            .ok_or_else(|| format!("the app's answer carries no {field}"))?;
        pairs.push((field, Value::text(value)));
    }
    let text = json::render(&Value::map(pairs));
    let read = read_text(text.as_bytes())?;
    if read.public_key != public_key_hex {
        return Err(format!(
            "the app answered with a certificate for {} and this key is {public_key_hex}",
            read.public_key
        ));
    }
    Ok(text)
}

struct Read {
    public_key: String,
    organisation: String,
    from: i128,
    until: i128,
}

fn read_text(bytes: &[u8]) -> Result<Read, String> {
    let field = |name: &str| json_field(bytes, name).ok_or_else(|| format!("it carries no {name}"));
    let nanos = |name: &str| -> Result<i128, String> {
        field(name)?
            .parse::<i128>()
            .map_err(|_| format!("its {name} is not a whole number"))
    };
    let public_key = field("publicKey")?;
    if public_key.len() != 64 || !public_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("its publicKey is not 64 hex digits".into());
    }
    let from = nanos("validFromNanos")?;
    let until = nanos("validUntilNanos")?;
    if until <= from {
        return Err("its window ends before it starts".into());
    }
    field("method")?;
    field("leafHash")?;
    Ok(Read {
        public_key: public_key.to_ascii_lowercase(),
        organisation: field("organisation")?,
        from,
        until,
    })
}

/// Whether the certificate at `path` lets this key sign at `now`, in nanoseconds since the epoch.
///
/// The error is what is missing, in words a job log can show as they are.
pub fn current(path: &Path, public_key_hex: &str, now: i128) -> Result<Held, String> {
    let shown = path.display();
    let bytes = fs::read(path).map_err(|_| format!("there is no certificate at {shown}"))?;
    let read =
        read_text(&bytes).map_err(|e| format!("the certificate at {shown} is unreadable: {e}"))?;
    if read.public_key != public_key_hex {
        return Err(format!(
            "the certificate at {shown} is for the key {} and this key is {public_key_hex}",
            read.public_key
        ));
    }
    if now < read.from {
        return Err(format!(
            "the certificate at {shown} has a window that has not opened yet"
        ));
    }
    let left = read.until - now;
    if left < LEAST_LEFT_NS {
        return Err(if left <= 0 {
            format!("the certificate at {shown} has a window that has ended")
        } else {
            format!(
                "the certificate at {shown} has {} minutes of its window left, and a stamp needs an hour",
                left / 60_000_000_000
            )
        });
    }
    Ok(Held {
        organisation: read.organisation,
        until: read.until,
    })
}

/// The certificate file a stamp has to hold, or none where nothing asks for one yet.
///
/// A caller who names a file is asking for it to be held. Otherwise one is asked for once
/// certification has begun, and it is looked for beside the key.
#[must_use]
pub fn needed(
    certification_began: Option<i128>,
    named: Option<&str>,
    key_path: &str,
) -> Option<PathBuf> {
    match (named, certification_began) {
        (Some(path), _) => Some(PathBuf::from(path)),
        (None, Some(_)) => Some(beside(key_path)),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "07de4306352562a212928f5f8228b4f027af4856ae0b17ea25c7de14a61639ec";
    const HOUR: i128 = LEAST_LEFT_NS;

    fn answer(key: &str, from: i128, until: i128) -> String {
        format!(
            r#"{{"organisation":"0f6e0c5e-3c1a-4a55-9d4a-2f0b1c9e8a77","method":"machine-credential","publicKey":"{key}","validFromNanos":"{from}","validUntilNanos":"{until}","leafHash":"ab"}}"#
        )
    }

    fn written(name: &str, text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "timewitness-certificate-{name}-{}.certificate",
            std::process::id()
        ));
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn nothing_asks_for_a_certificate_until_certification_begins_or_a_caller_names_one() {
        assert_eq!(needed(None, None, "agent.key"), None);
        assert_eq!(
            needed(Some(1), None, "agent.key"),
            Some(PathBuf::from("agent.key.certificate"))
        );
        assert_eq!(
            needed(None, Some("mine.certificate"), "agent.key"),
            Some(PathBuf::from("mine.certificate"))
        );
    }

    #[test]
    fn a_certificate_the_app_answers_with_is_kept_and_read_back() {
        let kept = from_the_app(answer(KEY, 10 * HOUR, 20 * HOUR).as_bytes(), KEY).unwrap();
        let path = written("kept", &kept);
        let held = current(&path, KEY, 11 * HOUR).unwrap();
        assert_eq!(held.until, 20 * HOUR);
        assert_eq!(held.organisation, "0f6e0c5e-3c1a-4a55-9d4a-2f0b1c9e8a77");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_certificate_for_another_key_is_refused_from_the_app_and_from_disk() {
        let other = "11".repeat(32);
        assert!(from_the_app(answer(&other, 0, HOUR * 5).as_bytes(), KEY).is_err());
        let path = written("other", &answer(&other, 0, HOUR * 5));
        assert!(current(&path, KEY, HOUR)
            .unwrap_err()
            .contains("is for the key"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_window_not_open_ended_or_under_an_hour_from_its_end_is_refused_and_said() {
        let path = written("windows", &answer(KEY, 10 * HOUR, 20 * HOUR));
        assert!(current(&path, KEY, 9 * HOUR)
            .unwrap_err()
            .contains("not opened"));
        assert!(current(&path, KEY, 20 * HOUR)
            .unwrap_err()
            .contains("ended"));
        assert!(current(&path, KEY, 20 * HOUR - HOUR / 2)
            .unwrap_err()
            .contains("30 minutes"));
        assert!(
            current(&path, KEY, 19 * HOUR).is_ok(),
            "exactly an hour left is enough"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn no_file_is_said_as_no_certificate() {
        let path = std::env::temp_dir().join("timewitness-certificate-none-at-all.certificate");
        assert!(current(&path, KEY, 0)
            .unwrap_err()
            .starts_with("there is no certificate"));
    }
}
