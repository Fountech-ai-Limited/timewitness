//! What the operating system said when a file could not be read or written, in words a person can
//! act on.
//!
//! Its own sentence ends in a code, "(os error 2)", which tells a stranger nothing, and on Windows a
//! folder given where a file was wanted reads "Access is denied", which is the wrong reason: nothing
//! was denied, a folder is not a file. Until 2026-09-25 every refusal of the command line passed that
//! sentence on as it came. These say what happened, name the path, and never end in a code.

use std::io::{Error, ErrorKind};
use std::path::Path;

/// Why `path` could not be read, as a whole sentence naming it.
#[must_use]
pub fn unreadable(path: &Path, error: &Error) -> String {
    let shown = path.display();
    if path.is_dir() {
        return format!("{shown} is a folder, and a file is needed there");
    }
    match error.kind() {
        ErrorKind::NotFound => format!("there is no file at {shown}"),
        ErrorKind::PermissionDenied => {
            format!("{shown} could not be read: this account is not allowed to read it")
        }
        ErrorKind::InvalidData => format!("{shown} could not be read as text"),
        _ => format!("{shown} could not be read: {}", plain(error)),
    }
}

/// Why `path` could not be written, as a whole sentence naming it.
#[must_use]
pub fn unwritable(path: &Path, error: &Error) -> String {
    let shown = path.display();
    if let Some(folder) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !folder.is_dir() {
            return format!(
                "{shown} could not be written: there is no folder at {}",
                folder.display()
            );
        }
    }
    if path.is_dir() {
        return format!("{shown} is a folder, and a file is needed there");
    }
    match error.kind() {
        ErrorKind::PermissionDenied => {
            format!("{shown} could not be written: this account is not allowed to write there")
        }
        _ => format!("{shown} could not be written: {}", plain(error)),
    }
}

/// The operating system's own sentence without the code it ends in, and without its full stop, so
/// it sits inside a sentence of ours.
fn plain(error: &Error) -> String {
    let said = error.to_string();
    let said = match said.rfind(" (os error ") {
        Some(at) => &said[..at],
        None => said.as_str(),
    };
    said.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let folder = std::env::temp_dir().join(format!("tw-files-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }

    #[test]
    fn a_missing_file_a_folder_and_a_missing_folder_are_each_called_what_they_are() {
        let folder = scratch("read");
        let missing = folder.join("no-such-file.cbor");
        let e = std::fs::read(&missing).unwrap_err();
        let said = unreadable(&missing, &e);
        assert!(said.starts_with("there is no file at "), "{said}");
        assert!(!said.contains("os error"), "{said}");

        let e = std::fs::read(&folder).unwrap_err();
        let said = unreadable(&folder, &e);
        assert!(
            said.ends_with("is a folder, and a file is needed there"),
            "{said}"
        );
        assert!(!said.contains("denied"), "{said}");

        let out = folder.join("nope").join("receipt.cbor");
        let e = std::fs::write(&out, b"x").unwrap_err();
        let said = unwritable(&out, &e);
        assert!(said.contains("there is no folder at "), "{said}");
        assert!(!said.contains("os error"), "{said}");
    }

    #[test]
    fn a_code_is_taken_off_the_end_of_whatever_else_the_system_says() {
        let e = Error::from_raw_os_error(28);
        assert!(!plain(&e).contains("os error"), "{}", plain(&e));
        assert!(!plain(&e).ends_with('.'), "{}", plain(&e));
    }
}
