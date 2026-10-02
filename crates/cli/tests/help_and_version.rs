//! The first thing a stranger types, and what it answers.
//!
//! Since 2026-09-14 anybody can build this tool from the public repository, and the first thing most
//! people type at a tool they have just built is `--help`. Until 2026-09-15 that was the one form
//! that printed nothing useful: `--help` and `--version` before a subcommand were refused as options
//! with nothing to apply to, and `-h` and `help` were refused as subcommands this does not have, all
//! with exit 2. There was no way to ask the tool which verifier it is, which is the first question a
//! reader of a `v0` receipt has.
//!
//! So these read the shipped binary, the same way a stranger would meet it.

use std::process::{Command, Output};

use timewitness_receipt::FORMAT_VERSION;

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The line the usage opens its first subcommand with, which only the usage prints.
const USAGE: &str = "timewitness verify <receipt>";

#[test]
fn every_way_of_asking_for_help_prints_the_usage_and_succeeds() {
    for asked in [&["--help"][..], &["-h"], &["help"], &["verify", "--help"]] {
        let out = run(asked);
        let said = text(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{asked:?} exited {:?}: {}",
            out.status.code(),
            text(&out.stderr)
        );
        assert!(
            said.contains(USAGE),
            "{asked:?} did not print the usage: {said}"
        );
    }
}

/// The tag a manifest version is released under, worked out here from the string rather than with
/// the binary's own function, so a mistake in one is not repeated in the other.
fn tag_of(version: &str) -> String {
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let core = core.strip_suffix(".0").unwrap_or(core);
    match pre {
        Some(pre) => format!("v{core}-{pre}"),
        None => format!("v{core}"),
    }
}

#[test]
fn a_manifest_version_is_spelled_as_its_tag() {
    assert_eq!(tag_of("0.3.0"), "v0.3");
    assert_eq!(tag_of("0.3.1"), "v0.3.1");
    assert_eq!(tag_of("1.0.0"), "v1.0");
    assert_eq!(tag_of("0.4.0-rc.1"), "v0.4-rc.1");
}

#[test]
fn asking_which_version_names_the_build_and_the_format_it_reads() {
    for asked in [&["--version"][..], &["version"]] {
        let out = run(asked);
        let said = text(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{asked:?} exited {:?}: {}",
            out.status.code(),
            text(&out.stderr)
        );
        assert_eq!(
            said.lines().next(),
            Some(format!("timewitness {}", tag_of(env!("CARGO_PKG_VERSION"))).as_str()),
            "{asked:?} did not name the release the way its tag does: {said}"
        );
        assert!(
            said.contains(&format!("receipt format v{FORMAT_VERSION}")),
            "{asked:?} did not name the receipt format it reads: {said}"
        );
    }
}

#[test]
fn any_other_word_before_a_subcommand_is_still_refused_with_the_usage() {
    for asked in [
        "--helpme",
        "--versions",
        "--subject",
        "-x",
        "-v",
        "helps",
        "versions",
    ] {
        let out = run(&[asked]);
        let said = text(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{asked} exited {:?} and should be refused",
            out.status.code()
        );
        assert!(
            said.contains(USAGE),
            "{asked} was refused without the usage beside it: {said}"
        );
        assert!(
            out.stdout.is_empty(),
            "{asked} printed to standard output as though it had worked"
        );
    }
}
