//! Reading a command line, without a library to do it.
//!
//! The whole surface is three subcommands and a dozen options, so a parser is a few lines and a
//! dependency is a supply chain. The verifier in particular ships as a thing a stranger runs against
//! a receipt they were sent, and every crate it links is a crate they have to be comfortable with.

use std::collections::BTreeMap;

/// One command line, taken apart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Args {
    /// The subcommand, where one was given.
    pub command: Option<String>,
    /// Everything that was not an option.
    pub positional: Vec<String>,
    /// Options that took a value.
    pub values: BTreeMap<String, String>,
    /// Options that did not.
    pub flags: Vec<String>,
}

/// Options that take a value after them. Anything else beginning with two dashes is a flag.
const TAKES_A_VALUE: &[&str] = &[
    "--subject",
    "--digest",
    "--anchors",
    "--key-log",
    "--min-width",
    "--key",
    "--out",
    "--rounds",
    "--gap",
    "--max-width",
    "--sequence",
    "--previous",
    "--label",
    "--agent",
    "--endpoint",
    "--interval",
    "--bind",
    "--log",
    "--add",
    "--from",
    "--until",
    "--sign",
    "--kept-log",
    "--key-log-signer",
    "--role",
    "--retire",
    "--at",
];

/// What each subcommand accepts, and how many things it takes that are not options.
///
/// The list is what is allowed rather than what is forbidden, so an option nobody has thought about
/// is refused instead of being read as a flag and dropped. That is the direction that fails safe on
/// a tool whose whole job is saying what it checked.
pub const ACCEPTED: &[(&str, &[&str], usize)] = &[
    (
        "verify",
        &[
            "--subject",
            "--digest",
            "--anchors",
            "--no-anchors",
            "--key-log",
            "--kept-log",
            "--key-log-signer",
            "--min-width",
            "--fields",
            "--json",
            "--quiet",
        ],
        1,
    ),
    (
        "stamp",
        &[
            "--subject",
            "--key",
            "--out",
            "--rounds",
            "--gap",
            "--max-width",
            "--sequence",
            "--previous",
            "--no-evidence",
            "--agent",
        ],
        0,
    ),
    ("agent", &["--endpoint", "--interval", "--max-width"], 0),
    (
        "roughtime-serve",
        &["--bind", "--key", "--interval", "--max-width"],
        0,
    ),
    (
        "key-log",
        &[
            "--log", "--add", "--role", "--label", "--from", "--until", "--retire", "--at",
            "--sign",
        ],
        0,
    ),
    ("cannot-prove", &[], 0),
];

/// Accepted everywhere, because refusing an unrecognised option would otherwise make this the one
/// thing a reader tries first and the one thing that stops working.
pub const HELP: &str = "--help";

/// Accepted everywhere for the same reason. Which verifier this is, and which receipt format it
/// reads, is the first question somebody holding a `v0` receipt has.
pub const VERSION: &str = "--version";

/// The words that ask for help or for the version where a subcommand would go. Until 2026-09-15
/// the first thing a stranger typed, `timewitness --help`, was refused as an option with nothing to
/// apply to, and `-h` and `help` as subcommands this does not have.
const ASKS_FOR_HELP: [&str; 3] = [HELP, "-h", "help"];
const ASKS_FOR_VERSION: [&str; 2] = [VERSION, "version"];

/// Why a command line could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgError(pub String);

impl core::fmt::Display for ArgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Take a command line apart.
pub fn parse(argv: &[String]) -> Result<Args, ArgError> {
    let mut args = Args::default();
    let mut rest = argv.iter();

    if let Some(first) = rest.next() {
        if ASKS_FOR_HELP.contains(&first.as_str()) {
            args.flags.push(HELP.to_string());
        } else if ASKS_FOR_VERSION.contains(&first.as_str()) {
            args.flags.push(VERSION.to_string());
        } else if first.starts_with("--") {
            return Err(ArgError(format!(
                "{first} came before a subcommand, and there is nothing for it to apply to"
            )));
        } else {
            args.command = Some(first.clone());
        }
    }

    while let Some(item) = rest.next() {
        if let Some(name) = item.strip_prefix("--").map(|_| item.as_str()) {
            if TAKES_A_VALUE.contains(&name) {
                let value = rest.next().ok_or_else(|| {
                    ArgError(format!(
                        "{name} needs a value after it and there is nothing there"
                    ))
                })?;
                args.values.insert(name.to_string(), value.clone());
            } else {
                args.flags.push(name.to_string());
            }
        } else {
            args.positional.push(item.clone());
        }
    }

    Ok(args)
}

impl Args {
    /// Whether a flag was given.
    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    /// The value of an option, where it was given.
    #[must_use]
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The value of an option, or a refusal naming it.
    pub fn required(&self, name: &str) -> Result<&str, ArgError> {
        self.value(name)
            .ok_or_else(|| ArgError(format!("{name} is needed and was not given")))
    }

    /// Whether the reader asked what this does.
    #[must_use]
    pub fn wants_help(&self) -> bool {
        self.flag(HELP)
    }

    /// Whether the reader asked which build this is.
    #[must_use]
    pub fn wants_version(&self) -> bool {
        self.flag(VERSION)
    }

    /// Refuse anything this subcommand does not have, by name.
    ///
    /// Without this a mistyped option is parsed as a flag nobody reads, so `verify --min-sources 9`
    /// prints that the receipt held and exits zero, and the reader believes their number was
    /// applied. That is the same fault as reporting held for a check that was never run.
    pub fn check_accepted(&self) -> Result<(), ArgError> {
        let Some(command) = self.command.as_deref() else {
            return Ok(());
        };
        let Some((_, accepted, positionals)) =
            ACCEPTED.iter().find(|(name, _, _)| *name == command)
        else {
            // Not a subcommand this tool has. Saying so is somebody else's job, and saying it twice
            // would bury the useful half.
            return Ok(());
        };

        for given in self.flags.iter().chain(self.values.keys()) {
            if given != HELP && given != VERSION && !accepted.contains(&given.as_str()) {
                return Err(ArgError(format!(
                    "{command} has no {given}. Run `timewitness` with nothing after it for what it does have"
                )));
            }
        }

        if self.positional.len() > *positionals {
            let extra = &self.positional[*positionals];
            return Err(ArgError(format!(
                "{command} takes {positionals} of those and was given {}, the first spare being {extra:?}",
                self.positional.len()
            )));
        }

        Ok(())
    }

    /// A whole number option.
    pub fn number(&self, name: &str) -> Result<Option<i128>, ArgError> {
        match self.value(name) {
            None => Ok(None),
            Some(text) => text.replace('_', "").parse().map(Some).map_err(|_| {
                ArgError(format!(
                    "{name} takes a whole number and was given {text:?}"
                ))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_subcommand_a_file_a_value_and_a_flag() {
        let args = parse(&argv(&[
            "verify",
            "receipt.cbor",
            "--subject",
            "build.tar",
            "--json",
        ]))
        .expect("a well-formed line");

        assert_eq!(args.command.as_deref(), Some("verify"));
        assert_eq!(args.positional, vec!["receipt.cbor".to_string()]);
        assert_eq!(args.value("--subject"), Some("build.tar"));
        assert!(args.flag("--json"));
        assert!(!args.flag("--quiet"));
    }

    #[test]
    fn an_option_with_nothing_after_it_refuses_rather_than_being_ignored() {
        // Being ignored is how somebody ends up checking a receipt against no subject while
        // believing they supplied one.
        let err = parse(&argv(&["verify", "receipt.cbor", "--subject"]))
            .expect_err("there is no file after it");
        assert!(err.0.contains("--subject"), "{}", err.0);
    }

    #[test]
    fn a_number_that_is_not_a_number_refuses() {
        let args = parse(&argv(&["verify", "--min-width", "wide"])).unwrap();
        assert!(args.number("--min-width").is_err());

        let args = parse(&argv(&["verify", "--min-width", "1_000"])).unwrap();
        assert_eq!(args.number("--min-width").unwrap(), Some(1_000));
    }

    #[test]
    fn an_option_the_subcommand_does_not_have_is_refused_by_name() {
        // The whole fault: this used to print that the receipt held and exit zero, so a reader who
        // meant to raise the floor and mistyped got an acceptance they believed was judged against
        // their number.
        let args = parse(&argv(&["verify", "receipt.cbor", "--min-sources", "9"])).unwrap();
        let err = args
            .check_accepted()
            .expect_err("verify has no --min-sources");
        assert!(err.0.contains("--min-sources"), "{}", err.0);

        let args = parse(&argv(&["verify", "receipt.cbor", "--not-a-flag"])).unwrap();
        let err = args.check_accepted().expect_err("nor a --not-a-flag");
        assert!(err.0.contains("--not-a-flag"), "{}", err.0);

        let args = parse(&argv(&["stamp", "--max-width", "1", "--anchors", "keys"])).unwrap();
        let err = args
            .check_accepted()
            .expect_err("--anchors is the verifier's");
        assert!(err.0.contains("--anchors"), "{}", err.0);
    }

    #[test]
    fn a_second_file_is_refused_rather_than_ignored() {
        let args = parse(&argv(&["verify", "one.cbor", "two.cbor"])).unwrap();
        let err = args
            .check_accepted()
            .expect_err("verify checks one receipt");
        assert!(err.0.contains("two.cbor"), "{}", err.0);
    }

    #[test]
    fn everything_each_subcommand_documents_is_accepted() {
        let verify = parse(&argv(&[
            "verify",
            "receipt.cbor",
            "--subject",
            "build.tar",
            "--anchors",
            "keys",
            "--no-anchors",
            "--min-width",
            "1000",
            "--key-log",
            "log",
            "--kept-log",
            "old",
            "--key-log-signer",
            "00",
            "--fields",
            "--json",
            "--quiet",
        ]))
        .unwrap();
        assert!(verify.check_accepted().is_ok());

        let key_log = parse(&argv(&[
            "key-log", "--log", "l", "--add", "k", "--role", "agent", "--label", "n", "--from",
            "1", "--until", "2", "--retire", "k", "--at", "3", "--sign", "s",
        ]))
        .unwrap();
        assert!(key_log.check_accepted().is_ok());

        let stamp = parse(&argv(&[
            "stamp",
            "--subject",
            "build.tar",
            "--key",
            "k",
            "--out",
            "r.cbor",
            "--rounds",
            "16",
            "--gap",
            "1",
            "--max-width",
            "1",
            "--sequence",
            "2",
            "--previous",
            "p.cbor",
            "--no-evidence",
        ]))
        .unwrap();
        assert!(stamp.check_accepted().is_ok());
    }

    #[test]
    fn help_is_accepted_on_every_subcommand() {
        for command in ["verify", "stamp", "cannot-prove"] {
            let args = parse(&argv(&[command, "--help"])).unwrap();
            assert!(args.check_accepted().is_ok(), "{command} refused --help");
            assert!(args.wants_help());
        }
    }

    #[test]
    fn an_option_before_a_subcommand_refuses() {
        let err = parse(&argv(&["--json", "verify"])).expect_err("nothing to apply it to");
        assert!(err.0.contains("--json"), "{}", err.0);
    }
}
