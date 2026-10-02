//! The module boundary, enforced rather than remembered.
//!
//! The repository layout document states which module may import which. A rule written only in a
//! document is a rule somebody breaks in six months without noticing, so this test reads the
//! workspace manifests and checks the dependency edges against the same list.
//!
//! The two edges that matter, and the reason this file exists at all:
//!
//! - the clock model may not depend on the receipt, so a change to the receipt format cannot alter
//!   how a bound is computed;
//! - the receipt may not depend on the clock model, so a receipt can be read by a verifier that has
//!   none of the agent in it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Which of our own crates each crate is allowed to depend on, directly.
const ALLOWED: &[(&str, &[&str])] = &[
    ("timewitness-core", &[]),
    ("timewitness-sources", &["timewitness-core"]),
    (
        "timewitness-clock",
        &["timewitness-core", "timewitness-sources"],
    ),
    ("timewitness-platform", &["timewitness-core"]),
    ("timewitness-receipt", &["timewitness-core"]),
    // The resident agent joins the clock model to the machine it runs on and to the boundary a
    // stamp reaches it over, so it is the one crate below the command line that sees all four. It
    // depends on the receipt because a reading crosses the boundary in the receipt's own frozen
    // format rather than in a second one written for this, and the receipt still knows nothing
    // about it: the edge goes this way and never the other, which the two tests below check.
    (
        "timewitness-agent",
        &[
            "timewitness-core",
            "timewitness-sources",
            "timewitness-clock",
            "timewitness-platform",
            "timewitness-receipt",
        ],
    ),
    (
        "timewitness-verify",
        &["timewitness-core", "timewitness-receipt"],
    ),
    (
        "timewitness-verify-web",
        &[
            "timewitness-core",
            "timewitness-receipt",
            "timewitness-verify",
        ],
    ),
    (
        "timewitness-cli",
        &[
            "timewitness-core",
            "timewitness-sources",
            "timewitness-clock",
            "timewitness-platform",
            "timewitness-agent",
            "timewitness-receipt",
            "timewitness-verify",
            // What `timewitness roughtime-serve` runs. The subcommand holds a clock model
            // disciplined exactly as the agent's is and hands the server a reading per request,
            // because the server refuses to decide its own uncertainty.
            "timewitness-roughtime-server",
            // What `timewitness countersign` reads. The subcommand takes one half of an exchange
            // off the command line and says what it establishes, which is the same kind of local,
            // network-free check `verify` is.
            "timewitness-countersign",
        ],
    ),
    ("timewitness-architecture", &[]),
    // A Roughtime server of our own. It is a leaf on core and deliberately nothing more: the wire
    // format lives in core beside the checker that reads it, and everything here is about running
    // a server rather than about the format. It knows nothing of the clock model, so it cannot
    // quietly decide its own uncertainty; a caller hands it a reading and it refuses without one.
    ("timewitness-roughtime-server", &["timewitness-core"]),
];

fn workspace_root() -> PathBuf {
    // This crate sits at crates/architecture, so the workspace root is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the architecture crate should sit two levels below the workspace root")
        .to_path_buf()
}

/// The three kinds of dependency table Cargo has.
const DEPENDENCY_KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// What a table heading in a manifest turns out to be.
enum Table<'a> {
    /// A table whose keys are dependency names.
    Dependencies,
    /// A table describing one dependency, whose name is on the heading itself.
    OneDependency(&'a str),
    /// A table that has nothing to do with dependencies.
    Other,
}

/// Work out what a table heading is, or say why this parser will not guess.
///
/// The forms it knows, and Cargo has no others that declare a dependency:
///
/// - `[dependencies]` and its dev and build variants, whose keys are the dependency names;
/// - `[workspace.dependencies]`, the same thing at the root;
/// - `[target.'cfg(windows)'.dependencies]`, the same thing under a condition;
/// - `[dependencies.some-crate]`, and the same under a target, where the crate is named on the
///   heading and the keys underneath are its own fields rather than dependency names.
///
/// Anything else whose heading mentions a dependency table is an error rather than a table to skip.
/// That direction matters: a heading this parser does not recognise and quietly walks past is a
/// dependency the boundary is not enforced against, and the whole point of the file is that the two
/// edges it guards cannot be crossed by accident.
fn classify(heading: &str) -> Result<Table<'_>, String> {
    let segments: Vec<&str> = heading.split('.').map(str::trim).collect();

    if let Some(i) = segments
        .iter()
        .position(|s| DEPENDENCY_KINDS.contains(&s.trim_matches(['\'', '"'])))
    {
        let last = segments.len() - 1;
        if i == last {
            return Ok(Table::Dependencies);
        }
        if i == last - 1 {
            return Ok(Table::OneDependency(segments[last]));
        }
        return Err(format!(
            "[{heading}] names a dependency table and then keeps going, and this parser will not \
             guess what the rest of it means"
        ));
    }

    // Nothing matched a kind exactly. A heading that still looks like a dependency table is a
    // spelling this parser has not been taught, and a boundary guard that skips what it does not
    // understand is a boundary guard that passes.
    if segments
        .iter()
        .any(|s| s.trim_matches(['\'', '"']).ends_with("dependencies"))
    {
        return Err(format!(
            "[{heading}] looks like a dependency table and is not one this parser knows"
        ));
    }

    Ok(Table::Other)
}

/// The `timewitness-*` dependencies named in one manifest.
///
/// A deliberately small parser rather than a TOML crate. It walks the file line by line and takes
/// every dependency on one of our own crates, whether it is declared as a key inside a dependency
/// table or as a table of its own. The manifests in this workspace are written by hand and stay
/// simple, and a dependency added in a shape this parser cannot see is itself worth catching, so an
/// unrecognised heading fails the test rather than being skipped.
///
/// It skipped them until 2026-09-07, and the doc comment here claimed the opposite. A dependency
/// under `[target."cfg(windows)".dependencies]` was invisible, which is the exact shape the network
/// clients will arrive in.
fn own_dependencies(manifest: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", manifest.display()));
    dependencies_in(&text, manifest)
}

/// The same, over text already in hand, so the parser can be tested on manifests that do not exist.
fn dependencies_in(text: &str, manifest: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut in_dependencies = false;

    for raw in text.lines() {
        let line = raw.trim();
        if let Some(heading) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            match classify(heading.trim()) {
                Ok(Table::Dependencies) => in_dependencies = true,
                Ok(Table::OneDependency(name)) => {
                    in_dependencies = false;
                    let name = name.trim_matches(['\'', '"']);
                    if name.starts_with("timewitness-") {
                        found.insert(name.to_string());
                    }
                }
                Ok(Table::Other) => in_dependencies = false,
                Err(why) => panic!("{}: {why}", manifest.display()),
            }
            continue;
        }
        if !in_dependencies || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if key.starts_with("timewitness-") {
            found.insert(key.to_string());
        }
    }

    found
}

fn manifest_for(crate_dir: &str) -> PathBuf {
    workspace_root()
        .join("crates")
        .join(crate_dir)
        .join("Cargo.toml")
}

fn dir_for(package: &str) -> &'static str {
    match package {
        "timewitness-core" => "core",
        "timewitness-sources" => "sources",
        "timewitness-clock" => "clock",
        "timewitness-platform" => "platform",
        "timewitness-agent" => "agent",
        "timewitness-receipt" => "receipt",
        "timewitness-verify" => "verify",
        "timewitness-verify-web" => "verify-web",
        "timewitness-cli" => "cli",
        "timewitness-architecture" => "architecture",
        "timewitness-roughtime-server" => "roughtime-server",
        other => panic!("no directory recorded for {other}"),
    }
}

#[test]
fn every_crate_imports_only_what_the_layout_allows() {
    for (package, allowed) in ALLOWED {
        let allowed: BTreeSet<String> = allowed.iter().map(|s| (*s).to_string()).collect();
        let actual = own_dependencies(&manifest_for(dir_for(package)));

        let extra: Vec<_> = actual.difference(&allowed).cloned().collect();
        assert!(
            extra.is_empty(),
            "{package} depends on {extra:?}, which the repository layout does not allow"
        );
    }
}

#[test]
fn only_the_platform_crate_is_allowed_unsafe_code() {
    // The workspace forbids it and every crate inherits that by writing `[lints] workspace = true`.
    // Two crates write their own lint table instead and each says in its manifest why. The verifier
    // for the page cannot meet `forbid` at all, because exporting a function to WebAssembly uses an
    // attribute this compiler classes as unsafe, so it denies and allows that attribute on four
    // named functions; it writes no unsafe block. The platform crate does write them, two of them,
    // because the counters it reads have no safe interface in the standard library.
    //
    // So there are two lists here and only the second one matters. A crate stepping out of the
    // workspace lints is worth noticing; a crate actually writing unsafe code is the thing being
    // guarded.
    let mut exceptions = Vec::new();
    for (package, _) in ALLOWED {
        let dir = dir_for(package);
        let text = fs::read_to_string(manifest_for(dir))
            .unwrap_or_else(|e| panic!("could not read the manifest for {package}: {e}"));
        let inherits = text
            .lines()
            .map(str::trim)
            .any(|line| line == "workspace = true" || line == "workspace=true");
        if !inherits {
            exceptions.push(*package);
        }
    }
    exceptions.sort_unstable();
    assert_eq!(
        exceptions,
        vec!["timewitness-platform", "timewitness-verify-web"],
        "the crates not inheriting the workspace lints, each of which says in its manifest why"
    );

    let platform = fs::read_to_string(manifest_for("platform")).expect("the manifest is there");
    assert!(
        !platform.contains("unsafe_code = \"allow\""),
        "the platform crate takes the exception by not forbidding unsafe, not by allowing it, so \
         that a reader of the manifest sees a lint table with something missing rather than a line \
         switching a guard off"
    );

    let mut with_unsafe = Vec::new();
    for (package, _) in ALLOWED {
        // This crate is the one doing the looking, and the words it looks for are written in its
        // own source. Skipping it is the only way a check phrased as a grep can check itself.
        if *package == "timewitness-architecture" {
            continue;
        }
        let dir = workspace_root().join("crates").join(dir_for(package));
        let mut found = false;
        walk(&dir, &mut |path| {
            if path.extension().is_some_and(|e| e == "rs") {
                let Ok(text) = fs::read_to_string(path) else {
                    return;
                };
                if text.contains("unsafe {") || text.contains("unsafe fn") {
                    found = true;
                }
            }
        });
        if found {
            with_unsafe.push(*package);
        }
    }
    assert_eq!(
        with_unsafe,
        vec!["timewitness-platform"],
        "the crates that actually write unsafe code"
    );
}

#[test]
fn the_clock_model_does_not_know_what_a_receipt_is() {
    let clock = own_dependencies(&manifest_for("clock"));
    assert!(
        !clock.contains("timewitness-receipt"),
        "the clock model must not depend on the receipt crate"
    );
}

#[test]
fn the_receipt_does_not_know_how_the_bound_was_computed() {
    let receipt = own_dependencies(&manifest_for("receipt"));
    assert!(
        !receipt.contains("timewitness-clock"),
        "the receipt crate must not depend on the clock model"
    );
    assert!(
        !receipt.contains("timewitness-sources"),
        "the receipt crate must not depend on the source pool"
    );
}

#[test]
fn the_verifier_does_not_need_the_agent() {
    let verify = own_dependencies(&manifest_for("verify"));
    assert!(
        !verify.contains("timewitness-clock"),
        "the verifier must not depend on the clock model"
    );
    assert!(
        !verify.contains("timewitness-sources"),
        "the verifier must not depend on the source pool"
    );
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "target" {
            continue;
        }
        if path.is_dir() {
            walk(&path, f);
        } else {
            f(&path);
        }
    }
}

// ---------------------------------------------------------------------------
// The parser's own tests, because a guard nobody tests is a guard nobody has
// ---------------------------------------------------------------------------

#[test]
fn every_shape_a_dependency_can_be_declared_in_is_seen() {
    let manifest = "\
[package]
name = \"example\"

[dependencies]
timewitness-core = { path = \"../core\" }
serde = \"1\"

[dev-dependencies]
timewitness-receipt = { path = \"../receipt\" }

[dependencies.timewitness-verify]
path = \"../verify\"

[target.\"cfg(windows)\".dependencies]
timewitness-clock = { path = \"../clock\" }

[target.'cfg(unix)'.dependencies.timewitness-sources]
path = \"../sources\"

[package.metadata.docs.rs]
all-features = true
";
    let found = dependencies_in(manifest, Path::new("<in memory>"));
    let mut names: Vec<&str> = found.iter().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "timewitness-clock",
            "timewitness-core",
            "timewitness-receipt",
            "timewitness-sources",
            "timewitness-verify",
        ],
        "a dependency declared in one of Cargo's shapes was not seen"
    );
}

#[test]
fn a_dependency_inside_a_target_table_is_not_invisible() {
    // The shape the network clients will arrive in, and the one that was silently skipped. Kept
    // separate from the sweep above because this is the specific hole rather than the general case.
    let manifest = "[target.\"cfg(windows)\".dependencies]\ntimewitness-receipt = \"0.1\"\n";
    assert!(dependencies_in(manifest, Path::new("<in memory>")).contains("timewitness-receipt"));
}

#[test]
fn the_fields_of_one_dependency_are_not_read_as_dependencies() {
    // Inside `[dependencies.some-crate]` the keys are that crate's own fields. A parser that read
    // them as dependency names would invent edges that are not there.
    let manifest = "[dependencies.timewitness-core]\npath = \"../core\"\nfeatures = []\n";
    let found = dependencies_in(manifest, Path::new("<in memory>"));
    assert_eq!(found.len(), 1);
    assert!(found.contains("timewitness-core"));
}

#[test]
#[should_panic(expected = "looks like a dependency table")]
fn a_dependency_heading_this_parser_does_not_know_fails_the_build() {
    dependencies_in(
        "[weird-dependencies]\ntimewitness-core = \"0.1\"\n",
        Path::new("x"),
    );
}

#[test]
#[should_panic(expected = "keeps going")]
fn a_dependency_heading_with_more_after_it_than_a_name_fails_the_build() {
    dependencies_in(
        "[dependencies.timewitness-core.metadata]\nx = 1\n",
        Path::new("x"),
    );
}

#[test]
fn an_ordinary_table_is_not_mistaken_for_a_dependency_table() {
    let manifest = "[package]\nname = \"x\"\n\n[lints.rust]\nunsafe_code = \"forbid\"\n";
    assert!(dependencies_in(manifest, Path::new("<in memory>")).is_empty());
}
