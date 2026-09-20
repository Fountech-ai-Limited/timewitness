//! Two paths need no account and no call to us, and this is what keeps them so.
//!
//! **Checking a receipt.** Generating one may one day go through a service of ours. Verifying one
//! never does: a stranger checks a receipt with no account, no network call to us and nothing of
//! ours in the loop, and a verifier that needed any of those would be a verifier we could switch
//! off.
//!
//! **Countersigning one.** The exchange is between two agents with nothing of ours in it, which is
//! what makes receiver-only mode free and the counterparty's cost zero. A receiver that had to ask
//! us anything would be a receiver we could charge, and the free half of the protocol would be free
//! until we changed our minds.
//!
//! Both hold today because nothing on either path could reach a network. The time that stops
//! holding is when something is built beside one of them and a key lookup, a token or a fallback to
//! our host finds its way in, so the check is written now rather than then.
//!
//! What counts as a path. The crates named as its roots, the WebAssembly build where there is one,
//! every crate any of those links, every file of the command line that its subcommand can reach,
//! and any page it is served in. The command line's files are found by reading them: from the arm
//! of `main.rs` that runs the subcommand, every module a reached file names is reached too, so a new
//! file it calls into is read the day it is added rather than the day somebody lists it. The rest of
//! the command line is not on either: the agent and the stamp talk to time sources by design, and
//! which of them may need an account is a separate question that is not settled.
//!
//! The countersign path was added on 2026-09-20, when the receive half was built. Until then the
//! promise that the exchange has nothing of ours in it was a sentence in a document and nothing
//! checked it. Both seeds below were watched turning the build red before it went in, and the same
//! seed was watched passing with the countersign entry taken out, which is what says the entry is
//! doing the work rather than the verify path happening to cover it.
//!
//! Three rules, and each names what it refuses and why, so an honest change that trips one can say
//! which rule it is arguing with:
//!
//! - nothing linked may be an HTTP client, a TLS stack, a socket runtime or a binding to the
//!   browser's fetch, checked by package name over the whole dependency closure;
//! - no source on the path may name `timewitness.dev` at all, open a socket, start another program,
//!   read the environment at run time or at build time, or bring in code from a file this check
//!   does not read;
//! - no source on the path may carry the name of a credential variable.
//!
//! The first version of this file, of 2026-09-14, read spellings rather than reach, and a test run
//! the same evening showed it: a spawned `curl`, a host built with `format!`, a module the command
//! line reached from a fifth file, a module loaded by `#[path]` from outside `src/` and an `env!`
//! read all stayed green. Each of those is now a seed below, and each was watched turning the build
//! red on a harness copy of the tree before this version went in.
//!
//! The network itself is the other half and it is not here. `scripts/verify-offline.sh` runs the
//! verifier in a process with no network at all and holds its verdict to the one it gives with a
//! network, which catches a path this file cannot see, such as a crate it has never heard of or a
//! host spelled so that no line of source holds it. The page has a half of its own too:
//! `scripts/verifier-page-offline.mjs` reads the page as built, module and all.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Where the command line's modules live, and the file it starts in.
const COMMAND_LINE_SRC: &str = "crates/cli/src";
const COMMAND_LINE_MAIN: &str = "main.rs";

/// The page the verifier module is served in. The built page embeds the module and is not tracked;
/// this is the source it is built from.
const PAGE: &str = "verifier-page/page.html";

/// One path this file holds to the three rules, with what it is called when it fails.
///
/// There are two of them and they make two different promises out of one set of rules, which is why
/// the promise is a field rather than a sentence in a message. A failure that said "the verify path"
/// about the countersign one would send a reader to the wrong claim.
struct Guarded {
    /// What the path is called in a failure.
    name: &'static str,
    /// The crates whose whole closure is on it.
    roots: &'static [&'static str],
    /// The subcommand whose reach through the command line is on it.
    subcommand: &'static str,
    /// The command line's modules the reach has to find, because they are the ones that subcommand
    /// runs through today. Finding fewer means the reader broke, not that the path got shorter.
    floor: &'static [&'static str],
    /// A file outside any crate that is part of the path, with how it is reached.
    extra: &'static [(&'static str, &'static str)],
    /// What the path promises, in the words a failure gives.
    promise: &'static str,
}

/// The two paths, and the second one arrived on 2026-09-20.
///
/// The verify path has been held here since 2026-09-14. The countersign path was not held by
/// anything until the receive half was built, and the promise it makes is the one the whole
/// peer-to-peer design rests on: the exchange is between two agents with nothing of ours in it, so a
/// receiver countersigns with no account and at no cost. A promise nothing checks is a promise that
/// is true until somebody adds a key lookup to it.
const PATHS: [Guarded; 2] = [
    Guarded {
        name: "the verify path",
        roots: &["timewitness-verify", "timewitness-verify-web"],
        subcommand: "verify",
        floor: &["verify_cmd", "args", "render", "as_json"],
        extra: &[(PAGE, "the page")],
        promise: "verifying needs no account and no call to anybody",
    },
    Guarded {
        name: "the countersign path",
        roots: &["timewitness-countersign"],
        subcommand: "countersign",
        floor: &["countersign_cmd", "args", "render"],
        extra: &[],
        promise: "a receiver countersigns with no account and nothing of ours in the exchange",
    },
];

/// Packages that exist to reach a network. Any one of them in the closure fails the build.
///
/// A list of what may not come in, which is the weaker direction, and it is chosen knowingly. The
/// closure has seventy-odd crates of arithmetic and a list of those would fail on every patch release.
/// What makes the weaker direction safe enough is the other half: a network client this list has
/// never heard of still fails the no-network run.
const NETWORK_PACKAGES: &[&str] = &[
    // HTTP clients.
    "reqwest",
    "hyper",
    "hyper-util",
    "ureq",
    "isahc",
    "curl",
    "curl-sys",
    "attohttpc",
    "minreq",
    "surf",
    "http-req",
    "ehttp",
    "h2",
    "h3",
    "quinn",
    "awc",
    "tungstenite",
    "websocket",
    // TLS stacks. Nothing on the path talks to anybody, so nothing on it needs to do so privately.
    "rustls",
    "rustls-webpki",
    "webpki",
    "native-tls",
    "openssl",
    "openssl-sys",
    "boring",
    "schannel",
    "security-framework",
    // Socket runtimes and resolvers.
    "tokio",
    "tokio-rustls",
    "async-std",
    "smol",
    "mio",
    "socket2",
    "trust-dns-resolver",
    "hickory-resolver",
    // The ways a WebAssembly module reaches the browser's own fetch. The page module is built
    // without any of them on purpose, so that it runs in a plain engine with nothing to import.
    "web-sys",
    "js-sys",
    "wasm-bindgen",
    "wasm-bindgen-futures",
    "gloo-net",
];

/// Words in a source file on the path that mean it could reach a network, with the reason given.
const SOURCE_RULES: &[(&str, &str)] = &[
    ("TcpStream", "opens a socket"),
    ("UdpSocket", "opens a socket"),
    ("TcpListener", "opens a socket"),
    ("ToSocketAddrs", "resolves a host name"),
    (
        "env::var",
        "reads the environment, which is where an account token would come from",
    ),
    (
        "env::vars",
        "reads the environment, which is where an account token would come from",
    ),
    (
        "env::{",
        "brings in part of the environment under a name this check cannot follow",
    ),
    (
        "Command::new",
        "starts another program, and that program can reach anything",
    ),
    (
        "process::Command",
        "starts another program, and that program can reach anything",
    ),
    (
        ".spawn(",
        "starts another program or thread, and a program can reach anything",
    ),
    (
        "#[path",
        "loads a module from a file of its own choosing, which this check never reads",
    ),
    (
        "include!(",
        "pastes in code from a file of its own choosing, which this check never reads",
    ),
    ("fetch(", "fetches from a network"),
    ("XMLHttpRequest", "fetches from a network"),
    ("WebSocket", "opens a connection"),
    ("EventSource", "opens a connection"),
    ("sendBeacon", "sends to a network"),
];

/// Environment variables a build may bake in. Cargo writes these from the manifest, which is in the
/// tree this check reads, so nothing of the building machine's own environment reaches the binary
/// through them. `--version` is the reason the door is open at all.
const BUILD_VARIABLES_ALLOWED: &str = "CARGO_PKG_";

/// Credential names. Only inside a string, so an identifier that happens to hold the word, such as
/// the part of a timestamp authority's answer called its token, is not caught.
const CREDENTIAL_WORDS: [&str; 5] = ["TOKEN", "API_KEY", "APIKEY", "SECRET", "PASSWORD"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the architecture crate should sit two levels below the workspace root")
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// The dependency closure
// ---------------------------------------------------------------------------

/// One package as `Cargo.lock` records it.
struct Locked {
    name: String,
    version: String,
    /// Whether it is one of ours. Ours have no `source` line.
    ours: bool,
    /// What the lock says it depends on, as `name` or `name version`.
    dependencies: Vec<String>,
}

/// Every package in the lock file.
///
/// A small reader rather than a TOML crate, for the reason the boundary test gives: the file is
/// written by Cargo in one shape, and a shape this reader does not recognise fails loudly.
fn locked_packages(text: &str) -> Vec<Locked> {
    let mut packages = Vec::new();
    let mut current: Option<Locked> = None;
    let mut in_dependencies = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            if let Some(done) = current.take() {
                packages.push(done);
            }
            current = Some(Locked {
                name: String::new(),
                version: String::new(),
                ours: true,
                dependencies: Vec::new(),
            });
            in_dependencies = false;
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
            } else {
                let entry = line.trim_end_matches(',').trim_matches('"');
                if !entry.is_empty() {
                    package.dependencies.push(entry.to_string());
                }
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("name = ") {
            package.name = value.trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("version = ") {
            package.version = value.trim_matches('"').to_string();
        } else if line.starts_with("source = ") {
            package.ours = false;
        } else if line == "dependencies = [" {
            in_dependencies = true;
        } else if line.starts_with("dependencies = [") {
            panic!("Cargo.lock lists dependencies in a shape this reader does not know: {line}");
        }
    }
    if let Some(done) = current {
        packages.push(done);
    }
    packages
}

/// The package names one of our manifests depends on for building and running, leaving out
/// development dependencies, which are never linked into what a reader runs.
///
/// A renamed dependency is followed to the package it names, because `sha2_for_bls` is not a crate
/// anybody could look up.
fn linked_dependencies(manifest: &str, path: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut in_table = false;
    let mut one: Option<String> = None;

    let finish = |one: &mut Option<String>, found: &mut BTreeSet<String>| {
        if let Some(name) = one.take() {
            found.insert(name);
        }
    };

    for raw in manifest.lines() {
        let line = raw.trim();
        if let Some(heading) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            finish(&mut one, &mut found);
            in_table = false;
            let segments: Vec<&str> = heading
                .split('.')
                .map(|s| s.trim().trim_matches(['\'', '"']))
                .collect();
            let kind = segments
                .iter()
                .position(|s| *s == "dependencies" || *s == "build-dependencies");
            match kind {
                Some(i) if i == segments.len() - 1 => in_table = true,
                Some(i) if i == segments.len() - 2 => one = Some(segments[i + 1].to_string()),
                Some(_) => panic!(
                    "{}: [{heading}] is a dependency heading this reader does not know",
                    path.display()
                ),
                None => {
                    let dev = segments.contains(&"dev-dependencies");
                    if !dev && segments.iter().any(|s| s.ends_with("dependencies")) {
                        panic!(
                            "{}: [{heading}] looks like a dependency table and is not one this \
                             reader knows",
                            path.display()
                        );
                    }
                }
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = one.as_mut() {
            if let Some(renamed) = package_field(line) {
                *name = renamed;
            }
            continue;
        }
        if !in_table {
            continue;
        }
        let key = line
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if key.is_empty() {
            continue;
        }
        found.insert(package_field(line).unwrap_or_else(|| key.to_string()));
    }
    finish(&mut one, &mut found);
    found
}

/// The value of a `package = "..."` field on a line, where there is one.
fn package_field(line: &str) -> Option<String> {
    let at = line.find("package")?;
    let rest = line[at + "package".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

fn manifest_path(package: &str) -> PathBuf {
    let dir = package
        .strip_prefix("timewitness-")
        .unwrap_or_else(|| panic!("{package} is not one of ours"));
    workspace_root().join("crates").join(dir).join("Cargo.toml")
}

/// Every package the verify path links, by name, each with the chain that brought it in.
///
/// Our own crates are followed through their manifests, because the lock file records development
/// dependencies for them too. Everybody else's are followed through the lock file, which records only
/// what they build with. Where the lock holds two versions of one name both are followed, which can
/// only ever refuse more.
fn closure(roots: &[&str]) -> BTreeMap<String, String> {
    let root = workspace_root();
    let lock = fs::read_to_string(root.join("Cargo.lock"))
        .unwrap_or_else(|e| panic!("could not read Cargo.lock: {e}"));
    let packages = locked_packages(&lock);

    let mut by_name: BTreeMap<&str, Vec<&Locked>> = BTreeMap::new();
    for package in &packages {
        by_name.entry(&package.name).or_default().push(package);
    }

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut queue: Vec<(String, String)> = roots
        .iter()
        .map(|r| ((*r).to_string(), (*r).to_string()))
        .collect();

    while let Some((name, chain)) = queue.pop() {
        if seen.contains_key(&name) {
            continue;
        }
        seen.insert(name.clone(), chain.clone());

        let candidates = by_name.get(name.as_str()).cloned().unwrap_or_default();
        let ours = candidates.iter().any(|p| p.ours) || name.starts_with("timewitness-");
        let next: BTreeSet<String> = if ours {
            let path = manifest_path(&name);
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
            linked_dependencies(&text, &path)
        } else {
            assert!(
                !candidates.is_empty(),
                "{name} is linked by {chain} and is not in Cargo.lock, so the lock is stale and this \
                 check cannot see what it brings in"
            );
            candidates
                .iter()
                .flat_map(|p| p.dependencies.iter())
                .map(|d| d.split(' ').next().unwrap_or(d).to_string())
                .collect()
        };
        for dependency in next {
            if !seen.contains_key(&dependency) {
                queue.push((dependency.clone(), format!("{chain} -> {dependency}")));
            }
        }
    }
    seen
}

// ---------------------------------------------------------------------------
// The sources on the path
// ---------------------------------------------------------------------------

/// Every source file on one path, each with how it was reached.
fn path_sources(path: &Guarded, linked: &BTreeMap<String, String>) -> BTreeMap<PathBuf, String> {
    let root = workspace_root();
    let mut files = BTreeMap::new();
    for (name, chain) in linked.iter().filter(|(n, _)| n.starts_with("timewitness-")) {
        let dir = manifest_path(name)
            .parent()
            .expect("a manifest sits in a directory")
            .to_path_buf();
        let build_script = dir.join("build.rs");
        let mut found = Vec::new();
        if build_script.is_file() {
            found.push(build_script);
        }
        collect(&dir.join("src"), &mut found);
        for file in found {
            files.entry(file).or_insert_with(|| chain.clone());
        }
    }

    let src = root.join(COMMAND_LINE_SRC);
    let reached = command_line_reach(path.subcommand, |relative| {
        fs::read_to_string(src.join(relative)).ok()
    });
    for module in path.floor {
        assert!(
            reached.contains_key(*module),
            "the command line's {module} was not reached from the arm that runs `{}`, and it \
             is on {} today, so the reader below has stopped seeing what it should",
            path.subcommand,
            path.name
        );
    }
    for (module, (relative, chain)) in &reached {
        let path = src.join(relative);
        assert!(
            path.is_file(),
            "{module} was reached and {relative} is not there"
        );
        files.insert(path, chain.clone());
    }

    for (relative, how) in path.extra {
        let file = root.join(relative);
        assert!(
            file.is_file(),
            "{relative} is named as part of {} and is not there; if it moved, tell this check \
             where it went rather than dropping it",
            path.name
        );
        files.insert(file, (*how).to_string());
    }
    files
}

// ---------------------------------------------------------------------------
// The command line's reach
// ---------------------------------------------------------------------------

/// Every module of the command line that `timewitness verify` can reach, keyed by its path inside
/// the crate, with the file it lives in and the chain of modules that reached it.
///
/// It starts from `main.rs`, which always runs, and from the module its `verify` arm calls. It
/// follows what `main.rs` names outside the arms that run some other subcommand, and from every
/// reached file it follows each `crate::` path, each `super::` path and each `mod` declaration. A
/// `crate::*` reaches every module there is. A top-level name it reaches whose file is not there
/// fails the check by name, so a shape this reader does not know refuses rather than passes.
///
/// `read` takes a path relative to the crate's `src/` and gives the file's text, which is what lets
/// the test below hand it a crate that lives only in memory.
fn command_line_reach(
    subcommand: &str,
    read: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, (String, String)> {
    let main = read(COMMAND_LINE_MAIN)
        .unwrap_or_else(|| panic!("{COMMAND_LINE_SRC}/{COMMAND_LINE_MAIN} could not be read"));
    let declared = declared_modules(&main);

    let arm = arm_for(subcommand, &main, &declared).unwrap_or_else(|| {
        panic!(
            "{COMMAND_LINE_MAIN} has no arm this check can read that runs `{subcommand}` as \
             `Some(\"{subcommand}\") => module::...`; if the dispatch changed shape, teach this \
             reader the new one rather than listing files"
        )
    });

    let mut reached: BTreeMap<String, (String, String)> = BTreeMap::new();
    reached.insert(
        String::new(),
        (COMMAND_LINE_MAIN.to_string(), COMMAND_LINE_MAIN.to_string()),
    );

    let mut queue: Vec<(String, String)> = vec![(
        arm.clone(),
        format!("{COMMAND_LINE_MAIN} -> {arm}, the arm that runs {subcommand}"),
    )];
    for name in named_by_main(subcommand, &main, &declared) {
        queue.push((name.clone(), format!("{COMMAND_LINE_MAIN} -> {name}")));
    }

    while let Some((module, chain)) = queue.pop() {
        if module.is_empty() || reached.contains_key(&module) {
            continue;
        }
        let file = module_file(&module, &read);
        let Some(text) = read(&file) else {
            // Below the top level, `super::name` is as likely to be an item of the parent as a
            // module beside it, and the parent is read already. At the top level every name here
            // is a declared module, so a missing file is kept and fails the check by name.
            if module.contains("::") {
                continue;
            }
            reached.insert(module.clone(), (file, chain.clone()));
            continue;
        };
        reached.insert(module.clone(), (file, chain.clone()));
        for next in modules_named_in(&text, &module, &declared) {
            if !reached.contains_key(&next) {
                queue.push((next.clone(), format!("{chain} -> {next}")));
            }
        }
    }
    reached
}

/// The modules `main.rs` declares, by name.
fn declared_modules(main: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in main.lines() {
        if let Some(name) = mod_declaration(line) {
            found.insert(name);
        }
    }
    found
}

/// The module a `mod name;` line declares, where the line is one.
fn mod_declaration(line: &str) -> Option<String> {
    let line = line.trim();
    let rest = line
        .strip_prefix("pub mod ")
        .or_else(|| line.strip_prefix("pub(crate) mod "))
        .or_else(|| line.strip_prefix("mod "))?;
    let name = rest.strip_suffix(';')?.trim();
    identifier(name).then(|| name.to_string())
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !text.starts_with(|c: char| c.is_ascii_digit())
}

/// The module the named arm of the dispatch calls.
fn arm_for(subcommand: &str, main: &str, declared: &BTreeSet<String>) -> Option<String> {
    let arm = format!("Some(\"{subcommand}\") =>");
    let line = main.lines().find(|l| l.contains(&arm))?;
    let after = &line[line.find(&arm)? + arm.len()..];
    let name = after.trim_start().split("::").next()?.trim();
    declared.contains(name).then(|| name.to_string())
}

/// The declared modules `main.rs` names outside the arms that run another subcommand.
///
/// Those arms are the one place `main.rs` names a module this path does not run. An arm is
/// recognised by its opening, `Some("name") =>`, and only its opening line is set aside; an arm
/// written over several lines puts its module on the path, which refuses more rather than less.
fn named_by_main(subcommand: &str, main: &str, declared: &BTreeSet<String>) -> BTreeSet<String> {
    let kept: String = main
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            let other_arm = trimmed.starts_with("Some(\"")
                && trimmed.contains("\") =>")
                && !trimmed.starts_with(&format!("Some(\"{subcommand}\")"));
            if other_arm || mod_declaration(line).is_some() {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut found = modules_named_in(&kept, "", declared);
    for line in kept.lines() {
        for name in declared {
            if names_path_start(line, name) {
                found.insert(name.clone());
            }
        }
    }
    found
}

/// Whether a line uses `name::` as the start of a path, rather than as the tail of a longer one.
fn names_path_start(line: &str, name: &str) -> bool {
    let needle = format!("{name}::");
    let mut from = 0;
    while let Some(offset) = line[from..].find(&needle) {
        let at = from + offset;
        let before = line[..at].chars().next_back();
        let tail_of_longer =
            before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
        if !tail_of_longer {
            return true;
        }
        from = at + needle.len();
    }
    false
}

/// The modules a file names: each `crate::` path, each `super::` path and each `mod` declaration,
/// resolved against `module`, which is the file's own path inside the crate, empty for `main.rs`.
///
/// `super::` means the parent of the file's module at the top level of the file, and the file's own
/// module inside an inline `mod name { ... }`, which is where every test module's `use super::*;`
/// sits. A glob of the crate root reaches every module; a glob of anything else reaches nothing the
/// `mod` declarations below do not already.
fn modules_named_in(text: &str, module: &str, declared: &BTreeSet<String>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let parent = module.rsplit_once("::").map_or("", |(p, _)| p);
    let inline = inline_module_spans(text);

    for prefix in ["crate::", "super::"] {
        let mut from = 0;
        while let Some(offset) = text[from..].find(prefix) {
            let at = from + offset + prefix.len();
            from = at;
            let base = if prefix == "crate::" {
                ""
            } else if inline.iter().any(|(s, e)| (*s..*e).contains(&at)) {
                module
            } else {
                parent
            };
            let rest = &text[at..];
            let items = if let Some(group) = rest.strip_prefix('{') {
                top_level_items(group)
            } else {
                vec![rest.to_string()]
            };
            for item in items {
                if item.starts_with('*') {
                    if base.is_empty() {
                        found.extend(declared.iter().cloned());
                    }
                } else if let Some(first) = first_segment(&item) {
                    found.insert(join(base, &first));
                }
            }
        }
    }

    if !module.is_empty() {
        for line in text.lines() {
            if let Some(child) = mod_declaration(line) {
                found.insert(join(module, &child));
            }
        }
    }

    // A path such as `crate::helper` names something in `main.rs` rather than a module, and
    // `main.rs` is read already. Only a name that is a module goes further.
    found.retain(|m| {
        let top = m.split("::").next().unwrap_or(m);
        !m.is_empty() && top != "self" && (declared.contains(top) || m.contains("::"))
    });
    found
}

/// The byte ranges of the inline modules in a file, each from its opening brace to its closing one.
///
/// Braces inside a string or a comment are skipped, well enough for source that compiles, and an
/// inline module this misreads only moves where `super::` points, never whether a file is read.
fn inline_module_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let code = line.split("//").next().unwrap_or(line).trim();
        let opens = code
            .strip_prefix("pub ")
            .unwrap_or(code)
            .strip_prefix("mod ")
            .and_then(|r| r.strip_suffix('{'))
            .is_some_and(|name| identifier(name.trim()));
        if opens {
            let start = offset + line.rfind('{').unwrap_or(0);
            spans.push((start, matching_brace(text, start)));
        }
        offset += line.len();
    }
    spans
}

/// Where the brace opened at `start` closes, or the end of the text if it never does.
fn matching_brace(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            // A character literal, such as the `'{'` a parser holds, rather than a lifetime.
            b'\'' if bytes.get(i + 1) == Some(&b'\\') => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\'' {
                    i += 1;
                }
            }
            b'\'' if bytes.get(i + 2) == Some(&b'\'') => i += 2,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// The items of a `{ ... }` group, split at its own commas and not at those of a nested group.
fn top_level_items(group: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for c in group.chars() {
        match c {
            '{' => {
                depth += 1;
                current.push(c);
            }
            '}' if depth == 0 => break,
            '}' => {
                depth -= 1;
                current.push(c);
            }
            ',' if depth == 0 => items.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    items.push(current);
    items
        .into_iter()
        .map(|i| i.trim().to_string())
        .filter(|i| !i.is_empty())
        .collect()
}

/// The first segment of a path, where it starts with a name.
fn first_segment(path: &str) -> Option<String> {
    let name: String = path
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    identifier(&name).then_some(name)
}

fn join(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}::{name}")
    }
}

/// The file a module lives in, relative to `src/`: `a/b.rs` where it exists, `a/b/mod.rs` otherwise.
fn module_file(module: &str, read: &impl Fn(&str) -> Option<String>) -> String {
    let stem = module.replace("::", "/");
    let flat = format!("{stem}.rs");
    if read(&flat).is_some() {
        flat
    } else {
        format!("{stem}/mod.rs")
    }
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, files);
        } else if path
            .extension()
            .is_some_and(|e| e == "rs" || e == "html" || e == "js")
        {
            files.push(path);
        }
    }
}

/// What is wrong with one file's text, one line per finding, each naming the line and the reason.
fn findings(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let at = number + 1;
        if let Some(host) = our_host(line) {
            found.push(format!(
                "line {at}: names {host}, and a path held here may not know any address of ours"
            ));
        }
        for (word, why) in SOURCE_RULES {
            if line.contains(word) {
                found.push(format!("line {at}: `{word}` {why}"));
            }
        }
        if let Some(variable) = baked_variable(line) {
            found.push(format!(
                "line {at}: bakes {variable} into the build, and what the building machine's \
                 environment holds is where a service address or a token would come from"
            ));
        }
        if line.contains("process::{") && line.contains("Command") {
            found.push(format!(
                "line {at}: brings in `Command`, which starts another program, and that program can \
                 reach anything"
            ));
        }
        if host_import_block(line) {
            found.push(format!(
                "line {at}: declares a function the host provides, which on the page is the \
                 browser and on the command line is the system, and either can reach a network"
            ));
        }
        for literal in strings_in(line) {
            if let Some(word) = CREDENTIAL_WORDS.iter().find(|w| literal.contains(**w)) {
                found.push(format!(
                    "line {at}: the string \"{literal}\" carries {word}, which is the name of a \
                     credential, and verifying needs none"
                ));
            }
        }
    }
    found
}

/// Our domain named on a line, however the rest of the address is built: the app's host, a host
/// whose first label comes from `format!`, and the bare domain as well.
///
/// The bare domain was allowed until 2026-09-14, on the thought that a verdict might point a reader
/// at the page of what a receipt cannot prove. Nothing on the path did, and the allowance is what let
/// a `curl` to `https://timewitness.dev/api/key/...` through. What a receipt cannot prove is printed
/// by the verifier itself, so the path needs no address of ours for anything.
fn our_host(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let end = lower.find("timewitness.dev")? + "timewitness.dev".len();
    let start = lower[..end]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || "-.{}_".contains(c)))
        .map_or(0, |i| i + 1);
    Some(line[start..end].to_string())
}

/// The variable an `env!` or `option_env!` on a line reads, where it is not one Cargo writes from
/// the manifest.
fn baked_variable(line: &str) -> Option<String> {
    let at = line.find("env!(")?;
    let rest = &line[at + "env!(".len()..];
    let variable = rest
        .trim_start()
        .strip_prefix('"')
        .and_then(|r| r.split('"').next())
        .unwrap_or(rest);
    (!variable.starts_with(BUILD_VARIABLES_ALLOWED)).then(|| variable.to_string())
}

/// Whether a line opens an `extern` block, which declares functions for somebody else to supply,
/// as against `extern "C" fn`, which hands one of ours out.
fn host_import_block(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or(line).trim();
    let Some(rest) = code
        .strip_prefix("unsafe ")
        .unwrap_or(code)
        .strip_prefix("extern")
    else {
        return false;
    };
    let rest = rest.trim_start();
    let rest = match rest.strip_prefix('"') {
        Some(abi) => abi.split_once('"').map_or("", |(_, r)| r).trim_start(),
        None => rest,
    };
    rest.starts_with('{')
}

/// The double-quoted strings on a line.
fn strings_in(line: &str) -> Vec<&str> {
    line.split('"').skip(1).step_by(2).collect()
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

#[test]
fn nothing_either_path_links_can_reach_a_network() {
    for path in &PATHS {
        let linked = closure(path.roots);
        for root in path.roots {
            assert!(
                linked.contains_key(*root),
                "{root} is not in its own closure, so this check read nothing"
            );
        }

        let refused: Vec<String> = linked
            .iter()
            .filter(|(name, _)| NETWORK_PACKAGES.contains(&name.as_str()))
            .map(|(name, chain)| format!("{name}, linked as {chain}"))
            .collect();
        assert!(
            refused.is_empty(),
            "{} links a package that exists to reach a network, and {}:\n  {}",
            path.name,
            path.promise,
            refused.join("\n  ")
        );
    }
}

#[test]
fn no_source_on_either_path_needs_an_account_or_our_host() {
    let root = workspace_root();
    let mut refused = Vec::new();
    for path in &PATHS {
        let linked = closure(path.roots);
        let files = path_sources(path, &linked);
        assert!(
            files.len() > path.floor.len() + 2,
            "only {} files were read on {}, so the crates on it contributed none",
            files.len(),
            path.name
        );

        for (file, chain) in &files {
            let text = fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", file.display()));
            let shown = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .display()
                .to_string()
                .replace('\\', "/");
            for finding in findings(&text) {
                refused.push(format!(
                    "{} {shown} {finding} (reached as {chain})",
                    path.name
                ));
            }
        }
    }
    assert!(
        refused.is_empty(),
        "a source on one of these paths could reach a network, a service of ours or a credential, \
         and neither path may need any of them:\n  {}",
        refused.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// The readers and the rules, each shown refusing, because a guard nobody has seen fail is a guard
// nobody knows is connected
// ---------------------------------------------------------------------------

#[test]
fn each_source_rule_refuses_what_it_names() {
    let seeds = [
        "const HOST: &str = \"https://app.timewitness.dev/keys\";",
        "let s = std::net::TcpStream::connect(addr)?;",
        "let token = std::env::var(\"TIMEWITNESS_TOKEN\");",
        "await fetch(url);",
        "headers.insert(\"X_API_KEY\", key);",
        // The five the first version passed, each as the test run of 2026-09-14 wrote it.
        "pub fn key_host(sub: &str) -> String { format!(\"https://{}.timewitness.dev/keys\", sub) }",
        "std::process::Command::new(\"curl\").arg(\"-s\").output().ok()",
        "    s.send_to(key.as_bytes(), \"keys.timewitness.dev:4460\")?;",
        "#[path = \"../net/net.rs\"] pub mod net;",
        "pub const KEY_SERVICE: &str = env!(\"TW_KEY_SERVICE\");",
        // And the near relations of each.
        "let page = format!(\"https://timewitness.dev/api/key/{key}\");",
        "use std::process::{Command, ExitCode};",
        "let child = program.spawn()?;",
        "include!(\"../../outside/net.rs\");",
        "const SERVICE: Option<&str> = option_env!(\"KEY_SERVICE\");",
        "use std::env::{var as read};",
        "extern \"C\" {",
        "unsafe extern \"C\" { fn fetch_key(at: usize) -> usize; }",
        "extern {",
    ];
    for seed in seeds {
        assert!(!findings(seed).is_empty(), "nothing refused: {seed}");
    }
}

#[test]
fn what_the_path_legitimately_says_passes() {
    let fine = [
        "use std::net::IpAddr;",
        "if token.peek_tag() == Some(TAG_TOKEN_AUTHORITY_NAME) {",
        "<!-- BRAND-TOKENS -->",
        // What the path carries today, and what `--version` needs.
        "use std::process::ExitCode;",
        "let argv: Vec<String> = std::env::args().skip(1).collect();",
        "pub extern \"C\" fn tw_alloc(len: usize) -> usize {",
        "pub const DOCUMENT: &str = include_str!(\"../../../docs/what-timewitness-cannot-prove.md\");",
        "const VERSION: &str = env!(\"CARGO_PKG_VERSION\");",
    ];
    for line in fine {
        assert!(findings(line).is_empty(), "refused an honest line: {line}");
    }
}

/// A command line held in memory, so the reach can be shown finding what it should and nothing
/// more without touching the real tree.
fn in_memory(files: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let files: BTreeMap<String, String> = files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect();
    move |path: &str| files.get(path).cloned()
}

#[test]
fn the_reach_follows_what_verify_names_and_not_what_stamp_does() {
    let read = in_memory(&[
        (
            "main.rs",
            "mod args;
mod lookup;
mod render;
mod stamp_cmd;
mod verify_cmd;

fn main() {
    let parsed = args::parse();
    match parsed {
        Some(\"verify\") => verify_cmd::run(),
        Some(\"stamp\") => stamp_cmd::run(),
        None => render::usage(),
    }
}
",
        ),
        ("args.rs", "pub fn parse() {}\n"),
        ("render.rs", "pub fn usage() {}\n"),
        (
            "verify_cmd.rs",
            "use crate::{render, lookup::fetch as key_lookup};
pub fn run() {}

#[cfg(test)]
mod tests {
    use super::*;
}
",
        ),
        (
            "lookup.rs",
            "mod wire;\npub fn fetch() { super::render::usage(); }\n",
        ),
        ("lookup/wire.rs", "pub fn send() {}\n"),
        (
            "stamp_cmd.rs",
            "pub fn run() { std::net::UdpSocket::bind(\"0.0.0.0:0\"); }\n",
        ),
    ]);
    let reached = command_line_reach("verify", read);
    let names: Vec<&str> = reached.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        ["", "args", "lookup", "lookup::wire", "render", "verify_cmd"]
    );
    assert_eq!(reached["lookup::wire"].0, "lookup/wire.rs");
    assert!(reached["lookup"].1.contains("verify_cmd -> lookup"));
}

#[test]
fn the_reach_takes_a_glob_of_the_crate_as_every_module() {
    let read = in_memory(&[
        (
            "main.rs",
            "mod stamp_cmd;
mod verify_cmd;

fn main() {
    match command {
        Some(\"verify\") => verify_cmd::run(),
        Some(\"stamp\") => stamp_cmd::run(),
    }
}
",
        ),
        ("verify_cmd.rs", "use crate::*;\n"),
        ("stamp_cmd.rs", "pub fn run() {}\n"),
    ]);
    assert!(command_line_reach("verify", read).contains_key("stamp_cmd"));
}

#[test]
fn the_lock_reader_sees_dependencies_and_whose_a_package_is() {
    let lock = "\
version = 3

[[package]]
name = \"ureq\"
version = \"2.10.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
dependencies = [
 \"rustls 0.23.0\",
 \"webpki-roots\",
]

[[package]]
name = \"timewitness-verify\"
version = \"0.1.0\"
dependencies = [
 \"timewitness-core\",
]
";
    let packages = locked_packages(lock);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].name, "ureq");
    assert_eq!(packages[0].version, "2.10.0");
    assert!(!packages[0].ours);
    assert_eq!(packages[0].dependencies, ["rustls 0.23.0", "webpki-roots"]);
    assert!(packages[1].ours);
}

#[test]
fn the_manifest_reader_follows_every_linked_shape_and_leaves_out_development_ones() {
    let manifest = "\
[package]
name = \"example\"

[dependencies]
timewitness-core = { workspace = true }
sha2_for_bls = { version = \"0.9\", package = \"sha2\" }

[dev-dependencies]
reqwest = \"0.12\"

[build-dependencies]
cc = \"1\"

[target.'cfg(target_arch = \"wasm32\")'.dependencies]
getrandom = { version = \"0.2\" }

[dependencies.ureq]
version = \"2\"

[target.\"cfg(unix)\".dependencies.renamed]
package = \"hyper\"
version = \"1\"
";
    let found = linked_dependencies(manifest, Path::new("<in memory>"));
    let names: Vec<&str> = found.iter().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "cc",
            "getrandom",
            "hyper",
            "sha2",
            "timewitness-core",
            "ureq"
        ]
    );
}
