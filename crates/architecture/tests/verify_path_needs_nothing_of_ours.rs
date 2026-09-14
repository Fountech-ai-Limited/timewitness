//! Checking a receipt needs no account and no call to us, and this is what keeps it so.
//!
//! Generating a receipt may one day go through a service of ours. Verifying one never does: a
//! stranger checks a receipt with no account, no network call to us and nothing of ours in the loop,
//! and a verifier that needed any of those would be a verifier we could switch off. Today that holds
//! because nothing on the path could reach a network. The time it stops holding is when something is
//! built beside the verifier and a key lookup, a token or a fallback to our host finds its way in, so
//! the check is written now rather than then.
//!
//! What counts as the verify path. The verifier crate, the WebAssembly build of it, every crate
//! either of those links, the four files of the command line that `timewitness verify` runs through,
//! and the page the verifier is served in. The rest of the command line is not on it: the agent and
//! the stamp talk to time sources by design, and which of them may need an account is a separate
//! question that is not settled.
//!
//! Three rules, and each names what it refuses and why, so an honest change that trips one can say
//! which rule it is arguing with:
//!
//! - nothing linked may be an HTTP client, a TLS stack, a socket runtime or a binding to the
//!   browser's fetch, checked by package name over the whole dependency closure;
//! - no source on the path may name a host under `timewitness.dev`, open a socket, or read the
//!   environment;
//! - no source on the path may carry the name of a credential variable.
//!
//! The network itself is the other half and it is not here. `scripts/verify-offline.sh` runs the
//! verifier in a process with no network at all and holds its verdict to the one it gives with a
//! network, which catches a path this file cannot see, such as a crate it has never heard of.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// The crates whose whole closure is the verify path.
const ROOTS: [&str; 2] = ["timewitness-verify", "timewitness-verify-web"];

/// The files of the command line that `timewitness verify` runs through, and nothing else of it.
const COMMAND_LINE_FILES: [&str; 4] = [
    "crates/cli/src/verify_cmd.rs",
    "crates/cli/src/args.rs",
    "crates/cli/src/render.rs",
    "crates/cli/src/as_json.rs",
];

/// The page the verifier module is served in. The built page embeds the module and is not tracked;
/// this is the source it is built from.
const PAGE: &str = "verifier-page/page.html";

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
        "option_env!",
        "bakes an environment variable into the build",
    ),
    ("fetch(", "fetches from a network"),
    ("XMLHttpRequest", "fetches from a network"),
    ("WebSocket", "opens a connection"),
    ("EventSource", "opens a connection"),
    ("sendBeacon", "sends to a network"),
];

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
fn closure() -> BTreeMap<String, String> {
    let root = workspace_root();
    let lock = fs::read_to_string(root.join("Cargo.lock"))
        .unwrap_or_else(|e| panic!("could not read Cargo.lock: {e}"));
    let packages = locked_packages(&lock);

    let mut by_name: BTreeMap<&str, Vec<&Locked>> = BTreeMap::new();
    for package in &packages {
        by_name.entry(&package.name).or_default().push(package);
    }

    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut queue: Vec<(String, String)> = ROOTS
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

/// Every source file on the verify path, relative to the workspace root.
fn path_sources(linked: &BTreeMap<String, String>) -> Vec<PathBuf> {
    let root = workspace_root();
    let mut files = Vec::new();
    for name in linked.keys().filter(|n| n.starts_with("timewitness-")) {
        let dir = manifest_path(name)
            .parent()
            .expect("a manifest sits in a directory")
            .to_path_buf();
        let build_script = dir.join("build.rs");
        if build_script.is_file() {
            files.push(build_script);
        }
        collect(&dir.join("src"), &mut files);
    }
    for file in COMMAND_LINE_FILES.iter().chain([PAGE].iter()) {
        let path = root.join(file);
        assert!(
            path.is_file(),
            "{file} is named as part of the verify path and is not there; if it moved, tell this \
             check where it went rather than dropping it"
        );
        files.push(path);
    }
    files.sort();
    files.dedup();
    files
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
                "line {at}: names {host}, and the verify path may not know any host of ours"
            ));
        }
        for (word, why) in SOURCE_RULES {
            if line.contains(word) {
                found.push(format!("line {at}: `{word}` {why}"));
            }
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

/// A host under our domain named on a line, such as the app's. The bare domain is allowed, because
/// a verdict may point a reader at the page that lists what a receipt cannot prove; a host under it
/// is a service, and a service is what the path may not depend on.
fn our_host(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let mut from = 0;
    while let Some(offset) = lower[from..].find(".timewitness.dev") {
        let end = from + offset;
        let start = lower[..end]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
            .map_or(0, |i| i + 1);
        if start < end {
            return Some(line[start..end + ".timewitness.dev".len()].to_string());
        }
        from = end + 1;
    }
    None
}

/// The double-quoted strings on a line.
fn strings_in(line: &str) -> Vec<&str> {
    line.split('"').skip(1).step_by(2).collect()
}

// ---------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------

#[test]
fn nothing_the_verifier_links_can_reach_a_network() {
    let linked = closure();
    for root in ROOTS {
        assert!(
            linked.contains_key(root),
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
        "the verify path links a package that exists to reach a network, and verifying needs no \
         call to anybody:\n  {}",
        refused.join("\n  ")
    );
}

#[test]
fn no_source_on_the_verify_path_needs_an_account_or_our_host() {
    let root = workspace_root();
    let linked = closure();
    let files = path_sources(&linked);
    assert!(
        files.len() > COMMAND_LINE_FILES.len() + 1,
        "only {} files were read, so the crates on the path contributed none",
        files.len()
    );

    let mut refused = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", file.display()));
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string()
            .replace('\\', "/");
        for finding in findings(&text) {
            refused.push(format!("{shown} {finding}"));
        }
    }
    assert!(
        refused.is_empty(),
        "a source on the verify path could reach a network, a service of ours or a credential, and \
         verifying needs none of them:\n  {}",
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
    ];
    for seed in seeds {
        assert!(!findings(seed).is_empty(), "nothing refused: {seed}");
    }
}

#[test]
fn what_the_path_legitimately_says_passes() {
    let fine = [
        "use std::net::IpAddr;",
        "see https://timewitness.dev/cannot-prove for what this cannot prove",
        "if token.peek_tag() == Some(TAG_TOKEN_AUTHORITY_NAME) {",
        "<!-- BRAND-TOKENS -->",
    ];
    for line in fine {
        assert!(findings(line).is_empty(), "refused an honest line: {line}");
    }
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
