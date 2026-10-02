//! Nothing in this repository sets the machine's clock.
//!
//! The default is measure and vouch. The agent disciplines a model of the clock and hands out
//! readings against it; it never moves the clock the rest of the machine reads. That is a promise to
//! the person who installs it, and it matters more than most: the Windows time service contends with
//! any other discipliner by design, a second one fighting it makes both worse, and a time agent that
//! moved the clock unasked would be a time agent nobody should run. The agent's own documentation
//! says it, and until 2026-09-22 nothing checked it.
//!
//! What is read: every source file under every crate's `src`, every script, the Action and the deploy
//! folder. What is refused: a call into any interface that sets or slews a clock, on any of the three
//! platforms, and the commands that do the same from a shell. A comment may name one, because the
//! documentation has to be able to say what is not done; code may not.
//!
//! Setting the clock on the operator's word may be built one day. When it is, it goes in one module,
//! named below as the one allowed, and this check holds everything else to the rule.

use std::fs;
use std::path::{Path, PathBuf};

/// The interfaces that set or slew a clock, with the platform each belongs to.
const SETTERS: &[(&str, &str)] = &[
    ("SetSystemTime", "Windows"),
    ("SetLocalTime", "Windows"),
    ("SetSystemTimeAdjustment", "Windows"),
    ("NtSetSystemTime", "Windows"),
    ("settimeofday", "Unix"),
    ("clock_settime", "Unix"),
    ("clock_adjtime", "Linux"),
    ("adjtimex", "Linux"),
    ("ntp_adjtime", "Linux and the BSDs"),
    ("adjtime(", "Unix"),
    ("stime(", "Unix"),
    ("w32tm", "the Windows time service's own command"),
    ("timedatectl set-time", "systemd"),
    ("Set-Date", "PowerShell"),
    ("hwclock", "Linux"),
    ("systemsetup -settime", "macOS"),
    ("systemsetup -setdate", "macOS"),
    ("date -s ", "a shell"),
    ("date --set", "a shell"),
    // The same commands with their words apart, which is how code starts another program. The
    // guard read only the shell spelling until 2026-09-25, and a planted
    // `Command::new("timedatectl").args(["set-time", ...])` went through it.
    ("\"set-time\"", "systemd, with the words apart"),
    ("'set-time'", "systemd, with the words apart"),
    ("\"-settime\"", "macOS, with the words apart"),
    ("\"-setdate\"", "macOS, with the words apart"),
    ("'date', '-s'", "a shell's date, with the words apart"),
    ("\"date\", \"-s\"", "a shell's date, with the words apart"),
    ("bin/date\")", "a shell's date, named by its path"),
    (
        "set-ntp",
        "systemd, handing the clock to its own time service",
    ),
    ("ntpdate", "the old NTP client, which steps the clock"),
    ("makestep", "chrony, told to step the clock"),
    (
        "Command::new(\"date\")",
        "a shell's date, which sets the clock when it is given one",
    ),
];

/// Where setting the clock on the operator's word would live, once there is such a thing. None yet.
const ALLOWED: &[&str] = &[];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("Cargo.lock").exists())
        .expect("the workspace root")
        .to_path_buf()
}

fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|e| {
            ["rs", "sh", "ps1", "py", "mjs", "js", "yml", "yaml", "toml"]
                .iter()
                .any(|x| e == *x)
        }) {
            files.push(path);
        }
    }
}

/// The code on a line, with a comment after it taken off. A whole-line comment is no code at all.
fn code_of(line: &str) -> &str {
    let trimmed = line.trim_start();
    if ["//", "#", "*", "/*"]
        .iter()
        .any(|c| trimmed.starts_with(c))
    {
        return "";
    }
    line.split(" //").next().unwrap_or(line)
}

/// Each line of `text` that sets a clock, with the interface it uses.
fn setting_the_clock(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let code = code_of(line);
        for (setter, platform) in SETTERS {
            if code.contains(setter) {
                found.push(format!(
                    "line {}: {setter}, which sets the clock on {platform}",
                    number + 1
                ));
            }
        }
    }
    found
}

#[test]
fn no_source_sets_the_machines_clock() {
    let root = workspace_root();
    let mut files = Vec::new();
    for entry in fs::read_dir(root.join("crates"))
        .expect("the crates folder")
        .flatten()
    {
        collect(&entry.path().join("src"), &mut files);
    }
    let before = files.len();
    collect(&root.join("scripts"), &mut files);
    collect(&root.join("deploy"), &mut files);
    files.push(root.join("action.yml"));
    assert!(
        before > 50 && files.len() > before + 10,
        "only {} files were read, so this check is reading nothing",
        files.len()
    );

    let mut refused = Vec::new();
    for file in &files {
        let shown = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string()
            .replace('\\', "/");
        if ALLOWED.contains(&shown.as_str()) {
            continue;
        }
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for finding in setting_the_clock(&text) {
            refused.push(format!("{shown} {finding}"));
        }
    }
    assert!(
        refused.is_empty(),
        "the agent measures and vouches and never moves this machine's clock unasked, and these \
         lines would:\n  {}",
        refused.join("\n  ")
    );
}

#[test]
fn each_setter_is_refused_in_code_and_let_through_in_a_comment() {
    let seeds = [
        "unsafe { SetSystemTime(&st) };",
        "windows_sys::Win32::System::SystemInformation::SetSystemTimeAdjustment(adj, 0);",
        "let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };",
        "unsafe { libc::settimeofday(&tv, std::ptr::null()) };",
        "libc::adjtimex(&mut buf);",
        "Command::new(\"w32tm\").args([\"/resync\"]).status()?;",
        "sudo timedatectl set-time \"2026-09-22 12:00:00\"",
        "Set-Date -Date $when",
        "sudo date -s \"$moment\"",
        "let x = adjtime(&delta, &mut old);",
        "Command::new(\"timedatectl\").args([\"set-time\", \"2026-09-22 12:00:00\"]).status()?;",
        "run(['timedatectl', 'set-time', when])",
        "Command::new(\"date\").arg(\"--set=12:00\").status()?;",
        "subprocess.run(['date', '-s', when])",
        "Command::new(\"/bin/date\").arg(when).status()?;",
        "sudo timedatectl set-ntp true",
        "sudo ntpdate pool.ntp.org",
        "chronyc makestep",
    ];
    for seed in seeds {
        assert!(
            !setting_the_clock(seed).is_empty(),
            "nothing refused: {seed}"
        );
    }
    let honest = [
        "// The agent never calls SetSystemTime or settimeofday.",
        "# w32tm is the Windows time service, which this contends with",
        "    /// It does not set this machine's clock with clock_settime.",
        "let wall = SystemTime::now();",
        "let adjusted = model.adjust(reading);",
    ];
    for line in honest {
        assert!(setting_the_clock(line).is_empty(), "refused: {line}");
    }
}
