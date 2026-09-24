//! `timewitness agent install` and `uninstall` on the command line, short of installing anything.
//!
//! Installing a service changes the machine a test runs on, so nothing here does it. What is read
//! is what a person meets first: the usage names both, and a word the agent does not know, or an
//! account given to an agent run by hand, is refused in plain words before anything is touched.
//! The install itself is checked on machines that exist to be thrown away, by
//! `scripts/the-agent-survives-a-reboot.py`.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(args)
        .output()
        .expect("the binary this test was built alongside runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_usage_says_how_to_install_and_uninstall_the_agent() {
    let usage = text(&run(&["--help"]).stdout);
    for line in [
        "timewitness agent install [--user <name>] [options]",
        "timewitness agent uninstall\n",
        "never sets the clock",
    ] {
        assert!(usage.contains(line), "no {line:?} in the usage");
    }
    assert!(
        !usage.contains("installs no service"),
        "the usage still says the agent installs no service"
    );
}

#[test]
fn a_word_the_agent_does_not_know_is_refused_in_plain_words() {
    let out = run(&["agent", "reinstall"]);
    assert_eq!(out.status.code(), Some(1));
    let said = text(&out.stderr);
    assert!(
        said.contains("\"reinstall\" is not something the agent does")
            && said.contains("timewitness agent install"),
        "{said}"
    );
}

#[test]
fn a_second_word_after_install_is_refused() {
    let out = run(&["agent", "install", "now"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("\"now\""),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_service_takes_no_endpoint_and_uninstall_takes_nothing() {
    let out = run(&["agent", "install", "--endpoint", "somewhere.endpoint"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("a service writes its endpoint to a folder of its own"),
        "{}",
        text(&out.stderr)
    );
    assert!(!std::path::Path::new("somewhere.endpoint").exists());

    let out = run(&["agent", "uninstall", "--user", "nobody"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("uninstall takes nothing after it"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn an_account_given_to_an_agent_run_by_hand_is_refused_before_it_starts() {
    let dir = std::env::temp_dir().join(format!("tw-service-user-{}", std::process::id()));
    let endpoint = dir.join("agent.endpoint");
    let out = run(&[
        "agent",
        "--endpoint",
        &endpoint.display().to_string(),
        "--user",
        "nobody",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("--user names the account a service runs as"),
        "{}",
        text(&out.stderr)
    );
    assert!(!endpoint.exists(), "a refused start wrote its endpoint");
    let _ = std::fs::remove_dir_all(&dir);
}
