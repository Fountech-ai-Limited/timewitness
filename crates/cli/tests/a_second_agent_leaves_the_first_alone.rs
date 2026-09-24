//! `timewitness agent` started on an endpoint file another agent still answers on.
//!
//! Until 2026-09-24 the second one started, wrote its own address over the file and ran. Once it was
//! stopped, `status` said no agent was answering and to start one, while the first was still running
//! and still polling other people's time servers with nothing left to find it by. Seen 4 of 4 times
//! by the test pass that found it (RC-349).
//!
//! These run the real binary. The first agent polls the published servers as it always does, and
//! nothing here needs them to answer: an agent that has not synchronised still answers its token with
//! a refusal, and a refusal is enough to say an agent is there. Every agent started here is stopped by
//! the handle it was started under, so no other agent on this machine is touched.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Long enough for a debug build to start and write its endpoint on a busy machine.
const START_PATIENCE: Duration = Duration::from_secs(30);

/// An agent this test started, stopped when the test ends however it ends.
struct Started {
    child: Child,
    log: PathBuf,
}

impl Started {
    fn said(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tw-second-agent-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn agent(endpoint: &Path, log: PathBuf) -> Started {
    let out = File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(["agent", "--endpoint", endpoint.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .expect("the binary runs");
    Started { child, log }
}

fn status(endpoint: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_timewitness"))
        .args(["status", "--agent", endpoint.to_str().unwrap()])
        .output()
        .expect("the binary runs")
}

fn words(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Wait until `status` finds an agent up on `endpoint`, and say at which address.
fn up(endpoint: &Path, first: &Started) -> String {
    let began = Instant::now();
    loop {
        if endpoint.exists() {
            let said = words(&status(endpoint));
            if said.contains("is up") {
                return said;
            }
        }
        assert!(
            began.elapsed() < START_PATIENCE,
            "no agent was up on {} after {:?}. It said: {}",
            endpoint.display(),
            START_PATIENCE,
            first.said()
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn address_in(endpoint: &Path) -> String {
    std::fs::read_to_string(endpoint)
        .unwrap()
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_second_agent_on_a_live_endpoint_refuses_and_the_first_stays_reachable() {
    let dir = scratch("live");
    let endpoint = dir.join("agent.endpoint");
    let first = agent(&endpoint, dir.join("first.log"));
    up(&endpoint, &first);
    let before = std::fs::read(&endpoint).unwrap();

    let mut second = agent(&endpoint, dir.join("second.log"));
    let began = Instant::now();
    let code = loop {
        if let Some(exit) = second.child.try_wait().unwrap() {
            break exit.code();
        }
        if began.elapsed() > START_PATIENCE {
            let file_now = address_in(&endpoint);
            panic!(
                "a second agent started on an endpoint the first still answers on and was still \
                 running after {START_PATIENCE:?}, with the file now naming {file_now}. It said: {}",
                second.said()
            );
        }
        thread::sleep(Duration::from_millis(100));
    };
    let said = second.said();

    assert_eq!(code, Some(1), "{said}");
    assert!(said.contains("already answering"), "{said}");
    assert!(said.contains("has not started"), "{said}");
    // The sentence a person reads, and nothing a type prints of itself.
    for never in ["Refused(", "Malformed(", "WireError", "Endpoint(", "{", "}"] {
        assert!(!said.contains(never), "{never}: {said}");
    }
    // It names the way out, which is either of two things a person can do.
    assert!(said.contains("--endpoint"), "{said}");

    // The file is the first agent's, byte for byte, and the first agent is the one that answers.
    assert_eq!(std::fs::read(&endpoint).unwrap(), before);
    let still = words(&status(&endpoint));
    assert!(still.contains("is up"), "{still}");
    assert!(
        still.contains(&address_in(&endpoint)),
        "status found an agent at an address the file does not name: {still}"
    );
    drop(first);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_endpoint_left_by_an_agent_that_was_stopped_is_taken_over() {
    // A killed agent leaves its file behind, and the next one has to be able to start on it. This is
    // the case writing over the file was for, and refusing a second agent must not break it.
    let dir = scratch("stale");
    let endpoint = dir.join("agent.endpoint");
    let first = agent(&endpoint, dir.join("first.log"));
    up(&endpoint, &first);
    let stale = address_in(&endpoint);
    drop(first);

    let second = agent(&endpoint, dir.join("second.log"));
    let said = up(&endpoint, &second);
    assert_ne!(address_in(&endpoint), stale, "{}", second.said());
    assert!(said.contains(&address_in(&endpoint)), "{said}");
    drop(second);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_endpoint_file_that_is_not_one_is_written_over() {
    // Whatever was at the path before, if it does not name an agent that answers, the agent starts.
    let dir = scratch("garbage");
    let endpoint = dir.join("agent.endpoint");
    std::fs::write(&endpoint, "not an endpoint\n").unwrap();
    let first = agent(&endpoint, dir.join("first.log"));
    up(&endpoint, &first);
    drop(first);
    let _ = std::fs::remove_dir_all(&dir);
}
