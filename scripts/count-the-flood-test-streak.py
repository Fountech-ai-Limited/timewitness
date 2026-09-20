#!/usr/bin/env python3
"""Count how many CI runs in a row on `main` have passed the socket-flood test.

The test floods a real socket for a minute and then asks whether an honest client is still
answered. Twice in one afternoon it failed on a shared runner and blocked a merge, and both times
it passed on a re-run with nothing changed. So the question of whether it has settled is a count of
consecutive CI runs on `main` that passed it, and that count has to come off attempt 1 of each run.
`gh run view` shows the latest attempt, so a re-run with nothing changed reads success there and
the original failure is not in the answer.

A run whose overall conclusion is failure still counts as a pass here when the `Tests` step itself
passed and something later failed, because what is being counted is this test and not the run.

    python scripts/count-the-flood-test-streak.py

prints one line per run and a sentence saying how far the streak has got. It exits 0 once the
streak has reached the number asked for and 1 while it has not, so the answer is an exit status
rather than a reading somebody takes by eye.

    python scripts/count-the-flood-test-streak.py --self-test

plants what the counter has to refuse and watches it refuse each one.
"""

import argparse
import io
import json
import pathlib
import re
import subprocess
import tempfile
import sys

REPO = "Fountech-ai-Limited/timewitness"
WORKFLOW = "CI"
BRANCH = "main"
STEP = "Tests"
# The commit that changed what the flood test measures. The streak starts here and not before it.
SINCE = "4b4f572b453c572470eec566d2985c0b2cfe0cba"
NEED = 20
# The test the step has to still be running. A step name is not evidence on its own: `cargo test
# --workspace` goes on passing after the test it was counted for has been deleted.
TEST_FN = "a_flood_of_oversize_datagrams_for_a_minute_does_not_stop_the_server"
TEST_FILE = "crates/roughtime-server/tests/over_a_real_socket.rs"


def gh(args):
    out = subprocess.run(["gh"] + args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("gh %s failed: %s" % (" ".join(args), out.stderr.strip()))
    return out.stdout


def runs_from_github(root):
    """Every completed CI run on the branch at or after SINCE, oldest first."""
    later = subprocess.run(
        ["git", "-C", str(root), "rev-list", "--reverse", "%s..origin/%s" % (SINCE, BRANCH)],
        capture_output=True, text=True, check=True).stdout.split()
    rank = {sha: i for i, sha in enumerate([SINCE] + later)}
    listed = json.loads(gh([
        "run", "list", "--repo", REPO, "--workflow", WORKFLOW, "--branch", BRANCH,
        "--limit", "200", "--json", "databaseId,headSha,conclusion,status,createdAt"]))
    listed = [r for r in listed if r["status"] == "completed"]
    since_time = min((r["createdAt"] for r in listed if r["headSha"] == SINCE), default=None)
    # A run on a commit `main` no longer has says nothing about the code `main` carries, so it
    # neither counts nor resets the streak. It is still printed. Dropping one in silence is how a
    # counter reads higher than the history it is counted over: one such run sits on a merge commit
    # that `main` dropped on 2026-09-19, and a count taken by hand counted it.
    orphaned = [r for r in listed
                if r["headSha"] not in rank and since_time and r["createdAt"] >= since_time]
    kept = [r for r in listed if r["headSha"] in rank]
    kept.sort(key=lambda r: (rank[r["headSha"]], r["databaseId"]))
    out = []
    for r in orphaned:
        out.append({"id": r["databaseId"], "sha": r["headSha"], "run_conclusion": r["conclusion"],
                    "jobs": [], "orphaned": True})
    for r in kept:
        jobs = json.loads(gh([
            "api", "repos/%s/actions/runs/%d/attempts/1/jobs" % (REPO, r["databaseId"])]))
        out.append({
            "id": r["databaseId"],
            "sha": r["headSha"],
            "run_conclusion": r["conclusion"],
            "jobs": [{"name": j["name"],
                      "steps": [{"name": s["name"], "conclusion": s["conclusion"]}
                                for s in j.get("steps", [])]}
                     for j in jobs["jobs"]],
        })
    return out


def step_verdict(run):
    """What the counted step did on attempt 1, or why the run cannot be counted."""
    if run.get("orphaned"):
        return "on a commit main no longer has, so it counts for nothing either way"
    found = None
    for job in run["jobs"]:
        for step in job["steps"]:
            if step["name"] == STEP:
                if found is not None:
                    return "the step appears more than once"
                found = step["conclusion"]
    if found is None:
        return "the step did not run"
    if found != "success":
        return str(found)
    return "success"


def the_test_is_still_there(root):
    path = pathlib.Path(root) / TEST_FILE
    if not path.exists():
        return False, "%s is gone" % TEST_FILE
    body = path.read_text(encoding="utf-8")
    if not re.search(r"^fn %s\(" % re.escape(TEST_FN), body, re.M):
        return False, "%s no longer holds %s" % (TEST_FILE, TEST_FN)
    if re.search(r"#\[ignore", body):
        return False, "%s carries an ignore attribute" % TEST_FILE
    return True, "%s holds %s and nothing in the file is ignored" % (TEST_FILE, TEST_FN)


def count(runs, need, out=sys.stdout):
    streak = 0
    for run in runs:
        verdict = step_verdict(run)
        print("run %-12s %s  %s: %s" % (run["id"], run["sha"][:7], STEP, verdict), file=out)
        if run.get("orphaned"):
            continue
        if verdict == "success":
            streak += 1
        else:
            print("   streak reset here, it stood at %d" % streak, file=out)
            streak = 0
    print("%d consecutive runs of the %d needed." % (streak, need), file=out)
    return streak


def self_test(root):
    """Plant what the counter must refuse and watch it refuse."""
    def run(sha, steps, conclusion="success"):
        return {"id": 1, "sha": sha, "run_conclusion": conclusion,
                "jobs": [{"name": "build, lint and test", "steps": steps}]}

    passed = [{"name": "Build", "conclusion": "success"},
              {"name": STEP, "conclusion": "success"}]
    failed = [{"name": "Build", "conclusion": "success"},
              {"name": STEP, "conclusion": "failure"}]
    # The step never ran, inside a job that is present and green in every other way. This is the
    # shape that fails open: a missing container is obvious and a missing member inside a present
    # one is not.
    absent = [{"name": "Build", "conclusion": "success"},
              {"name": "Repository hygiene", "conclusion": "success"}]
    skipped = [{"name": "Build", "conclusion": "success"},
               {"name": STEP, "conclusion": "skipped"}]

    cases = [
        ("twenty clean runs", [run("a" * 40, passed) for _ in range(20)], 20, True),
        ("one failure in the middle",
         [run("a" * 40, passed) for _ in range(10)] + [run("b" * 40, failed)]
         + [run("c" * 40, passed) for _ in range(9)], 9, False),
        ("the step did not run in one of them",
         [run("a" * 40, passed) for _ in range(19)] + [run("d" * 40, absent)], 0, False),
        ("the step was skipped in the last one",
         [run("a" * 40, passed) for _ in range(19)] + [run("e" * 40, skipped)], 0, False),
        ("nineteen clean runs is not twenty",
         [run("a" * 40, passed) for _ in range(19)], 19, False),
        ("a run on a commit main no longer has neither counts nor resets",
         [dict(run("g" * 40, failed), orphaned=True)] + [run("a" * 40, passed) for _ in range(20)],
         20, True),
        ("and it cannot be used to make up the twenty",
         [dict(run("g" * 40, passed), orphaned=True)] + [run("a" * 40, passed) for _ in range(19)],
         19, False),
        ("a failing run whose Tests step passed still counts",
         [run("f" * 40, passed, conclusion="failure") for _ in range(20)], 20, True),
    ]
    bad = 0
    for name, runs, want_streak, want_ok in cases:
        buf = io.StringIO()
        got = count(runs, NEED, out=buf)
        ok = got >= NEED
        right = got == want_streak and ok == want_ok
        if not right:
            bad += 1
        print("%-52s streak %2d, passes %-5s  %s"
              % (name, got, str(ok).lower(), "as expected" if right else "WRONG"))

    there, why = the_test_is_still_there(root)
    print("%-52s %-5s  %s" % ("the test is still in the tree", str(there).lower(), why))
    if not there:
        bad += 1

    # The plants go into a copy of the tree rather than into the tree. A self-test that rewrites
    # the file it is checking leaves the repository dirty when it is interrupted, and on Windows it
    # rewrites every line ending on the way past even when it puts the same words back.
    body = (pathlib.Path(root) / TEST_FILE).read_text(encoding="utf-8", newline="")
    with tempfile.TemporaryDirectory() as tmp:
        planted_path = pathlib.Path(tmp) / TEST_FILE
        planted_path.parent.mkdir(parents=True, exist_ok=True)
        for label, planted in [
                ("the test renamed out of the tree", body.replace("fn %s(" % TEST_FN, "fn gone(")),
                ("the test left in place but ignored",
                 body.replace("fn %s(" % TEST_FN, "#[ignore]\nfn %s(" % TEST_FN)),
                ("the file gone altogether", None)]:
            if planted is None:
                planted_path.unlink()
            else:
                planted_path.write_text(planted, encoding="utf-8", newline="")
            there, why = the_test_is_still_there(tmp)
            print("%-52s %-5s  %s" % (label, str(there).lower(), why))
            if there:
                bad += 1
    return bad


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--need", type=int, default=NEED)
    ap.add_argument("--from-json", help="read the runs from a file instead of the API")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        bad = self_test(root)
        print("self-test: %d wrong" % bad)
        return 1 if bad else 0

    there, why = the_test_is_still_there(root)
    print("the test itself: %s" % why)
    if not there:
        print("Counting stops: the step could pass without running the test being counted.")
        return 1

    if args.from_json:
        runs = json.loads(pathlib.Path(args.from_json).read_text(encoding="utf-8"))
    else:
        runs = runs_from_github(root)
    if not runs:
        print("No completed CI run on %s at or after %s." % (BRANCH, SINCE[:7]))
        return 1
    streak = count(runs, args.need)
    return 0 if streak >= args.need else 1


if __name__ == "__main__":
    sys.exit(main())
