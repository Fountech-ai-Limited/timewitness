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
import hashlib
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
# The counted test's body as it stands at SINCE, hashed with its line endings normalised so a
# Windows checkout and a Linux one agree. A name is not the test: the function can be there, not
# ignored, and assert nothing, and every check above it goes on passing. So the body is pinned, and
# a deliberate change to it is one line of work here rather than a streak that silently restarts
# counting something else. Recompute with --body-sha256 and put the answer here in the same commit.
BODY_SHA256 = "47c95457e35175fa7660c7a462848a3e9dea8b1ef096e09ef803c0812ce3f502"


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
    # A run on a commit `main` no longer has is read like any other run and then counted differently,
    # and the two halves of that are not one judgement. A pass on such a commit says nothing about
    # the code `main` carries, so it does not count toward the twenty. A failure is the test failing,
    # whatever `main` later did with the commit, so it resets. Until 2026-09-20 both sat on one
    # branch and a failing one was thrown away, which is how a counter reads higher than the history
    # it was counted over.
    orphaned = [r for r in listed
                if r["headSha"] not in rank and since_time and r["createdAt"] >= since_time]
    kept = [r for r in listed if r["headSha"] in rank]
    kept.sort(key=lambda r: (rank[r["headSha"]], r["databaseId"]))

    def as_record(r, orphan):
        jobs = json.loads(gh([
            "api", "repos/%s/actions/runs/%d/attempts/1/jobs" % (REPO, r["databaseId"])]))
        record = {
            "id": r["databaseId"],
            "sha": r["headSha"],
            "created": r["createdAt"],
            "run_conclusion": r["conclusion"],
            "jobs": [{"name": j["name"],
                      "steps": [{"name": s["name"], "conclusion": s["conclusion"]}
                                for s in j.get("steps", [])]}
                     for j in jobs["jobs"]],
        }
        if orphan:
            record["orphaned"] = True
        return record

    out = [as_record(r, False) for r in kept]
    # An orphan goes where it happened rather than at the front. A failing one that reset a streak
    # in the middle of the history has to reset it in the middle of the reading too, and a list with
    # every orphan at the top can only ever reset a streak of nought.
    for r in sorted(orphaned, key=lambda r: r["createdAt"]):
        record = as_record(r, True)
        at = next((i for i, k in enumerate(out) if k["created"] > r["createdAt"]), len(out))
        out.insert(at, record)
    return out


def step_verdict(run):
    """What the counted step did on attempt 1, or why the run cannot be counted."""
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


# The body a name check cannot tell from the real one: present, not ignored, and asserting nothing.
GUTTED = "\n".join([
    "fn %s() {" % TEST_FN,
    '    assert!(true, "an honest client is answered after the flood");',
    "}",
])


def hash_of(written):
    """The sha256 of a test body, with its line endings normalised."""
    flat = "\n".join(line.rstrip("\r") for line in written.split("\n"))
    return hashlib.sha256(flat.encode("utf-8")).hexdigest()


def the_body(text):
    """The counted test as it is written, from its `fn` line to its closing brace.

    A step name says the suite ran and a function name says the function is there. Neither says the
    test still measures what it was counted for, and a body replaced by an assertion that cannot
    fail leaves both of them true.
    """
    start = re.search(r"^fn %s\(" % re.escape(TEST_FN), text, re.M)
    if not start:
        return None
    depth = 0
    i = text.index("{", start.start())
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start.start():i + 1]
        i += 1
    return None


def the_test_is_still_there(root):
    path = pathlib.Path(root) / TEST_FILE
    if not path.exists():
        return False, "%s is gone" % TEST_FILE
    body = path.read_text(encoding="utf-8")
    if not re.search(r"^fn %s\(" % re.escape(TEST_FN), body, re.M):
        return False, "%s no longer holds %s" % (TEST_FILE, TEST_FN)
    if re.search(r"#\[ignore", body):
        return False, "%s carries an ignore attribute" % TEST_FILE
    written = the_body(body)
    if written is None:
        return False, "%s holds %s and its body cannot be read" % (TEST_FILE, TEST_FN)
    got = hash_of(written)
    if got != BODY_SHA256:
        return False, ("%s has moved: the body hashes %s and the streak was counted over %s. "
                       "Change BODY_SHA256 in the same commit that changes the test, or the count "
                       "carries on over a test that measures something else"
                       % (TEST_FN, got[:16], BODY_SHA256[:16]))
    return True, ("%s holds %s, nothing in the file is ignored, and the body still hashes %s"
                  % (TEST_FILE, TEST_FN, BODY_SHA256[:16]))


def count(runs, need, out=sys.stdout):
    streak = 0
    for run in runs:
        verdict = step_verdict(run)
        orphan = run.get("orphaned")
        print("run %-12s %s  %s: %s%s"
              % (run["id"], run["sha"][:7], STEP, verdict,
                 "  (on a commit main no longer has)" if orphan else ""), file=out)
        if verdict == "success":
            # A pass on a commit `main` dropped is not evidence about the code `main` carries, so it
            # does not count. It does not reset either: nothing failed.
            if not orphan:
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
        ("a passing run on a commit main no longer has neither counts nor resets",
         [run("a" * 40, passed) for _ in range(10)]
         + [dict(run("g" * 40, passed), orphaned=True)]
         + [run("a" * 40, passed) for _ in range(10)],
         20, True),
        # The half the orphan rule got wrong. Not counting a pass is the conservative direction and
        # not resetting on a failure is the reckless one, and the two sat on one branch.
        ("a failing run on a commit main no longer has still resets the streak",
         [run("a" * 40, passed) for _ in range(10)]
         + [dict(run("g" * 40, failed), orphaned=True)]
         + [run("a" * 40, passed) for _ in range(10)],
         10, False),
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
                # The one a name check cannot see. The function is there, it is not ignored, and
                # it asserts nothing, so every check above it goes on passing.
                ("the test gutted to an assertion that cannot fail",
                 body.replace(the_body(body), GUTTED)),
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
    ap.add_argument("--body-sha256", action="store_true",
                    help="print the counted test's body hash as it stands in this tree")
    args = ap.parse_args()

    if args.body_sha256:
        written = the_body((root / TEST_FILE).read_text(encoding="utf-8"))
        if written is None:
            print("%s does not hold a readable %s" % (TEST_FILE, TEST_FN))
            return 1
        print(hash_of(written))
        return 0

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
