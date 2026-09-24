#!/usr/bin/env python3
"""Say whether the public install check installed the latest release, and passed, today.

`Fountech-ai-Limited/timewitness-install-check` is a repository that is not this one. Its workflow
asks GitHub which release is the latest, installs it with the line the README at that release gives
a stranger, stamps a build, and checks the receipt with no token. It runs every six hours and names
the release it installed in its job names, so this reads the answer from outside:

    python scripts/the-install-check-is-on-the-latest-release.py

It reads the latest release of this repository, then the most recent scheduled or dispatched run of
the install check that has finished, and passes only when that run was green, is under a day old,
and installed and checked that same release. It prints what it read and exits 0 or 1, so the answer
is an exit status rather than a reading somebody takes by eye.

The failure it exists for is a check that was green on one release and stays green after the next
one ships, because it is still installing the old one. A run that names any release other than the
latest is refused however green it is.

    python scripts/the-install-check-is-on-the-latest-release.py --self-test

plants what it has to refuse and watches it refuse each one.
"""

import argparse
import datetime
import json
import re
import subprocess
import sys

REPO = "Fountech-ai-Limited/timewitness"
CHECK = "Fountech-ai-Limited/timewitness-install-check"
WORKFLOW = "install-check.yml"
EVENTS = ("schedule", "workflow_dispatch")
MAX_AGE = datetime.timedelta(hours=24)

# The job names in the install check's workflow, with the release filled in by the run. Every one
# has to be there and green: finding the release, installing it, and checking what it made.
FIND = "Find the latest release"
INSTALL = re.compile(r"^Install (\S+) in one line and stamp a build$")
VERIFY = re.compile(r"^Check what (\S+) made, as a stranger$")


def gh(args):
    out = subprocess.run(["gh"] + args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("gh %s failed: %s" % (" ".join(args), out.stderr.strip()))
    return out.stdout


def when(stamp):
    return datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


def judge(latest, runs, jobs_of, now):
    """Return (passed, lines). `runs` is newest first, as GitHub lists them; `jobs_of(id)` gives a
    run's jobs as name and conclusion."""
    lines = ["latest release of %s: %s" % (REPO, latest)]
    chosen = None
    for run in runs:
        if run["event"] not in EVENTS:
            continue
        if run["status"] != "completed":
            lines.append("run %s (%s) is still %s, so the one before it is read" % (
                run["id"], run["event"], run["status"]))
            continue
        chosen = run
        break
    if chosen is None:
        lines.append("no finished scheduled or dispatched run of %s" % WORKFLOW)
        return False, lines

    started = when(chosen["run_started_at"])
    age = now - started
    lines.append("run %s, %s, started %s, %.1f hours ago, %s" % (
        chosen["id"], chosen["event"], chosen["run_started_at"], age.total_seconds() / 3600,
        chosen["conclusion"]))

    passed = True
    if chosen["conclusion"] != "success":
        lines.append("refused: the run did not pass")
        passed = False
    if age > MAX_AGE:
        lines.append("refused: the run is more than %d hours old" % (MAX_AGE.total_seconds() / 3600))
        passed = False
    if age < -datetime.timedelta(minutes=5):
        lines.append("refused: the run starts in the future, so this clock or that one is wrong")
        passed = False

    jobs = jobs_of(chosen["id"])
    for job in jobs:
        lines.append("  job %r: %s" % (job["name"], job["conclusion"]))

    def one(test, what):
        found = [j for j in jobs if (test(j["name"]) if callable(test) else j["name"] == test)]
        if len(found) != 1:
            lines.append("refused: found %d jobs where one job %s" % (len(found), what))
            return None
        if found[0]["conclusion"] != "success":
            lines.append("refused: the job that %s did not pass" % what)
            return None
        return found[0]

    if one(FIND, "finds the latest release") is None:
        passed = False
    for pattern, what in ((INSTALL, "installs and stamps"), (VERIFY, "checks what it made")):
        job = one(lambda name, p=pattern: p.match(name) is not None, what)
        if job is None:
            passed = False
            continue
        named = pattern.match(job["name"]).group(1)
        if named != latest:
            lines.append("refused: the job that %s names %s and the latest release is %s" % (
                what, named, latest))
            passed = False

    lines.append("PASS: the install check installed %s and passed within %d hours" % (
        latest, MAX_AGE.total_seconds() / 3600) if passed else "FAIL")
    return passed, lines


def from_github():
    latest = json.loads(gh(["api", "repos/%s/releases/latest" % REPO]))["tag_name"]
    runs = json.loads(gh(["api", "repos/%s/actions/workflows/%s/runs?per_page=50" % (
        CHECK, WORKFLOW)]))["workflow_runs"]

    def jobs_of(run_id):
        data = json.loads(gh(["api", "repos/%s/actions/runs/%s/jobs?per_page=100" % (CHECK, run_id)]))
        return [{"name": j["name"], "conclusion": j["conclusion"]} for j in data["jobs"]]

    return latest, runs, jobs_of


def self_test():
    now = when("2026-09-24T12:00:00Z")

    def run(i, event="schedule", status="completed", conclusion="success",
            started="2026-09-24T06:17:00Z"):
        return {"id": i, "event": event, "status": status, "conclusion": conclusion,
                "run_started_at": started}

    def jobs(install="v0.3", verify="v0.3", find="success", inst="success", ver="success"):
        out = [{"name": FIND, "conclusion": find}]
        if install is not None:
            out.append({"name": "Install %s in one line and stamp a build" % install,
                        "conclusion": inst})
        if verify is not None:
            out.append({"name": "Check what %s made, as a stranger" % verify, "conclusion": ver})
        return out

    good = jobs()
    shapes = [
        ("a green scheduled run on the latest release", True, [run(1)], {1: good}),
        ("a green dispatched run on the latest release", True,
         [run(1, event="workflow_dispatch")], {1: good}),
        ("a newer run still going, the finished one before it green", True,
         [run(2, status="in_progress", conclusion=None), run(1)], {1: good}),
        ("green, but on the release before the latest", False, [run(1)],
         {1: jobs(install="v0.2", verify="v0.2")}),
        ("installed the latest and checked the one before", False, [run(1)],
         {1: jobs(verify="v0.2")}),
        ("a run that failed", False, [run(1, conclusion="failure")], {1: good}),
        ("a green run a day and an hour old", False,
         [run(1, started="2026-09-23T10:59:00Z")], {1: good}),
        ("a run dated in the future", False, [run(1, started="2026-09-24T13:00:00Z")], {1: good}),
        ("only push runs", False, [run(1, event="push")], {1: good}),
        ("no runs at all", False, [], {}),
        ("the install job skipped", False, [run(1)], {1: jobs(inst="skipped")}),
        ("no install job", False, [run(1)], {1: jobs(install=None)}),
        ("no checking job", False, [run(1)], {1: jobs(verify=None)}),
        ("the finding job failed", False, [run(1)], {1: jobs(find="failure")}),
        ("a newest failed run behind an older green one", False,
         [run(2, conclusion="failure"), run(1)], {1: good, 2: good}),
    ]
    wrong = 0
    for name, want, runs, table in shapes:
        got, lines = judge("v0.3", runs, lambda i, t=table: t[i], now)
        mark = "ok" if got == want else "WRONG"
        if got != want:
            wrong += 1
        why = [line for line in lines if line.startswith(("refused", "no finished"))]
        print("%-5s %-60s %s" % (mark, name, "passed" if got else why[0] if why else "refused"))
    print("self-test: %d wrong" % wrong)
    return 1 if wrong else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    latest, runs, jobs_of = from_github()
    passed, lines = judge(latest, runs, jobs_of, datetime.datetime.now(datetime.timezone.utc))
    for line in lines:
        print(line)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
