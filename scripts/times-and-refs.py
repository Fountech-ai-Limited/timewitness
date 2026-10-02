#!/usr/bin/env python3
"""Two rules about what a stranger can read off this repository's history: the times, and the name
of every branch pushed to it.

The times. Every commit here is written in Cyprus, so its author offset and its committer offset
are the one Cyprus keeps at that instant: +0300 from 01:00 UTC on the last Sunday in March to 01:00
UTC on the last Sunday in October, +0200 otherwise. A commit the merge button wrote may carry either
of the two, because nothing yet shows which one GitHub writes across a change of clocks. A commit is
also not committed more than a day before any of its parents. That reads committer dates, because a
rebase keeps a commit's author date and moves its committer date, so the committer date is the one
that says when a commit joined this history. A commit can be excused the author offset only by
being listed below by its full id, and none is.

The branch names. A branch is pushed under a name with hyphens in it and never with a slash, which
the repository's ruleset refuses to make as well. The hook before every push reads each ref it is
about to send, so the refusal comes before GitHub's rather than after it.

A breach is reported by the commit or the ref it is in.

    python3 scripts/times-and-refs.py [--repo PATH]   every commit's two dates and offsets
    python3 scripts/times-and-refs.py --ref NAME      one ref about to be pushed
    python3 scripts/times-and-refs.py --self-test     each rule put to what it has to refuse

Exit 0 is clean, 1 is a rule broken with the place named, and 2 is a check that could not run.
`scripts/repo-hygiene.sh` runs the first as its fifth rule, and the hook runs `--ref` on each ref it
pushes.
"""

import calendar
import datetime
import os
import re
import subprocess
import sys

# Commits excused the author offset, by full id. None is.
OFFSET_EXCUSED = frozenset()

# The committer the merge button writes, as `scripts/repo-hygiene.sh` rule 1 allows it.
THE_BUTTON = "GitHub <noreply@github.com>"

COMMIT_ID = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
DAY = 24 * 60 * 60


class CannotRun(Exception):
    pass


def last_sunday(year, month):
    last = calendar.monthrange(year, month)[1]
    day = datetime.date(year, month, last)
    return last - (day.weekday() - 6) % 7


def cyprus_offset(seconds):
    """Minutes east of UTC that Cyprus keeps at this instant, by the European rule: summer time
    from 01:00 UTC on the last Sunday of March to 01:00 UTC on the last Sunday of October."""
    at = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    start = datetime.datetime(at.year, 3, last_sunday(at.year, 3), 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(at.year, 10, last_sunday(at.year, 10), 1, tzinfo=datetime.timezone.utc)
    return 180 if start <= at < end else 120


def offset_text(minutes):
    sign = "-" if minutes < 0 else "+"
    return "%s%02d%02d" % (sign, abs(minutes) // 60, abs(minutes) % 60)


def offset_minutes(text):
    """`+0300` as 180, `-0130` as -90."""
    m = re.fullmatch(r"([+-])(\d\d)(\d\d)", text)
    if not m:
        raise CannotRun("an offset read '%s', which is not one" % text)
    minutes = int(m.group(2)) * 60 + int(m.group(3))
    return -minutes if m.group(1) == "-" else minutes


def judge_times(commits, excused=OFFSET_EXCUSED):
    """Each commit as a dict: sha, author and committer seconds and offsets, whether the merge
    button wrote it, and its parent ids. Returns the sentences. `excused` holds the ids whose author
    offset is not read."""
    found = []
    committed = {c["sha"]: c["committed"] for c in commits}
    for c in commits:
        for who, seconds, offset in (("authored", c["authored"], c["author_offset"]),
                                     ("committed", c["committed"], c["committer_offset"])):
            if who == "authored" and c["sha"] in excused:
                continue
            allowed = {120, 180} if c["button"] else {cyprus_offset(seconds)}
            if offset_minutes(offset) not in allowed:
                found.append("%s is %s at %s, and Cyprus was on %s then" % (
                    c["sha"], who, offset, offset_text(cyprus_offset(seconds))))
        for parent in c["parents"]:
            if parent in committed and c["committed"] < committed[parent] - DAY:
                found.append("%s is committed more than a day before its parent %s" % (c["sha"], parent))
    return found


def judge_ref(name):
    """The sentences for one ref about to be pushed."""
    if name.startswith("refs/heads/") and "/" in name[len("refs/heads/"):]:
        return ["a branch is about to be pushed under a name with a slash in it, which the "
                "repository refuses to make; name it with hyphens"]
    return []


def git(repo, *args):
    run = subprocess.run(["git", "-C", repo] + list(args), capture_output=True)
    if run.returncode != 0:
        # git's own words are not printed: they can quote the path or name being read.
        raise CannotRun("git %s exited %d" % (args[0], run.returncode))
    return run.stdout


def judge_repo(repo):
    """The sentences for every commit any ref of the clone reaches, and how many were read."""
    count = int(git(repo, "rev-list", "--all", "--count").decode().strip())
    raw = git(repo, "log", "--all", "-z",
              "--format=%H%x01%P%x01%at%x01%ai%x01%ct%x01%ci%x01%cn <%ce>").decode("utf-8", "replace")
    records = [r for r in raw.split("\0") if r.strip()]
    if len(records) != count:
        raise CannotRun("git log gave %d commits where rev-list counts %d" % (len(records), count))
    if not records:
        raise CannotRun("git rev-list counted no commit")
    commits = []
    for record in records:
        fields = record.lstrip("\n").split("\x01")
        if len(fields) != 7 or not COMMIT_ID.match(fields[0]):
            raise CannotRun("a commit record did not read as seven fields")
        sha, parents, at, ai, ct, ci, committer = fields
        commits.append({"sha": sha, "parents": parents.split(),
                        "authored": int(at), "author_offset": ai.rsplit(" ", 1)[-1],
                        "committed": int(ct), "committer_offset": ci.rsplit(" ", 1)[-1],
                        "button": committer == THE_BUTTON and len(parents.split()) >= 2})
    return judge_times(commits), count


def self_test():
    wrong = []

    def expect(what, got, want):
        if bool(got) != want:
            wrong.append("%s: %s" % (what, "refused" if got else "passed"))

    expect("a branch with a slash", judge_ref("refs/heads/a/b"), True)
    expect("a branch with two slashes", judge_ref("refs/heads/a/b/c"), True)
    expect("a plain branch", judge_ref("refs/heads/the-bound-holds"), False)
    expect("a release tag", judge_ref("refs/tags/v0.6"), False)

    def commit(sha, at, aoff, ct=None, coff=None, button=False, parents=()):
        return {"sha": sha, "authored": at, "author_offset": aoff, "committed": at if ct is None else ct,
                "committer_offset": aoff if coff is None else coff, "button": button, "parents": list(parents)}

    summer = calendar.timegm((2026, 10, 1, 5, 24, 33))
    winter = calendar.timegm((2026, 11, 2, 9, 0, 0))
    for what, c, want in (
        ("summer at +0300", commit("a" * 40, summer, "+0300"), False),
        ("summer at +0000", commit("a" * 40, summer, "+0000"), True),
        ("summer at +0200", commit("a" * 40, summer, "+0200"), True),
        ("summer, authored at +0300 and committed at +0000", commit("a" * 40, summer, "+0300", coff="+0000"), True),
        ("winter at +0200", commit("b" * 40, winter, "+0200"), False),
        ("winter at +0300", commit("b" * 40, winter, "+0300"), True),
        ("the merge button in winter at +0300", commit("b" * 40, winter, "+0300", button=True), False),
        ("the merge button at +0000", commit("b" * 40, winter, "+0000", button=True), True),
        # The clocks go back at 01:00 UTC on 2026-10-25, the last Sunday of October.
        ("a minute before the change, at +0300",
         commit("c" * 40, calendar.timegm((2026, 10, 25, 0, 59, 0)), "+0300"), False),
        ("a minute after the change, at +0200",
         commit("c" * 40, calendar.timegm((2026, 10, 25, 1, 1, 0)), "+0200"), False),
        ("forward on 2027-03-28, at +0300", commit("c" * 40, calendar.timegm((2027, 3, 28, 1, 0, 0)), "+0300"), False),
    ):
        expect(what, judge_times([c]), want)
    listed = "f" * 40
    for what, c, want in (
        ("an excused commit authored at +0000", commit(listed, summer, "+0000", coff="+0300"), False),
        ("an excused commit committed at +0000", commit(listed, summer, "+0000", coff="+0000"), True),
        ("a commit not on the list authored at +0000", commit("a" * 40, summer, "+0000", coff="+0300"), True),
    ):
        expect(what, judge_times([c], excused={listed}), want)
    expect("a commit authored at +0000 with nothing excused",
           judge_times([commit(listed, summer, "+0000", coff="+0300")]), True)
    parent = commit("d" * 40, summer, "+0300")
    expect("a commit committed two days before its parent",
           judge_times([parent, commit("e" * 40, summer - 2 * DAY, "+0300", parents=["d" * 40])]), True)
    expect("a commit authored two days before its parent and committed after it, as a rebase leaves it",
           judge_times([parent, commit("e" * 40, summer - 2 * DAY, "+0300", ct=summer + 60, parents=["d" * 40])]), False)

    if wrong:
        for w in wrong:
            print("times and refs, self-test: judged wrongly: %s" % w, file=sys.stderr)
        return 1
    print("times and refs, self-test: every shape judged as it should be")
    return 0


def main(argv):
    args = argv[1:]
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    try:
        if args == ["--self-test"]:
            return self_test()
        if len(args) == 2 and args[0] == "--ref":
            found, where = judge_ref(args[1]), None
        elif not args or (len(args) == 2 and args[0] == "--repo"):
            found, count = judge_repo(args[1] if args else here)
            where = "the times of %d commits" % count
        else:
            print("times and refs: that is not a way this runs; see the head of this file", file=sys.stderr)
            return 2
    except CannotRun as e:
        print("times and refs: %s, so nothing was checked" % e, file=sys.stderr)
        return 2
    except Exception as e:
        # Never a breach and never a pass. The type alone, because an exception's own words can
        # quote what was being read.
        print("times and refs: the check stopped on %s, so nothing was checked" % type(e).__name__, file=sys.stderr)
        return 2
    for sentence in found:
        print("times and refs: %s" % sentence, file=sys.stderr)
    if found:
        return 1
    # A ref is read on every push, where a line saying all is well is noise.
    if where:
        print("times and refs: clean over %s" % where)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
