#!/usr/bin/env python3
"""Every check on the newest commit of `main` comes from a run this repository makes itself.

An app installed on the organisation can write a check suite on every commit pushed here, whether
or not it ever runs anything, and anybody can read the suite and the app's name through the API
without signing in. Nothing in a commit shows it, so no rule that reads the tree or the history can
see it. This reads the check suites GitHub holds for the newest commit on `main` and refuses any
written by an app that is not on the list below. The list names what is allowed rather than what is
not, so an app nobody has heard of yet is refused too, and this file names no outside app.

It reads the newest commit and not the history, because what it guards is the next push: an app
that writes a suite writes it on every commit pushed, so the newest commit shows it. Branch and pull
request heads other than the one named are not read; a suite an app writes there alone is not seen
here.

    python3 scripts/checks-come-from-our-own-runs.py [--repo OWNER/REPO] [--ref NAME]
    python3 scripts/checks-come-from-our-own-runs.py --self-test

`--repo` defaults to `GITHUB_REPOSITORY` and `--ref` to `main`. `GH_TOKEN` is used where it is set,
and the read is anonymous where it is not, which is the read a stranger makes.

A breach is reported by the commit and a count, never by the app's name: the log a build writes is
public. Exit 0 is clean, 1 is a check suite from an app off the list, and 2 is a read that could not
be made or did not come back whole.
"""

import json
import os
import sys
import urllib.error
import urllib.request

# The apps whose check suites belong on a commit here, by the slug GitHub gives them. GitHub's own
# workflow runner is the only one this repository runs.
ALLOWED = {"github-actions"}

API = "https://api.github.com"


class CannotRun(Exception):
    pass


def read(path):
    """One API read, as JSON. Anonymous unless `GH_TOKEN` is set."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "timewitness-checks"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with urllib.request.urlopen(urllib.request.Request(API + path, headers=headers), timeout=60) as answer:
            return json.load(answer)
    except urllib.error.HTTPError as e:
        raise CannotRun("the API answered %d" % e.code)
    except Exception as e:
        raise CannotRun("the API could not be read (%s)" % type(e).__name__)


def judge(repo, ref, ask=read):
    """The sentences for the newest commit of `ref`, and the commit read."""
    head = ask("/repos/%s/commits/%s" % (repo, ref))
    sha = (head or {}).get("sha") or ""
    if len(sha) != 40:
        raise CannotRun("the API named no commit for %s" % ref)
    suites, page = [], 1
    while True:
        answer = ask("/repos/%s/commits/%s/check-suites?per_page=100&page=%d" % (repo, sha, page))
        listed = answer.get("check_suites")
        total = answer.get("total_count")
        if not isinstance(listed, list) or not isinstance(total, int):
            raise CannotRun("the API's answer for %s did not list its check suites" % sha)
        suites += listed
        if len(suites) >= total or not listed:
            break
        page += 1
    if len(suites) != total:
        raise CannotRun("the API counted %d check suites on %s and listed %d" % (total, sha, len(suites)))
    outside = [s for s in suites if ((s.get("app") or {}).get("slug") or "") not in ALLOWED]
    if outside:
        return ["%s carries %d check suite%s from an app this repository does not run" % (
            sha, len(outside), "" if len(outside) == 1 else "s")], sha, len(suites)
    return [], sha, len(suites)


def self_test():
    wrong = []
    sha = "a" * 40

    def answers(slugs, total=None, head=sha):
        def ask(path):
            if path.endswith("/commits/main"):
                return {"sha": head}
            if "/check-suites" in path:
                listed = [{"app": {"slug": s}} for s in slugs] if path.endswith("&page=1") else []
                return {"total_count": len(listed) if total is None else total, "check_suites": listed}
            raise CannotRun("the stand-in API was asked something it does not know")
        return ask

    outsider = "an-app-" + "nobody-runs-here"
    for what, ask, want in (
        ("only this repository's own runs", answers(["github-actions", "github-actions"]), False),
        ("no check suite at all", answers([]), False),
        ("one suite from another app", answers(["github-actions", outsider]), True),
        ("a suite with no app named", answers([None]), True),
    ):
        found, _, _ = judge("o/r", "main", ask)
        if bool(found) != want:
            wrong.append("%s: %s" % (what, "refused" if found else "passed"))
        if outsider in " ".join(found):
            wrong.append("%s: the report printed the app it found" % what)
    for what, ask in (
        ("a count the list does not reach", answers(["github-actions"], total=3)),
        ("no commit named", answers([], head="")),
    ):
        try:
            judge("o/r", "main", ask)
            wrong.append("%s: read as whole" % what)
        except CannotRun:
            pass
    if wrong:
        for w in wrong:
            print("checks, self-test: judged wrongly: %s" % w, file=sys.stderr)
        return 1
    print("checks, self-test: every shape judged as it should be")
    return 0


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    repo, ref = os.environ.get("GITHUB_REPOSITORY", ""), "main"
    while args:
        if len(args) >= 2 and args[0] == "--repo":
            repo, args = args[1], args[2:]
        elif len(args) >= 2 and args[0] == "--ref":
            ref, args = args[1], args[2:]
        else:
            print("checks: that is not a way this runs; see the head of this file", file=sys.stderr)
            return 2
    if "/" not in repo:
        print("checks: no repository named, so nothing was checked", file=sys.stderr)
        return 2
    try:
        found, sha, count = judge(repo, ref)
    except CannotRun as e:
        print("checks: %s, so nothing was checked" % e, file=sys.stderr)
        return 2
    except Exception as e:
        print("checks: the check stopped on %s, so nothing was checked" % type(e).__name__, file=sys.stderr)
        return 2
    for sentence in found:
        print("checks: %s" % sentence, file=sys.stderr)
    if found:
        return 1
    print("checks: the %d check suites on %s, the newest commit of %s, all come from this repository's own runs"
          % (count, sha, ref))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
