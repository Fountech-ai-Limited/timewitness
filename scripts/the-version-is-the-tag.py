#!/usr/bin/env python3
"""Hold what `timewitness --version` prints to the release tag the source was cut as.

A build from the `v0.2` tag printed `timewitness 0.1.0`, because the manifest said 0.1.0 at `v0.1`
and nobody moved it for `v0.2`. The first line of `--version` is the one label a person reads to
know which release they have, so it has to be the tag, spelled as the tag is spelled. The manifest
version 0.3.0 is the tag `v0.3`: a patch number of nought is left off, a pre-release is kept.

Three ways to run it:

    python scripts/the-version-is-the-tag.py

reads the manifest here and the first line the binary built from this tree prints (`TIMEWITNESS_BIN`,
or `target/debug/timewitness`), and holds them to the tags. On a commit a release tag names, the
line has to be that tag. On any other commit it may not be the name of a release that already
exists elsewhere, so the commit after a cut has to move the manifest on to the next pre-release
before it builds, and a build from `main` never says it is the last release.

    python scripts/the-version-is-the-tag.py --release v0.3 [--at REF] [--from URL]

clones the public repository at the tag, builds it the way a stranger would, runs `--version` and
compares the first line to the tag. With `--at` it builds that commit or branch instead and holds it
to the tag it is about to be cut as, which is the dry run before a tag exists.

    python scripts/the-version-is-the-tag.py --self-test

puts each rule to the shapes it has to accept and the shapes it has to refuse, the `v0.2` one among
them, and says which were judged wrongly.

Exit 0 when the label is the tag, 1 when it is not, 2 when the check could not run.
"""

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = "https://github.com/Fountech-ai-Limited/timewitness.git"

# A release tag here is `v` and two or three numbers, perhaps with a pre-release after a hyphen.
# `v0` is a release too, cut before this spelling was settled, and it is read as a tag like any
# other so a commit it names is still held to it.
RELEASE_TAG = re.compile(r"^v\d+(\.\d+){0,2}(-[0-9A-Za-z.-]+)?$")
VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


class CouldNotRun(Exception):
    pass


def tag_of(version):
    """The tag a manifest version is released as: 0.3.0 is v0.3, 0.3.1 is v0.3.1, 0.4.0-dev is
    v0.4-dev."""
    found = VERSION.match(version)
    if not found:
        raise CouldNotRun("the manifest version [%s] is not major.minor.patch" % version)
    major, minor, patch, pre = found.groups()
    name = "v%s.%s" % (major, minor) if patch == "0" else "v%s.%s.%s" % (major, minor, patch)
    return name + ("-" + pre if pre else "")


def next_pre_release(version):
    """What the manifest moves to straight after `version` is cut."""
    major, minor = VERSION.match(version).groups()[:2]
    return "%s.%d.0-dev" % (major, int(minor) + 1)


def manifest_version(text):
    """The version under [workspace.package] in the root manifest, which every crate takes."""
    section = re.search(r"^\[workspace\.package\]\s*$(.*?)(?=^\[|\Z)", text, re.M | re.S)
    if not section:
        raise CouldNotRun("the root manifest has no [workspace.package] section")
    found = re.search(r'^version\s*=\s*"([^"]+)"\s*$', section.group(1), re.M)
    if not found:
        raise CouldNotRun("[workspace.package] in the root manifest states no version")
    return found.group(1)


def judge_tree(version, printed, tags_here, tags_elsewhere):
    """`printed` is the first line of --version from this tree, `tags_here` the release tags on this
    commit, `tags_elsewhere` the release tags on any other commit, as a name to commit map."""
    lines = []
    wanted = tag_of(version)
    lines.append("the manifest says %s, which is released as %s" % (version, wanted))
    lines.append("the binary built from this tree says [%s]" % printed)
    passed = True
    if printed != "timewitness " + wanted:
        lines.append("refused: the first line of --version is not [timewitness %s]" % wanted)
        passed = False
    if tags_here:
        for tag in sorted(tags_here):
            if tag != wanted:
                lines.append("refused: this commit is %s and a build of it says it is %s" % (tag, wanted))
                passed = False
        if passed:
            lines.append("this commit is %s, and that is what a build of it says" % wanted)
    elif wanted in tags_elsewhere:
        lines.append(
            "refused: %s is commit %s, and a build of this commit would say it is %s as well. "
            "Move the manifest on to %s straight after a cut"
            % (wanted, tags_elsewhere[wanted][:7], wanted, next_pre_release(version)))
        passed = False
    else:
        lines.append("no release is called %s yet, so this commit may say it" % wanted)
    return passed, lines


def judge_release(tag, printed):
    lines = ["a build from %s says [%s]" % (tag, printed)]
    if printed == "timewitness " + tag:
        return True, lines
    lines.append("refused: the first line of --version is not [timewitness %s]" % tag)
    return False, lines


def run(args, cwd=None, env=None):
    out = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if out.returncode != 0:
        raise CouldNotRun("%s failed: %s" % (" ".join(args), (out.stderr or out.stdout).strip()[-800:]))
    return out.stdout


def first_line(binary):
    if not os.path.isfile(binary):
        raise CouldNotRun("there is no binary at %s to ask. Build it first" % binary)
    said = run([binary, "--version"]).splitlines()
    return said[0].strip() if said else ""


def built_binary():
    named = os.environ.get("TIMEWITNESS_BIN")
    if named:
        return named
    base = os.path.join(ROOT, "target", "debug", "timewitness")
    return base + ".exe" if os.path.isfile(base + ".exe") else base


def release_tags():
    """Every release tag in this checkout, as a name to the commit it names."""
    names = [t for t in run(["git", "-C", ROOT, "tag", "--list"]).split() if RELEASE_TAG.match(t)]
    if not names:
        raise CouldNotRun("this checkout holds no release tags, so there is nothing to hold the "
                          "version to. A shallow clone does this; fetch the tags")
    return {t: run(["git", "-C", ROOT, "rev-list", "-n", "1", t]).strip() for t in names}


def check_tree():
    with open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") as handle:
        version = manifest_version(handle.read())
    head = run(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip()
    tags = release_tags()
    here = {t for t, c in tags.items() if c == head}
    elsewhere = {t: c for t, c in tags.items() if c != head}
    return judge_tree(version, first_line(built_binary()), here, elsewhere)


def remove(path):
    """A clone's objects are read-only on Windows, and rmtree gives up on them unless told to make
    each one writable first."""
    def writable(func, target, _):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    try:
        shutil.rmtree(path, onexc=writable)
    except TypeError:
        shutil.rmtree(path, onerror=writable)


def check_release(tag, at, source, work):
    scratch = tempfile.mkdtemp(prefix="tw-version-", dir=work)
    try:
        tree = os.path.join(scratch, "timewitness")
        if at:
            run(["git", "clone", "--quiet", "--filter=blob:none", source, tree])
            run(["git", "-C", tree, "checkout", "--quiet", "--detach", at])
        else:
            run(["git", "clone", "--quiet", "--depth", "1", "--branch", tag, source, tree])
        commit = run(["git", "-C", tree, "rev-parse", "HEAD"]).strip()
        print("built from %s at %s%s" % (source, commit[:7],
                                        " (%s, a dry run of %s)" % (at, tag) if at else ""))
        target = os.path.join(scratch, "target")
        run(["cargo", "build", "--quiet", "--release", "--locked", "--bin", "timewitness",
             "--manifest-path", os.path.join(tree, "Cargo.toml"), "--target-dir", target])
        binary = os.path.join(target, "release", "timewitness")
        if os.path.isfile(binary + ".exe"):
            binary += ".exe"
        return judge_release(tag, first_line(binary))
    finally:
        remove(scratch)


def self_test():
    wrong = 0

    def expect(name, want, got):
        nonlocal wrong
        ok = want == got
        wrong += 0 if ok else 1
        print("%-5s %s" % ("ok" if ok else "WRONG", name))

    for version, tag in (("0.3.0", "v0.3"), ("0.3.1", "v0.3.1"), ("1.0.0", "v1.0"),
                         ("0.4.0-dev", "v0.4-dev"), ("0.4.0-rc.1", "v0.4-rc.1"),
                         ("0.4.0+build.7", "v0.4")):
        expect("%s is released as %s" % (version, tag), tag, tag_of(version))
    expect("the pre-release after 0.3.0 is 0.4.0-dev", "0.4.0-dev", next_pre_release("0.3.0"))
    try:
        tag_of("0.3")
        expect("a version with no patch number is refused", True, False)
    except CouldNotRun:
        expect("a version with no patch number is refused", True, True)

    v02 = {"v0.2": "7fb3edf"}
    tree = [
        ("0.3.0 printed as v0.3, no v0.3 anywhere yet", True, "0.3.0", "timewitness v0.3", set(), v02),
        ("0.3.0 on the commit tagged v0.3", True, "0.3.0", "timewitness v0.3", {"v0.3"}, v02),
        ("0.4.0-dev after v0.3 was cut elsewhere", True, "0.4.0-dev", "timewitness v0.4-dev", set(),
         {"v0.3": "a1b2c3d"}),
        ("the v0.2 tag, whose manifest said 0.1.0", False, "0.1.0", "timewitness v0.1", {"v0.2"},
         {"v0.1": "2e17c92"}),
        ("the spelling --version used until v0.3", False, "0.3.0", "timewitness 0.3.0", set(), v02),
        ("the commit after the cut still saying v0.3", False, "0.3.0", "timewitness v0.3", set(),
         {"v0.3": "a1b2c3d"}),
        ("a binary older than the manifest", False, "0.4.0-dev", "timewitness v0.3", set(),
         {"v0.3": "a1b2c3d"}),
        ("a commit tagged twice with different releases", False, "0.3.0", "timewitness v0.3",
         {"v0.3", "v0.3.1"}, {}),
    ]
    for name, want, version, printed, here, elsewhere in tree:
        expect("tree: " + name, want, judge_tree(version, printed, here, elsewhere)[0])

    release = [
        ("v0.3 building as timewitness v0.3", True, "v0.3", "timewitness v0.3"),
        ("v0.2 building as timewitness 0.1.0", False, "v0.2", "timewitness 0.1.0"),
        ("v0.3 building as a pre-release", False, "v0.3", "timewitness v0.3-dev"),
        ("v0.3 building as nothing at all", False, "v0.3", ""),
    ]
    for name, want, tag, printed in release:
        expect("release: " + name, want, judge_release(tag, printed)[0])

    print("self-test: %d wrong" % wrong)
    return 1 if wrong else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--release", metavar="TAG")
    parser.add_argument("--at", metavar="REF", help="build this commit or branch as if it were TAG")
    parser.add_argument("--from", dest="source", default=PUBLIC, metavar="URL")
    parser.add_argument("--work", metavar="DIR", help="where the clone and the build go")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.at and not args.release:
        parser.error("--at builds a commit as a release, so it needs --release")
    try:
        if args.release:
            if not RELEASE_TAG.match(args.release):
                raise CouldNotRun("%s is not spelled as a release tag" % args.release)
            passed, lines = check_release(args.release, args.at, args.source, args.work)
        else:
            passed, lines = check_tree()
    except CouldNotRun as e:
        print("the version check could not run: %s" % e, file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
