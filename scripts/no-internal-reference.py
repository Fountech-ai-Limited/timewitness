#!/usr/bin/env python3
"""Nothing a stranger can read here names how the work behind it is organised.

A public repository is read whole: its files, every commit message, the text of its pull requests
and the names of its refs. None of them has any use for a reference to a step of the work, a
numbered item of a list kept somewhere else, or the name a machine was given. A reader cannot
follow one, and each one tells them something about a process they were never meant to see.

What is refused is a shape and never a list of our own names, so this file names nothing it is
guarding. Each shape is described in words rather than shown, because an example of one would be
a breach in this file:

  - an identifier of one to four capital letters, a dash and three or more digits, other than the
    names of public standards that take that shape, such as SHA-256;
  - an identifier of one capital letter, a dash, a word in capitals, a dash and a date written as
    eight digits, with a number after it;
  - a row with a number of three or more digits after it, which only means something beside the
    list it is a row of;
  - the default name a machine is given: a word in capitals, a dash, and seven capital letters and
    digits with at least one of each;
  - and one short word this repository has no use for, spelt in two halves below so that this
    file does not carry it.

    scripts/no-internal-reference.py                     every tracked file and every commit message HEAD reaches
    scripts/no-internal-reference.py --repo <path>       the same, over another clone
    scripts/no-internal-reference.py --message <file>    one text: a commit message before it is made,
                                                         or a pull request's title and body
    scripts/no-internal-reference.py --refs <remote>     the refs a remote lists, by name
    scripts/no-internal-reference.py --self-test         seeds, each watched refused, and a plain repository passed

Three exits: 0 clean, 1 with every breach named, 2 a check that could not run.

A commit already published cannot be taken back: it stays fetchable by its id whatever is done to
the history. Its message is named in the allow file beside this one, one full id and a reason per
line, and read past. An entry naming a commit the history does not hold is refused, so the file
cannot excuse more than it says. The tree is never excused; a file that names something is changed.

The file is written to be lifted whole into another repository: it reads only git and the allow
file named beside it, and it needs nothing outside the standard library.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOW_NAME = "no-internal-reference-allowed.txt"

# Public standards whose names take the identifier's shape. A name added here is a standard a
# stranger can look up, never one of ours.
STANDARDS = {"SHA", "CIP", "CVE", "CWE", "ISO", "IEC", "ECMA", "CRC", "UTF"}

WORD = "t" + "c"

SHAPES = [
    ("an identifier", re.compile(r"(?<![A-Za-z0-9-])([A-Z]{1,4})-[0-9]{3,}(?![0-9])")),
    ("a dated identifier", re.compile(r"(?<![A-Za-z0-9-])[A-Z]-[A-Z]{2,}-20[0-9]{6}-[0-9]+")),
    ("a numbered row", re.compile(r"(?i)\brows? [0-9]{3,}\b")),
    (
        "a machine's default name",
        re.compile(r"\b[A-Z][A-Z0-9]{2,9}-(?=[A-Z0-9]*[0-9])(?=[A-Z0-9]*[A-Z])[A-Z0-9]{7}\b"),
    ),
    ("a word this repository has no use for", re.compile(r"(?<![A-Za-z0-9_.-])" + WORD + r"(?![A-Za-z0-9_])")),
]


class CouldNotRun(Exception):
    pass


def git(repo, *args, data=None):
    try:
        out = subprocess.run(
            ["git", "-C", repo, *args],
            input=data,
            capture_output=True,
            check=False,
        )
    except OSError as e:
        raise CouldNotRun(f"git could not be started: {e}")
    if out.returncode != 0:
        raise CouldNotRun(f"git {' '.join(args[:2])} exited {out.returncode}: {out.stderr.decode('utf-8', 'replace').strip()}")
    return out.stdout


def breaches(text):
    """Each line of `text` that carries a refused shape, as (line number, what, the match)."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for what, shape in SHAPES:
            for m in shape.finditer(line):
                if what == "an identifier" and m.group(1) in STANDARDS:
                    continue
                found.append((number, what, m.group(0)))
    return found


def read_allow(path):
    """The full commit ids the allow file names, each with its line number."""
    allowed = {}
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return allowed
    except OSError as e:
        raise CouldNotRun(f"the allow file {path} could not be read: {e}")
    for number, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        sha, _, reason = line.partition(" ")
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or not reason.strip():
            raise CouldNotRun(f"{path}:{number} is not a full commit id followed by a reason")
        allowed[sha] = number
    return allowed


def check_repo(repo, allow_path):
    problems = []

    files = git(repo, "ls-files", "-z").decode("utf-8", "replace").split("\0")
    files = [f for f in files if f]
    if not files:
        raise CouldNotRun("the tree lists no files")
    read = 0
    for name in files:
        path = os.path.join(repo, name)
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        if b"\0" in data:
            continue
        read += 1
        for number, what, match in breaches(data.decode("utf-8", "replace")):
            problems.append(f"{name}:{number} carries {what}, {match}")
        for number, what, match in breaches(name):
            problems.append(f"the path {name} carries {what}, {match}")

    allowed = read_allow(allow_path)
    held = set(git(repo, "rev-list", "HEAD").decode().split())
    if not held:
        raise CouldNotRun("HEAD reaches no commits")
    for sha, number in allowed.items():
        if sha not in held:
            problems.append(f"{os.path.basename(allow_path)}:{number} names {sha[:12]}, which this history does not hold")

    log = git(repo, "log", "--format=%H%x00%B%x00", "HEAD").decode("utf-8", "replace")
    parts = log.split("\0")
    messages = 0
    for i in range(0, len(parts) - 1, 2):
        sha = parts[i].strip()
        if not sha:
            continue
        messages += 1
        if sha in allowed:
            continue
        for number, what, match in breaches(parts[i + 1]):
            problems.append(f"the message of {sha[:12]}, line {number}, carries {what}, {match}")
    if messages != len(held):
        raise CouldNotRun(f"read {messages} messages where HEAD reaches {len(held)} commits")
    return problems, read, messages


def check_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        raise CouldNotRun(f"{path} could not be read: {e}")
    return [f"line {n} carries {what}, {match}" for n, what, match in breaches(text)]


def check_refs(remote, repo):
    out = git(repo, "ls-remote", "--refs", remote).decode("utf-8", "replace")
    problems = []
    for line in out.splitlines():
        _, _, ref = line.partition("\t")
        if ref.startswith("refs/backup/"):
            problems.append(f"{remote} lists {ref}, a copy of somebody's working branch")
        for _, what, match in breaches(ref):
            problems.append(f"{remote} lists {ref}, which carries {what}, {match}")
    return problems, len(out.splitlines())


def run_self_test():
    me = os.path.abspath(__file__)
    missed = []

    def ask(*args):
        return subprocess.run([sys.executable, me, *args], capture_output=True).returncode

    with tempfile.TemporaryDirectory() as work:
        repo = os.path.join(work, "seed")
        os.makedirs(os.path.join(repo, "scripts"))
        g = lambda *a: git(repo, *a)
        g("init", "-q")
        g("config", "user.name", "Somebody")
        g("config", "user.email", "somebody@example.com")
        g("config", "commit.gpgsign", "false")
        with open(os.path.join(repo, "plain.txt"), "w") as f:
            f.write("A plain line, hashed with SHA-256 under RFC 3161.\n")
        g("add", "-A")
        g("commit", "-q", "-m", "A plain message")
        allow = os.path.join(repo, "scripts", ALLOW_NAME)
        if ask("--repo", repo) != 0:
            missed.append("a plain repository was refused")

        # Each tree seed on its own, put in, read and taken out again.
        seeds = [
            "AB" + "-1234",
            "A-WORD-" + "20260101-1",
            "row" + " 1234",
            "ABCDEFG-" + "1A2B3C4",
            "it was read by " + WORD + " first",
        ]
        for seed in seeds:
            with open(os.path.join(repo, "seed.txt"), "w") as f:
                f.write(f"# A comment with {seed} in it.\n")
            g("add", "-A")
            if ask("--repo", repo) != 1:
                missed.append(f"the tree seed '{seed}' was not refused")
            g("rm", "-q", "--cached", "seed.txt")
            os.remove(os.path.join(repo, "seed.txt"))

        # A message seed, refused, then read past once the allow file names it.
        g("commit", "-q", "--allow-empty", "-m", "A message naming " + "AB" + "-1234")
        sha = g("rev-parse", "HEAD").decode().strip()
        if ask("--repo", repo) != 1:
            missed.append("a message naming an identifier was not refused")
        with open(allow, "w") as f:
            f.write(f"# seed\n{sha} a seeded message, published\n")
        g("add", "-A")
        g("commit", "-q", "-m", "Name the seeded message")
        if ask("--repo", repo) != 0:
            missed.append("a message the allow file names was still refused")
        with open(allow, "a") as f:
            f.write(f"{'0' * 40} a commit nobody made\n")
        if ask("--repo", repo) != 1:
            missed.append("an allow entry naming a commit the history does not hold was not refused")
        with open(allow, "w") as f:
            f.write("abc a short id\n")
        if ask("--repo", repo) != 2:
            missed.append("an allow line that is not a full id and a reason did not stop the check")
        with open(allow, "w") as f:
            f.write(f"{sha} a seeded message, published\n")

        # One text, as a commit message or a pull request's title and body.
        text = os.path.join(work, "text.txt")
        with open(text, "w") as f:
            f.write("A title\n\nA body that names " + "AB" + "-1234.\n")
        if ask("--message", text) != 1:
            missed.append("a text naming an identifier was not refused")
        with open(text, "w") as f:
            f.write("A title\n\nA plain body about SHA-512.\n")
        if ask("--message", text) != 0:
            missed.append("a plain text was refused")
        if ask("--message", os.path.join(work, "absent.txt")) != 2:
            missed.append("a text that is not there did not stop the check")

        # The refs a remote lists, with a bare clone standing in for the remote.
        remote = os.path.join(work, "remote.git")
        git(work, "clone", "-q", "--bare", repo, remote)
        if ask("--repo", repo, "--refs", remote) != 0:
            missed.append("a remote listing its branches alone was refused")
        git(remote, "update-ref", "refs/backup/a-host/main", sha)
        if ask("--repo", repo, "--refs", remote) != 1:
            missed.append("a remote listing a backup ref was not refused")
        git(remote, "update-ref", "-d", "refs/backup/a-host/main")
        git(remote, "update-ref", "refs/heads/ABCDEFG-" + "1A2B3C4", sha)
        if ask("--repo", repo, "--refs", remote) != 1:
            missed.append("a remote listing a branch named for a machine was not refused")

    if missed:
        for m in missed:
            print(f"no internal reference: self-test: {m}", file=sys.stderr)
        return 1
    print("no internal reference: every seed refused, the allowed message read past, and the plain repository passed")
    return 0


def main(argv):
    repo = None
    mode = "repo"
    target = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--repo", "--message", "--refs"):
            if i + 1 >= len(argv):
                raise CouldNotRun(f"{a} needs a value")
            if a == "--repo":
                repo = argv[i + 1]
            else:
                mode, target = a[2:], argv[i + 1]
            i += 2
        elif a == "--self-test":
            mode = "self-test"
            i += 1
        else:
            raise CouldNotRun(f"{a} is not an option this takes")
    repo = os.path.abspath(repo or os.path.join(HERE, ".."))

    if mode == "self-test":
        return run_self_test()
    if mode == "message":
        problems = check_text(target)
        summary = "the text names nothing internal"
    elif mode == "refs":
        problems, count = check_refs(target, repo)
        summary = f"{count} refs listed by the remote, and none is a working copy or names a machine"
    else:
        problems, files, messages = check_repo(repo, os.path.join(repo, "scripts", ALLOW_NAME))
        summary = f"{files} files and {messages} commit messages read, and none names anything internal"
    if problems:
        for p in problems:
            print(f"no internal reference: {p}", file=sys.stderr)
        return 1
    print(f"no internal reference: {summary}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except CouldNotRun as e:
        print(f"no internal reference: {e}, so nothing was checked", file=sys.stderr)
        sys.exit(2)
