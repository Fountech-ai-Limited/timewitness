#!/usr/bin/env python3
"""Hold every label that names a receipt format to the format the receipt is written in.

Two labels said version 0 long after the receipts under them were version 1. The verifier page
printed "Receipt format v0" as a constant, and the Action wrote `timewitness-receipt-v0` into the
provenance around every receipt, while every receipt the `v0.2` release writes is version 1. A
consumer choosing a reader by the provenance label would have chosen one that refuses the receipt.
Both labels are now read off something: the page off the checking code, the provenance off the
version the verifier read from the receipt's own bytes. This holds them to that.

    python scripts/the-format-labels-are-the-receipts.py

reads this tree. The page may name no format as a constant and has to ask the checking code for the
formats it reads and for the version of the receipt in hand. The provenance writer is driven over a
committed receipt of each version and has to label each with the version in its bytes, and has to
refuse to write anything when it is handed no version.

    python scripts/the-format-labels-are-the-receipts.py --release v0.3 [--provenance FILE]

reads what shipped. The page at the tag is held to the same rule, and the provenance the public
install check made with that release, from its `stamped-with-v0.3` release, is downloaded with no
token and its label held to the version in the bytes of the receipt it carries. The version is read
from the CBOR here, by hand, rather than by anything of ours. `--provenance` reads a statement from
disk instead and `--at` reads the page at a commit rather than the tag, which together are the dry
run before a release exists.

    python scripts/the-format-labels-are-the-receipts.py --self-test

plants each fault the rules exist for and watches each one refused, the two labels as they stood on
`v0.2` among them.

Exit 0 when every label is the receipt's, 1 when one is not, 2 when the check could not run.
"""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = "verifier-page/page.html"
WRITER = "scripts/action-provenance.py"
STAMPER = "scripts/action-stamp.sh"
CHECK = "Fountech-ai-Limited/timewitness-install-check"
DATA = os.path.join(ROOT, "crates", "verify", "tests", "data")

# A format named as a number written into the page: "format v0", "format version 1", "receipt-v0".
CONSTANT = re.compile(r"format\s+(?:version\s+)?v?\d|receipt-v\d", re.I)


class CouldNotRun(Exception):
    pass


def without_comments(text):
    """The page with its comments taken out, so a comment saying what the page used to print is not
    read as the page printing it."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def judge_page(text, where):
    lines = []
    passed = True
    code = without_comments(text)
    for line in code.splitlines():
        if CONSTANT.search(line):
            lines.append("refused: %s names a format as a constant: %s" % (where, line.strip()))
            passed = False
    if "tw_formats(" not in code:
        lines.append("refused: %s does not ask the checking code which formats it reads" % where)
        passed = False
    if "format_version" not in code:
        lines.append("refused: %s does not print the version the receipt in hand carries" % where)
        passed = False
    if passed:
        lines.append("%s names no format of its own and reads both off the checking code" % where)
    return passed, lines


def head(data, at):
    """One CBOR item's head: major type, argument, where the bytes after the head start."""
    first = data[at]
    major, low = first >> 5, first & 0x1F
    if low < 24:
        return major, low, at + 1
    if low > 27:
        raise ValueError("an indefinite or reserved length at byte %d" % at)
    width = 1 << (low - 24)
    return major, int.from_bytes(data[at + 1:at + 1 + width], "big"), at + 1 + width


def skip(data, at):
    major, argument, after = head(data, at)
    if major in (0, 1, 7):
        return after
    if major in (2, 3):
        return after + argument
    if major == 4:
        for _ in range(argument):
            after = skip(data, after)
        return after
    if major == 5:
        for _ in range(argument * 2):
            after = skip(data, after)
        return after
    return skip(data, after)


def version_in(receipt):
    """The `v` in a receipt's signed payload: a COSE_Sign1 array of four whose third item is a byte
    string holding a map."""
    major, count, at = head(receipt, 0)
    if major == 6:
        major, count, at = head(receipt, at)
    if (major, count) != (4, 4):
        raise ValueError("not a COSE_Sign1 array of four")
    at = skip(receipt, skip(receipt, at))
    major, length, start = head(receipt, at)
    if major != 2:
        raise ValueError("the payload is not a byte string")
    payload = receipt[start:start + length]
    major, entries, at = head(payload, 0)
    if major != 5:
        raise ValueError("the payload is not a map")
    for _ in range(entries):
        key_end = skip(payload, at)
        if payload[at:key_end] == b"\x61v":
            major, value, _ = head(payload, key_end)
            if major != 0:
                raise ValueError("the version is not an unsigned integer")
            return value
        at = skip(payload, key_end)
    raise ValueError("the payload has no key v")


def judge_statement(statement, where):
    lines = []
    try:
        carried = statement["predicate"]["boundedTime"]
        said = carried["format"]
        receipt = base64.b64decode(carried["receiptBase64"], validate=True)
    except (KeyError, TypeError, ValueError) as e:
        return False, ["refused: %s carries no readable receipt and label: %s" % (where, e)]
    try:
        version = version_in(receipt)
    except (ValueError, IndexError) as e:
        return False, ["refused: the receipt %s carries could not be read: %s" % (where, e)]
    lines.append("%s calls its receipt [%s], and the receipt's own bytes say version %d"
                 % (where, said, version))
    if said != "timewitness-receipt-v%d" % version:
        lines.append("refused: a format %d receipt is labelled %s" % (version, said))
        return False, lines
    return True, lines


def fixture(name):
    folder = os.path.join(DATA, name)
    if os.path.isfile(os.path.join(folder, "receipt.cbor")):
        with open(os.path.join(folder, "receipt.cbor"), "rb") as handle:
            return handle.read()
    with open(os.path.join(folder, "receipt.hex"), encoding="ascii") as handle:
        return bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", handle.read()))


def drive_writer(receipt, version, work):
    """Run the provenance writer the way the Action does, over a bare statement. Returns its exit
    status and the statement as it was left."""
    path = os.path.join(work, "statement.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"_type": "https://in-toto.io/Statement/v1", "predicate": {}}, handle)
    env = dict(os.environ, TW_P=path, TW_R=base64.b64encode(receipt).decode("ascii"),
               TW_E="build", TW_EARLIEST="1", TW_LATEST="2", TW_WIDTH="1", TW_READING="1")
    env.pop("TW_FORMAT", None)
    if version is not None:
        env["TW_FORMAT"] = version
    out = subprocess.run([sys.executable, os.path.join(ROOT, WRITER)], env=env,
                         capture_output=True, text=True)
    with open(path, encoding="utf-8") as handle:
        return out.returncode, json.load(handle)


def check_writer():
    lines = []
    passed = True
    with open(os.path.join(ROOT, STAMPER), encoding="utf-8") as handle:
        stamper = handle.read()
    if "field format_version" not in stamper or 'TW_FORMAT="$format"' not in stamper:
        lines.append("refused: %s does not hand the provenance writer the version the verifier "
                     "read off the receipt" % STAMPER)
        passed = False
    work = tempfile.mkdtemp(prefix="tw-labels-")
    try:
        for name in ("a-real-stamp", "a-version-1-stamp"):
            receipt = fixture(name)
            status, statement = drive_writer(receipt, str(version_in(receipt)), work)
            ok, said = judge_statement(statement, "the provenance written over %s" % name)
            lines.extend(said)
            if status != 0 or not ok:
                lines.append("refused: the writer exited %d over %s" % (status, name))
                passed = False
        status, statement = drive_writer(fixture("a-version-1-stamp"), None, work)
        if status == 0 or "boundedTime" in statement.get("predicate", {}):
            lines.append("refused: handed no version, the writer still wrote a label")
            passed = False
        else:
            lines.append("handed no version, the writer wrote nothing and exited %d" % status)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return passed, lines


def check_tree():
    with open(os.path.join(ROOT, PAGE), encoding="utf-8") as handle:
        page_ok, lines = judge_page(handle.read(), PAGE)
    writer_ok, more = check_writer()
    return page_ok and writer_ok, lines + more


def check_release(tag, at, provenance):
    shown = run_git(["show", "%s:%s" % (at or tag, PAGE)])
    page_ok, lines = judge_page(shown, "the page at %s" % (at or tag))
    if provenance:
        with open(provenance, encoding="utf-8") as handle:
            statement = json.load(handle)
        where = provenance
    else:
        url = "https://github.com/%s/releases/download/stamped-with-%s/widget.intoto.json" % (CHECK, tag)
        try:
            with urllib.request.urlopen(url, timeout=60) as answer:
                statement = json.load(answer)
        except Exception as e:
            raise CouldNotRun("no provenance could be read from %s: %s" % (url, e))
        where = "the install check's provenance for %s" % tag
    statement_ok, more = judge_statement(statement, where)
    return page_ok and statement_ok, lines + more


def run_git(args):
    out = subprocess.run(["git", "-C", ROOT] + args, capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise CouldNotRun("git %s failed: %s. Fetch the tags" % (" ".join(args), out.stderr.strip()))
    return out.stdout


def self_test():
    wrong = 0

    def expect(name, want, got):
        nonlocal wrong
        wrong += 0 if want == got else 1
        print("%-5s %s" % ("ok" if want == got else "WRONG", name))

    with open(os.path.join(ROOT, PAGE), encoding="utf-8") as handle:
        page = handle.read()
    expect("the page as it stands", True, judge_page(page, "page")[0])
    as_on_v02 = page.replace('"This page carries the verifier as "',
                             '"Receipt format v0. This page carries the verifier as "')
    expect("the page printing Receipt format v0, as on v0.2", False, judge_page(as_on_v02, "page")[0])
    expect("the page naming format version 1 in a sentence", False,
           judge_page(page + '\n<script>x = "This receipt is format version 1.";</script>', "page")[0])
    expect("a format named only in a comment", True,
           judge_page(page + "\n<!-- it said Receipt format v0 -->\n// format v0\n", "page")[0])
    expect("a page that never asks for the formats", False,
           judge_page(page.replace("tw_formats(", "tw_nothing("), "page")[0])
    expect("a page that never prints the receipt's version", False,
           judge_page(page.replace("format_version", "some_field"), "page")[0])

    v0, v1 = fixture("a-real-stamp"), fixture("a-version-1-stamp")
    expect("the version 0 fixture reads as 0", 0, version_in(v0))
    expect("the version 1 fixture reads as 1", 1, version_in(v1))

    def statement(receipt, label):
        return {"predicate": {"boundedTime": {
            "format": label, "receiptBase64": base64.b64encode(receipt).decode("ascii")}}}

    expect("a version 1 receipt labelled v1", True,
           judge_statement(statement(v1, "timewitness-receipt-v1"), "s")[0])
    expect("a version 0 receipt labelled v0", True,
           judge_statement(statement(v0, "timewitness-receipt-v0"), "s")[0])
    expect("a version 1 receipt labelled v0, as v0.2 wrote it", False,
           judge_statement(statement(v1, "timewitness-receipt-v0"), "s")[0])
    expect("a version 0 receipt labelled v1", False,
           judge_statement(statement(v0, "timewitness-receipt-v1"), "s")[0])
    expect("a statement with no receipt in it", False, judge_statement({"predicate": {}}, "s")[0])
    expect("a receipt that is not base64", False,
           judge_statement({"predicate": {"boundedTime": {
               "format": "timewitness-receipt-v1", "receiptBase64": "not base64!"}}}, "s")[0])
    expect("a receipt cut short", False,
           judge_statement(statement(v1[:40], "timewitness-receipt-v1"), "s")[0])

    work = tempfile.mkdtemp(prefix="tw-labels-")
    try:
        status, written = drive_writer(v1, "1", work)
        expect("the writer labels a version 1 receipt v1", (0, True),
               (status, judge_statement(written, "s")[0]))
        status, written = drive_writer(v1, "", work)
        expect("the writer handed an empty version writes nothing", True,
               status != 0 and "boundedTime" not in written["predicate"])
        status, written = drive_writer(v1, "1; v0", work)
        expect("the writer handed a version that is not a number writes nothing", True,
               status != 0 and "boundedTime" not in written["predicate"])
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("self-test: %d wrong" % wrong)
    return 1 if wrong else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--release", metavar="TAG")
    parser.add_argument("--provenance", metavar="FILE", help="a statement on disk, with --release")
    parser.add_argument("--at", metavar="REF", help="read the page at this commit rather than the tag")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if (args.provenance or args.at) and not args.release:
        parser.error("--provenance and --at stand in for what a release shipped, so they need --release")
    try:
        passed, lines = check_release(args.release, args.at, args.provenance) if args.release else check_tree()
    except (CouldNotRun, OSError, ValueError) as e:
        print("the format label check could not run: %s" % e, file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
