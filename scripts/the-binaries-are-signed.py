#!/usr/bin/env python3
"""Say whether a release carries a signed binary for every platform, and whether each one says it is
that release.

A time agent is something a stranger runs with the rights to read the clock and talk to the network,
so an unsigned one is not a thing anybody should be asked to run. The release workflow builds five
binaries from a tag, signs them, and attaches them with a list of their digests. This reads what was
actually attached, from outside, the way a stranger would get it:

    python scripts/the-binaries-are-signed.py --release v0.4

It asks GitHub for the release, and refuses it unless all five archives are there, Linux on x86_64
and aarch64, macOS on x86_64 and aarch64 and Windows on x86_64, with `SHA256SUMS` and a Sigstore
bundle beside each Linux archive and beside the digest list. It downloads them and holds every
archive to its line in `SHA256SUMS`. Then, where the tools are on this machine:

- the Linux archives and the digest list are checked against their bundles with `cosign`, which
  holds the signature to this repository's release workflow and to GitHub's token issuer, and to
  nothing we hold a key for;
- on macOS, each macOS binary has to pass `codesign --verify --strict`, carry a Developer ID
  Application authority, and be accepted by `spctl` as notarised;
- on Windows, the Windows binary has to pass `signtool verify /pa`.

Last, the binary built for this machine is run, and the first line of `--version` has to be
`timewitness <tag>`. Run it on each of the three systems to cover all five, which is what
`.github/workflows/binaries-check.yml` does.

It prints a line per clause, PASS, FAIL or NOT RUN, and exits 0 when every clause passed, 1 when any
failed, and 2 when none failed but one could not be run here. A clause that could not run is never
read as a pass.

    python scripts/the-binaries-are-signed.py --self-test

puts each judgement to the shapes it has to accept and the shapes it has to refuse, a missing
archive and an unsigned binary among them, and says which were judged wrongly.
"""

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile

REPO = "Fountech-ai-Limited/timewitness"

# Each target, the system it runs on, and what it is packed in. The Linux builds are gnu rather than
# musl, built on the oldest runner image GitHub still offers so the glibc they need is an old one.
TARGETS = {
    "x86_64-unknown-linux-gnu": ("linux", ".tar.gz"),
    "aarch64-unknown-linux-gnu": ("linux", ".tar.gz"),
    "x86_64-apple-darwin": ("macos", ".tar.gz"),
    "aarch64-apple-darwin": ("macos", ".tar.gz"),
    "x86_64-pc-windows-msvc": ("windows", ".zip"),
}
SUMS = "SHA256SUMS"
BUNDLE = ".sigstore.json"

ISSUER = "https://token.actions.githubusercontent.com"


class CouldNotRun(Exception):
    pass


def archive_name(tag, target):
    return "timewitness-%s-%s%s" % (tag, target, TARGETS[target][1])


def signer(tag):
    """Who may have signed a Linux archive of this tag. Keyless signing binds the signature to the
    workflow that ran and the ref it ran from, so this is a statement about where the file came from
    rather than about a key somebody could copy: this tag pushed, or the workflow run from main."""
    return (r"^https://github\.com/Fountech-ai-Limited/timewitness/\.github/workflows/release\.yml"
            r"@refs/(heads/main|tags/%s)$" % re.escape(tag))


def required_assets(tag):
    names = [archive_name(tag, t) for t in TARGETS]
    names += [archive_name(tag, t) + BUNDLE for t in TARGETS if TARGETS[t][0] == "linux"]
    names += [SUMS, SUMS + BUNDLE]
    return names


# The judgements, each a pure function of what was read, so the self-test can put them to shapes.

def judge_assets(tag, attached):
    """The names a release has to carry and does not."""
    return [n for n in required_assets(tag) if n not in set(attached)]


def judge_sums(sums_text, digests):
    """Every archive downloaded has a line in the digest list and its digest is that line's."""
    listed = {}
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            listed[parts[1].lstrip("*")] = parts[0]
    problems = []
    for name, digest in sorted(digests.items()):
        if name not in listed:
            problems.append("%s is not in %s" % (name, SUMS))
        elif listed[name] != digest:
            problems.append("%s has digest %s and %s says %s" % (name, digest[:12], SUMS, listed[name][:12]))
    return problems


def judge_version(tag, first_line):
    return first_line.strip() == "timewitness " + tag


def judge_spctl(code, output):
    """Accepted, and accepted because it is notarised. A Developer ID signature that was never
    notarised reads `source=Unnotarized Developer ID` and is refused."""
    return code == 0 and "accepted" in output and "source=Notarized Developer ID" in output


def judge_codesign(code, output):
    return code == 0 and "Authority=Developer ID Application:" in output


def judge_signtool(code, output):
    return code == 0 and "Successfully verified" in output


def judge_cosign(code, output):
    return code == 0 and "Verified OK" in output


def verdict(results):
    states = [state for state, _ in results]
    if "FAIL" in states:
        return 1
    if "NOT RUN" in states or not states:
        return 2
    return 0


# Reading the world.

def run(argv):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CouldNotRun("%s could not be run: %s" % (argv[0], e))
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def fetch(url, accept=None):
    request = urllib.request.Request(url, headers={"User-Agent": "timewitness-binaries-check"})
    if accept:
        request.add_header("Accept", accept)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise CouldNotRun("%s answered %s" % (url, e.code))
    except OSError as e:
        raise CouldNotRun("%s could not be read: %s" % (url, e))


def host_target():
    system, machine = platform.system(), platform.machine().lower()
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(machine)
    target = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
        ("Darwin", "aarch64"): "aarch64-apple-darwin",
        ("Windows", "x86_64"): "x86_64-pc-windows-msvc",
    }.get((system, arch))
    return target


def unpack(archive, into):
    os.makedirs(into, exist_ok=True)
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            z.extractall(into)
    else:
        with tarfile.open(archive) as t:
            if hasattr(tarfile, "data_filter"):
                t.extractall(into, filter="data")
            else:
                t.extractall(into)
    for name in ("timewitness.exe", "timewitness"):
        path = os.path.join(into, name)
        if os.path.isfile(path):
            return path
    raise CouldNotRun("%s holds no timewitness binary at its top level" % os.path.basename(archive))


def signtool():
    found = shutil.which("signtool")
    if found:
        return found
    kits = sorted(glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"))
    return kits[-1] if kits else None


def check(tag, repo, work):
    results = []

    def say(state, line):
        results.append((state, line))
        print("%s: %s" % (state, line), flush=True)

    raw = fetch("https://api.github.com/repos/%s/releases/tags/%s" % (repo, tag), "application/vnd.github+json")
    if raw is None:
        say("FAIL", "%s has no release called %s" % (repo, tag))
        return results
    release = json.loads(raw)
    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    print("%s %s: %d assets, %s" % (repo, tag, len(assets), "pre-release" if release.get("prerelease") else "release"))

    missing = judge_assets(tag, assets)
    if missing:
        say("FAIL", "missing from the release: " + ", ".join(missing))
    else:
        say("PASS", "all five archives, their digest list and the three Sigstore bundles are attached")

    files = {}
    for name in required_assets(tag):
        if name in assets:
            try:
                body = fetch(assets[name])
            except CouldNotRun as e:
                say("NOT RUN", "%s could not be downloaded: %s" % (name, e))
                continue
            if body is None:
                say("FAIL", "%s is listed and could not be downloaded" % name)
                continue
            path = os.path.join(work, name)
            with open(path, "wb") as f:
                f.write(body)
            files[name] = path

    archives = {n: p for n, p in files.items() if not n.endswith(BUNDLE) and n != SUMS}
    if SUMS in files:
        with open(files[SUMS], encoding="utf-8") as f:
            sums_text = f.read()
        digests = {}
        for name, path in archives.items():
            with open(path, "rb") as f:
                digests[name] = hashlib.sha256(f.read()).hexdigest()
        problems = judge_sums(sums_text, digests)
        if problems:
            say("FAIL", "; ".join(problems))
        elif digests:
            say("PASS", "%d archives each match their line in %s" % (len(digests), SUMS))

    # The Linux signatures, which any machine with cosign can check.
    cosign = shutil.which("cosign")
    signed_blobs = [n for n in files if n + BUNDLE in files]
    if not cosign:
        say("NOT RUN", "cosign is not on this machine, so the Linux signatures were not checked here")
    else:
        for name in sorted(signed_blobs):
            code, out = run([cosign, "verify-blob", files[name], "--bundle", files[name + BUNDLE],
                             "--certificate-identity-regexp", signer(tag),
                             "--certificate-oidc-issuer", ISSUER])
            if judge_cosign(code, out):
                say("PASS", "%s is signed by this repository's release workflow (cosign)" % name)
            else:
                say("FAIL", "%s did not verify against its bundle: %s" % (name, out.strip().splitlines()[-1:] or out))

    def opened(name, into):
        try:
            return unpack(files[name], into)
        except (CouldNotRun, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
            say("FAIL", "%s could not be unpacked: %s" % (name, e))
            return None

    here = host_target()
    system = TARGETS[here][0] if here else None
    for target, (os_name, _) in TARGETS.items():
        name = archive_name(tag, target)
        if name not in files:
            continue
        if os_name == "macos" and system == "macos":
            binary = opened(name, os.path.join(work, target))
            if binary is None:
                continue
            code, out = run(["codesign", "--verify", "--strict", "--verbose=2", binary])
            code2, out2 = run(["codesign", "-dv", "--verbose=4", binary])
            if code == 0 and judge_codesign(code2, out2):
                say("PASS", "%s: codesign verifies it and names a Developer ID Application authority" % target)
            else:
                say("FAIL", "%s: codesign says it is not signed with a Developer ID: %s" % (target, (out + out2).strip().splitlines()[:2]))
            code, out = run(["spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "-vv", binary])
            if judge_spctl(code, out):
                say("PASS", "%s: spctl accepts it as notarised" % target)
            else:
                say("FAIL", "%s: spctl refuses it: %s" % (target, " ".join(out.split())[:200]))
        elif os_name == "windows" and system == "windows":
            binary = opened(name, os.path.join(work, target))
            if binary is None:
                continue
            tool = signtool()
            if not tool:
                say("NOT RUN", "%s: signtool is not on this machine, so the Windows signature was not checked here" % target)
            else:
                code, out = run([tool, "verify", "/pa", "/v", binary])
                if judge_signtool(code, out):
                    say("PASS", "%s: signtool verify /pa passes" % target)
                else:
                    say("FAIL", "%s: signtool verify /pa refuses it: %s" % (target, " ".join(out.split())[-200:]))
        elif os_name != "linux":
            # Not a clause here: the leg on that system checks it. Said, so nobody reads it as checked.
            print("ELSEWHERE: %s: its signature is checked on %s, and this is not" % (target, os_name))

    if here is None:
        say("NOT RUN", "this machine is none of the five targets, so no --version was read")
    elif archive_name(tag, here) in files:
        binary = opened(archive_name(tag, here), os.path.join(work, here + "-run"))
        if binary is None:
            return results
        if system != "windows":
            os.chmod(binary, 0o755)
        code, out = run([binary, "--version"])
        first = out.splitlines()[0] if out.splitlines() else ""
        if code == 0 and judge_version(tag, first):
            say("PASS", "%s: --version says [%s]" % (here, first))
        else:
            say("FAIL", "%s: --version says [%s], not [timewitness %s]" % (here, first, tag))
    return results


def self_test():
    wrong = []

    def expect(name, got, want):
        if got != want:
            wrong.append("%s: judged %r, should be %r" % (name, got, want))

    tag = "v0.4"
    whole = required_assets(tag)
    expect("every asset there", judge_assets(tag, whole), [])
    expect("an archive missing", judge_assets(tag, [n for n in whole if "windows" not in n]),
           ["timewitness-v0.4-x86_64-pc-windows-msvc.zip"])
    expect("a bundle missing", judge_assets(tag, [n for n in whole if n != SUMS + BUNDLE]), [SUMS + BUNDLE])
    expect("the digest list missing", judge_assets(tag, [n for n in whole if n != SUMS]), [SUMS])
    expect("an empty release", len(judge_assets(tag, [])), len(whole))

    a, b = "a" * 64, "b" * 64
    expect("digests match", judge_sums("%s  x.zip\n%s *y.tar.gz\n" % (a, b), {"x.zip": a, "y.tar.gz": b}), [])
    expect("a digest differs", len(judge_sums("%s  x.zip\n" % a, {"x.zip": b})), 1)
    expect("an archive not listed", len(judge_sums("%s  x.zip\n" % a, {"x.zip": a, "y.tar.gz": b})), 1)

    expect("the tag", judge_version("v0.4", "timewitness v0.4"), True)
    expect("a dev build under a release tag", judge_version("v0.4", "timewitness v0.4-dev"), False)
    expect("the manifest spelling", judge_version("v0.4", "timewitness 0.4.0"), False)
    expect("nothing printed", judge_version("v0.4", ""), False)

    expect("notarised", judge_spctl(0, "x: accepted\nsource=Notarized Developer ID\n"), True)
    expect("unsigned", judge_spctl(3, "x: rejected\nsource=no usable signature\n"), False)
    expect("signed and never notarised", judge_spctl(3, "x: rejected\nsource=Unnotarized Developer ID\n"), False)
    expect("accepted for another reason", judge_spctl(0, "x: accepted\nsource=Apple System\n"), False)
    expect("Developer ID", judge_codesign(0, "Authority=Developer ID Application: Someone (TEAM)\n"), True)
    expect("ad hoc", judge_codesign(0, "Signature=adhoc\n"), False)
    expect("not signed at all", judge_codesign(1, "code object is not signed at all\n"), False)

    expect("signtool passes", judge_signtool(0, "Successfully verified: x.exe\n"), True)
    expect("signtool, no signature", judge_signtool(1, "SignTool Error: No signature found.\n"), False)
    expect("signtool, exit 0 and no verdict", judge_signtool(0, ""), False)
    base = "https://github.com/Fountech-ai-Limited/timewitness/.github/workflows/release.yml@refs/"
    expect("signed by this tag's run", bool(re.match(signer("v0.4"), base + "tags/v0.4")), True)
    expect("signed by a run from main", bool(re.match(signer("v0.4"), base + "heads/main")), True)
    expect("signed by another tag's run", bool(re.match(signer("v0.4"), base + "tags/v0.4.1")), False)
    expect("signed by a run from a branch", bool(re.match(signer("v0.4"), base + "heads/other")), False)
    expect("signed by another workflow", bool(re.match(signer("v0.4"), base.replace("release.yml", "ci.yml") + "tags/v0.4")), False)
    expect("cosign passes", judge_cosign(0, "Verified OK\n"), True)
    expect("cosign refuses", judge_cosign(1, "Error: none of the expected identities matched\n"), False)

    expect("all pass", verdict([("PASS", "")] * 3), 0)
    expect("a failure beats a clause not run", verdict([("NOT RUN", ""), ("FAIL", "")]), 1)
    expect("a clause not run is not a pass", verdict([("PASS", ""), ("NOT RUN", "")]), 2)
    expect("nothing read is not a pass", verdict([]), 2)

    for line in wrong:
        print("self-test: " + line)
    if wrong:
        print("self-test: %d judged wrongly" % len(wrong))
        return 1
    print("self-test: every shape judged as it should be, a missing archive and an unsigned binary among the refusals")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", help="the release tag to check")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.release:
        parser.error("name the release with --release, or run --self-test")
    work = tempfile.mkdtemp(prefix="tw-binaries-")
    try:
        results = check(args.release, args.repo, work)
    except CouldNotRun as e:
        print("NOT RUN: %s" % e)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)
    code = verdict(results)
    print({0: "PASS: every clause passed on this machine",
           1: "FAIL: at least one clause failed",
           2: "NOT RUN: nothing failed, and at least one clause could not be checked here"}[code])
    return code


if __name__ == "__main__":
    sys.exit(main())
