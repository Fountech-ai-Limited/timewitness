#!/usr/bin/env python3
"""Say whether the signature check's self-test notices each of its clauses taken away.

`scripts/the-binaries-are-signed.py --self-test` is what stands between a change to the signature
check and a release that trusts it. A self-test that stays green with a clause deleted is not
holding that clause, and nothing else would notice until a binary signed by somebody else passed.
So this copies the check to a scratch folder, removes one clause at a time, and runs the self-test
on each copy. Every copy has to fail it.

    python scripts/the-signing-self-test-notices-each-clause-removed.py

Each clause is named by the exact text it is removed from. Where that text is not in the check,
the clause is reported as MOVED and the run fails, because a clause that has been rewritten is a
clause nobody has shown the self-test holds. Fix the text here in the same change.

It prints a line per clause, CAUGHT, MISSED or MOVED, and exits 0 only when the untouched copy
passes its self-test and every clause is CAUGHT.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = "the-binaries-are-signed.py"

# What each clause is, the text it lives in, and what that text becomes without it.
CLAUSES = [
    ("Windows: the certificate signtool verified is the one inside the file",
     'if not chain or chain[-1].get("sha1") != signer["sha1"]:',
     'if not chain:'),
    ("Windows: the chain ends at our root",
     'elif chain[0]["to"] != w["root"]:',
     'elif False:'),
    ("Windows: the publisher's common name and organisation",
     'if signer["subject_cn"] != [w["subject_common_name"]] or signer["subject_o"] != [w["subject_organisation"]]:',
     'if False:'),
    ("Windows: the publisher's common name",
     'signer["subject_cn"] != [w["subject_common_name"]] or signer["subject_o"]',
     'signer["subject_o"]'),
    ("Windows: the publisher's organisation",
     ' or signer["subject_o"] != [w["subject_organisation"]]:',
     ':'),
    ("Windows: our identity usage",
     'if w["identity_usage"] not in signer["usages"]:',
     'if False:'),
    ("Windows: the publisher and the identity usage, both",
     'if signer["subject_cn"] != [w["subject_common_name"]] or signer["subject_o"] != [w["subject_organisation"]]:',
     'if False:',
     'if w["identity_usage"] not in signer["usages"]:',
     'if False:'),
    ("Windows: the issuer's organisation",
     'if (signer["issuer_o"] != [w["issuer_organisation"]]\n            or ',
     'if ('),
    ("Windows: the issuer's common name",
     '\n            or len(signer["issuer_cn"]) != 1 or not signer["issuer_cn"][0].startswith(w["issuer_common_name_starts"])):',
     '):'),
    ("Windows: signtool verifies it",
     'if code != 0 or "Successfully verified" not in output:\n        return ["signtool verify /pa does not verify it"]',
     'pass'),
    ("macOS: notarised, and not only signed",
     'return code == 0 and "accepted" in output and "source=Notarized Developer ID" in output',
     'return code == 0'),
    ("Linux: cosign verified it",
     'return code == 0 and "Verified OK" in output',
     'return True'),
    ("Linux: signed by the release workflow run from main, and not from a tag",
     'r"@refs/heads/main$")',
     'r"@refs/")'),
    ("every archive: its digest is its line in the list",
     'elif listed[name] != digest:',
     'elif False:'),
    ("macOS: our team",
     'if teams != [team]:',
     'if False:'),
    ("macOS: a Developer ID Application certificate of our team",
     'if not authorities or not re.fullmatch(r"Developer ID Application: .+ \\(%s\\)" % re.escape(team), authorities[0]):',
     'if not authorities:'),
    ("macOS: the chain is Apple's",
     'elif authorities[1:] != APPLE_CHAIN:',
     'elif False:'),
    ("--version runs only once the target's own clauses passed",
     'return bool(digest) and bool(signature) and all(state == "PASS" for state in clauses)',
     'return True'),
    ("a whole check asks that rule before it runs a binary",
     'if not may_run(digest_of[here], signature_of[here]):',
     'if False:'),
    ("--version runs with no token in its environment",
     'if key.upper() in RUN_ENVIRONMENT]',
     ']'),
]


def self_test(folder):
    done = subprocess.run([sys.executable, os.path.join(folder, CHECK), "--self-test"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def copy_of(source, work, name):
    folder = os.path.join(work, name)
    shutil.copytree(source, folder, ignore=shutil.ignore_patterns("__pycache__"))
    return folder


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else HERE
    with open(os.path.join(source, CHECK), encoding="utf-8") as f:
        text = f.read()
    work = tempfile.mkdtemp(prefix="tw-clauses-")
    failed = False
    try:
        # Only the check, its identities and its fixtures, which is all the self-test reads.
        base = os.path.join(work, "base")
        os.makedirs(base)
        shutil.copy(os.path.join(source, CHECK), base)
        shutil.copy(os.path.join(source, "signing-identities.json"), base)
        shutil.copytree(os.path.join(source, "signing-fixtures"), os.path.join(base, "signing-fixtures"))

        code, out = self_test(base)
        if code != 0:
            print("FAIL: the untouched check does not pass its own self-test, so nothing below means anything")
            print(out.strip())
            return 1
        print("PASS: the untouched check passes its own self-test")

        for number, clause in enumerate(CLAUSES):
            name, pairs = clause[0], list(zip(clause[1::2], clause[2::2]))
            changed = text
            moved = [old for old, _ in pairs if changed.count(old) != 1]
            if moved:
                print("MOVED: %s: the text it lives in is not in the check exactly once" % name)
                failed = True
                continue
            for old, new in pairs:
                changed = changed.replace(old, new)
            folder = copy_of(base, work, "clause-%d" % number)
            with open(os.path.join(folder, CHECK), "w", encoding="utf-8") as f:
                f.write(changed)
            code, out = self_test(folder)
            if code != 0:
                print("CAUGHT: %s: the self-test fails without it" % name)
            else:
                print("MISSED: %s: the self-test passes without it" % name)
                failed = True
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if failed:
        print("FAIL: the self-test does not hold every clause of the signature check")
        return 1
    print("PASS: the self-test fails with any one of its %d clauses taken away" % len(CLAUSES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
