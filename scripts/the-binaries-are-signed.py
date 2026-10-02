#!/usr/bin/env python3
"""Say whether a release carries a binary for every platform signed by us, and whether each one says
it is that release.

A time agent is something a stranger runs with the rights to read the clock and talk to the network,
so an unsigned one is not a thing anybody should be asked to run, and nor is one signed by somebody
else. The release workflow builds five binaries from a tag, signs them, and attaches them with a list
of their digests. This reads what was actually attached, from outside, the way a stranger would get
it:

    python scripts/the-binaries-are-signed.py --release v0.4

It asks GitHub for the release, and refuses it unless all five archives are there, Linux on x86_64
and aarch64, macOS on x86_64 and aarch64 and Windows on x86_64, with `SHA256SUMS` and a Sigstore
bundle beside each Linux archive and beside the digest list. It downloads them and holds every
archive to its line in `SHA256SUMS`. Then, where the tools are on this machine:

- the Linux archives and the digest list are checked against their bundles with `cosign`, which
  holds the signature to this repository's release workflow and to GitHub's token issuer, and to
  nothing we hold a key for, and then the certificate cosign verified is held to the one job in that
  workflow that signs them, so no other job's token passes for it;
- on macOS, each macOS binary has to pass `codesign --verify --strict`, carry a Developer ID
  Application authority for our own Apple team and no other, chained to Apple's root, and be
  accepted by `spctl` as notarised;
- on Windows, the Windows binary has to pass `signtool verify /pa`, and the certificate that signed
  it has to be ours: our subject, our identity usage and the issuer our signing service uses, read
  off the signature inside the file and tied to the chain signtool verified by its SHA-1.

Who "ours" is lives in one tracked file beside this one, `scripts/signing-identities.json`. Any
Developer ID and any trusted code-signing certificate would pass a check that did not ask, so a
value left unset there fails every release rather than letting one through, and says so.

Last, the binary built for this machine is run, and the first line of `--version` has to be
`timewitness <tag>`. It is run only once both clauses about it have passed here: its line in
`SHA256SUMS` and its own signature. A binary this check has refused, or could not check, is never
run. The one it runs is handed an environment holding nothing but what it needs to start, so no
token the check was given is in the binary's own environment; that is not a sandbox, and anything
running as the same user can still read what the check's parent holds, so run this where no token
worth having is held. Run it on each of the three systems to cover all five, which is what
`.github/workflows/binaries-check.yml` does. `--no-run` leaves the binary alone and says so.

It prints a line per clause, PASS, FAIL or NOT RUN, and exits 0 when every clause passed, 1 when any
failed, and 2 when none failed but one could not be run here. A clause that could not run is never
read as a pass. A signature that can only be checked on another system is printed as ELSEWHERE, and
the last line names those targets, so a pass on one machine is not read as a pass for all five.

    python scripts/the-binaries-are-signed.py --release v0.4 --dist dist --no-run

reads the same assets out of a folder instead of a release, which is how the release workflow's
rehearsal checks what it would have attached. It runs nothing there, because that job holds the
token that signs.

    python scripts/the-binaries-are-signed.py --release v0.4 --dist dist --no-run --rehearsal-key cosign.pub

is what the rehearsal runs, since it signs the Linux archives with a key made for that run alone
rather than into the public transparency log. The bundles are checked against that key, and a line
saying so fails the run whatever else passed: a signature from a key nobody else has seen proves
nothing about where a file came from, so with this option the check can never pass a release.

    python scripts/the-binaries-are-signed.py --binary path/to/timewitness

holds one binary already on this machine to the same signature clauses, which is how the release
workflow checks what it signed before anything is attached.

    python scripts/the-binaries-are-signed.py --pins

says whether every identity is set, exit 0 when it is and 1 with the unset ones named.

    python scripts/the-binaries-are-signed.py --self-test

puts each judgement to the shapes it has to accept and the shapes it has to refuse, and says which
were judged wrongly. Among the refusals are a missing archive, an unsigned binary, another team's
Developer ID, a Windows binary really signed by another publisher, one signed with our name by
another issuer, one signed by another customer of our own signing service, one whose certificate is
not the one signtool verified, and a check whose identities are not set. The Windows ones are real
signed binaries, built by `scripts/signing-fixtures/make-fixtures.py` from throwaway certificates.
`scripts/the-signing-self-test-notices-each-clause-removed.py` takes each clause away in turn and
holds this self-test to failing without it.
"""

import argparse
import base64
import glob
import hashlib
import io
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
import zipfile

REPO = "Fountech-ai-Limited/timewitness"
HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(HERE, "signing-identities.json")
FIXTURES = os.path.join(HERE, "signing-fixtures")

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

# Above our own Developer ID Application certificate, in the order codesign lists them. Apple's
# second generation intermediate keeps the first one's common name, so one list covers both.
APPLE_CHAIN = ["Developer ID Certification Authority", "Apple Root CA"]


class CouldNotRun(Exception):
    pass


def archive_name(tag, target):
    return "timewitness-%s-%s%s" % (tag, target, TARGETS[target][1])


# Who may have signed a Linux archive. Keyless signing binds the signature to the workflow that ran
# and the ref it ran from, so this is a statement about where the file came from rather than about a
# key somebody could copy: the release workflow, run from main. A run started by a tag is refused,
# because a tag's commit carries its own copy of the workflow and need never have been reviewed. The
# tag itself is held by the archive's name and by `--version`.
SIGNER = (r"^https://github\.com/Fountech-ai-Limited/timewitness/\.github/workflows/release\.yml"
          r"@refs/heads/main$")

# Which job in that run signed. Every job in a run of the release workflow from main is given the
# identity above, so it does not tell the job that signs the Linux archives from `sign-windows`,
# which asks GitHub for a token to sign in to Azure. Code running there could trade that token for a
# Sigstore certificate of its own and sign a Linux archive the identity above accepts. The subject of
# the token does tell them apart, and Fulcio copies it into the certificate: a job that enters an
# environment is given a subject naming that environment, and only the job that signs the Linux
# archives enters `linux-signing`. The subject names this repository and its owner by number as well
# as by name, so a repository renamed or recreated under the same name does not carry it, and the ref
# and the workflow the job ran from, as the identity above does. The repository's number is written
# here once, and `scripts/the-release-route-holds.py` fails while it differs from `REPO_NUMBER` there.
LINUX_SUBJECT = "repo:Fountech-ai-Limited@110895113/timewitness@1401363610:environment:linux-signing:ref:refs/heads/main:job_workflow_ref:Fountech-ai-Limited/timewitness/.github/workflows/release.yml@refs/heads/main"
OID_TOKEN_SUBJECT = "1.3.6.1.4.1.57264.1.24"


def required_assets(tag):
    names = [archive_name(tag, t) for t in TARGETS]
    names += [archive_name(tag, t) + BUNDLE for t in TARGETS if TARGETS[t][0] == "linux"]
    names += [SUMS, SUMS + BUNDLE]
    return names


# Who we are. Read from one file, so the release workflow, this check and a stranger all hold a
# binary to the same names.

PIN_SHAPES = {
    ("apple", "team_id"): (r"[A-Z0-9]{10}", "the Apple Team ID"),
    ("windows", "subject_common_name"): (r".*\S.*", "the Windows publisher's common name"),
    ("windows", "subject_organisation"): (r".*\S.*", "the Windows publisher's organisation"),
    ("windows", "identity_usage"): (r"[0-2](\.[0-9]+)+", "the identity usage on our Windows certificate"),
    ("windows", "issuer_organisation"): (r".*\S.*", "the organisation that issues our Windows certificate"),
    ("windows", "issuer_common_name_starts"): (r".*\S.*", "the name our Windows certificate's issuer starts with"),
    ("windows", "root"): (r".*\S.*", "the root our Windows certificate chains to"),
}


def not_pinned(what):
    return ("NOT PINNED: %s is not set in scripts/signing-identities.json, so this check cannot tell our "
            "binaries from anybody else's and refuses rather than pass them" % what)


def load_pins(path=PINS):
    """The identities, and a sentence for each one that is unset or malformed. Nothing is pinned
    until the list of sentences is empty."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        return {}, ["NOT PINNED: %s could not be read (%s), so nothing is pinned" % (os.path.basename(path), e)]
    pins, problems = {}, []
    for (system, key), (shape, what) in PIN_SHAPES.items():
        section = raw.get(system) if isinstance(raw, dict) else None
        value = section.get(key) if isinstance(section, dict) else None
        if value is None or value == "":
            problems.append(not_pinned(what))
        elif not isinstance(value, str) or not re.fullmatch(shape, value):
            problems.append("NOT PINNED: %s in scripts/signing-identities.json reads %r, which is not one"
                            % (what, value))
        else:
            pins.setdefault(system, {})[key] = value
    return pins, problems


def pin(pins, system, key):
    return (pins.get(system) or {}).get(key)


# Reading a Windows signature out of the file itself. Authenticode keeps it in the PE's security
# directory as a PKCS#7 SignedData, and the certificate that signed is the one the signer info names
# by issuer and serial. Read here with nothing beyond the standard library, so the parsing runs on any
# system; whether the signature is good is signtool's to say, on Windows, and the SHA-1 of the
# certificate read here has to be the one at the end of the chain signtool verified.

OID_CN, OID_O, OID_EKU, OID_SKI = "2.5.4.3", "2.5.4.10", "2.5.29.37", "2.5.29.14"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"


def der(data, i):
    """The tag at `i`, where its contents start, and where they end."""
    if i + 2 > len(data):
        raise ValueError("DER runs past its end")
    tag, first = data[i], data[i + 1]
    i += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or i + n > len(data):
            raise ValueError("a DER length this does not read")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    if i + length > len(data):
        raise ValueError("DER runs past its end")
    return tag, i, i + length


def children(data, start, end):
    out, i = [], start
    while i < end:
        tag, s, e = der(data, i)
        out.append((tag, s, e, i))
        i = e
    return out


def oid_text(b):
    parts, value = [], 0
    for byte in b:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if not parts:
        return ""
    first = min(parts[0] // 40, 2)
    return ".".join(str(p) for p in [first, parts[0] - 40 * first] + parts[1:])


def string_value(tag, b):
    if tag == 0x1E:
        return b.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return b.decode("utf-32-be", "replace")
    if tag == 0x14:
        return b.decode("latin-1")
    return b.decode("utf-8", "replace")


def name_fields(data, start, end):
    fields = {}
    for _, s, e, _ in children(data, start, end):
        for _, s2, e2, _ in children(data, s, e):
            parts = children(data, s2, e2)
            if len(parts) >= 2 and parts[0][0] == 0x06:
                oid = oid_text(data[parts[0][1]:parts[0][2]])
                fields.setdefault(oid, []).append(string_value(parts[1][0], data[parts[1][1]:parts[1][2]]))
    return fields


def read_certificate(data, start, end, whole_start):
    """What one certificate says, from the DER at data[whole_start:end]."""
    tbs = children(data, start, end)[0]
    fields = children(data, tbs[1], tbs[2])
    if fields and fields[0][0] == 0xA0:
        fields = fields[1:]
    serial, issuer, subject = fields[0], fields[2], fields[4]
    usages, ski = [], None
    for tag, s, e, _ in fields[6:]:
        if tag != 0xA3:
            continue
        for _, s2, e2, _ in children(data, *children(data, s, e)[0][1:3]):
            ext = children(data, s2, e2)
            oid = oid_text(data[ext[0][1]:ext[0][2]])
            value = ext[-1]
            if oid == OID_EKU:
                inner = children(data, value[1], value[2])[0]
                usages = [oid_text(data[s3:e3]) for _, s3, e3, _ in children(data, inner[1], inner[2])]
            elif oid == OID_SKI:
                inner = children(data, value[1], value[2])[0]
                ski = data[inner[1]:inner[2]]
    subject_fields = name_fields(data, subject[1], subject[2])
    issuer_fields = name_fields(data, issuer[1], issuer[2])
    return {
        "sha1": hashlib.sha1(data[whole_start:end]).hexdigest().upper(),
        "subject_cn": subject_fields.get(OID_CN, []),
        "subject_o": subject_fields.get(OID_O, []),
        "issuer_cn": issuer_fields.get(OID_CN, []),
        "issuer_o": issuer_fields.get(OID_O, []),
        "usages": usages,
        "issuer_der": data[issuer[3]:issuer[2]],
        "serial_der": data[serial[3]:serial[2]],
        "ski": ski,
    }


def pe_signature(data):
    """The PKCS#7 in a PE's security directory, None when there is none, and ValueError for a file
    this will not read, which includes a second signature entry Windows would never look at."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not a Windows executable")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a Windows executable")
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("an optional header this does not read")
    directories = optional + (96 if magic == 0x10B else 112)
    count = struct.unpack_from("<I", data, directories - 4)[0]
    if count <= 4:
        return None
    offset, size = struct.unpack_from("<II", data, directories + 4 * 8)
    if offset == 0 or size == 0:
        return None
    if offset + size > len(data) or size < 8:
        raise ValueError("the security directory runs past the end of the file")
    length, revision, kind = struct.unpack_from("<IHH", data, offset)
    if revision != 0x0200 or kind != 0x0002 or length < 8 or length > size:
        raise ValueError("the security directory holds something other than one Authenticode signature")
    if size - ((length + 7) & ~7) > 0:
        raise ValueError("the security directory holds more than one signature entry")
    return data[offset + 8:offset + length]


def read_signer(data):
    """The certificate that signed a Windows binary, from the binary's own bytes, or None when it is
    not signed. ValueError for anything this will not read."""
    try:
        return signer_of(data)
    except (IndexError, struct.error) as e:
        raise ValueError("the file is cut short or malformed where the signature should be (%s)" % e)


def signer_of(data):
    blob = pe_signature(data)
    if blob is None:
        return None
    top = children(blob, *der(blob, 0)[1:3])
    if len(top) != 2 or top[0][0] != 0x06 or oid_text(blob[top[0][1]:top[0][2]]) != OID_SIGNED_DATA:
        raise ValueError("the signature is not a PKCS#7 SignedData")
    signed = children(blob, *children(blob, top[1][1], top[1][2])[0][1:3])
    certificates = []
    for tag, s, e, _ in signed:
        if tag == 0xA0:
            for _, s2, e2, whole in children(blob, s, e):
                certificates.append(read_certificate(blob, s2, e2, whole))
    if signed[-1][0] != 0x31:
        raise ValueError("the signature carries no signer")
    signer_infos = children(blob, signed[-1][1], signed[-1][2])
    if len(signer_infos) != 1:
        raise ValueError("an Authenticode signature has one signer and this has %d" % len(signer_infos))
    sid = children(blob, signer_infos[0][1], signer_infos[0][2])[1]
    if sid[0] == 0x30:
        issuer, serial = children(blob, sid[1], sid[2])[:2]
        want = (blob[issuer[3]:issuer[2]], blob[serial[3]:serial[2]])
        found = [c for c in certificates if (c["issuer_der"], c["serial_der"]) == want]
    else:
        found = [c for c in certificates if c["ski"] == blob[sid[1]:sid[2]]]
    if len(found) != 1:
        raise ValueError("the certificate the signature names is not among the ones it carries")
    return found[0]


def signtool_chain(output):
    """The primary signature's certificate chain as signtool printed it, root first, each entry the
    name it was issued to and its SHA-1."""
    chain, entry, inside = [], {}, False
    for line in output.replace("\r", "").splitlines():
        text = line.strip()
        if text == "Signing Certificate Chain:":
            inside = True
            continue
        if not inside:
            continue
        if text and not line.startswith(" "):
            break
        if text.startswith("Issued to:"):
            entry = {"to": text.split(":", 1)[1].strip()}
            chain.append(entry)
        elif text.startswith("SHA1 hash:") and entry:
            entry["sha1"] = text.split(":", 1)[1].strip().upper()
    return chain


# Reading which job a Linux signature came from. cosign has verified the bundle's certificate, its
# chain to Fulcio and the signature before this reads anything, and it is asked nothing here that it
# could answer itself: only the token subject, which it has no option for. A bundle carries one
# certificate, and one carrying more, or a certificate carrying an extension twice, is refused
# rather than read one way of several.

def certificate_extensions(data):
    """Each extension of the DER certificate `data`, by OID, as the bytes its value holds. ValueError
    for anything this does not read, and for an extension that appears twice."""
    try:
        _, start, end = der(data, 0)
        if end != len(data):
            raise ValueError("bytes follow the certificate")
        tbs = children(data, start, end)[0]
        found = {}
        for tag, s, e, _ in children(data, tbs[1], tbs[2]):
            if tag != 0xA3:
                continue
            for _, s2, e2, _ in children(data, *children(data, s, e)[0][1:3]):
                parts = children(data, s2, e2)
                if parts[0][0] != 0x06 or parts[-1][0] != 0x04:
                    raise ValueError("an extension this does not read")
                oid = oid_text(data[parts[0][1]:parts[0][2]])
                if oid in found:
                    raise ValueError("the extension %s appears twice" % oid)
                found[oid] = data[parts[-1][1]:parts[-1][2]]
        return found
    except IndexError:
        raise ValueError("the certificate is cut short or malformed")


# What a Sigstore bundle holds at its top level, and nothing else. cosign reads a file that does not
# load as one of these as its older bundle, which keeps its certificate under `cert` and ignores any
# other key. So a file carrying both could show cosign one certificate and this another, and a bundle
# with anything else at its top level is refused. Each of these names is one the older reader never
# takes for its own, whatever their case.
BUNDLE_KEYS = {"mediaType", "verificationMaterial", "messageSignature", "dsseEnvelope"}
BUNDLE_TYPE = "application/vnd.dev.sigstore.bundle"


def bundle_certificate(text):
    """The DER certificate a Sigstore bundle's signature was made under."""
    try:
        bundle = json.loads(text)
        if not isinstance(bundle, dict) or not set(bundle) <= BUNDLE_KEYS:
            raise ValueError("it is not a Sigstore bundle and nothing else")
        if not str(bundle.get("mediaType", "")).startswith(BUNDLE_TYPE):
            raise ValueError("its media type is not a Sigstore bundle's")
        material = bundle["verificationMaterial"]
        kinds = [k for k in ("certificate", "x509CertificateChain", "publicKey") if k in material]
        if kinds == ["certificate"]:
            raw = material["certificate"]["rawBytes"]
        elif kinds == ["x509CertificateChain"]:
            raw = material["x509CertificateChain"]["certificates"][0]["rawBytes"]
        else:
            raise ValueError("it carries %s where one certificate belongs" % (" and ".join(kinds) or "nothing"))
        raw = raw.replace("-", "+").replace("_", "/")
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
        raise ValueError("its certificate could not be read (%s)" % e)


def token_subject(certificate):
    """The subject of the token Fulcio issued `certificate` for, or None where it names none."""
    value = certificate_extensions(certificate).get(OID_TOKEN_SUBJECT)
    if value is None:
        return None
    tag, start, end = der(value, 0)
    if tag != 0x0C or end != len(value):
        raise ValueError("the token subject is not one string")
    return value[start:end].decode("utf-8")


# The judgements, each a pure function of what was read, so the self-test can put them to shapes.
# The signature judges return why a binary is not ours, and nothing when it is.

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


def judge_codesign(code, output, pins):
    """`codesign -dv --verbose=4` names our team, as the team and in the certificate's own name, and
    the chain above it is Apple's."""
    team = pin(pins, "apple", "team_id")
    if not team:
        return [not_pinned("the Apple Team ID")]
    if code != 0:
        return ["codesign could not read a signature on it"]
    lines = [line.strip() for line in output.replace("\r", "").splitlines()]
    authorities = [line[len("Authority="):] for line in lines if line.startswith("Authority=")]
    teams = [line[len("TeamIdentifier="):] for line in lines if line.startswith("TeamIdentifier=")]
    problems = []
    if teams != [team]:
        problems.append("its team is %s, and ours is %s" % (", ".join(teams) or "not stated", team))
    if not authorities or not re.fullmatch(r"Developer ID Application: .+ \(%s\)" % re.escape(team), authorities[0]):
        problems.append("it is signed by [%s], not by a Developer ID Application certificate of team %s"
                        % (authorities[0] if authorities else "no authority", team))
    elif authorities[1:] != APPLE_CHAIN:
        problems.append("its certificate chains through [%s], not %s" % (", ".join(authorities[1:]), " then ".join(APPLE_CHAIN)))
    return problems


def judge_signtool(code, output, signer, pins):
    """signtool verifies the primary signature, and the certificate that made it is our publisher's,
    from our issuer, under our root."""
    unset = [what for (system, key), (_, what) in PIN_SHAPES.items()
             if system == "windows" and not pin(pins, "windows", key)]
    if unset:
        return [not_pinned(what) for what in unset]
    w = pins["windows"]
    if code != 0 or "Successfully verified" not in output:
        return ["signtool verify /pa does not verify it"]
    if signer is None:
        return ["no signature could be read out of the file"]
    problems = []
    chain = signtool_chain(output)
    if not chain or chain[-1].get("sha1") != signer["sha1"]:
        problems.append("the certificate signtool verified is not the one inside the file")
    elif chain[0]["to"] != w["root"]:
        problems.append("its chain ends at [%s], not at %s" % (chain[0]["to"], w["root"]))
    if signer["subject_cn"] != [w["subject_common_name"]] or signer["subject_o"] != [w["subject_organisation"]]:
        problems.append("it is signed by [%s / %s], and our publisher is [%s / %s]"
                        % (", ".join(signer["subject_cn"]), ", ".join(signer["subject_o"]),
                           w["subject_common_name"], w["subject_organisation"]))
    if w["identity_usage"] not in signer["usages"]:
        problems.append("its certificate does not carry our identity usage %s" % w["identity_usage"])
    if (signer["issuer_o"] != [w["issuer_organisation"]]
            or len(signer["issuer_cn"]) != 1 or not signer["issuer_cn"][0].startswith(w["issuer_common_name_starts"])):
        problems.append("its certificate was issued by [%s / %s], not by our signing service"
                        % (", ".join(signer["issuer_cn"]), ", ".join(signer["issuer_o"])))
    return problems


def judge_cosign(code, output):
    return code == 0 and "Verified OK" in output


def judge_signing_job(subject):
    """Signed in the one job that enters `linux-signing`, and in no other job of the run."""
    return subject == LINUX_SUBJECT


def may_run(digest, signature):
    """A binary is run only once its digest line and its own signature have both been checked here
    and both passed. A clause missing is a clause not passed."""
    clauses = digest + signature
    return bool(digest) and bool(signature) and all(state == "PASS" for state in clauses)


# All a binary needs to start and print its version. The check runs in CI with a token that reads
# this repository, and the binary is run before anybody has trusted it, so nothing else is put in
# its environment. This keeps the token out of the binary's own environment and no further.
RUN_ENVIRONMENT = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "LANG"}


def run_environment(environ):
    return dict([(key, value) for key, value in environ.items() if key.upper() in RUN_ENVIRONMENT])


def verdict(results):
    states = [state for state, _ in results]
    if "FAIL" in states:
        return 1
    if "NOT RUN" in states or not states:
        return 2
    return 0


def summary(code, results):
    """The last line, which names the targets whose signatures this machine did not check."""
    elsewhere = [line.split(":", 1)[0] for state, line in results
                 if state == "ELSEWHERE" and "its signature is checked on" in line]
    if code == 0 and elsewhere:
        return ("PASS: every clause run on this machine passed, and the signatures of %s were not checked "
                "here, so this is a pass for this machine's targets only" % ", ".join(elsewhere))
    return {0: "PASS: every clause passed on this machine",
            1: "FAIL: at least one clause failed",
            2: "NOT RUN: nothing failed, and at least one clause could not be checked here"}[code]


# Reading the world.

def run(argv, env=None):
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=600, env=env)
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


# The most a binary in a release archive may be, read before it is, so an archive that unpacks to far
# more than it holds is refused rather than read into memory. The binaries are a few megabytes.
ARCHIVE_LIMIT = 256 * 1024 * 1024


def plain_name(entry):
    """An archive entry's name as a file system would take it, `./` taken off and case folded, or
    None for one that is anything but a plain name in the archive's top folder."""
    name = entry[2:] if entry.startswith("./") else entry
    if not name or name in (".", "..") or "/" in name or "\\" in name or ":" in name:
        return None
    return name.lower()


def unpack(archive, into, limit=ARCHIVE_LIMIT):
    """The binary out of a release archive, written into `into` under its own name. An archive is
    opened before any signature in it has been read, and a stranger's `tar` or unzip takes out
    everything in it, so the archive has to hold the binary, LICENSE and NOTICE and nothing else: each
    a plain file at the top, once, after `./` and case are taken off, since a case-blind file system
    keeps whichever of two spellings comes last. Only the binary is taken out here, so no name or link
    in the archive can reach outside `into`, whatever this Python's defaults."""
    os.makedirs(into, exist_ok=True)
    name = "timewitness.exe" if archive.endswith(".zip") else "timewitness"
    where = os.path.basename(archive)
    if archive.endswith(".zip"):
        opened = zipfile.ZipFile(archive)
        entries = [(i.filename, not i.is_dir() and (i.external_attr >> 16) & 0o170000 in (0, 0o100000), i.file_size, i)
                   for i in opened.infolist()]
        read = opened.read
    else:
        opened = tarfile.open(archive)
        entries = [(m.name, m.isreg(), m.size, m) for m in opened.getmembers()]
        read = lambda member: opened.extractfile(member).read()
    try:
        # A name with a folder or a drive in it is written somewhere other than beside the binary by
        # somebody's unzip, so it is refused as that before the names are counted.
        odd = [entry for entry, _, _, _ in entries if plain_name(entry) is None]
        if odd:
            raise CouldNotRun("%s holds %s, which is not a plain name at the top of the archive" % (where, ", ".join(odd)))
        names = sorted(str(plain_name(entry)) for entry, _, _, _ in entries)
        if names != sorted([name, "license", "notice"]):
            raise CouldNotRun("%s holds [%s], and a release archive holds %s, LICENSE and NOTICE and nothing else"
                              % (where, ", ".join(entry for entry, _, _, _ in entries), name))
        for entry, regular, size, _ in entries:
            if not regular:
                raise CouldNotRun("%s holds %s as a link or something else that is not a plain file" % (where, entry))
            if size > limit:
                raise CouldNotRun("%s holds %s at %d bytes, more than a release binary is" % (where, entry, size))
        if archive.endswith(".zip"):
            # A zip names each file twice, in its directory and again in front of the file, and an
            # unzip that reads it front to back writes the second name. Opening a member holds the two
            # to each other, so every member is opened, not only the binary.
            for _, _, _, member in entries:
                with opened.open(member) as each:
                    each.read(0)
        data = read([member for entry, _, _, member in entries if plain_name(entry) == name][0])
    finally:
        opened.close()
    path = os.path.join(into, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


# Where the tools this runs are taken from. Somebody checking a download often does it from the
# folder the download was saved to, and a `signtool.exe` or `cosign.exe` shipped beside it would be run
# as ours and could print a pass for a binary nobody signed. On Windows a bare name, and Python's own
# lookup, try the working folder before anything on the path. So signtool comes from the Windows Kits
# folder or from a full path given, the macOS tools from where macOS keeps them, and cosign from an
# absolute folder on the path that is not the one this is run in, nor the one the assets are read
# from.
SIGNTOOL_KITS = os.path.join(os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)",
                             "Windows Kits", "10", "bin", "*", "x64", "signtool.exe")
CODESIGN, SPCTL = "/usr/bin/codesign", "/usr/sbin/spctl"


def signtool(given=None, kits_at=SIGNTOOL_KITS):
    """The signtool given, or the newest in the Windows Kits folder, by its version read as numbers,
    since 10.0.9999.0 sorts after 10.0.22621.0 as text."""
    if given:
        return given
    def version(path):
        folder = os.path.basename(os.path.dirname(os.path.dirname(path)))
        return [int(part) if part.isdigit() else -1 for part in folder.split(".")]
    kits = sorted(glob.glob(kits_at), key=version)
    return kits[-1] if kits else None


def signtool_given(value):
    """Why `--signtool VALUE` is refused, or None. Only a full path is taken, since a bare or relative
    name is looked for in the working folder first."""
    if not (os.path.isabs(value) and os.path.isfile(value)):
        return "--signtool takes the full path of signtool, and %s is not one" % value
    return None


def same_folder(one, other):
    """Whether two names are one folder on disk, whatever each is spelt as: by its file system's own
    identity for it, not by comparing the text, which a device path, a share, a short name or a link
    all spell differently."""
    try:
        return os.path.samefile(one, other)
    except (OSError, ValueError):
        return False


def tool_on_path(name, avoid, path=None, exe_only=os.name == "nt"):
    """`name` from an absolute folder on the path that is none of the folders in `avoid`, or None.
    A relative entry, `.` and an empty one among them, is a folder under wherever this is run, so it
    is never searched, and nor is one led by two separators, which on Windows names a share or a
    device path rather than a folder on this disk. Each folder is known by what it is on disk rather
    than by how it is spelt. On Windows only an `.exe` is taken, so no batch file stands in for one."""
    path = os.environ.get("PATH", "") if path is None else path
    file_name = name + ".exe" if exe_only else name
    for entry in path.split(os.pathsep):
        if not os.path.isabs(entry):
            continue
        if len(entry) > 1 and entry[0] in "\\/" and entry[1] in "\\/":
            continue
        if any(same_folder(entry, folder) for folder in avoid):
            continue
        candidate = os.path.join(entry, file_name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def unpinned(problems):
    return any(p.startswith("NOT PINNED") for p in problems)


def check_macos_binary(label, binary, pins, say, run=run):
    code, out = run([CODESIGN, "--verify", "--strict", "--verbose=2", binary])
    code2, out2 = run([CODESIGN, "-dv", "--verbose=4", binary])
    problems = judge_codesign(code2, out2, pins) if code == 0 else ["codesign --verify refuses it: %s" % out.strip().splitlines()[:2]]
    if unpinned(problems):
        say("FAIL", "%s: refused, because the team it is held to is not set (said above)" % label)
    elif problems:
        say("FAIL", "%s: not signed by our Developer ID: %s" % (label, "; ".join(problems)))
    else:
        say("PASS", "%s: codesign verifies it, signed by our Developer ID, team %s" % (label, pin(pins, "apple", "team_id")))
    code, out = run([SPCTL, "--assess", "--type", "open", "--context", "context:primary-signature", "-vv", binary])
    if judge_spctl(code, out):
        say("PASS", "%s: spctl accepts it as notarised" % label)
    else:
        say("FAIL", "%s: spctl refuses it: %s" % (label, " ".join(out.split())[:200]))


def check_windows_binary(label, binary, pins, say, signtool_at=None):
    tool = signtool(signtool_at)
    if not tool:
        say("NOT RUN", "%s: signtool is not in the Windows Kits folder here and no --signtool was given, so the "
                       "Windows signature was not checked here" % label)
        return
    code, out = run([tool, "verify", "/pa", "/v", binary])
    try:
        with open(binary, "rb") as f:
            signer = read_signer(f.read())
    except (OSError, ValueError) as e:
        say("FAIL", "%s: the signature inside it could not be read: %s" % (label, e))
        return
    problems = judge_signtool(code, out, signer, pins)
    if unpinned(problems):
        say("FAIL", "%s: refused, because the publisher it is held to is not set (said above)" % label)
    elif problems:
        tail = " ".join(out.split())[-200:] if "signtool verify" in problems[0] else ""
        say("FAIL", "%s: not signed by our publisher: %s%s" % (label, "; ".join(problems), (" (" + tail + ")") if tail else ""))
    else:
        say("PASS", "%s: signtool verify /pa passes, signed by %s" % (label, pin(pins, "windows", "subject_common_name")))


def check_signing_job(name, bundle, say):
    """Whether the Linux signing job made the signature cosign has just verified, said as a line
    about `name`."""
    try:
        with open(bundle, encoding="utf-8") as f:
            subject = token_subject(bundle_certificate(f.read()))
    except (OSError, ValueError) as e:
        say("FAIL", "%s has a bundle whose signing job could not be read: %s" % (name, e))
        return "FAIL"
    if judge_signing_job(subject):
        say("PASS", "%s was signed in the job that signs the Linux archives, and in no other job" % name)
        return "PASS"
    say("FAIL", "%s was signed with a token for [%s], which is not the Linux signing job's" % (name, subject or "no subject"))
    return "FAIL"


def pinned_or_say(say):
    pins, problems = load_pins()
    for problem in problems:
        say("FAIL", problem)
    return pins


def check(tag, work, repo=REPO, folder=None, run_binary=True, cosign=None, rehearsal_key=None, signtool_at=None):
    """Every clause for the release `tag`, reading its assets from GitHub, or from `folder` where one
    is given. `cosign` is the command that runs cosign, or a function that answers for it, found on
    the path where it is not given,
    `rehearsal_key` the public half of a rehearsal's throwaway key, and `signtool_at` signtool's full
    path where it is not in the Windows Kits folder."""
    results = []

    def say(state, line):
        results.append((state, line))
        print("%s: %s" % (state, line), flush=True)

    # What each target's own clauses said, so a binary is run only once they have all passed.
    digest_of = {target: [] for target in TARGETS}
    signature_of = {target: [] for target in TARGETS}

    def for_target(target):
        def said(state, line):
            say(state, line)
            signature_of[target].append(state)
        return said

    pins = pinned_or_say(say)

    if folder is None:
        raw = fetch("https://api.github.com/repos/%s/releases/tags/%s" % (repo, tag), "application/vnd.github+json")
        if raw is None:
            say("FAIL", "%s has no release called %s" % (repo, tag))
            return results
        release = json.loads(raw)
        assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
        print("%s %s: %d assets, %s" % (repo, tag, len(assets), "pre-release" if release.get("prerelease") else "release"))
    else:
        assets = {n: os.path.join(folder, n) for n in sorted(os.listdir(folder)) if os.path.isfile(os.path.join(folder, n))}
        print("%s: %d files, read as the assets of %s" % (folder, len(assets), tag))

    missing = judge_assets(tag, assets)
    if missing:
        say("FAIL", "missing from the release: " + ", ".join(missing))
    else:
        say("PASS", "all five archives, their digest list and the three Sigstore bundles are attached")

    files = {}
    for name in required_assets(tag):
        if name not in assets:
            continue
        if folder is not None:
            files[name] = assets[name]
            continue
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
    targets_of = {archive_name(tag, t): t for t in TARGETS}
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
        for name, digest in digests.items():
            digest_of[targets_of[name]].append("FAIL" if judge_sums(sums_text, {name: digest}) else "PASS")
    else:
        for name in archives:
            digest_of[targets_of[name]].append("FAIL")

    # The Linux signatures, which any machine with cosign can check. An archive with no bundle
    # beside it has no signature to check, and that is a failure of its own.
    if cosign is None:
        found = tool_on_path("cosign", [os.getcwd()] + ([folder] if folder else []))
        cosign = [found] if found else None
    signed_blobs = [n for n in files if n + BUNDLE in files]
    for target, (os_name, _) in TARGETS.items():
        name = archive_name(tag, target)
        if os_name == "linux" and name in files and name not in signed_blobs:
            signature_of[target].append("FAIL")
    if not cosign:
        say("NOT RUN", "cosign is not on this machine, so the Linux signatures were not checked here")
        for name in signed_blobs:
            if name in targets_of:
                signature_of[targets_of[name]].append("NOT RUN")
    else:
        # A rehearsal's bundle carries no log entry and no certificate, only the key's hint, so it is
        # held to the key and told there is no log to find it in.
        if rehearsal_key:
            against, signer = ["--key", rehearsal_key, "--insecure-ignore-tlog"], "the rehearsal's throwaway key"
        else:
            against = ["--certificate-identity-regexp", SIGNER, "--certificate-oidc-issuer", ISSUER]
            signer = "this repository's release workflow"
        for name in sorted(signed_blobs):
            asked = ["verify-blob", files[name], "--bundle", files[name + BUNDLE]] + against
            code, out = cosign(asked) if callable(cosign) else run(cosign + asked)
            state = "PASS" if judge_cosign(code, out) else "FAIL"
            if state == "PASS":
                say(state, "%s is signed by %s (cosign)" % (name, signer))
            else:
                say(state, "%s did not verify against its bundle: %s" % (name, out.strip().splitlines()[-1:] or out))
            if state == "PASS" and not rehearsal_key:
                state = check_signing_job(name, files[name + BUNDLE], say)
            if name in targets_of:
                signature_of[targets_of[name]].append(state)
    if rehearsal_key:
        say("FAIL", "REHEARSAL KEY: the Linux signatures were held to a throwaway key and not to this "
                    "repository's release workflow, so this check does not pass a release")

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
            if binary is not None:
                check_macos_binary(target, binary, pins, for_target(target))
        elif os_name == "windows" and system == "windows":
            binary = opened(name, os.path.join(work, target))
            if binary is not None:
                check_windows_binary(target, binary, pins, for_target(target), signtool_at)
        elif os_name != "linux":
            # Not a clause here: the leg on that system checks it. Said, so nobody reads it as checked.
            say("ELSEWHERE", "%s: its signature is checked on %s, and this is not" % (target, os_name))

    if here is None:
        say("NOT RUN", "this machine is none of the five targets, so no --version was read")
    elif archive_name(tag, here) in files and not run_binary:
        say("ELSEWHERE", "%s: --version is not run here, because this job holds a token worth having; the "
                         "build that made it asked it already" % here)
    elif archive_name(tag, here) in files:
        if not may_run(digest_of[here], signature_of[here]):
            say("NOT RUN", "%s: --version was not run, because a clause about this binary did not pass here, "
                           "and a binary this check has not passed is never run" % here)
            return results
        binary = opened(archive_name(tag, here), os.path.join(work, here + "-run"))
        if binary is None:
            return results
        if system != "windows":
            os.chmod(binary, 0o755)
        code, out = run([binary, "--version"], env=run_environment(os.environ))
        first = out.splitlines()[0] if out.splitlines() else ""
        if code == 0 and judge_version(tag, first):
            say("PASS", "%s: --version says [%s]" % (here, first))
        else:
            say("FAIL", "%s: --version says [%s], not [timewitness %s]" % (here, first, tag))
    return results


def check_one(binary, signtool_at=None):
    """The signature clauses for one binary already on this machine."""
    results = []

    def say(state, line):
        results.append((state, line))
        print("%s: %s" % (state, line), flush=True)

    pins = pinned_or_say(say)
    system = platform.system()
    label = os.path.basename(binary)
    if system == "Darwin":
        check_macos_binary(label, binary, pins, say)
    elif system == "Windows":
        check_windows_binary(label, binary, pins, say, signtool_at)
    else:
        say("NOT RUN", "a signature is checked here only on macOS or Windows, and this is %s" % system)
    return results


# The self-test's own shapes.

TEST_PINS = {
    "apple": {"team_id": "TESTTEAM01"},
    "windows": {
        "subject_common_name": "Ours Test Publisher",
        "subject_organisation": "Ours Test Publisher",
        "identity_usage": "1.3.6.1.4.1.311.97.990001.1",
        "issuer_organisation": "Synthetic Issuer",
        "issuer_common_name_starts": "Synthetic ID Verified CS ",
        "root": "Synthetic Identity Verification Root 2026",
    },
}


def codesign_text(authorities, team):
    """`codesign -dv --verbose=4` as it prints a Developer ID signed command line tool."""
    lines = ["Executable=/tmp/timewitness", "Identifier=timewitness", "Format=Mach-O thin (arm64)",
             "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=28+7 location=embedded",
             "Hash type=sha256 size=32", "CDHash=0f3c", "Signature size=9051"]
    lines += ["Authority=" + a for a in authorities]
    lines += ["Timestamp=27 Sep 2026 at 10:00:00", "Info.plist=not bound", "TeamIdentifier=" + team,
              "Runtime Version=15.0.0", "Sealed Resources=none", "Internal requirements count=1 size=180"]
    return "\n".join(lines) + "\n"


def signtool_text(chain, verified=True):
    """`signtool verify /pa /v` in the layout of `signing-fixtures/ours.signtool.txt`, which is what it
    printed for a real signed file, with the chain given root first as (name, SHA-1)."""
    lines = ["", "Verifying: timewitness.exe", "", "Signature Index: 0 (Primary Signature)",
             "Hash of file (sha256): " + "AB" * 32, "", "Signing Certificate Chain:"]
    for depth, (name, sha1) in enumerate(chain):
        pad = "    " * (depth + 1)
        issuer = chain[depth - 1][0] if depth else name
        lines += [pad + "Issued to: " + name, pad + "Issued by: " + issuer,
                  pad + "Expires:   Sat Sep 22 08:58:56 2046", pad + "SHA1 hash: " + sha1, ""]
    if verified:
        lines += ["The signature is timestamped: Sun Sep 27 10:00:00 2026", "",
                  "Successfully verified: timewitness.exe", "", "Number of files successfully Verified: 1"]
    else:
        lines += ["Number of files successfully Verified: 0", "SignTool Error: No signature found."]
    return "\n".join(lines) + "\n"


def fixture(name):
    with open(os.path.join(FIXTURES, name + ".exe.b64"), encoding="ascii") as f:
        return base64.b64decode(f.read())


def der_of(tag, body):
    size = len(body)
    if size < 0x80:
        return bytes([tag, size]) + body
    length = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def oid_der(text):
    parts = [int(p) for p in text.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out += bytes(reversed(chunk))
    return der_of(0x06, bytes(out))


def fulcio_shaped(subjects, critical=True):
    """A certificate laid out as Fulcio lays one out, where this check reads it: a critical extension
    first, then one token subject extension for each of `subjects`. Nothing signs it, since cosign's
    stand-in says whether it verifies."""
    def extension(oid, value, is_critical=False):
        return der_of(0x30, oid_der(oid) + (b"\x01\x01\xff" if is_critical else b"") + der_of(0x04, value))
    extensions = [extension("2.5.29.15", der_of(0x03, b"\x07\x80"), critical)]
    extensions += [extension(OID_TOKEN_SUBJECT, der_of(0x0C, s.encode("utf-8"))) for s in subjects]
    algorithm = der_of(0x30, oid_der("1.2.840.10045.4.3.3"))
    name = der_of(0x30, der_of(0x31, der_of(0x30, oid_der(OID_O) + der_of(0x0C, b"sigstore.dev"))))
    tbs = der_of(0x30, der_of(0xA0, der_of(0x02, b"\x02")) + der_of(0x02, b"\x01") + algorithm + name
                 + der_of(0x30, der_of(0x17, b"260930000000Z") * 2) + der_of(0x30, b"")
                 + der_of(0x30, algorithm + der_of(0x03, b"\x00")) + der_of(0xA3, der_of(0x30, b"".join(extensions))))
    return der_of(0x30, tbs + algorithm + der_of(0x03, b"\x00"))


def bundle_of(certificate, kind="certificate"):
    """A Sigstore bundle as cosign writes one, holding `certificate`."""
    raw = base64.b64encode(certificate).decode("ascii")
    material = {"certificate": {"certificate": {"rawBytes": raw}},
                "x509CertificateChain": {"x509CertificateChain": {"certificates": [{"rawBytes": raw}]}},
                "key": {"publicKey": {"hint": "a key"}}}[kind]
    return json.dumps({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": material})


def fulcio_elsewhere():
    """A real certificate from Fulcio, for another repository's release job in an environment of its
    own: pytest's publishing job, taken from the provenance PyPI serves for pytest 9.1.1."""
    with open(os.path.join(FIXTURES, "fulcio-another-repository.pem"), encoding="ascii") as f:
        return base64.b64decode("".join(line for line in f.read().splitlines() if not line.startswith("-----")))


# The token subject each job of a release run from main is given: the Linux signing job's, and the
# ones `sign-windows` and a job in no environment would be given.
OUR_PREFIX = LINUX_SUBJECT.split(":environment:")[0]
OUR_SUFFIX = ":ref:refs/heads/main:job_workflow_ref:Fountech-ai-Limited/timewitness/.github/workflows/release.yml@refs/heads/main"
WINDOWS_SUBJECT = OUR_PREFIX + ":environment:release" + OUR_SUFFIX
NO_ENVIRONMENT_SUBJECT = OUR_PREFIX + ":ref:refs/heads/main" + OUR_SUFFIX


def pack(archive, binary, body, extra=None):
    """A release archive at `archive` holding `binary` with `body`, LICENSE and NOTICE, as the release
    workflow packs one, or the entries `extra` gives instead: each a name and a body, or a name and
    ("link", target) for a link."""
    entries = extra if extra is not None else [(binary, body), ("LICENSE", b"licence\n"), ("NOTICE", b"notice\n")]
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive, "w") as z:
            for name, data in entries:
                if isinstance(data, tuple):
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (0o120777 << 16)
                    z.writestr(info, data[1])
                else:
                    z.writestr(name, data)
    else:
        with tarfile.open(archive, "w:gz") as t:
            for name, data in entries:
                info = tarfile.TarInfo(name)
                if isinstance(data, tuple):
                    info.type, info.linkname = tarfile.SYMTYPE, data[1]
                    t.addfile(info)
                else:
                    info.size, info.mode = len(data), 0o755
                    t.addfile(info, io.BytesIO(data))


def refuses_to_run_what_it_refused(wrong_digest):
    """A check over a folder holding a binary for this machine that is not signed, listed with the
    wrong digest or the right one. Whatever else it says, it must not run that binary."""
    here = host_target()
    if here is None:
        return True
    tag = "v0.4"
    work = tempfile.mkdtemp(prefix="tw-refused-self-test-")
    try:
        dist = os.path.join(work, "dist")
        os.makedirs(dist)
        exe = "timewitness.exe" if TARGETS[here][0] == "windows" else "timewitness"
        archive = os.path.join(dist, archive_name(tag, here))
        pack(archive, exe, fixture("unsigned") if exe.endswith(".exe") else b"#!/bin/sh\necho timewitness v0.4\n")
        with open(archive, "rb") as f:
            digest = "0" * 64 if wrong_digest else hashlib.sha256(f.read()).hexdigest()
        with open(os.path.join(dist, SUMS), "w", encoding="utf-8") as f:
            f.write("%s  %s\n" % (digest, os.path.basename(archive)))
        with open(os.devnull, "w") as quiet:
            saved, sys.stdout = sys.stdout, quiet
            try:
                results = check(tag, work, folder=dist)
            finally:
                sys.stdout = saved
        ran = [line for _, line in results if "--version says" in line]
        held = [line for state, line in results if state == "NOT RUN" and "--version was not run" in line]
        return not ran and len(held) == 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


# cosign's stand-in holds a signature to the identity and issuer it is handed as real cosign does:
# the identity as a regular expression found anywhere in the certificate's identity, since cosign's
# is unanchored, and the issuer exactly. It is told what the certificate says, as Fulcio would have
# written it, by the shape, and never reads it from the check, so a check that asked for too little
# is refused or accepted here as cosign would. It answers only the two questions the check asks,
# keyless and with a rehearsal's key, word for word, so a flag that loosens either, such as one
# that skips the transparency log, is refused rather than ignored. It cannot say which certificate
# in a file it would have verified, so the shapes below that hold the check to reading the one
# cosign reads are shapes of the file itself, refused before any certificate in it is believed.
def stand_in_cosign(said, identity, issuer):
    """cosign verify-blob, as the shape tells it the certificate reads, answering in this process
    rather than as one started for each signature, which on Windows costs most of a second."""
    def cosign(args):
        keyless = (len(args) == 8 and args[0] == "verify-blob" and args[2] == "--bundle"
                   and args[4] == "--certificate-identity-regexp" and args[6] == "--certificate-oidc-issuer")
        rehearsal = len(args) == 7 and args[0] == "verify-blob" and args[2] == "--bundle" and args[4:] == [
            "--key", args[5], "--insecure-ignore-tlog"]
        if not (keyless or rehearsal):
            return 1, "Error: the stand-in answers the check's two questions and nothing else: %s" % " ".join(args[4:])
        if keyless and (args[7] != issuer or not re.search(args[5], identity)):
            return 1, "Error: none of the expected identities matched what was in the certificate"
        if said == "refuses":
            return 1, "Error: the signature does not verify"
        return 0, "Verified OK"
    return cosign


# What Fulcio writes into the certificate of a run of the release workflow from main, as the stand-in
# is told it. Written out here rather than taken from SIGNER and ISSUER, which are what is under test.
OUR_WORKFLOW = "https://github.com/Fountech-ai-Limited/timewitness/.github/workflows/release.yml@refs/heads/main"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


def write_release(dist, tag, targets, bundle, drop=()):
    """The assets of `tag` for `targets` in `dist`, each archive holding a stand-in binary, with the
    digest list and a bundle beside each Linux archive and the list, less any named in `drop`."""
    for target in targets:
        archive = os.path.join(dist, archive_name(tag, target))
        pack(archive, "timewitness.exe" if archive.endswith(".zip") else "timewitness",
             b"#!/bin/sh\necho timewitness %s\n" % tag.encode())
        if TARGETS[target][0] == "linux":
            with open(archive + BUNDLE, "w", encoding="utf-8") as f:
                f.write(bundle)
    lines = []
    for target in targets:
        with open(os.path.join(dist, archive_name(tag, target)), "rb") as f:
            lines.append("%s  %s\n" % (hashlib.sha256(f.read()).hexdigest(), archive_name(tag, target)))
    with open(os.path.join(dist, SUMS), "w", encoding="utf-8") as f:
        f.write("".join(lines))
    with open(os.path.join(dist, SUMS + BUNDLE), "w", encoding="utf-8") as f:
        f.write(bundle)
    for name in drop:
        os.remove(os.path.join(dist, name))


def linux_bundle_check(cosign_says, rehearsal_key=None, bundle=None, identity=OUR_WORKFLOW, issuer=GITHUB_ISSUER,
                       targets=("x86_64-unknown-linux-gnu",), drop=(), find_cosign=False, plant=None):
    """check() over a folder holding a Linux archive and its bundle, or the assets of `targets`, with
    cosign replaced by a stand-in that verifies or refuses as told and holds the check's identity
    and issuer to the certificate's `identity` and `issuer`. The bundle holds a certificate for the
    Linux signing job unless another is given. With `find_cosign` the check looks for cosign itself,
    and with `plant` a function is handed the folder the assets are in first."""
    if bundle is None:
        bundle = bundle_of(fulcio_shaped([LINUX_SUBJECT]))
    tag = "v0.4"
    work = tempfile.mkdtemp(prefix="tw-cosign-self-test-")
    try:
        dist = os.path.join(work, "dist")
        os.makedirs(dist)
        write_release(dist, tag, targets, bundle, drop)
        if plant:
            plant(dist)
        cosign = None if find_cosign else stand_in_cosign(cosign_says, identity, issuer)
        with open(os.devnull, "w") as quiet:
            saved, sys.stdout = sys.stdout, quiet
            try:
                return check(tag, work, folder=dist, run_binary=False, cosign=cosign, rehearsal_key=rehearsal_key)
            finally:
                sys.stdout = saved
    finally:
        shutil.rmtree(work, ignore_errors=True)


def planted_tools_taken():
    """What the check takes for signtool and cosign when each is left in the folder it is run in, and
    that folder is on the path by its full name, as `.`, as an empty entry and by a relative name;
    and whether a cosign left in the folder the assets are read from, on the path by its full name,
    is run by a whole check. Each planted tool that runs leaves a mark, and one that cannot run
    counts as run. Returns the signtool taken, the cosign taken, whether a planted one ran, and the
    folder they were planted in."""
    here, path = os.getcwd(), os.environ.get("PATH", "")
    work = tempfile.mkdtemp(prefix="tw-planted-self-test-")
    mark = os.path.join(work, "ran")

    def plant_in(folder):
        for name in ("signtool", "cosign"):
            if os.name == "nt":
                with open(os.path.join(folder, name + ".exe"), "wb") as f:
                    f.write(b"MZ planted")
                with open(os.path.join(folder, name + ".cmd"), "w", encoding="ascii") as f:
                    f.write('@echo Verified OK\r\n@echo Successfully verified\r\n@echo ran> "%s"\r\n' % mark)
            else:
                stand_in = os.path.join(folder, name)
                with open(stand_in, "w", encoding="ascii") as f:
                    f.write("#!/bin/sh\necho Verified OK\necho Successfully verified\necho ran > '%s'\n" % mark)
                os.chmod(stand_in, 0o755)

    def whole_check(**given):
        try:
            linux_bundle_check("verifies", find_cosign=True, **given)
        except CouldNotRun:
            with open(mark, "w") as f:
                f.write("a planted tool was started and could not run")

    try:
        plant = os.path.join(work, "downloads")
        for folder in (plant, os.path.join(plant, "tools")):
            os.makedirs(folder)
            plant_in(folder)
        os.chdir(plant)
        os.environ["PATH"] = os.pathsep.join([plant, ".", "", "tools", path])
        took_signtool = signtool()
        took_cosign = tool_on_path("cosign", [os.getcwd()])
        whole_check()
        os.chdir(here)

        def on_the_path(dist):
            plant_in(dist)
            os.environ["PATH"] = os.pathsep.join([dist, path])

        whole_check(plant=on_the_path)
        return took_signtool, took_cosign, os.path.exists(mark), plant
    finally:
        os.chdir(here)
        os.environ["PATH"] = path
        shutil.rmtree(work, ignore_errors=True)


def batch_file_taken():
    """Whether cosign is taken as a batch file where only an .exe may be, from an absolute folder on
    the path that is not the working folder."""
    work = tempfile.mkdtemp(prefix="tw-batch-self-test-")
    try:
        with open(os.path.join(work, "cosign.cmd"), "w", encoding="ascii") as f:
            f.write("@echo Verified OK\r\n")
        os.chmod(os.path.join(work, "cosign.cmd"), 0o755)
        return tool_on_path("cosign", [os.getcwd()], path=work, exe_only=True) is not None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def link_to(target, link):
    """A link at `link` to the folder `target`: a junction on Windows, which needs no privilege, and a
    symbolic link elsewhere. Whether it could be made."""
    if os.name == "nt":
        subprocess.run(["cmd", "/c", "mklink", "/J", link, target], capture_output=True)
    else:
        try:
            os.symlink(target, link)
        except OSError:
            pass
    return os.path.isdir(link)


def spellings_of(folder):
    """Other names for `folder` a PATH could give, each a name Windows or the system here opens as
    that folder: a link to it, and on Windows its device path, its short name, its administrative
    share and its volume's device name."""
    names = {}
    link = folder.rstrip("\\/") + "-link"
    if link_to(folder, link):
        names["a link to it"] = link
    if os.name == "nt":
        import ctypes
        drive, rest = os.path.splitdrive(folder)
        names["its device path"] = "\\\\?\\" + folder
        names["its device path, in lower case"] = "\\\\?\\" + folder.lower()
        names["its name in upper case"] = folder.upper()
        buf = ctypes.create_unicode_buffer(1024)
        if ctypes.windll.kernel32.GetShortPathNameW(folder, buf, 1024):
            names["its short name"] = buf.value
        names["its administrative share by name"] = "\\\\localhost\\" + drive[0] + "$" + rest
        names["its administrative share by address"] = "\\\\127.0.0.1\\" + drive[0].lower() + "$" + rest
        names["its administrative share as a device path"] = "\\\\?\\UNC\\localhost\\" + drive[0] + "$" + rest
        if ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 1024):
            names["its volume's device name"] = "\\\\?\\GLOBALROOT" + buf.value + rest
    else:
        names["led by a second separator"] = "/" + folder
    return names


def cosign_taken_by_spelling():
    """Which spellings of the working folder, and of the folder the assets are read from, hand the
    check a cosign left in them; and which a folder that is neither does, led by two separators and
    plainly. Returns the spellings taken, what the plain folder gave, and what the led one gave."""
    here = os.getcwd()
    work = tempfile.mkdtemp(prefix="tw-spelling-self-test-")
    tool = "cosign.exe" if os.name == "nt" else "cosign"
    try:
        plant = os.path.join(work, "Download Folder")
        dist = os.path.join(plant, "dist")
        other = os.path.join(work, "tools")
        for folder in (plant, dist, other):
            os.makedirs(folder)
            with open(os.path.join(folder, tool), "wb") as f:
                f.write(b"MZ planted")
            os.chmod(os.path.join(folder, tool), 0o755)
        os.chdir(plant)
        taken = []
        for folder, what in ((plant, "the working folder"), (dist, "the assets' folder")):
            for label, entry in spellings_of(folder).items():
                if tool_on_path("cosign", [os.getcwd(), "dist"], path=entry):
                    taken.append("%s as %s" % (what, label))
        # The check run from inside a link to the folder, and the folder on the path by its own name.
        inside = work + "-inside"
        if link_to(plant, inside):
            os.chdir(inside)
            if tool_on_path("cosign", [os.getcwd()], path=plant):
                taken.append("the working folder by its own name, the check run from a link to it")
            os.chdir(plant)
        plainly = tool_on_path("cosign", [os.getcwd()], path=other)
        # Led by two separators, either way round: a device path or a share is not a folder here.
        leds = ["\\\\?\\" + other, "//?/" + other.replace("\\", "/")] if os.name == "nt" else ["/" + other]
        return taken, plainly, [tool_on_path("cosign", [os.getcwd()], path=led) for led in leds], other
    finally:
        os.chdir(here)
        for link in (os.path.join(work, "Download Folder-link"), os.path.join(work, "Download Folder", "dist-link"), work + "-inside"):
            if os.path.lexists(link):
                if os.name == "nt":
                    subprocess.run(["cmd", "/c", "rmdir", link], capture_output=True)
                else:
                    os.remove(link)
        shutil.rmtree(work, ignore_errors=True)


def spellings_misread():
    """Which spellings of a folder that open as that folder are not known as it. The lookup above
    never searches a folder led by two separators, so most of these never reach the comparison
    there; asked here, the comparison is held on its own and not only behind that rule."""
    work = tempfile.mkdtemp(prefix="tw-identity-self-test-")
    folder = os.path.join(work, "Download Folder")
    os.makedirs(folder)
    try:
        return [label for label, entry in spellings_of(folder).items()
                if os.path.isdir(entry) and not same_folder(entry, folder)]
    finally:
        link = folder + "-link"
        if os.path.lexists(link):
            if os.name == "nt":
                subprocess.run(["cmd", "/c", "rmdir", link], capture_output=True)
            else:
                os.remove(link)
        shutil.rmtree(work, ignore_errors=True)


def newest_signtool():
    """The signtool taken from a Windows Kits folder holding three versions, one of them the newest
    only when read as numbers."""
    work = tempfile.mkdtemp(prefix="tw-kits-self-test-")
    try:
        for version in ("10.0.9999.0", "10.0.22621.0", "10.0.17763.0"):
            folder = os.path.join(work, "Windows Kits", "10", "bin", version, "x64")
            os.makedirs(folder)
            open(os.path.join(folder, "signtool.exe"), "wb").close()
        found = signtool(kits_at=os.path.join(work, "Windows Kits", "10", "bin", "*", "x64", "signtool.exe"))
        return os.path.basename(os.path.dirname(os.path.dirname(found))) if found else None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def refused_as(entries, kind=".zip"):
    """Why unpack() refuses an archive holding `entries`, or None where it takes the binary out."""
    work = tempfile.mkdtemp(prefix="tw-refused-as-self-test-")
    try:
        archive = os.path.join(work, "a" + kind)
        pack(archive, None, None, extra=entries)
        try:
            unpack(archive, os.path.join(work, "in"))
            return None
        except CouldNotRun as e:
            return str(e)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def relative_signtool_taken():
    """Whether `--signtool` takes a relative name that is a file in the working folder."""
    here = os.getcwd()
    work = tempfile.mkdtemp(prefix="tw-signtool-self-test-")
    try:
        with open(os.path.join(work, "signtool.exe"), "wb") as f:
            f.write(b"MZ planted")
        os.chdir(work)
        return signtool_given("signtool.exe") is None, signtool_given(os.path.join(work, "signtool.exe")) is None
    finally:
        os.chdir(here)
        shutil.rmtree(work, ignore_errors=True)


def macos_said(verify, describe, assess, pins):
    """What the check says of one macOS binary, where codesign --verify, codesign -dv and spctl answer
    as given, each an exit code and its output."""
    answers = {"--verify": verify, "-dv": describe, "--assess": assess}
    said = []

    def answer(argv):
        return answers[argv[1]] if argv[0] in (CODESIGN, SPCTL) else (127, "%s is not named in full" % argv[0])

    check_macos_binary("x86_64-apple-darwin", "timewitness", pins, lambda state, line: said.append((state, line)), run=answer)
    return said


def unpacked(entries, kind=".tar.gz", limit=ARCHIVE_LIMIT):
    """What unpack() makes of an archive holding `entries`, as pack() takes them, and whether anything
    was written outside the folder it unpacks into."""
    work = tempfile.mkdtemp(prefix="tw-unpack-self-test-")
    try:
        archive = os.path.join(work, "a" + kind)
        pack(archive, None, None, extra=entries)
        into = os.path.join(work, "in", "here")
        try:
            got = unpack(archive, into, limit)
            outcome = os.path.relpath(got, into)
        except CouldNotRun:
            outcome = "refused"
        except (tarfile.TarError, zipfile.BadZipFile, OSError) as e:
            outcome = "refused by the archive reader: %s" % type(e).__name__
        outside = [n for n in os.listdir(work) if n not in ("a" + kind, "in")]
        outside += [n for n in os.listdir(os.path.join(work, "in")) if n != "here"]
        return outcome, outside
    finally:
        shutil.rmtree(work, ignore_errors=True)


def zip_header_renamed(body):
    """What unpack() makes of a zip whose LICENSE is named another way in front of the file than in
    the zip's directory."""
    work = tempfile.mkdtemp(prefix="tw-zip-header-self-test-")
    try:
        archive = os.path.join(work, "a.zip")
        pack(archive, None, None, extra=[("timewitness.exe", body), ("LICENSE", b"l\n"), ("NOTICE", b"n\n")])
        with open(archive, "rb") as f:
            raw = f.read()
        with open(archive, "wb") as f:
            f.write(raw.replace(b"LICENSE", b"../LICE", 1))
        try:
            unpack(archive, os.path.join(work, "in"))
            return "taken"
        except (CouldNotRun, zipfile.BadZipFile) as e:
            return "refused" if "LICE" in str(e) else "refused for another reason: %s" % e
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cosign_said(results):
    """What the check said about the one Linux archive: its state, and whether a rehearsal line failed it."""
    about = [state for state, line in results if line.startswith(archive_name("v0.4", "x86_64-unknown-linux-gnu") + " ")]
    return about, any(state == "FAIL" and line.startswith("REHEARSAL KEY") for state, line in results)


def self_test():
    wrong = []

    def expect(name, got, want):
        if got != want:
            wrong.append("%s: judged %r, should be %r" % (name, got, want))

    def refused(problems):
        return bool(problems)

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
    expect("spctl failing and printing an acceptance", judge_spctl(3, "x: accepted\nsource=Notarized Developer ID\n"), False)

    # macOS: our team passes, and every other shape of Developer ID is refused.
    ours = "Developer ID Application: Ours Test Publisher (TESTTEAM01)"
    expect("our Developer ID", judge_codesign(0, codesign_text([ours] + APPLE_CHAIN, "TESTTEAM01"), TEST_PINS), [])
    expect("another team's Developer ID", refused(judge_codesign(
        0, codesign_text(["Developer ID Application: Someone Else Ltd (FOREIGN001)"] + APPLE_CHAIN, "FOREIGN001"),
        TEST_PINS)), True)
    expect("our team's name in another team's certificate", refused(judge_codesign(
        0, codesign_text([ours] + APPLE_CHAIN, "FOREIGN001"), TEST_PINS)), True)
    expect("our team, and a development certificate", refused(judge_codesign(
        0, codesign_text(["Apple Development: Ours Test Publisher (TESTTEAM01)", "Apple Worldwide Developer "
                          "Relations Certification Authority", "Apple Root CA"], "TESTTEAM01"), TEST_PINS)), True)
    expect("our team, and a Developer ID certificate for installers rather than code", refused(judge_codesign(
        0, codesign_text(["Developer ID Installer: Ours Test Publisher (TESTTEAM01)"] + APPLE_CHAIN, "TESTTEAM01"),
        TEST_PINS)), True)
    expect("our name, chained to somebody else's root", refused(judge_codesign(
        0, codesign_text([ours, "Developer ID Certification Authority", "Someone Root CA"], "TESTTEAM01"),
        TEST_PINS)), True)
    expect("ad hoc", refused(judge_codesign(0, "Signature=adhoc\nTeamIdentifier=not set\n", TEST_PINS)), True)
    expect("not signed at all", refused(judge_codesign(1, "code object is not signed at all\n", TEST_PINS)), True)
    unpinned_apple = judge_codesign(0, codesign_text([ours] + APPLE_CHAIN, "TESTTEAM01"), {"windows": TEST_PINS["windows"]})
    expect("our Developer ID, with no team pinned", refused(unpinned_apple), True)
    expect("an unpinned team says so", any(p.startswith("NOT PINNED: the Apple Team ID") for p in unpinned_apple), True)

    # Windows: real binaries, each signed by a throwaway chain, read out of their own bytes.
    signers = {}
    kinds = ("ours", "foreign", "impostor", "stranger", "namesake", "other-name", "other-org", "twin")
    for name in kinds:
        try:
            signers[name] = read_signer(fixture(name))
        except (OSError, ValueError) as e:
            wrong.append("the %s fixture could not be read: %s" % (name, e))
    expect("an unsigned binary has no signer", read_signer(fixture("unsigned")), None)
    if len(signers) == len(kinds):
        s = signers["ours"]
        expect("the signer read out of our fixture", (s["subject_cn"], s["subject_o"], s["issuer_cn"], s["issuer_o"]),
               (["Ours Test Publisher"], ["Ours Test Publisher"], ["Synthetic ID Verified CS EOC CA 01"], ["Synthetic Issuer"]))
        expect("its usages, code signing and our identity", s["usages"], ["1.3.6.1.5.5.7.3.3", "1.3.6.1.4.1.311.97.990001.1"])

        with open(os.path.join(FIXTURES, "ours.signtool.txt"), encoding="ascii") as f:
            captured = f.read()
        chain = signtool_chain(captured)
        expect("signtool's real chain names our fixture's certificate last", chain[-1:] and chain[-1].get("sha1"), s["sha1"])
        expect("signtool's real chain, untrusted root", refused(judge_signtool(1, captured, s, TEST_PINS)), True)

        root = (TEST_PINS["windows"]["root"], "11" * 20)
        ca = ("Synthetic ID Verified CS EOC CA 01", "22" * 20)
        foreign_root, foreign_ca = ("Foreign Test Root 2026", "33" * 20), ("Foreign Test Code Signing CA", "44" * 20)

        def trusted(signer, top, issuing):
            return signtool_text([top, issuing, (signer["subject_cn"][0], signer["sha1"])])

        expect("our publisher", judge_signtool(0, trusted(s, root, ca), s, TEST_PINS), [])
        f = signers["foreign"]
        expect("another publisher, trusted by signtool", refused(judge_signtool(0, trusted(f, foreign_root, foreign_ca), f, TEST_PINS)), True)
        i = signers["impostor"]
        expect("our name and usage from another issuer", refused(judge_signtool(0, trusted(i, foreign_root, foreign_ca), i, TEST_PINS)), True)
        expect("another certificate in the file than the one signtool verified", refused(judge_signtool(
            0, trusted(s, root, ca), i, TEST_PINS)), True)
        expect("our certificate, under another root", refused(judge_signtool(0, trusted(s, foreign_root, ca), s, TEST_PINS)), True)
        expect("our root's name, with another root above it", refused(judge_signtool(
            0, signtool_text([foreign_root, root, ca, (s["subject_cn"][0], s["sha1"])]), s, TEST_PINS)), True)
        expect("signtool refuses it", refused(judge_signtool(1, signtool_text([], verified=False), s, TEST_PINS)), True)
        expect("signtool refuses it, and prints our chain", refused(judge_signtool(
            1, signtool_text([root, ca, (s["subject_cn"][0], s["sha1"])], verified=False), s, TEST_PINS)), True)

        # Every other customer of our signing service has our issuer and our root, so only the
        # publisher and the identity usage tell their binaries from ours. Each of these is a real
        # certificate from the same issuing CA as ours, and each differs from ours in one respect.
        def ours_otherwise(name):
            return refused(judge_signtool(0, trusted(signers[name], root, ca), signers[name], TEST_PINS))

        g = signers["stranger"]
        expect("another customer of our issuer", (g["issuer_cn"], g["issuer_o"]), (s["issuer_cn"], s["issuer_o"]))
        expect("another customer of our issuer, refused", ours_otherwise("stranger"), True)
        expect("our name in full, another customer's identity usage", ours_otherwise("namesake"), True)
        expect("our organisation and identity usage, another common name", ours_otherwise("other-name"), True)
        expect("our common name and identity usage, another organisation", ours_otherwise("other-org"), True)

        # Every one of our names and our usage, in a certificate from a chain named like ours with
        # other keys. Only the tie to the certificate signtool verified tells it from ours.
        t = signers["twin"]
        names = ("subject_cn", "subject_o", "issuer_cn", "issuer_o", "usages")
        expect("the twin carries every one of our names", [t[k] for k in names], [s[k] for k in names])
        expect("the twin is another certificate", t["sha1"] != s["sha1"], True)
        expect("signtool verified ours, and the file carries the twin", refused(judge_signtool(
            0, trusted(s, root, ca), t, TEST_PINS)), True)

        # The issuer, under our root, each half on its own.
        expect("our name and usage from another issuer, under our root", refused(judge_signtool(
            0, trusted(i, root, ca), i, TEST_PINS)), True)
        expect("our certificate, with another issuing organisation", refused(judge_signtool(
            0, trusted(s, root, ca), dict(s, issuer_o=["Foreign Test Issuer"]), TEST_PINS)), True)
        expect("our certificate, from an issuer with another name", refused(judge_signtool(
            0, trusted(s, root, ca), dict(s, issuer_cn=["Foreign Test Code Signing CA"]), TEST_PINS)), True)
        expect("signtool passes and nothing in the file", refused(judge_signtool(0, trusted(s, root, ca), None, TEST_PINS)), True)
        for key in ("subject_common_name", "subject_organisation", "identity_usage"):
            unset = {"apple": TEST_PINS["apple"], "windows": dict(TEST_PINS["windows"], **{key: None})}
            said = judge_signtool(0, trusted(s, root, ca), s, unset)
            expect("our publisher, with %s not pinned" % key, refused(said), True)
            expect("an unpinned %s says so" % key, any(p.startswith("NOT PINNED") for p in said), True)

        # A second signature entry Windows would never look at is refused rather than read past.
        data = bytearray(fixture("ours"))
        offset, size = struct.unpack_from("<II", data, 0x40 + 24 + 112 + 32)
        extra = struct.pack("<IHH", 16, 0x0200, 0x0002) + b"\x00" * 8
        data += extra
        struct.pack_into("<I", data, 0x40 + 24 + 112 + 32 + 4, size + len(extra))
        try:
            read_signer(bytes(data))
            wrong.append("a second signature entry: read, should be refused")
        except ValueError:
            pass

        # On Windows, signtool itself reads our fixture, and the chain it prints ends at the
        # certificate read out of the file. It is refused, because nothing trusts the throwaway root.
        tool = signtool() if platform.system() == "Windows" else None
        if tool:
            work = tempfile.mkdtemp(prefix="tw-signing-self-test-")
            try:
                path = os.path.join(work, "ours.exe")
                with open(path, "wb") as out:
                    out.write(fixture("ours"))
                code, out = run([tool, "verify", "/pa", "/v", path])
                live = signtool_chain(out)
                expect("signtool here names our fixture's certificate last", live[-1:] and live[-1].get("sha1"), s["sha1"])
                expect("signtool here, untrusted root", refused(judge_signtool(code, out, s, TEST_PINS)), True)
            finally:
                shutil.rmtree(work, ignore_errors=True)

    # The pins: unset, malformed and missing each refuse, and a whole set loads.
    work = tempfile.mkdtemp(prefix="tw-pins-self-test-")
    try:
        def pins_from(value):
            path = os.path.join(work, "pins.json")
            with open(path, "w", encoding="utf-8") as out:
                out.write(value if isinstance(value, str) else json.dumps(value))
            return load_pins(path)

        loaded, problems = pins_from(TEST_PINS)
        expect("a whole set of pins", (problems, loaded), ([], TEST_PINS))
        _, problems = pins_from(dict(TEST_PINS, apple={"team_id": None}))
        expect("no Apple Team ID", problems, [not_pinned("the Apple Team ID")])
        _, problems = pins_from(dict(TEST_PINS, windows=dict(TEST_PINS["windows"], subject_organisation="")))
        expect("no Windows publisher", problems, [not_pinned("the Windows publisher's organisation")])
        _, problems = pins_from(dict(TEST_PINS, apple={"team_id": "testteam"}))
        expect("a Team ID that is not one", len(problems), 1)
        _, problems = pins_from({})
        expect("an empty file", len(problems), len(PIN_SHAPES))
        _, problems = pins_from("{ not json")
        expect("a file that does not parse", len(problems), 1)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # The tracked file, as a release check reads it: each identity it leaves unset is a failure of
    # its own, so a run whose every other clause passes still fails.
    said = []
    _, problems = load_pins()
    pinned_or_say(lambda state, line: said.append((state, line)))
    expect("each unset identity in the tracked file is a failure", [state for state, _ in said], ["FAIL"] * len(problems))
    expect("and says it is not pinned", all(line.startswith("NOT PINNED") for _, line in said), True)
    if problems:
        expect("so a run with every other clause passing fails", verdict(said + [("PASS", "")] * 9), 1)

    expect("signtool, no signature", refused(judge_signtool(1, "SignTool Error: No signature found.\n", None, TEST_PINS)), True)
    # Who signed a Linux archive, as cosign reads SIGNER: found anywhere in the certificate's
    # identity, not only at its start, which is why it is anchored at both ends.
    base = OUR_WORKFLOW[:-len("heads/main")]
    expect("signed by a run started by this tag", bool(re.search(SIGNER, base + "tags/v0.4")), False)
    expect("signed by a run from main", bool(re.search(SIGNER, OUR_WORKFLOW)), True)
    expect("signed by another tag's run", bool(re.search(SIGNER, base + "tags/v0.4.1")), False)
    expect("signed by a run from a branch", bool(re.search(SIGNER, base + "heads/other")), False)
    expect("signed by a run from a branch whose name starts main", bool(re.search(SIGNER, OUR_WORKFLOW + "-next")), False)
    expect("signed by another workflow", bool(re.search(SIGNER, base.replace("release.yml", "ci.yml") + "heads/main")), False)
    expect("signed by the same workflow of another owner",
           bool(re.search(SIGNER, OUR_WORKFLOW.replace("Fountech-ai-Limited/", "someone-else/"))), False)
    expect("signed by the same workflow of another repository of ours",
           bool(re.search(SIGNER, OUR_WORKFLOW.replace("/timewitness/", "/timewitness-fork/"))), False)
    expect("our workflow's address inside another one", bool(re.search(SIGNER, "https://example.com/" + OUR_WORKFLOW)), False)
    expect("cosign passes", judge_cosign(0, "Verified OK\n"), True)
    expect("cosign refuses", judge_cosign(1, "Error: none of the expected identities matched\n"), False)
    expect("a Linux archive cosign verifies, signed in the Linux signing job, passes",
           cosign_said(linux_bundle_check("verifies")), (["PASS", "PASS"], False))
    expect("a Linux archive cosign refuses fails", cosign_said(linux_bundle_check("refuses")), (["FAIL"], False))

    # What the check asks cosign to hold a signature to. Each certificate here is one Fulcio would
    # issue and cosign would verify against a looser question, and only the first is ours.
    def signed_as(identity, issuer=GITHUB_ISSUER):
        return cosign_said(linux_bundle_check("verifies", identity=identity, issuer=issuer))[0]

    expect("our release workflow from main, by GitHub's issuer", signed_as(OUR_WORKFLOW), ["PASS", "PASS"])
    expect("the same workflow in another owner's repository",
           signed_as(OUR_WORKFLOW.replace("Fountech-ai-Limited/", "someone-else/")), ["FAIL"])
    expect("the same workflow in another repository", signed_as(OUR_WORKFLOW.replace("/timewitness/", "/other/")), ["FAIL"])
    expect("our workflow's address inside another identity", signed_as("https://example.com/" + OUR_WORKFLOW), ["FAIL"])
    expect("our workflow, from an issuer other than GitHub's", signed_as(OUR_WORKFLOW, "https://accounts.example.com"), ["FAIL"])

    # A release missing anything a stranger needs is refused by name, whatever else passes.
    whole = list(TARGETS)

    def missing_said(drop):
        return [line for state, line in linux_bundle_check("verifies", targets=whole, drop=drop)
                if state == "FAIL" and line.startswith("missing from the release: ")]

    expect("a whole release is missing nothing", missing_said(()), [])
    expect("a release missing the Windows archive", missing_said((archive_name("v0.4", "x86_64-pc-windows-msvc"),)),
           ["missing from the release: " + archive_name("v0.4", "x86_64-pc-windows-msvc")])
    expect("a release missing the digest list's bundle", missing_said((SUMS + BUNDLE,)), ["missing from the release: " + SUMS + BUNDLE])
    expect("a release missing a Linux archive's bundle",
           missing_said((archive_name("v0.4", "aarch64-unknown-linux-gnu") + BUNDLE,)),
           ["missing from the release: " + archive_name("v0.4", "aarch64-unknown-linux-gnu") + BUNDLE])

    # macOS, the tools as the check runs them: codesign --verify has the first word, and the tools
    # are named in full.
    good = (0, codesign_text(["Developer ID Application: Ours Test Publisher (TESTTEAM01)"] + APPLE_CHAIN, "TESTTEAM01"))
    notarised = (0, "x: accepted\nsource=Notarized Developer ID\n")
    expect("macOS, codesign verifies ours and spctl accepts it",
           [state for state, _ in macos_said((0, "valid on disk\n"), good, notarised, TEST_PINS)], ["PASS", "PASS"])
    refused_verify = macos_said((1, "timewitness: invalid signature (code or signature have been modified)\n"), good, notarised, TEST_PINS)
    expect("macOS, codesign --verify refuses it and -dv reads our team",
           [(state, "codesign --verify refuses it" in line) for state, line in refused_verify][:1], [("FAIL", True)])
    expect("the macOS tools are named where macOS keeps them", (CODESIGN, SPCTL), ("/usr/bin/codesign", "/usr/sbin/spctl"))

    # The binary taken out of an archive: the archive holds it, LICENSE and NOTICE, each once, each a
    # plain file, however spelt; and nothing is written anywhere but the binary.
    body = b"#!/bin/sh\necho timewitness v0.4\n"
    notices = [("LICENSE", b"l\n"), ("NOTICE", b"n\n")]
    expect("a zip naming its LICENSE one way in its directory and another in front of the file",
           zip_header_renamed(body), "refused")
    expect("an archive holding the binary and its two notices", unpacked([("timewitness", body)] + notices), ("timewitness", []))
    expect("the same, each name led by ./", unpacked([("./timewitness", body), ("./LICENSE", b"l\n"), ("./NOTICE", b"n\n")]),
           ("timewitness", []))
    expect("an archive whose binary is a link to another entry", unpacked([("timewitness", ("link", "LICENSE"))] + notices),
           ("refused", []))
    expect("an archive holding the binary twice", unpacked([("timewitness", body), ("timewitness", body)] + notices), ("refused", []))
    expect("an archive holding the binary as timewitness and ./timewitness",
           unpacked([("timewitness", body), ("./timewitness", b"other\n")] + notices), ("refused", []))
    expect("an archive with an entry that climbs out of the folder",
           unpacked([("timewitness", body), ("../escaped", b"x\n")] + notices), ("refused", []))
    expect("an archive with a file beside the three", unpacked([("timewitness", body), ("install.sh", b"x\n")] + notices), ("refused", []))
    expect("an archive without its notices", unpacked([("timewitness", body)]), ("refused", []))
    expect("an archive whose binary is larger than a release binary is",
           unpacked([("timewitness", body)] + notices, limit=len(body) - 1), ("refused", []))
    expect("a zip holding the binary and its two notices", unpacked([("timewitness.exe", body)] + notices, ".zip"),
           ("timewitness.exe", []))
    expect("a zip holding the binary as timewitness.exe and TIMEWITNESS.EXE",
           unpacked([("timewitness.exe", body), ("TIMEWITNESS.EXE", b"other\n")] + notices, ".zip"), ("refused", []))
    expect("a zip whose binary is a link", unpacked([("timewitness.exe", ("link", "LICENSE"))] + notices, ".zip"), ("refused", []))
    expect("a zip holding the binary in capitals, taken out under its own name",
           unpacked([("TIMEWITNESS.EXE", body)] + notices, ".zip"), ("timewitness.exe", []))
    # A zip written on Windows turns a backslash into a slash, and a tar keeps it, so both are asked.
    for kind in (".zip", ".tar.gz"):
        for entry in ("sub/timewitness.exe", "sub\\timewitness.exe", "C:timewitness.exe", ".."):
            said = refused_as([(entry, body)] + notices, kind)
            expect("a %s holding [%s] refused as not a plain name" % (kind, entry), bool(said) and "is not a plain name" in said, True)

    # signtool and cosign left in the folder the check is run in, and that folder on the path; a
    # cosign in the folder the assets are read from; a batch file for cosign; a relative --signtool.
    took_signtool, took_cosign, ran, plant = planted_tools_taken()
    expect("signtool left in the working folder is not taken", bool(took_signtool) and took_signtool.startswith(plant), False)
    expect("cosign left in the working folder is not taken", bool(took_cosign) and took_cosign.startswith(plant), False)
    expect("no tool left in the working or the assets' folder is run by a whole check", ran, False)
    expect("a cosign batch file in a folder on the path is not taken for cosign.exe", batch_file_taken(), False)
    expect("--signtool refuses a relative name and takes a full path", relative_signtool_taken(), (False, True))

    # The working folder and the assets' folder are known by what they are on disk, so no other
    # spelling of either on the path hands the check a cosign left there; a folder led by two
    # separators is a share or a device path and is never searched; and a folder that is neither is.
    taken, plainly, led, other = cosign_taken_by_spelling()
    expect("no spelling of the working or the assets' folder hands the check their cosign", taken, [])
    expect("a cosign in another folder on the path is taken", bool(plainly) and plainly.startswith(other), True)
    expect("a cosign in a folder on the path led by two separators is not taken", [t for t in led if t], [])
    expect("every spelling that opens as a folder is known as that folder", spellings_misread(), [])
    expect("the newest Windows Kits signtool is taken, by its version as numbers", newest_signtool(), "10.0.22621.0")
    # Asked of runs of this file started without the setting, since whoever started this one may
    # have set it already: one checking a binary and one checking a release, the two that start
    # tools, each given nothing to check so that it stops before it starts any.
    empty = tempfile.mkdtemp(prefix="tw-nothing-self-test-")
    told = []
    for given in (["--binary", os.path.join(empty, "timewitness.exe")], ["--release", "v0.0", "--dist", empty, "--no-run"]):
        started = subprocess.run([sys.executable, "-c", "import os, runpy, sys\n"
                                  "sys.argv = sys.argv[1:]\n"
                                  "try:\n    runpy.run_path(sys.argv[0], run_name='__main__')\n"
                                  "except SystemExit:\n    pass\n"
                                  "print(os.environ.get('NoDefaultCurrentDirectoryInExePath'))\n",
                                  os.path.abspath(__file__)] + given,
                                 capture_output=True, text=True, timeout=120,
                                 env={k: v for k, v in os.environ.items() if k.lower() != "nodefaultcurrentdirectoryinexepath"})
        told.append((started.stdout.strip().splitlines() or [""])[-1])
    shutil.rmtree(empty, ignore_errors=True)
    expect("whatever this starts on Windows is told not to look in the working folder", told, ["1", "1"])

    # Which job signed. cosign holds a bundle to the workflow and the ref, which every job in the run
    # shares, so each of these is a certificate it would verify, and only the first is ours.
    def job_said(subjects=None, bundle=None):
        if bundle is None:
            bundle = bundle_of(fulcio_shaped(subjects))
        return cosign_said(linux_bundle_check("verifies", bundle=bundle))[0]

    expect("the Linux signing job's token", job_said([LINUX_SUBJECT]), ["PASS", "PASS"])
    expect("sign-windows' token, which cosign's identity alone accepts", job_said([WINDOWS_SUBJECT]), ["PASS", "FAIL"])
    expect("a token from a job in no environment", job_said([NO_ENVIRONMENT_SUBJECT]), ["PASS", "FAIL"])
    expect("the Linux signing environment in a repository of the same name made again",
           job_said([OUR_PREFIX.rsplit("@", 1)[0] + "@9999999999:environment:linux-signing"]), ["PASS", "FAIL"])
    expect("the Linux signing environment under the default subject",
           job_said(["repo:Fountech-ai-Limited/timewitness:environment:linux-signing"]), ["PASS", "FAIL"])
    expect("the Linux signing environment, naming no ref and no workflow",
           job_said([OUR_PREFIX + ":environment:linux-signing"]), ["PASS", "FAIL"])
    expect("the Linux signing environment, from another workflow",
           job_said([LINUX_SUBJECT.replace("/release.yml@", "/other.yml@")]), ["PASS", "FAIL"])
    expect("a certificate naming no token subject", job_said([]), ["PASS", "FAIL"])
    expect("a certificate naming ours and sign-windows'", job_said([LINUX_SUBJECT, WINDOWS_SUBJECT]), ["PASS", "FAIL"])
    expect("a certificate naming ours twice", job_said([LINUX_SUBJECT, LINUX_SUBJECT]), ["PASS", "FAIL"])
    expect("ours, in a certificate chain rather than a certificate",
           job_said(bundle=bundle_of(fulcio_shaped([LINUX_SUBJECT]), "x509CertificateChain")), ["PASS", "PASS"])
    expect("ours, beside sign-windows' in a chain",
           job_said(bundle=json.dumps({"mediaType": BUNDLE_TYPE + ".v0.3+json", "verificationMaterial": {
               "certificate": {"rawBytes": base64.b64encode(fulcio_shaped([LINUX_SUBJECT])).decode()},
               "x509CertificateChain": {"certificates": [{"rawBytes": base64.b64encode(fulcio_shaped([WINDOWS_SUBJECT])).decode()}]}}})),
           ["PASS", "FAIL"])
    expect("a bundle signed with a key and no certificate", job_said(bundle=bundle_of(b"", "key")), ["PASS", "FAIL"])
    expect("a bundle that is not one", job_said(bundle="{}"), ["PASS", "FAIL"])

    # One file for two readers: cosign reads a file that is not a bundle as its older bundle, from
    # `cert` and the keys beside it, whatever their case, and the check reads `verificationMaterial`.
    windows_der = fulcio_shaped([WINDOWS_SUBJECT])
    windows_pem = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % base64.b64encode(windows_der).decode()
    ours_bundle = json.loads(bundle_of(fulcio_shaped([LINUX_SUBJECT])))
    older = {"base64Signature": "c2lnbmF0dXJl", "cert": base64.b64encode(windows_pem.encode()).decode(), "rekorBundle": {}}
    expect("sign-windows' certificate for cosign beside ours for the check", job_said(bundle=json.dumps(dict(ours_bundle, **older))),
           ["PASS", "FAIL"])
    expect("the same, its keys spelt in another case", job_said(bundle=json.dumps(dict(ours_bundle, Cert=older["cert"],
           BASE64SIGNATURE=older["base64Signature"]))), ["PASS", "FAIL"])
    expect("ours beside an older bundle's certificate alone", job_said(bundle=json.dumps(dict(ours_bundle, cert=older["cert"]))),
           ["PASS", "FAIL"])
    expect("ours with no media type", job_said(bundle=json.dumps({"verificationMaterial": ours_bundle["verificationMaterial"]})),
           ["PASS", "FAIL"])

    # The subject extension read as Fulcio writes it: one UTF8String, inside an OCTET STRING.
    def subject_in(value):
        extension = der_of(0x30, oid_der(OID_TOKEN_SUBJECT) + value)
        extensions = der_of(0xA3, der_of(0x30, der_of(0x30, oid_der("2.5.29.15") + der_of(0x04, der_of(0x03, b"\x07\x80")))
                                          + extension))
        algorithm = der_of(0x30, oid_der("1.2.840.10045.4.3.3"))
        tbs = der_of(0x30, der_of(0xA0, der_of(0x02, b"\x02")) + der_of(0x02, b"\x01") + algorithm + der_of(0x30, b"")
                     + der_of(0x30, b"") + der_of(0x30, b"") + der_of(0x30, b"") + extensions)
        return bundle_of(der_of(0x30, tbs + algorithm + der_of(0x03, b"\x00")))

    expect("the subject as Fulcio writes it", job_said(bundle=subject_in(der_of(0x04, der_of(0x0C, LINUX_SUBJECT.encode())))),
           ["PASS", "PASS"])
    expect("the subject as another kind of string", job_said(bundle=subject_in(der_of(0x04, der_of(0x13, LINUX_SUBJECT.encode())))),
           ["PASS", "FAIL"])
    expect("the subject with bytes after it", job_said(bundle=subject_in(der_of(0x04, der_of(0x0C, LINUX_SUBJECT.encode()) + b"\x00"))),
           ["PASS", "FAIL"])
    expect("the subject's extension holding something other than an OCTET STRING",
           job_said(bundle=subject_in(der_of(0x30, der_of(0x0C, LINUX_SUBJECT.encode())))), ["PASS", "FAIL"])
    expect("a certificate with bytes after it", job_said(bundle=bundle_of(fulcio_shaped([LINUX_SUBJECT]) + b"\x00")), ["PASS", "FAIL"])
    real = fulcio_elsewhere()
    expect("the subject read out of a real Fulcio certificate", token_subject(real), "repo:pytest-dev/pytest:environment:deploy")
    expect("a real Fulcio certificate for another repository's release job", job_said(bundle=bundle_of(real)), ["PASS", "FAIL"])
    expect("a rehearsal key the archive verifies against still fails the check",
           cosign_said(linux_bundle_check("verifies", rehearsal_key="cosign.pub")), (["PASS"], True))
    expect("a rehearsal key the archive does not verify against fails it twice",
           cosign_said(linux_bundle_check("refuses", rehearsal_key="cosign.pub")), (["FAIL"], True))

    # A binary is run only once every clause about it passed, and with no token beside it.
    expect("run, its digest and its signature passed", may_run(["PASS"], ["PASS", "PASS"]), True)
    expect("not run, its signature refused", may_run(["PASS"], ["PASS", "FAIL"]), False)
    expect("not run, its digest refused", may_run(["FAIL"], ["PASS"]), False)
    expect("not run, its signature not checked here", may_run(["PASS"], ["NOT RUN"]), False)
    expect("not run, no signature checked at all", may_run(["PASS"], []), False)
    expect("not run, no digest checked at all", may_run([], ["PASS"]), False)
    expect("not run, nothing checked about it", may_run([], []), False)
    handed = run_environment({"PATH": "/usr/bin", "SYSTEMROOT": r"C:\Windows", "GH_TOKEN": "t", "GITHUB_TOKEN": "t",
                              "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t", "ACTIONS_RUNTIME_TOKEN": "t",
                              "WINDOWS_AZURE_CLIENT_ID": "t", "MACOS_CERTIFICATE_PASSWORD": "t"})
    expect("the binary is handed its path and nothing that holds a token", sorted(handed), ["PATH", "SYSTEMROOT"])
    expect("a check refuses to run a binary whose digest line is wrong", refuses_to_run_what_it_refused(True), True)
    expect("a check refuses to run a binary whose digest is right and whose signature is not",
           refuses_to_run_what_it_refused(False), True)

    linux_only = [("PASS", ""), ("ELSEWHERE", "x86_64-apple-darwin: its signature is checked on macos, and this is not"),
                  ("ELSEWHERE", "x86_64-pc-windows-msvc: its signature is checked on windows, and this is not")]
    last = summary(verdict(linux_only), linux_only)
    expect("a pass on one system names the targets it did not check",
           ("x86_64-apple-darwin" in last, "x86_64-pc-windows-msvc" in last, "every clause passed" in last),
           (True, True, False))

    expect("all pass", verdict([("PASS", "")] * 3), 0)
    expect("a failure beats a clause not run", verdict([("NOT RUN", ""), ("FAIL", "")]), 1)
    expect("a clause not run is not a pass", verdict([("PASS", ""), ("NOT RUN", "")]), 2)
    expect("nothing read is not a pass", verdict([]), 2)

    # The exit code is all CI, the push check, and the release workflow read, so the check is run here
    # as they run it. cosign is kept off the path, where the self-test has no use for a real one.
    exits = tempfile.mkdtemp(prefix="tw-exits-self-test-")
    try:
        no_tools = os.path.join(exits, "no-tools")
        os.makedirs(no_tools)
        bare = dict(os.environ, PATH=no_tools)

        def as_run(given, preamble=""):
            """This file run as `given` asks, with `preamble` run first on it loaded as a module."""
            done = subprocess.run([sys.executable, "-c", "import importlib.util, sys\n"
                                   "spec = importlib.util.spec_from_file_location('check', sys.argv[1])\n"
                                   "check = importlib.util.module_from_spec(spec)\n"
                                   "spec.loader.exec_module(check)\n" + preamble +
                                   "sys.argv = sys.argv[1:]\n"
                                   "sys.exit(check.main())\n", os.path.abspath(__file__)] + given,
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, env=bare)
            return done.returncode, done.stdout

        whole_dist, short_dist = os.path.join(exits, "whole"), os.path.join(exits, "short")
        for dist, drop in ((whole_dist, ()), (short_dist, (archive_name(tag, "x86_64-pc-windows-msvc"),))):
            os.makedirs(dist)
            write_release(dist, tag, TARGETS, bundle_of(fulcio_shaped([LINUX_SUBJECT])), drop=drop)
        code, out = as_run(["--release", tag, "--dist", short_dist, "--no-run"])
        expect("a release missing an archive exits 1, and says which",
               (code, "FAIL: missing from the release: " + archive_name(tag, "x86_64-pc-windows-msvc") in out), (1, True))
        # On Windows or macOS the stand-in binaries go to signtool or codesign as well, which can fail
        # them, so this asks only that the run does not pass.
        code, out = as_run(["--release", tag, "--dist", whole_dist, "--no-run"])
        expect("a release checked with no cosign on the path says so, and does not pass",
               (code != 0, "NOT RUN: cosign is not on this machine" in out), (True, True))
        # The tool for one binary cannot start: on Linux no tool is ever started, so its failure to
        # start is made here, where the check would meet it on macOS or Windows.
        code, out = as_run(["--binary", os.path.join(exits, "timewitness")],
                           "def cannot(binary, signtool_at=None):\n    raise check.CouldNotRun('the tool could not be started')\n"
                           "check.check_one = cannot\n")
        expect("a binary whose tool cannot start exits 2, and says so",
               (code, "NOT RUN: the tool could not be started" in out), (2, True))
        # The same for a release, which is how the release workflow runs the check.
        code, out = as_run(["--release", tag, "--dist", whole_dist],
                           "def cannot(*given, **named):\n    raise check.CouldNotRun('the release could not be read')\n"
                           "check.check = cannot\n")
        expect("a release that cannot be checked exits 2, and says so",
               (code, "NOT RUN: the release could not be read" in out), (2, True))
    finally:
        shutil.rmtree(exits, ignore_errors=True)

    for line in wrong:
        print("self-test: " + line)
    if wrong:
        print("self-test: %d judged wrongly" % len(wrong))
        return 1
    print("self-test: every shape judged as it should be; refused among them another team's Developer ID, "
          "a Windows binary signed by another publisher, one signed with our name by another issuer, one "
          "signed by another customer of our own issuer, a certificate other than the one signtool verified, "
          "a Linux archive signed with the Windows signing job's token, and a check with an identity unset; "
          "and no binary the check refused is run")
    if problems:
        print("self-test: the tracked identities are not all set, so a release check run now refuses: "
              + "; ".join(p[len("NOT PINNED: "):].split(" is not set")[0] for p in problems))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--release", help="the release tag to check")
    parser.add_argument("--repo", default=REPO)
    parser.add_argument("--dist", help="read the release's assets from this folder rather than from GitHub")
    parser.add_argument("--no-run", action="store_true", help="check the signatures and run no binary")
    parser.add_argument("--rehearsal-key", help="hold the Linux bundles to this public key, as a rehearsal signs them, "
                                                "and never pass")
    parser.add_argument("--binary", help="check the signature on one binary already on this machine")
    parser.add_argument("--signtool", help="the full path of signtool, where it is not in the Windows Kits folder")
    parser.add_argument("--pins", action="store_true", help="say whether every identity is set")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    # Whatever this starts on Windows looks in the working folder last, if at all, rather than first.
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    if args.signtool and signtool_given(args.signtool):
        parser.error(signtool_given(args.signtool))
    if args.self_test:
        return self_test()
    if args.pins:
        pins, problems = load_pins()
        for problem in problems:
            print(problem)
        if problems:
            return 1
        print("PINNED: Apple team %s; Windows publisher %s, identity usage %s, issued by %s* under %s"
              % (pins["apple"]["team_id"], pins["windows"]["subject_common_name"], pins["windows"]["identity_usage"],
                 pins["windows"]["issuer_common_name_starts"], pins["windows"]["root"]))
        return 0
    if args.binary:
        try:
            results = check_one(args.binary, args.signtool)
        except CouldNotRun as e:
            print("NOT RUN: %s" % e)
            return 2
    else:
        if not args.release:
            parser.error("name the release with --release, a file with --binary, or run --pins or --self-test")
        work = tempfile.mkdtemp(prefix="tw-binaries-")
        try:
            results = check(args.release, work, repo=args.repo, folder=args.dist, run_binary=not args.no_run,
                            rehearsal_key=args.rehearsal_key, signtool_at=args.signtool)
        except CouldNotRun as e:
            print("NOT RUN: %s" % e)
            return 2
        finally:
            shutil.rmtree(work, ignore_errors=True)
    code = verdict(results)
    print(summary(code, results))
    return code


if __name__ == "__main__":
    sys.exit(main())
