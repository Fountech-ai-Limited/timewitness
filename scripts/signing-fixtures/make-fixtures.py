#!/usr/bin/env python3
"""Build the Windows binaries the signature check's self-test reads, each one really signed.

    python scripts/signing-fixtures/make-fixtures.py

The self-test has to watch the check refuse a binary signed by somebody else, and accept one signed
by us, without either of our real signing identities, which do not exist yet and which a test should
never hold. So this makes two throwaway certificate chains, each a root, an issuing CA and a
code-signing certificate, and signs a small program with each. Nothing here is trusted by any
machine and the keys are thrown away when it finishes.

- `ours.exe` is signed by a chain shaped the way Azure Trusted Signing issues ours will be: the
  subject names the publisher in both its common name and its organisation, and the certificate
  carries an identity usage under Microsoft's 1.3.6.1.4.1.311.97 arc. The names and the number are
  made up and say so.
- `foreign.exe` is signed by another publisher from another issuer.
- `impostor.exe` carries our publisher's name and our identity usage, issued by the other issuer.
  A certificate authority will write any name into a certificate for anybody who can prove they
  hold it somewhere, so a name alone is not an identity.
- `stranger.exe` is another customer of our own signing service: our issuer, our root, somebody
  else's name and somebody else's identity usage. Every other customer of that service looks like
  this, which is the shape the publisher and usage pins exist for.
- `namesake.exe` is from our issuer, with our name in full and another customer's identity usage: a
  company of the same name, validated on its own.
- `other-name.exe` and `other-org.exe` are from our issuer with our identity usage, and differ from
  our subject in its common name alone and in its organisation alone.
- `twin.exe` carries every one of our names and our identity usage, from a second chain whose names
  are ours and whose keys are not. Only the certificate's own digest tells it from ours.
- `unsigned.exe` is the same program with no signature.

The program is written here byte by byte, so the fixtures depend on no compiler. Signing needs
`openssl` and either `signtool` (Windows) or `osslsigncode`. Where `signtool` is here, what it prints
verifying `ours.exe` is kept as `ours.signtool.txt`, because the self-test holds the chain it reads
out of that text to the certificate it reads out of the file.

Each binary is written as base64 beside this file, `ours.exe.b64` and so on, because the repository
holds text and nothing else: a file git classes as binary is one every check that greps goes blind
to, and `scripts/repo-hygiene.sh` refuses it. The self-test decodes them. A fresh run makes different
keys and so different bytes, which is expected: the self-test reads what the certificates say rather
than their digests.
"""

import base64
import glob
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# The made-up identities. The self-test pins the first and expects the second refused.
OURS = {
    "root": "Synthetic Identity Verification Root 2026",
    "ca": "Synthetic ID Verified CS EOC CA 01",
    "ca_org": "Synthetic Issuer",
    "leaf": "Ours Test Publisher",
    "leaf_org": "Ours Test Publisher",
    "eku": "1.3.6.1.4.1.311.97.990001.1",
}
FOREIGN = {
    "root": "Foreign Test Root 2026",
    "ca": "Foreign Test Code Signing CA",
    "ca_org": "Foreign Test Issuer",
    "leaf": "Someone Else Test Ltd",
    "leaf_org": "Someone Else Test Ltd",
    "eku": None,
}
IMPOSTOR = dict(FOREIGN, leaf=OURS["leaf"], leaf_org=OURS["leaf_org"], eku=OURS["eku"])

# Further certificates from our own issuer. Each differs from ours in what its name says.
STRANGER = {"leaf": "Stranger Test Ltd", "leaf_org": "Stranger Test Ltd", "eku": "1.3.6.1.4.1.311.97.990002.1"}
NAMESAKE = {"leaf": OURS["leaf"], "leaf_org": OURS["leaf_org"], "eku": "1.3.6.1.4.1.311.97.990003.1"}
OTHER_NAME = {"leaf": "Stranger Test Ltd", "leaf_org": OURS["leaf_org"], "eku": OURS["eku"]}
OTHER_ORG = {"leaf": OURS["leaf"], "leaf_org": "Stranger Test Ltd", "eku": OURS["eku"]}


def tiny_pe():
    """A 64-bit Windows console program whose whole body is `xor eax, eax; ret`."""
    file_align, section_align = 0x200, 0x1000
    code = b"\x31\xc0\xc3"
    text = code + b"\x00" * (file_align - len(code))
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x0022)
    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 14, 0,                  # PE32+, linker version
        len(text), 0, 0,               # code, initialised and uninitialised data
        section_align, section_align,  # entry point, base of code
        0x140000000,                   # image base
        section_align, file_align,
        6, 0, 0, 0, 6, 0,              # system, image and subsystem versions
        0,                             # Win32 version
        section_align * 2,             # size of image
        file_align,                    # size of headers
        0,                             # checksum
        3, 0x8100,                     # console; NX and terminal server aware, and no relocations to move it
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16,
    )
    directories = b"\x00" * (16 * 8)
    section = struct.pack("<8sIIIIIIHHI", b".text", len(code), section_align, len(text), file_align,
                          0, 0, 0, 0, 0x60000020)
    headers = bytes(dos) + b"PE\x00\x00" + coff + optional + directories + section
    headers += b"\x00" * (file_align - len(headers))
    return headers + text


def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def chain(name, spec, work):
    """A root, an issuing CA and a code-signing certificate, and a .pfx holding the last with its key."""
    d = os.path.join(work, name)
    os.makedirs(d)
    with open(os.path.join(d, "ca.ext"), "w") as f:
        f.write("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
            "-days", "7300", "-subj", "/CN=%s/O=%s" % (spec["root"], spec["ca_org"]),
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            cwd=d)
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.csr",
            "-subj", "/CN=%s/O=%s/C=GB" % (spec["ca"], spec["ca_org"]), cwd=d)
    openssl("x509", "-req", "-in", "ca.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
            "-out", "ca.pem", "-days", "7300", "-extfile", "ca.ext", cwd=d)
    with open(os.path.join(d, "chain.pem"), "wb") as out:
        for part in ("ca.pem", "root.pem"):
            with open(os.path.join(d, part), "rb") as f:
                out.write(f.read())
    leaf(d, "leaf", spec)
    return d


def leaf(d, name, spec):
    """A code-signing certificate from the issuing CA in `d`, and a .pfx holding it with its key."""
    usages = "codeSigning" + (", " + spec["eku"] if spec["eku"] else "")
    with open(os.path.join(d, name + ".ext"), "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" % usages)
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr",
            "-subj", "/C=GB/L=London/O=%s/CN=%s" % (spec["leaf_org"], spec["leaf"]), cwd=d)
    openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", name + ".pem", "-days", "7300", "-extfile", name + ".ext", cwd=d)
    openssl("pkcs12", "-export", "-inkey", name + ".key", "-in", name + ".pem", "-certfile", "chain.pem",
            "-out", name + ".pfx", "-passout", "pass:throwaway", cwd=d)
    return os.path.join(d, name + ".pfx")


def signtool():
    found = shutil.which("signtool")
    if found:
        return found
    kits = sorted(glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"))
    return kits[-1] if kits else None


def sign(program, pfx, out):
    tool = signtool()
    if tool:
        shutil.copyfile(program, out)
        subprocess.run([tool, "sign", "/f", pfx, "/p", "throwaway", "/fd", "SHA256", out],
                       check=True, capture_output=True)
    elif shutil.which("osslsigncode"):
        subprocess.run(["osslsigncode", "sign", "-pkcs12", pfx,
                        "-pass", "throwaway", "-h", "sha256", "-in", program, "-out", out],
                       check=True, capture_output=True)
    else:
        sys.exit("make-fixtures: neither signtool nor osslsigncode is on this machine")


def keep(path, name):
    with open(path, "rb") as f:
        text = base64.encodebytes(f.read()).decode("ascii")
    with open(os.path.join(HERE, name + ".exe.b64"), "w", encoding="ascii", newline="\n") as f:
        f.write(text)


def main():
    work = tempfile.mkdtemp(prefix="tw-signing-fixtures-")
    try:
        program = os.path.join(work, "program.exe")
        with open(program, "wb") as f:
            f.write(tiny_pe())
        keep(program, "unsigned")
        made = {}
        for name, spec in (("ours", OURS), ("foreign", FOREIGN), ("impostor", IMPOSTOR), ("twin", OURS)):
            made[name] = chain(name, spec, work)
            signed = os.path.join(work, name + ".exe")
            sign(program, os.path.join(made[name], "leaf.pfx"), signed)
            keep(signed, name)
            print("make-fixtures: %s.exe signed by %s, issued by %s" % (name, spec["leaf"], spec["ca"]))
        for name, spec in (("stranger", STRANGER), ("namesake", NAMESAKE), ("other-name", OTHER_NAME),
                           ("other-org", OTHER_ORG)):
            signed = os.path.join(work, name + ".exe")
            sign(program, leaf(made["ours"], name, spec), signed)
            keep(signed, name)
            print("make-fixtures: %s.exe signed by %s / %s, issued by %s"
                  % (name, spec["leaf"], spec["leaf_org"], OURS["ca"]))
        tool = signtool()
        if tool:
            # Read as bytes: signtool ends its lines with two carriage returns, which text mode turns
            # into a blank line after every line.
            done = subprocess.run([tool, "verify", "/pa", "/v", "ours.exe"], cwd=work, capture_output=True)
            printed = (done.stdout + done.stderr).decode("utf-8", "replace").replace("\r", "")
            with open(os.path.join(HERE, "ours.signtool.txt"), "w", encoding="ascii", newline="\n") as f:
                f.write(printed)
            print("make-fixtures: ours.signtool.txt is what signtool printed verifying ours.exe")
        else:
            print("make-fixtures: signtool is not here, so ours.signtool.txt was not made again and no "
                  "longer names the certificate in ours.exe; make the fixtures on Windows")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
