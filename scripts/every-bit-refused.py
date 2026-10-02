"""Change every bit of every committed receipt, one at a time, and require the verifier to refuse each.

Run by `scripts/every-bit-refused.sh`, which takes the network away first. This half does the
sweeping: it checks each receipt is accepted as it is, then writes each single-bit change to a file
of its own and runs `timewitness verify` on it, one process per change, and requires every one of
them to exit 1, which is the verifier's refusal. A change that exits 0 is a receipt that still
verifies after a bit of it moved, and any other exit is a verifier that fell over rather than
refusing, and both fail the run.

It refuses to start while it can still open a connection to a public address, so that it never
reports a sweep done with the network in reach as one done without it.

    python3 scripts/every-bit-refused.py <timewitness binary> <jobs>
"""

import os
import socket
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor

DATA = "crates/verify/tests/data"
V1_SUBJECT = f"{DATA}/a-version-1-stamp/subject.bin"

# Every committed receipt that verifies as it is, with what it stamps. A receipt the verifier
# already refuses whole would be refused under every change for the wrong reason, so it is not here,
# and the sweep checks each of these is accepted before it changes a bit of it.
RECEIPTS = [
    (f"{DATA}/a-real-stamp/receipt.cbor", f"{DATA}/a-real-stamp/subject.bin"),
    (f"{DATA}/a-backdated-receipt/receipt.hex", f"{DATA}/a-real-stamp/subject.bin"),
    (f"{DATA}/a-runner-receipt-2026-09-14/receipt.hex", None),
    (f"{DATA}/a-version-1-stamp/receipt.hex", V1_SUBJECT),
    (f"{DATA}/a-version-1-stamp-witnessed-again/sectigo.hex", V1_SUBJECT),
    (f"{DATA}/a-version-1-stamp-witnessed-again/digicert.hex", V1_SUBJECT),
]


def network_is_gone():
    try:
        with socket.create_connection(("1.1.1.1", 443), timeout=5):
            return False
    except OSError:
        return True


def read_receipt(path):
    with open(path, "rb") as f:
        raw = f.read()
    if path.endswith(".hex"):
        return bytes.fromhex("".join(raw.decode("ascii").split()))
    return raw


def verify(binary, path, subject):
    command = [binary, "verify", path]
    if subject:
        command += ["--subject", subject]
    return subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    ).returncode


def sweep(binary, receipt, subject, jobs, scratch):
    """Every single-bit change of `receipt`, as (byte, bit, exit code) for each that was not refused."""
    bits = len(receipt) * 8
    share = -(-bits // jobs)

    def worker(n):
        path = os.path.join(scratch, f"changed-{n}.cbor")
        changed = bytearray(receipt)
        wrong = []
        for index in range(n * share, min((n + 1) * share, bits)):
            at, bit = divmod(index, 8)
            changed[at] ^= 1 << bit
            with open(path, "wb") as f:
                f.write(changed)
            code = verify(binary, path, subject)
            if code != 1:
                wrong.append((at, bit, code))
            changed[at] ^= 1 << bit
        return wrong

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        found = [w for part in pool.map(worker, range(jobs)) for w in part]
    return bits, sorted(found)


def main():
    binary, jobs = os.path.abspath(sys.argv[1]), max(1, int(sys.argv[2]))
    if not network_is_gone():
        print("every bit: a connection to 1.1.1.1:443 opened, so this would prove nothing")
        return 97

    failed = False
    total = 0
    with tempfile.TemporaryDirectory() as scratch:
        for path, subject in RECEIPTS:
            receipt = read_receipt(path)
            whole = os.path.join(scratch, "whole.cbor")
            with open(whole, "wb") as f:
                f.write(receipt)
            code = verify(binary, whole, subject)
            if code != 0:
                print(f"every bit: {path} exits {code} as it is, so a sweep of it shows nothing")
                failed = True
                continue
            bits, wrong = sweep(binary, receipt, subject, jobs, scratch)
            total += bits
            through = [w for w in wrong if w[2] == 0]
            fell = [w for w in wrong if w[2] != 0]
            if wrong:
                failed = True
                print(
                    f"every bit: {path}: {len(through)} of {bits} changes still verify and "
                    f"{len(fell)} exit neither 0 nor 1; first few as (byte, bit, exit): {wrong[:8]}"
                )
            else:
                print(f"every bit: {path}: all {bits} single-bit changes refused, exit 1 each")

    if failed:
        return 1
    print(
        f"every bit: {total} single-bit changes across {len(RECEIPTS)} receipts, every one refused "
        "with no network"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
