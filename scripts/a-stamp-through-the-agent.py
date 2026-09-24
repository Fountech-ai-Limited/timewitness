#!/usr/bin/env python3
"""A stamp through the agent verifies, a stopped agent refuses, and a second agent leaves the first
alone.

Three things are said about the resident agent and this checks all three against the real binary, one
after another on one agent of its own:

1. `stamp --agent` writes a receipt, and `verify` passes it and says the reading came from a resident
   agent.
2. A second `agent` started on the same endpoint file refuses in a plain sentence, leaves the file as
   it was, and the first is still the one `status` reaches. Until 2026-09-24 the second one took the
   file over and the first ran on with nothing left to find it by (RC-349).
3. With the agent stopped, `stamp --agent` exits non-zero and writes no receipt.

    python scripts/a-stamp-through-the-agent.py

is the check. It needs the servers the agent ships against to answer, because a stamp needs a bound,
and a fresh agent refuses most readings in its first two minutes, so it asks until one is signed or
four times the stated first-bound time has gone. Every agent it starts gets an endpoint file of its
own in a fresh folder and is stopped by the handle it was started under, so no other agent on the
machine is touched.

    python scripts/a-stamp-through-the-agent.py --self-test

reads canned answers of every kind and checks each is sorted the way a real one would be.
"""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATUS_SOURCE = ROOT / 'crates' / 'cli' / 'src' / 'status_cmd.rs'

# No console window for anything this starts. The run is headless on every platform.
NO_WINDOW = 0x08000000 if os.name == 'nt' else 0

# What a type prints of itself, which a person should never be shown in place of a sentence.
TYPE_NAMES = re.compile(r'\b[A-Z][A-Za-z]+ ?[({]|WireError|CrossingError')


def stated_first_bound():
    found = re.search(r'pub const FIRST_BOUND_WITHIN: u64 = (\d+);',
                      STATUS_SOURCE.read_text(encoding='utf-8'))
    if not found:
        sys.exit(f'a stamp through the agent: {STATUS_SOURCE} does not state FIRST_BOUND_WITHIN')
    return int(found.group(1))


def verified_from_the_agent(code, text):
    """Whether `verify` passed the receipt and said its reading came from a resident agent."""
    return code == 0 and 'read from a resident agent' in ' '.join(text.split())


def refused_plainly(code, text):
    """Whether a second agent refused to start, in words, and pointed at the way out."""
    return (code not in (0, None) and 'already answering' in text and 'has not started' in text
            and '--endpoint' in text and not TYPE_NAMES.search(text))


def reached(text, address):
    """Whether `status` reached an agent, and the one at `address`."""
    return 'is up' in text and address in text


def run(binary, *args, timeout=120):
    try:
        done = subprocess.run([binary, *args], capture_output=True, text=True, encoding='utf-8',
                              errors='replace', timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return None, f'{args[0]} was still running after {timeout} s and was stopped'
    return done.returncode, done.stdout + done.stderr


def start_agent(binary, endpoint, log_path):
    log = open(log_path, 'w+', encoding='utf-8', errors='replace')
    child = subprocess.Popen([binary, 'agent', '--endpoint', str(endpoint)], stdout=log,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             creationflags=NO_WINDOW)
    return child, log


def stop(child):
    # By the handle it was started under and nothing else.
    if child is not None and child.poll() is None:
        child.kill()
        child.wait()


def address_in(endpoint):
    lines = endpoint.read_text(encoding='utf-8').splitlines()
    return lines[0].strip() if lines else ''


def check(binary, give_up):
    scratch = pathlib.Path(tempfile.mkdtemp(prefix='tw-a10-'))
    endpoint = scratch / 'agent.endpoint'
    subject = scratch / 'subject.txt'
    subject.write_text('a stamp through the agent\n', encoding='utf-8')
    key = scratch / 'agent.key'
    held = []
    first = second = None
    logs = []
    try:
        first, log = start_agent(binary, endpoint, scratch / 'first.log')
        logs.append(log)
        began = time.monotonic()

        # 1. A receipt through the agent, and it verifies.
        receipt = scratch / 'receipt.cbor'
        stamped = None
        tries = 0
        while time.monotonic() - began < give_up:
            if first.poll() is not None:
                break
            if endpoint.exists():
                tries += 1
                code, text = run(binary, 'stamp', '--agent', str(endpoint), '--subject', str(subject),
                                 '--key', str(key), '--out', str(receipt))
                if code == 0 and receipt.exists():
                    stamped = time.monotonic() - began
                    break
                if receipt.exists():
                    held.append(f'a refused stamp left a receipt behind: {text.strip()}')
                    break
            time.sleep(2)
        if stamped is None and first.poll() is not None:
            held.append(f'the agent stopped by itself with exit {first.returncode}; its output is in '
                        f'{scratch / "first.log"}')
        elif stamped is None:
            held.append(f'no stamp through the agent was signed in {give_up} s over {tries} tries')
        else:
            code, text = run(binary, 'verify', str(receipt), '--subject', str(subject))
            if verified_from_the_agent(code, text):
                print(f'  1. stamped through the agent at {stamped:.1f} s of uptime on try {tries}, '
                      f'and verify passed it as read from a resident agent')
            else:
                held.append(f'verify did not pass the receipt as read from a resident agent '
                            f'(exit {code}): {text.strip()}')

        # 2. A second agent on the same file refuses, and the first is still the one reached.
        if endpoint.exists() and first.poll() is None:
            before = endpoint.read_bytes()
            first_address = address_in(endpoint)
            second, log = start_agent(binary, endpoint, scratch / 'second.log')
            logs.append(log)
            ran_on = False
            try:
                second.wait(timeout=30)
            except subprocess.TimeoutExpired:
                ran_on = True
                held.append(f'a second agent on a live endpoint was still running after 30 s, and the '
                            f'file now names {address_in(endpoint)} where the first is at '
                            f'{first_address}')
                stop(second)
            log.seek(0)
            said = log.read()
            code, status_text = run(binary, 'status', '--agent', str(endpoint))
            if ran_on:
                pass
            elif not refused_plainly(second.returncode, said) and second.returncode != 0:
                held.append(f'a second agent stopped without saying why in words: {said.strip()}')
            elif second.returncode == 0:
                held.append('a second agent on a live endpoint exited 0')
            elif endpoint.read_bytes() != before:
                held.append('a second agent refused and still changed the endpoint file')
            elif not reached(status_text, first_address):
                held.append(f'after the second agent, status did not reach the first at '
                            f'{first_address}: {status_text.strip()}')
            elif refused_plainly(second.returncode, said):
                print(f'  2. a second agent on the same endpoint exited {second.returncode} and said: '
                      f'{" ".join(said.split())}')
                print(f'     the file is unchanged and status still reaches the first at '
                      f'{first_address}')
        else:
            held.append('the first agent was not up to test a second one against')

        # 3. With the agent stopped, a stamp through it refuses and writes nothing.
        stop(first)
        after = scratch / 'after.cbor'
        code, text = run(binary, 'stamp', '--agent', str(endpoint), '--subject', str(subject),
                         '--key', str(key), '--out', str(after))
        if code in (0, None) or after.exists():
            held.append(f'with the agent stopped, stamp --agent exited {code} and '
                        f'{"wrote" if after.exists() else "did not write"} a receipt')
        else:
            print(f'  3. with the agent stopped, stamp --agent exited {code}, wrote no receipt, and '
                  f'said: {" ".join(text.split())}')
    finally:
        stop(second)
        stop(first)
        for log in logs:
            log.close()

    if held:
        for line in held:
            print(f'a stamp through the agent: {line}', file=sys.stderr)
        print(f'a stamp through the agent: the agents\' output is kept in {scratch}', file=sys.stderr)
        return 1
    shutil.rmtree(scratch, ignore_errors=True)
    print('a stamp through the agent: all three hold')
    return 0


def self_test():
    bad = 0
    verify_cases = [
        (0, 'VERIFIED\n  The reading was read from a resident agent on the signing machine, so it '
            'rests\n  on that agent', True),
        (0, 'VERIFIED\n  The reading was taken by the process that signed it', False),
        (1, 'REFUSED\n  The reading was read from a resident agent', False),
    ]
    for code, text, want in verify_cases:
        if verified_from_the_agent(code, text) != want:
            print(f'a stamp through the agent: verify {text[:50]!r} read as {not want}', file=sys.stderr)
            bad += 1
    refusal = ('timewitness: an agent is already answering on ep, at 127.0.0.1:5, so this one has not '
               'started. A second agent there would take the file over and leave the first running '
               'with nothing to find it by. Stop the first one, or give this one a file of its own '
               'with --endpoint. If no agent of yours is running, something else has taken that '
               'address, and deleting ep lets this one start')
    refusal_cases = [
        (1, refusal, True),
        (0, refusal, False),
        (None, refusal, False),
        # The same refusal with a type's own name in it is not a sentence a person should read.
        (1, refusal + ': Refused("x")', False),
        (1, refusal.replace('already answering', 'answering'), False),
        # What a second agent printed until 2026-09-24: it started.
        (1, 'Agent running. Listening on 127.0.0.1:5', False),
    ]
    for code, text, want in refusal_cases:
        if refused_plainly(code, text) != want:
            print(f'a stamp through the agent: refusal {text[-40:]!r} at {code} read as {not want}',
                  file=sys.stderr)
            bad += 1
    reach_cases = [
        ('The agent at 127.0.0.1:5 is up, and would not sign a stamp right now.', '127.0.0.1:5', True),
        ('The agent at 127.0.0.1:6 is up and answering.', '127.0.0.1:5', False),
        ('timewitness: the agent is not answering: no agent answered at 127.0.0.1:5', '127.0.0.1:5',
         False),
    ]
    for text, address, want in reach_cases:
        if reached(text, address) != want:
            print(f'a stamp through the agent: status {text[:50]!r} read as {not want}', file=sys.stderr)
            bad += 1
    stated_first_bound()
    total = len(verify_cases) + len(refusal_cases) + len(reach_cases)
    print(f'a stamp through the agent: self-test, {total} answers read, {bad} wrong')
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--binary', help='the timewitness binary, the release build by default')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    binary = pathlib.Path(args.binary) if args.binary else ROOT / 'target' / 'release' / (
        'timewitness.exe' if os.name == 'nt' else 'timewitness')
    if not binary.exists():
        sys.exit(f'a stamp through the agent: there is no binary at {binary}. Build one with '
                 f'`cargo build --release -p timewitness-cli`')
    give_up = 4 * stated_first_bound()
    print(f'a stamp through the agent: {binary}, asking for a signed stamp for up to {give_up} s')
    return check(str(binary), give_up)


if __name__ == '__main__':
    sys.exit(main())
