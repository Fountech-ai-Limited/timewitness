#!/usr/bin/env python3
"""Start the agent from cold, again and again, and time how soon `status` says how wrong the clock
could be.

A person who has just started an agent asks it one thing, and the README states how soon it answers.
That is a stated time, and a stated time nobody measures is a guess written as a fact. So this starts
a fresh agent, asks `timewitness status` every half second until it prints the width and the plain
sentence that goes with it, stops the agent by the number it was started under, and does that as many
times as it is told. It fails if any start took longer than the time the code states, and it fails if
the README states a different time from the code, so the two cannot drift apart without a red run.

    python scripts/status-from-cold.py --starts 10

is the check. With `--watch 300` each agent is kept up for five minutes and asked the whole time,
which is how the second stated time, after which a refusal is occasional rather than usual, was
measured.
That run takes the best part of an hour for ten starts and is run by hand; the check without it takes
a couple of minutes and runs every morning beside the other tests that need real servers.

    python scripts/status-from-cold.py --self-test

reads canned answers of every kind and checks each is sorted the way a real one would be.

It needs the servers the agent ships against to answer. A machine that cannot reach them gets no
bound and this fails, which is the right answer: the stated time is a claim about a machine that can.
"""

import argparse
import datetime
import json
import os
import pathlib
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATUS_SOURCE = ROOT / 'crates' / 'cli' / 'src' / 'status_cmd.rs'
README = ROOT / 'README.md'

# The sentence a status prints when it knows the width, whether or not a stamp would be signed at it.
PLAIN = re.compile(r'Right now the time it gives could be wrong by (?:as much as (\S+ \S+)|more than an hour)\.')
# The width line a signed answer carries beside the sentence.
WIDTH_LINE = re.compile(r'bound now\s+(\S+ \S+) wide')

# No console window for anything this starts. The run is headless on every platform.
NO_WINDOW = 0x08000000 if os.name == 'nt' else 0


def stated(name):
    """A stated time in seconds, read off the code that prints it."""
    found = re.search(rf'pub const {name}: u64 = (\d+);', STATUS_SOURCE.read_text(encoding='utf-8'))
    if not found:
        sys.exit(f'status from cold: {STATUS_SOURCE} does not state {name}')
    return int(found.group(1))


def readme_states(first_bound):
    """Whether the README states the same first-bound time as the code, and what it states."""
    text = ' '.join(README.read_text(encoding='utf-8').split())
    found = re.search(r'within (\d+) seconds of a fresh agent starting', text)
    return (found is not None and int(found.group(1)) == first_bound,
            found.group(1) if found else None)


def classify(code, text):
    """What one answer from `status` was.

    `signed` is an answer a stamp would have been given, `past` is a width the agent would not sign
    at, `none` is an agent up with no bound to give, and `down` is no agent answering at all. A width
    counts only where the plain sentence is there too, because the sentence is what is being timed.
    """
    sentence = PLAIN.search(text)
    if code == 0 and sentence and WIDTH_LINE.search(text):
        return 'signed', sentence.group(1) or 'more than an hour'
    if code == 1 and sentence:
        return 'past', sentence.group(1) or 'more than an hour'
    if 'is up' in text:
        return 'none', None
    return 'down', None


def one_start(binary, number, watch, every, give_up):
    """Start one agent, ask it until it answers with a width, and stop it."""
    scratch = tempfile.mkdtemp(prefix='tw-cold-')
    endpoint = os.path.join(scratch, 'agent.endpoint')
    log = open(os.path.join(scratch, 'agent.log'), 'w+', encoding='utf-8')
    began = time.monotonic()
    agent = subprocess.Popen([binary, 'agent', '--endpoint', endpoint], stdout=log,
                             stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
    answers = []
    first_width = None
    try:
        horizon = max(watch, give_up)
        while True:
            at = time.monotonic() - began
            if at > horizon or (first_width is not None and at > watch):
                break
            if os.path.exists(endpoint):
                ran = subprocess.run([binary, 'status', '--agent', endpoint], capture_output=True,
                                     text=True, creationflags=NO_WINDOW, timeout=30)
                at = time.monotonic() - began
                kind, width = classify(ran.returncode, ran.stdout + ran.stderr)
                answers.append({'at': round(at, 2), 'kind': kind, 'width': width})
                if first_width is None and kind in ('signed', 'past'):
                    first_width = answers[-1]
                    print(f'  start {number}: width and sentence at {at:.1f} s, {kind}, {width}',
                          flush=True)
            time.sleep(every)
    finally:
        # By the number it was started under and nothing else, so no other agent on this machine is
        # touched.
        agent.kill()
        agent.wait()
        log.seek(0)
        banner = log.read()
        log.close()

    widths = [a for a in answers if a['kind'] in ('signed', 'past')]
    refused = [a for a in answers if a['kind'] != 'signed']
    signed = [a for a in answers if a['kind'] == 'signed']
    return {
        'start': number,
        'first_width_at': first_width['at'] if first_width else None,
        'first_width_kind': first_width['kind'] if first_width else None,
        'first_width': first_width['width'] if first_width else None,
        'first_signed_at': signed[0]['at'] if signed else None,
        'last_refused_at': refused[-1]['at'] if refused and watch else None,
        'asked': len(answers),
        'refused': len(refused),
        'with_width': len(widths),
        'banner': banner.splitlines()[:6],
        'answers': answers,
    }


def conditions(binary):
    """What a reader needs to reproduce the run, written before the first start."""
    try:
        head = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', '--short', 'HEAD'],
                              capture_output=True, text=True).stdout.strip()
    except OSError:
        head = 'unknown'
    return {
        'date_utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'host': socket.gethostname(),
        'platform': platform.platform(),
        'cpus': os.cpu_count(),
        'binary': str(binary),
        'commit': head,
    }


def self_test():
    cases = [
        (0, 'The agent at 127.0.0.1:1 is up and answering.\n\nRight now the time it gives could be '
            'wrong by as much as 84.011 ms. A stamp taken now would carry that bound.\n\n'
            '  bound now     84.011 ms wide, on 9 of 9 sources', ('signed', '84.011 ms')),
        (1, 'The agent at 127.0.0.1:1 is up, and would not sign a stamp right now.\n\nRight now the '
            'time it gives could be wrong by as much as 3.868 s. That is past the 250.000 ms it will '
            'sign for', ('past', '3.868 s')),
        (1, 'The agent at 127.0.0.1:1 is up, and would not sign a stamp right now.\n\nRight now the '
            'time it gives could be wrong by more than an hour.', ('past', 'more than an hour')),
        (1, 'timewitness: the agent at 127.0.0.1:1 is up and would not give a reading a stamp could '
            'use: the clock has not synchronised yet', ('none', None)),
        (1, 'timewitness: the agent is not answering: no agent answered', ('down', None)),
        # A signed answer with the sentence missing is not a width and a sentence.
        (0, 'The agent at 127.0.0.1:1 is up and answering.\n\n  bound now     84.011 ms wide',
         ('none', None)),
        # The old refusal carried a width in its reason and no sentence, and does not count.
        (1, 'timewitness: the agent at 127.0.0.1:1 is up and would not give a reading a stamp could '
            'use: the bound has grown to 1203.6 ms, past the 250 ms ceiling', ('none', None)),
    ]
    bad = 0
    for code, text, want in cases:
        got = classify(code, text)
        if got != want:
            print(f'status from cold: {text[:70]!r} read as {got}, not {want}', file=sys.stderr)
            bad += 1
    first = stated('FIRST_BOUND_WITHIN')
    agrees, readme = readme_states(first)
    if not agrees:
        print(f'status from cold: the code states {first} s and the README states {readme}',
              file=sys.stderr)
        bad += 1
    print(f'status from cold: self-test, {len(cases)} answers read, {bad} wrong')
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--binary', help='the timewitness binary, the release build by default')
    parser.add_argument('--starts', type=int, default=10)
    parser.add_argument('--watch', type=float, default=0,
                        help='keep each agent up this many seconds and keep asking')
    parser.add_argument('--every', type=float, default=0.5, help='seconds between asks')
    parser.add_argument('--json', help='write every answer here')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    binary = pathlib.Path(args.binary) if args.binary else ROOT / 'target' / 'release' / (
        'timewitness.exe' if os.name == 'nt' else 'timewitness')
    if not binary.exists():
        sys.exit(f'status from cold: there is no binary at {binary}. Build one with '
                 f'`cargo build --release -p timewitness-cli`')

    first_bound = stated('FIRST_BOUND_WITHIN')
    settles = stated('SETTLES_WITHIN')
    agrees, readme = readme_states(first_bound)

    where = conditions(binary)
    print(f'status from cold: {args.starts} starts, asking every {args.every} s, '
          f'{"watching each for " + str(int(args.watch)) + " s" if args.watch else "until the first width"}')
    print(f'  on {where["host"]}, {where["platform"]}, {where["cpus"]} CPUs, at {where["date_utc"]} UTC, '
          f'commit {where["commit"]}')
    print(f'  stated: a width and a plain sentence within {first_bound} s of starting')

    # Give up on a start at four times the stated time, so a start that never gets a width is
    # reported as a figure rather than a hang.
    give_up = 4 * first_bound
    runs = []
    for number in range(1, args.starts + 1):
        runs.append(one_start(str(binary), number, args.watch, args.every, give_up))
        time.sleep(2)

    print()
    print('  start  first width at  kind    width        first signed at  last refused at  refused/asked')
    for r in runs:
        fw = f'{r["first_width_at"]:.1f} s' if r['first_width_at'] is not None else 'never'
        fs = f'{r["first_signed_at"]:.1f} s' if r['first_signed_at'] is not None else 'never'
        lr = f'{r["last_refused_at"]:.1f} s' if r['last_refused_at'] is not None else '-'
        print(f'  {r["start"]:>5}  {fw:>14}  {str(r["first_width_kind"]):<6}  '
              f'{str(r["first_width"]):<11}  {fs:>15}  {lr:>15}  {r["refused"]}/{r["asked"]}')

    times = [r['first_width_at'] for r in runs]
    late = [r for r in runs if r['first_width_at'] is None or r['first_width_at'] > first_bound]
    got = [t for t in times if t is not None]
    print()
    if got:
        print(f'status from cold: first width and sentence at {min(got):.1f} s to {max(got):.1f} s '
              f'over {len(got)} of {len(runs)} starts, against a stated {first_bound} s')
    if args.watch:
        last = [r['last_refused_at'] for r in runs if r['last_refused_at'] is not None]
        if last:
            print(f'status from cold: last refusal in the first {int(args.watch)} s at '
                  f'{min(last):.1f} s to {max(last):.1f} s')
        # The share refused in the first two minutes and from the settling time on, which is what the
        # README and the status sentence say about settling. There is no time after which a refusal
        # stops, so a last refusal is not the figure to state.
        for low, high in ((0, 120), (settles, args.watch)):
            asked = [a for r in runs for a in r['answers'] if low <= a['at'] < high]
            refused = [a for a in asked if a['kind'] != 'signed']
            if asked:
                print(f'status from cold: {len(refused)} of {len(asked)} answers refused from '
                      f'{low:.0f} s to {high:.0f} s of uptime')

    if args.json:
        pathlib.Path(args.json).write_text(json.dumps({'conditions': where, 'runs': runs}, indent=1),
                                           encoding='utf-8')

    failed = False
    if late:
        print(f'status from cold: {len(late)} of {len(runs)} starts took longer than the stated '
              f'{first_bound} s or never gave a width', file=sys.stderr)
        failed = True
    if not agrees:
        print(f'status from cold: the code states {first_bound} s and the README states {readme}',
              file=sys.stderr)
        failed = True
    print('status from cold: ' + ('FAIL' if failed else 'PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
