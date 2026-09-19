#!/usr/bin/env python3
"""Run the agent beside Japan's national time source and record whether the two agree.

NICT's public NTP service at `ntp.nict.jp` is a comparison here and never a source. Nothing it says
enters the model, the selection or a receipt. It is asked over a plain socket in this file, by code
the product does not link, so there is no route by which it could become one by accident.

## What a pair is

Two readings taken seconds apart on one machine, and both are turned into the same quantity before
they are compared: how wrong this machine's own clock is.

The agent gives an interval of UTC for the instant it read, so subtracting the local clock at that
instant gives the interval it puts the local clock's error in. The NTP exchange gives the classic
four timestamps, so it gives an estimate of the same error and a half width of half the round trip.
Both are errors of the same clock, so the seconds between the two readings cancel out of the
comparison and only this machine's drift over those seconds is left, which is under a tenth of a
millisecond at a hundred parts per million. Every row carries the gap it was taken over, so a reader
can do that arithmetic rather than take it on trust.

A pair counts as agreeing when NICT's estimate sits inside the agent's interval. Each reading also
carries whether the two intervals overlap at all, which is the weaker test and the one that is fair
to NICT, because NICT's own answer has a width and the strict test ignores it.

## Running it

    python scripts/nict-compare.py --out DIR --binary PATH --days 3

It starts its own resident agent, restarts it if it dies, and writes one row every `--every` seconds
until the days are up. A second copy started against the same output directory finds the lock and
exits, so a boot trigger cannot double the load on anybody's servers.

Point `--binary` at a copy rather than at `target/release`. A capture holds its binary open for days
and cargo cannot replace a running exe, so a capture started out of the build tree stops every build
in this repository until it finishes. That happened once, on 2026-09-19, twenty minutes in.

    python scripts/nict-compare.py --summarise DIR

reads what is on disk and prints one sentence a reader can reproduce.
"""

import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import sys
import time

# Seconds between the NTP epoch of 1900 and the Unix epoch of 1970.
NTP_TO_UNIX = 2_208_988_800
NS = 1_000_000_000


def now_ns():
    """This machine's wall clock, in nanoseconds since the Unix epoch.

    On Windows this is GetSystemTimePreciseAsFileTime, so it is the same clock the agent reads and
    it is not the fifteen millisecond tick a reader might expect.
    """
    return time.time_ns()


def ntp_to_ns(raw):
    """One NTP 64-bit timestamp as nanoseconds since the Unix epoch."""
    seconds, fraction = struct.unpack('>II', raw)
    return (seconds - NTP_TO_UNIX) * NS + (fraction * NS) // (1 << 32)


def ns_to_ntp(value):
    """The other direction, for the transmit timestamp this sends and checks on the way back."""
    seconds, rest = divmod(value, NS)
    return struct.pack('>II', seconds + NTP_TO_UNIX, (rest * (1 << 32)) // NS)


def ask_ntp(host, timeout):
    """One SNTP exchange, as the four timestamps and what the server said about itself.

    The transmit timestamp goes out and is checked against the origin timestamp that comes back, so
    a reply that is not an answer to this question is refused rather than recorded as a reading.
    """
    packet = bytearray(48)
    packet[0] = 0x23  # No leap warning, version 4, client mode.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t1 = now_ns()
        packet[40:48] = ns_to_ntp(t1)
        sock.sendto(bytes(packet), (host, 123))
        reply, _ = sock.recvfrom(96)
        t4 = now_ns()
    finally:
        sock.close()

    if len(reply) < 48:
        raise ValueError('the reply was %d bytes and an NTP reply is at least 48' % len(reply))
    if reply[24:32] != packet[40:48]:
        raise ValueError('the origin timestamp in the reply is not the one that was sent')

    leap = reply[0] >> 6
    stratum = reply[1]
    if stratum == 0:
        raise ValueError('stratum 0, which is a kiss of death rather than a time')

    return {
        't1': t1,
        't2': ntp_to_ns(reply[32:40]),
        't3': ntp_to_ns(reply[40:48]),
        't4': t4,
        'leap': leap,
        'stratum': stratum,
        'poll': reply[2],
        'precision': struct.unpack('>b', reply[3:4])[0],
        'root_delay_ns': (struct.unpack('>I', reply[4:8])[0] * NS) >> 16,
        'root_dispersion_ns': (struct.unpack('>I', reply[8:12])[0] * NS) >> 16,
        'refid': reply[12:16].decode('ascii', 'replace').strip('\x00'),
    }


def what_the_agent_said(binary, workdir, endpoint):
    """One stamp from the resident agent, bracketed by the local clock.

    The bracket is the whole point. The receipt says what UTC was when the agent read, and it does
    not say what this machine's own clock said at that moment, so the clock is read either side and
    the midpoint is used. The width of the bracket is carried on each reading as the pairing
    uncertainty, because a pair is only as good as the instant it can be pinned to.
    """
    receipt = workdir / 'pair.cbor'
    receipt.unlink(missing_ok=True)

    before = now_ns()
    stamped = subprocess.run(
        [binary, 'stamp', '--subject', str(workdir / 'subject.txt'),
         '--key', str(workdir / 'pair.key'), '--out', str(receipt),
         '--agent', str(endpoint), '--no-evidence'],
        capture_output=True, text=True, cwd=workdir)
    after = now_ns()

    middle, half = (before + after) // 2, (after - before) // 2
    bracket = {'local_before_ns': before, 'local_after_ns': after}
    if stamped.returncode != 0:
        return None, middle, half, bracket, stamped.stdout + stamped.stderr

    read = subprocess.run([binary, 'verify', str(receipt), '--json', '--no-anchors'],
                          capture_output=True, text=True, cwd=workdir)
    if not read.stdout.strip():
        return None, middle, half, bracket, read.stdout + read.stderr

    claim = json.loads(read.stdout)['claim']
    return claim, middle, half, bracket, ''


def one_pair(binary, workdir, endpoint, host, timeout):
    """The agent and NICT, close together, as one row."""
    claim, local_at_read, pair_half_ns, bracket, trouble = what_the_agent_said(
        binary, workdir, endpoint)
    row = {'at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'local_at_read_ns': local_at_read,
           'pair_half_ns': pair_half_ns}
    # Both ends of the bracket, not only its middle. The instant the agent read is somewhere inside
    # the process's life and the midpoint is a guess at where; a reader given both ends can bound
    # the error exactly, or pick a different anchor, without re-taking three days of readings.
    row.update(bracket)

    if claim is None:
        row['agent'] = 'refused'
        row['why'] = ' '.join(trouble.split())[:400]
    else:
        row['agent'] = 'signed'
        row['width_ns'] = claim['width_ns']
        row['sources_kept'] = claim['sources_kept']
        row['operators_kept'] = claim['operators_kept']
        # The agent's interval, as an interval for this machine's own clock error.
        row['agent_error_lo_ns'] = claim['earliest_ns'] - local_at_read
        row['agent_error_hi_ns'] = claim['latest_ns'] - local_at_read
        row['agent_error_mid_ns'] = claim['reading_ns'] - local_at_read

    try:
        seen = ask_ntp(host, timeout)
    except (OSError, ValueError, struct.error) as trouble:
        row['nict'] = 'no answer'
        row['why_nict'] = str(trouble)[:200]
        return row

    offset = ((seen['t2'] - seen['t1']) + (seen['t3'] - seen['t4'])) // 2
    delay = (seen['t4'] - seen['t1']) - (seen['t3'] - seen['t2'])
    row.update({
        'nict': 'answered',
        'nict_error_ns': offset,
        'nict_half_ns': delay // 2,
        'nict_delay_ns': delay,
        'nict_stratum': seen['stratum'],
        'nict_leap': seen['leap'],
        'nict_refid': seen['refid'],
        'nict_root_delay_ns': seen['root_delay_ns'],
        'nict_root_dispersion_ns': seen['root_dispersion_ns'],
        'gap_ns': seen['t4'] - local_at_read,
    })

    if claim is not None:
        lo, hi = row['agent_error_lo_ns'], row['agent_error_hi_ns']
        row['inside'] = lo <= offset <= hi
        row['miss_ns'] = 0 if row['inside'] else min(abs(offset - lo), abs(offset - hi))
        row['overlaps'] = (offset + delay // 2) >= lo and (offset - delay // 2) <= hi
    return row


COLUMNS = ['at', 'agent', 'nict', 'inside', 'miss_ns', 'width_ns', 'agent_error_lo_ns',
           'agent_error_hi_ns', 'nict_error_ns', 'nict_half_ns', 'pair_half_ns', 'gap_ns',
           'sources_kept', 'operators_kept', 'nict_stratum', 'overlaps']


def alive(pid):
    """Whether a pid is a process on this machine. Windows has no kill(0), so ask the task list."""
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    seen = subprocess.run(['tasklist', '/FI', 'PID eq %d' % pid], capture_output=True, text=True)
    return str(pid) in seen.stdout


def lock(where):
    """One capture per output directory, so a boot trigger cannot double the load on NICT."""
    held = where / 'capture.pid'
    if held.exists():
        try:
            was = int(held.read_text().strip())
        except ValueError:
            was = None
        if was is not None and alive(was):
            print('a capture is already running as pid %d, so this one is not starting' % was)
            return False
    held.write_text(str(os.getpid()))
    return True


def ends(args):
    """When this capture stops, as a Unix time.

    `--until` wins where it is given, because a capture that is restarted after a reboot has to
    finish when it was always going to finish. `--days` is the convenience for starting one by hand.
    """
    if args.until:
        return time.mktime(time.strptime(args.until, '%Y-%m-%dT%H:%M:%S'))
    return time.time() + args.days * 86400


def start_agent(binary, workdir, endpoint, log):
    """The resident agent at its shipped cadence, with nothing passed that changes it."""
    endpoint.unlink(missing_ok=True)
    handle = open(log, 'a', encoding='utf-8')
    return subprocess.Popen([binary, 'agent', '--endpoint', str(endpoint)],
                            stdout=handle, stderr=subprocess.STDOUT, cwd=workdir)


def put_the_task_away(name):
    """Remove the logon task that restarts a capture, once there is nothing left to restart.

    A capture that runs over days wants to survive a reboot, and the way to do that on Windows is a
    task that fires at logon. A task nobody removes outlives the capture and starts things on a
    machine long after anybody remembers why, so the capture removes its own.
    """
    if not name or os.name != 'nt':
        return
    subprocess.run(['schtasks', '/Delete', '/TN', name, '/F'], capture_output=True, text=True)


def capture(args):
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if not lock(out):
        return 0

    if time.time() >= ends(args):
        print('this capture ended at %s, so nothing is being started' % args.until)
        (out / 'capture.pid').unlink(missing_ok=True)
        put_the_task_away(args.task_name)
        return 0

    binary = str(pathlib.Path(args.binary).resolve())
    endpoint = out / 'endpoint.txt'
    (out / 'subject.txt').write_text('the thing being stamped beside NICT\n')
    if not (out / 'pair.key').exists():
        (out / 'pair.key').write_bytes(os.urandom(32))

    rows = out / 'pairs.jsonl'
    table = out / 'pairs.tsv'
    if not table.exists():
        table.write_text('\t'.join(COLUMNS) + '\n', encoding='utf-8')

    run_log = open(out / 'run.log', 'a', encoding='utf-8', buffering=1)

    def say(line):
        run_log.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), line))

    say('capture started, pid %d, binary %s, server %s, every %ss for %s days'
        % (os.getpid(), binary, args.server, args.every, args.days))

    agent = start_agent(binary, out, endpoint, out / 'agent.log')
    say('agent started as pid %d' % agent.pid)
    # The agent refuses until it has enough rounds behind it. Waiting here keeps that out of the
    # first rows rather than recording it as disagreement.
    time.sleep(args.settle)

    # An end written as a moment rather than a length, so a capture that is restarted after a reboot
    # finishes when it was always going to finish instead of starting the three days again.
    ends_at = ends(args)
    say('this capture ends at %s' % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ends_at)))
    while time.time() < ends_at:
        slot = time.time()
        if agent.poll() is not None:
            say('the agent exited with %s, starting another' % agent.returncode)
            agent = start_agent(binary, out, endpoint, out / 'agent.log')
            say('agent started as pid %d' % agent.pid)
            time.sleep(args.settle)

        try:
            row = one_pair(binary, out, endpoint, args.server, args.timeout)
        except Exception as trouble:  # A three day run does not stop for one bad row.
            say('a pair could not be taken: %r' % (trouble,))
            time.sleep(args.every)
            continue

        with open(rows, 'a', encoding='utf-8') as handle:
            handle.write(json.dumps(row) + '\n')
        with open(table, 'a', encoding='utf-8') as handle:
            handle.write('\t'.join(str(row.get(name, '')) for name in COLUMNS) + '\n')

        rest = args.every - (time.time() - slot)
        if rest > 0:
            time.sleep(rest)

    say('the days are up, stopping the agent')
    agent.terminate()
    try:
        agent.wait(timeout=20)
    except subprocess.TimeoutExpired:
        agent.kill()
    (out / 'capture.pid').unlink(missing_ok=True)
    put_the_task_away(args.task_name)
    say('capture finished')
    return 0


def ms(value):
    return '%.3f ms' % (value / 1_000_000)


def summarise(where):
    """What is on disk, as one sentence a reader can reproduce."""
    out = pathlib.Path(where).resolve()
    rows = [json.loads(line)
            for line in (out / 'pairs.jsonl').read_text(encoding='utf-8').splitlines()
            if line.strip()]
    if not rows:
        print('nothing has been captured yet')
        return 1

    paired = [row for row in rows if row.get('agent') == 'signed' and row.get('nict') == 'answered']
    inside = [row for row in paired if row.get('inside')]
    missed = [row for row in paired if not row.get('inside')]
    overlapped = [row for row in paired if row.get('overlaps')]
    refused = [row for row in rows if row.get('agent') == 'refused']
    silent = [row for row in rows if row.get('nict') != 'answered']

    print('From %s to %s, %d attempts, of which %d are pairs where the agent signed and NICT '
          'answered.' % (rows[0]['at'], rows[-1]['at'], len(rows), len(paired)))
    print('%d of %d put NICT inside the agent\'s bound. %d of %d overlap NICT\'s own interval.'
          % (len(inside), len(paired), len(overlapped), len(paired)))
    print('The agent refused %d times and NICT did not answer %d times.'
          % (len(refused), len(silent)))
    if paired:
        widths = sorted(row['width_ns'] for row in paired)
        print('Bound width: narrowest %s, median %s, widest %s.'
              % (ms(widths[0]), ms(widths[len(widths) // 2]), ms(widths[-1])))
        halves = sorted(row['pair_half_ns'] for row in paired)
        print('Pairing uncertainty, half the bracket the stamp was taken in: median %s, worst %s.'
              % (ms(halves[len(halves) // 2]), ms(halves[-1])))
        # The pairs where the bracket is small against the bound, which is where the comparison is
        # about the two clocks rather than about how busy this machine was. A bracket as wide as the
        # bound cannot answer the question either way, and reporting those beside the rest without
        # saying so would be reporting the machine's load as disagreement.
        tight = [row for row in paired if row['pair_half_ns'] * 5 <= row['width_ns']]
        if tight:
            print('On the %d pairs whose bracket is under a fifth of the bound: %d inside, %d '
                  'overlapping.'
                  % (len(tight), sum(1 for r in tight if r.get('inside')),
                     sum(1 for r in tight if r.get('overlaps'))))
    for row in missed:
        print('  miss at %s: %s outside, bound %s wide, NICT half width %s, %s'
              % (row['at'], ms(row['miss_ns']), ms(row['width_ns']), ms(row['nict_half_ns']),
                 'overlapping' if row.get('overlaps') else 'no overlap'))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--out', help='where the readings go')
    parser.add_argument('--binary', help='the timewitness binary to run')
    parser.add_argument('--server', default='ntp.nict.jp')
    parser.add_argument('--days', type=float, default=3.0)
    parser.add_argument('--until',
                        help='when to stop, as 2026-09-22T18:00:00 in local time. It wins '
                                        'over --days so a restart does not extend the capture')
    parser.add_argument('--every', type=float, default=300.0, help='seconds between pairs')
    parser.add_argument('--settle', type=float, default=180.0,
                        help='seconds to let a fresh agent gather rounds before the first pair')
    parser.add_argument('--timeout', type=float, default=5.0, help='seconds to wait for NICT')
    parser.add_argument('--task-name',
                        help='the name of the logon task that restarts this capture, '
                                            'so the capture can remove it once it is finished')
    parser.add_argument('--summarise',
                        help='read a finished or running capture and say what it holds')
    args = parser.parse_args()

    if args.summarise:
        return summarise(args.summarise)
    if not args.out or not args.binary:
        parser.error('--out and --binary are both needed to capture')
    return capture(args)


if __name__ == '__main__':
    sys.exit(main())
