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

reads what is on disk and prints one sentence a reader can reproduce, including how many of the
pairs met the condition for being about the two clocks at all.

    python scripts/nict-compare.py --attribute DIR

attributes every reading already taken to the binary and the capture that produced it, worked out
from the log, and rebuilds the table. A capture does this itself at every start; this is for a
directory with no capture running. `--self-test` plants a spliced capture and watches both of
those answer on it.

## What one file holds

Not one series. A capture restarted, on a reboot or by hand, is a new process and may be a new
binary, and the readings go on being appended to one file. So every reading carries which build and
which capture took it. The capture of 2026-09-19 was started four times across two builds before
that field existed, and what it wrote is attributed from the log rather than guessed at; anything
older than the log's first line is left unattributed and counted out loud.
"""

import argparse
import contextlib
import io
import json
import os
import pathlib
import re
import socket
import struct
import subprocess
import sys
import time

# Seconds between the NTP epoch of 1900 and the Unix epoch of 1970.
NTP_TO_UNIX = 2_208_988_800
NS = 1_000_000_000


# Windows gives a console application a console of its own when the process that starts it has
# none, and a capture started by `pythonw.exe` or by a logon task has none. That console is charged
# to the bracket every pair is pinned to, and it was most of the bracket.
#
# Measured 2026-09-19 on this desktop, four stamps a group, the same binary against the same running
# agent: from a process with no console, a plain start brackets at 188.919 ms at the median and this
# flag brings it to 26.207 ms. Six more at 20 s apart, with the flag, ran 23.251 to 34.035 ms with
# no first-one penalty, so what is left is the process start itself and there is nothing to warm.
# From a process that does have a console the same stamps brackets at 16.884 ms, because the child
# inherits the console instead of being given one. Three earlier accounts of the bracket were
# refused by their own controls before this one: the binary being cold on disk, which five stamps
# from a fresh process in the capture's own directory refused at 5.835 to 8.460 ms, and the caller
# having slept five minutes, which a process doing exactly that refused at 13.311 ms while the live
# capture beside it was taking 75.247 and 135.727 ms.
#
# Nothing is lost by refusing the child a console. Its output goes to pipes here and it never writes
# to one. It also means nothing this file starts can put a window on anybody's desktop.
QUIET = 0x08000000 if os.name == 'nt' else 0


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


def stamp_once(binary, workdir, endpoint, receipt):
    """One `stamp` against the resident agent, as the process the bracket has to contain."""
    receipt.unlink(missing_ok=True)
    return subprocess.run(
        [binary, 'stamp', '--subject', str(workdir / 'subject.txt'),
         '--key', str(workdir / 'pair.key'), '--out', str(receipt),
         '--agent', str(endpoint), '--no-evidence'],
        capture_output=True, text=True, cwd=workdir, creationflags=QUIET)


def what_the_agent_said(binary, workdir, endpoint):
    """One stamp from the resident agent, bracketed by the local clock.

    The bracket is the whole point. The receipt says what UTC was when the agent read, and it does
    not say what this machine's own clock said at that moment, so the clock is read either side and
    the midpoint is used. The width of the bracket is carried on each reading as the pairing
    uncertainty, because a pair is only as good as the instant it can be pinned to.

    What is inside the bracket is one process start and the agent's answer, and until 2026-09-19 it
    was also a console. See `QUIET`.
    """
    receipt = workdir / 'pair.cbor'

    before = now_ns()
    stamped = stamp_once(binary, workdir, endpoint, receipt)
    after = now_ns()

    middle, half = (before + after) // 2, (after - before) // 2
    bracket = {'local_before_ns': before, 'local_after_ns': after}
    if stamped.returncode != 0:
        return None, middle, half, bracket, stamped.stdout + stamped.stderr

    read = subprocess.run([binary, 'verify', str(receipt), '--json', '--no-anchors'],
                          capture_output=True, text=True, cwd=workdir, creationflags=QUIET)
    if not read.stdout.strip():
        return None, middle, half, bracket, read.stdout + read.stderr

    claim = json.loads(read.stdout)['claim']
    return claim, middle, half, bracket, ''


def one_pair(binary, workdir, endpoint, host, timeout, made_by):
    """The agent and NICT, close together, as one row.

    `made_by` is which build of the product and which capture process produced this reading, and it
    is on every one of them because this file is not one series. The capture of 2026-09-19 was
    started four times across two builds, and until each reading carried it, nothing on disk said
    which came from which. A reader comparing the first day with the third has to see that.
    """
    claim, local_at_read, pair_half_ns, bracket, trouble = what_the_agent_said(
        binary, workdir, endpoint)
    row = {'at': time.strftime('%Y-%m-%dT%H:%M:%S'), 'local_at_read_ns': local_at_read,
           'pair_half_ns': pair_half_ns}
    row.update(made_by)
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
           'sources_kept', 'operators_kept', 'nict_stratum', 'overlaps',
           'binary', 'capture_pid', 'attribution']

# The table is tab separated, and the separator is named so no line in this file has to
# carry an escape a reader has to decode to see the shape of one line.
TAB = '\t'


STARTED = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) capture started, pid (\d+), '
                     r'binary (.+), server ')


def captures_in(log):
    """Every capture this directory has held, as (when it started, its pid, its binary).

    A capture that loses the lock exits before it writes anything, so a `capture started` line is
    a capture that actually ran. That is what makes the log enough to attribute rows by.
    """
    if not log.exists():
        return []
    found = []
    for line in log.read_text(encoding='utf-8', errors='replace').splitlines():
        hit = STARTED.match(line)
        if hit:
            found.append((hit.group(1).replace(' ', 'T'), int(hit.group(2)),
                          pathlib.Path(hit.group(3)).name))
    found.sort()
    return found


def attribute(out, say=None):
    """Give every reading already on disk the binary and the capture that produced it.

    `pairs.jsonl` is one file and it is not one series. The capture of 2026-09-19 was started four
    times across two builds of the product between 11:17 and 13:00, and nothing written down said
    which. A reader comparing the first day against the third would have been comparing two
    binaries without being told.

    Each reading belongs to the last capture that started at or before it, which the log gives
    exactly. Anything older than the first line in the log cannot be placed and is left alone rather
    than guessed at, and the count of those is returned so the caller can say so out loud.

    Idempotent: what already carries a binary is not touched, so this can run at every start.
    """
    rows_file = out / 'pairs.jsonl'
    if not rows_file.exists():
        return 0, 0
    starts = captures_in(out / 'run.log')
    rows = [json.loads(line) for line in
            rows_file.read_text(encoding='utf-8').splitlines() if line.strip()]

    placed, lost = 0, 0
    for row in rows:
        if row.get('binary'):
            continue
        was = [s for s in starts if s[0] <= row.get('at', '')]
        if not was:
            lost += 1
            continue
        when, pid, binary = was[-1]
        row['binary'] = binary
        row['capture_pid'] = pid
        row['attribution'] = 'run.log'
        placed += 1

    if placed:
        spare = rows_file.with_suffix('.jsonl.rewriting')
        spare.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        spare.replace(rows_file)
    if say and lost:
        say('%d readings are older than the first line in the log and cannot be attributed' % lost)
    return placed, lost


def header_of(table):
    """The column names a table was written with, or None where there is no table."""
    if not table.exists():
        return None
    first = table.read_text(encoding='utf-8').splitlines()
    return first[0].split(TAB) if first else None


def rebuild_table(out):
    """Write `pairs.tsv` again from `pairs.jsonl`, which is the file that holds everything.

    The table is a convenience and the jsonl is the record, so the table is always the one that
    gets rewritten. Appending a wider reading to a narrower header is what this stops: every column
    after the new one lines up against the wrong name and nothing says so.
    """
    rows_file = out / 'pairs.jsonl'
    rows = ([json.loads(line) for line in
             rows_file.read_text(encoding='utf-8').splitlines() if line.strip()]
            if rows_file.exists() else [])
    with open(out / 'pairs.tsv', 'w', encoding='utf-8') as handle:
        handle.write(TAB.join(COLUMNS) + '\n')
        for row in rows:
            handle.write(TAB.join(str(row.get(name, '')) for name in COLUMNS) + '\n')


def attribute_only(where):
    """`--attribute DIR`: place every reading already taken, without starting anything.

    It refuses while a capture holds the directory, because that capture is appending to the file
    this would rewrite.
    """
    out = pathlib.Path(where).resolve()
    held = out / 'capture.pid'
    if held.exists():
        try:
            was = int(held.read_text().strip())
        except ValueError:
            was = None
        if was is not None and alive(was):
            print('a capture is running here as pid %d, so nothing was rewritten' % was)
            return 1
    placed, lost = attribute(out)
    rebuild_table(out)
    print('attributed %d rows from the log, could not place %d, and rebuilt the table' %
          (placed, lost))
    return 0


def alive(pid):
    """Whether a pid is a process on this machine. Windows has no kill(0), so ask the task list."""
    if os.name != 'nt':
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    seen = subprocess.run(['tasklist', '/FI', 'PID eq %d' % pid], capture_output=True, text=True,
                          creationflags=QUIET)
    return str(pid) in seen.stdout


def image_of(pid):
    """The executable a pid is running, or None where nothing is running as that pid.

    Windows reuses pids, so a pid on its own is never enough to kill on. This is the second half of
    the check: the pid has to be alive and it has to be running the image the caller expects.

    Off Windows this answers None and the caller stops nothing, which is the honest answer rather
    than an untested branch. This capture runs on the desktop the product is measured on.
    """
    if os.name != 'nt':
        return None
    seen = subprocess.run(['tasklist', '/FI', 'PID eq %d' % pid, '/FO', 'CSV', '/NH'],
                          capture_output=True, text=True, creationflags=QUIET)
    line = seen.stdout.strip().splitlines()
    if not line or not line[0].startswith('"'):
        return None
    name = line[0].split('","')[0].strip('"')
    return name if str(pid) in line[0] else None


def stop_a_stale_agent(out, binary, say):
    """Stop the agent a previous capture left behind, so this desktop polls at one rate and not two.

    The agent is a child of the capture and nothing reaps it, so a capture that is killed rather
    than stopped leaves its agent running. That happened on 2026-09-19: a capture restarted at
    12:59:59 and the agent its predecessor had started at 11:25:35 went on asking the same nine
    public NTP and Roughtime servers at the same thirty-two second cadence for nine hours. Two
    agents on one desktop is twice the rate this product intends, at somebody else's expense, and
    both of them sit inside every measurement taken on the machine.

    The pid is only killed where the image running as it is the binary this capture runs, because
    a pid written hours ago may belong to anything by now.
    """
    held = out / 'agent.pid'
    if not held.exists():
        return
    try:
        was = int(held.read_text().strip())
    except ValueError:
        held.unlink(missing_ok=True)
        return
    running = image_of(was)
    if running is None or running.lower() != pathlib.Path(binary).name.lower():
        say('the agent pid %d is not running %s, so nothing was stopped'
            % (was, pathlib.Path(binary).name))
        held.unlink(missing_ok=True)
        return
    subprocess.run(['taskkill', '/PID', str(was), '/T', '/F'], capture_output=True, text=True,
                   creationflags=QUIET)
    say('stopped the agent a previous capture left running as pid %d' % was)
    held.unlink(missing_ok=True)


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
    """The resident agent at its shipped cadence, with nothing passed that changes it.

    The pid goes on disk beside the endpoint, because the next capture to start here has to be able
    to stop this one. See `stop_a_stale_agent`.
    """
    endpoint.unlink(missing_ok=True)
    handle = open(log, 'a', encoding='utf-8')
    started = subprocess.Popen([binary, 'agent', '--endpoint', str(endpoint)],
                               stdout=handle, stderr=subprocess.STDOUT, cwd=workdir,
                               creationflags=QUIET)
    (workdir / 'agent.pid').write_text(str(started.pid))
    return started


def put_the_task_away(name):
    """Remove the logon task that restarts a capture, once there is nothing left to restart.

    A capture that runs over days wants to survive a reboot, and the way to do that on Windows is a
    task that fires at logon. A task nobody removes outlives the capture and starts things on a
    machine long after anybody remembers why, so the capture removes its own.
    """
    if not name or os.name != 'nt':
        return
    subprocess.run(['schtasks', '/Delete', '/TN', name, '/F'], capture_output=True, text=True,
                   creationflags=QUIET)


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
    run_log = open(out / 'run.log', 'a', encoding='utf-8', buffering=1)

    def say(line):
        run_log.write('%s %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), line))

    say('capture started, pid %d, binary %s, server %s, every %ss for %s days'
        % (os.getpid(), binary, args.server, args.every, args.days))

    # What this capture puts on every row it writes, so a file several captures wrote says where
    # each reading came from. `attribution` says how it got its provenance: `capture` is the
    # capture saying what it was at the time, and `run.log` is `--attribute` working it out later.
    made_by = {'binary': pathlib.Path(binary).name, 'capture_pid': os.getpid(),
               'attribution': 'capture'}

    # What is already here is attributed from the log before anything is added to it, and the
    # table is rebuilt from what is in the jsonl whenever its header is not the one about to be
    # written. A header older than what it heads lines every column up against the wrong name.
    attributed, unattributed = attribute(out, say)
    if attributed or unattributed:
        say('attributed %d rows from the log and could not place %d'
            % (attributed, unattributed))
    if not table.exists() or header_of(table) != COLUMNS:
        rebuild_table(out)
        say('the table was rebuilt from the jsonl, at %d columns' % len(COLUMNS))

    stop_a_stale_agent(out, binary, say)

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
            row = one_pair(binary, out, endpoint, args.server, args.timeout,
                           made_by)
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
    (out / 'agent.pid').unlink(missing_ok=True)
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
        #
        # This count is printed on every run, including when it is nought, and that is the half of
        # it that is not a judgement call. Until 2026-09-19 the line was inside `if tight:`, so a
        # capture in which no pair at all resolved the two clocks printed its inside count and said
        # nothing about the condition it had set for itself. Over the first 39 pairs that is what
        # happened: a reader was shown "7 of 39 put NICT inside the agent's bound" and was not told
        # that nought of the 39 were a comparison of the two clocks.
        tight = [row for row in paired if row['pair_half_ns'] * 5 <= row['width_ns']]
        print('%d of %d pairs were taken in a bracket under a fifth of the bound, which is the '
              'condition for the pair to be about the two clocks rather than about how long this '
              'machine took to start a process.' % (len(tight), len(paired)))
        if tight:
            print('On those %d: %d inside, %d overlapping.'
                  % (len(tight), sum(1 for r in tight if r.get('inside')),
                     sum(1 for r in tight if r.get('overlaps'))))
        else:
            print('So no pair here resolved the two clocks, and every count above is bounded by '
                  'the bracket rather than by the agent.')

        # Which build took which readings. This file is not one series: the capture of 2026-09-19
        # was started four times across two builds, and a reader comparing one day against another
        # has to see that before they compare anything.
        by_build = {}
        for row in paired:
            by_build.setdefault(row.get('binary') or 'not attributed', []).append(row)
        for name in sorted(by_build):
            some = by_build[name]
            halves = sorted(row['pair_half_ns'] for row in some)
            print('  %s: %d pairs, %s to %s, %d inside, bracket half %s at the median.'
                  % (name, len(some), some[0]['at'], some[-1]['at'],
                     sum(1 for r in some if r.get('inside')), ms(halves[len(halves) // 2])))
    for row in missed:
        print('  miss at %s: %s outside, bound %s wide, NICT half width %s, %s'
              % (row['at'], ms(row['miss_ns']), ms(row['width_ns']), ms(row['nict_half_ns']),
                 'overlapping' if row.get('overlaps') else 'no overlap'))
    return 0


def self_test():
    """Plant a spliced capture and watch every branch this file gained on 2026-09-19 answer on it.

    A green run of a check is not evidence the check works, so this builds the fault rather than
    describing it: a directory whose log holds two captures on two binaries, with readings before
    the first of them, and with brackets chosen so one of them qualifies and another does not.
    Nothing here touches the network, starts an agent or reads a real capture.
    """
    import tempfile

    failures = []

    def holds(claim, what):
        if not claim:
            failures.append(what)
        print('%s  %s' % ('ok  ' if claim else 'FAIL', what))

    with tempfile.TemporaryDirectory() as room:
        out = pathlib.Path(room)
        (out / 'run.log').write_text(
            '2026-09-19 11:17:26 capture started, pid 63968, binary C:/w/target/release/tw.exe, '
            'server ntp.nict.jp, every 300.0s for 3.0 days\n'
            '2026-09-19 11:17:26 agent started as pid 50720\n'
            '2026-09-19 12:59:59 capture started, pid 63608, binary C:/w/frozen/tw-7689719.exe, '
            'server ntp.nict.jp, every 300.0s for 3.0 days\n', encoding='utf-8')

        def row(at, half_ms, width_ms, inside):
            return {'at': at, 'agent': 'signed', 'nict': 'answered',
                    'pair_half_ns': int(half_ms * 1_000_000),
                    'width_ns': int(width_ms * 1_000_000), 'inside': inside, 'miss_ns': 0,
                    'nict_half_ns': 0, 'overlaps': True}

        planted = [
            row('2026-09-19T10:00:00', 90.0, 115.0, True),    # older than the log's first line
            row('2026-09-19T11:20:26', 90.0, 115.0, True),    # the first capture, a wide bracket
            row('2026-09-19T13:03:00', 90.0, 115.0, False),   # the second, still a wide bracket
            row('2026-09-19T13:08:00', 5.0, 115.0, True),     # the second, a bracket that resolves
        ]
        (out / 'pairs.jsonl').write_text(
            ''.join(json.dumps(one) + '\n' for one in planted), encoding='utf-8')

        placed, lost = attribute(out)
        holds(placed == 3, 'three readings are placed against the capture that was running')
        holds(lost == 1, 'a reading older than the first line in the log is not guessed at')

        back = [json.loads(line) for line in
                (out / 'pairs.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
        holds(back[0].get('binary') is None, 'what cannot be placed is left alone')
        holds(back[1]['binary'] == 'tw.exe' and back[1]['capture_pid'] == 63968,
              'a reading at 11:20 belongs to the capture that started at 11:17')
        holds(back[2]['binary'] == 'tw-7689719.exe' and back[2]['capture_pid'] == 63608,
              'a reading at 13:03 belongs to the capture that started at 12:59')
        holds(all(one['attribution'] == 'run.log' for one in back[1:]),
              'anything placed afterwards says it was placed from the log')

        again, lost_again = attribute(out)
        holds(again == 0 and lost_again == 1, 'running it twice places nothing a second time')

        rebuild_table(out)
        head = header_of(out / 'pairs.tsv')
        holds(head == COLUMNS, 'the table is rebuilt with the header its contents are written to')
        holds(len(head) == len((out / 'pairs.tsv').read_text(encoding='utf-8')
                               .splitlines()[1].split(TAB)),
              'a line of the table has one cell per column in its header')

        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            summarise(out)
        report = said.getvalue()
        holds('1 of 4 pairs were taken in a bracket under a fifth of the bound' in report,
              'the summary says how many pairs met its own condition')
        holds('tw-7689719.exe: 2 pairs' in report and 'tw.exe: 1 pairs' in report,
              'the summary says which build took which pairs')

        # The same file with the one qualifying row widened, which is the shape the real capture was
        # in all morning. This is the branch that printed nothing before 2026-09-19.
        back[3]['pair_half_ns'] = 90 * 1_000_000
        (out / 'pairs.jsonl').write_text(
            ''.join(json.dumps(one) + '\n' for one in back), encoding='utf-8')
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            summarise(out)
        report = said.getvalue()
        holds('0 of 4 pairs were taken in a bracket under a fifth of the bound' in report,
              'a capture where nothing qualified says so rather than saying nothing')
        holds('no pair here resolved the two clocks' in report,
              'and says what that leaves every other count in the report bounded by')

    print('%d of the checks above failed' % len(failures))
    return 1 if failures else 0


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
    parser.add_argument('--attribute',
                        help='give every reading already taken the binary and the capture '
                                          'that produced it, from the log, and rebuild the table')
    parser.add_argument('--self-test', action='store_true',
                        help='plant a spliced capture and watch the attribution and the '
                                             'qualifying count both answer on it')
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.summarise:
        return summarise(args.summarise)
    if args.attribute:
        return attribute_only(args.attribute)
    if not args.out or not args.binary:
        parser.error('--out and --binary are both needed to capture')
    return capture(args)


if __name__ == '__main__':
    sys.exit(main())
