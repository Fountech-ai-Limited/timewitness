#!/usr/bin/env python3
"""Ask clocks the product never consulted whether the bound it claimed actually contained UTC.

Every containment test in this repository runs against a simulated network with a known true
offset, which checks the arithmetic and cannot check the answer. The product's one claim is that
UTC is inside the interval. Nothing held it to a clock it did not ask.

So this takes a stamp, reads this machine's own clock either side of it, and then asks at least
three operators the product does not use how far that clock is from UTC. Both sides are turned into
the same quantity, how wrong this machine's clock is, so the seconds between the two readings cancel
and only the machine's drift over those seconds is left, which is under a tenth of a millisecond at
a hundred parts per million.

    python scripts/the-bound-holds-against-clocks-it-never-asked.py --runs 6 --rounds 16

prints one row per stamp with the margin to the nearer edge, and exits 1 if any claimed interval
and any outside measurement fail to overlap. The outside servers are asked over a plain socket in
this file, by code the product does not link, so there is no route by which one could become a
source by accident. It is checked rather than promised: the receipt names its own sources and their
operators, and an outside host whose operator appears there is refused and not counted.

    ... --shift-ms 500

is the red control. It moves every claimed interval off UTC by that much before judging, so a run
that passes without it has to fail with it. A green run is not evidence a check works.

    ... --self-test

plants the readings the judgement has to refuse and watches it refuse each one, with no network.

## What this is not

It is not a figure for anybody else's machine, and it is not a figure for this one on a quiet day
unless the run says the machine was quiet. It is one machine, one network, one hour. The outside
servers carry their own error, bounded here by half their round trip, and that is carried on every
row rather than assumed away.
"""

import argparse
import json
import os
import pathlib
import socket
import statistics
import struct
import subprocess
import sys
import time

NS = 1_000_000_000
NTP_TO_UNIX = 2_208_988_800
MS = 1_000_000

# Three operators the product does not use. The check that they are outside the source set is
# below and reads the receipt, so this list is a starting point rather than the guarantee.
OUTSIDE = ['time.nist.gov', 'time.apple.com', 'time.windows.com']
# Below three operators there is no majority and one wrong server decides the answer, which is the
# same floor the product itself applies to its own sources.
FLOOR = 3
# A stamp and the outside readings have to be about the same moment. Past this the machine's own
# drift is no longer negligible against the margins being measured.
SAME_MOMENT_S = 30

# Windows gives a console application a console of its own when the caller has none, and that shows
# up as time inside the bracket. `nict-compare.py` measured it at most of the bracket on this
# desktop on 2026-09-19.
QUIET = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def now_ns():
    return time.time_ns()


def ntp_to_ns(raw):
    seconds, fraction = struct.unpack('>II', raw)
    return (seconds - NTP_TO_UNIX) * NS + (fraction * NS) // (1 << 32)


def ns_to_ntp(value):
    seconds, rest = divmod(value, NS)
    return struct.pack('>II', seconds + NTP_TO_UNIX, (rest * (1 << 32)) // NS)


def ask_ntp(host, timeout):
    """One SNTP exchange. The transmit timestamp is checked on the way back, so a reply that is not
    an answer to this question is refused rather than recorded as a reading."""
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
    if reply[1] == 0:
        raise ValueError('stratum 0, which is a kiss of death rather than a time')

    t2 = ntp_to_ns(reply[32:40])
    t3 = ntp_to_ns(reply[40:48])
    return {
        'host': host,
        'at_ns': (t1 + t4) // 2,
        # How wrong this machine's clock is, by the classic four timestamps.
        'offset_ns': ((t2 - t1) + (t3 - t4)) // 2,
        'round_trip_ns': (t4 - t1) - (t3 - t2),
        'root_delay_ns': (struct.unpack('>I', reply[4:8])[0] * NS) >> 16,
        'root_dispersion_ns': (struct.unpack('>I', reply[8:12])[0] * NS) >> 16,
        'stratum': reply[1],
    }


def operator_of(host):
    """The registrable-looking part of a name, for comparing with a receipt's operator field."""
    parts = host.lower().rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host.lower()


def outside_the_source_set(host, sources):
    """Whether this host belongs to none of the operators the receipt says it used.

    Checked rather than promised. The whole reading is worth nothing if one of the clocks being
    asked is a clock the product asked, and a list in a comment does not stop that happening the
    day somebody adds a source.
    """
    operators = {str(s.get('operator', '')).lower() for s in sources}
    operators |= {str(s.get('id', '')).split(':')[-1].lower() for s in sources}
    ours = operator_of(host)
    if ours in operators:
        return False
    # `ntp:cloudflare` and `time.cloudflare.com` are the same operator under different spellings.
    label = ours.split('.')[0]
    return label not in operators


def judge(reading, shift_ns=0, allowance_ns=0, max_gap_ns=1 * NS):
    """Whether one stamp's claimed interval and the outside measurements agree about UTC.

    Both sides are turned into the same quantity: how far ahead of UTC this machine's own clock is.
    The receipt gives UTC in an interval for the instant it read, and the local clock is read the
    moment the stamp exits, so the claimed error is the exit reading minus that interval. The
    outside exchange gives UTC minus the local clock directly, so the outside error is the negative
    of its offset, with half its round trip as the width of its own doubt.

    **Pairing is on the exit and not the midpoint of the run.** A sixteen-round stamp takes about
    twelve seconds and the reading is at the end of it, so pairing on the midpoint puts six seconds
    of polling into what then reads as clock error. That is not a subtlety: the first run of this
    file did it and reported the machine five seconds wrong.

    The gap between the reading and the exit is not assumed, it is measured on every stamp and
    printed: it is the claimed error minus the outside error, which is what is left once both agree
    about the clock. A gap past `--max-gap-ms` refuses the stamp, because then the two measurements
    are no longer about the same instant.

    Two verdicts, because they answer two different questions and only one of them fails a run.

    The fair one asks whether the claimed interval and the outside interval overlap at all. A
    failure there is the product and the outside world contradicting each other, and that is what
    this exits 1 on.

    The strict one asks whether the outside estimate itself sits inside the claimed interval with
    no allowance. It is the stronger statement and it is reported rather than enforced.
    """
    if reading.get('refused'):
        return dict(reading, fair=None, strict=None)

    outside = reading['outside']
    if len(outside) < FLOOR:
        return dict(reading, fair=False, strict=False,
                    why='%d operator(s) answered and the floor is %d, so nothing outside had a '
                        'majority' % (len(outside), FLOOR))

    pair = reading['local_after_ns']
    far = [o for o in outside if abs(o['at_ns'] - pair) > SAME_MOMENT_S * NS]
    if far:
        return dict(reading, fair=False, strict=False,
                    why="%s answered %.1f s from the stamp, and past %d s this machine's own "
                        'drift is no longer small against the margins'
                        % (far[0]['host'], abs(far[0]['at_ns'] - pair) / NS, SAME_MOMENT_S))

    # How far ahead of UTC this machine's clock is, as the receipt has it.
    low = pair - (reading['latest_ns'] + shift_ns)
    high = pair - (reading['earliest_ns'] + shift_ns)

    fair = True
    strict = True
    margins = []
    gaps = []
    misses = []
    for o in outside:
        err = -o['offset_ns']
        own = o['round_trip_ns'] // 2
        if not (err + own >= low - allowance_ns and err - own <= high + allowance_ns):
            fair = False
            misses.append(o['host'])
        if not (low <= err <= high):
            strict = False
        margins.append(min(err - low, high - err))
        gaps.append(pair - reading['reading_ns'] - err)

    gap = int(statistics.median(gaps))
    if gap > max_gap_ns:
        return dict(reading, fair=False, strict=False, gap_ns=gap,
                    why='the reading and the exit are %.3f s apart, which is past the ceiling, so '
                        'the two measurements are not about the same instant' % (gap / NS))

    return dict(reading, fair=fair, strict=strict, low_ns=low, high_ns=high, gap_ns=gap,
                margin_ns=min(margins), margins_ns=margins, missed_by=misses,
                why='' if fair else 'the claimed interval does not overlap what %s measured'
                                    % ', '.join(misses))


def one_stamp(binary, workdir, rounds, timeout, outside_hosts):
    """One stamp, bracketed by the local clock, then the outside operators."""
    receipt = workdir / 'stamp.cbor'
    receipt.unlink(missing_ok=True)

    before = now_ns()
    stamped = subprocess.run(
        [str(binary), 'stamp', '--subject', str(workdir / 'subject.txt'),
         '--key', str(workdir / 'pair.key'), '--out', str(receipt),
         '--rounds', str(rounds), '--no-evidence'],
        capture_output=True, text=True, cwd=str(workdir), creationflags=QUIET)
    after = now_ns()

    if stamped.returncode != 0:
        return {'refused': 'the stamp failed: ' + (stamped.stderr or stamped.stdout).strip()[:200]}

    read = subprocess.run([str(binary), 'verify', str(receipt), '--json'],
                          capture_output=True, text=True, cwd=str(workdir), creationflags=QUIET)
    if not read.stdout.strip():
        return {'refused': 'the receipt did not verify: '
                           + (read.stderr or read.stdout).strip()[:200]}
    claim = json.loads(read.stdout)['claim']

    asked = []
    for host in outside_hosts:
        if not outside_the_source_set(host, claim.get('sources', [])):
            print('  %s shares an operator with a source in the receipt, so it is not an outside '
                  'clock and is not counted' % host)
            continue
        try:
            asked.append(ask_ntp(host, timeout))
        except Exception as error:  # noqa: BLE001 - any failure here is one fewer outside clock
            print('  %s: no answer, %s' % (host, error))

    return {
        'earliest_ns': claim['earliest_ns'],
        'latest_ns': claim['latest_ns'],
        'reading_ns': claim['reading_ns'],
        'width_ns': claim['width_ns'],
        'sources_kept': claim.get('sources_kept'),
        'operators_kept': claim.get('operators_kept'),
        'local_before_ns': before,
        'local_after_ns': after,
        'local_mid_ns': (before + after) // 2,
        'bracket_half_ns': (after - before) // 2,
        'outside': asked,
    }


def report(judged, shift_ns, out=sys.stdout):
    print('', file=out)
    print('%-4s %12s %12s %12s %10s %9s %8s %7s' %
          ('run', 'outside ms', 'claimed low', 'claimed high', 'margin ms', 'read-exit',
           'overlap', 'inside'), file=out)
    failures = 0
    strict_misses = 0
    for n, r in enumerate(judged, 1):
        if r.get('refused'):
            print('%-4d refused: %s' % (n, r['refused']), file=out)
            failures += 1
            continue
        if r['fair'] is False and 'low_ns' not in r:
            print('%-4d refused: %s' % (n, r['why']), file=out)
            failures += 1
            continue
        best = statistics.median([-o['offset_ns'] for o in r['outside']])
        print('%-4d %12.3f %12.3f %12.3f %10.3f %9.3f %8s %8s' %
              (n, best / MS, r['low_ns'] / MS, r['high_ns'] / MS, r['margin_ns'] / MS,
               r['gap_ns'] / MS, 'yes' if r['fair'] else 'NO',
               'yes' if r['strict'] else 'no'), file=out)
        if not r['fair']:
            failures += 1
            print('      %s' % r['why'], file=out)
        elif not r['strict']:
            strict_misses += 1
    print('', file=out)
    if shift_ns:
        print('The claimed interval was moved %.3f ms off UTC before judging. This run is the red '
              'control and it is meant to fail.' % (shift_ns / MS), file=out)
    print('%d stamp(s), %d where the claimed interval and an outside measurement do not overlap, '
          '%d where the outside estimate sits outside the claimed interval while the two still '
          'overlap.' % (len(judged), failures, strict_misses), file=out)
    gaps = [r['gap_ns'] for r in judged if 'gap_ns' in r]
    if gaps:
        print('The reading sat %.3f to %.3f ms before the exit the local clock was read at, '
              'measured rather than assumed, and every margin above moves by that much if the '
              'pairing is taken at the reading instead.'
              % (min(gaps) / MS, max(gaps) / MS), file=out)
    print('Every figure here is one machine, one network, one run of this file. Nothing in it is a '
          "figure for anybody else's machine, and it is not a quiet-machine figure unless the "
          'machine was quiet.', file=out)
    return failures


def self_test():
    """Plant what the judgement has to refuse and watch it refuse each one."""
    PAIR = 1_000 * NS

    def outside(error_ms, round_trip_ms=10.0, at_ns=PAIR, host='time.nist.gov'):
        """An exchange saying this machine's clock is `error_ms` ahead of UTC."""
        return {'host': host, 'at_ns': at_ns, 'offset_ns': -int(error_ms * MS),
                'round_trip_ns': int(round_trip_ms * MS), 'root_delay_ns': 0,
                'root_dispersion_ns': 0, 'stratum': 2}

    def reading(low_ms, high_ms, outs, gap_ms=10.0):
        """A receipt claiming this machine's clock is between `low_ms` and `high_ms` ahead."""
        err = statistics.median([-o['offset_ns'] for o in outs]) if outs else 0
        return {'earliest_ns': PAIR - int(high_ms * MS), 'latest_ns': PAIR - int(low_ms * MS),
                'reading_ns': int(PAIR - err - gap_ms * MS), 'width_ns': int((high_ms - low_ms) * MS),
                'local_before_ns': PAIR - 12 * NS, 'local_after_ns': PAIR,
                'local_mid_ns': PAIR - 6 * NS, 'bracket_half_ns': 6 * NS, 'outside': outs}

    three = [outside(207.0), outside(207.5, host='time.apple.com'),
             outside(206.5, host='time.windows.com')]

    cases = [
        ('the true value in the middle', reading(130, 280, three), True, True),
        ('the claimed interval is below where the outside clocks put UTC',
         reading(-50, 50, three), False, False),
        ('the claimed interval is above where the outside clocks put UTC',
         reading(400, 500, three), False, False),
        ('the outside estimate is just outside but the intervals still overlap',
         reading(130, 200, [outside(207.0, 20.0), outside(207.5, 20.0, host='time.apple.com'),
                            outside(206.5, 20.0, host='time.windows.com')]), True, False),
        ('only two operators answered', reading(130, 280, three[:2]), False, False),
        ('no operator answered at all', reading(130, 280, []), False, False),
        ('one operator answered a minute from the stamp',
         reading(130, 280, three[:2] + [outside(207.0, at_ns=PAIR + 60 * NS,
                                                host='time.windows.com')]), False, False),
        ('one operator wildly wrong and the other two right',
         reading(130, 280, [outside(207.0), outside(207.5, host='time.apple.com'),
                            outside(5_000.0, host='time.windows.com')]), False, False),
        ('the reading and the exit are two seconds apart',
         reading(130, 280, three, gap_ms=2_000.0), False, False),
    ]

    bad = 0
    for name, r, want_fair, want_strict in cases:
        got = judge(r)
        right = got['fair'] == want_fair and got['strict'] == want_strict
        if not right:
            bad += 1
        print('%-62s overlap %-5s inside %-5s  %s'
              % (name, str(got['fair']).lower(), str(got['strict']).lower(),
                 'as expected' if right else 'WRONG'))

    # The red control, on a reading that passes without it, in both directions.
    good = reading(130, 280, three)
    for shift_ms in (500.0, -500.0):
        got = judge(good, shift_ns=int(shift_ms * MS))
        right = got['fair'] is False
        if not right:
            bad += 1
        print('%-62s overlap %-5s inside %-5s  %s'
              % ('the same reading with the interval moved %+.0f ms' % shift_ms,
                 str(got['fair']).lower(), str(got['strict']).lower(),
                 'as expected' if right else 'WRONG'))

    # A shift too small to move the verdict has to leave it alone, or the control says nothing
    # about the size of what it moved.
    got = judge(good, shift_ns=1 * MS)
    right = got['fair'] is True and got['strict'] is True
    if not right:
        bad += 1
    print('%-62s overlap %-5s inside %-5s  %s'
          % ('the same reading with the interval moved +1 ms', str(got['fair']).lower(),
             str(got['strict']).lower(), 'as expected' if right else 'WRONG'))

    # The gap is measured rather than assumed, so it has to come back as what was planted.
    got = judge(reading(130, 280, three, gap_ms=37.0))
    right = abs(got.get('gap_ns', 0) - 37 * MS) < MS
    if not right:
        bad += 1
    print('%-62s %9.3f ms  %s' % ('a planted 37 ms gap between the reading and the exit',
                                  got.get('gap_ns', 0) / MS,
                                  'as expected' if right else 'WRONG'))

    # The fault the first run of this file made: pairing on the midpoint of a twelve-second stamp.
    midpaired = dict(good, local_after_ns=good['local_mid_ns'])
    got = judge(midpaired)
    right = got['fair'] is False
    if not right:
        bad += 1
    print('%-62s overlap %-5s  %s' % ('paired six seconds off, which is what a midpoint pairing does',
                                      str(got['fair']).lower(),
                                      'as expected' if right else 'WRONG'))

    # The outside-the-source-set check, against a receipt's own source list.
    sources = [{'id': 'ntp:cloudflare', 'operator': 'cloudflare.com'},
               {'id': 'roughtime:int08h', 'operator': 'int08h.com'},
               {'id': 'nts:netnod', 'operator': 'netnod.se'}]
    for host, wanted in [('time.nist.gov', True), ('time.apple.com', True),
                         ('time.cloudflare.com', False), ('roughtime.int08h.com', False),
                         ('nts.netnod.se', False), ('cloudflare.com', False)]:
        got = outside_the_source_set(host, sources)
        right = got == wanted
        if not right:
            bad += 1
        print('%-62s outside %-5s  %s' % ('is %s outside the source set' % host,
                                          str(got).lower(),
                                          'as expected' if right else 'WRONG'))

    print('self-test: %d wrong' % bad)
    return 1 if bad else 0


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--runs', type=int, default=6)
    ap.add_argument('--rounds', type=int, default=16)
    ap.add_argument('--timeout', type=float, default=5.0)
    ap.add_argument('--outside', default=','.join(OUTSIDE),
                    help='comma-separated hosts the product does not use')
    ap.add_argument('--shift-ms', type=float, default=0.0,
                    help='the red control: move every claimed interval this far off UTC')
    ap.add_argument('--allowance-ms', type=float, default=0.0,
                    help='widen the claimed interval by this much before judging. Nought by '
                         'default: the outside half round trip is already carried')
    ap.add_argument('--max-gap-ms', type=float, default=1000.0,
                    help='refuse a stamp whose reading and exit are further apart than this')
    ap.add_argument('--binary', default=None)
    ap.add_argument('--out', default=None, help='where to write every reading as JSON')
    ap.add_argument('--self-test', action='store_true')
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    binary = args.binary
    if binary is None:
        for candidate in ('target/release/timewitness.exe', 'target/release/timewitness'):
            if (root / candidate).exists():
                binary = root / candidate
                break
    if binary is None:
        print('there is no release binary under target/release. Build it with `cargo build '
              '--release`, or say where it is with --binary')
        return 1
    binary = pathlib.Path(binary)

    work = root / 'target' / 'clocks-it-never-asked'
    work.mkdir(parents=True, exist_ok=True)
    (work / 'subject.txt').write_text('the thing being stamped\n', encoding='utf-8')
    if not (work / 'pair.key').exists():
        (work / 'pair.key').write_bytes(os.urandom(32))

    hosts = [h.strip() for h in args.outside.split(',') if h.strip()]
    if len({operator_of(h) for h in hosts}) < FLOOR:
        print('%d outside operator(s) named and the floor is %d' %
              (len({operator_of(h) for h in hosts}), FLOOR))
        return 1

    print('%d stamp(s) at %d rounds, against %s. Binary %s.'
          % (args.runs, args.rounds, ', '.join(hosts), binary))
    shift_ns = int(args.shift_ms * MS)
    judged = []
    for n in range(args.runs):
        print('run %d of %d' % (n + 1, args.runs))
        judged.append(judge(one_stamp(binary, work, args.rounds, args.timeout, hosts),
                            shift_ns, int(args.allowance_ms * MS), int(args.max_gap_ms * MS)))

    failures = report(judged, shift_ns)
    if args.out:
        pathlib.Path(args.out).write_text(json.dumps(judged, indent=1) + '\n', encoding='utf-8')
        print('every reading written to %s' % args.out)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
