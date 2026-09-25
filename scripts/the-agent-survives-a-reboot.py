#!/usr/bin/env python3
"""The agent starts at boot as a service, and the clock it measures is left where it was.

`timewitness agent install` hands the agent to whatever starts things at boot. Saying so proves
nothing until a machine has been restarted and the agent is found answering afterwards with nobody
having started it, and "never touches the clock" proves nothing until the clock has been watched.
Neither can be done on a machine anybody cares about, so this boots one to throw away.

    python3 scripts/the-agent-survives-a-reboot.py --binary target/release/timewitness

boots Ubuntu 24.04 under KVM, with the guest's own time service masked and its clock started seven
seconds ahead of the host's through the emulated real-time clock. It installs the binary, runs
`sudo timewitness agent install`, waits for `status` to answer, restarts the guest and asks `status`
again without starting anything. Then it watches the guest's clock against public NTP servers for
an hour. It passes when the agent answers after the restart and the clock's offset moved by no more
than TOLERANCE over the hour, and by no more than that between the install and two minutes of the
agent running before the restart.

Why the clock starts seven seconds out. A guest whose clock already agrees with the servers to a
millisecond would show nothing if something set it, because there would be nothing to set. Seven
seconds out, anything that set the clock takes seven seconds off the offset in one go, and anything
that slewed it at the fastest rate Linux allows, half a millisecond a second, takes 1.8 s off in the
hour. Both are far past TOLERANCE. What is left is the drift of a clock nobody is correcting, which
is what TOLERANCE is set from.

It exits 0 on a pass, 1 on a fail, and 2 when it could not run: no KVM, no image, no network, or a
guest clock that did not start out, because a check with nothing to see has learned nothing.

    python3 scripts/the-agent-survives-a-reboot.py --binary ... --seed no-start-at-boot

turns one thing wrong and exits 0 only when the check fails for it. `no-start-at-boot` installs the
service and then disables it, so it is not there at boot. `the-clock-moved` starts the guest's own
time service partway through the watch, which sets the clock back to the servers' time.

    python3 scripts/the-agent-survives-a-reboot.py --binary ... --here

is for a machine that is itself thrown away, a GitHub-hosted runner on Windows, macOS or Linux, where
nothing can be restarted. It installs the service, waits for `status` to answer, checks the
platform has it down to start at boot, then uninstalls it and checks nothing is left. That is the
install and the uninstall proved, and not the restart. It refuses to run outside GitHub Actions,
because installing a service on somebody's own machine is not a test.

    python3 scripts/the-agent-survives-a-reboot.py --self-test

reads canned answers and needs no machine and no network.
"""

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

IMAGE = 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img'
SUMS = 'https://cloud-images.ubuntu.com/noble/current/SHA256SUMS'

# How far ahead of the host the guest's clock starts, in seconds.
SEEDED_OFFSET = 7

# The most the offset may move over the watch, in seconds, for a pass.
TOLERANCE = 0.25

# Where the service's agent writes its endpoint on Linux, as `agent install` says.
LINUX_ENDPOINT = '/var/lib/timewitness/agent.endpoint'

# How long after the guest answers ssh the agent has to answer `status`. A fresh agent has a first
# bound within a minute, and a service waits for the network before it starts.
STATUS_WITHIN = 180

# Public NTP servers the guest's offset is measured against. Five operators, none of them ours, and
# none asked more than four times in a sample.
REFERENCES = ['time.cloudflare.com', 'time.google.com', 'time.aws.com', 'pool.ntp.org',
              'ntp.ubuntu.com']

SEEDS = {
    'no-start-at-boot': 'the service is installed and then disabled, so nothing starts it at boot',
    'the-clock-moved': "the guest's own time service is started partway through the watch",
}

# Run inside the guest. It measures the guest's clock against each reference with plain SNTP and
# prints what it found as JSON. The offset is the guest's clock minus the server's, and each server's
# best of four is the one with the shortest round trip, whose half is the most it can be out by.
PROBE = r'''
import json, socket, struct, time
EPOCH = 2208988800
def ask(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.connect((host, 123))
    packet = bytearray(48)
    packet[0] = 0x23
    t0 = time.time()
    s.send(packet)
    data = s.recv(48)
    t3 = time.time()
    s.close()
    if len(data) < 48 or data[1] == 0 or (data[0] >> 6) == 3:
        raise ValueError('unsynchronised')
    def at(i):
        whole, part = struct.unpack('!II', data[i:i + 8])
        return whole - EPOCH + part / 2 ** 32
    t1, t2 = at(32), at(40)
    return {'offset': ((t0 - t1) + (t3 - t2)) / 2, 'delay': (t3 - t0) - (t2 - t1)}
found, failed = [], []
for host in HOSTS:
    best = None
    for _ in range(4):
        try:
            got = ask(host)
        except Exception as e:
            continue
        if best is None or got['delay'] < best['delay']:
            best = got
    if best is None:
        failed.append(host)
    else:
        best['host'] = host
        found.append(best)
print(json.dumps({'found': found, 'failed': failed}))
'''


def say(line):
    print(f'[{time.strftime("%H:%M:%S", time.gmtime())}] {line}', flush=True)


# ---------------------------------------------------------------------------------------------------
# The verdicts, kept apart from any machine so the self-test can read them
# ---------------------------------------------------------------------------------------------------

def agent_answered(text):
    """Whether what `status` printed is an agent answering, whether or not it would sign yet."""
    return bool(re.search(r'^The agent at \S+ is up', text, re.MULTILINE))


def endpoint_from_install(text):
    """The endpoint file `agent install` says the agent writes to."""
    found = re.search(r'writes its endpoint to (.+?)\.\n', text)
    return found.group(1) if found else None


def offset_of(sample):
    """The median offset across the references that answered, or None with fewer than three."""
    offsets = [s['offset'] for s in sample['found']]
    return statistics.median(offsets) if len(offsets) >= 3 else None


def clock_verdict(offsets, tolerance=TOLERANCE, seeded=SEEDED_OFFSET):
    """(code, words) for a series of offsets: 0 unchanged, 1 moved, 2 nothing to see."""
    if not offsets:
        return 2, 'no offset could be measured, so the clock was not watched'
    first = offsets[0]
    if abs(first) < seeded / 2:
        return 2, (f'the guest clock started {first:+.3f} s from the references and was meant to '
                   f'start about {seeded:+d} s out, so a clock being set would not have shown')
    moved = max(abs(o - first) for o in offsets)
    words = (f'the offset started at {first:+.3f} s and moved by at most {moved:.3f} s over '
             f'{len(offsets)} samples, against a tolerance of {tolerance} s')
    return (0 if moved <= tolerance else 1), words


# ---------------------------------------------------------------------------------------------------
# A guest to throw away
# ---------------------------------------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def fetch_image(cache):
    cache.mkdir(parents=True, exist_ok=True)
    image = cache / 'noble-server-cloudimg-amd64.img'
    sums = urllib.request.urlopen(SUMS, timeout=60).read().decode()
    wanted = next((line.split()[0] for line in sums.splitlines()
                   if line.endswith('noble-server-cloudimg-amd64.img')), None)
    if wanted is None:
        raise RuntimeError('the image is not in its own list of digests')
    if not image.exists() or hashlib.sha256(image.read_bytes()).hexdigest() != wanted:
        say(f'fetching {IMAGE}')
        with urllib.request.urlopen(IMAGE, timeout=600) as answer, open(image, 'wb') as out:
            shutil.copyfileobj(answer, out)
        got = hashlib.sha256(image.read_bytes()).hexdigest()
        if got != wanted:
            raise RuntimeError(f'the image fetched has digest {got}, not {wanted}')
    return image


class Guest:
    def __init__(self, work, image):
        self.work = work
        self.key = work / 'key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)],
                       check=True)
        seed = work / 'seed'
        seed.mkdir()
        public = (work / 'key.pub').read_text().strip()
        (seed / 'meta-data').write_text('instance-id: timewitness-reboot\nlocal-hostname: tw\n')
        (seed / 'vendor-data').write_text('')
        (seed / 'user-data').write_text(
            '#cloud-config\n'
            'users:\n'
            '  - name: ubuntu\n'
            '    sudo: ALL=(ALL) NOPASSWD:ALL\n'
            '    shell: /bin/bash\n'
            f'    ssh_authorized_keys: ["{public}"]\n'
            # The guest's own time service would correct the clock this watches, so it is masked
            # before anything is measured and stays masked across the restart.
            'bootcmd:\n'
            '  - [systemctl, mask, --now, systemd-timesyncd.service]\n')
        handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(  # noqa: E731
            *a, directory=str(seed), **k)
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        disk = work / 'disk.qcow2'
        subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b',
                        str(image), str(disk), '8G'], check=True)
        self.port = free_port()
        base = (datetime.now(timezone.utc) + timedelta(seconds=SEEDED_OFFSET))
        self.console = work / 'console.log'
        self.qemu = subprocess.Popen([
            'qemu-system-x86_64', '-machine', 'accel=kvm', '-cpu', 'host', '-m', '2048',
            '-smp', '2', '-drive', f'file={disk},if=virtio,format=qcow2',
            '-netdev', f'user,id=n0,hostfwd=tcp:127.0.0.1:{self.port}-:22',
            '-device', 'virtio-net-pci,netdev=n0',
            '-smbios', f'type=1,serial=ds=nocloud-net;s=http://10.0.2.2:{self.http.server_port}/',
            '-rtc', 'base=' + base.strftime('%Y-%m-%dT%H:%M:%S'),
            '-display', 'none', '-serial', f'file:{self.console}', '-monitor', 'none',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        say(f'guest started, pid {self.qemu.pid}, its clock {SEEDED_OFFSET} s ahead')

    def ssh(self, command, timeout=120, stdin=None):
        return subprocess.run(
            ['ssh', '-i', str(self.key), '-p', str(self.port), '-o', 'StrictHostKeyChecking=no',
             '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'BatchMode=yes',
             '-o', 'ConnectTimeout=5', 'ubuntu@127.0.0.1', command],
            input=stdin, capture_output=True, text=True, timeout=timeout)

    def reachable(self):
        try:
            return self.ssh('true', timeout=20).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def wait_up(self, within=900):
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            if self.qemu.poll() is not None:
                raise RuntimeError('the guest stopped: ' + self.qemu.stderr.read().decode()[-400:])
            if self.reachable():
                return
            time.sleep(5)
        raise RuntimeError(f'the guest did not answer ssh within {within} s')

    def copy_in(self, local, remote):
        subprocess.run(['scp', '-q', '-i', str(self.key), '-P', str(self.port), '-o',
                        'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null', '-o',
                        'LogLevel=ERROR', str(local), f'ubuntu@127.0.0.1:{remote}'], check=True)

    def boot_id(self):
        return self.ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip()

    def restart(self):
        before = self.boot_id()
        try:
            self.ssh('sudo systemctl reboot', timeout=30)
        except subprocess.TimeoutExpired:
            pass
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline and self.reachable():
            time.sleep(2)
        self.wait_up()
        after = self.boot_id()
        if not after or after == before:
            raise RuntimeError('the guest answered again without having restarted')
        say(f'restarted: boot {before[:8]} became {after[:8]}')

    def offset(self):
        for _ in range(3):
            code = 'HOSTS = ' + json.dumps(REFERENCES) + '\n' + PROBE
            got = self.ssh('python3 -', stdin=code, timeout=120)
            if got.returncode == 0:
                sample = json.loads(got.stdout)
                value = offset_of(sample)
                if value is not None:
                    return value, sample
            time.sleep(10)
        return None, None

    def stop(self):
        self.http.shutdown()
        if self.qemu.poll() is None:
            self.qemu.terminate()
            try:
                self.qemu.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.qemu.kill()


def status_answers(guest, endpoint, within):
    """Asks `status` until the agent answers or `within` seconds pass. Returns (answered, text)."""
    deadline = time.monotonic() + within
    text = ''
    while time.monotonic() < deadline:
        got = guest.ssh(f'timewitness status --agent {endpoint}', timeout=60)
        text = got.stdout + got.stderr
        if agent_answered(text):
            return True, text
        time.sleep(5)
    return False, text


def in_a_guest(binary, minutes, every, seed, cache):
    for tool in ['qemu-system-x86_64', 'qemu-img', 'ssh', 'scp', 'ssh-keygen']:
        if shutil.which(tool) is None:
            say(f'could not run: {tool} is not on this machine')
            return 2
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        say('could not run: /dev/kvm is not there or not open to this account')
        return 2
    try:
        image = fetch_image(cache)
    except Exception as e:  # noqa: BLE001
        say(f'could not run: no image: {e}')
        return 2

    work = pathlib.Path(tempfile.mkdtemp(prefix='tw-reboot-'))
    guest = Guest(work, image)
    try:
        guest.wait_up()
        guest.ssh('cloud-init status --wait', timeout=900)
        masked = guest.ssh('systemctl is-enabled systemd-timesyncd.service').stdout.strip()
        say(f"the guest's own time service is {masked}")
        if masked != 'masked':
            say('could not run: the guest has a time service of its own running')
            return 2

        # The clock is watched on both sides of the restart. A restart reads the clock back from the
        # emulated real-time clock, so a change the agent made before it would be gone afterwards,
        # and only a look before it would see one.
        before, _ = guest.offset()
        if before is None:
            say('could not run: fewer than three references answered the guest')
            return 2
        say(f'offset {before:+.4f} s before the install')

        guest.copy_in(binary, '/tmp/timewitness')
        guest.ssh('sudo install -m 0755 /tmp/timewitness /usr/local/bin/timewitness')
        installed = guest.ssh('sudo timewitness agent install')
        installed_at = time.monotonic()
        say('sudo timewitness agent install exited ' + str(installed.returncode))
        print(installed.stdout + installed.stderr, flush=True)
        if installed.returncode != 0:
            return 1
        endpoint = endpoint_from_install(installed.stdout) or LINUX_ENDPOINT
        answered, text = status_answers(guest, endpoint, STATUS_WITHIN)
        if not answered:
            say('FAIL: the service did not answer before the restart')
            print(text, flush=True)
            return 1
        say('the service answers before the restart')
        # Two minutes of the agent running, which covers its settling rounds and the rounds after.
        time.sleep(max(0, 120 - (time.monotonic() - installed_at)))
        settled, _ = guest.offset()
        code, words = clock_verdict([before] + ([settled] if settled is not None else []))
        if settled is None or code != 0:
            say(('FAIL' if code == 1 else 'could not tell') + ' before the restart: ' + words)
            return code if settled is not None else 2
        say(f'offset {settled:+.4f} s with the agent running two minutes: {words}')

        if seed == 'no-start-at-boot':
            guest.ssh('sudo systemctl disable timewitness-agent.service')
            say('seeded: the service is disabled, so nothing starts it at boot')

        guest.restart()
        started = time.monotonic()
        answered, text = status_answers(guest, endpoint, STATUS_WITHIN)
        print(text, flush=True)
        if not answered:
            say(f'FAIL: after the restart `status --agent {endpoint}` did not answer within '
                f'{STATUS_WITHIN} s, and nothing but the boot could have started it')
            return 1
        say(f'after the restart the agent answered {time.monotonic() - started:.0f} s after ssh '
            'did, and nothing but the boot started it')
        facts = guest.ssh(
            'systemctl show timewitness-agent.service -p ActiveEnterTimestampMonotonic '
            '-p ProtectClock -p User --value; pid=$(systemctl show timewitness-agent.service -p '
            'MainPID --value); grep -E "^(CapEff|CapBnd|Seccomp):" /proc/$pid/status').stdout
        say('the unit and the running agent: ' + ' '.join(facts.split()))

        offsets = []
        deadline = time.monotonic() + minutes * 60
        while True:
            value, sample = guest.offset()
            if value is None:
                say('could not run: fewer than three references answered the guest')
                return 2
            offsets.append(value)
            spread = ' '.join(f"{s['host']}={s['offset']:+.4f}/{s['delay'] * 500:.1f}ms"
                              for s in sample['found'])
            say(f'offset {value:+.4f} s ({spread})')
            if seed == 'the-clock-moved' and len(offsets) == 1:
                guest.ssh('sudo systemctl unmask systemd-timesyncd.service && '
                          'sudo systemctl start systemd-timesyncd.service')
                say("seeded: the guest's own time service is started")
            if time.monotonic() >= deadline:
                break
            time.sleep(min(every, max(0, deadline - time.monotonic())))
        still = guest.ssh(f'timewitness status --agent {endpoint}', timeout=60)
        say('at the end of the watch the agent '
            + ('still answers' if agent_answered(still.stdout + still.stderr) else 'did not answer'))

        code, words = clock_verdict(offsets)
        say(('PASS: ' if code == 0 else 'FAIL: ' if code == 1 else 'could not tell: ') + words)
        say(f'conditions: Ubuntu 24.04 under KVM, its own time service masked, its clock started '
            f'{SEEDED_OFFSET} s ahead through the emulated real-time clock, the offset the median of '
            f'SNTP answers from {len(REFERENCES)} public servers, asked from inside the guest every '
            f'{every} s for {minutes} min')
        if code == 0 and not agent_answered(still.stdout + still.stderr):
            return 1
        return code
    finally:
        guest.stop()
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------------------------------
# A runner to throw away, where nothing can be restarted
# ---------------------------------------------------------------------------------------------------

def system_temp():
    """Windows' own temporary folder, where the install makes a folder only administrators can write."""
    return pathlib.Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'Temp'


def on_this_runner(binary):
    # Both, because a runner somebody hosts on their own machine sets the first one too.
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        say('could not run: --here installs a service, and does so only on a GitHub-hosted runner')
        return 2
    windows = os.name == 'nt'
    mac = sys.platform == 'darwin'
    admin = [] if windows else ['sudo']

    def run(args):
        got = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return got.returncode, got.stdout + got.stderr

    if windows:
        # Where the task definition used to be written, a fixed name in the installing account's own
        # temporary folder, which anything running unelevated as that account could take first. It
        # is taken here, and the install has to be unaffected.
        taken = pathlib.Path(tempfile.gettempdir()) / 'timewitness-agent-task.xml'
        taken.mkdir(exist_ok=True)
        before = set(system_temp().glob('timewitness-install-*'))

    code, text = run(admin + [binary, 'agent', 'install'])
    print(text, flush=True)
    if code != 0:
        say(f'FAIL: agent install exited {code}')
        return 1
    if windows:
        left = set(system_temp().glob('timewitness-install-*')) - before
        if left:
            say(f'FAIL: the install left its folder behind: {sorted(map(str, left))}')
            return 1
        say('the install wrote its task definition somewhere of its own, and took it away after')
    endpoint = endpoint_from_install(text)
    if endpoint is None:
        say('FAIL: agent install did not say where the endpoint is')
        return 1

    deadline = time.monotonic() + STATUS_WITHIN
    answered = False
    while time.monotonic() < deadline and not answered:
        code, text = run([binary, 'status', '--agent', endpoint])
        answered = agent_answered(text)
        if not answered:
            time.sleep(5)
    print(text, flush=True)
    if not answered:
        say(f'FAIL: the service did not answer `status` within {STATUS_WITHIN} s')
        return 1
    say('the service answers')

    if windows:
        code, text = run(['schtasks', '/Query', '/TN', r'\TimeWitness\Agent', '/XML'])
        # Task Scheduler hands the definition back in its own spelling: an enabled trigger with
        # nothing else in it comes back as `<BootTrigger />`.
        at_boot = code == 0 and '<BootTrigger' in text and '<LogonType>S4U' in text
    elif mac:
        code, text = run(['sudo', 'launchctl', 'print', 'system/dev.timewitness.agent'])
        plist = pathlib.Path('/Library/LaunchDaemons/dev.timewitness.agent.plist').read_text()
        at_boot = code == 0 and '<key>RunAtLoad</key>\n\t<true/>' in plist
    else:
        code, text = run(['systemctl', 'is-enabled', 'timewitness-agent.service'])
        _, clock = run(['systemctl', 'show', 'timewitness-agent.service', '-p', 'ProtectClock',
                        '--value'])
        at_boot = text.strip() == 'enabled' and clock.strip() == 'yes'
    if not at_boot:
        print(text, flush=True)
        say('FAIL: the platform does not have the service down to start at boot')
        return 1
    say('the platform has it down to start at boot')

    code, text = run(admin + [binary, 'agent', 'uninstall'])
    print(text, flush=True)
    if code != 0:
        say(f'FAIL: agent uninstall exited {code}')
        return 1
    time.sleep(3)
    _, text = run([binary, 'status', '--agent', endpoint])
    if agent_answered(text):
        say('FAIL: the agent still answers after uninstall')
        return 1
    if windows:
        gone = run(['schtasks', '/Query', '/TN', r'\TimeWitness\Agent'])[0] != 0
    elif mac:
        gone = not pathlib.Path('/Library/LaunchDaemons/dev.timewitness.agent.plist').exists()
    else:
        gone = not pathlib.Path('/etc/systemd/system/timewitness-agent.service').exists()
    if not gone:
        say('FAIL: the service definition is still there after uninstall')
        return 1
    say('PASS: installed, answered, down to start at boot, and taken away again. No restart was '
        'done here: a hosted runner cannot restart')
    return 0


# ---------------------------------------------------------------------------------------------------
# The self-test
# ---------------------------------------------------------------------------------------------------

def self_test():
    up = ('The agent at 127.0.0.1:40111 is up and answering.\n\nRight now the time it gives could '
          'be wrong by as much as 40 ms, on its own model.\n')
    refusing = ('The agent at 127.0.0.1:40111 is up, and would not sign a stamp right now.\n')
    absent = 'REFUSED: no agent is running from /var/lib/timewitness/agent.endpoint: gone.\n'
    silent = 'REFUSED: the agent is not answering: connection refused\n'
    install = ('Installed. The agent runs as the systemd service timewitness-agent, as runner, and '
               'it starts at every boot.\n\nIt is starting now and writes its endpoint to '
               '/var/lib/timewitness/agent.endpoint.\n  timewitness status --agent ...\n')
    windows = install.replace('/var/lib/timewitness/agent.endpoint',
                              r'C:\Users\runneradmin\AppData\Local\TimeWitness\agent.endpoint')
    sample = {'found': [{'offset': 7.01}, {'offset': 7.03}, {'offset': 7.02}], 'failed': []}
    thin = {'found': [{'offset': 7.01}, {'offset': 7.03}], 'failed': ['a', 'b', 'c']}
    cases = [
        ('an agent answering is an answer', agent_answered(up), True),
        ('an agent refusing to sign has still answered', agent_answered(refusing), True),
        ('no endpoint is no answer', agent_answered(absent), False),
        ('an endpoint nobody answers on is no answer', agent_answered(silent), False),
        ('the endpoint is read off what install said', endpoint_from_install(install),
         '/var/lib/timewitness/agent.endpoint'),
        ('and a Windows one', endpoint_from_install(windows),
         r'C:\Users\runneradmin\AppData\Local\TimeWitness\agent.endpoint'),
        ('three references give a median', offset_of(sample), 7.02),
        ('two are too few', offset_of(thin), None),
        ('a clock drifting a little is unchanged', clock_verdict([7.02, 7.03, 7.06, 7.1])[0], 0),
        ('a clock set back to the servers has moved', clock_verdict([7.02, 7.03, 0.01])[0], 1),
        ('a clock slewed at the kernel limit has moved', clock_verdict([7.0, 6.4, 5.8, 5.2])[0], 1),
        ('a clock that never started out shows nothing', clock_verdict([0.003, 0.004])[0], 2),
        ('no samples show nothing', clock_verdict([])[0], 2),
    ]
    failed = [name for name, got, wanted in cases if got != wanted]
    for name in failed:
        say(f'self-test failed: {name}')
    say(f'self-test: {len(cases) - len(failed)} of {len(cases)} held')
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--binary', help='the timewitness binary to install')
    parser.add_argument('--minutes', type=float, default=60, help='how long to watch the clock')
    parser.add_argument('--every', type=int, default=300, help='seconds between offset samples')
    parser.add_argument('--seed', choices=sorted(SEEDS), help='turn one thing wrong')
    parser.add_argument('--here', action='store_true', help='install on this throwaway runner')
    parser.add_argument('--cache', default=os.path.join(tempfile.gettempdir(), 'tw-images'),
                        help='where the guest image is kept between runs')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.binary or not os.path.exists(args.binary):
        say('could not run: --binary names no file')
        return 2
    binary = os.path.abspath(args.binary)
    if args.here:
        return on_this_runner(binary)
    if args.seed:
        say(f'seed {args.seed}: {SEEDS[args.seed]}. This passes only if the check fails')
    code = in_a_guest(binary, args.minutes, args.every, args.seed, pathlib.Path(args.cache))
    if args.seed:
        if code == 1:
            say(f'PASS: seed {args.seed} was caught')
            return 0
        say(f'FAIL: seed {args.seed} was not caught (the check exited {code})')
        return 1
    return code


if __name__ == '__main__':
    sys.exit(main())
