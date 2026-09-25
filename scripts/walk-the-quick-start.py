#!/usr/bin/env python3
"""Walk the quick start, command by command, on a machine with nothing of ours on it.

`docs/quick-start.md` promises a newcomer a verified receipt if they type what it says. A page like
that drifts the day a flag is renamed or a release moves, and nobody notices until a stranger gives
up. So this reads the commands off the page itself, every fenced block marked `sh` in the order the
page gives them, and runs them as written in a fresh Ubuntu 24.04 container as an ordinary user who
can sudo, which is what a new machine looks like. It keeps no copy of the commands. Change one on the
page and this runs the changed one.

    python scripts/walk-the-quick-start.py

exits 0 when every command ran and the last one, which has to be a `timewitness verify`, printed the
line a receipt that holds up opens with. It exits 1 when a command failed, when the verify refused,
or when the page no longer ends in a verify. It exits 2 when it could not run at all, which is almost
always no Docker: a walk that could not start has learned nothing and says so rather than passing.

    python scripts/walk-the-quick-start.py --seed the-subject-checked

changes one command on the page, in memory, and walks that instead. It exits 0 only when the changed
page fails, so it is the check that this script notices a changed command rather than a promise that
it would. The seeds are in SEEDS below, each with what it changes and why it has to fail.

    python scripts/walk-the-quick-start.py --self-test

reads canned pages and canned output and needs no Docker and no network.

The container is the only thing that stands in for a person. It gets `sudo` and a user called
newcomer, because a fresh Ubuntu machine has both and the image does not. Nothing else is installed
before the page's own first command, and nothing from the machine running this is mounted into it
except the walk itself.
"""

import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / 'docs' / 'quick-start.md'
IMAGE = 'ubuntu:24.04'

# The line `timewitness verify` opens with when a receipt holds up. A refusal opens with REFUSED.
HELD = 'This receipt holds up as far as it was checked'

# What each walk prints before a block of the page's commands, so the output after the last one can
# be told from the output of everything before it.
MARK = '==> quick start, block'

FENCE = re.compile(r'^```sh[ \t]*\n(.*?)^```[ \t]*$', re.MULTILINE | re.DOTALL)

# One command changed each, and each has to turn the walk red. The first two fail early and cheaply.
# The third compiles and stamps as the page says and fails only at the last command, so it is the one
# that shows the verify itself is what decides. That the verdict is read from what the verify printed,
# and not only from its exit code, is held by the self-test.
SEEDS = {
    'the-release': ('--tag v0.4', '--tag v0.4-never-released',
                    'a release that does not exist cannot be installed'),
    'the-cargo-path': ('. "$HOME/.cargo/env"\n', '\n',
                       'without it the shell that installed Rust cannot find cargo'),
    'the-subject-checked': ('verify hello.receipt.cbor --subject hello.txt',
                            'verify hello.receipt.cbor --subject my-agent.key',
                            'a receipt checked against a file it does not stamp is refused'),
}

# Makes the image look like a fresh machine with a person at it, and then hands over to them.
PREPARE = (
    'set -e; '
    'export DEBIAN_FRONTEND=noninteractive; '
    'apt-get update -qq >/dev/null; '
    'apt-get install -y -qq sudo >/dev/null; '
    'useradd --create-home --shell /bin/bash newcomer; '
    "echo 'newcomer ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/newcomer; "
    'chmod 0440 /etc/sudoers.d/newcomer; '
    "exec su - newcomer -c 'bash /walk/walk.sh'"
)


class PageError(Exception):
    """The page cannot be walked as it stands, which is a failure of the page and not of this run."""


def blocks_on(page_text):
    """Every fenced `sh` block on the page, in order, exactly as written."""
    return [found.group(1) for found in FENCE.finditer(page_text)]


def commands_in(block):
    return [line.strip() for line in block.splitlines()
            if line.strip() and not line.strip().startswith('#')]


def walk_of(page_text):
    """The script the container runs, built from the page's blocks and nothing else."""
    blocks = blocks_on(page_text)
    if not blocks:
        raise PageError('the page has no fenced sh block, so there is nothing to walk')
    last = commands_in(blocks[-1])
    if not last or not last[-1].startswith('timewitness verify '):
        raise PageError('the last command on the page is not a timewitness verify, so a walk of it '
                        'could not end in a verified receipt')
    parts = ['set -exo pipefail', 'cd "$HOME"']
    for number, block in enumerate(blocks, start=1):
        parts.append(f"echo '{MARK} {number} of {len(blocks)}'")
        parts.append(block.rstrip('\n'))
    return '\n'.join(parts) + '\n', len(blocks)


def seeded(page_text, name):
    """The page with one seed's command changed, refused where the seed no longer fits the page."""
    old, new, _ = SEEDS[name]
    count = page_text.count(old)
    if count != 1:
        raise PageError(f'seed {name} looks for {old!r} and the page has it {count} times, so the '
                        'seed has to be moved with the page')
    return page_text.replace(old, new)


def verdict(code, output, blocks):
    """None when the walk ended in a verified receipt, or the reason it did not."""
    if code != 0:
        return f'the walk stopped with exit {code}, so a command on the page failed'
    last_mark = f'{MARK} {blocks} of {blocks}'
    lines = output.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == last_mark]
    if not starts:
        return 'the walk never reached the last block of the page'
    after = lines[starts[-1] + 1:]
    if not any(line.startswith(HELD) for line in after):
        return f'the last block ran and never printed "{HELD}"'
    return None


def walk(page_text, image):
    try:
        script, blocks = walk_of(page_text)
    except PageError as problem:
        print(f'walk the quick start: {problem}', file=sys.stderr)
        return 1
    docker = shutil.which('docker')
    if docker is None:
        print('walk the quick start: there is no docker here, so there is no clean machine to walk the '
              'page on, and nothing was checked', file=sys.stderr)
        return 2
    folder = pathlib.Path(tempfile.mkdtemp(prefix='tw-quick-start-'))
    (folder / 'walk.sh').write_text(script, encoding='utf-8', newline='\n')
    os.chmod(folder, 0o755)
    os.chmod(folder / 'walk.sh', 0o644)
    print(f'walk the quick start: {blocks} blocks off {PAGE.relative_to(ROOT).as_posix()}, on {image}',
          flush=True)
    collected = []
    try:
        child = subprocess.Popen([docker, 'run', '--rm', '-v', f'{folder}:/walk:ro', image,
                                  'bash', '-c', PREPARE],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, text=True, encoding='utf-8',
                                 errors='replace')
    except OSError as problem:
        print(f'walk the quick start: docker would not start: {problem}', file=sys.stderr)
        return 2
    for line in child.stdout:
        sys.stdout.write(line)
        collected.append(line)
    code = child.wait()
    shutil.rmtree(folder, ignore_errors=True)
    if code == 125:
        print('walk the quick start: docker could not start the container, so nothing was checked',
              file=sys.stderr)
        return 2
    reason = verdict(code, ''.join(collected), blocks)
    if reason:
        print(f'walk the quick start: FAILED. {reason}', file=sys.stderr)
        return 1
    print(f'walk the quick start: every command on the page ran on a fresh {image}, and the receipt '
          'it made verifies', flush=True)
    return 0


def walk_seeded(page_text, name, image):
    try:
        changed = seeded(page_text, name)
    except PageError as problem:
        print(f'walk the quick start: {problem}', file=sys.stderr)
        return 2
    print(f'walk the quick start: seed {name}, {SEEDS[name][2]}', flush=True)
    code = walk(changed, image)
    if code == 1:
        print(f'walk the quick start: seed {name} was refused, as it has to be', flush=True)
        return 0
    if code == 0:
        print(f'walk the quick start: seed {name} walked green with a command changed on the page',
              file=sys.stderr)
        return 1
    return 2


def self_test():
    bad = []

    def expect(what, got, want):
        if got != want:
            bad.append(f'{what}: got {got!r}, wanted {want!r}')

    page = PAGE.read_text(encoding='utf-8')
    script, blocks = walk_of(page)
    expect('the page has blocks to walk', blocks >= 2, True)
    # Every command on the page is in the walk, in the page's order, and nothing else is.
    commands = [c for b in blocks_on(page) for c in commands_in(b)]
    walked = [line for line in script.splitlines()
              if line and not line.startswith(('set -exo', 'cd "$HOME"', f"echo '{MARK}"))]
    expect('the walk is the page', [w.strip() for w in walked if not w.strip().startswith('#')],
           commands)

    def refused(text):
        try:
            walk_of(text)
        except PageError:
            return True
        return False

    expect('a page with no sh block', refused('# Nothing\n\n```text\ntimewitness verify r --subject s\n```\n'), True)
    expect('a page that stops before the verify',
           refused('```sh\ntimewitness stamp --subject s --key k --out r\n```\n'), True)
    expect('a page whose verify is not last',
           refused('```sh\ntimewitness verify r --subject s\n```\n\n```sh\necho done\n```\n'), True)
    expect('a verify fenced as text is not a command',
           refused('```sh\necho hi\n```\n\n```text\ntimewitness verify r --subject s\n```\n'), True)
    expect('a page ending in a verify', refused('```sh\ntimewitness verify r --subject s\n```\n'), False)

    for name in SEEDS:
        changed = seeded(page, name)
        expect(f'seed {name} changes the walk', walk_of(changed)[0] != script, True)
    try:
        seeded(page.replace(SEEDS['the-release'][0], '--tag v9'), 'the-release')
        bad.append('a seed that no longer fits the page was applied anyway')
    except PageError:
        pass

    last = f'{MARK} 5 of 5'
    held = f'{MARK} 4 of 5\n+ stamp\nReceipt written\n{last}\n+ timewitness verify r\n{HELD}, and all 3.\n'
    expect('a verify that holds', verdict(0, held, 5), None)
    expect('a verify that holds, from a walk that failed', verdict(1, held, 5) is None, False)
    expect('a refusal', verdict(0, f'{last}\n+ timewitness verify r\nREFUSED.\n', 5) is None, False)
    expect('the line printed before the last block and not after it',
           verdict(0, f'{MARK} 4 of 5\n{HELD}\n{last}\n+ timewitness verify r\n', 5) is None, False)
    expect('a walk that never reached the last block',
           verdict(0, f'{MARK} 4 of 5\n{HELD}\n', 5) is None, False)
    expect('the line quoted inside another line',
           verdict(0, f'{last}\necho "{HELD}"\n', 5) is None, False)

    for line in bad:
        print(f'walk the quick start, self-test: {line}', file=sys.stderr)
    print(f'walk the quick start, self-test: {len(bad)} wrong')
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--seed', choices=sorted(SEEDS))
    parser.add_argument('--image', default=IMAGE)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    try:
        page = PAGE.read_text(encoding='utf-8')
    except OSError as problem:
        print(f'walk the quick start: {problem}', file=sys.stderr)
        return 2
    if args.seed:
        return walk_seeded(page, args.seed, args.image)
    return walk(page, args.image)


if __name__ == '__main__':
    sys.exit(main())
