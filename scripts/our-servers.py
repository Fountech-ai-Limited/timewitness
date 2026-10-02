#!/usr/bin/env python3
"""No surface may say our Roughtime servers are not there while the key log names them.

Two servers of ours have answered since 2026-09-12 and the log served at
timewitness.dev/key-log.txt has named both since 2026-09-15. Until 2026-09-24 the README said the
three tests that need a server of ours were not run "because none is deployed", and the comment at
the head of `.github/workflows/live.yml` said the same, so the daily live run asked nobody's server
of ours and a stopped one would have gone unnoticed. Every surface agreed with every other, which
is why `scripts/three-surfaces.sh` stayed green: it holds the copies to each other, and the copies
were all wrong about the deployment in the same words. This holds them to the key log instead.

    python3 scripts/our-servers.py                       this tree, the committed key log, and the site beside it
    python3 scripts/our-servers.py --no-site             this tree alone, said on purpose
    python3 scripts/our-servers.py --site <url>          this tree, and the page a running site serves
    python3 scripts/our-servers.py --key-log <file|url>  against another key log, the served one on the schedule
    python3 scripts/our-servers.py --list <file>         the servers a key log names in use, for the live run
    python3 scripts/our-servers.py --self-test           one seed per rule, each watched refused

Three rules, each read against the servers the key log names in use.

1. No sentence on a surface says a server of ours is not deployed, not running or not asked. The
   surfaces are the README, every document at the top of `docs/`, the live workflow and the site.
2. The README names every one of those servers by address, beside the badge the live run drives.
3. The live workflow fetches the served key log and asks every server it names, under the key it
   names for it, with the tests in `crates/cli/tests/against_a_running_server.rs`. What it asks is
   read from the log at run time, so a server added to the log is asked the next morning.

`--list` is how the live run reads the log, so the run and this check agree on which servers are in
use by construction rather than by two parsers that happen to match today.

Exit 0 where every rule holds, 1 where one does not, with the file and the sentence named, and 2
where the key log or a surface could not be read. A key log that names no server in use is not a
pass of rules 2 and 3: the live run asks nobody, so that is a failure. The site beside this tree is a
surface, and its absence is a failure unless --no-site says it is deliberate.
"""

import html
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY_LOG = 'deploy/key-log/entries.txt'
LIVE = '.github/workflows/live.yml'
SITE = ROOT.parent / 'timewitness-web' / 'content'

# A sentence is about our servers when it names them one of these ways.
MENTION = re.compile(
    r"\b(servers? of ours|servers? of our own|our (own )?(two )?(roughtime )?servers?)\b", re.I)

# And it denies them when it says one of these. Each is written for the claim rather than for the one
# sentence it was found in, so the passive, the plural and a "yet" all count.
DENIALS = [
    (re.compile(r'\bnone (is|are|has been|have been) (yet )?(deployed|running|serving|up)\b', re.I),
     'says none is deployed'),
    (re.compile(r'\bno (roughtime )?servers? of (ours|our own)\b[^.]{0,40}?'
                r'\b(is|are)?\s*(yet )?(deployed|running|serving|serves|answers|exists?)\b', re.I),
     'says no server of ours is there'),
    (re.compile(r'\b(is|are|was|were) not (yet )?(deployed|running|serving)\b', re.I),
     'says a server of ours is not deployed'),
    (re.compile(r'\bnot (yet )?deployed\b', re.I),
     'says a server of ours is not deployed'),
    (re.compile(r'\b(is|are) not (run|asked|probed)\b', re.I),
     'says what would ask a server of ours is not run'),
]

# What the live workflow has to carry outside its comments, each with what its absence means.
LIVE_NEEDS = [
    ('timewitness.dev/key-log.txt', 'does not fetch the served key log'),
    ('scripts/our-servers.py --list', 'does not read the servers out of the key log with --list'),
    ('--test against_a_running_server', 'does not run the tests that ask a server of ours'),
    ('--ignored', 'does not run ignored tests, which is what those are'),
    ('TIMEWITNESS_PROBE_KEY_LOG=', 'does not ask every server the log names under the key it names'),
    ('TIMEWITNESS_PROBE_ADDRESS=', 'does not ask each server by its address'),
    ('TIMEWITNESS_PROBE_KEY=', 'does not ask each server under its key'),
]


def read(where):
    """A file under this tree, a file named on the command line, or a URL."""
    if re.match(r'https?://', where):
        request = urllib.request.Request(where, headers={'User-Agent': 'timewitness-our-servers'})
        with urllib.request.urlopen(request, timeout=30) as answer:
            return answer.read().decode('utf-8')
    path = Path(where)
    if not path.is_absolute() and not path.exists():
        path = ROOT / where
    return path.read_text(encoding='utf-8')


def servers(log):
    """The servers a key log names in use, as (address, key), in the order the log names them.

    In use is an entry with the server role, no end to its window, no later retirement of its key,
    and a deployment that ends in host:port. The test that asks every server a log names applies the
    first and last of those; retirement is applied here as well, because a retired key still asked
    every morning would be a server we said we stopped using.
    """
    entries, retired = [], set()
    for line in log.splitlines():
        field = line.split()
        if len(field) < 6 or field[0] != 'entry':
            continue
        role, key, until, address = field[1], field[2], field[4], field[-1]
        if role == 'retired':
            retired.add(key)
        elif role == 'server' and until == '-' and ':' in address:
            entries.append((address, key))
    return [(address, key) for address, key in entries if key not in retired]


def words(text):
    """One run of words, with the markdown's code marks taken out."""
    return ' '.join(text.replace('`', '').split())


def yaml_words(text):
    """The workflow as a reader of it sees it, with the comment marks taken out."""
    return words('\n'.join(re.sub(r'^\s*#\s?', '', line) for line in text.splitlines()))


def yaml_code(text):
    """The workflow without its comments, which is what actually runs."""
    return '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))


def json_words(text):
    """Every string in a JSON file, each ended as a sentence so two strings do not run together."""
    out = []

    def walk(value):
        if isinstance(value, str):
            out.append(value.rstrip() + ('' if value.rstrip().endswith(('.', '!', '?')) else '.'))
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(json.loads(text))
    return words(' '.join(out))


def page_words(text):
    """The text of a served page, with the markup and anything that is not prose taken out."""
    text = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', text)
    return words(html.unescape(re.sub(r'<[^>]+>', ' ', text)))


def denials(text):
    """Every sentence that is about our servers and says they are not there, with what it says."""
    found = []
    for sentence in re.split(r'(?<=[.!?])\s+', text):
        if not MENTION.search(sentence):
            continue
        for pattern, what in DENIALS:
            if pattern.search(sentence):
                found.append((what, sentence))
                break
    return found


def check(surfaces, readme, live, in_use, log_named):
    """The three rules over surfaces already read, so the self-test can hand it seeds."""
    problems = []
    if in_use:
        for name, text in surfaces:
            for what, sentence in denials(text):
                problems.append(f'{name} {what} while {log_named} names {len(in_use)} in use: '
                                f'"{sentence[:160]}"')
    else:
        problems.append(f'{log_named} names no server of ours in use, so the live run asks nobody. '
                        f'That is a failure and not a pass: every other rule here is about those servers')

    flat_readme = words(readme)
    for address, _ in in_use:
        if address not in flat_readme:
            problems.append(f'README.md does not name {address}, which {log_named} names in use, so a '
                            f'reader of the badge is not told which servers of ours it watches')

    code = yaml_code(live)
    for needed, what in LIVE_NEEDS:
        if needed not in code:
            problems.append(f'{LIVE} {what}: "{needed}" is not in any line of it that runs')
    return problems


def surfaces_of_this_tree():
    named = [('README.md', words(read('README.md')))]
    for doc in sorted((ROOT / 'docs').glob('*.md')):
        named.append((f'docs/{doc.name}', words(doc.read_text(encoding='utf-8'))))
    named.append((LIVE, yaml_words(read(LIVE))))
    return named


def self_test():
    """Each rule, seeded one at a time into the real files, and watched refusing for its own reason.

    A check that passes on a tree it was written against has shown nothing about a tree it was not.
    So each seed below is a real surface with one thing changed, and each has to be refused with the
    words its rule prints. Two controls go the other way: the real tree with a log naming no servers
    has to be refused as a log that asks nobody, and a sentence that mentions a server of ours without
    denying it has to pass, because a check that refuses every mention is as useless as one that
    refuses none.
    """
    log = read(KEY_LOG)
    in_use = servers(log)
    if not in_use:
        print(f'FAIL  {KEY_LOG} names no server in use, so there is nothing to seed against')
        return 1
    readme, live = read('README.md'), read(LIVE)
    base = [('README.md', words(readme)), (LIVE, yaml_words(live))]
    first = in_use[0][0]
    one_live_line = next(needed for needed, _ in LIVE_NEEDS)

    def said(sentence):
        return [(n, t + ' ' + sentence) if n == 'README.md' else (n, t) for n, t in base]

    seeds = [
        ('the README said none is deployed',
         said('Three tests that need a Roughtime server of ours are not run, because none is deployed.'),
         readme, live, 'says none is deployed'),
        ('the site said no server of ours runs',
         base + [('the site', 'No server of ours is running yet.')], readme, live,
         'says no server of ours is there'),
        ('the list said ours are not yet deployed',
         base + [('docs/x.md', 'Our two Roughtime servers are not yet deployed.')], readme, live,
         'says a server of ours is not deployed'),
        ('the workflow said the tests are not run',
         base + [(LIVE, 'The tests that need a server of ours are not run.')], readme, live,
         'is not run'),
        ('the README stopped naming a server',
         base, readme.replace(first, 'a server'), live, f'does not name {first}'),
        ('the workflow stopped fetching the served log',
         base, readme, live.replace(one_live_line, 'example.org/nothing.txt'),
         'does not fetch the served key log'),
        ('the workflow says it but only in a comment',
         base, readme, re.sub(r'(?m)^(\s*)(.*TIMEWITNESS_PROBE_KEY_LOG=)', r'\1# \2', live),
         'does not ask every server the log names'),
    ]

    failures = 0
    for name, surfaces, seeded_readme, seeded_live, reason in seeds:
        problems = check(surfaces, seeded_readme, seeded_live, in_use, KEY_LOG)
        ok = any(reason in p for p in problems)
        failures += not ok
        print(f'{"ok  " if ok else "FAIL"}  {name}: {problems[0][:110] if problems else "nothing refused"}')

    problems = check(base, readme, live, [], 'an empty log')
    ok = any('names no server of ours in use' in p for p in problems)
    failures += not ok
    print(f'{"ok  " if ok else "FAIL"}  a log naming no server in use is refused, not passed')

    mention = 'A server of ours is not an independent chance to be wrong. Our two Roughtime servers answer.'
    problems = check(said(mention), readme, live, in_use, KEY_LOG)
    ok = not any(mention[:30] in p for p in problems)
    failures += not ok
    print(f'{"ok  " if ok else "FAIL"}  a sentence naming our servers without denying them passes')

    retired = log + f'\nentry retired {in_use[0][1]} 1 - retired\n'
    ok = [a for a, _ in servers(retired)] == [a for a, _ in in_use[1:]]
    failures += not ok
    print(f'{"ok  " if ok else "FAIL"}  a retired server key is not asked')

    print(f'our servers: {failures} of the controls above failed')
    return 1 if failures else 0


def main(argv):
    if argv[:1] == ['--self-test']:
        return self_test()
    if argv[:1] == ['--list']:
        if len(argv) != 2:
            print(__doc__, file=sys.stderr)
            return 2
        try:
            named = servers(read(argv[1]))
        except (OSError, ValueError) as error:
            print(f'our servers: the key log at {argv[1]} could not be read: {error}', file=sys.stderr)
            return 2
        # Bytes rather than print, because print on Windows ends a line with a carriage return and
        # `read` in Git Bash then hands the test a key sixty-five characters long.
        sys.stdout.buffer.write(''.join(f'{address} {key}\n' for address, key in named).encode())
        return 0

    log_named, site, no_site = KEY_LOG, None, False
    rest = list(argv)
    while rest:
        flag = rest.pop(0)
        if flag == '--no-site':
            no_site = True
        elif flag in ('--site', '--key-log') and rest:
            if flag == '--site':
                site = rest.pop(0)
            else:
                log_named = rest.pop(0)
        else:
            print(__doc__, file=sys.stderr)
            return 2

    try:
        in_use = servers(read(log_named))
        surfaces = surfaces_of_this_tree()
        readme, live = read('README.md'), read(LIVE)
        if site:
            surfaces.append((site, page_words(read(site))))
        elif not no_site:
            if not SITE.is_dir():
                print(f'our servers: there is no site copy at {SITE}, so the site was compared with '
                      f'nothing. That is a failure and not a skip; --no-site says it is deliberate',
                      file=sys.stderr)
                return 2
            for copy in sorted(SITE.glob('*.json')):
                surfaces.append((f'the site\'s {copy.name}', json_words(copy.read_text(encoding='utf-8'))))
    except (OSError, ValueError) as error:
        print(f'our servers: a surface or the key log could not be read: {error}', file=sys.stderr)
        return 2

    problems = check(surfaces, readme, live, in_use, log_named)
    for problem in problems:
        print('our servers: ' + problem, file=sys.stderr)
    if problems:
        print(f'our servers: {len(problems)} disagreements with {log_named}', file=sys.stderr)
        return 1
    print(f'our servers: {log_named} names {len(in_use)} in use, '
          + ', '.join(address for address, _ in in_use)
          + f'; {len(surfaces)} surfaces read and none says otherwise, the README names each, '
          f'and {LIVE} asks each under the key the served log names')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
