#!/usr/bin/env python3
"""Every sentence on a surface has to agree with the policy this tree ships.

`scripts/three-surfaces.sh` holds the limitation list, the README and the site to each other, and
it was green on 2026-09-15 over four faults at once, because each of them said the same wrong thing
on every surface. The site called the width of a receipt outside-vouched while every receipt this
code issues rests on its own model. Five places called a machine that reaches only Roughtime seconds
wide while the operator floor refuses it. The list said the shipped default refuses over 250 ms while
the one-shot command signed up to 30 s. A twin can only tell you the copies match. This reads the
policy off the code and asks each sentence whether it contradicts it.

    python3 scripts/policy-sentences.py                 this tree, and the site beside it where it is on disk
    python3 scripts/policy-sentences.py --site <url>    this tree, and the pages a running site serves
    python3 scripts/policy-sentences.py --self-test     one seed per rule, each watched refused
    python3 scripts/policy-sentences.py FILE...         only the files named, for a copy of an old tree

Exit 0 where nothing contradicts the policy, 1 where something does, with the file and the sentence
named, and 2 where the policy could not be read off the code. A fact this cannot find is a failure,
because a check that has read nothing has agreed with nothing.

What it reads off the code, and nothing else:

- the operator floor, `min_operators` in `Policy::default`
- the agent's width ceiling, `max_bound_width` in `Policy::default`
- the one-shot command's ceiling, `CI_MAX_BOUND_WIDTH`, and the Action's `max-width` default, which
  have to be the same number
- how many operators stand behind the published Roughtime servers
- how many kinds of time source have a client
- whether anything outside the tests issues a receipt resting on outside signatures
- whether anything ships that lowers the floor, and whether a refusal receipt exists

What it cannot do. It reads sentences for the shapes each fault took, so a new way of saying the same
wrong thing gets past it until somebody adds the shape. A figure it has no rule for is not checked
here; `tests/check-messaging-figures.py` at the product root holds figures to the artefacts they
came from.
"""

import html
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE_BESIDE = ROOT.parent / 'timewitness-web' / 'content'

SURFACES = ['README.md', 'docs/what-timewitness-cannot-prove.md', 'docs/verifier.md', 'action.yml',
            'scripts/action-stamp.sh']
SITE_FILES = ['landing.json', 'cannot-prove.json', 'how-a-receipt-works.json', 'for-maintainers.json',
              'product-fixtures.json']
SITE_PAGES = ['/', '/cannot-prove', '/how-a-receipt-works', '/for-maintainers', '/screen']

# Keys in the site's content files that are notes to whoever edits them and never reach a page. The
# build sheds them, and `doNotSay` is the list of what not to say, so it is made of wrong sentences.
NOT_SERVED = re.compile(r'^\$|^src$|Note$|^provenance$|^departsFromSource$|^carriedLimit$|^doNotSay$|'
                        r'^claimsUsed$|^srcNote$|^gapNote$|^editorNote$|^note_?src$')

WORDS = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8,
         'nine': 9, 'ten': 10, 'twelve': 12, 'fifteen': 15, 'twenty': 20, 'thirty': 30, 'sixty': 60}


class Unreadable(Exception):
    """The policy could not be read off the code."""


def read(path):
    return (ROOT / path).read_text(encoding='utf-8')


def block(text, opener):
    """The body of the first `{ ... }` after `opener`, braces counted."""
    start = text.find(opener)
    if start < 0:
        raise Unreadable(f'no "{opener}" to read')
    at = text.index('{', start)
    depth = 0
    for i in range(at, len(text)):
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0:
                return text[at + 1:i]
    raise Unreadable(f'"{opener}" never closes')


def constant_expression(expr, known):
    """A Rust constant expression of whole numbers, known names and multiplication, evaluated."""
    expr = re.sub(r'\bas\s+\w+', '', expr)
    value = 1
    for factor in expr.split('*'):
        factor = factor.strip().replace('_', '') if factor.strip().replace('_', '').isdigit() else factor.strip()
        if factor.isdigit():
            value *= int(factor)
        elif factor in known:
            value *= known[factor]
        else:
            raise Unreadable(f'"{factor}" in "{expr}" is not a number or a name this check knows')
    return value


def the_policy():
    """Everything the sentences are held to, read off the code."""
    policy = read('crates/clock/src/policy.rs')
    default = block(policy, 'impl Default for Policy')
    floor = re.search(r'min_operators:\s*(\d+)', default)
    agent = re.search(r'max_bound_width:\s*(\d+)\s*\*\s*NANOS_PER_(MILLI|SEC)', default)
    if not floor or not agent:
        raise Unreadable('Policy::default no longer sets min_operators and max_bound_width in a form this reads')
    per = {'MILLI': 10**6, 'SEC': 10**9}

    roughtime_core = read('crates/core/src/evidence/roughtime.rs')
    radius = re.search(r'pub const MIN_RADIUS_SECONDS: u32 = (\d+);', roughtime_core)
    if not radius:
        raise Unreadable('MIN_RADIUS_SECONDS is not where this reads it')
    known = {'NANOS_PER_SEC': 10**9, 'NANOS_PER_MILLI': 10**6, 'NANOS_PER_MICRO': 10**3,
             'MIN_RADIUS_SECONDS': int(radius.group(1))}
    one_shot = re.search(r'const CI_MAX_BOUND_WIDTH: Nanos = ([^;]+);', read('crates/cli/src/stamp_cmd.rs'))
    if not one_shot:
        raise Unreadable('CI_MAX_BOUND_WIDTH is not where this reads it')
    one_shot_ns = constant_expression(one_shot.group(1), known)

    action = read('action.yml')
    max_width = re.search(r'\n  max-width:\n(?:    .*\n)*?    default: "(\d+)"', action)
    if not max_width:
        raise Unreadable('action.yml has no max-width input with a default this reads')

    names = re.findall(r'name:\s*"([^"]+)"', block(roughtime_core, 'pub fn published_keys()'))
    if not names:
        raise Unreadable('published_keys() names no Roughtime server this reads')
    overrides = dict(re.findall(r'server\.name == "([^"]+)"\s*\{\s*server\.operated_by\("([^"]+)"\)',
                                read('crates/sources/src/roughtime.rs')))
    operators = {overrides.get(n, '.'.join(n.split('.')[-2:])) for n in names}

    sources = ROOT / 'crates' / 'sources' / 'src'
    kinds = sum(p.read_text(encoding='utf-8').count('impl TimeSource for') for p in sources.glob('*.rs'))

    # A receipt rests on outside signatures only where something sets that basis. The two files
    # allowed to name it are the one that reads and writes the word and the one that judges it.
    sandwich_setters = []
    for path in (ROOT / 'crates').glob('*/src/**/*.rs'):
        rel = path.relative_to(ROOT).as_posix()
        if rel in ('crates/receipt/src/schema.rs', 'crates/receipt/src/validate.rs'):
            continue
        if 'EpsilonBasis::ThirdPartySandwich' in path.read_text(encoding='utf-8'):
            sandwich_setters.append(rel)

    cli = ''.join(p.read_text(encoding='utf-8') for p in (ROOT / 'crates' / 'cli' / 'src').glob('*.rs'))
    inputs = re.findall(r'^  ([a-z-]+):\s*$', action.split('\noutputs:')[0], re.M)
    floor_lowerable = '--min-operators' in cli or any('operator' in i for i in inputs)
    # `Refusal` in the core crate is the return value a refusal is today, and not a receipt: nothing
    # signs it and nothing carries it anywhere. A receipt of one would be a type of its own.
    refusal_receipt = any(re.search(r'struct RefusalReceipt|fn refusal_receipt', p.read_text(encoding='utf-8'))
                          for p in (ROOT / 'crates').glob('*/src/**/*.rs'))

    return {
        'floor': int(floor.group(1)),
        'agent_ns': int(agent.group(1)) * per[agent.group(2)],
        'one_shot_ns': one_shot_ns,
        'action_ns': int(max_width.group(1)),
        'roughtime_operators': len(operators),
        'kinds': kinds,
        'local_model_only': not sandwich_setters,
        'floor_lowerable': floor_lowerable,
        'refusal_receipt': refusal_receipt,
    }


def words_of(text):
    return ' '.join(text.replace('**', '').replace('`', '').split())


def sentences(text):
    return [s for s in re.split(r'(?<=[.!?:;])\s+(?=[A-Z0-9])', words_of(text)) if s]


def markdown_text(text, list_file):
    # The version notes at the head of the limitation list are its history, and history is allowed
    # to quote what used to be true. Everything from the first heading down is the list itself.
    if list_file:
        at = text.find('\n## ')
        text = text[at:] if at >= 0 else text
    return text


def yaml_text(text):
    return '\n'.join(line.strip() for line in text.splitlines()
                     if not line.strip().startswith('#') and not line.strip().startswith('run:'))


def summary_text(text):
    return '\n'.join(m.group(1) for m in re.finditer(r'echo "([^"]*)"', text))


def site_strings(node, key=''):
    if isinstance(node, dict):
        if node.get('name') == 'max-width' and 'default' in node:
            yield ('max-width input', f'max-width default {node["default"]} ns. {node.get("body", "")}')
        for k, v in node.items():
            if not NOT_SERVED.search(k):
                yield from site_strings(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from site_strings(v, key)
    elif isinstance(node, str):
        yield (key, node)


def served_text(url):
    page = urllib.request.urlopen(url, timeout=30).read().decode('utf-8')
    body = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', page)
    return html.unescape(re.sub(r'<[^>]+>', ' ', body))


def duration_ns(number, unit):
    value = float(WORDS.get(number.lower(), number)) if not re.match(r'[\d.]+$', number) else float(number)
    return round(value * {'ms': 10**6, 's': 10**9, 'second': 10**9, 'seconds': 10**9}[unit])


NEGATED_BEFORE = re.compile(r"\b(?:no|not|never|nothing|none|nor|cannot)\b|n't\b", re.I)
ROUGHTIME_ONLY = re.compile(r'\bonly\b[^.,;]{0,30}?\bRoughtime\b(?! signs)|Roughtime alone|'
                            r'cannot reach an NTP server', re.I)
PRESENT_SECONDS = re.compile(r'\b(?:is|are) seconds\b|\bseconds wide\b|\bstill reaches\b|\bSeconds is still\b|'
                             r'\bcan honestly (?:reach|do)\b|\bseconds on one\b|'
                             r'\babout [\d.]+ s where only\b', re.I)
HISTORY = re.compile(r'refus|\bfloor\b|\bwould be\b|\bbefore 2026|\buntil 2026|\bhistory\b|\bno receipt\b|'
                     r'\bgets no\b|^Measured\b', re.I)
LOWERING = re.compile(r'\blower(?:s|ing)? (?:the|its) floor\b|\bone line of configuration\b', re.I)
# Each has one group, the word the claim turns on, and a negation is looked for in the clause before
# that word rather than anywhere in the sentence: "does not vouch for the bound" is the honest
# sentence and "who have never heard of us that supports it" is the fault.
VOUCHING = [re.compile(p, re.I) for p in (
    r'evidence[^.;]{0,80}?\b(supporting|for) (?:that|the|its|this) (?:bound|width|second number|interval)\b',
    r'\b(vouch)(?:es)? for (?:that|the|its|this) (?:second number|bound|width|interval)\b',
    r'evidence[^.;]{0,120}?\bthat (supports) it\b',
    r'\bhow wrong it could be,? and (proves) it\b',
    r'\breceipt anyone (can) check without trusting\b',
    r'\b(makes) the bound checkable\b',
)]
# The product's own phrase for a third party, which carries a "never" that negates nothing.
NEVER_HEARD = re.compile(r'\bwho (?:have|has) never heard of (?:us|this product)\b', re.I)
ONE_SOURCE = re.compile(r'\bno ordinary time sources\b|\bonly the corridor\b|'
                        r'\b(?:one|a single) (?:time )?source (?:client|kind)\b', re.I)
REFUSAL_RECEIPT = re.compile(r'\ba refusal receipt (?:records|says|shows|is signed|proves)\b', re.I)
CEILING = re.compile(r'(?:refuses? (?:any|an|one)(?: interval| bound| width)? wider than|'
                     r'raises (?:that|it) to|ceiling (?:of|is|at)) ([\d.]+) ?(ms|s)\b|'
                     r'\b([\d.]+) ?(ms|s) ceiling\b', re.I)
AGENT = re.compile(r'\bagent\b|\buptime\b|\bcadence\b', re.I)
ONE_SHOT = re.compile(r'one-shot|\bAction\b|\bstamp command\b|\brunner\b|\bworkflow\b|max-width', re.I)
MAX_WIDTH_DEFAULT = re.compile(r'\bdefault (?:of |is )?(?:the )?([\d.]+|' + '|'.join(WORDS) +
                               r') ?(seconds|second|ms|s)\b|\bso (' + '|'.join(WORDS) + r') seconds\b', re.I)


def negated(sentence, match, group=0):
    """Whether the clause leading up to the word the claim turns on carries a negation."""
    anchor = match.start(group) if group else match.start()
    before = sentence[:anchor]
    clause = max(before.rfind(','), before.rfind(';'), before.rfind(':'), before.rfind('('))
    return bool(NEGATED_BEFORE.search(before[clause + 1:]))


def judge(sentence, policy, landing=None):
    """What is wrong with one sentence against the policy, or nothing."""
    faults = []
    floor, rt = policy['floor'], policy['roughtime_operators']

    if ROUGHTIME_ONLY.search(sentence):
        if rt < floor and PRESENT_SECONDS.search(sentence) and not HISTORY.search(sentence):
            faults.append(f'calls the Roughtime-only round seconds wide, and it is refused: the published '
                          f'Roughtime servers are {rt} operators and the floor is {floor}')
        if rt >= floor and re.search(r'refus', sentence, re.I):
            faults.append(f'says the Roughtime-only round is refused, and {rt} operators clear the floor of {floor}')

    if not policy['floor_lowerable']:
        for m in LOWERING.finditer(sentence):
            if not negated(sentence, m):
                faults.append('says the operator floor can be lowered, and no option or input that ships lowers it')

    if policy['local_model_only']:
        plain = NEVER_HEARD.sub('who are strangers to us', sentence)
        for rule in VOUCHING:
            m = rule.search(plain)
            if m and not negated(plain, m, 1):
                faults.append('says outside evidence supports the width, and every receipt this code issues '
                              'rests on its own model')
                break

    if policy['kinds'] >= 2:
        m = ONE_SOURCE.search(sentence)
        if m and not negated(sentence, m):
            faults.append(f'speaks of one kind of time source, and {policy["kinds"]} have a client')

    if not policy['refusal_receipt']:
        m = REFUSAL_RECEIPT.search(sentence)
        if m and not negated(sentence, m):
            faults.append('says a refusal receipt records something, and there is no refusal receipt')

    for m in CEILING.finditer(sentence):
        number, unit = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        value = duration_ns(number, unit.lower())
        before = sentence[:m.start()]
        # Whose ceiling the figure is, read off the nearest subject before it in the sentence, and
        # off the whole sentence where nothing comes before it.
        agent_at = max((a.end() for a in AGENT.finditer(before)), default=-1)
        shot_at = max((a.end() for a in ONE_SHOT.finditer(before)), default=-1)
        if agent_at < 0 and shot_at < 0:
            agent_at = 0 if AGENT.search(sentence) else -1
            shot_at = 0 if ONE_SHOT.search(sentence) else -1
        if agent_at < 0 and shot_at < 0:
            faults.append(f'states a ceiling of {number} {unit} without saying whose; the agent refuses '
                          f'over {policy["agent_ns"] / 1e6:g} ms and the one-shot command over '
                          f'{policy["one_shot_ns"] / 1e9:g} s')
        elif agent_at >= shot_at and value != policy['agent_ns']:
            faults.append(f'puts the agent\'s ceiling at {number} {unit}, and it is {policy["agent_ns"] / 1e6:g} ms')
        elif shot_at > agent_at and value != policy['one_shot_ns']:
            faults.append(f'puts the one-shot ceiling at {number} {unit}, and it is {policy["one_shot_ns"] / 1e9:g} s')

    if 'max-width' in sentence:
        for m in MAX_WIDTH_DEFAULT.finditer(sentence):
            number = m.group(1) or m.group(3)
            unit = (m.group(2) or 'seconds').lower()
            if duration_ns(number, unit) != policy['one_shot_ns']:
                faults.append(f'gives max-width a default of {number} {unit}, and it is '
                              f'{policy["one_shot_ns"] / 1e9:g} s')
        stated = re.search(r'max-width default (\d+) ns', sentence)
        if stated and int(stated.group(1)) != policy['one_shot_ns']:
            faults.append(f'gives max-width a default of {stated.group(1)} ns, and it is {policy["one_shot_ns"]} ns')

    if landing is not None and re.search(r'\bfront page says four to six\b', sentence, re.I) \
            and 'four to six' not in landing:
        faults.append('says the front page claims four to six independent sources, and the front page does not')
    return faults


def surfaces(files, site):
    """Every sentence to read, with where it came from."""
    out = []
    for path in files:
        full = Path(path) if Path(path).is_absolute() else ROOT / path
        text = full.read_text(encoding='utf-8')
        name = full.name
        if name.endswith('.md'):
            text = markdown_text(text, 'cannot-prove' in name)
        elif name.endswith('.yml'):
            text = yaml_text(text)
        elif name.endswith('.sh'):
            text = summary_text(text)
        elif name.endswith('.json'):
            text = '\n\n'.join(s for _, s in site_strings(json.loads(text)))
        out += [(path, s) for s in sentences(text)]
    landing = None
    if site and site.startswith('http'):
        for page in SITE_PAGES:
            text = served_text(site.rstrip('/') + page)
            if page == '/':
                landing = text
            out += [(site.rstrip('/') + page, s) for s in sentences(text)]
    elif site:
        base = Path(site)
        for name in SITE_FILES:
            data = json.loads((base / name).read_text(encoding='utf-8'))
            strings = [s for _, s in site_strings(data)]
            if name == 'landing.json':
                landing = ' '.join(strings)
            out += [(f'{base.name}/{name}', s) for text in strings for s in sentences(text)]
    return out, landing


# One seed per rule, each the sentence the fault actually took on a served or shipped surface
# before 2026-09-15, and each has to be refused by the rule it is here for.
SEEDS = [
    ('Roughtime-only round seconds wide', 'A machine that can only reach public Roughtime servers is seconds wide rather than milliseconds, because a Roughtime server states its own uncertainty as a radius in whole seconds and nothing narrows that.'),
    ('Roughtime-only round seconds wide', 'A runner that reaches only the public Roughtime servers is seconds wide whatever else is done to it.'),
    ('operator floor can be lowered', 'Lowering the floor is one line of configuration and it is deliberately not the default.'),
    ('outside evidence supports the width', 'The receipt holds signed evidence from independent outside sources supporting that bound.'),
    ('outside evidence supports the width', 'TimeWitness says: at this local counter reading, UTC was somewhere in this interval, and here is signed evidence from three parties who have never heard of us that supports it.'),
    ('one kind of time source', 'Today there are no ordinary time sources here, only the corridor, which is why the bound is seconds and not milliseconds.'),
    ('a refusal receipt records', 'A refusal receipt records that TimeWitness declined to sign.'),
    ('a ceiling without saying whose', 'The shipped default refuses any interval wider than 250 ms, and the GitHub Action raises that to 30 s, which is headroom and not a measurement.'),
    ('max-width default', 'The default of thirty seconds on max-width is what a runner reaching only public Roughtime servers can honestly do.'),
]


def self_test(policy):
    missed = []
    for rule, seed in SEEDS:
        faults = judge(seed, policy)
        if not faults:
            missed.append(f'the seed for "{rule}" passed: {seed}')
    for line in missed:
        print('policy sentences: ' + line, file=sys.stderr)
    if missed:
        return 1
    # The sentences that replaced them, which have to pass, so a rule wide enough to refuse
    # everything cannot pass this test either.
    for honest in ('A machine that can reach only the three public Roughtime servers reaches three operators, which is under the shipped floor of four, so it refuses to sign, and nothing that ships lowers the floor.',
                   'The resident agent refuses any interval wider than 250 ms, and the one-shot command, which the GitHub Action runs, refuses one wider than 2 s.',
                   'Every receipt this product issues says its bound rests on the agent\'s own model, so no receipt yet carries third-party signed evidence for its bound.',
                   'There is no refusal receipt.'):
        faults = judge(honest, policy)
        if faults:
            print(f'policy sentences: an honest sentence was refused ({"; ".join(faults)}): {honest}', file=sys.stderr)
            return 1
    print(f'policy sentences: {len(SEEDS)} seeds, each refused by its own rule, and four honest sentences passed')
    return 0


def main(argv):
    try:
        policy = the_policy()
    except (Unreadable, OSError) as e:
        print(f'policy sentences: the policy could not be read off the code: {e}', file=sys.stderr)
        return 2
    if policy['one_shot_ns'] != policy['action_ns']:
        print(f'policy sentences: the one-shot command defaults to {policy["one_shot_ns"]} ns and the Action\'s '
              f'max-width to {policy["action_ns"]} ns, and they are meant to be one number', file=sys.stderr)
        return 1
    if '--self-test' in argv:
        return self_test(policy)

    site = None
    files = [a for a in argv if not a.startswith('--')]
    if '--site' in argv:
        site = argv[argv.index('--site') + 1]
        files = [a for a in files if a != site]
    if not files:
        files = SURFACES
        if site is None and SITE_BESIDE.is_dir():
            site = str(SITE_BESIDE)

    read_from, landing = surfaces(files, site)
    problems = []
    for where, sentence in read_from:
        for fault in judge(sentence, policy, landing):
            problems.append(f'{where}: {fault}:\n    "{sentence[:220]}"')
    for p in problems:
        print('policy sentences: ' + p, file=sys.stderr)
    said = (f'floor {policy["floor"]}, {policy["roughtime_operators"]} Roughtime operators, agent '
            f'{policy["agent_ns"] / 1e6:g} ms, one-shot {policy["one_shot_ns"] / 1e9:g} s, '
            f'{policy["kinds"]} source kinds, ' + ('every receipt on its own model' if policy['local_model_only']
                                                     else 'a receipt can rest on outside signatures'))
    if problems:
        print(f'policy sentences: {len(problems)} sentences contradict the shipped policy ({said})', file=sys.stderr)
        return 1
    where = 'and no site' if site is None else f'and the site at {site}'
    print(f'policy sentences: {len(read_from)} sentences over {len(files)} files {where} agree with the '
          f'shipped policy ({said})')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
