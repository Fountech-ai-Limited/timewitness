#!/usr/bin/env python3
"""Every sentence on a surface has to agree with the policy this tree ships.

`scripts/three-surfaces.sh` holds the limitation list, the README and the site to each other, and
it was green on 2026-09-15 over four faults at once, because each of them said the same wrong thing
on every surface. The site called the width of a receipt outside-vouched while every receipt this
code issues rests on its own model. Five places called a machine that reaches only Roughtime seconds
wide while the operator floor refuses it. The list said the shipped default refuses over 250 ms while
the one-shot command signed up to 30 s. A twin can only tell you the copies match. This reads the
policy off the code and asks each sentence whether it contradicts it.

    python3 scripts/policy-sentences.py                 this tree, and the site beside it
    python3 scripts/policy-sentences.py --no-site       this tree alone, said on purpose
    python3 scripts/policy-sentences.py --site <url>    this tree, and the pages a running site serves
    python3 scripts/policy-sentences.py --self-test     seeds per rule and per shape, each watched refused
    python3 scripts/policy-sentences.py FILE...         only the files named, for a copy of an old tree

Exit 0 where nothing contradicts the policy, 1 where something does, with the file and the sentence
named, and 2 where the policy could not be read off the code or a surface could not be read. A fact
this cannot find is a failure, and so is a surface that is missing, empty or short of the floor of
sentences it yields, because a check that has read nothing has agreed with nothing. The site beside
this tree is a surface: absent, it is a failure unless --no-site says its absence is deliberate. On
2026-09-15 an emptied README, a landing file set to {}, and the site not beside all passed.

What it reads off the code, and nothing else:

- the operator floor, `min_operators` in `Policy::default`
- the agent's width ceiling, `max_bound_width` in `Policy::default`
- the one-shot command's ceiling, `CI_MAX_BOUND_WIDTH`, and the Action's `max-width` default, which
  have to be the same number
- how many operators stand behind the published Roughtime servers
- how many kinds of time source have a client, counted as `impl TimeSource for` anywhere under
  `crates/sources/src`
- whether anything outside the tests issues a receipt resting on outside signatures
- whether anything ships that lowers the floor, and whether a refusal receipt exists

Every one of those is held to the sentences. A sentence stating the floor, the Roughtime operator
count or the kind count wrongly is refused, and so is one saying the Roughtime-only round is signed,
that the floor can be lowered, that outside evidence backs the width, that a refusal receipt exists,
or a ceiling or a max-width default that is not the code's. Each rule is written for the claim rather
than for one wording of it: a number in digits or in words, the verb in any of its forms, and the
passive as well as the active. Until the evening of 2026-09-15 three of the facts were read and held
nothing, and each of the other shapes was matched on the one sentence it was written from, so "at
least two operators" and "the outside signatures back up the width" passed on every surface.

What it cannot do. A sentence that says the wrong thing in a form none of the rules describes gets
past it, and somebody adds the form. A figure it has no rule for is not checked here;
`tests/check-messaging-figures.py` at the product root holds figures to the artefacts they came from.

Served pages are read as text and as the attributes a reader is given without seeing the page: the
meta description, every alt, title and aria-label, and the page title. Until 2026-09-15 served mode
stripped attributes, so the sentence that called our width outside-vouched passed in an alt.
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

# The fewest sentences a surface can yield and count as read. The smallest surface, the Action's
# job summary, yields nineteen; an emptied file yields none.
SENTENCE_FLOOR = 5

# Keys in the site's content files that are notes to whoever edits them and never reach a page. The
# build sheds them, and `doNotSay` is the list of what not to say, so it is made of wrong sentences.
NOT_SERVED = re.compile(r'^\$|^src$|Note$|^provenance$|^departsFromSource$|^carriedLimit$|^doNotSay$|'
                        r'^claimsUsed$|^srcNote$|^gapNote$|^editorNote$|^note_?src$')

WORDS = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8,
         'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12, 'fifteen': 15, 'sixteen': 16, 'twenty': 20,
         'thirty': 30, 'forty': 40, 'fifty': 50, 'sixty': 60, 'ninety': 90, 'hundred': 100}
# A count, in digits or in words, as sentences about operators and kinds write it.
COUNT = r'(?:\d+|' + '|'.join(WORDS) + r'|a single|single)'
# A duration's number, which can also be "a", "an", "half a" or "a quarter of a".
AMOUNT = (r'(?:\d+(?:\.\d+)?|half an?|a quarter of an?|an?|(?:' + '|'.join(WORDS) + r')(?:-(?:'
          + '|'.join(WORDS) + r'))?)')
UNIT = r'(ms|milliseconds?|s|seconds?)'


class Unreadable(Exception):
    """The policy or a surface could not be read."""


def read(path):
    full = ROOT / path
    if not full.is_file():
        raise Unreadable(f'{path} is not there')
    return full.read_text(encoding='utf-8')


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

    # Counted wherever the client sits under the crate, not only at its top level: on 2026-09-15
    # two clients moved one folder down and the count read one.
    sources = ROOT / 'crates' / 'sources' / 'src'
    if not sources.is_dir():
        raise Unreadable('crates/sources/src is not there, so the source kinds cannot be counted')
    kinds = sum(p.read_text(encoding='utf-8').count('impl TimeSource for') for p in sources.rglob('*.rs'))
    if kinds == 0:
        raise Unreadable('no "impl TimeSource for" anywhere under crates/sources/src, so the source kinds cannot be counted')

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
    # A blank line ends a sentence whatever punctuation came before it, so the job summary's echo
    # lines and a content file's strings are read one at a time rather than run together into one
    # sentence that names nothing when it is refused.
    out = []
    for paragraph in re.split(r'\n\s*\n', text):
        out += [s for s in re.split(r'(?<=[.!?:;])\s+(?=[A-Z0-9])', words_of(paragraph)) if s]
    return out


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
    return '\n\n'.join(m.group(1) for m in re.finditer(r'echo "([^"]*)"', text))


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


# What a served page says to a reader who is not shown the page: the description a search result
# quotes, the alt a screen reader speaks, a title or label a pointer shows.
ATTRIBUTE_TEXT = re.compile(r'<meta\b[^>]*\b(?:name|property)="(?:description|og:description|twitter:description)"[^>]*'
                            r'\bcontent="([^"]*)"|<meta\b[^>]*\bcontent="([^"]*)"[^>]*'
                            r'\b(?:name|property)="(?:description|og:description|twitter:description)"|'
                            r'\b(?:alt|title|aria-label)="([^"]*)"|<title\b[^>]*>([^<]*)</title>', re.I)


def served_text(url):
    page = urllib.request.urlopen(url, timeout=30).read().decode('utf-8')
    body = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', page)
    spoken = [html.unescape(next(g for g in m.groups() if g is not None)) for m in ATTRIBUTE_TEXT.finditer(body)]
    text = html.unescape(re.sub(r'<[^>]+>', ' ', body))
    return text + '\n\n' + '\n\n'.join(s for s in spoken if s.strip())


def number_of(token):
    """A count or an amount written in digits or in words, as a number."""
    token = token.strip().lower()
    if re.match(r'[\d.]+$', token):
        return float(token)
    if token in ('a', 'an', 'a single', 'single'):
        return 1.0
    if token.startswith('half'):
        return 0.5
    if token.startswith('a quarter'):
        return 0.25
    total = 0
    for part in token.split('-'):
        if part not in WORDS:
            raise ValueError(token)
        total += WORDS[part]
    return float(total)


def duration_ns(number, unit):
    return round(number_of(number) * {'ms': 10**6, 'millisecond': 10**6, 'milliseconds': 10**6,
                                      's': 10**9, 'second': 10**9, 'seconds': 10**9}[unit.lower()])


NEGATED_BEFORE = re.compile(r"\b(?:no|not|never|nothing|none|nor|cannot|without)\b|n't\b", re.I)
ROUGHTIME_ONLY = re.compile(r'\bonly\b[^.,;]{0,30}?\bRoughtime\b(?! signs)|Roughtime alone|'
                            r'cannot reach an NTP server', re.I)
PRESENT_SECONDS = re.compile(r'\b(?:is|are) seconds\b|\bseconds wide\b|\bstill reaches\b|\bSeconds is still\b|'
                             r'\bcan honestly (?:reach|do)\b|\bseconds on one\b|'
                             r'\babout [\d.]+ s where only\b', re.I)
# A Roughtime-only round said to be signed, in the forms that claim takes.
ROUGHTIME_SIGNED = re.compile(r'\bclears? the floor\b|\bis signed\b|\bgets? a receipt\b|\bstill signs\b|'
                              r'\bsigns anyway\b|\bis enough\b|\benough for a receipt\b|\bis accepted\b', re.I)
HISTORY = re.compile(r'refus|\bfloor\b|\bwould be\b|\bbefore 2026|\buntil 2026|\bhistory\b|\bno receipt\b|'
                     r'\bgets no\b|^Measured\b', re.I)
LOWERING = re.compile(r'\b(?:lower|drop|reduce|relax|override|change|turn down|set)(?:s|ing|ed)? (?:the|its|that|this|our) '
                      r'(?:operator |independence )?floor\b|'
                      r'\bfloor (?:can|may|could|might) be (?:lowered|dropped|reduced|relaxed|set|changed|overridden|configured)\b|'
                      r'\bfloor is (?:configurable|adjustable|a setting|an option|a flag|yours to set)\b|'
                      r'\bone line of configuration\b|--min-operators|\bmin-operators input\b', re.I)
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
    # Outside parties said to stand behind the width, whichever verb carries it.
    r'\b(?:(?:outside|third.party|independent|external|their|signed)\s+(?:evidence|signatures?|parties|witnesses|attestations?)|signers)\b'
    r'[^.;]{0,40}?\b(backs?|back up|backing|supports?|vouch(?:es)? for|underwrites?|confirms?|attests?(?: to)?|corroborates?|proves?|'
    r'stands? behind|guarantees?|verif(?:y|ies)|certif(?:y|ies))\b[^.;]{0,25}?\b(?:the|that|its|our|this) (?:bound|width|interval|claim|second number)\b',
    # The passive.
    r'\b(?:bound|width|interval|second number)\b[^.;]{0,20}?\b(?:is|are|was|were|gets?) (backed|supported|vouched for|underwritten|confirmed|'
    r'attested|corroborated|proved|proven|verified|guaranteed|certified) by\b',
    # What a receipt is said to rest on, in the present tense. A bound "resting on" outside evidence
    # is the target the surfaces name and is not this.
    r'\b(?:receipts?|the (?:bound|width|interval|second number)|its (?:bound|width)|every receipt|each receipt)\b[^.;]{0,30}?'
    r'\b(rests?) on (?:the |its |their )?(?:third.party|outside|independent|external|signed|signers\'?)\b',
)]
# The product's own phrase for a third party, which carries a "never" that negates nothing.
NEVER_HEARD = re.compile(r'\bwho (?:have|has) never heard of (?:us|this product)\b', re.I)
ONE_SOURCE = re.compile(r'\bno ordinary time sources\b|\bonly the corridor\b|'
                        r'\b(?:one|a single) (?:time )?source (?:client|kind)\b|'
                        r'\b(?:only|just) (?:one|a single) (?:kind|sort|type) of (?:time )?source\b|'
                        r'\b(?:only|just) (?:Roughtime|NTP|NTS)\b[^.;]{0,20}?\bhas a client\b|'
                        r'\b(?:Roughtime|NTP|NTS) has the only client\b|\bthe only (?:time )?(?:source )?client\b', re.I)
# A count of the kinds that have a client, which is the count the code gives, and not a count of
# the kinds in one round or of the variants an enum has.
KIND_COUNT = [re.compile(p, re.I) for p in (
    r'\b(' + COUNT + r') (?:kinds?|sorts?|types?) of (?:time )?sources?\b[^.;]{0,40}?\b(?:have|has|with|got|have got) (?:a |their own |its own )?clients?\b',
    r'\b(' + COUNT + r') source (?:kinds?|clients?)\b[^.;]{0,30}?\b(?:have|has|with|exist|are built|are implemented|in this repository|here)\b',
    r'\b(' + COUNT + r') (?:kinds?|sorts?|types?) (?:of (?:time )?sources? )?(?:this product|the product|the agent|it|this repository|the tree) (?:speaks|knows|polls|supports|implements|has|carries)\b',
    r'\b(?:this repository|the repository|the tree|the code|the agent|this product|the product|it) (?:speaks|has|carries|holds|implements|polls|knows) (' + COUNT + r') (?:kinds?|sorts?|types?) of (?:time )?sources?\b',
    r'\b(?:only|just) (' + COUNT + r') (?:kinds?|sorts?|types?) of (?:time )?sources?\b',
)]
# The count of operators behind the published Roughtime servers, stated as such.
ROUGHTIME_COUNT = [re.compile(p, re.I) for p in (
    r'\b(?:public|published|three|3) Roughtime servers?\b[^.;]{0,60}?\b(' + COUNT + r') (?:independent |distinct |different )?operators\b',
    r'\b(' + COUNT + r') (?:independent |distinct |different )?Roughtime operators\b',
    r'\bRoughtime\b[^.;]{0,40}?\b(?:run|operated|owned) by (' + COUNT + r')\b',
    r'\bRoughtime (?:alone|only)\b[^.;]{0,30}?\b(?:reaches|is|gives|gets|means|counts) (' + COUNT + r') operators\b',
    r'\b(' + COUNT + r') (?:independent |distinct |different )?operators (?:run|operate|stand behind|are behind|own) the (?:public |published |three )?Roughtime servers\b',
)]
# The floor, wherever a sentence states it as a number.
FLOOR_COUNT = [re.compile(p, re.I) for p in (
    r'\bfloor (?:of|is|at|sits at|stays at|was|remains|stands at) (' + COUNT + r')\b(?!\s*(?:ms|s|us|ns|seconds?|milliseconds?)\b)',
    r'\b(' + COUNT + r') (?:independent |distinct |different )?operators (?:is|are|were|would be|will) (?:the )?(?:floor|minimum|enough|sufficient|all it takes|required|needed|what it takes|plenty|do|suffice)\b',
    r'\b(' + COUNT + r') (?:independent |distinct |different )?operators (?:suffices?|will do)\b',
    r'\b(?:at least|no fewer than|a minimum of|fewer than|under|below|short of|needs?|requires?|takes?|wants?|before) (' + COUNT + r') (?:independent |distinct |different )?operators\b',
    r'\b(?:at least|no fewer than|fewer than|a minimum of|minimum of) (' + COUNT + r')\b(?!\s*(?:ms|s|us|ns|seconds?|milliseconds?|sources?|servers?|names?|kinds?|of|beacons?|parties)\b)',
    r'\b(?:minimum|floor) (?:is|of) (' + COUNT + r') (?:independent |distinct |different )?operators\b',
    r'\b(' + COUNT + r') (?:independent |distinct |different )?operators (?:must|have to|need to) (?:stand|be|answer|agree)\b',
)]
REFUSAL_RECEIPT = re.compile(r'\b(?:signed )?refusal receipts?\b', re.I)
REFUSAL_HYPOTHETICAL = re.compile(r'\bwould\b|\bif one\b|\bnot yet\b|\bis not (?:built|shipped|issued)\b|\bphrase rather than\b|'
                                  r'\bthere is no\b|\bno refusal receipt\b', re.I)
# A ceiling, in the forms a sentence gives one: refused over, up to, capped at, nothing wider than.
CEILING = re.compile(r'(?:refuses? (?:any|an|one|a)(?: interval| bound| width| receipt)? (?:wider|over|more|past|beyond) (?:than )?|'
                     r'no (?:receipt|interval|bound|width) (?:wider|more|over|past|beyond) (?:than )?|'
                     r'raises (?:that|it) to |ceiling (?:of|is|at) |(?:up to|at most|no wider than|no more than|as wide as|'
                     r'capped at|a cap of|caps? (?:the|its|a|every) (?:bound|width|interval|receipt) at|limit(?:ed|s)? (?:of|to|at)|'
                     r'nothing (?:over|wider than|narrower than|past|beyond|above)|anything (?:narrower than|under|below|inside|within|up to)|'
                     r'(?:signs?|accepts?|answers? with|hands? back|gives?)[^.;]{0,30}?\b(?:narrower than|under|below|inside|within)) )'
                     r'(' + AMOUNT + r') ?' + UNIT + r'\b|'
                     r'\b(' + AMOUNT + r') ?' + UNIT + r' (?:ceiling|cap|limit)\b|'
                     r'\b(' + AMOUNT + r') ?' + UNIT + r'\b,? (?:is|are|which is|being) the (?:widest|most|largest|ceiling|cap|limit)\b', re.I)
AGENT = re.compile(r'\bagent\b|\buptime\b|\bcadence\b', re.I)
ONE_SHOT = re.compile(r'one-shot|\bAction\b|\bstamp command\b|\brunner\b|\bworkflow\b|max-width', re.I)
MAX_WIDTH_DEFAULT = re.compile(r'\bdefault (?:of |is )?(?:the )?(' + AMOUNT + r') ?' + UNIT + r'\b|\bso (' + '|'.join(WORDS) + r') seconds\b|'
                               r'\bmax-width (?:is|of|defaults? to|comes as|ships as|ships at|starts at|sits at) (' + AMOUNT + r') ?' + UNIT + r'\b|'
                               r'\b(?:left unset|unset|out of the box|by default|if you do not set it|when nothing is set)\b[^.;]{0,30}?'
                               r'\b(' + AMOUNT + r') ?' + UNIT + r'\b', re.I)


def negated(sentence, match, group=0):
    """Whether the clause leading up to the word the claim turns on carries a negation."""
    anchor = match.start(group) if group else match.start()
    before = sentence[:anchor]
    clause = max(before.rfind(','), before.rfind(';'), before.rfind(':'), before.rfind('('))
    return bool(NEGATED_BEFORE.search(before[clause + 1:]))


def counted(match):
    """The count a rule matched, as a whole number, or nothing where it is not one this reads."""
    try:
        return int(number_of(match.group(1)))
    except ValueError:
        return None


def judge(sentence, policy, landing=None):
    """What is wrong with one sentence against the policy, or nothing."""
    faults = []
    floor, rt = policy['floor'], policy['roughtime_operators']

    if ROUGHTIME_ONLY.search(sentence):
        if rt < floor and PRESENT_SECONDS.search(sentence) and not HISTORY.search(sentence):
            faults.append(f'calls the Roughtime-only round seconds wide, and it is refused: the published '
                          f'Roughtime servers are {rt} operators and the floor is {floor}')
        m = ROUGHTIME_SIGNED.search(sentence)
        if rt < floor and m and not negated(sentence, m):
            faults.append(f'says the Roughtime-only round is signed, and it is refused: the published '
                          f'Roughtime servers are {rt} operators and the floor is {floor}')
        if rt >= floor and re.search(r'refus', sentence, re.I):
            faults.append(f'says the Roughtime-only round is refused, and {rt} operators clear the floor of {floor}')

    # The three counts, each held to the code wherever a sentence states it.
    if re.search(r'\boperator', sentence, re.I):
        for rule in FLOOR_COUNT:
            for m in rule.finditer(sentence):
                n = counted(m)
                if n is not None and n != floor:
                    faults.append(f'puts the operator floor at {n}, and it is {floor}')
                    break
            else:
                continue
            break
    if re.search(r'\bRoughtime\b', sentence) and not re.search(r'\bNTP\b|\bNTS\b', sentence):
        for rule in ROUGHTIME_COUNT:
            m = rule.search(sentence)
            if m:
                n = counted(m)
                if n is not None and n != rt:
                    faults.append(f'puts {n} operators behind the published Roughtime servers, and there are {rt}')
                break
    for rule in KIND_COUNT:
        m = rule.search(sentence)
        if m:
            n = counted(m)
            if n is not None and n != policy['kinds']:
                faults.append(f'says {n} kinds of time source have a client, and {policy["kinds"]} do')
            break

    if not policy['floor_lowerable']:
        for m in LOWERING.finditer(sentence):
            if not negated(sentence, m):
                faults.append('says the operator floor can be lowered, and no option or input that ships lowers it')
                break

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
        if m and not negated(sentence, m) and not REFUSAL_HYPOTHETICAL.search(sentence):
            faults.append('speaks of a refusal receipt as a thing that exists, and there is no refusal receipt')

    for m in CEILING.finditer(sentence):
        groups = [g for g in m.groups() if g is not None]
        number, unit = groups[0], groups[1]
        try:
            value = duration_ns(number, unit.lower())
        except ValueError:
            continue
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
            groups = [g for g in m.groups() if g is not None]
            number = groups[0]
            unit = groups[1] if len(groups) > 1 else 'seconds'
            try:
                if duration_ns(number, unit) != policy['one_shot_ns']:
                    faults.append(f'gives max-width a default of {number} {unit}, and it is '
                                  f'{policy["one_shot_ns"] / 1e9:g} s')
                    break
            except ValueError:
                continue
        stated = re.search(r'max-width default (\d+) ns', sentence)
        if stated and int(stated.group(1)) != policy['one_shot_ns']:
            faults.append(f'gives max-width a default of {stated.group(1)} ns, and it is {policy["one_shot_ns"]} ns')

    if landing is not None and re.search(r'\bfront page says four to six\b', sentence, re.I) \
            and 'four to six' not in landing:
        faults.append('says the front page claims four to six independent sources, and the front page does not')
    return faults


def enough(where, found, floor):
    """A surface that yielded fewer sentences than the floor was not read."""
    if len(found) < floor:
        raise Unreadable(f'{where} yielded {len(found)} sentences, under the floor of {floor}, so it was not read')
    return found


def surfaces(files, site, floor=SENTENCE_FLOOR):
    """Every sentence to read, with where it came from. `floor` is the fewest sentences a file may
    yield; the shipped surfaces are held to SENTENCE_FLOOR and a file named on the command line,
    which may be one seed sentence, to one."""
    out = []
    for path in files:
        full = Path(path) if Path(path).is_absolute() else ROOT / path
        if not full.is_file():
            raise Unreadable(f'{path} is not there')
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
        out += [(path, s) for s in enough(path, sentences(text), floor)]
    landing = None
    if site and site.startswith('http'):
        for page in SITE_PAGES:
            text = served_text(site.rstrip('/') + page)
            if page == '/':
                landing = text
            out += [(site.rstrip('/') + page, s) for s in enough(site.rstrip('/') + page, sentences(text), SENTENCE_FLOOR)]
    elif site:
        base = Path(site)
        if not base.is_dir():
            raise Unreadable(f'{site} is not a directory of site content')
        for name in SITE_FILES:
            file = base / name
            if not file.is_file():
                raise Unreadable(f'{base.name}/{name} is not there')
            data = json.loads(file.read_text(encoding='utf-8'))
            strings = [s for _, s in site_strings(data)]
            if name == 'landing.json':
                landing = ' '.join(strings)
            found = [s for text in strings for s in sentences(text)]
            out += [(f'{base.name}/{name}', s) for s in enough(f'{base.name}/{name}', found, SENTENCE_FLOOR)]
    return out, landing


# Seeds, each the sentence a fault took on a served or shipped surface before 2026-09-15 or a
# paraphrase of it, and each has to be refused by the rule it is here for. The paraphrases were
# added the evening of 2026-09-15, when the rotation found every rule matched only the sentence
# it was written from.
SEEDS = [
    ('Roughtime-only round seconds wide', 'A machine that can only reach public Roughtime servers is seconds wide rather than milliseconds, because a Roughtime server states its own uncertainty as a radius in whole seconds and nothing narrows that.'),
    ('Roughtime-only round seconds wide', 'A runner that reaches only the public Roughtime servers is seconds wide whatever else is done to it.'),
    ('Roughtime-only round signed', 'A machine that reaches only Roughtime clears the floor and is signed.'),
    ('Roughtime-only round signed', 'Roughtime alone is enough for a receipt.'),
    ('Roughtime-only round signed', 'With only Roughtime in reach the stamp still signs.'),
    ('operator floor can be lowered', 'Lowering the floor is one line of configuration and it is deliberately not the default.'),
    ('operator floor can be lowered', 'The floor can be lowered with a flag.'),
    ('operator floor can be lowered', 'Set the floor to two if your network reaches fewer operators.'),
    ('operator floor can be lowered', 'The operator floor is configurable.'),
    ('operator floor stated wrongly', 'The operator floor is three, so three independent operators are enough for a receipt.'),
    ('operator floor stated wrongly', 'A round needs at least two operators before anything is signed.'),
    ('operator floor stated wrongly', 'Fewer than three operators and the agent declines.'),
    ('operator floor stated wrongly', 'Five operators must stand behind every round.'),
    ('operator floor stated wrongly', 'The minimum is six operators.'),
    ('operator floor stated wrongly', 'Three independent operators are enough for a signature.'),
    ('Roughtime operator count stated wrongly', 'The published Roughtime servers are run by four independent operators, which clears the floor on its own.'),
    ('Roughtime operator count stated wrongly', 'Four operators run the public Roughtime servers, so a round of them is signed.'),
    ('Roughtime operator count stated wrongly', 'Roughtime alone reaches four operators.'),
    ('Roughtime operator count stated wrongly', 'The three published Roughtime servers belong to two operators.'),
    ('outside evidence supports the width', 'The receipt holds signed evidence from independent outside sources supporting that bound.'),
    ('outside evidence supports the width', 'TimeWitness says: at this local counter reading, UTC was somewhere in this interval, and here is signed evidence from three parties who have never heard of us that supports it.'),
    ('outside evidence supports the width', 'The outside signatures back up the width.'),
    ('outside evidence supports the width', 'Receipts rest on third-party evidence rather than on our own model.'),
    ('outside evidence supports the width', 'The width is backed by outside signatures.'),
    ('outside evidence supports the width', 'Independent parties vouch for the bound.'),
    ('outside evidence supports the width', 'Third-party evidence underwrites the width.'),
    ('outside evidence supports the width', 'The bound is corroborated by the signers.'),
    ('outside evidence supports the width', 'The signers stand behind the width.'),
    ('one kind of time source', 'Today there are no ordinary time sources here, only the corridor, which is why the bound is seconds and not milliseconds.'),
    ('one kind of time source', 'There is a single source client in this repository, Roughtime.'),
    ('one kind of time source', 'Only one kind of time source has a client in this repository.'),
    ('one kind of time source', 'Only Roughtime has a client today.'),
    ('kind count stated wrongly', 'Two kinds of time source have a client here, Roughtime and plain NTP.'),
    ('kind count stated wrongly', 'Two source kinds have clients.'),
    ('kind count stated wrongly', 'This repository speaks two kinds of time source.'),
    ('kind count stated wrongly', 'Four kinds of source have a client here.'),
    ('a refusal receipt records', 'A refusal receipt records that TimeWitness declined to sign.'),
    ('a refusal receipt records', 'The refusal receipt proves the agent declined.'),
    ('a refusal receipt records', 'A signed refusal receipt is issued when the agent declines.'),
    ('a ceiling without saying whose', 'The shipped default refuses any interval wider than 250 ms, and the GitHub Action raises that to 30 s, which is headroom and not a measurement.'),
    ('a ceiling stated wrongly', 'The resident agent refuses any interval wider than 500 ms.'),
    ('a ceiling stated wrongly', 'The agent will answer with a bound of up to half a second.'),
    ('a ceiling stated wrongly', 'The one-shot command refuses any bound wider than 30 s.'),
    ('a ceiling stated wrongly', 'The GitHub Action signs anything narrower than thirty seconds.'),
    ('a ceiling stated wrongly', 'The agent caps the bound at one second.'),
    ('a ceiling stated wrongly', 'No receipt wider than 5 s leaves the Action.'),
    ('a ceiling stated wrongly', 'The one-shot command accepts intervals as wide as 30 s.'),
    ('a ceiling stated wrongly', 'The agent signs nothing over 400 ms.'),
    ('max-width default', 'The default of thirty seconds on max-width is what a runner reaching only public Roughtime servers can honestly do.'),
    ('max-width default', 'The default of 30 s on max-width is headroom.'),
    ('max-width default', 'Left unset, max-width is thirty seconds.'),
    ('max-width default', 'max-width defaults to 30 s.'),
    ('max-width default', 'Out of the box max-width is 30 s.'),
]

# The sentences that replaced them and the sentences the surfaces carry that sit nearest a rule,
# which have to pass, so a rule wide enough to refuse everything cannot pass this test either.
HONEST = [
    'A machine that can reach only the three public Roughtime servers reaches three operators, which is under the shipped floor of four, so it refuses to sign, and nothing that ships lowers the floor.',
    'The resident agent refuses any interval wider than 250 ms, and the one-shot command, which the GitHub Action runs, refuses one wider than 2 s.',
    'Every receipt this product issues says its bound rests on the agent\'s own model, so no receipt yet carries third-party signed evidence for its bound.',
    'There is no refusal receipt.',
    'A refusal records that TimeWitness declined to sign, and today that record is a return value inside the agent rather than anything a third party can be shown.',
    'The shipped policy will not sign on fewer than four operators standing behind the round.',
    'Nine servers reach six operators, so two can go dark and the agent carries on.',
    'On the count this product defines and enforces the claim is met, at six operators with the shipped floor refusing below four.',
    'That runner reached three Roughtime operators, and from 2026-09-09 the shipped floor of four refuses such a round, so the step now fails there rather than issuing a receipt this wide.',
    'Measured against two kinds on 2026-09-09 at the sixteen rounds the Action ships now:',
    'Nine public servers disciplined the clock, three of each of the three kinds this product speaks.',
    'SourceKind has four variants, so six kinds cannot exist and a claim of four to six kinds could never be met.',
    'The fourth source kind, local hardware, has no client and needs a receiver this product cannot assume anybody has.',
    'The outside signatures pin the moment to a few seconds and do not vouch for the bound.',
    'They pin when it was taken to 2 s and do not vouch for the width.',
    'About one second is still the target and it is a target for something else: a bound resting on third-party evidence rather than on the agent\'s own model, which nothing outside the tests constructs.',
    'The format can express a bound resting on outside signatures and nothing issues a receipt that does.',
    'The outside signatures it carries are checked and pin the moment to a few seconds, and nothing issues a receipt whose width rests on them.',
    'The width beside those signatures is the signer\'s own claim, and the verifier says so under its verdict.',
    'No option on the command line and no input to the Action lowers the floor.',
    'It is min_operators in Policy::default, in crates/clock/src/policy.rs, so lowering it means building from a changed source.',
    'The default of two seconds on max-width is the narrowest interval a Roughtime corridor can state.',
    'The design names drand, the NIST beacon and the UChile beacon, and asks for at least two.',
    'That interval does hold true UTC while at most one of the three is wrong, which is what the algorithm promises.',
    'What is left unknown is how unevenly the round trip was split between the two directions, and that residual is at most half the round trip.',
    'Where only Roughtime is reachable it now refuses, and the 12 s it reached there on 2026-09-08 is from before the operator floor.',
    'Measured on 2026-09-08 against the three public Roughtime servers, two passes each, before the operator floor that now refuses a round of those three alone:',
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
    for honest in HONEST:
        faults = judge(honest, policy)
        if faults:
            print(f'policy sentences: an honest sentence was refused ({"; ".join(faults)}): {honest}', file=sys.stderr)
            return 1
    print(f'policy sentences: {len(SEEDS)} seeds, each refused by its own rule, and {len(HONEST)} honest sentences passed')
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
    whole_tree = not files
    if whole_tree:
        files = SURFACES
        if site is None and '--no-site' not in argv:
            if not SITE_BESIDE.is_dir():
                print(f'policy sentences: the site is not beside this tree at {SITE_BESIDE}, and nothing said '
                      f'--no-site, so the site\'s sentences were not read', file=sys.stderr)
                return 2
            site = str(SITE_BESIDE)

    try:
        read_from, landing = surfaces(files, site, SENTENCE_FLOOR if whole_tree else 1)
    except (Unreadable, OSError, ValueError) as e:
        print(f'policy sentences: a surface could not be read: {e}', file=sys.stderr)
        return 2
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
    where = 'and no site, said on purpose' if site is None else f'and the site at {site}'
    print(f'policy sentences: {len(read_from)} sentences over {len(files)} files {where} agree with the '
          f'shipped policy ({said})')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
