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
- which kinds those are, by the file each client sits in, so a protocol named as having a client
  when no file carries one is refused by name

Every one of those is held to the sentences. A sentence stating the floor, the Roughtime operator
count or the kind count wrongly is refused, and so is one saying the Roughtime-only round is signed,
that the floor can be lowered, that outside evidence backs the width, that a refusal receipt exists,
or a ceiling or a max-width default that is not the code's. Each rule is written for the claim rather
than for one wording of it: a number in digits or in words, the verb in any of its forms, and the
passive as well as the active. Until the evening of 2026-09-15 three of the facts were read and held
nothing, and each of the other shapes was matched on the one sentence it was written from, so "at
least two operators" and "the outside signatures back up the width" passed on every surface.

What it refuses on principle, because the fact is the design and not a number in the code. Until
2026-09-16 every rule here held a sentence to a value read off the tree, and two independent test
passes that day refused 7 of 24 and 5 of 29 fresh sentences: "Our clock is accurate to the
millisecond", "TimeWitness prevents a backdated build from being published", "averages the readings
from all its sources" and "receipts carry legal weight under eIDAS" all passed, because nothing here
had a rule for them. Five claims are now refused wherever a clause asserts them and does not deny
them: accuracy where the product has resolution, our own bound presented as outside evidence or NTS
as evidence of any kind, enforcement of anything beyond declining to sign, readings averaged into a
time, and legal weight or compliance. Each is written as the claim rather than as a wording of it: a
list of the words the claim turns on, the clause each word sits in, and one test of whether that
clause asserts or denies it. The clause is what the denial is scoped to, so "No regulation we have
checked, including A, B and C, requires clock accuracy" is one denial and "It refuses to sign, so it
prevents the build" is a denial and then a claim.

What a cold reader found on 2026-09-16, and what changed for it. Two sentence sets written from the
the rules of what this product may say, before this file was opened, were refused 26 of 45 and 22 of 45 while three sets whose
misses had been folded in scored 45, 35 and 42, so the seeds were measuring the seeds. The eight
classes they found are rules now, and each is written as the class rather than the sentence: the
three millisecond figures rule 1 of what this product may say names as somebody else's, and the two the simulated harness
produced, are refused beside a first-person subject without the attribution; accuracy as a bare noun
with a positive predicate, as ours, or as a thing delivered or guaranteed; Roughtime called a standard,
held to the standing its own client states; our own number said to be, to count as or to be treated as
evidence of any kind, whatever verb links them; each evidence role held to the direction it proves; the
gating verbs when negated, the neutral objects a CI gate acts on, and the noun forms of enforcement;
averaging by particle or by arithmetic; the verifiable delay function said to prove elapsed time; and
accreditation or qualified status claimed in the first person, where the phrase that let the honest
denial through had been letting the claim through too. The denial test changed shape with them: the
negated verb after a claim word has to be that word's own predicate, with no conjunction between,
so a trailing "and no hardware is required" denies nothing; `do`, `does` and `did` are denials; and
"nothing" counts only as the claim word's own object. Every set is fitted the moment its classes go
in, so the number that measures this file is the next cold set and never one of these.

What it cannot do. Metaphor: "your machine stops lying about the time" and "the door already shut"
say the forbidden thing in words no list carries. A negation of something else that sits before the
claim word in the same clause with no comma, "a stranger who trusts none of us can lean on the
servers' word that the bound is correct", is read as a denial. A pronoun standing for an outside
party, "they certify how far from UTC it could have been", names nothing this reads. And each rule's
honest register, the words that make a mention honest, is a list a writer could ride: "comes from
accreditation" beside a claim passes the claim. A figure it has no rule for is not checked here;
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
import urllib.error
import urllib.parse
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

# Keys in the site's content files whose own string is a note to whoever edits them and never
# reaches a page: an id, a source, a provenance line, an editor's note. The test is made against the
# key that holds the string and against nothing above it. Until 2026-09-16 it was made against every
# key on the way down, so `Note$` matched `commandNote` and pruned the whole object under it, and
# `install.commandNote.text`, which the front page prints under the install command, was not read: a
# dishonest sentence planted there exited 0 with the count unmoved at 1618, while the same sentence
# one key over exited 1. Two keys hold objects that are editorial in full and are named here rather
# than matched: `claimsUsed` is the register of which claim each block drew on, and `doNotSay` is the
# list of what not to say, so it is made of wrong sentences on purpose.
NOT_SERVED = re.compile(r'^\$|^src$|^id$|Note$|^provenance$|^departsFromSource$|^carriedLimit$|^note_?src$')
NOT_SERVED_OBJECTS = {'claimsUsed', 'doNotSay'}

WORDS = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8,
         'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12, 'fifteen': 15, 'sixteen': 16, 'twenty': 20,
         'thirty': 30, 'forty': 40, 'fifty': 50, 'sixty': 60, 'ninety': 90, 'hundred': 100,
         'a couple of': 2, 'a pair of': 2, 'half a dozen': 6, 'a dozen': 12, 'dozen': 12}
WORD = '(?:' + '|'.join(sorted(WORDS, key=len, reverse=True)) + ')'
# A count, in digits or in words, as sentences about operators and kinds write it.
COUNT = r'(?:\d+|' + WORD + r'|a single|single)'
# A duration's number, which can also be "a", "an", "a full", "half a", "a quarter of a" or
# "two hundred and fifty".
AMOUNT = (r'(?:\d+(?:\.\d+)?|half an?|a quarter of an?|a full|an?|' + WORD + r' hundred(?: and ' + WORD
          + r'(?:-' + WORD + r')?)?|' + WORD + r'(?:-' + WORD + r')?)')
UNIT = r'(ms|milliseconds?|s|seconds?|minutes?)'


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
    # The client says at its head which document it implements and what standing that document has.
    # A sentence calling Roughtime an RFC or a standard is held to this line, and the day the draft is
    # published as one the line changes and this check stops reading until the rule below is revisited.
    standing = re.search(r'(Internet-Draft with intended status \w+), not an RFC', roughtime_core)
    if not standing:
        raise Unreadable('roughtime.rs no longer says what standing the specification it implements has')
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
    # The kinds by name, from the file each client sits in: ntp.rs is NTP, roughtime.rs is Roughtime.
    kind_names = {p.stem.upper() if len(p.stem) <= 3 else p.stem.title()
                  for p in sources.rglob('*.rs') if 'impl TimeSource for' in p.read_text(encoding='utf-8')}

    return {
        'floor': int(floor.group(1)),
        'agent_ns': int(agent.group(1)) * per[agent.group(2)],
        'one_shot_ns': one_shot_ns,
        'action_ns': int(max_width.group(1)),
        'roughtime_operators': len(operators),
        'roughtime_servers': len(names),
        'kinds': kinds,
        'kind_names': kind_names,
        'local_model_only': not sandwich_setters,
        'floor_lowerable': floor_lowerable,
        'refusal_receipt': refusal_receipt,
        'roughtime_standing': 'an ' + standing.group(1),
    }


def words_of(text):
    return ' '.join(text.replace('**', '').replace('`', '').split())


def sentences(text):
    # A blank line ends a sentence whatever punctuation came before it, so the job summary's
    # paragraphs and a content file's strings are read one at a time rather than run together into
    # one sentence that names nothing when it is refused.
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
    # The job summary is written one echo a line and a bare echo between paragraphs, so the lines of
    # a paragraph are one text and a sentence that runs over a line break is read whole. Until
    # 2026-09-16 each echo was its own paragraph, and "enforcement path in this design." was read as a
    # sentence with its "there is no" on the line before.
    paragraphs, current = [], []
    for m in re.finditer(r'^\s*echo(?: "([^"]*)")?\s*$', text, re.M):
        if m.group(1) is None:
            paragraphs.append(' '.join(current))
            current = []
        else:
            current.append(m.group(1))
    paragraphs.append(' '.join(current))
    return '\n\n'.join(p for p in paragraphs if p)


def site_strings(node, key=''):
    if isinstance(node, dict):
        if node.get('name') == 'max-width' and 'default' in node:
            yield ('max-width input', f'max-width default {node["default"]} ns. {node.get("body", "")}')
        for k, v in node.items():
            if k in NOT_SERVED_OBJECTS:
                continue
            yield from site_strings(v, k)
    elif isinstance(node, list):
        for v in node:
            yield from site_strings(v, key)
    elif isinstance(node, str) and not NOT_SERVED.search(key):
        yield (key, node)


# What a served page says to a reader who is not shown the page: the description a search result
# quotes, the alt a screen reader speaks, a title or label a pointer shows.
ATTRIBUTE_TEXT = re.compile(r'<meta\b[^>]*\b(?:name|property)="(?:description|og:description|twitter:description)"[^>]*'
                            r'\bcontent="([^"]*)"|<meta\b[^>]*\bcontent="([^"]*)"[^>]*'
                            r'\b(?:name|property)="(?:description|og:description|twitter:description)"|'
                            r'\b(?:alt|title|aria-label)="([^"]*)"|<title\b[^>]*>([^<]*)</title>', re.I)


# A block element ends a sentence the way a blank line does in a content file, so the three items
# of a list on the front page are three sentences and not one. Until 2026-09-16 every tag became a
# space, and "signed evidence from independent outside parties of when it was taken Our own bound is
# labelled inside the receipt as our claim" was read as one sentence and refused, because the outside
# party of item three and the bound of the sentence after the list sat in one clause.
BLOCK_TAG = re.compile(r'</?(?:p|li|ul|ol|dl|dt|dd|h[1-6]|div|section|article|header|footer|nav|aside|main|table|tr|td|th|'
                       r'blockquote|figure|figcaption|pre|br|hr)\b[^>]*>', re.I)


class Landed(urllib.request.HTTPRedirectHandler):
    """Keeps every hop a fetch took, so the fetch can refuse the ones that changed the page.

    `urlopen` follows a redirect and says nothing. Until 2026-09-16 nothing here compared where it
    landed with what it asked for, so a site answering 302 on all five paths was read as one page
    five times and the run exited 0 at 1,408 sentences with four fifths of the surface never
    opened. The sentence floor cannot catch that, because the page it lands on is a real page well
    over the floor.
    """

    def __init__(self):
        self.hops = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append((req.full_url, newurl, code))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def only_the_scheme(asked, landed):
    """True where two URLs differ by nothing but http becoming https.

    **The one redirect this check allows, and it is a deliberate call rather than an oversight.** An
    upgrade to https on the same host and the same path cannot change which page is read, so it is
    about the transport and not about the routing. Every other hop is refused, including a different
    path, a different host, a query appended, and https falling back to http.
    """
    a, b = urllib.parse.urlsplit(asked), urllib.parse.urlsplit(landed)
    return (a.scheme, b.scheme) == ('http', 'https') and a[1:] == b[1:]


def served_text(url):
    landed = Landed()
    opener = urllib.request.build_opener(landed)
    with opener.open(url, timeout=30) as response:
        page = response.read().decode('utf-8')
        final = response.geturl()
    for asked, to, code in landed.hops:
        if not only_the_scheme(asked, to):
            raise Unreadable(f'{asked} answered {code} to {to}, so the page read was not the page '
                             f'asked for. Only an upgrade of http to https on the same host and '
                             f'path is followed here')
    if final != url and not only_the_scheme(url, final):
        raise Unreadable(f'{url} was asked for and {final} was read')
    body = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', page)
    spoken = [html.unescape(next(g for g in m.groups() if g is not None)) for m in ATTRIBUTE_TEXT.finditer(body)]
    text = html.unescape(re.sub(r'<[^>]+>', ' ', BLOCK_TAG.sub('\n\n', body)))
    return text + '\n\n' + '\n\n'.join(s for s in spoken if s.strip())


def number_of(token):
    """A count or an amount written in digits or in words, as a number."""
    token = token.strip().lower()
    if re.match(r'[\d.]+$', token):
        return float(token)
    if token in WORDS:
        return float(WORDS[token])
    if token in ('a', 'an', 'a single', 'single', 'a full'):
        return 1.0
    if token.startswith('half'):
        return 0.5
    if token.startswith('a quarter'):
        return 0.25
    hundreds = re.match(r'(\w+) hundred(?: and (.+))?$', token)
    if hundreds:
        return 100 * number_of(hundreds.group(1)) + (number_of(hundreds.group(2)) if hundreds.group(2) else 0)
    total = 0
    for part in token.split('-'):
        if part not in WORDS:
            raise ValueError(token)
        total += WORDS[part]
    return float(total)


def duration_ns(number, unit):
    return round(number_of(number) * {'ms': 10**6, 'millisecond': 10**6, 'milliseconds': 10**6,
                                      's': 10**9, 'second': 10**9, 'seconds': 10**9,
                                      'minute': 60 * 10**9, 'minutes': 60 * 10**9}[unit.lower()])


NEGATED_BEFORE = re.compile(r"\b(?:no|not|never|nothing|none|nor|cannot|without)\b|n't\b", re.I)
ROUGHTIME_ONLY = re.compile(r'\bonly\b[^.,;]{0,30}?\bRoughtime\b(?! signs)|Roughtime(?: servers?)? alone|'
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
                      r'\bfloor\b[^.;]{0,30}?\b(?:was|were|is|has been|got|gets|will be) (?:reduced|lowered|dropped|cut|relaxed|'
                      r'changed|set|configured|turned down|overridden)\b|'
                      r'\bone line of configuration\b|--min-operators|\bmin-operators input\b', re.I)

# A clause ends at a semicolon, a colon, a bracket, a conjunction, or a comma followed by one. A bare
# comma does not end one, so "No regulation we have checked, including A, B and C, requires X" is one
# denial rather than four clauses with the "No" in the first, and "It refuses, so it prevents the
# build" is a denial and then a claim.
CLAUSE_BREAK = re.compile(r'[;:()|]|,\s*(?=(?:and|but|so|which|while|whereas|yet|because|although|though|whose|where|'
                          r'when|rather than|not|nor|thereby|therefore|hence|thus)\b)|'
                          r'(?<=\s)(?=(?:but|whereas|although|though|so that|thereby|therefore|hence|thus)\b)', re.I)
# What makes a clause a denial of the word the claim turns on: one of these before it in the clause,
# or a denial of it in the words after, per DENIED_AFTER below. "The third kind narrowed nothing", "An
# average of clocks is not a measurement" and "a compliance claim built on any of them would be
# false" are the second kind; "averages the readings from all its sources but not the outliers" is
# not one, because the "but" between the claim word and the negation means the negation is of
# something else.
DENIED_BEFORE = re.compile(r"^\W*(?:instead of|whether)\b|\b(?:no|not|never|nothing|none|nor|neither|cannot|without|refus\w*|declin\w*|"
                           r"rather than|far from|anything but|as opposed to|false|wrong|untrue|myth)\b|n't\b", re.I)
# The denial after the word has to be of that word. Until 2026-09-16 this was any negation inside a
# five-word window, and `and` and `but` were on its list of verbs, so "Certified microsecond accuracy
# ships with the standard agent and no hardware is required" was read as a denial of the accuracy,
# and one trailing selling point switched off four of the five claim rules. Now the words between the
# claim word and its verb may not include a conjunction, so the negated verb is the claim word's own
# predicate; `do`, `does` and `did` are on the list, because "AI Act Article 12 does not require
# tamper-evidence" is the sentence rule 6 of what this product may say wants written and it was refused; and "nothing" or
# "nobody" counts only as the claim word's own object, not as the subject of a following verb, so
# "narrowed nothing" is a denial and "evidence nobody has to trust us for" is not.
AUXILIARY = r"(?:is|are|was|were|be|being|been|remains?|does|do|did|has|have|had|can|could|will|would|shall|should|may|might|must)"
NOT_A_CONJUNCTION = r"(?!(?:and|but|or|so|which|whose|whom|that|because|when|while|if|where|since|although|though|whereas|as|unless|until)\b)"
DENIED_AFTER = re.compile(r"^\W*(?:" + NOT_A_CONJUNCTION + r"[\w'-]+\s+){0,5}?" + AUXILIARY + r"(?:\s+be)?(?:n't\b|\s+(?:not|never|no|nothing|false|wrong|untrue)\b)|"
                          r"^\W*(?:" + NOT_A_CONJUNCTION + r"[\w'-]+\s+){0,5}?(?:would|could|might) be\b[^.;,]{0,30}?\brather than\b|"
                          r"^\W*(?:(?:for|of|about|to|at|by|with|from|on|in)\s+)?(?:nothing|none|nobody|no one|no-one|neither)\b"
                          r"(?=\s*(?:$|[.,;:!?)]|(?:about|from|of|to|at|for|in|on|by|with|else|at all|whatever|more|further|beyond|but|and)\b))|"
                          r"^\W*(?:for|of|about|to|at|by|with|from|on|in)\s+no\b", re.I)
# A comma starts a new clause when what follows it has a subject or a verb of its own, and stays
# inside the clause when what follows is a list item or an aside: "No regulation we have checked,
# including A, B and C, requires X" is one denial and "Never mind the weather, our bound is third-party
# evidence" is an aside and then a claim.
NEW_CLAUSE = re.compile(r"\b(?:is|are|was|were|be|been|has|have|had|does|do|did|will|would|can|could|should|may|might|must|"
                        r"we|our|us|TimeWitness|it|its|they|their|you|your)\b", re.I)


def clause_around(sentence, at):
    """The span of the clause holding position `at`."""
    start, end = 0, len(sentence)
    for m in CLAUSE_BREAK.finditer(sentence):
        if m.end() <= at:
            start = m.end()
        elif m.start() > at:
            end = m.start()
            break
    return start, end


ANSWER = re.compile(r'^\W*(?:A: )?(?:No|Yes)[,.:;]\s*', re.I)


def same_clause(before):
    """The part of `before` from the last comma that starts a new clause, per NEW_CLAUSE."""
    start = at = 0
    for i, segment in enumerate(before.split(',')):
        if i and NEW_CLAUSE.search(segment):
            start = at
        at += len(segment) + 1
    return before[start:]


def denied_at(sentence, at, until, blank=None):
    """Whether the clause holding the span [at, until) denies it. `blank` is another span in the
    same clause whose words are not read for a negation, because they are the other half of the
    match: "not later than" in an evidence role is the role and not a denial."""
    c0, c1 = clause_around(sentence, at)
    before = sentence[c0:at]
    if blank and c0 <= blank[0] < at:
        before = before[:blank[0] - c0] + ' ' * (blank[1] - blank[0]) + before[blank[1] - c0:]
    before = ANSWER.sub('', before) if c0 == 0 else before
    return bool(DENIED_BEFORE.search(same_clause(before))) or bool(DENIED_AFTER.match(sentence[until:c1]))


def denied(sentence, match, group=0):
    """Whether the clause holding the word the claim turns on denies it."""
    at, until = match.span(group) if group and match.group(group) is not None else match.span()
    return denied_at(sentence, at, until)


def clauses(sentence):
    """The spans of the sentence's clauses."""
    cuts = [(m.start(), m.end()) for m in CLAUSE_BREAK.finditer(sentence)]
    starts = [0] + [end for _, end in cuts]
    ends = [start for start, _ in cuts] + [len(sentence)]
    return [(a, b) for a, b in zip(starts, ends) if b > a]


def denied_pair(sentence, c0, c1, first, second):
    """Whether the clause [c0, c1) denies a claim made of two spans in it. The later span is the
    word the denial is read against and the earlier is blanked out of the words before it."""
    a, b = (first, second) if first[0] <= second[0] else (second, first)
    return denied_at(sentence, b[0], b[1], blank=a)


# Outside parties, as the surfaces name them, and the width they may not be said to stand behind.
OUTSIDE = (r'(?:(?:outside|third.party|external|neutral|disinterested)\s+'
           r'(?:evidence|signatures?|parties|witnesses|attestations?|signers?|operators?|servers?|sources?)|'
           r'(?:independent|their|signed)\s+(?:evidence|signatures?|parties|witness(?:es)?|attestations?|signers?)|'
           r'(?:servers?|sources?|operators?|signers?)\'\s+(?:signatures?|word|say-so|names?)|independent (?:servers?|sources?)|'
           r'third parties|signers|strangers)')
OURS = (r'(?:(?:the|that|its|our|your|this|a receipt\'s|the receipt\'s) (?:whole |entire |stated |full |error |own )?(?:bound|width|interval|second number|claim|error margin|margin|'
        r'uncertainty|error bar)|how (?:wide|tight|narrow|big|small) (?:the|its|our|that) (?:bound|width|interval) (?:is|was)|'
        r'how far (?:from|off) UTC|how wrong (?:it|the clock|the reading) (?:could|might|may|can) (?:have )?be(?:en)?)')
# Each has one group, the word the claim turns on, and the clause around that word is what is read
# for a denial: "does not vouch for the bound" is the honest sentence and "who have never heard of us
# that supports it" is the fault. The seventh names no verb: until 2026-09-16 it listed the verbs an
# outside party could be said to do to the width, and "are what make the width believable" and "sign
# off on how wide the bound is" were not on the list. An outside party and our width in one clause,
# in that order and with nothing denying it, is the claim whatever verb carries it.
VOUCHING = [re.compile(p, re.I) for p in (
    r'evidence[^.;]{0,80}?\b(supporting|for) (?:that|the|its|this) (?:bound|width|second number|interval)\b',
    r'\b(vouch)(?:es|ing)? for (?:that|the|its|this) (?:second number|bound|width|interval)\b',
    r'evidence[^.;]{0,120}?\bthat (supports) it\b',
    r'\bhow wrong it could be,? and (proves) it\b',
    r'\breceipt anyone (can) check without trusting\b',
    r'\b(makes) the bound checkable\b',
    r'\b' + OUTSIDE + r'\b[^.;,]{0,60}?\b(' + OURS + r')\b',
    r'\b(?:bound|width|interval|second number)\b[^.;,]{0,25}?\b(?:is|are) (?:something|what|a (?:number|figure|thing)) '
    r'(?:the |that |those )?(' + OUTSIDE + r')\b',
    # A named signer said to stand behind the width, and the width said to be signed by one.
    r'\b(?:Roughtime|Cloudflare|Google|the (?:upstream |time |outside )?servers)\b(?: and \w+)?(?: servers?)? '
    r'((?:confirms?|attests?|vouch\w*|certif\w*|stands? behind|backs?|signs? off|underwrites?|guarantees?|verif\w*)\b[^.;,]{0,40}?'
    r'\b(?:bound|width|interval|margin|second number|uncertainty)\b)',
    r'\b(?:bound|width|interval|margin|second number)\b[^.;,]{0,30}?\b(?:is|are|was|were|gets?) ((?:counter)?signed by (?:[\w-]+ ){0,3}?'
    r'(?:Roughtime|NTS|NTP|servers?|sources?|operators?|signers?|third.part\w+|outside|independent|external|Cloudflare|Google)\b)',
    # The passive.
    r'\b(?:bound|width|interval|second number|claim|model)s?\b[^.;,]{0,30}?\b(?:is|are|was|were|gets?|has been|have been) '
    r'(?:[\w-]+ ){0,3}?((?:backed|supported|vouched for|underwritten|confirmed|attested|corroborated|proved|proven|verified|'
    r'guaranteed|certified|validated|endorsed|warranted|audited|signed off)(?: [\w-]+){0,3}? (?:by|from)\b)',
    # Our own number said to be, or to count as, outside evidence.
    r'\b(?:bound|width|interval|second number|model)s?\b[^.;,]{0,40}?\b(?:is|as|counts? as|serves? as|stands? as|amounts? to|'
    r'constitutes?|doubles? as|becomes?) (?:\w+[ ,-]+){0,3}?((?:outside|third.party|independent|external|portable|'
    r'stranger.checkable|neutral|signed|objective)[- ](?:evidence|proof|attestation))\b',
    # What a receipt is said to rest on, in the present tense. A bound "resting on" outside evidence
    # is the target the surfaces name and is not this.
    r'\b(?:receipts?|the (?:bound|width|interval|second number)|its (?:bound|width)|every receipt|each receipt)\b[^.;]{0,30}?'
    r'\b(rests?) on (?:the |its |their )?(?:third.party|outside|independent|external|signed|signers\'?)\b',
)]
# The product's own phrase for a third party, which carries a "never" that negates nothing.
NEVER_HEARD = re.compile(r'\bwho (?:have|has) never heard of (?:us|this product)\b', re.I)
# A receipt said to be signed by anybody but the agent that issued it. The outside signatures inside a
# receipt are on the signers' own answers, and the receipt itself is signed by the agent's key.
RECEIPT_SIGNED_BY = re.compile(r'\breceipts?\b[^.;,]{0,30}?\b(?:(?:is|are|gets?|was|were|being) (?:counter)?signed by |'
                               r'(?:bears?|carr(?:y|ies)|holds?) the (?:counter)?signatures? of )('
                               r'(?:(?:the |its |their )?(?:Roughtime |NTS |NTP |public |time |upstream |outside )?(?:servers?|sources?|signers?|operators?|corridor)\b|Roughtime|NTS|NTP|'
                               r'(?:a |an |the )?(?:third.part\w+|outside|independent|external|neutral|public)\b))', re.I)
# NTS said to be evidence of any kind. Its keys are symmetric, so the machine holding one could
# compose the answer it then checks, and the receipt format refuses it in every evidence role.
NTS_EVIDENCE = re.compile(r'\bNTS\b[^.;]{0,80}?\b(evidence(?! role)|proof|attest\w*|portable|stranger|third.party|vouch\w*|'
                          r'verifiable|checkable|witness\w*)\b|'
                          r'\b(evidence(?! role)|proof|attest\w*|portable|stranger|third.party|vouch\w*|verifiable|checkable|witness\w*)\b'
                          r'[^.;]{0,80}?\bNTS\b', re.I)
# Our own number said to be, to count as, or to be treated as evidence, whatever kind of evidence
# and whatever verb links them. VOUCHING above needed the evidence to be called outside or
# third-party; "the interval is independently attested", "treat the agent's interval as the
# independent witness" and "our own bound are the same kind of proof" said it without that word.
OUR_NUMBER = r'(?:bound|width|interval|second number|model|reading|number|figure|error margin|uncertainty)s?'
OWN_AS_EVIDENCE = [re.compile(p, re.I) for p in (
    r'\b' + OUR_NUMBER + r'\b[^.;,]{0,40}?\b(?:is|are|as|counts? as|serves? as|stands? as|amounts? to|constitutes?|doubles? as|'
    r'becomes?|supplies|supply|provides?|carries|carry|generates?|makes?) (?:\w+[ -]+){0,4}?'
    r'((?:evidence|proof|attest\w*|witness\w*|vouched for|corroborated|underwritten|certified|notari[sz]ed|independently \w+))\b',
    r'\b(?:treat\w*|read|take|count|accept|regard|use)\b[^.;,]{0,30}?\b' + OUR_NUMBER + r'\b[^.;,]{0,20}?\bas (?:\w+ ){0,3}?'
    r'((?:evidence|proof|attestation|witness\w*))\b',
    r'\b(?:evidence|proof|attestation|witness\w*)\b[^.;,]{0,30}?\b((?:generated|produced|computed|written|issued|made|supplied|'
    r'provided|created|signed) by (?:our|the agent|us|TimeWitness|itself|the product|the receipt))\b',
    r'\b' + OUR_NUMBER + r'\b[^.;]{0,60}?\b((?:the )?same (?:kind|sort|class|type|grade|level|weight)(?: of)? '
    r'(?:evidence|proof|attestation|witness))\b',
    r'\b(self.signed (?:\w+ ){0,2}?(?:is|as|counts? as) (?:\w+ ){0,3}?(?:evidence|proof|attestation|witness))\b',
)]
# The three evidence roles, and the direction each one proves. A public freshness beacon proves
# not-earlier-than, because its value could not have been known before its round was published; an
# independent final witness, a timestamp authority, a transparency log or a public anchor, proves
# not-later-than, because it signed after the payload existed. A source given the other direction
# is refused: "the freshness beacon proves the stamp was not made later than it says" was passing
# on 2026-09-16 because nothing here knew which way each role points.
ROLE_SOURCE = {
    'freshness beacon': re.compile(r'\b(?:(?:freshness|public|randomness) )?beacons?\b|\bdrand\b|\bUChile\b', re.I),
    'final witness': re.compile(r'\bRFC ?3161\b|\bRFC ?9921\b|\btime.?stamp(?:ing)? authorit(?:y|ies)\b|\bTSA\b|\btransparency logs?\b|'
                                r'\bOpenTimestamps\b|\bpublic anchors?\b|\banchors? into a public chain\b|\bfinal witness(?:es)?\b|'
                                r'\btime.?stamp tokens?\b', re.I),
}
ROLE_DIRECTION = {
    'not-later-than': re.compile(r'\bnot[- ]later[- ]than\b|\bno later than\b|\bnot (?:been )?(?:made|taken|created|written|stamped|issued) '
                                 r'(?:any )?later\b|\bat the latest\b|\bexisted by\b|\bby then\b|\bbefore (?:that|then|it says)\b', re.I),
    'not-earlier-than': re.compile(r'\bnot[- ]earlier[- ]than\b|\bno earlier than\b|\bnot (?:been )?(?:made|taken|created|written|stamped|issued) '
                                   r'(?:any )?earlier\b|\bat the earliest\b|\bafter (?:that|then|it says)\b|'
                                   r'\bcould not have (?:been )?(?:known|existed|made) before\b', re.I),
}
ROLE_PROVES = {'freshness beacon': 'not-earlier-than', 'final witness': 'not-later-than'}
# A verifiable delay function proves sequential work and never elapsed time (rule 4).
DELAY_FUNCTION = re.compile(r'\b(?:verifiable )?delay functions?\b|\bVDFs?\b', re.I)
ELAPSED = re.compile(r'\belapsed\b|\bseconds?\b|\bminutes?\b|\bhours?\b|\bhow long\b|\bduration\b|\bwall.?clock\b|\breal time\b|'
                     r'\btime (?:passed|elapsed|has passed|went by)\b|\bpassage of time\b|\bmeasures? time\b|\bproves? time\b', re.I)
# The three millisecond figures rule 1 of what this product may say names as somebody else's, each with the conditions it
# belongs to, and the two the simulated harness produced. None of the five has been measured by
# this product, so beside a first-person subject and without the attribution they are a claim.
FOREIGN_FIGURES = [(re.compile(p, re.I), where) for p, where in (
    (r'\b5 to 50 ?(?:ms|milliseconds?)\b', 'the public internet with no owned hardware'),
    (r'(?<![\d.])(?:about |roughly |around |some |under |within )?1 ?(?:ms|millisecond)\b(?! of half)', 'a good LAN against a stratum-1 source'),
    (r'(?<![\d.])(?:about |roughly |around |some )?100 ?(?:us|\u00b5s|\u03bcs|microseconds?)\b', 'a cloud instance with a hypervisor clock'),
)]
SIMULATED_FIGURES = re.compile(r'(?<![\d.])(?:26\.6|234\.6) ?(?:ms|milliseconds?)\b', re.I)
OURS_SUBJECT = re.compile(r"\b(?:we|our|us|ours|TimeWitness|the agent|the product|this product|the clock|the bound|your bound|the stamp|"
                          r"receipts?|you(?:'ll| will)? (?:see|get|reach)|expect)\b", re.I)
OURS_MEASURED = re.compile(r'\b(?:we|our agent|TimeWitness|the agent|our clock|the clock) (?:\w+ ){0,2}?(?:measured?|measures|reach\w*|hold\w*|'
                           r'see|sees|saw|achiev\w*|deliver\w*|get\w*|got|settl\w*|hit\w*|manag\w*|attain\w*)\b|\bour measured\b', re.I)
ATTRIBUTED = re.compile(r'\bresearch\b|\bquot\w+\b|\bpublished\b|\bsomebody else|\bsomeone else|\bnot ours\b|\bnever (?:been )?measured|'
                        r'\bnot (?:been )?measured|\bhas not been measured|\bbelongs?\b|\btypical(?:ly)?\b|\bliterature\b|\busually\b|'
                        r'\bfor (?:ordinary|other people\'s|anybody else\'s) machines|\bpresented as ours\b', re.I)
SIMULATED = re.compile(r'\bsimulat\w*|\bharness\b|\barithmetic of the model\b|\btest wrote\b|\bknown true offset\b', re.I)
# Roughtime called a standard. Held to the standing the client's own head says the document has.
ROUGHTIME_STANDARD = re.compile(r'\bRoughtime\b[^.;,]{0,40}?\b(RFC)\b(?!\s*\d)|'
                                r'\bRoughtime\b[^.;,]{0,40}?\b((?:is|as|being|became|now) (?:an? |the )?(?:IETF |internet |published |full |'
                                r'ratified |finished |final |proposed )?(?:RFC|standard))\b', re.I)
STANDING_SAID = re.compile(r'\bdraft\b|\bnot an RFC\b|\bexpir\w*', re.I)
OTHER_SOURCE = re.compile(r'\bRoughtime\b|\bNTP\b|\bdrand\b|\bbeacon\b|\bauthority\b|\bRFC\b', re.I)
ONE_SOURCE = re.compile(r'\bno ordinary time sources\b|\bonly the corridor\b|'
                        r'\b(?:one|a single) (?:time )?source (?:client|kind)\b|'
                        r'\b(?:only|just) (?:one|a single) (?:kind|sort|type) of (?:time )?source\b|'
                        r'\b(?:only|just) (?:Roughtime|NTP|NTS)\b[^.;]{0,20}?\bhas a client\b|'
                        r'\b(?:Roughtime|NTP|NTS) has the only client\b|\bthe only (?:time )?(?:source )?client\b', re.I)
QUAL = r'(?:independent |distinct |different |separate |unrelated )?'
# A count of the kinds that have a client, which is the count the code gives, and not a count of
# the kinds in one round or of the variants an enum has. "N kinds of time source" anywhere is that
# count: no surface writes the phrase about anything else.
KIND_COUNT = [re.compile(p, re.I) for p in (
    r'\b(' + COUNT + r') ' + QUAL + r'(?:kinds?|sorts?|types?) of (?:time )?sources?\b',
    r'\b(' + COUNT + r') source (?:kinds?|clients?)\b[^.;]{0,30}?\b(?:have|has|with|exist|are built|are implemented|in this repository|here)\b',
    r'\b(' + COUNT + r') (?:kinds?|sorts?|types?) (?:of (?:time )?sources? )?(?:this product|the product|the agent|it|this repository|the tree) (?:speaks|knows|polls|supports|implements|has|carries)\b',
    r'\b(?:this repository|the repository|the tree|the code|the agent|this product|the product|it) (?:speaks|has|carries|holds|implements|polls|knows) (' + COUNT + r') (?:kinds?|sorts?|types?) of (?:time )?sources?\b',
    r'\b(?:only|just) (' + COUNT + r') (?:kinds?|sorts?|types?) of (?:time )?sources?\b',
)]
# A protocol named as having a client here. Held to the file names under crates/sources/src.
FOREIGN_KIND = re.compile(r'\b(PTP|SNTP|GPS|GNSS|PPS|White Rabbit|IEEE 1588|chrony|ntpd|IRIG|DCF77|WWVB|MSF|GLONASS|Galileo)\b')
HAS_CLIENT = re.compile(r'\bclients?\b|\bship\w*\b|\bsupports?\b|\bspeaks?\b|\bimplements?\b', re.I)
# The count of operators behind the published Roughtime servers, stated as such. Until 2026-09-16
# five shapes each named the verb, and "Roughtime gives us four operators" was not one of them. A
# count of operators in a sentence about Roughtime and no other kind is that count, unless the
# clause it sits in is about the floor, which FLOOR_COUNT holds.
ROUGHTIME_COUNT = re.compile(r'\b(' + COUNT + r') ' + QUAL + r'(?:Roughtime )?operators\b', re.I)
# The count of published Roughtime servers, stated as such: "Roughtime's four public servers".
ROUGHTIME_SERVERS = re.compile(r'\b(' + COUNT + r') (?:public |published )Roughtime servers\b|'
                               r'\bRoughtime\'s (' + COUNT + r') (?:public |published )?servers\b|'
                               r'\b(' + COUNT + r') (?:public |published )servers\b', re.I)
# The floor, wherever a sentence states it as a number.
FLOOR_COUNT = [re.compile(p, re.I) for p in (
    r'\bfloor (?:of|is|at|sits at|stays at|was|remains|stands at) (' + COUNT + r')\b(?!\s*(?:ms|s|us|ns|seconds?|milliseconds?)\b)',
    r'\bfloor\b[^.;]{0,40}?\b(?:reduced|lowered|dropped|cut|set|raised|changed|moved) to (' + COUNT + r')\b',
    r'\b(' + COUNT + r') ' + QUAL + r'operators (?:is|are|were|would be|will be|will) (?:the )?(?:floor|minimum|bar|quorum|enough|sufficient|'
    r'all it takes|required|needed|what it takes|plenty|do|suffice|all (?:\w+ ){0,3}?(?:takes|needs?|asks? for|wants?|requires?)|'
    r'what (?:\w+ ){0,3}?(?:takes|needs?|asks? for|wants?|requires?))\b',
    r'\b(' + COUNT + r') ' + QUAL + r'operators (?:suffices?|will do)\b',
    r'\b(?:at least|no fewer than|a minimum of|a quorum of|quorum of|fewer than|under|below|short of|unless|until|needs?|requires?|'
    r'takes?|wants?|asks? for|insists? on|before) (' + COUNT + r') ' + QUAL + r'operators\b',
    r'\b(?:at least|no fewer than|fewer than|a minimum of|minimum of) (' + COUNT + r')\b(?!\s*(?:ms|s|us|ns|seconds?|milliseconds?|sources?|servers?|names?|kinds?|of|beacons?|parties)\b)',
    r'\b(?:minimum|floor|quorum) (?:is|of) (' + COUNT + r') ' + QUAL + r'operators\b',
    r'\b(' + COUNT + r') ' + QUAL + r'operators (?:must|have to|need to) (?:stand|be|answer|agree)\b',
    r'\b(' + COUNT + r') (?:is|was|remains|being) (?:the |our )?(?:shipped |current |operator )?(?:floor|minimum|quorum)\b',
)]
# Signing said to happen on fewer operators than the floor: "will happily sign with three operators".
SIGNS_ON = re.compile(r'\b(?:signs?|signing|signed) (?:with|on|at|from) (?:just |only )?(' + COUNT + r') ' + QUAL + r'operators\b', re.I)
# Sources said to be enough on their own. A source stands at one operator, so N sources cannot reach
# a floor of more than N operators.
SOURCES_ENOUGH = re.compile(r'\b(' + COUNT + r') (?:good |healthy |independent |single |working |reachable )?(?:time )?(?:sources?|servers?) '
                            r'(?:is|are|would be|will be|was|were) (?:enough|sufficient|plenty|all it takes)\b', re.I)
REFUSAL_RECEIPT = re.compile(r'\b(?:signed )?refusal receipts?\b', re.I)
REFUSAL_HYPOTHETICAL = re.compile(r'\bwould\b|\bif one\b|\bnot yet\b|\bis not (?:built|shipped|issued)\b|\bphrase rather than\b|'
                                  r'\bthere is no\b|\bno refusal receipt\b', re.I)
# A ceiling, in the forms a sentence gives one: refused over, up to, capped at, nothing wider than,
# holds itself to, at worst, will happily sign a bound of.
CEILING = re.compile(r'(?:refuses? (?:any|an|one|a)(?: interval| bound| width| receipt)? (?:wider|over|more|past|beyond) (?:than )?|'
                     r'refuses? anything (?:over|wider than|past|beyond|above|more than) |refused (?:past|over|beyond|above|wider than) |'
                     r'no (?:receipt|interval|bound|width) (?:wider|more|over|past|beyond) (?:than )?|'
                     r'rais(?:es|ed|ing) (?:that|it|the ceiling|the cap|its ceiling)? ?to |ceiling (?:of|is|at|sits at|stands at|is set at|was set at|is at|now at) |'
                     r'(?:up to|at most|no wider than|no more than|as wide as|'
                     r'capped at|a cap of|caps? (?:the|its|a|every) (?:bound|width|interval|receipt) at|limit(?:ed|s)? (?:of|to|at)|'
                     r'holds? (?:itself|the bound|the width|its bound) (?:to|at|under|within)|'
                     r'(?:tolerates?|allows?|permits?) (?:a |an )?(?:bound|width|interval)s? (?:of|up to|as wide as)|'
                     r'will (?:happily |gladly |still |readily )?(?:report|sign|issue|give|return|hand back|accept|allow|tolerate)[^.;]{0,25}?'
                     r'\b(?:bound|width|interval|receipt)s? (?:of|as wide as|at|up to)|'
                     r'nothing (?:over|wider than|narrower than|past|beyond|above)|anything (?:over|wider than|narrower than|under|below|inside|within|up to)|'
                     r'(?:signs?|accepts?|answers? with|hands? back|gives?)[^.;]{0,30}?\b(?:narrower than|under|below|inside|within)) )'
                     r'(' + AMOUNT + r') ?' + UNIT + r'\b|'
                     r'\b(' + AMOUNT + r') ?' + UNIT + r' (?:ceiling|cap|limit)\b|'
                     r'\b(' + AMOUNT + r') ?' + UNIT + r'\b,? (?:is|are|which is|being) the (?:widest|most|largest|ceiling|cap|limit)\b|'
                     r'\b(' + AMOUNT + r') ?' + UNIT + r' at (?:worst|most|the (?:widest|outside|most))\b', re.I)
# A width said to sit inside the ceiling, which is a claim the ceiling is at least that wide.
INSIDE_CEILING = re.compile(r'\b(' + AMOUNT + r') ?' + UNIT + r' (?:is|are|sits|falls|lies|counts as|still) (?:well |comfortably |still |easily )?'
                            r'(?:within|inside|under|below|acceptable|accepted|fine|allowed|permitted)\b[^.;]{0,40}?'
                            r'\b(?:bound|ceiling|cap|limit|width|policy)\b', re.I)
AGENT = re.compile(r'\bagent\b|\buptime\b|\bcadence\b', re.I)
ONE_SHOT = re.compile(r'one-shot|\bAction\b|\bstamp command\b|\brunner\b|\bworkflow\b|max-width', re.I)
MAX_WIDTH_DEFAULT = re.compile(r'\bdefault (?:of |is )?(?:the )?(' + AMOUNT + r') ?' + UNIT + r'\b|\bso (' + WORD + r') seconds\b|'
                               r'\bmax-width(?: input)? (?:is|of|defaults? to|comes as|ships as|ships at|starts at|sits at) (' + AMOUNT + r') ?' + UNIT + r'\b|'
                               r'\b(?:left unset|unset|out of the box|by default|if you do not set it|when nothing is set|unless you set|'
                               r'if you don\'t set|if unset|when unset|with nothing set|absent a value)\b[^.;]{0,30}?'
                               r'\b(' + AMOUNT + r') ?' + UNIT + r'\b', re.I)

# The claims refused on principle. Each is a rule of what this product may say, rather than a value read off
# the code, and each row is the words the claim turns on, in a group where the claim turns on one
# word inside a longer match; what else the sentence must carry for the words to be that claim;
# what in the clause makes the mention honest whatever else it says; and what the refusal says.
CLAIMS = [
    ('accuracy', [
        r'\b(accurate(?:ly)?)\b',
        r'\b(?:nanosecond|microsecond|picosecond|sub-?millisecond|sub-?microsecond|ns|us|\u00b5s|\u03bcs)[- ](?:level |grade )?(accura\w*)',
        r'\b(accura\w+) (?:to|of|at|within|down to) (?:the |a |an |about |roughly |within |under |better than |a few |some )?'
        r'(?:\d+(?:\.\d+)? ?)?(?:nanosecond|microsecond|picosecond|ns\b|us\b|\u00b5s|\u03bcs)',
        r'\b(?:reading|resolution|counter)\b[^.;,]{0,25}?\b(?:is|are) (?:also |the same as )?(?:its|our|the|their|an?) (accuracy)\b',
        r'\b(accuracy) of (?:about |roughly |under |better than |within )?\d',
        r'\b(precise (?:time|UTC))\b',
        r'\b((?:precise(?:ly)?|correct(?:ly)?|exact(?:ly)?|true|faithful(?:ly)?|right) to (?:within |the |a |about |roughly )?'
        r'(?:\d|a |the |one |nearest|nano|micro|milli|billionth|millionth|thousandth))',
        # Accuracy as a bare noun with a positive predicate, as ours, or as something delivered or
        # guaranteed. "Accuracy is the whole product" and "Accuracy today is 128.7 milliseconds" are
        # the claim whatever figure follows; "Milliseconds is the accuracy to UTC" is not.
        r'\b(accuracy) (?:is|was|remains|matters|comes|today|of the fleet|improves?|gets? better|goes? up)\b',
        r"\b(?:our|the agent's|TimeWitness's|the product's|the fleet's|the clock's) (?:[\w']+ )?(accuracy)\b",
        r'\b(?:deliver|offer|give|provide|bring|guarantee|promise|achieve|reach|sell|boast)\w* (?:\w+ ){0,3}?(accuracy)\b',
        r'\b(accura\w+)\b[^.;,]{0,30}?\bguarantee\w*\b',
        r'\b(within) (?:a |about |roughly |\d)[^.;,]{0,30}? of UTC\b',
        r'\b(exactly) when\b',
        r'\b(?:precise|correct|faithful|true|exact|synchroni[sz]ed|agree\w*|right)\b[^.;,]{0,20}?\b(to UTC)\b',
        r'\b(?:exact|precise|correct|right|true)\b[^.;]{0,40}?\b((?:down )?to the (?:last )?(?:nanosecond|microsecond|billionth|millionth|thousandth))',
        r'\b(agree\w*|synchroni[sz]\w*|match\w*|aligned|in step) [^.;,]{0,25}?\bto the (?:nanosecond|microsecond|billionth|millionth)\b',
        r'\b(nanosecond|microsecond|picosecond)[- ](?:timekeeping|synchroni[sz]ation|sync|UTC|truth|agreement|clock)\b',
        r'\b(?:knows?|has|holds?|keeps?|tracks?|gives?|reports?|tells? you|shows?) (the true (?:time|UTC))\b',
        r'\b((?:clock |timing |time )?accuracy)\s*[:|]\s*(?:sub-?\w+|\d|nanosecond|microsecond|millisecond|to the)',
    ], None,
     r'\b(?:needs?|requires?|takes?|means?|is|are) (?:\w+ ){0,2}?hardware\b|\bdatacent(?:re|er)\b|\bdata cent(?:re|er)\b|'
     r'somebody else|someone else|public research|\b(?:in|of|as) resolution\b|'
     r'\b(?:anyone|anybody|whoever|those|people|vendors?|somebody|someone) (?:who |that )?(?:promis|sell|claim|offer|quot|advertis|tell)\w*\b|'
     r"\b(?:cannot|can't|could not|will not|won't) (?:build|deliver|reach|promise|offer|sell|do|make|ship)\b|"
     r"\bsource's own\b|\bits own accuracy\b|\bstates? (?:no|any) accuracy\b|\bconfused\b",
     'claims accuracy, and this product has resolution and a bound: bounded, never accurate (rule 1 of what this product may say)'),
    ('another source narrows the bound', [
        r'\b(?:adding|add|another|more|extra|additional|each (?:new|extra|additional)|every (?:new|extra|additional)|'
        r'a (?:second|third|fourth|fifth|sixth) (?:kind|source|server)|(?:the|that|this) third kind|NTS|'
        r'an? authenticated (?:source|corridor|kind)|' + COUNT + r' (?:\w+ )?(?:sources?|servers?|operators?|kinds?) instead of|'
        r'with ' + COUNT + r' (?:\w+ )?(?:sources?|servers?|operators?|kinds?)|(?:switching|turning) on (?:the |an? )?(?:\w+ )?(?:NTS|kind|source|client)|'
        r'point(?:ing|s|ed)? (?:it|the agent) at more)\b'
        r'[^.;]{0,50}?\b((?:narrow|tighten|shrink|sharpen|shave|vanish|disappear|collaps)\w*|improv\w* (?:\w+ ){0,2}?'
        r'(?:bound|interval|width|accuracy|margin|uncertainty)\b|tighter|narrower|smaller|sharper|better|comes? down|goes? down|falls? away)\b',
        r'\b((?:narrow|tighten|shrink|sharpen|improv)\w*|tighter|narrower|smaller|sharper|better) (?:\w+ ){0,3}?with '
        r'(?:each|every|another|more|extra|additional)\b',
    ], None, None,
     'says another source narrows the bound, and a source of the same width narrows nothing: the third kind narrowed nothing '
     'and nobody may write that it did (rule 1 of what this product may say)'),
    ('enforcement', [
        r'\b(prevents?|prevented|preventing|stops?|stopped|stopping|blocks?|blocked|blocking|halts?|halted|halting|thwarts?|'
        r'thwarted|forbids?|forbade|defeats?|defeated|deters?|deterred|foils?|foiled|intercepts?|guards? (?:\w+ ){0,3}?against|'
        r'protects? (?:\w+ ){0,3}?(?:against|from)|defends? (?:\w+ ){0,3}?against|rules? out|shuts? down)\b[^.;,]{0,45}?'
        r'\b(?:back.?dat\w*|tamper\w*|attack\w*|rollback\w*|roll(?:ed|ing|s)? back|publish\w*|deploy\w*|releas\w*|forg\w*|fraud\w*|'
        r'spoof\w*|manipulat\w*|adversar\w*|attacker\w*|malicious|intruder\w*|offending|rogue|unauthori[sz]ed|fraudulent|'
        r'from (?:being|completing|happening|taking effect|going|running|landing|shipping)|in real time|at runtime|'
        r'before (?:it|they) (?:can|could)|being (?:published|deployed|released|merged|shipped)|'
        # The neutral objects: what a CI gate would be said to act on. "Blocks any build whose clock
        # has drifted" is the claim with no adversary word in it.
        r'builds?\b|pipelines?\b|publication|merges?\b|commits?\b|pushes\b|tags?\b|workflows?\b|jobs?\b|artefacts?\b|artifacts?\b|'
        r'packages?\b|images?\b|signatures?\b|(?:the |an? |any |every )action\b|promotion|the release|runs?\b|steps?\b)',
        # The gating verbs are the claim when negated: "will not permit", "refuses to let ... continue".
        r"\b((?:will not|won't|does not|doesn't|do not|don't|did not|never|cannot|can't|refuses? to|declines? to|is not going to) "
        r"(?:permit|allow|let|authori[sz]e|tolerate|admit|clear|green.?light|wave through) (?:\w+ ){0,4}?"
        r"(?:builds?|pipelines?|releases?|publication|deploy\w*|merges?|commits?|push(?:es)?|tags?|workflows?|jobs?|steps?|runs?|"
        r"artefacts?|artifacts?|packages?|images?|signatures?|stamps?|receipts?|actions?|anything|it|them|through|continue|proceed|past|out))\b",
        # The noun forms.
        r'\b((?:prevention|blocking|interception|deterrence|suppression) of (?:\w+ ){0,2}?(?:tamper\w*|back.?dat\w*|rollbacks?|attacks?|'
        r'fraud|forger\w*|spoofing|manipulation))\b',
        r'\b((?:tamper|rollback|back.?dating|fraud|attack|replay) (?:prevention|blocking|suppression|interception))\b',
        r'\b(enforcement)\b',
        r'\b(tamper-? ?proof)\b',
        r'\b((?:cannot|can\'t|can not|could not|couldn\'t|will never|can never|impossible to|no way to|nobody can|no one can|never) '
        r'be (?:back.?dated|tampered with|rolled back))\b',
        r'\b(?:back.?dating|tampering|rollback|clock rollback|a rollback|rolling back)\b[^.;,]{0,20}?\b((?:is|are|becomes?|is made|are made) '
        r'(?:\w+ )?impossible)\b',
        r'\b(makes? (?:\w+ ){0,3}?(?:back.?dating|tampering|rollback|rolling back) impossible)\b',
        r'\b((?:nothing|no (?:build|release|artefact|artifact|commit|deployment|merge|tag|package|image))\b[^.;,]{0,40}?'
        r'\b(?:gets?|is|can be|will be|ever|may be|shall be) (?:published|deployed|released|shipped|merged|promoted|committed|pushed|'
        r'tagged|accepted|signed off))\b',
        # The passive, and the two impossibility forms that name the adversary's act rather than ours.
        r'\b(?:back.?dat\w*|tamper\w*|attacks?|rollbacks?|roll.?backs?|forger\w*|fraud|spoofing|manipulation|deployments?|builds?|'
        r'releases?|publication|merges?|commits?|pipelines?|the action)\b[^.;,]{0,20}?'
        r'\b(?:is|are|was|were|gets?|get) (?:\w+ly )?((?:blocked|prevented|stopped|halted|thwarted|forbidden|defeated|deterred|foiled|'
        r'intercepted|ruled out|shut down))\b',
        r'\b(?:tampered|back.?dated|forged|rolled.back|fraudulent|rogue|malicious|unauthori[sz]ed)\b[^.;,]{0,25}?'
        r'\b((?:cannot|can\'t|can never|will never|could never|never) (?:be )?(?:published|deployed|released|shipped|merged|go out|'
        r'get out|land|pass|slip through|get through))\b',
        r'\b(?:nobody|no one|no-one|none)\b[^.;,]{0,30}?\b((?:gets? to|can|could|is able to|will be able to|would be able to|may|shall)'
        r'(?: ever)? (?:\w+ )?(?:tamper|back.?date|roll back|falsify))\b',
        r'\b(stands? guard|standing guard|keeps? watch)\b',
        r'\b(guarantee\w*)\b[^.;,]{0,30}?\b(?:back.?dat\w*|tamper\w*|rollback|rolled back|forg\w*)',
        r'\b((?:rollback|tamper|back.?dating|replay) protection|protection (?:against|from) (?:rollback|tamper\w*|back.?dat\w*|replay))\b',
        r'\b(enforces? (?:honest|correct|true|accurate|trustworthy|genuine) (?:time|timestamps?|stamps?|clocks?|dates?))\b',
        r'\b(?:publication|publishing|releases?|deployments?|deploys?|builds?|merges?|shipping)\b[^.;,]{0,15}?'
        r'\b((?:does not|doesn\'t|do not|don\'t|will not|won\'t|cannot|can\'t|is not allowed to|are not allowed to) '
        r'(?:go ahead|proceed|happen|ship|go out|complete|run|land))\b',
    ], None, None,
     'claims enforcement, and TimeWitness declines to sign rather than preventing anything: a refusal records that it did not sign, '
     'not that an action was stopped (rule 3 of what this product may say)'),
    ('averaging', [
        r'(?<!on )\b(averag\w*)\b(?! (?:desktop|machine|laptop|user|person|day|case|network|round.?trip|latency|developer|reader))',
        r'\b((?:summed|added up|added together|totalled|totaled)\b[^.;,]{0,30}?\bdivided\b|divided by the (?:number|count) of)\b',
        r'\b((?:the|a|an|simple|plain|arithmetic|weighted|straight|running) mean|mean of|mean (?:offset|time|reading|value|clock))\b',
        r'\b(median)\b',
        r'\b((?:midpoint|middle (?:value|point|reading|answer)) of (?:the |its |all )?(?:\w+ )?(?:readings|sources|answers|replies|responses|'
        r'clocks|servers|offsets|intervals|values))\b',
        r'\b(split(?:s|ting)? the difference)\b',
        r'\b(consensus (?:of|between|among|value|time|offset)|midpoint between|the (?:one|value|reading|answer) in the middle|middle one)\b',
        r'\b(pool(?:ed|s|ing)?|blend(?:ed|s|ing)?|smooth(?:ed|s|ing)?)\b',
        r'\b(?:finds?|computes?|calculates?|derives?|arrives? at|determines?|works? out|settles? on|reports?) (?:the )?(true (?:time|UTC))\b',
    ], None, None,
     'says readings are averaged, and sources are combined by Marzullo intersection and never averaged: an average of clocks is '
     'not a measurement (rule 4 of what this product may say)'),
    ('legal weight', [
        r'\b(legal(?:ly)?)\b',
        r'\b(evidenti(?:al|ary))\b',
        r'\b((?:in|before|to) (?:a |the )?courts?|court-?(?:ready|grade|admissible|proof)|(?:hold|stand)s? up in court)\b',
        r'\b(admissible (?:in|as))\b',
        r'\b(non-?repudiation|notar\w*|barristers?|solicitors?|attorneys?|lawyers?|tribunals?|litigation|(?:the|a|your) hearing)\b',
        r'\b((?:same|equal|equivalent|as much) (?:weight|standing|force|authority) (?:as|to)|carries (?:the )?(?:same |legal |full )?weight)\b',
        r'\b(complian\w+(?: claim)?|compl(?:y|ies|ied|ying) with)\b',
        r'\b((?:satisf|meet|fulfil|pass|tick|discharg)\w* (?:\w+ ){0,4}?(?:requirements?|regulations?|regulators?|rules?|standards?|'
        r'obligations?|audits?|mandates?))\b',
        r'\b((?:required|mandated|recognised|recognized|accepted|approved|endorsed) (?:by|under) (?:the |a )?(?:\w+ )?(?:regulat\w+|law|'
        r'courts?|SEC|FINRA|eIDAS|EU|statute|auditors?))\b',
        r'\b(regulators? (?:accept|recogni[sz]e|approve|require|treat)s?)\b',
        r'\b((?:certified|qualified|legal|official) (?:electronic )?time.?stamps?)\b',
        r'\b(eIDAS|AI Act|Article 12|17a-4|FINRA|MiFID|GDPR|Sarbanes|SOX|HIPAA|DORA|NIS ?2|21 CFR|Part 11|ISO ?27001|SOC ?2|ETSI|PCI.?DSS)\b',
    # What makes the mention honest is saying where standing comes from, never the noun on its own:
    # until 2026-09-16 "qualified trust service provider" was on this list, so "We are a qualified
    # trust service provider for timestamping" passed on the entry written to let the denial through.
    ], None, r'\bfrom (?:being )?(?:an? )?accredit\w*\b|\baccreditation\b[^.;,]{0,20}?\b(?:rather|not|confers?|is (?:the only|what))\b|'
             r'\bstanding\b[^.;,]{0,25}?\bcomes from\b|\bcomes from (?:being )?(?:an? )?(?:accredit\w*|qualified|QTSP)\b',
     'claims legal weight or compliance, and standing comes from accreditation rather than engineering: no regulation we have '
     'checked requires a clock bound (rule 6 of what this product may say)'),
    ('accreditation', [
        r'\b(?:we|TimeWitness|the (?:agent|product|company)|our (?:company|product)) (?:is|are|am|remains?|became|become|were|was)\b'
        r'[^.;,]{0,25}?\b((?:an? )?(?:accredited|qualified trust service|QTSP|certified|licen[sc]ed|approved|recogni[sz]ed))\b',
        r'\b(our (?:eIDAS |own )?(?:accreditation|QTSP status|qualified status|licen[sc]e|certification|qualification))\b',
        r'\b((?:eIDAS[- ])?qualified (?:trust service provider|status|time.?stamps?|electronic time.?stamps?)\b[^.;,]{0,30}?'
        r'\b(?:is|are|ours|conferred|granted|held|comes with|ships))\b',
    ], None, None,
     'claims accreditation or qualified status, and this product holds neither: standing under eIDAS comes from being an '
     'accredited qualified trust service provider, which we are not (rule 6 of what this product may say)'),
]
CLAIMS = [(name, [re.compile(p, re.I) for p in patterns], re.compile(needs, re.I) if needs else None,
           re.compile(unless, re.I) if unless else None, message) for name, patterns, needs, unless, message in CLAIMS]


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


def claimed(sentence):
    """Which of the principle claims the sentence asserts, each as its refusal."""
    faults = []
    if sentence.rstrip().endswith('?'):
        return faults
    for name, patterns, needs, unless, message in CLAIMS:
        if needs and not needs.search(sentence):
            continue
        for pattern in patterns:
            for m in pattern.finditer(sentence):
                group = 1 if m.re.groups else 0
                c0, c1 = clause_around(sentence, m.start(group))
                if unless and unless.search(sentence[c0:c1]):
                    continue
                if not denied(sentence, m, group):
                    faults.append(message)
                    break
            else:
                continue
            break
    return faults


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
    floor_at = set()
    if re.search(r'\boperator', sentence, re.I):
        for rule in FLOOR_COUNT:
            for m in rule.finditer(sentence):
                n = counted(m)
                if n is None:
                    continue
                floor_at.add(m.start(1))
                if n != floor:
                    faults.append(f'puts the operator floor at {n}, and it is {floor}')
                    break
            else:
                continue
            break
    if re.search(r'\bRoughtime\b', sentence) and not re.search(r'\bNTP\b|\bNTS\b', sentence):
        for m in ROUGHTIME_SERVERS.finditer(sentence):
            count = next(g for g in m.groups() if g is not None)
            try:
                n = int(number_of(count))
            except ValueError:
                continue
            if n != policy['roughtime_servers']:
                faults.append(f'puts {n} published Roughtime servers where there are {policy["roughtime_servers"]}')
            break
        for m in ROUGHTIME_COUNT.finditer(sentence):
            n = counted(m)
            c0, c1 = clause_around(sentence, m.start(1))
            if n is None or m.start(1) in floor_at or re.search(r'\bfloor\b|\bminimum\b|\bquorum\b', sentence[c0:c1], re.I):
                continue
            if n != rt:
                faults.append(f'puts {n} operators behind the published Roughtime servers, and there are {rt}')
            break
    for rule in KIND_COUNT:
        m = rule.search(sentence)
        if m:
            n = counted(m)
            if n is not None and n != policy['kinds']:
                faults.append(f'says {n} kinds of time source have a client, and {policy["kinds"]} do')
            break
    if HAS_CLIENT.search(sentence):
        for m in FOREIGN_KIND.finditer(sentence):
            if m.group(1) not in policy['kind_names'] and not denied(sentence, m):
                faults.append(f'names a {m.group(1)} client, and the kinds with a client are '
                              f'{", ".join(sorted(policy["kind_names"]))}')
                break
    m = SIGNS_ON.search(sentence)
    if m and not denied(sentence, m):
        n = counted(m)
        if n is not None and n < floor:
            faults.append(f'says it signs on {n} operators, and the floor refuses below {floor}')
    m = SOURCES_ENOUGH.search(sentence)
    if m and not denied(sentence, m):
        n = counted(m)
        if n is not None and n < floor:
            faults.append(f'says {n} source{"s" if n != 1 else ""} {"are" if n != 1 else "is"} enough, and a source stands '
                          f'at one operator, so fewer than the floor of {floor} operators can never be enough')

    if not policy['floor_lowerable']:
        for m in LOWERING.finditer(sentence):
            if not negated(sentence, m):
                faults.append('says the operator floor can be lowered, and no option or input that ships lowers it')
                break

    if policy['local_model_only']:
        plain = NEVER_HEARD.sub('who are strangers to us', sentence)
        for rule in VOUCHING:
            m = rule.search(plain)
            if m and not denied(plain, m, 1):
                faults.append('says outside evidence supports the width, and every receipt this code issues '
                              'rests on its own model')
                break
    m = RECEIPT_SIGNED_BY.search(sentence)
    if m and not denied(sentence, m, 1):
        faults.append('says a receipt is signed by an outside party, and a receipt is signed by the agent\'s own key: the '
                      'outside signatures inside it are on the signers\' own answers (rule 2 of what this product may say)')
    for m in NTS_EVIDENCE.finditer(sentence):
        group = 1 if m.group(1) is not None else 2
        c0, c1 = clause_around(sentence, m.start(group))
        clause = sentence[c0:c1]
        # NTS has to be the subject of the clause the evidence word sits in: in that clause, or in
        # the one before it with no other source named in this one.
        if 'NTS' not in clause and OTHER_SOURCE.search(clause):
            continue
        if not denied(sentence, m, group):
            faults.append('presents NTS as evidence, and NTS can never be portable evidence: its keys are symmetric, so the '
                          'machine holding one could compose the answer it then checks (rule 2 of what this product may say)')
            break

    for rule in OWN_AS_EVIDENCE:
        m = rule.search(sentence)
        if m and not denied(sentence, m, 1):
            faults.append('presents our own bound as evidence, and our own bound is labelled inside the receipt as our claim: only '
                          'a signature a stranger can check is evidence (rule 2 of what this product may say)')
            break
    for c0, c1 in clauses(sentence):
        clause = sentence[c0:c1]
        for role, source in ROLE_SOURCE.items():
            s = source.search(clause)
            if not s:
                continue
            for direction, said in ROLE_DIRECTION.items():
                d = said.search(clause)
                if d and direction != ROLE_PROVES[role] and not denied_pair(sentence, c0, c1, (c0 + s.start(), c0 + s.end()),
                                                                             (c0 + d.start(), c0 + d.end())):
                    faults.append(f'gives a {role} the {direction} role, and a {role} proves {ROLE_PROVES[role]}: the three evidence '
                                  f'roles do different jobs and none of them does another\'s (rule 2 of what this product may say)')
                    break
        v, e = DELAY_FUNCTION.search(clause), ELAPSED.search(clause)
        if v and e and not denied_pair(sentence, c0, c1, (c0 + v.start(), c0 + v.end()), (c0 + e.start(), c0 + e.end())):
            faults.append('says a verifiable delay function proves elapsed time, and it proves sequential work rather than elapsed '
                          'seconds (rule 4 of what this product may say)')
        m = ROUGHTIME_STANDARD.search(clause)
        if m and not STANDING_SAID.search(clause):
            group = 1 if m.group(1) else 2
            if not denied_at(sentence, c0 + m.start(group), c0 + m.end(group)):
                faults.append(f'calls Roughtime a standard, and the specification this code implements is {policy["roughtime_standing"]}')
    for figure, where in FOREIGN_FIGURES:
        for m in figure.finditer(sentence):
            c0, c1 = clause_around(sentence, m.start())
            clause = sentence[c0:c1]
            if OURS_MEASURED.search(clause) or (OURS_SUBJECT.search(clause) and not ATTRIBUTED.search(sentence)
                                                and not denied_at(sentence, m.start(), m.end())):
                faults.append(f'writes {m.group().strip()} as ours, and it is somebody else\'s figure for {where}, quoted from public '
                              'research and never measured by this product (rule 1 of what this product may say)')
                break
    m = SIMULATED_FIGURES.search(sentence)
    if m and not SIMULATED.search(sentence):
        faults.append(f'gives {m.group()} as a reading, and it is the arithmetic of the simulated harness at '
                      'crates/clock/tests/common/mod.rs and says so wherever it is quoted (rule 1 of what this product may say)')

    if policy['kinds'] >= 2:
        m = ONE_SOURCE.search(sentence)
        if m and not negated(sentence, m):
            faults.append(f'speaks of one kind of time source, and {policy["kinds"]} have a client')

    if not policy['refusal_receipt']:
        m = REFUSAL_RECEIPT.search(sentence)
        if m and not negated(sentence, m) and not REFUSAL_HYPOTHETICAL.search(sentence):
            faults.append('speaks of a refusal receipt as a thing that exists, and there is no refusal receipt')

    def whose(before):
        # Whose ceiling the figure is, read off the nearest subject before it in the sentence, and
        # off the whole sentence where nothing comes before it.
        agent_at = max((a.end() for a in AGENT.finditer(before)), default=-1)
        shot_at = max((a.end() for a in ONE_SHOT.finditer(before)), default=-1)
        if agent_at < 0 and shot_at < 0:
            agent_at = 0 if AGENT.search(sentence) else -1
            shot_at = 0 if ONE_SHOT.search(sentence) else -1
        return agent_at, shot_at

    for m in CEILING.finditer(sentence):
        groups = [g for g in m.groups() if g is not None]
        number, unit = groups[0], groups[1]
        try:
            value = duration_ns(number, unit.lower())
        except ValueError:
            continue
        agent_at, shot_at = whose(sentence[:m.start()])
        if agent_at < 0 and shot_at < 0:
            faults.append(f'states a ceiling of {number} {unit} without saying whose; the agent refuses '
                          f'over {policy["agent_ns"] / 1e6:g} ms and the one-shot command over '
                          f'{policy["one_shot_ns"] / 1e9:g} s')
        elif agent_at >= shot_at and value != policy['agent_ns']:
            faults.append(f'puts the agent\'s ceiling at {number} {unit}, and it is {policy["agent_ns"] / 1e6:g} ms')
        elif shot_at > agent_at and value != policy['one_shot_ns']:
            faults.append(f'puts the one-shot ceiling at {number} {unit}, and it is {policy["one_shot_ns"] / 1e9:g} s')
    m = INSIDE_CEILING.search(sentence)
    if m and not denied(sentence, m):
        try:
            value = duration_ns(m.group(1), m.group(2).lower())
        except ValueError:
            value = None
        agent_at, shot_at = whose(sentence[:m.start()])
        agent_at, shot_at = (0, -1) if agent_at < 0 and shot_at < 0 else (agent_at, shot_at)
        ceiling, label = ((policy['agent_ns'], f'{policy["agent_ns"] / 1e6:g} ms') if agent_at >= shot_at
                          else (policy['one_shot_ns'], f'{policy["one_shot_ns"] / 1e9:g} s'))
        if value is not None and value > ceiling:
            faults.append(f'puts {m.group(1)} {m.group(2)} inside the ceiling, and the ceiling is {label}')

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

    faults += claimed(sentence)
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
    ('max-width default', 'Unless you set max-width, the ceiling is a minute.'),
    # From 2026-09-16: the sentences two independent test passes wrote that day and this check let
    # through, one or more per class, and the classes it had no rule for at all.
    ('operator floor stated wrongly', 'Three operators is all a round needs before we will sign.'),
    ('operator floor stated wrongly', 'We will not sign unless five separate operators answer.'),
    ('operator floor stated wrongly', 'TimeWitness accepts a quorum of three independent operators before it will sign.'),
    ('operator floor can be lowered', 'The floor for independent operators was reduced to two in the latest release.'),
    ('sources said to be enough', 'One good source is enough to bound the clock.'),
    ('Roughtime operator count stated wrongly', 'Roughtime gives us four operators today.'),
    ('Roughtime operator count stated wrongly', 'Roughtime is run by half a dozen operators we can reach.'),
    ('kind count stated wrongly', 'Our agent disciplines the clock against five independent kinds of time source.'),
    ('a client that does not ship', 'We ship clients for Roughtime, NTP, NTS and PTP.'),
    ('a ceiling stated wrongly', 'The agent will happily report a bound of 300 milliseconds.'),
    ('a ceiling stated wrongly', 'The Action refuses anything over ten seconds.'),
    ('a ceiling stated wrongly', 'The agent holds itself to a quarter of a second, or half a second at worst.'),
    ('a ceiling stated wrongly', 'Six hundred milliseconds is within the agent\'s accepted bound today.'),
    ('a ceiling stated wrongly', 'The resident agent will happily sign a receipt with a bound as wide as five hundred milliseconds.'),
    ('outside evidence supports the width', 'The outside signatures are what make the width believable.'),
    ('outside evidence supports the width', 'Independent parties sign off on how wide the bound is.'),
    ('outside evidence supports the width', 'Our own bound is independently verified by a neutral third party before it ships.'),
    ('outside evidence supports the width', 'The agent\'s measured bound counts as outside, stranger-checkable evidence on its own.'),
    ('a receipt signed by an outside party', 'Every receipt is signed by Roughtime.'),
    ('a receipt signed by an outside party', 'Every receipt is countersigned by the Roughtime operators.'),
    ('NTS as evidence', 'NTS timestamps give a stranger portable, verifiable evidence of the bound.'),
    ('NTS as evidence', 'Because NTS authenticates the packet, its evidence is as portable as Roughtime\'s.'),
    ('accuracy claimed', 'Our clock is accurate to the millisecond.'),
    ('accuracy claimed', 'The agent reports UTC with nanosecond accuracy.'),
    ('accuracy claimed', 'The agent\'s nanosecond reading is also its accuracy figure against UTC.'),
    ('accuracy claimed', 'TimeWitness delivers accurate time to the nanosecond on every stamp.'),
    ('another source narrows the bound', 'Adding another server narrows the bound.'),
    ('another source narrows the bound', 'NTS tightens the interval because the packet is authenticated.'),
    ('another source narrows the bound', 'More sources means a tighter interval every time.'),
    ('enforcement', 'TimeWitness prevents a backdated build from being published.'),
    ('enforcement', 'The agent stops a clock rollback attack before it can take effect.'),
    ('enforcement', 'TimeWitness blocks tampering with the build pipeline in real time.'),
    ('enforcement', 'A stamped build cannot be backdated afterwards.'),
    ('enforcement', 'The receipt is tamper-proof.'),
    ('averaging', 'TimeWitness averages the readings from all its sources to compute true time.'),
    ('averaging', 'The clock model takes a simple mean of the source clocks to find the correct offset.'),
    ('averaging', 'The agent takes the median of the nine answers as the time.'),
    ('legal weight', 'TimeWitness receipts carry legal weight under eIDAS once they are countersigned.'),
    ('legal weight', 'Using TimeWitness satisfies SEC 17a-4 recordkeeping requirements out of the box.'),
    ('legal weight', 'Our receipts are admissible in court as certified legal timestamps.'),
    ('legal weight', 'These receipts will hold up in court.'),
    # From the two cold sets of 2026-09-16, written from the rules of what this product may say before this file was opened,
    # which refused 26 of 45 and 22 of 45 against the rules above: one or two sentences a class.
    ('somebody else\'s figure written as ours', 'We measured 5 to 50 ms over the public internet, so your bound is never worse than that.'),
    ('somebody else\'s figure written as ours', 'On a good LAN our agent holds about 1 ms against a stratum-1 source.'),
    ('somebody else\'s figure written as ours', 'About 100 microseconds on a cloud instance is what TimeWitness reaches with a hypervisor clock.'),
    ('a simulated figure given as a reading', 'The agent settles at 26.6 ms at synchronisation and 234.6 ms after fifteen minutes on real networks.'),
    ('a simulated figure given as a reading', 'The bound narrows to 26.6 ms at synchronisation.'),
    ('accuracy claimed', 'Accuracy is the whole product: we tell you the time correctly to the nanosecond.'),
    ('accuracy claimed', 'Accuracy to UTC is guaranteed at one millisecond by the resident agent.'),
    ('accuracy claimed', 'Accuracy today is 128.7 milliseconds and improving.'),
    ('Roughtime called a standard', 'Roughtime is an RFC, so the corridor is standards-backed.'),
    ('Roughtime server count stated wrongly', 'Roughtime\'s four public servers were probably unreachable; check your firewall.'),
    ('our bound presented as evidence', 'Because our agent signs the interval, the interval is independently attested.'),
    ('our bound presented as evidence', 'A Roughtime signature and our own bound are the same kind of proof.'),
    ('our bound presented as evidence', 'Treat the agent\'s interval as the independent witness.'),
    ('our bound presented as evidence', 'Every receipt carries independent evidence generated by our own agent.'),
    ('our bound presented as evidence', 'The bound we compute is evidence nobody has to trust us for.'),
    ('our bound presented as evidence', 'We are not a notary, we are the independent witness standing behind your own bound.'),
    ('an evidence role swapped', 'The freshness beacon proves the stamp was not made later than it says.'),
    ('an evidence role swapped', 'An RFC 3161 authority in the receipt proves the event was not earlier than the stamp.'),
    ('NTS as evidence', 'Evidence of not-later-than comes from our NTS discipline.'),
    ('enforcement', 'TimeWitness blocks any build whose clock has drifted out of bounds.'),
    ('enforcement', 'The gate refuses to let the pipeline continue when the bound is too wide.'),
    ('enforcement', 'TimeWitness will not permit a signature outside the corridor.'),
    ('enforcement', 'Prevention of tampering is built into the agent.'),
    ('enforcement', 'The agent, which refuses to sign, thereby prevents the action.'),
    ('enforcement', 'Deployment is blocked automatically when the bound is exceeded.'),
    ('enforcement', 'Nothing that happens outside the bound can be committed.'),
    ('averaging', 'Outliers are averaged out rather than discarded.'),
    ('averaging', 'The readings are summed and divided by the number of servers.'),
    ('a verifiable delay function proving elapsed time', 'A verifiable delay function proves how many seconds actually elapsed.'),
    ('accreditation claimed', 'We are a qualified trust service provider for timestamping.'),
    ('accreditation claimed', 'eIDAS qualified status is conferred by the public verifier.'),
    # The denial of something else, which switched four of the five claim rules off until 2026-09-16.
    ('a denial of something else', 'Certified microsecond accuracy ships with the standard agent and no hardware is required.'),
    ('a denial of something else', 'We average the sources and no hardware is required.'),
    ('a denial of something else', 'TimeWitness receipts are legally admissible under eIDAS and no hardware is required.'),
    ('a denial of something else', 'Our agent\'s own bound is the third-party evidence in every receipt and no hardware is required.'),
    ('a denial of something else', 'Never mind the weather, our agent\'s own bound is the third-party evidence in every receipt.'),
    ('a denial of something else', 'It averages the readings but not the outliers.'),
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
    # The sentences the surfaces carry nearest each claim refused on principle, from 2026-09-16.
    # Each has to pass while the seed beside it in the list above is refused.
    'The reading is at nanosecond resolution and the accuracy to UTC is in milliseconds.',
    'Nanoseconds is the resolution of the local read and never the accuracy to UTC.',
    'Milliseconds is the accuracy to UTC.',
    'Nanosecond accuracy is a datacentre thing and is not something this product sells.',
    'Bounded, not accurate.',
    'Resolution is not accuracy.',
    'A machine\'s recorded time looks precise and is not.',
    'What that third kind buys is not a narrower bound, and this list says so before anything else.',
    'The third kind narrowed nothing and the breakdown says so.',
    'An authenticated corridor does not tighten the bound.',
    'A round under the floor is refused.',
    'It does not prevent anything: a refusal records that TimeWitness declined to sign, not that an action was stopped.',
    'We do not claim to prevent that at runtime.',
    'An agent that cannot reach its sources stops issuing receipts; it does not issue worse ones.',
    'A refusal prevents nothing from being published.',
    'An average of clocks is not a measurement and lets one liar move the answer.',
    'Combined by Marzullo intersection and then inverse-square weighting, never averaged.',
    'Sources are combined by Marzullo intersection and a weighted regression, never a plain average.',
    'It does not establish legal weight, which comes from accreditation rather than engineering, and no regulation we have checked requires it.',
    'Legal standing in this area comes from accreditation, meaning qualified trust service provider status under eIDAS, and not from engineering.',
    'A private root is admissible and never presumed.',
    'No regulation we have checked, including AI Act Article 12, SEC 17a-4 and FINRA 4511 and 6820, requires tamper-evidence, cryptographic proof or clock accuracy, so a compliance claim built on any of them would be false.',
    'It carries no legal weight and no compliance claim.',
    'NTS improves the clock and can never be portable evidence.',
    'The receipt format refuses an NTS response in an evidence role outright.',
    'Three time source clients exist in this repository, Roughtime, plain NTP and NTS, and only Roughtime signs anything a stranger can check.',
    'The interval is our own claim and the outside evidence does not vouch for it.',
    'The width is our own claim and the outside signatures bracket the moment rather than the width.',
    'Our own bound is labelled inside the receipt as our claim, never as third-party evidence.',
    'Most stratum-1 servers in the world are disciplined by GPS, and one spoofed constellation moves every operator that trusts it.',
    'A Roughtime corridor, where one is carried and checked, is signed by a key the reader holds, and every other operator name is the signer\'s word.',
    'Three operators publish the Roughtime servers we reach today.',
    'The agent\'s width ceiling refuses any bound wider than two hundred and fifty milliseconds.',
    # The honest sentences the two cold sets of 2026-09-16 carried that were refused, and the ones
    # nearest the rules added that day. Each has to pass while its neighbour in the list above is refused.
    'Anyone promising you microsecond accuracy without hardware is selling something we cannot build.',
    'A mean of clocks would be arithmetic rather than a measurement, which is why there is none here.',
    'Standing under eIDAS comes from being an accredited QTSP, and we are not one.',
    'No legal weight is claimed, and accreditation under eIDAS is the only thing that confers it.',
    'AI Act Article 12 does not require tamper-evidence.',
    'AI Act Article 12 does not require tamper-evidence, and we do not say that it does.',
    'eIDAS does not apply to a private root.',
    'SEC 17a-4 did not ask for a clock bound.',
    'Our receipts do not carry legal weight.',
    'The 5 to 50 ms figure is quoted from public research and has not been measured by us.',
    'The 5 to 50 ms, the 1 ms and the 100 microsecond figures are quoted from public research and none of them has been measured by us.',
    'About 1 ms on a good LAN against a stratum-1 source',
    'That figure and the widths behind it, 26.6 ms at the moment of synchronising and 234.6 ms at fifteen minutes, come from the simulated harness at crates/clock/tests/common/mod.rs, whose whole purpose is that the true offset is a number the test wrote down; they are the arithmetic of the model rather than a reading from a real network.',
    'A public freshness beacon proves not-earlier-than, because the beacon value could not have been known before its round was published.',
    'An independent final witness proves not-later-than: an RFC 3161 timestamp authority, a transparency log, or an anchor into a public chain.',
    'DigiCert signed for the payload hash, so the document existed no later than the moment its token states.',
    'It cannot prove elapsed time from a verifiable delay function, which proves sequential work.',
    'A delay function shows that sequential work was done, and it says nothing about how many seconds passed.',
    'Roughtime is an Internet-Draft that expires on 18 September 2026.',
    'A Roughtime corridor, a drand beacon and an RFC 3161 timestamp authority.',
    'The interval is our own claim and the outside evidence does not vouch for it.',
    'NTS improves the clock and can never be portable evidence.',
    'Two of the four timestamps in an exchange are the source\'s, and so is its statement about its own accuracy.',
    'Resolution and accuracy get confused constantly and the confusion is the whole problem this product exists to fix.',
    'An agent that cannot reach its sources stops issuing receipts; it does not issue worse ones.',
    'A refusal does not prevent anything, it records that we declined to sign.',
    'We do not block a deploy; the receipt records what the clock could have been.',
    'Nothing prevents a machine from lying about its own clock; the receipt makes the lie checkable.',
]


def content_reader_reads_the_leaf():
    """Whether site_strings prunes a note's own string and nothing above or beside it. Until
    2026-09-16 a key that looked like a note pruned the object under it, and the front page's
    install note went unread."""
    seed = 'The install block says our clock is accurate to the microsecond.'
    faults = []
    for key in ('commandNote', 'gapNote', 'editorNote', 'srcNote', 'provenance', 'src', 'id', '$source'):
        if list(site_strings({key: seed})):
            faults.append(f'a string under the key {key} was read, and it is a note')
        if [s for _, s in site_strings({key: {'text': seed}})] != [seed]:
            faults.append(f'the object under the key {key} was pruned whole, and only its own string is a note')
    for key in NOT_SERVED_OBJECTS:
        if list(site_strings({key: [{'note': seed}, seed]})):
            faults.append(f'a string under {key} was read, and that object is editorial in full')
    if [s for _, s in site_strings({'install': {'commandNote': {'text': seed, 'src': 'x', 'id': 'y'}}})] != [seed]:
        faults.append('install.commandNote.text is not read, and the front page prints it')
    return faults


def the_fetch_refuses_a_redirect():
    """A local server answers 302 on every path, and the fetch has to refuse each one by name.

    It is here rather than in a file beside it because the fault was in the one function nothing
    tested: `served_text` is the only thing in this product that reads what a visitor is actually
    given, and it followed a redirect in silence. The server below is that measurement made
    repeatable, and the three cases after it are the ones a rewrite of this function would
    otherwise break quietly.
    """
    import http.server
    import threading

    faults = []

    class Answers(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/elsewhere':
                body = b'<p>A real page, well over the sentence floor.</p>'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == '/missing':
                self.send_error(404)
            else:
                self.send_response(302)
                self.send_header('Location', '/elsewhere')
                self.end_headers()

        def log_message(self, *_):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Answers)
    base = f'http://127.0.0.1:{server.server_address[1]}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for page in SITE_PAGES:
            try:
                served_text(base + page)
                faults.append(f'{page} answered 302 to /elsewhere and was read as though it were {page}')
            except Unreadable as e:
                if '/elsewhere' not in str(e) or page not in str(e):
                    faults.append(f'the refusal of {page} names neither the path asked for nor the '
                                  f'one landed on: {e}')
        # What was already right and stays right: a page that answers is read, and a 404 is an error
        # rather than an empty page read as honest.
        if 'real page' not in served_text(base + '/elsewhere'):
            faults.append('a page that answers on the path asked for is no longer read')
        try:
            served_text(base + '/missing')
            faults.append('a 404 no longer fails the fetch')
        except urllib.error.HTTPError:
            pass
    finally:
        server.shutdown()
        server.server_close()

    # The one hop that is followed, and the shapes that look like it and are not.
    allowed = ('http://timewitness.dev/cannot-prove', 'https://timewitness.dev/cannot-prove')
    if not only_the_scheme(*allowed):
        faults.append('an upgrade to https on the same host and path is meant to be followed')
    for asked, to in [('http://timewitness.dev/', 'https://timewitness.dev/screen'),
                      ('http://timewitness.dev/', 'https://www.timewitness.dev/'),
                      ('https://timewitness.dev/', 'http://timewitness.dev/'),
                      ('http://timewitness.dev/', 'https://timewitness.dev/?preview=1')]:
        if only_the_scheme(asked, to):
            faults.append(f'{asked} to {to} is more than an upgrade of the scheme and was allowed')
    return faults


def self_test(policy):
    missed = content_reader_reads_the_leaf() + the_fetch_refuses_a_redirect()
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
    print(f'policy sentences: {len(SEEDS)} seeds, each refused by its own rule, {len(HONEST)} honest sentences passed, and the '
          f'content reader prunes a note and reads the object under a note-shaped key')
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
