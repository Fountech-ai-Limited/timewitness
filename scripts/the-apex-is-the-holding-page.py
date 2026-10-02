#!/usr/bin/env python3
"""Whether the page the public address answers with is the holding page, read as a page.

While the product is in development `timewitness.dev` serves one holding page and sends every other
page of the site to it, the limitation list among them. `scripts/three-surfaces.sh` then has no site
copy of the list to compare, and says so. What it has to be sure of first is that the page in front
of it really is the holding page, because that answer is what lets the wire route stop comparing.

Until 2026-09-23 it was sure on a substring. A root whose bytes contained
`<meta name="tw-stage" content="holding"` anywhere passed: inside a comment, inside a script string,
in a textarea, on a marketing page selling what this product may not claim with no limitation list
on it, on the holding page with its link to the list taken off, and in the body of a 302 to somebody
else's origin. Seven shapes of eleven that were not the holding page passed, and nothing in the
build ran the branch, so returning yes unconditionally left every check green. Found on 2026-09-23
by driving the branch with each shape.

So the page is parsed rather than searched, and three things have to hold, each named where it does
not:

1. The root answered 200 itself. A redirect is not the holding page, whatever its body says.
2. `tw-stage` is `holding` on a real `meta` element whose parent is `head`. Text in a comment, a
   script, a textarea or the body is not the tag, however it is spelled.
3. The page links to the limitation list, with words on the link. A page with no way to what the
   product cannot prove is not the holding page, because shipping that beside the claim is the one
   thing the holding page exists to keep doing: every claim ships beside what it cannot prove.

    python3 scripts/the-apex-is-the-holding-page.py <status> <page.html>
    python3 scripts/the-apex-is-the-holding-page.py --self-test

exits 0 when the page is the holding page, 1 naming each thing that is not so, and 2 when the page
could not be read. The self-test builds each of the seven shapes and the holding page itself, and
watches the first seven refused and the last accepted, twice: once here, and once through the wire
route of `scripts/three-surfaces.sh` against a local server answering the way the public address
does, because that branch is the thing the shapes got through and the scheduled guard was the only
other caller. It needs what that script needs, a built `timewitness` or cargo, and fails where it
has neither.
"""

import os
import subprocess
import sys
import threading
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The limitation list a stranger can read while the site carries no copy. The holding page's own
# content file names the same address, `content/holding.json` in the site repository.
LIST = 'https://github.com/Fountech-ai-Limited/timewitness/blob/main/docs/what-timewitness-cannot-prove.md'

# Elements that never hold children, so they never go on the stack of open elements.
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source',
        'track', 'wbr'}


class Page(HTMLParser):
    """The two facts the rule needs, read off the elements rather than off the bytes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.open = []
        self.stage_in_head = False
        self.stage_elsewhere = False
        self.link_words = None
        self.in_link = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'meta' and a.get('name') == 'tw-stage' and a.get('content') == 'holding':
            if self.open and self.open[-1] == 'head':
                self.stage_in_head = True
            else:
                self.stage_elsewhere = True
        if tag == 'a' and a.get('href') == LIST and 'body' in self.open and self.link_words is None:
            self.in_link = True
            self.link_words = ''
        if tag not in VOID:
            self.open.append(tag)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.open and self.open[-1] == tag:
            self.open.pop()

    def handle_endtag(self, tag):
        if tag == 'a':
            self.in_link = False
        if tag in self.open:
            while self.open:
                if self.open.pop() == tag:
                    break

    def handle_data(self, data):
        if self.in_link:
            self.link_words += data


def faults(status, html):
    """Every reason this is not the holding page, or none."""
    out = []
    if status != '200':
        out.append(f'the root answered {status or "nothing"}, and only a 200 is the holding page')
    page = Page()
    page.feed(html)
    page.close()
    if not page.stage_in_head:
        where = ' somewhere other than the head' if page.stage_elsewhere else ''
        out.append('there is no meta element in the head saying tw-stage holding'
                   + (f', only one{where}' if where else ''))
    if page.link_words is None:
        out.append(f'nothing on the page links to the limitation list at {LIST}')
    elif not page.link_words.strip():
        out.append('the link to the limitation list carries no words, so a reader cannot see it')
    return out


def holding_page():
    """The holding page's shape, as the site builds it: the tags in the head, the link in the body."""
    return ('<!DOCTYPE html><html lang="en-GB"><head><meta charSet="utf-8"/>'
            '<title>TimeWitness</title><meta name="robots" content="noindex, nofollow, nocache"/>'
            '<meta name="tw-built-from" content="not-a-deployment"/>'
            '<meta name="tw-stage" content="holding"/></head><body><main>'
            '<h1>A timestamp that says how wrong it could be.</h1><p>In development</p>'
            '<a href="https://dev.timewitness.dev/">Private preview: sign in</a>'
            f'<p><a href="{LIST}">What it cannot prove</a>'
            '<a href="https://fountech.ai/">fountech.ai</a></p></main></body></html>')


def shapes():
    """Every shape the self-test tries, as (name, status, page, what it must be refused for)."""
    good = holding_page()
    tag = '<meta name="tw-stage" content="holding"/>'
    untagged = good.replace(tag, '')
    link = f'<a href="{LIST}">What it cannot prove</a>'
    selling = ('<html><head><title>Something else</title></head><body>'
               '<h1>Accurate to the nanosecond. Legally binding timestamps. $5 a month. Sign up.</h1>'
               '</body></html>')
    cases = [
        ('the tag inside a comment', '200', untagged.replace('<main>', f'<main><!-- {tag} -->'), 'no meta element'),
        ('the tag inside a script string', '200',
         untagged.replace('</head>', f'<script>var s = \'{tag}\';</script></head>'), 'no meta element'),
        ('the tag as text in the body', '200', untagged.replace('<main>', f'<main><p>{tag}</p>'), 'only one'),
        ('the tag inside a textarea', '200',
         untagged.replace('<main>', f'<main><textarea>{tag}</textarea>'), 'no meta element'),
        ('a page selling what may not be claimed, tagged, with no list', '200',
         selling.replace('</head>', tag + '</head>'), 'links to the limitation list'),
        ('the holding page with its link to the list taken off', '200', good.replace(link, ''),
         'links to the limitation list'),
        ('a 302 to another origin with the tag in its body', '302', good, 'only a 200'),
        ('the link to the list with no words on it', '200',
         good.replace(link, f'<a href="{LIST}"></a>'), 'carries no words'),
        ('the tag in a meta element under a template in the head', '200',
         untagged.replace('</head>', f'<template>{tag}</template></head>'), 'somewhere other'),
    ]
    return good, cases


def through_the_wire_route(status, html):
    """Run the wire route of three-surfaces.sh against a local address answering like the public one.

    The list's address answers 308 to the root, as the holding state does, and the root answers with
    the shape under test. Returns the exit status and everything the run printed.
    """
    body = html.encode('utf-8')

    class Answer(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/cannot-prove'):
                self.send_response(308)
                self.send_header('Location', '/')
                self.end_headers()
                return
            self.send_response(int(status))
            if status.startswith('3'):
                self.send_header('Location', 'https://somewhere-else.invalid/')
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Answer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, TW_SURFACES_SITE='wire', TW_SURFACES_WAIT='0',
                   TW_SITE_URL=f'http://127.0.0.1:{server.server_address[1]}/cannot-prove')
        run = subprocess.run(['bash', 'scripts/three-surfaces.sh'], cwd=root, env=env,
                             capture_output=True, text=True, timeout=600)
        return run.returncode, run.stdout + run.stderr
    finally:
        server.shutdown()
        server.server_close()


def self_test():
    good, cases = shapes()
    wrong = 0
    for name, status, html, expect in cases:
        found = faults(status, html)
        if not any(expect in f for f in found):
            print(f'the apex is the holding page: {name} was not refused for "{expect}": {found}',
                  file=sys.stderr)
            wrong += 1
        else:
            print(f'the apex is the holding page: {name}, refused')
    found = faults('200', good)
    if found:
        print(f'the apex is the holding page: the holding page itself was refused: {found}', file=sys.stderr)
        wrong += 1
    else:
        print('the apex is the holding page: the holding page itself, accepted')

    # The same shapes through the branch that reads them. Each has to be refused for being not the
    # holding page, and not for anything else, or a run that failed on a missing binary would read
    # as a refusal.
    for name, status, html, _ in cases:
        code, said = through_the_wire_route(status, html)
        if code == 0 or 'is not the holding page' not in said:
            print(f'the apex is the holding page: through the wire route, {name} was not refused as '
                  f'not the holding page (exit {code}):\n{said}', file=sys.stderr)
            wrong += 1
        else:
            print(f'the apex is the holding page: through the wire route, {name}, refused')
    code, said = through_the_wire_route('200', good)
    if code != 0 or 'answers 308 to the holding page' not in said:
        print(f'the apex is the holding page: through the wire route, the holding page itself was not '
              f'accepted (exit {code}):\n{said}', file=sys.stderr)
        wrong += 1
    else:
        print('the apex is the holding page: through the wire route, the holding page itself, accepted')

    if wrong:
        print(f'the apex is the holding page: {wrong} case(s) went the wrong way', file=sys.stderr)
        return 1
    print(f'the apex is the holding page: {len(cases)} shapes that are not it refused and the page '
          f'accepted, here and through the wire route')
    return 0


def main(argv):
    if argv[1:] == ['--self-test']:
        return self_test()
    if len(argv) != 3:
        print(__doc__.split('\n\n')[-2], file=sys.stderr)
        return 2
    status, path = argv[1], argv[2]
    try:
        html = open(path, encoding='utf-8', errors='replace').read()
    except OSError as e:
        print(f'the apex is the holding page: {path} could not be read: {e}', file=sys.stderr)
        return 2
    found = faults(status, html)
    for f in found:
        print(f'the apex is the holding page: {f}', file=sys.stderr)
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
