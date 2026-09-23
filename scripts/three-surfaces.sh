#!/usr/bin/env bash
# The limitation list ships on three surfaces and they have to say the same thing.
#
# Every public claim ships beside what it cannot prove, and the list is a section of the
# product rather than a disclaimer under it. There are three copies of it. The full list is
# `docs/what-timewitness-cannot-prove.md`, the short form is in `README.md`, and the site carries
# `content/cannot-prove.json` in the other repository. The copy goes one way, from here to the site.
#
# Three copies of anything drift, and a limitation list that drifts is worse than one surface having
# nothing: a reader who checks two of them and finds different answers has learned that neither is
# maintained. This checks the sentences that matter most, which are the ones about the claim the
# product opens with.
#
# It checks the whole list as well, from 2026-09-08. Until then it did not, because
# seventeen items differed in wording between the markdown and the site, mostly by the site dropping
# a backtick or shortening a clause, and reconciling all of them was a job of its own. That job is
# done, so every lead and every body in the site copy has to appear in the markdown word for word,
# and every item in the markdown has to appear on the site, with backticks the one difference
# allowed: the markdown names files in code spans and the site copy is prose. The second half of
# that was added later the same day, and the run prints the item count on each
# surface so a reader gets two numbers rather than a verdict.
#
# That half ran on one desktop and nowhere else until 2026-09-10. It needed the
# other repository checked out beside this one, said so where it had only this tree, and exited 0,
# which is what happened on every continuous integration run this repository has ever had. The only
# machine comparing the markdown with the site was one pre-push hook that a fresh clone does not
# have. So a guard that existed and was correct was absent from the place it was written for, and
# the board read green.
#
# It now reads the site from the site. Where the other repository is on disk the file is used,
# because that is the copy a pre-push hook is trying to catch before it ships. Where it is not, the
# deployed page is fetched and its items are read out of the served HTML, which is a better surface
# than a sibling checkout in any case: it is the copy a reader is actually handed. Where neither can
# be read the run fails. A cross-surface check that cannot reach one of the surfaces has learned
# nothing, and saying so and exiting 0 is how this one was quietly absent for a week.
#
# What that couples: the markdown here and the site over there are changed in the same act. A change
# made here and not shipped there turns this red, and that is the drift rather than a false alarm.
#
# Which was true of a pre-push hook and false of a runner, and the split below is the difference. The
# copy goes one way, from here to the site, so at the moment a commit lands here the site is behind
# it by design. Reading the wire from the job that grades the commit therefore asks whether the
# world agrees with a commit the world has not seen yet, and it is red for the time it takes somebody
# to make the second commit and for the deploy to finish. On 2026-09-11 that was twenty minutes, and
# nothing in either repository was going to run the check again: it went green on a hand re-run at
# 11:43:53Z with nothing changed. The harm is not the twenty minutes. `gh run list` shows the newest
# attempt, so a hand re-run erases the red from the board, and anybody who learns to re-run past this
# guard will re-run past the next real disagreement in the same clothes.
#
# So the check is split by what each surface is a function of. The markdown and the README are in the
# commit and are graded with it. The served page is not, and no commit here can move it, so holding
# it to the markdown is a question about the world rather than about a commit and it gets a guard
# with its own clock: `.github/workflows/surfaces.yml`, on a schedule and on demand, which waits out
# a deploy in flight rather than calling propagation drift. `TW_SURFACES_SITE` says which route this
# run takes and `TW_SURFACES_WAIT` says how long the wire route waits.
#
# Nothing here is allowed to pass because it could not see. Reaching the page and disagreeing is a
# failure, not reaching it is a failure, and the end of the wait is a failure. The one thing the tree
# route may do without failing is not read the site at all, and it says so in a sentence naming the
# guard that does, because the sixty-day disabling of a scheduled workflow would otherwise take the
# wire half away in silence. `scripts/wire-guard-is-alive.sh` is what stops that, and `ci.yml` runs
# it beside this.
#
# It stopped pinning measured figures on 2026-09-10, and that half is at the foot of
# this file. Pinning a figure made a fourth copy of it, and the fourth copy went stale the way the
# other three do: three of the sentences here were the widths of a receipt that had been replaced
# twice, so the check was holding the drift in place rather than catching it. A figure attributed to
# the receipt on disk is now read off the receipt on disk. A figure that is history keeps its pin and
# says in its own sentence that the receipt it came from has been replaced.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The site copy lives in a repository of its own beside this one, and is deployed from there.
site="${1:-../timewitness-web/content/cannot-prove.json}"
site_url="${TW_SITE_URL:-https://timewitness.dev/cannot-prove}"

# Which copy of the site this run is entitled to read.
#
#   auto   the file beside this tree where it is there, the served page where it is not. This is the
#          desktop and the pre-push hook, where the sibling is always on disk, and it is the default
#          so that a hand run of this script from a checkout behaves as it always has.
#   tree   the file beside this tree and nothing else. Where there is none, the site half does not
#          run and this says which guard runs it instead. This is the build job, which grades a
#          commit and can only grade what the commit ships.
#   wire   the served page and nothing else, waiting out a deploy in flight. This is the scheduled
#          guard, which grades the world rather than a commit.
route="${TW_SURFACES_SITE:-auto}"
case "$route" in
  auto|tree|wire) ;;
  *)
    echo "three surfaces: TW_SURFACES_SITE is \"$route\" and the routes are auto, tree and wire" >&2
    exit 1
    ;;
esac

# How long the wire route waits for the served page to catch up, in seconds, and it is zero
# everywhere except the scheduled guard. The wait is not a tolerance: the page still has to agree,
# and the end of the budget is a failure like any other. What it buys is that a run starting inside
# the fifty seconds a deploy takes reports the deploy rather than reporting drift. The figure and
# what it was measured against are in `.github/workflows/surfaces.yml`, which is the only caller
# that sets it.
wait_budget="${TW_SURFACES_WAIT:-0}"
wait_step="${TW_SURFACES_WAIT_STEP:-30}"

sentences=(
  "Nothing verifies order."
  "Every receipt carries a sequence number and the hash of the receipt before it, both signed, and no code anywhere compares two receipts, so nothing that exists today can put two receipts in order."
  "There is no refusal receipt."
  "A refusal is a return value inside the agent. Nothing signed and nothing portable is produced, so there is no artefact a third party could be shown."
  # Added 2026-09-08. Each of these is a figure or a claim that was
  # wrong on all three surfaces at once, which is what this check exists to stop happening again.
  # They carry no backticks on purpose: the site copy drops them and a sentence that cannot be
  # spelled the same way on both surfaces cannot be pinned.
  "Three time source clients exist in this repository, Roughtime, plain NTP and NTS, and only Roughtime signs anything a stranger can check, so the one that can be shown to a stranger is the one that cannot narrow the bound."
  "Measured against Roughtime alone on 2026-09-08, every one of them at the four rounds the Action shipped that day: a bound of 16.219 s from a GitHub runner, a bound of 16.424 s on an ordinary desktop's receipt committed at that path then and since replaced, and a bound of 16.439 s from that same desktop, stamped at 11:08."
  "Measured against two kinds on 2026-09-09 at the sixteen rounds the Action ships now, on an ordinary desktop: 153.6 ms and 164.8 ms wide over the first two of three passes at 14:52, and a bound of 176.7 ms on that desktop's receipt committed at that path then and since replaced, taken at 15:05. At 12:09 UTC a GitHub runner reached a bound of 211.3 ms, and that desktop reached the same on the remaining one of its three."
  # The sentence that used to sit here broke the width of the committed receipt into its parts, and
  # it was pinned to the receipt of 15:05 on 2026-09-09, which has been replaced twice since. It is
  # now read from the receipt instead, at the foot of this file. Every figure attributed to the
  # artefact is, and nothing about it is pinned here.
  "The 5 to 50 ms, the 1 ms and the 100 microsecond figures are quoted from public research and none of them has been measured by us."
  # Added 2026-09-09. The agent figures and the one-shot figures were taken
  # on the same desktop twelve minutes apart on purpose, so the comparison is a measurement
  # rather than two measurements from different days.
  "Measured through the resident agent on the same desktop on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 133.5 ms, 136.8 ms and 128.9 ms wide over three readings at 16:27, against 161.1 ms, 159.4 ms and 162.2 ms wide from the one-shot command on the same machine twelve minutes earlier."
  "What the agent moved is one term: the model's own residual fell from 39.3 to 45.6 ms of half width on those one-shot runs to 24.3 to 25.0 ms, and the sources overlapping did not move at all, so on that machine the width is now set by the sources rather than by the fit."
  # Replaced 2026-09-09, when a resident agent went into the tree. Both sentences
  # they replace said the agent did not exist, and one of them is now four sentences, because
  # what exists is narrower than what a reader will assume: a foreground process that installs
  # nothing, that the shipped Action does not use, against two source clients rather than four.
  "The agent runs only while somebody keeps it running: it installs no service, starts at no boot, and is not running after a restart until a person starts it again."
  # Added 2026-09-10. The measurement that says where a longer baseline stops buying anything.
  "Leaving the agent running longer stops narrowing the bound after about thirty minutes."
  "The one line a workflow installs runs the one-shot command and not the agent, so every receipt this product has issued in continuous integration came from a model built and thrown away in the same job."
  # Replaced 2026-09-10. The sentence it replaces measured this
  # product against four to six kinds, and four to six is the front page's claim about
  # independent sources, which in this product means operators. Six kinds could never exist:
  # `SourceKind` has four variants. What the old sentence was also carrying is a real
  # limitation and it is now the second of these two rather than a clause inside the wrong
  # comparison.
  "Three protocol implementations stand behind the nine servers a round asks, so at most three of the nine can fail for a different reason in the code."
  "A defect in one of the three source programs is one fault across three of the nine names at once, and no count of operators can see it."
  "Through the resident agent the reading behind a stamp is taken with no network call at all; through the one-shot command the network call that produced it is part of the same few seconds as the stamp."
  "Every receipt this product issues says its bound rests on the agent's own model, so no receipt yet carries third-party signed evidence for its bound."
  # Added 2026-09-09, with the work on four to six independent sources.
  # The first two are the measurement and what it says, and the point of pinning them together is
  # that the figure moved and the term a new source kind was supposed to move did not. The third is
  # the word independent, which the code does not yet enforce. The fourth is why NTS is never
  # evidence, on the surface a reader sees rather than only in the source file.
  "Measured with all three kinds on 2026-09-09 at the sixteen rounds the Action ships: 154.1 ms, 159.2 ms and 154.7 ms wide over three passes on an ordinary desktop at 20:28, and a bound of 149.8 ms on the receipt committed at that path then and since replaced, taken at 20:32, nine servers answering and nine kept."
  "The third kind narrowed nothing and the breakdown says so: the sources overlapping is 34.9 ms of half width on that nine-source receipt against 34.5 ms on the six-source one taken at 15:05, and what moved between the two receipts is the oscillator, 0.5 ms against 17.3 ms, which is how long after the last exchange each stamp was taken."
  "Measured through the resident agent with all three kinds on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 122.7 ms, 122.8 ms and 122.6 ms wide over three readings at 21:04, against 133.5 ms, 136.8 ms and 128.9 ms wide from the same agent at the same uptime and the same cadence with two kinds at 16:27."
  "The sources overlapping did not move there either, 37.6 ms of half width against 37.1 to 38.3 ms, so the ten milliseconds between the two sets is the fit and the oscillator rather than the sources."
  # Replaced 2026-09-09. The sentence it replaces said nothing in
  # the code counts operators, which stopped being true the same evening, and its figure was five
  # where the figure is six: Cloudflare answers on two of the three protocols rather than all three.
  "The nine servers a round asks stand behind six operators, and from 2026-09-09 the selection counts operators rather than names."
  "What an operator count cannot see is a shared upstream, a shared network path, a shared satellite constellation and a shared implementation, so it is an upper bound on how independent a round was rather than a measurement of it."
  # Rewritten 2026-09-15. It said the floor refuses "until somebody lowers the floor deliberately",
  # and nothing that ships can lower it. The two after it went in the same day: the two limitations a
  # reading of the receipt format found missing from every surface.
  "A machine that can reach only the three public Roughtime servers reaches three operators, which is under the shipped floor of four, so it refuses to sign, and nothing that ships lowers the floor."
  "A receipt carries no measurement from any source, so nobody else can recompute its width."
  "The operator names the floor counts are strings the signer wrote."
  # Pinned as far as the comma and no further. What follows it on each surface is the width of the
  # receipt on disk, and that is read from the receipt rather than pinned here.
  "Measured again with the independence rule in, on the same desktop at the same sixteen rounds: 149.3 ms, 161.2 ms and 163.2 ms wide over three passes at 21:39,"
  "Enforcing independence narrowed nothing and was never going to, because the rule refuses rounds rather than narrowing them: the sources overlapping is 35.1 ms of half width on that receipt against 34.9 ms on the one before it."
  "Measured through the resident agent on the same desktop on 2026-09-18, after the ageing of a source's interval over the local counter was bounded by the band, at thirty-six minutes of uptime and a thirty-two second polling cadence: 130.346 ms, 115.308 ms and 115.260 ms wide over three readings at 23:32, nine servers behind six operators and nine kept, with the sources overlapping at 37.991 ms of half width on the first and 36.830 ms on the other two."
  "The sources overlapping is 38.4 ms of half width there against 37.6 ms before the rule, so the six milliseconds between the two sets is a public network an hour apart rather than anything the rule did."
  "NTS authenticates a source and can never be evidence for a bound."
  # Rewritten 2026-09-15, when the one-shot ceiling moved from 30 s to 2 s. The sentence it replaces
  # said the shipped default refused over 250 ms, and only the resident agent did: the one-shot
  # command signed up to 30 s whether or not it ran inside the Action.
  "The resident agent refuses any interval wider than 250 ms, and the one-shot command, which the GitHub Action runs, refuses one wider than 2 s."
  # Added 2026-09-15. A log of our keys has been served since that afternoon and no surface said so.
  "A log of our keys is served at timewitness.dev/key-log.txt and names the keys of our two Roughtime servers and no agent key."
  # Added 2026-09-10. All three are refusals the agent makes that no surface said it made, and
  # every claim ships beside what it cannot prove: a refusal a reader has not been told about is a
  # surprise, and this list exists so that nothing about this product is a surprise.
  "A fresh agent refuses most readings for its first two minutes."
  "After it settles the agent still refuses a reading whenever the bound crosses the ceiling, and the share is not a fixed number."
  "The agent answers sixty-four callers at once and refuses the sixty-fifth."
)

fail=0

# The markdown and the README both wrap, so the file is read as one run of words with the line breaks
# taken out. A sentence that is right and hyphenated across two lines is right.
flatten() {
  tr '\n' ' ' <"$1" | tr -s ' '
}

# It reports rather than deciding, because the wire route runs it again after a deploy lands and a
# function that had already set the run's verdict could not be asked twice.
check() {
  local surface="$1" text="$2" missing=0
  for sentence in "${sentences[@]}"; do
    if ! [[ "$text" == *"$sentence"* ]]; then
      echo "three surfaces: $surface does not carry \"$sentence\"" >&2
      missing=1
    fi
  done
  return "$missing"
}
# Which copy of the site is read, and the route decides. `read_wire` and `compare_site` are
# functions rather than a run of statements because the wire route runs them again after a deploy
# lands, and a block that had already set the run's verdict could not be asked twice.
site_copy=''
site_read=''
site_compared=1
scratch=''
cleanup() { if [ -n "$scratch" ]; then rm -rf "$scratch"; fi; }
trap cleanup EXIT

# The deployed page, turned back into the JSON the site is built from, so nothing below has to know
# which route was taken.
read_wire() {
  local target="$1"
  if ! command -v curl >/dev/null 2>&1; then
    echo "three surfaces: there is no curl to read $site_url with" >&2
    return 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "three surfaces: there is no python3 to read $site_url with" >&2
    return 1
  fi
  if ! curl -fsS --max-time 30 "$site_url" -o "$scratch/served.html"; then
    echo "three surfaces: $site_url did not answer" >&2
    return 1
  fi
  if ! python3 - "$scratch/served.html" "$target" <<'PY'
import html as entities
import json
import re
import sys

source, target = sys.argv[1], sys.argv[2]
page = open(source, encoding='utf-8').read()


def words(fragment):
    """The text a reader sees, with the markup taken out and the entities put back."""
    return ' '.join(entities.unescape(re.sub(r'<[^>]+>', ' ', fragment)).split())


# Each item is a lead and then a body, both inside one list element. The class names are hashed by
# the bundler and only the prefix survives a rebuild, so the match is on the prefix. Nothing here
# passes on a page that has changed shape: no items at all is a failure, because a check that reads
# an empty list and finds no disagreement has found nothing.
items = [
    {'lead': words(lead), 'body': words(body)}
    for lead, body in re.findall(
        r'<p class="page_lead__[^"]*">(.*?)</p>\s*<p class="page_body__[^"]*">(.*?)</p>',
        page, re.S)
]
if not items:
    print('nothing on that page is shaped like a limitation item', file=sys.stderr)
    sys.exit(1)

# The whole of the visible page goes in beside the items, because the sentences pinned in this
# script are not all of them item text: some are the standfirst and the claim above the list.
body_only = re.sub(r'(?is)<(script|style)\b.*?</\1>', ' ', page)
json.dump({'sections': [{'id': 'the deployed page', 'items': items}],
           'pageText': words(body_only)},
          open(target, 'w', encoding='utf-8'), indent=1, ensure_ascii=False)
PY
  then
    echo "three surfaces: $site_url answered and the limitation list could not be read out of it" >&2
    return 1
  fi
  return 0
}

# The item walk. It takes the site copy, or a bare dash where this run is not entitled to one, and
# the dash still runs the half that is about two files in this commit: the number of items the README
# says the full list holds.
#
# That half was inside the site comparison until the tree route was watched refusing things, on
# 2026-09-11. It did not refuse a README claiming 56 items over a list of 57,
# because with no site copy the whole block was skipped and the count went unasked. A guard that
# stops asking a question it could still answer is a guard quietly absent again, one level down.
whole_list() {
  local copy="$1"
  if ! command -v python3 >/dev/null 2>&1; then
    echo "three surfaces: no python3 here, so neither the item-by-item comparison nor the README's own count ran. That is a failure and not a skip: the pinned sentences are a sample and this is the check that reads the whole list" >&2
    return 1
  fi
  # Every item, not just the pinned sentences, and in both directions. The site is a copy of the
  # markdown and a copy that paraphrases is worse than no copy: a reader who checks two surfaces and
  # finds different answers has learned that neither is maintained.
  #
  # It walked one way until 2026-09-08. Every sentence the site carried had to be in
  # the markdown, and nothing asked whether the site carried every item the markdown has, so the site
  # could drop any number of them and this stayed green. It had dropped one, "Only RSA signatures are
  # checked on timestamp tokens.", which the verifier prints in its own output on every run. The
  # list is a section of the product rather than a disclaimer, and the site is the surface most people read.
  if ! python3 - "$copy" docs/what-timewitness-cannot-prove.md README.md <<'PY'
import json
import re
import sys

site_path, md_path, readme_path = sys.argv[1], sys.argv[2], sys.argv[3]
markdown = open(md_path, encoding='utf-8').read()
flat_markdown = ' '.join(markdown.split()).replace('`', '')

# A bare dash means this run was not entitled to a copy of the site, which is the build job. The two
# halves below that compare the markdown with the site then do not run, and the half that reads the
# README's own count of the list does, because that one is about two files in this commit.
if site_path == '-':
    site = None
    flat_site = None
else:
    site = json.load(open(site_path, encoding='utf-8'))
    flat_site = ' '.join(open(site_path, encoding='utf-8').read().split()).replace('`', '')


def headlines(text):
    """Every item in the markdown, parsed the way the verifier parses it.

    An item is a paragraph opening with a bold sentence. This is `cannot_prove::limits` in
    `crates/verify`, so the count printed below is the count the verifier prints beside a result.

    A lead that wraps is joined across lines, the same as over there. Both parsers looked for the
    closing marker on the opening line until 2026-09-09, and both dropped six items without a sound;
    the document wraps at a hundred columns and a lead longer than that closes on the next line.
    """
    out = []
    lead = None
    for line in text.splitlines():
        if not line.strip():
            lead = None
            continue
        if lead is None:
            if not line.startswith('**'):
                continue
            carrying = line[2:]
        else:
            carrying = lead + ' ' + line
        end = carrying.find('**')
        if end >= 0:
            out.append(carrying[:end].strip())
            lead = None
        else:
            lead = carrying
    return out


markdown_items = headlines(markdown)
drifted = []
dropped = []

if site is None:
    print(f'three surfaces: {len(markdown_items)} items in the markdown, and no copy of the site was '
          f'read here')
else:
    items = [item for section in site['sections'] for item in section['items']]
    print(f'three surfaces: {len(markdown_items)} items in the markdown, {len(items)} on the site')

    for section in site['sections']:
        for item in section['items']:
            for field in ('lead', 'body'):
                text = item.get(field)
                if text and text.replace('`', '') not in flat_markdown:
                    drifted.append((section['id'], field, text))

    for section_id, field, text in drifted:
        print(f'three surfaces: the site\'s {section_id} {field} is not in the markdown: '
              f'"{text[:90]}..."', file=sys.stderr)

    dropped = [h for h in markdown_items if h.replace('`', '') not in flat_site]
    for headline in dropped:
        print(f'three surfaces: the site does not carry "{headline}"', file=sys.stderr)

# The README is held to a different test and it needs one, which it did not have until
# 2026-09-10. It was checked against a sample of hand-written sentences and against nothing
# else, so an item could be added to the markdown and to the site and the third surface would go on
# saying whatever it said. The README is a precis by design and an item-for-item comparison would be
# wrong: it carried 19 of the 55 items, read 2026-09-10 by running the headlines parser below over
# both files. What it can carry instead is the size of the thing
# it is a precis of. An item added to the full list then turns that number wrong and this goes red,
# and whoever added it either summarises it here or moves the number on purpose.
stated = re.search(r'The full list runs to (\d+) items', open(readme_path, encoding='utf-8').read())
if not stated:
    print('three surfaces: README.md does not say how long the full list is, so nothing on that '
          'surface notices an item being added to the other two', file=sys.stderr)
    sys.exit(1)
if int(stated.group(1)) != len(markdown_items):
    print(f'three surfaces: README.md says the full list runs to {stated.group(1)} items and it '
          f'runs to {len(markdown_items)}. Either the precis has not been revisited since an item '
          f'was added, or the number has', file=sys.stderr)
    sys.exit(1)
print(f'three surfaces: README.md is a precis and says so, of a list it puts at '
      f'{stated.group(1)} items')

sys.exit(1 if drifted or dropped else 0)
PY
  then
    echo "three surfaces: the whole-list comparison failed, and the lines above it say which part" >&2
    return 1
  fi
  return 0
}

# The whole of the site comparison, against whichever copy it is handed: the pinned sentences, and
# then the item walk with the site half of it switched on.
compare_site() {
  local copy="$1" label="$2" bad=0
  check "$label" "$(flatten "$copy")" || bad=1
  whole_list "$copy" || bad=1
  return "$bad"
}

# Whether the public address is in the holding state, where there is no site copy to read.
#
# While the product is in development the site's production deployment serves one holding page at
# the root and answers every other page, the limitation list among them, with a 308 to the root. The
# list then has no public copy on the site, and the copy a stranger can read is the markdown in this
# repository. That is a state the wire route states rather than a surface it failed to reach, so it
# is asserted on both halves: the list's address has to answer 308 to the root, and the root has to
# carry the holding page's own `tw-stage` tag. A site that answers anything else is read and compared
# as it always was, so the marketing site coming back to the public address is compared on the day
# it does.
holding=1
apex_holding() {
  local apex answer
  apex="$(printf '%s' "$site_url" | sed -E 's#^(https?://[^/]+).*#\1/#')"
  answer="$(curl -sS --max-time 30 -o /dev/null -w '%{http_code} %{redirect_url}' "$site_url" 2>/dev/null)" || return 1
  [ "$answer" = "308 $apex" ] || return 1
  curl -fsS --max-time 30 "$apex" -o "$scratch/apex.html" 2>/dev/null || return 1
  case "$(cat "$scratch/apex.html")" in
    *'<meta name="tw-stage" content="holding"'*) return 0 ;;
  esac
  return 1
}

# The tree routes take the file beside this tree, because that is the copy a pre-push hook is trying
# to catch before it ships.
if [ "$route" != wire ] && [ -f "$site" ]; then
  site_copy="$site"
  site_read="$site"
fi

# The wire route takes the served page, and waits out a deploy in flight. The comparison runs inside
# the wait rather than after it, because what tells a deploy from a disagreement is that one of them
# stops being true on its own and the other does not.
if [ -z "$site_copy" ] && [ "$route" != tree ]; then
  scratch="$(mktemp -d)"
  attempt="$scratch/attempt.log"
  deadline=$(( $(date +%s) + wait_budget ))
  # Read and agreed are two different answers and the run says which. A page that could not be
  # fetched at all is a different fault from one that was fetched and disagrees, and reporting the
  # second as the first is how a reader ends up looking for a network problem that is not there.
  wire_read=1
  wire_ok=1
  while true; do
    : > "$attempt"
    if apex_holding; then
      holding=0
      wire_ok=0
      break
    fi
    if read_wire "$scratch/served.json" >>"$attempt" 2>&1; then
      wire_read=0
      if compare_site "$scratch/served.json" "$site_url" >>"$attempt" 2>&1; then
        wire_ok=0
        break
      fi
    else
      wire_read=1
    fi
    left=$(( deadline - $(date +%s) ))
    if [ "$left" -le 0 ]; then
      break
    fi
    echo "three surfaces: $site_url does not carry this yet and a deploy takes about fifty seconds, ${left}s of the wait left"
    sleep "$wait_step"
  done
  if [ "$wire_read" -eq 0 ]; then
    site_copy="$scratch/served.json"
    site_read="$site_url"
    site_compared=0
  fi
  if [ "$wire_ok" -eq 0 ]; then
    cat "$attempt"
  else
    cat "$attempt" >&2
    if [ "$wait_budget" -gt 0 ]; then
      if [ "$wire_read" -eq 0 ]; then
        echo "three surfaces: $site_url still did not agree after ${wait_budget}s of waiting, so this is drift rather than a deploy in flight" >&2
      else
        echo "three surfaces: $site_url could not be read at all in ${wait_budget}s of trying" >&2
      fi
    fi
    fail=1
  fi
fi

# Saying what was not read, where it was not read, and who reads it instead. The tree route is the
# build job, which grades a commit and cannot grade a page the commit does not ship; it is the one
# route allowed to finish without the site, and it is allowed only because something else reads it
# and `ci.yml` fails when that something has stopped running.
if [ -z "$site_copy" ]; then
  if [ "$holding" -eq 0 ]; then
    echo "three surfaces: $site_url answers 308 to the holding page, so while the product is in development the site carries no copy of the list, by design. The public copy is docs/what-timewitness-cannot-prove.md in this repository, and the markdown and the README were held to each other"
  elif [ "$route" = tree ]; then
    echo "three surfaces: no site copy beside this tree, so this run held the markdown and the README to each other and to the committed receipt, and read nothing from the site"
    echo "three surfaces: the served page is read by .github/workflows/surfaces.yml, and scripts/wire-guard-is-alive.sh turns this build red when that has stopped running"
  else
    echo "three surfaces: no copy of the site could be read, so the markdown was compared with nothing. That is a failure and not a skip. This is the only check in either repository that compares the two" >&2
    fail=1
  fi
fi

check 'docs/what-timewitness-cannot-prove.md' "$(flatten docs/what-timewitness-cannot-prove.md)" || fail=1
check 'README.md' "$(flatten README.md)" || fail=1

if [ -n "$site_copy" ]; then
  echo "three surfaces: the site copy was read from $site_read"
  if [ "$site_compared" -ne 0 ]; then
    compare_site "$site_copy" "$site_read" || fail=1
  fi
else
  # No site copy, so the item walk runs on the half that needs none: what the README says the full
  # list holds against what the markdown holds. Without this the build job asked nothing about the
  # README beyond a sample of pinned sentences, which is the same class of fault over again: a
  # guard that passes because of where it looks.
  whole_list '-' || fail=1
fi
# Every figure attributed to the receipt on disk, checked against the receipt on disk.
#
# Pinning a measured figure as a sentence puts a fourth copy of it beside the three
# it is meant to keep honest, and a fourth copy drifts like the other three. Worse than that, it
# drifts in the one direction nobody can correct: three of the sentences pinned above were the
# figures of a receipt that had been replaced twice, so anybody who noticed and corrected one
# surface got a red build and concluded they had been wrong about the finding. The guard was
# holding the drift in place.
#
# So the figures come out of the array and are read from the artefact. There were two shapes
# for this and it is the second, which is the one that would have caught the stale figures rather
# than merely stopped holding them there. A width on a surface is now checked against what `timewitness verify` prints for
# the bytes committed at that path, at whatever precision the surface writes it to, so 153.9 ms and
# 153.875 ms are both right about a 153874770 ns receipt and 176.7 ms is not.
#
# A figure that is history keeps its pin above and says in its own sentence that the receipt it came
# from has been replaced. Only the present tense is read from the artefact.

receipt='crates/verify/tests/data/a-real-stamp/receipt.cbor'

# A binary that is already built is what continuous integration has by the time this runs, and what
# before-push.sh has on this desktop. Falling back to cargo costs a compile and is what a fresh
# checkout does. The .exe spellings are there because this is also run from Git Bash on Windows,
# where the file has that name and a test for the other one silently sends the run down to cargo.
built=''
for candidate in target/release/timewitness target/release/timewitness.exe \
                 target/debug/timewitness target/debug/timewitness.exe; do
  if [ -x "$candidate" ]; then built="$candidate"; break; fi
done

# Whether anything was asked about the receipt at all, which is not the same as what it answered.
verify_asked=1
if [ -n "$built" ]; then
  verify_output="$("$built" verify "$receipt" 2>&1 || true)"
elif command -v cargo >/dev/null 2>&1; then
  verify_output="$(cargo run -q -p timewitness-cli -- verify "$receipt" 2>&1 || true)"
else
  verify_asked=0
  verify_output=''
  echo "three surfaces: no timewitness binary and no cargo, so the committed receipt was not read. That is a failure and not a skip: every width on every surface here is attributed to those bytes" >&2
  fail=1
fi

# A verifier that ran and said nothing has not agreed with anything. Both the check below and its
# own "that is a failure and not a skip" compensator test `[ -n "$verify_output" ]`, so until
# 2026-09-19 an empty capture made the pair of them vanish and the run still printed that it had
# held three surfaces to each other and to the committed receipt. `|| true` above is what lets the
# capture come back empty, and it stays: what the verifier prints about a receipt it refuses is the
# thing this check reads.
if [ "$verify_asked" -eq 1 ] && [ -z "$verify_output" ]; then
  echo "three surfaces: the verifier was run over $receipt and printed nothing, so no width on any surface was checked against the receipt it names. That is a failure and not a skip" >&2
  fail=1
fi

if [ -n "$verify_output" ] && command -v python3 >/dev/null 2>&1; then
  surfaces=(docs/what-timewitness-cannot-prove.md README.md)
  [ -n "$site_copy" ] && surfaces+=("$site_copy")
  # The verify output goes across in the environment rather than on standard input, because the
  # program itself arrives on standard input and only one of them can.
  if ! TW_VERIFY="$verify_output" python3 - "${surfaces[@]}" <<'PY'
import os
import re
import sys

verify = os.environ['TW_VERIFY']
surfaces = sys.argv[1:]
problems = []

# What the command prints about this receipt. The width is on the line that says how wide it is; the
# parts are the breakdown under it, each a figure and then what it is.
width = re.search(r'([\d.]+) ms \(\d+ ns\) wide', verify)
if not width:
    print('three surfaces: the verify output has no width in it, so nothing was checked against '
          'the receipt. That is a failure and not a skip.', file=sys.stderr)
    sys.exit(1)
width = float(width.group(1))


def part(what):
    found = re.search(r'([\d.]+) ms\s+' + what, verify)
    return float(found.group(1)) if found else None


parts = {
    'residual': part("the model's own residual"),
    'sources': part('the sources overlapping, halved'),
    'oscillator': part('the oscillator since the last sync'),
}
missing = [name for name, value in parts.items() if value is None]
if missing:
    print('three surfaces: the verify output does not break the width down by ' + ', '.join(missing)
          + ', so the sentence that does cannot be checked against it', file=sys.stderr)
    sys.exit(1)


def agrees(written, actual):
    """True when a figure written to some number of decimals is that figure rounded to them."""
    decimals = len(written.split('.')[1]) if '.' in written else 0
    return round(actual, decimals) == float(written)


# Anything on a surface attributed to the receipt on disk. The phrase is the attribution: a figure
# said to be the receipt committed in this repository is a figure a reader will run the command to
# reproduce. A figure that has been superseded does not carry this phrase and is not checked here.
ATTRIBUTED = re.compile(r'([\d.]+)\s+(ms|s)\s+on the receipt committed in this repository')

BREAKDOWN = re.compile(
    r"Of the ([\d.]+) ms of width on the receipt committed in this repository, the largest single "
    r"part is the model's own regression residual doubled by the coverage factor, ([\d.]+) ms of half "
    r"width, with ([\d.]+) ms of the sources overlapping and ([\d.]+) ms of the oscillator "
    r'beside it')

for path in surfaces:
    text = ' '.join(open(path, encoding='utf-8').read().split()).replace('`', '')

    attributions = ATTRIBUTED.findall(text)
    if not attributions:
        problems.append(f'{path} attributes no width at all to the receipt committed here, and the '
                        f'receipt is {width} ms wide. A surface that stops saying what this product '
                        f'reaches has stopped answering the question the list is for.')
    for figure, unit in attributions:
        actual = width if unit == 'ms' else width / 1000.0
        if not agrees(figure, actual):
            problems.append(f'{path} says {figure} {unit} on the receipt committed in this '
                            f'repository, and verify prints {width} ms for the bytes at that path. '
                            f'Either the surface was not updated when the fixture was re-taken, or '
                            f'the figure belongs to a receipt that has been replaced and its '
                            f'sentence has to say so.')

    breakdown = BREAKDOWN.search(text)
    if not breakdown:
        problems.append(f'{path} does not break the committed receipt down into its parts in the '
                        f'words this check reads. That sentence carries the largest term in the '
                        f'bound and it is the one most at risk of being quoted '
                        f'without its conditions.')
    else:
        written = dict(zip(('total', 'residual', 'sources', 'oscillator'), breakdown.groups()))
        for name, actual in (('total', width), ('residual', parts['residual']),
                             ('sources', parts['sources']), ('oscillator', parts['oscillator'])):
            if not agrees(written[name], actual):
                problems.append(f'{path} gives {written[name]} ms for the {name} of the committed '
                                f'receipt and verify prints {actual} ms.')

for problem in problems:
    print('three surfaces: ' + problem, file=sys.stderr)

if not problems:
    print(f'three surfaces: the committed receipt is {width} ms wide and every surface that '
          f'attributes a width to it agrees, on {len(surfaces)} surfaces read')
sys.exit(1 if problems else 0)
PY
  then
    fail=1
  fi
elif [ -n "$verify_output" ]; then
  echo "three surfaces: no python3 here, so the committed receipt's own figures were not checked. That is a failure and not a skip" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "three surfaces: the copies disagree. The markdown is the one that is right and the others are copied from it" >&2
  exit 1
fi

echo "three surfaces: the same words on each one that was read"
