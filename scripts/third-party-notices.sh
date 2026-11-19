#!/usr/bin/env bash
# Writes the third-party notices for the verifier page, from the module's own dependency graph.
#
#     bash scripts/third-party-notices.sh            writes verifier-page/third-party-notices.html
#     bash scripts/third-party-notices.sh --check    fails if the committed file is not what the graph gives
#
# The page embeds a WebAssembly module built from `crates/verify-web`, and three of the crates in it
# are BSD-3-Clause, whose second clause asks for the copyright notice to go with a binary. Until
# 2026-11-19 the page went out with none. This reads the crates that reach that module on that target
# at the versions `Cargo.lock` pins, and writes each one's licence text as it ships it, copyright
# lines included. `about.toml` at the root says what is read and `verifier-page/third-party-notices.hbs`
# says how it is laid out.
#
# The file is committed rather than built on the day, so a lockfile change that moves the notices
# shows up as a change to them in the same pull request, and CI runs `--check` so the two cannot part.
# `scripts/page-for-a-host.sh` hands it to a host beside the page.
#
# Read offline, after a `cargo fetch`, so the answer comes from the crates as published and not from
# whatever a crate's repository holds today. The reader is pinned for the same reason: another version
# lays the same graph out differently, and the check would then fail on a tool and not on a change.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

wanted_about='0.9.3'
out="verifier-page/third-party-notices.html"

check=0
if [ "${1:-}" = '--check' ]; then
  check=1
fi

# In CI a check that cannot answer must fail. On a desktop the check says it could not answer and
# lets the run go on, as `check-advisories.sh` does, and `before-push.sh` shows any line saying
# "could not answer" rather than swallowing it with the rest of a passing step.
unanswered() {
  if [ -n "${CI:-}" ] || [ "$check" -eq 0 ]; then
    echo "third-party notices: $1" >&2
    exit 1
  fi
  echo "third-party notices: could not answer: $1"
  exit 0
}

have="$(cargo about --version 2>/dev/null | awk '{print $2}' || true)"
if [ -z "$have" ]; then
  unanswered "cargo-about is not installed here. It is $wanted_about that writes this file: cargo install cargo-about --locked --version $wanted_about"
fi
if [ "$have" != "$wanted_about" ]; then
  unanswered "cargo-about here is $have, and this file is written by $wanted_about, which lays it out its own way."
fi

cargo fetch --locked --quiet

scratch="$(mktemp)"
trap 'rm -f "$scratch"' EXIT
cargo about generate --locked --offline --fail \
  --manifest-path crates/verify-web/Cargo.toml \
  --config about.toml \
  --output-file "$scratch" \
  verifier-page/third-party-notices.hbs

# A few crates ship their licence with Windows line endings, and a few copyright lines carry a
# letter outside ASCII, such as the copyright sign in libm's. The repository stores text with Unix
# line endings and in ASCII alone (`repo-hygiene.sh` refuses anything else, here and in the site), so
# each such letter is written as an HTML character reference, which a browser shows as the letter.
python - "$scratch" <<'PYTHON'
import sys
path = sys.argv[1]
text = open(path, "rb").read().decode("utf-8").replace("\r\n", "\n")
open(path, "wb").write(text.encode("ascii", "xmlcharrefreplace"))
PYTHON

# grep says 1 for no match and 2 for a file it could not read, and only the second is a fault of
# its own. Read here, with `set -e` in force, the status is taken rather than ending the run.
status=0
crates=$(grep -c '^<tr><td>' "$scratch") || status=$?
if [ "$status" -gt 1 ]; then
  echo "third-party notices: grep could not read what cargo about wrote (exit $status)." >&2
  exit 2
fi
if [ "$crates" -eq 0 ]; then
  echo "third-party notices: the graph read as no crates at all, which is not this module." >&2
  exit 1
fi

if [ "$check" -eq 1 ]; then
  if ! cmp -s "$scratch" "$out"; then
    echo "third-party notices: $out is not what the module's graph gives today." >&2
    diff -u "$out" "$scratch" | head -40 >&2 || true
    echo "Run bash scripts/third-party-notices.sh and commit the file it writes." >&2
    exit 1
  fi
  echo "third-party notices: $out matches the graph, $crates crates"
  exit 0
fi

cp "$scratch" "$out"
echo "third-party notices: wrote $out, $crates crates"
