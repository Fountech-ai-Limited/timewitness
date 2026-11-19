#!/usr/bin/env bash
# Holds the dependency graph to `deny.toml`: the licences it allows, the crates it bans, and the one
# registry code may come from.
#
#     bash scripts/check-licences.sh
#
# Advisories are not read here. `check-advisories.sh` reads them against a pinned database, so a push
# fails only on what it changed, and reading them again here against the live one would undo that.
#
# The reader is pinned. A newer cargo-deny can read the same file differently, and a build that goes
# red because a tool moved under it is a build somebody learns to push past.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

wanted_deny='0.20.2'

# In CI a check that cannot answer fails. Outside it the check says it could not answer and the run
# goes on, which `before-push.sh` then shows rather than reading the skip as a pass.
unanswered() {
  if [ -n "${CI:-}" ]; then
    echo "licences: $1" >&2
    echo "licences: this runs in CI, so it fails rather than passing quietly." >&2
    exit 1
  fi
  echo "licences: could not answer: $1"
  exit 0
}

have="$(cargo deny --version 2>/dev/null | awk '{print $2}')"
if [ -z "$have" ]; then
  unanswered "cargo-deny is not installed here, so no crate was checked. cargo install cargo-deny --locked --version $wanted_deny"
fi
if [ "$have" != "$wanted_deny" ]; then
  unanswered "cargo-deny here is $have and this repository is checked with $wanted_deny."
fi

cargo deny --locked check bans licenses sources
