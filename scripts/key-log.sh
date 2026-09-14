#!/usr/bin/env bash
# The signed key log, built from what this repository holds rather than by hand.
#
#     scripts/key-log.sh <signing key> <out>
#
# `deploy/key-log/entries.txt` is the log with no head, and it is the only place an entry is ever
# written. This signs it with `timewitness key-log --sign`, reads the result back through
# `timewitness verify --key-log` on the committed receipt, and only then puts it at `<out>`. Anybody
# with this tree and the signing key gets the same entries and the same root, so the served copy is
# something a reader can check came from here rather than something somebody typed.
#
# The signing key is a file of 32 bytes and it is never in this repository. Continuous integration
# runs this with a key it makes and throws away, which proves the path end to end on every push and
# signs nothing anybody will ever be handed.
#
# Two refusals, both before anything is written:
#
# 1. Where `<out>` already holds a log, the new one has to be an extension of it: every entry the old
#    one carried, in the same order, and then possibly more. A log whose old entries change is not a
#    log, and a reader who kept the earlier head is the one it would lie to.
# 2. The verifier has to read the new log and check its head. For the committed receipt the answer
#    to `is that key one of ours` is no, because that receipt was signed by an agent key and this log
#    holds server keys, and no is the right answer. What this asks is that the answer comes from the
#    log, under a head signed by the key that signed it, rather than from a file it could not read.
#
# Set TIMEWITNESS_BIN to a built binary to skip the build.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

signing_key="${1:?key-log.sh needs the path to a 32-byte signing key}"
out="${2:?key-log.sh needs the path to write the signed log to}"

if [ -z "${TIMEWITNESS_BIN:-}" ]; then
  cargo build --quiet -p timewitness-cli
  bin="target/debug/timewitness"
else
  bin="$TIMEWITNESS_BIN"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Signed at a path of its own, so nothing at `<out>` moves until every check below has passed.
cp deploy/key-log/entries.txt "$work/log.txt"
"$bin" key-log --log "$work/log.txt" --sign "$signing_key" >/dev/null

if [ -f "$out" ]; then
  grep '^entry ' "$out" >"$work/before" || true
  grep '^entry ' "$work/log.txt" >"$work/after" || true
  kept="$(wc -l <"$work/before")"
  if ! head -n "$kept" "$work/after" | cmp -s - "$work/before"; then
    echo "key-log.sh: the log at $out is not a prefix of the one this would write, so nothing was written." >&2
    echo "key-log.sh: retire a key by appending an entry that says so; never edit or reorder one." >&2
    exit 1
  fi
fi

signed_by="$(awk '$1 == "head" { print $6 }' "$work/log.txt")"
entries="$(grep -c '^entry ' "$work/log.txt")"

set +e
fields="$("$bin" verify crates/verify/tests/data/a-real-stamp/receipt.cbor \
  --subject crates/verify/tests/data/a-real-stamp/subject.bin \
  --key-log "$work/log.txt" --fields 2>&1)"
code=$?
set -e

# Exit 2 is a run the verifier refused before judging anything, which is what an unreadable log
# produces. Exit 1 with the refusal on the key step and the head named is the log read and checked.
expected="refusal=the log states $entries entries under a head signed by ${signed_by:0:16}"
if [ "$code" -eq 2 ] || ! printf '%s\n' "$fields" | grep -qF "$expected"; then
  echo "key-log.sh: the verifier did not read this log and check its head, so nothing was written." >&2
  printf '%s\n' "$fields" | grep -E '^(accepted|refused_at|refusal)=' >&2 || true
  exit 1
fi

mkdir -p "$(dirname "$out")"
cp "$work/log.txt" "$out"
echo "key-log.sh: $entries entries, head signed by $signed_by, written to $out"
