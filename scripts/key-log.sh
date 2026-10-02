#!/usr/bin/env bash
# The signed key log, built from what this repository holds rather than by hand.
#
#     scripts/key-log.sh <signing key> <out> [--first] [--signer <64 hex>]
#
# `deploy/key-log/entries.txt` is the log with no head, and it is the only place an entry is ever
# written. This signs it with `timewitness key-log --sign`, reads the result back through
# `timewitness verify --key-log` on a receipt signed by our own key, holds it to the copy last served, and
# only then puts it at `<out>`. Anybody with this tree and the signing key gets the same entries and
# the same root, so the served copy is something a reader can check came from here rather than
# something somebody typed.
#
# The signing key is a file of 32 bytes and it is never in this repository. Continuous integration
# runs this with a key it makes and throws away, which proves the path end to end on every push and
# signs nothing anybody will ever be handed.
#
# Three refusals, all before anything is written:
#
# 1. The head has to be signed by the key the verifier holds for us. That is the pinned key shipped
#    in `crates/verify/src/anchor_file.rs`, and the verifier is what compares them: a head by any
#    other key comes back `key_log_head=signer-not-held` and nothing is written. A throwaway key
#    passes its own public half as `--signer`, which the verifier then holds for that run alone. The
#    expected signer is never read off this script's own output. Until 2026-09-15 it was, so a log
#    signed by whatever key was to hand checked against itself and passed.
# 2. The new log has to extend the copy last served, which is the one at `<out>`. The verifier
#    does the holding, `--kept-log`, and refuses a removed, changed or reordered entry by name.
#    There is no copy last served only once, before the first head, and that run says so with
#    `--first`; without it a missing `<out>` is a refusal and not a first run. Until 2026-09-15 the
#    check was skipped whenever `<out>` was absent, which was every CI run and every fresh machine.
# 3. The verifier has to read the new log and check its head, and it has to answer `is that key one
#    of ours` with held for `crates/verify/tests/data/our-agent-key/inside-its-window.hex`, which
#    was signed by the agent key this log vouches for, inside the window it names. A log of ours that
#    does not vouch for our own receipt is a log that lost an entry. Until 2026-09-24 the log held
#    server keys only, this read the receipt in `a-real-stamp`, and it asked no more than an answer
#    that was not a refusal. That receipt's key is not in the log, so against it that receipt is now
#    refused as not ours, which is the right answer for it.
#
# Set TIMEWITNESS_BIN to a built binary to skip the build.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

signing_key="${1:?key-log.sh needs the path to a 32-byte signing key}"
out="${2:?key-log.sh needs the path to write the signed log to}"
shift 2

first=no
signer=""
while [ $# -gt 0 ]; do
  case "$1" in
    --first) first=yes ;;
    --signer)
      signer="${2:?--signer needs the 64 hex characters of the key that signs the head}"
      shift
      ;;
    *)
      echo "key-log.sh: $1 is not an option this takes. It takes --first and --signer <hex>." >&2
      exit 2
      ;;
  esac
  shift
done

if [ ! -f "$signing_key" ]; then
  echo "key-log.sh: there is no signing key at $signing_key." >&2
  exit 2
fi
if [ "$(wc -c <"$signing_key" | tr -d ' ')" -ne 32 ]; then
  echo "key-log.sh: the signing key at $signing_key is not 32 bytes." >&2
  exit 2
fi

# Refusal 2, the half that needs no verifier: either there is a copy last served or this is the
# first head, and never both.
if [ "$first" = yes ] && [ -e "$out" ]; then
  echo "key-log.sh: --first was given and there is already a copy at $out, so this is not the first head." >&2
  echo "key-log.sh: run it without --first, and the new log is held to that copy." >&2
  exit 1
fi
if [ "$first" = no ] && [ ! -f "$out" ]; then
  echo "key-log.sh: there is no copy last served at $out, so the new log cannot be held to it." >&2
  echo "key-log.sh: for the first head, and only then, say --first." >&2
  exit 1
fi

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

python3 -c 'import sys; open(sys.argv[2], "wb").write(bytes.fromhex(open(sys.argv[1]).read()))' crates/verify/tests/data/our-agent-key/inside-its-window.hex "$work/ours.cbor"
verify=("$bin" verify "$work/ours.cbor"
  --subject crates/verify/tests/data/our-agent-key/subject.txt
  --key-log "$work/log.txt" --fields)
if [ -n "$signer" ]; then
  verify+=(--key-log-signer "$signer")
fi
if [ "$first" = no ]; then
  verify+=(--kept-log "$out")
fi

set +e
fields="$("${verify[@]}" 2>&1)"
code=$?
set -e

# The fields the decision reads, each looked for by name. A field that is not there is a refusal,
# because a verifier that printed nothing about the log did not read it.
field() {
  printf '%s\n' "$fields" | awk -F= -v name="$1" '$1 == name { print substr($0, length(name) + 2); found = 1 } END { if (!found) exit 1 }'
}

refuse() {
  echo "key-log.sh: $1, so nothing was written." >&2
  printf '%s\n' "$fields" | grep -E '^(accepted|refused_at|refusal|key_log_|kept_log)' >&2 || printf '%s\n' "$fields" >&2
  exit 1
}

# Exit 2 is a run the verifier refused before judging anything, which is what an unreadable log
# or an unreadable kept copy produces.
[ "$code" -ne 2 ] || refuse "the verifier could not read this log or the copy it was held to"

head_state="$(field key_log_head)" || refuse "the verifier said nothing about the log's head"
[ "$head_state" = checked ] || refuse "the head is $head_state: it is not signed by the key the verifier holds for us"
signed_by="$(field key_log_head_signed_by)" || refuse "the verifier named no signer"
if [ -n "$signer" ] && [ "$signed_by" != "$signer" ]; then
  refuse "the head is signed by $signed_by and --signer named $signer"
fi
entries="$(field key_log_entries)" || refuse "the verifier counted no entries"
step="$(field key_log_step)" || refuse "the verifier did not answer the key step"
[ "$step" = held ] || refuse "the log answers $step for a receipt signed by our own key inside its window, which a log of ours vouches for"

if [ "$first" = no ]; then
  kept="$(field kept_log)" || refuse "the verifier did not hold the new log to the copy at $out"
  [ "$kept" = held ] || refuse "the log at $out is not a prefix of the one this would write ($kept). Retire a key by appending an entry that says so; never edit or reorder one"
fi

mkdir -p "$(dirname "$out")"
cp "$work/log.txt" "$out"
if [ "$first" = yes ]; then
  echo "key-log.sh: $entries entries, head signed by $signed_by, the first head, written to $out"
else
  echo "key-log.sh: $entries entries, head signed by $signed_by, extends the copy last served, written to $out"
fi
