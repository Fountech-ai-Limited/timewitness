#!/usr/bin/env bash
# Whether a reader holding our key log can tell a receipt signed by our key, then, from one that was not.
#
#     scripts/our-key-in-the-log.sh [<key log, a file or an address>] [--signer <64 hex>]
#
# With no log named it fetches the one we serve, https://timewitness.dev/key-log.txt, because that is
# the copy a reader is handed. Three receipts of ours are put through `timewitness verify --key-log`
# against it, and each has to come back the way the log says it should:
#
# 1. `our-agent-key/inside-its-window.hex`, signed by the key our own receipts are signed with, after
#    the log said it was ours. Held, the answer names the entry and its window, and the reading is
#    inside that window by the numbers this script reads back.
# 2. `our-agent-key/before-its-window.hex`, signed by that same key before the log said it was ours.
#    Refused at `is that key one of ours`, the refusal names the reading and the window it fell
#    outside, and the reading is outside it by the same numbers.
# 3. `a-real-stamp`, signed on 2026-09-09 by an earlier key whose private half cannot be accounted
#    for, which the log does not name. Refused as not ours, with no window to name.
#
# The head has to be checked under the key the verifier holds for us, which is the pinned key it
# ships with. `--signer` replaces it for one run, which is how continuous integration runs this over
# the committed entries signed with a key it makes and throws away.
#
# This is our own statement about our own keys and it is never third-party evidence. What it shows a
# reader is that a key we published is one we cannot quietly unpublish, and that a receipt signed by
# one of our keys outside the window we gave it is not passed as ours. The window is judged on the
# receipt's own reading, so it tells these receipts apart and would not catch one that lies about
# when it was signed.
#
# Set TIMEWITNESS_BIN to a built binary to skip the build.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="https://timewitness.dev/key-log.txt"
signer=""
while [ $# -gt 0 ]; do
  case "$1" in
    --signer)
      signer="${2:?--signer needs the 64 hex characters of the key that signs the head}"
      shift
      ;;
    -*)
      echo "our-key-in-the-log.sh: $1 is not an option this takes. It takes a log and --signer <hex>." >&2
      exit 2
      ;;
    *) log="$1" ;;
  esac
  shift
done

if [ -z "${TIMEWITNESS_BIN:-}" ]; then
  cargo build --quiet -p timewitness-cli
  bin="target/debug/timewitness"
else
  bin="$TIMEWITNESS_BIN"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$log" in
  http://* | https://*)
    if ! curl -fsS --max-time 30 "$log" -o "$work/key-log.txt"; then
      echo "our-key-in-the-log.sh: the key log at $log could not be fetched, so nothing was checked." >&2
      exit 1
    fi
    ;;
  *)
    if [ ! -f "$log" ]; then
      echo "our-key-in-the-log.sh: there is no key log at $log." >&2
      exit 2
    fi
    cp "$log" "$work/key-log.txt"
    ;;
esac

data=crates/verify/tests/data
failed=0

# The two receipts signed by our key are committed as hex, because the repository holds text and one
# named binary, and are turned back into the bytes a reader would be handed here.
for name in inside-its-window before-its-window; do
  python3 -c 'import sys; open(sys.argv[2], "wb").write(bytes.fromhex(open(sys.argv[1]).read()))' "$data/our-agent-key/$name.hex" "$work/$name.cbor"
done

fail() {
  echo "  NO   $1" >&2
  failed=$((failed + 1))
}

# One receipt, run once for the fields a script reads and once for the words a person reads. The
# words are folded onto one line, because the verifier wraps them and a phrase can break anywhere.
run() {
  local receipt="$1" subject="$2"
  local args=("$bin" verify "$receipt" --subject "$subject" --key-log "$work/key-log.txt")
  if [ -n "$signer" ]; then
    args+=(--key-log-signer "$signer")
  fi
  fields="$("${args[@]}" --fields 2>&1)" || true
  words="$("${args[@]}" 2>&1 | tr '\n' ' ' | tr -s ' ')" || true
}

field() {
  printf '%s\n' "$fields" | awk -F= -v name="$1" '$1 == name { print substr($0, length(name) + 2); found = 1 } END { if (!found) print "(absent)" }'
}

# Whether a reading falls in a window written `from..until`, `open` being no end. The numbers are
# nanoseconds since 1970, and a shell's 64-bit integers hold them until the year 2262.
inside() {
  local reading="$1" from="${2%%..*}" until="${2##*..}"
  [ "$reading" -ge "$from" ] && { [ "$until" = open ] || [ "$reading" -le "$until" ]; }
}

the_head_is_ours() {
  local head
  head="$(field key_log_head)"
  [ "$head" = checked ] || fail "the head is $head, not checked under a key this reader holds for us"
}

held() {
  local name="$1" receipt="$2" subject="$3" entry window reading before="$failed"
  run "$receipt" "$subject"
  echo "$name"
  the_head_is_ours
  entry="$(field key_log_entry)"
  reading="$(field reading_ns)"
  window="$(field key_log_windows | tr ',' '\n' | awk -F: -v n="$entry" '$1 == n { print $2 }')"
  [ "$(field accepted)" = true ] || fail "the receipt was not accepted: $(field refusal)"
  [ "$(field key_log_step)" = held ] || fail "is that key one of ours answered $(field key_log_step), where the log names this key over the reading"
  case "$entry" in
    '' | none | '(absent)') fail "no entry was named" ;;
  esac
  if [ -z "$window" ]; then
    fail "entry $entry was named with no window"
  elif ! inside "$reading" "$window"; then
    fail "entry $entry was named for the reading at $reading ns, and its window $window does not hold it"
  fi
  case "$words" in
    *"Entry $entry of "*"names this key as an agent key from "*"and the reading at $reading ns falls in that window"*) ;;
    *) fail "the words do not name entry $entry and its window" ;;
  esac
  case "$words" in
    *"not third-party evidence"*) ;;
    *) fail "the words do not say the log is not third-party evidence" ;;
  esac
  [ "$failed" -ne "$before" ] || echo "  held under entry $entry, window $window ns, reading $reading ns"
}

refused() {
  local name="$1" receipt="$2" subject="$3" windows reading window before="$failed"
  run "$receipt" "$subject"
  echo "$name"
  the_head_is_ours
  windows="$(field key_log_windows)"
  reading="$(field reading_ns)"
  [ "$(field accepted)" = false ] || fail "a receipt signed outside its key's window was accepted"
  [ "$(field refused_at)" = "is that key one of ours" ] || fail "refused at $(field refused_at), not at the key log"
  [ "$(field key_log_step)" = failed ] || fail "is that key one of ours answered $(field key_log_step)"
  [ "$(field key_log_entry)" = none ] || fail "entry $(field key_log_entry) was named as vouching for it"
  case "$windows" in
    none | '(absent)') fail "no window was named for the key" ;;
    *)
      for window in $(printf '%s\n' "$windows" | tr ',' ' '); do
        if inside "$reading" "${window#*:}"; then
          fail "the reading at $reading ns is inside window $window, so this refusal is not about the window"
        fi
      done
      ;;
  esac
  case "$(field refusal)" in
    *"the reading at $reading ns falls outside every window it names for this key"*"refused as not ours at that moment"*) ;;
    *) fail "the refusal does not name the reading and the window it fell outside: $(field refusal)" ;;
  esac
  [ "$failed" -ne "$before" ] || echo "  refused as not ours at $reading ns, outside window $windows ns"
}

not_in_the_log() {
  local name="$1" receipt="$2" subject="$3" before="$failed"
  run "$receipt" "$subject"
  echo "$name"
  the_head_is_ours
  [ "$(field accepted)" = false ] || fail "a receipt signed by a key the log does not name was accepted"
  [ "$(field key_log_step)" = failed ] || fail "is that key one of ours answered $(field key_log_step)"
  [ "$(field key_log_windows)" = none ] || fail "windows were named for a key the log does not name: $(field key_log_windows)"
  case "$(field refusal)" in
    *"none of them names this key"*) ;;
    *) fail "the refusal does not say the log does not name the key: $(field refusal)" ;;
  esac
  [ "$failed" -ne "$before" ] || echo "  refused as not ours, and the log names no window for its key"
}

echo "Against $log"
held "our key, inside its window" "$work/inside-its-window.cbor" "$data/our-agent-key/subject.txt"
refused "our key, before its window opened" "$work/before-its-window.cbor" "$data/our-agent-key/subject.txt"
not_in_the_log "the committed receipt of 2026-09-09, by a key the log does not name" "$data/a-real-stamp/receipt.cbor" "$data/a-real-stamp/subject.bin"

if [ "$failed" -ne 0 ]; then
  echo "our-key-in-the-log.sh: the log does not answer for our keys as it should, $failed times." >&2
  exit 1
fi
echo "our-key-in-the-log.sh: every receipt of ours was answered from the log, under a head signed by $(field key_log_head_signed_by)."
