#!/usr/bin/env bash
# Every single-bit change anywhere in a receipt is refused, by the shipped command line, with no
# network.
#
# This is acceptance item A-01 held to the binary a consumer runs. `scripts/every-bit-refused.py`
# takes every receipt committed under `crates/verify/tests/data` that verifies as it is, changes one
# bit of it at a time, and runs `timewitness verify` on each change in a process of its own. Every
# one has to exit 1. The whole sweep runs inside a network namespace with nothing in it, and it is
# shown unable to reach a public address before the first run, so a verifier that looked anything
# up would be caught here as well.
#
#     scripts/every-bit-refused.sh
#
# `TIMEWITNESS_BIN` names the binary and defaults to the release build. `TW_EVERY_BIT_JOBS` sets how
# many changes are checked at once and defaults to the number of cores.
#
# It needs Linux for the namespace, as `scripts/verify-offline.sh` does, and where it cannot make one
# it fails rather than passing. The same sweep runs in one process on every machine as
# `crates/verify/tests/every_bit_of_a_receipt.rs`.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

bin="${TIMEWITNESS_BIN:-target/release/timewitness}"
jobs="${TW_EVERY_BIT_JOBS:-$(nproc 2>/dev/null || echo 2)}"

fail() {
  echo "every bit: $1" >&2
  exit 1
}

[ -x "$bin" ] || fail "there is no verifier at $bin; build it first, or say where it is with TIMEWITNESS_BIN"
command -v python3 >/dev/null 2>&1 || fail "there is no python3 here to run the sweep"
command -v unshare >/dev/null 2>&1 || fail "there is no unshare here, so the network cannot be taken away and nothing was checked"

if unshare --net --map-root-user true 2>/dev/null; then
  isolate=(unshare --net --map-root-user)
elif sudo -n unshare --net true 2>/dev/null; then
  isolate=(sudo -n unshare --net)
else
  fail "a network namespace could not be made here, with or without sudo, so nothing was checked"
fi

# The check run backwards. `leaky` makes no namespace, so the sweep has to stop before it starts,
# because the network is still there. `ci.yml` runs it and reads the reason as well as the exit.
case "${TW_EVERY_BIT_PROVE:-}" in
  '') ;;
  leaky)
    echo "every bit: proving, with no namespace made"
    isolate=(env)
    ;;
  *) fail "TW_EVERY_BIT_PROVE is leaky, not ${TW_EVERY_BIT_PROVE}" ;;
esac

"${isolate[@]}" python3 scripts/every-bit-refused.py "$bin" "$jobs"
