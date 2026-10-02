#!/usr/bin/env bash
# What the live run found, as a table a person reads without opening a log.
#
# The tests that talk to real Roughtime, NTP, NTS, drand and timestamp servers are ignored in the
# ordinary run, because a build should not fail when somebody else's server is down. Until
# 2026-09-21 nothing ran them at all, so a retired server, an expired certificate or a protocol
# change reached a user before it reached a test. `.github/workflows/live.yml` runs them once a day
# and hands their output to this.
#
#     cargo test ... -- --ignored 2>&1 | bash scripts/live-summary.sh      the table, exit 1 on a failure
#     bash scripts/live-summary.sh --self-test                            a planted failure refused
#
# It exits 1 where any test failed and 2 where no test ran at all, because nought tests passing is
# not the live integrations working.
set -uo pipefail

summarise() {
  local out passed=0 failed=0 line name verdict
  out="$(mktemp)"
  printf '| Test | Result |\n|---|---|\n' >"$out"
  while IFS= read -r line; do
    case "$line" in
      "test "*" ... ok" | "test "*" ... FAILED")
        name="${line#test }"
        name="${name% ... *}"
        verdict="${line##* ... }"
        if [ "$verdict" = ok ]; then
          passed=$((passed + 1))
          printf '| `%s` | answered |\n' "$name" >>"$out"
        else
          failed=$((failed + 1))
          printf '| `%s` | **failed** |\n' "$name" >>"$out"
        fi
        ;;
    esac
  done
  cat "$out"
  rm -f "$out"
  printf '\n%d answered, %d failed, on %s UTC.\n' "$passed" "$failed" "$(date -u +'%Y-%m-%d %H:%M')"
  if [ $((passed + failed)) -eq 0 ]; then
    echo "No live test ran, which is not the live integrations working."
    return 2
  fi
  [ "$failed" -eq 0 ] || return 1
}

self_test() {
  local said status wrong=0
  said="$(printf 'test a_server_answers ... ok\ntest a_server_that_went_away ... FAILED\n' | summarise)"
  status=$?
  if [ "$status" -ne 1 ]; then echo "a planted failure exited $status" >&2; wrong=$((wrong + 1)); fi
  case "$said" in *'`a_server_that_went_away` | **failed**'*) ;; *) echo "the failure is not named in the table" >&2; wrong=$((wrong + 1)) ;; esac
  printf 'running 0 tests\n' | summarise >/dev/null
  status=$?
  if [ "$status" -ne 2 ]; then echo "nought tests exited $status" >&2; wrong=$((wrong + 1)); fi
  printf 'test a_server_answers ... ok\n' | summarise >/dev/null
  status=$?
  if [ "$status" -ne 0 ]; then echo "a clean run exited $status" >&2; wrong=$((wrong + 1)); fi
  [ "$wrong" -eq 0 ] || return 1
  echo "live summary: a failure is named and refused, nought tests refused, a clean run passed"
}

if [ "${1:-}" = --self-test ]; then
  self_test
  exit $?
fi
summarise
