#!/usr/bin/env bash
# Verifying needs no network, shown by taking the network away.
#
# `crates/architecture/tests/verify_path_needs_nothing_of_ours.rs` reads what the verifier links and
# what its sources say. That catches the shapes somebody has thought of. This catches the rest: it
# runs `timewitness verify` on the committed receipt twice, once as it is and once inside a network
# namespace of its own with nothing in it, and requires the same output and the same exit code from
# both. A verifier that looked something up, fell back to a host of ours, or waited on a service
# would answer differently with the network gone, or not answer.
#
#     scripts/verify-offline.sh <key-log>
#
# The key log is read off disk, which is how a reader is handed one, and `scripts/key-log.sh` builds
# it from this tree. `TIMEWITNESS_BIN` names the binary and defaults to the debug build.
#
# It needs Linux, because a network namespace is a Linux thing. Where it cannot make one it fails
# rather than passing: a check that could not take the network away has learned nothing, and saying
# so and exiting 0 is how a guard ends up absent from the place it was written for. The pre-push
# script knows this and says in its own output that this half runs in CI.
#
# The namespace is shown empty before the verifier runs in it, by trying to open a connection to a
# public address from inside. Should that connection open, this fails, because then the run below
# it would have proved nothing.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

key_log="${1:?verify-offline.sh needs the path to a key log, which scripts/key-log.sh builds}"
bin="${TIMEWITNESS_BIN:-target/debug/timewitness}"
receipt='crates/verify/tests/data/a-real-stamp/receipt.cbor'
subject='crates/verify/tests/data/a-real-stamp/subject.bin'

fail() {
  echo "verify offline: $1" >&2
  exit 1
}

[ -x "$bin" ] || fail "there is no verifier at $bin; build it first, or say where it is with TIMEWITNESS_BIN"
[ -f "$key_log" ] || fail "there is no key log at $key_log"
command -v unshare >/dev/null 2>&1 || fail "there is no unshare here, so the network cannot be taken away and nothing was checked"

bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
key_log="$(cd "$(dirname "$key_log")" && pwd)/$(basename "$key_log")"

# A namespace without privileges where the kernel allows one, and through sudo where it does not.
# Ubuntu runners from 24.04 restrict unprivileged namespaces and give the runner sudo with no
# password, so on a runner it is usually the second.
if unshare --net --map-root-user true 2>/dev/null; then
  isolate=(unshare --net --map-root-user)
elif sudo -n unshare --net true 2>/dev/null; then
  isolate=(sudo -n unshare --net)
else
  fail "a network namespace could not be made here, with or without sudo, so nothing was checked"
fi

verify=("$bin" verify "$receipt" --subject "$subject" --key-log "$key_log" --fields)

# The check run backwards, so it is seen refusing on every push rather than having been seen once.
# Nothing on disk changes in either mode.
#
# `leaky` makes no namespace, so the connection from inside opens and the run has to stop there.
# `lookup` puts a verifier in front of the real one that answers only when it can reach the internet,
# which is the shape of a key lookup that falls back to a host of ours, and the verdicts have to
# differ. A proof run that exits 0 is the failure, and `ci.yml` checks the reason it gives as well as
# the exit, so a run that failed for some other reason does not count as the check catching.
case "${TW_OFFLINE_PROVE:-}" in
  '') ;;
  leaky)
    echo "verify offline: proving, with no namespace made"
    isolate=(env)
    ;;
  lookup)
    echo "verify offline: proving, with a verifier that needs to reach a network to answer"
    verify=(bash -c '
      if timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
        exec "$@"
      fi
      echo "accepted=false"
      echo "refusal=the key service could not be reached"
      exit 1
    ' _ "${verify[@]}")
    ;;
  *) fail "TW_OFFLINE_PROVE is leaky or lookup, not ${TW_OFFLINE_PROVE}" ;;
esac

set +e
with_network="$("${verify[@]}" 2>&1)"
with_code=$?

# Inside the namespace, in order: list the interfaces it has, try to reach a public address and stop
# with 97 should it answer, then hand over to the verifier.
#
# What the namespace says about itself goes to a file named as the first argument rather than to
# standard error, because the verifier writes a refusal to standard error and both runs have to capture
# the verifier the same way. A file rather than a spare descriptor, because sudo closes every
# descriptor above the first three.
notes="$root/target/verify-offline.namespace.txt"
mkdir -p "$root/target"
rm -f "$notes"
without_network="$("${isolate[@]}" bash -c '
  notes="$1"
  shift
  interfaces="$(awk -F: "NR > 2 { gsub(/ /, \"\", \$1); printf \"%s \", \$1 }" /proc/net/dev)"
  echo "interfaces in the namespace: ${interfaces:-none}" >>"$notes"
  if timeout 5 bash -c "exec 3<>/dev/tcp/1.1.1.1/443" 2>/dev/null; then
    echo "a connection to 1.1.1.1:443 opened from inside the namespace" >>"$notes"
    exit 97
  fi
  echo "a connection to 1.1.1.1:443 was refused from inside the namespace" >>"$notes"
  exec "$@" 2>&1
' _ "$notes" "${verify[@]}" 2>&1)"
without_code=$?
set -e

cat "$notes" 2>/dev/null || echo "the namespace wrote nothing about itself"
rm -f "$notes" 2>/dev/null || sudo -n rm -f "$notes" 2>/dev/null || true

if [ "$without_code" -eq 97 ]; then
  fail "the namespace could still reach the internet, so running the verifier in it would prove nothing"
fi

verdict() {
  printf '%s\n' "$1" | grep -E '^(accepted|refused_at|refusal)=' || true
}

echo "with the network:    exit $with_code, $(verdict "$with_network" | tr '\n' ' ')"
echo "without the network: exit $without_code, $(verdict "$without_network" | tr '\n' ' ')"

if [ "$with_code" -eq 2 ]; then
  fail "the verifier refused to run at all with the network, so there is no verdict to compare"
fi
if [ "$with_code" -ne "$without_code" ] || [ "$with_network" != "$without_network" ]; then
  diff <(printf '%s\n' "$with_network") <(printf '%s\n' "$without_network") >&2 || true
  fail "the verifier answered differently with the network taken away, and a receipt has to check the same on a machine that is unplugged"
fi

echo "verify offline: the same verdict, field for field, with no network at all"
