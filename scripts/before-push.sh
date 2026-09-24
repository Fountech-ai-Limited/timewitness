#!/usr/bin/env bash
# Everything CI runs, run here, before the push rather than after it.
#
# The reason this exists is a gap between two machines. Every change is verified on a Windows desktop and
# CI builds on Linux under `-D warnings`, so anything behind a `cfg` is checked by one of them and
# not the other. On 2026-09-08 that put six red runs on `main` between 07:35 and 08:56 UTC, all of
# them one unused import that the host-target clippy is silent about, while four closures the same
# day recorded a clean clippy run. Nobody was careless; the check they ran could not see it.
#
# So the clippy step here is the Linux one. The target is already installed and the whole run is
# under a minute warm, which is the entire cost of closing that class.
#
# It is not a replacement for a Linux leg in CI. That is a real job on a real runner and it is held
# on what the organisation's Actions minutes cost. This spends nothing and it removes the fault that
# has actually bitten.
#
#     scripts/before-push.sh
#
# Install it as a hook, so it runs whether or not anybody remembers. It is machine-local, a fresh
# clone does not have it, and it is two lines:
#
#     printf '#!/bin/sh\nexec scripts/before-push.sh\n' > .git/hooks/pre-push
#     chmod +x .git/hooks/pre-push
#
# Every step below is one step of `.github/workflows/ci.yml`, in the order that file runs them, and
# each is named for the step it stands in for. A step added there and not here shows up as a
# difference between two lists rather than as silence.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# rustup puts its shims in one place and not every shell has that place on PATH. Git Bash here is
# one that does not, and the same gap sent `build-verifier-page.sh` telling a reader to install a
# target they already had. Add the standard location rather than asking for it.
if ! command -v cargo >/dev/null 2>&1; then
  cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  if [ -x "$cargo_home/bin/cargo" ] || [ -x "$cargo_home/bin/cargo.exe" ]; then
    PATH="$cargo_home/bin:$PATH"
    export PATH
  else
    echo "before-push: cargo is not on PATH and is not in $cargo_home/bin." >&2
    exit 1
  fi
fi

# CI sets this for the whole job, so a warning there is a failed build. Set it here too or the two
# runs are not comparing the same thing.
export RUSTFLAGS="-D warnings"

# The one difference from CI, and it is the point of the script. CI is Linux and this is not, so the
# lint runs against the Linux target. Everything else builds and runs for the host, because a test
# has to execute and this machine cannot execute a Linux binary.
target="x86_64-unknown-linux-gnu"

# The advisory reader is a one-off install rather than part of the toolchain, so a fresh clone will
# not have it. `check-advisories.sh` notes that and carries on outside CI, and `step` below prints
# nothing from a run that succeeded, so the note would be swallowed and the skip would read as a
# pass. Say it here, where it is visible.
if ! cargo audit --version >/dev/null 2>&1; then
  echo "before-push: cargo-audit is not installed, so the advisory step will check nothing here." >&2
  echo "before-push: CI still runs it. Install it and this machine runs it too:" >&2
  echo "before-push: cargo install cargo-audit --locked --version 0.22.2" >&2
fi

failed=()
ran=0

step() {
  local name="$1"
  shift
  ran=$((ran + 1))
  printf '%s ... ' "$name"
  local out notes status
  if out="$("$@" 2>&1)"; then
    printf 'ok\n'
    # A step that passed and said it could not answer part of its question has not answered it, and
    # this function threw that away with the rest of a successful step's output until 2026-09-19.
    # The advisory step is the one that does it: outside CI a database it could not fetch is a note
    # at exit 0, and nobody saw the note.
    notes="$(printf '%s\n' "$out" | grep -E 'could not answer')"
    status=$?
    if [ "$status" -gt 1 ]; then
      printf 'before-push: grep could not read what %s printed (exit %s), so a note it made may have been lost\n' "$name" "$status" >&2
      failed+=("$name")
    elif [ "$status" -eq 0 ]; then
      printf '%s\n' "$notes" >&2
    fi
  else
    printf 'FAILED\n'
    printf '%s\n' "$out" >&2
    failed+=("$name")
  fi
}

# Say which of the two it is. A message that sends a reader to install something they already have
# is the fault this repository has already had once, in `build-verifier-page.sh`.
if ! command -v rustup >/dev/null 2>&1; then
  echo "before-push: rustup is not on PATH, so this cannot tell whether the $target target is there." >&2
  echo "before-push: it lives beside cargo, in ${CARGO_HOME:-$HOME/.cargo}/bin." >&2
  exit 1
fi

installed="$(rustup target list --installed)" || { echo "before-push: rustup could not list its targets." >&2; exit 2; }
if ! [[ "$installed" =~ (^|[[:space:]])"$target"($|[[:space:]]) ]]; then
  echo "before-push: the $target target is not installed, and it is the whole reason this runs." >&2
  echo "before-push: rustup target add $target" >&2
  exit 1
fi

# The Rust target on its own stopped being enough on 2026-09-09, when the NTS source brought a TLS
# stack in and that stack builds a little C. Compiling C for Linux from here needs a compiler that
# targets Linux, and this machine has none of the usual ones. Zig ships a C compiler with the
# headers and libraries for every target it knows, in one download and with nothing to configure, so
# that is what is used where it is present.
#
# It is a wrapper rather than the compiler itself because the two disagree about one spelling. The
# Rust world writes the target as `x86_64-unknown-linux-gnu` and Zig writes it `x86_64-linux-gnu`,
# and the build passes the Rust spelling straight through, so the wrapper rewrites that one argument
# and leaves everything else alone. Rewriting the string everywhere rather than in that argument was
# tried first and it also rewrote the output path, which fails in a way that reads like a missing
# directory.
#
# Nothing here is committed beyond this block: the wrapper is written into `target/`, which is
# already ignored, from whichever Zig is found.
if ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1 && [ -z "${CC_x86_64_unknown_linux_gnu:-}" ]; then
  zig=""
  if command -v zig >/dev/null 2>&1; then
    zig="$(command -v zig)"
  else
    for candidate in "$LOCALAPPDATA/Microsoft/WinGet/Packages"/zig.zig*/*/zig.exe; do
      [ -x "$candidate" ] && zig="$candidate" && break
    done
  fi
  if [ -z "$zig" ]; then
    echo "before-push: no compiler here builds C for $target, so the Linux lint cannot run." >&2
    echo "before-push: that lint is the whole point of this script, so this stops rather than" >&2
    echo "before-push: skipping it. Install one: winget install --id zig.zig" >&2
    exit 1
  fi
  # The wrapper is a cmd file, and cmd cannot run a path spelled the way this shell spells one:
  # `command -v` under Git Bash answers /c/Users/... and cmd answers "cannot find the path". So
  # the path is turned into its Windows spelling where the shell has the tool to do it, which
  # every Git Bash has. Until 2026-09-17 the wrapper was written with the POSIX spelling whenever
  # zig was on PATH, and the Linux lint failed on every push from such a shell.
  if command -v cygpath >/dev/null 2>&1; then
    zig="$(cygpath -w "$zig")"
  fi
  mkdir -p target
  wrapper="$root/target/linux-cc.cmd"
  {
    printf '@echo off\r\n'
    printf 'setlocal enabledelayedexpansion\r\n'
    printf 'set "ARGS="\r\n'
    printf ':loop\r\n'
    printf 'if "%%~1"=="" goto run\r\n'
    printf 'set "A=%%~1"\r\n'
    printf 'if "!A:~0,9!"=="--target=" set "A=--target=x86_64-linux-gnu"\r\n'
    printf 'set ARGS=!ARGS! "!A!"\r\n'
    printf 'shift\r\n'
    printf 'goto loop\r\n'
    printf ':run\r\n'
    printf '"%s" cc -target x86_64-linux-gnu %%ARGS%%\r\n' "$zig"
  } > "$wrapper"
  archiver="$root/target/linux-ar.cmd"
  {
    printf '@echo off\r\n'
    printf '"%s" ar %%*\r\n' "$zig"
  } > "$archiver"
  export CC_x86_64_unknown_linux_gnu="$wrapper"
  export AR_x86_64_unknown_linux_gnu="$archiver"
fi

step "Formatting"          cargo fmt --all -- --check
step "Lints, on Linux"     cargo clippy --workspace --all-targets --target "$target" -- -D warnings
step "Build"               cargo build --workspace --all-targets
step "Tests"               cargo test --workspace
throwaway_key="$(mktemp)"
head -c 32 /dev/urandom >"$throwaway_key"
# The throwaway's public half, derived here rather than read off the script's own output, which is
# the comparison the script's --signer check exists for.
signer="$({ printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'; cat "$throwaway_key"; } | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
step "The key log builds from this tree" bash -c "TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh '$throwaway_key' '$throwaway_key.log' --first --signer '$signer' && TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh '$throwaway_key' '$throwaway_key.log' --signer '$signer'"
# The same four refusals CI drives, so a script that stopped refusing is seen here first.
key_log_refuses() {
  local reason="$1"; shift
  local said
  if said="$(TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh "$@" 2>&1)"; then
    printf '%s\n' "$said"; echo "key-log.sh wrote a log it is built to refuse: $reason"; return 1
  fi
  case "$said" in
    *"$reason"*) ;;
    *) printf '%s\n' "$said"; echo "it refused, and not because $reason"; return 1 ;;
  esac
}
step "  and still refuses a first head where one exists" key_log_refuses "not the first head" "$throwaway_key" "$throwaway_key.log" --first --signer "$signer"
cp "$throwaway_key.log" "$throwaway_key.longer"
target/debug/timewitness key-log --log "$throwaway_key.longer" --add "$(printf '09%.0s' $(seq 32))" --role server --label "a third server" --sign "$throwaway_key" >/dev/null
step "  and a log that does not extend the copy last served" key_log_refuses "not a prefix of the one this would write" "$throwaway_key" "$throwaway_key.longer" --signer "$signer"
another_key="$(mktemp)"
head -c 32 /dev/urandom >"$another_key"
step "  and a head by a key the verifier does not hold" key_log_refuses "not signed by the key the verifier holds for us" "$another_key" "$throwaway_key.log" --signer "$signer"
step "  and no copy last served without --first" key_log_refuses "no copy last served" "$throwaway_key" "$throwaway_key.nowhere/key-log.txt" --signer "$signer"
step "The log answers for our keys" bash -c "TIMEWITNESS_BIN=target/debug/timewitness bash scripts/our-key-in-the-log.sh '$throwaway_key.log' --signer '$signer'"
rm -f "$throwaway_key" "$throwaway_key.log" "$throwaway_key.longer" "$another_key"
step "Verifying needs no account and no call to us" cargo test -p timewitness-architecture --test verify_path_needs_nothing_of_ours
# The other half of that CI step, `scripts/verify-offline.sh`, takes the network away in a Linux
# namespace, and this machine has no Linux to make one in. Said out loud rather than skipped quietly,
# the same as the advisory reader above: the half that reads the sources ran here, the half that
# unplugs the verifier runs in CI and nowhere else.
if ! command -v unshare >/dev/null 2>&1; then
  echo "before-push: no unshare here, so the verifier was not run with the network taken away. CI runs that half." >&2
else
  offline_key="$(mktemp)"
  head -c 32 /dev/urandom >"$offline_key"
  step "  and with the network taken away" bash -c "TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh '$offline_key' '$offline_key.log' --first >/dev/null && TIMEWITNESS_BIN=target/debug/timewitness bash scripts/verify-offline.sh '$offline_key.log'"
  rm -f "$offline_key" "$offline_key.log"
fi
# The verifier page stood outside this script until 2026-09-14 on the reading that it took minutes.
# Warm, the whole of it takes seconds, and the page half of the check above is read off the page as
# built, so it cannot run without it.
step "The verifier page"   bash scripts/build-verifier-page.sh
step "The verifier page asks for nothing" bash -c "node scripts/verifier-page-offline.mjs && node scripts/verifier-page-offline.mjs --self-test && node scripts/verifier-page-in-a-browser.mjs"
step "Repository hygiene"  bash scripts/repo-hygiene.sh
step "Repository hygiene still refuses its seeds" bash scripts/repo-hygiene.sh --self-test
step "The guards are written to the contract" bash -c "bash scripts/guard-lint.sh --self-test && bash scripts/guard-lint.sh scripts"
step "The hook's steps are this file's" bash -c "node scripts/steps-match.mjs --self-test && node scripts/steps-match.mjs"
# CI runs this on the tree route, because it grades a commit and the served page is not in one. Here
# the sibling checkout is on disk, so the same script compares all three and this machine is the one
# place that catches a markdown change before it ships without the site copy beside it. Strictly more
# than CI does, which is the point of the hook rather than a difference to reconcile.
step "The limitation list, on all three surfaces" bash scripts/three-surfaces.sh
# The wire route's holding branch, driven against a local server with the holding page and nine pages
# that are not it. Nothing above reads a served page, so without this only the schedule runs it.
step "The wire route tells the holding page from a page carrying its tag" python3 scripts/the-apex-is-the-holding-page.py --self-test
# And the newest release against its own copy of that list, which is a different question: the one
# above asks whether three surfaces of this commit agree, and this asks whether the thing a reader
# can actually download says what it can actually do.
step "The newest release against its own limitation list" bash -c "bash scripts/the-order-item-matches-the-release.sh --self-test && bash scripts/the-order-item-matches-the-release.sh"
# Here the site copy is beside this tree, so its sentences are held to the policy as well.
step "Every sentence agrees with the shipped policy" bash -c "python3 scripts/policy-sentences.py && python3 scripts/policy-sentences.py --self-test"
# And the deployment off the key log, with the site beside this tree read as well.
step "No surface says our servers are not there" bash -c "python3 scripts/our-servers.py && python3 scripts/our-servers.py --self-test"
# Here the site repository is usually beside this one, so this run also holds the two copies of the
# rules to each other, which CI cannot.
step "No surface sells precision or prices a receipt" node scripts/no-price-on-evidence.mjs
# The check run backwards. The reason it refuses is read from a capture rather than through a pipe,
# so a refusal for some other reason, or a check that could not run, is not read as the seed caught.
price_refuses() {
  local mode="$1" reason="$2" said
  if said="$(TW_PRICE_PROVE="$mode" node scripts/no-price-on-evidence.mjs 2>&1)"; then
    printf '%s\n' "$said"; echo "the check passed with TW_PRICE_PROVE=$mode, so it is not connected"; return 1
  fi
  case "$said" in
    *"$reason"*) ;;
    *) printf '%s\n' "$said"; echo "it refused, and not for $reason"; return 1 ;;
  esac
}
step "  and that check still refuses a precision tier" price_refuses precision "offers a reduced-precision tier"
step "  and a price per receipt" price_refuses per-receipt "offers a price per receipt"
# A count of checks says it came through the hosted checker, or it does not go out. Most checking
# reaches nothing of ours, so a bare figure claims what nobody counted.
step "A figure about how much checking happens says where it came from" node scripts/a-verification-figure-names-the-checker.mjs
count_refuses() {
  local said
  if said="$(TW_COUNT_PROVE=1 node scripts/a-verification-figure-names-the-checker.mjs 2>&1)"; then
    echo "$said"; echo "the check passed with a bare figure seeded into it, so it is not connected"; return 1
  fi
  case "$said" in
    *"README.md states how much checking happens"*) ;;
    *) echo "$said"; echo "it refused, and not for the seeded figure"; return 1 ;;
  esac
}
step "  and that check still refuses a bare one" count_refuses
step "The guard that reads the served page is still running" bash scripts/wire-guard-is-alive.sh
step "Every version and format label is read off what it labels" bash -c "python3 scripts/the-version-is-the-tag.py --self-test && python3 scripts/the-version-is-the-tag.py && python3 scripts/the-format-labels-are-the-receipts.py --self-test && python3 scripts/the-format-labels-are-the-receipts.py"
step "Dependency advisories" bash scripts/check-advisories.sh

if [ ${#failed[@]} -ne 0 ]; then
  echo >&2
  echo "before-push: ${#failed[@]} of $ran failed: ${failed[*]}" >&2
  echo "before-push: CI would go red on this. Fix it rather than pushing past it." >&2
  exit 1
fi

# Counted rather than written, because a step was added once and the number beside it was not.
echo "before-push: $ran for $ran. This is what CI will run."
