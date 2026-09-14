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
  local out
  if out="$("$@" 2>&1)"; then
    printf 'ok\n'
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

if ! rustup target list --installed | grep -qx "$target"; then
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
step "The key log builds from this tree" env TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh "$throwaway_key" "$throwaway_key.log"
rm -f "$throwaway_key" "$throwaway_key.log"
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
  step "  and with the network taken away" bash -c "TIMEWITNESS_BIN=target/debug/timewitness bash scripts/key-log.sh '$offline_key' '$offline_key.log' >/dev/null && TIMEWITNESS_BIN=target/debug/timewitness bash scripts/verify-offline.sh '$offline_key.log'"
  rm -f "$offline_key" "$offline_key.log"
fi
step "Repository hygiene"  bash scripts/repo-hygiene.sh
# CI runs this on the tree route, because it grades a commit and the served page is not in one. Here
# the sibling checkout is on disk, so the same script compares all three and this machine is the one
# place that catches a markdown change before it ships without the site copy beside it. Strictly more
# than CI does, which is the point of the hook rather than a difference to reconcile.
step "The limitation list, on all three surfaces" bash scripts/three-surfaces.sh
# Here the site repository is usually beside this one, so this run also holds the two copies of the
# rules to each other, which CI cannot.
step "No surface sells precision or prices a receipt" node scripts/no-price-on-evidence.mjs
step "  and that check still refuses a precision tier" bash -c "TW_PRICE_PROVE=precision node scripts/no-price-on-evidence.mjs 2>&1 | grep -qF 'offers a reduced-precision tier'"
step "  and a price per receipt" bash -c "TW_PRICE_PROVE=per-receipt node scripts/no-price-on-evidence.mjs 2>&1 | grep -qF 'offers a price per receipt'"
step "The guard that reads the served page is still running" bash scripts/wire-guard-is-alive.sh
step "Dependency advisories" bash scripts/check-advisories.sh

# The verifier page is CI's seventh step and it is not here. It needs the wasm target and a release
# build of the whole workspace, which is minutes rather than seconds, and it has its own check in
# `scripts/check-verifier-page.mjs` that whoever touches that page runs. Named rather than dropped
# quietly, so the two lists still line up.

if [ ${#failed[@]} -ne 0 ]; then
  echo >&2
  echo "before-push: ${#failed[@]} of $ran failed: ${failed[*]}" >&2
  echo "before-push: CI would go red on this. Fix it rather than pushing past it." >&2
  exit 1
fi

# Counted rather than written, because a step was added once and the number beside it was not.
echo "before-push: $ran for $ran. This is what CI will run."
