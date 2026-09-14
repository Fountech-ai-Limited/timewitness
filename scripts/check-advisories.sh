#!/usr/bin/env bash
# Reads every crate this workspace links against, against the RustSec advisory database.
#
# Nothing looked at this until 2026-09-10. The tree was 43 packages when the first source client
# went in and it is 107 now, read that day off `grep -c '^\[\[package\]\]' Cargo.lock`, and the
# growth is a TLS stack and four cryptography crates. The first audit found one hit and it is
# ignored below with the reason. The finding worth acting on was not that hit: it was that the next
# advisory, on a crate whose vulnerable path this product actually walks, would arrive with nothing
# looking for it.
#
#     bash scripts/check-advisories.sh              the pinned database, which is what CI reads
#     bash scripts/check-advisories.sh --latest     today's database, which is what the weekly job reads
#
# **Why there is a pin at all.** An advisory database is somebody else's file and it changes when
# they publish, not when we push. Read it live on every build and a commit that touched a comment
# goes red on a morning when a stranger filed a report about a crate we have never called, and the
# person whose push it was has to work out whether they broke something. That is how a check earns
# the reputation that gets it skipped. So the build reads a fixed revision and only ever fails on
# what changed in this repository, and a separate scheduled job reads the live database and is
# allowed to go red on its own. When it does, somebody looks, and moves the pin below in the same
# act as dealing with what it found.

set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The revision of https://github.com/RustSec/advisory-db that the build reads. Moved by hand, by
# whoever has dealt with what the weekly job reported. Read 2026-09-15 at 02:04 off
# `bash scripts/check-advisories.sh --latest`, at RUSTSEC-2026-0285, which it found against rustls
# 0.23.44 a day after publication and which the pin before this one could not see. rustls moved to
# 0.23.45 in the same act.
pin='e2e640471715167f73e22eaf761f2e547adafeec'

# The reader, pinned for the same reason the database is. `wanted_audit` is what CI installs and
# what a message here tells somebody to install; `minimum_audit` is what this refuses to run below.
wanted_audit='0.22.2'
minimum_audit='0.22.0'

latest=0
if [ "${1:-}" = '--latest' ]; then
  latest=1
fi

notes=()

# In CI a check that cannot answer its question has to fail. Outside it, the same check says what it
# could not do and lets the run continue, because a desktop is allowed to be missing a tool and a
# build machine is not. `scripts/private-only.mjs` in the site repository is the same shape.
unanswered() {
  if [ -n "${CI:-}" ]; then
    echo "advisories: $1" >&2
    echo "advisories: this runs in CI, so it fails rather than passing quietly." >&2
    exit 1
  fi
  notes+=("$1")
}

if ! command -v cargo >/dev/null 2>&1; then
  cargo_home="${CARGO_HOME:-$HOME/.cargo}"
  if [ -x "$cargo_home/bin/cargo" ] || [ -x "$cargo_home/bin/cargo.exe" ]; then
    PATH="$cargo_home/bin:$PATH"
    export PATH
  fi
fi

# The ignore below is only honest while this process holds no RSA private key, so that condition is
# a check rather than a sentence. If any of these ever appears in the tree, the advisory is back in
# scope and the ignore comes out on the same day.
#
# Each name is a private-key operation in the `rsa` crate's own vocabulary. Verifying a signature,
# which is all `crates/core/src/evidence/rfc3161.rs` does, uses none of them.
private_key_shapes=(
  'RsaPrivateKey'
  'Pkcs1v15Encrypt'
  'pkcs1v15::SigningKey'
  'pss::SigningKey'
)
for shape in "${private_key_shapes[@]}"; do
  found="$(grep -rln --include='*.rs' -F "$shape" crates/)"
  status=$?
  if [ "$status" -gt 1 ]; then
    echo "advisories: grep could not read crates/ (exit $status), so nothing was checked." >&2
    exit 2
  fi
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$found" >&2
    echo "advisories: the tree now contains $shape, which is an RSA private-key operation." >&2
    echo "advisories: that is the stated reopening condition for the RUSTSEC-2023-0071 ignore in" >&2
    echo "advisories: .cargo/audit.toml. Take the ignore out and deal with the advisory." >&2
    exit 1
  fi
done

version="$(cargo audit --version 2>/dev/null | tr -dc '0-9.' )"

if [ -z "$version" ]; then
  unanswered "cargo-audit is not installed here, so no crate was checked. Install it with: cargo install cargo-audit --locked --version $wanted_audit"
elif [ "$(printf '%s\n%s\n' "$minimum_audit" "$version" | sort -V | head -1)" != "$minimum_audit" ]; then
  # Worth its own message. cargo-audit 0.21 cannot parse an advisory that scores itself under
  # CVSS 4.0, and there are such advisories in the database from 2026. What it prints is a parse
  # error naming a crate this workspace has never heard of, which reads exactly like a hit, and it
  # exits non-zero either way. Say which it is rather than letting a reader chase it.
  echo "advisories: cargo-audit here is $version and $minimum_audit is the oldest that reads the" >&2
  echo "advisories: whole database. Below that it stops on the first CVSS 4.0 advisory and the" >&2
  echo "advisories: error it prints looks like a vulnerability in a crate you do not depend on." >&2
  echo "advisories: cargo install cargo-audit --locked --version $wanted_audit" >&2
  exit 1
else
  db="${TIMEWITNESS_ADVISORY_DB:-$root/target/advisory-db}"

  if [ "$latest" -eq 1 ]; then
    want='HEAD'
  else
    want="$pin"
  fi

  fetched=1
  if [ ! -d "$db/.git" ]; then
    mkdir -p "$db"
    git -C "$db" init --quiet 2>/dev/null
    git -C "$db" remote add origin https://github.com/RustSec/advisory-db 2>/dev/null
  fi
  if [ "$latest" -eq 1 ]; then
    git -C "$db" fetch --quiet --depth 1 origin main 2>/dev/null || fetched=0
    [ "$fetched" -eq 1 ] && git -C "$db" checkout --quiet --detach FETCH_HEAD 2>/dev/null || fetched=0
  elif [ "$(git -C "$db" rev-parse HEAD 2>/dev/null)" != "$pin" ]; then
    # A specific revision rather than a branch, because the whole point is that the same commit is
    # read on every machine. GitHub serves a commit by its own name, so this is one object and not
    # a history.
    git -C "$db" fetch --quiet --depth 1 origin "$pin" 2>/dev/null || fetched=0
    [ "$fetched" -eq 1 ] && git -C "$db" checkout --quiet --detach "$pin" 2>/dev/null || fetched=0
  fi

  if [ "$fetched" -eq 0 ]; then
    unanswered "the advisory database could not be fetched from here, so no crate was checked."
  else
    at="$(git -C "$db" rev-parse --short HEAD)"
    if [ "$latest" -eq 1 ]; then
      echo "advisories: reading today's database, at $at."
    else
      echo "advisories: reading the pinned database, at $at."
    fi

    # `--no-fetch` because the checkout above decided which revision this is. Left to itself
    # cargo-audit would pull the current one and the pin would mean nothing.
    if ! cargo audit --no-fetch --db "$db" --file Cargo.lock; then
      echo >&2
      if [ "$latest" -eq 1 ]; then
        echo "advisories: today's database has something the pinned one did not." >&2
        echo "advisories: deal with it, then move the pin in this file to the revision you read." >&2
      else
        echo "advisories: a crate in Cargo.lock has an advisory against it." >&2
        echo "advisories: upgrade it, or if it is genuinely not reachable, write the reasoning and" >&2
        echo "advisories: the condition that would reopen it into .cargo/audit.toml. An ignore with" >&2
        echo "advisories: no reason beside it is the same as no check at all." >&2
      fi
      exit 1
    fi
  fi
fi

for note in "${notes[@]:-}"; do
  [ -n "$note" ] && echo "  --  $note"
done
exit 0
