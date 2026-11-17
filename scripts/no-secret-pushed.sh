#!/usr/bin/env bash
# Nothing a push sends carries a credential.
#
#     scripts/no-secret-pushed.sh <refs-file>   the refs a pre-push hook was handed, one line each
#     scripts/no-secret-pushed.sh               the branch checked out, for a run by hand
#     scripts/no-secret-pushed.sh --self-test   a scratch repository seeded with one of each, watched refused
#
# exit 0 when nothing is found, 1 with each find named by commit and kind, 2 when it could not read.
#
# What is read is every commit the push sends that no remote branch here already holds, each one on
# its own: every line it adds and its message. A key one commit put in and the next took out is still
# on the remote once pushed, so the net change is not what is read. A backup ref is read the same way
# as a branch, because a key pushed to one is as public on GitHub as a key pushed to main.
#
# The shapes are the ones a key this company holds would take, each written so that the line naming
# it here does not match itself. What it prints is the commit and the kind, never the match.

set -uo pipefail

KINDS=(
  'an AWS access key|(AKIA|ASIA)[0-9A-Z]{16}'
  'a private key|-----BEGIN ([A-Z]+ )*PRIVATE KEY-----'
  'a GitHub token|(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})'
  'a Stripe key or signing secret|((sk|rk)_live_[0-9A-Za-z]{16,}|whsec_[0-9A-Za-z]{24,})'
  'a Slack token|xox[abpr]-[0-9A-Za-z-]{10,}'
  'a Google API key|AIza[0-9A-Za-z_-]{35}'
  'an API secret key|sk-[A-Za-z0-9_-]{32,}'
  'a database address with its password|postgres(ql)?://[^:/@[:space:]]+:[^@[:space:]]+@[^/:[:space:]]+'
)

# A password in a database address is a secret unless the address is this machine, which is how a
# test database is reached and what the app's CI file says.
LOCAL='postgres(ql)?://[^:/@[:space:]]+:[^@[:space:]]+@(localhost|127\.0\.0\.1)([:/]|$)'

stop() {
  echo "no secret pushed: $1" >&2
  exit 2
}

# The commits a tip sends: what it holds that no remote branch here holds.
commits_of() {
  git rev-list "$1" --not --remotes 2>/dev/null </dev/null
}

# One commit's added lines and its message, as text.
added_by() {
  git log -1 --format=%B "$1" </dev/null || return 2
  git show --no-color --no-ext-diff --format= -m --first-parent "$1" </dev/null | grep '^+' | grep -v '^+++ ' | cut -c2-
  return 0
}

scan() {
  local refs="$1" tips found=0 n=0 commit text hits kind name pattern local_ref local_sha remote_ref remote_sha
  tips="$(mktemp)"
  if [ -n "$refs" ] && [ -s "$refs" ]; then
    while read -r local_ref local_sha remote_ref remote_sha; do
      [ -n "${remote_ref:-}" ] || continue
      case "$local_sha" in *[!0]*) ;; *) continue ;; esac
      git rev-parse -q --verify "$local_sha^{commit}" >>"$tips" </dev/null || { rm -f "$tips"; stop "$local_sha is not a commit this clone can read"; }
    done <"$refs"
  else
    git rev-parse HEAD >"$tips" || { rm -f "$tips"; stop "there is no commit checked out"; }
  fi
  local commits
  commits="$(sort -u "$tips" | while read -r tip; do commits_of "$tip"; done | sort -u)"
  rm -f "$tips"
  for commit in $commits; do
    n=$((n + 1))
    text="$(added_by "$commit")" || stop "commit $commit could not be read"
    for kind in "${KINDS[@]}"; do
      name="${kind%%|*}"
      pattern="${kind#*|}"
      # Read into a variable rather than piped into grep -q, which under pipefail can read a match
      # as no match when the reader stops early and the writer dies of SIGPIPE.
      hits="$(printf '%s\n' "$text" | grep -E -- "$pattern" | grep -Ev -- "$LOCAL")"
      if [ -n "$hits" ]; then
        echo "commit $commit adds $name"
        found=1
      fi
    done
  done
  if [ "$found" -ne 0 ]; then
    echo "no secret pushed: a commit this push sends carries a credential. Take it out of the history, not only the tip, and change the credential"
    return 1
  fi
  echo "no secret pushed: $n commit(s) read, none carries a credential"
}

self_test() {
  local dir faults=0 said
  dir="$(mktemp -d)" || stop "no scratch directory"
  git init -q "$dir" && git -C "$dir" config core.autocrlf false && git -C "$dir" config user.email somebody@example.com && git -C "$dir" config user.name Somebody
  (
    cd "$dir" || exit 2
    printf 'An ordinary line.\n' >plain.txt
    git add -A && git commit -q -m "what was there before"
    base="$(git rev-parse HEAD)"
    printf 'postgres://postgres:ci-only@localhost:5432/postgres\n' >ci.txt
    git add -A && git commit -q -m "a test database on this machine"
    clean="$(git rev-parse HEAD)"
    # Each seed is put together here, so this file carries none of them whole.
    seeds=(
      "AKIA$(printf 'ABCDEFGHIJKLMNOP')"
      "-----BEGIN $(printf 'OPENSSH') PRIVATE KEY-----"
      "ghp_$(printf 'a%.0s' $(seq 1 36))"
      "sk_live_$(printf 'b%.0s' $(seq 1 24))"
      "whsec_$(printf 'c%.0s' $(seq 1 32))"
      "xoxb-$(printf '1%.0s' $(seq 1 12))-abc"
      "AIza$(printf 'd%.0s' $(seq 1 35))"
      "sk-$(printf 'e%.0s' $(seq 1 40))"
      "postgres://app:$(printf 'hunter2')@db.example.com:5432/app"
    )
    i=0
    for seed in "${seeds[@]}"; do
      i=$((i + 1))
      git checkout -q -b "seed-$i" "$clean"
      printf 'value=%s\n' "$seed" >seed.txt
      git add -A && git commit -q -m "a change"
      # And taken out again by the next commit, so only reading each commit finds it.
      printf 'value=nothing\n' >seed.txt
      git add -A && git commit -q -m "a later change"
    done
    git checkout -q -b main-here "$clean"
    printf '%s\n' "$base" >"$dir.base"
  ) || stop "the seeded repository could not be built"
  local base
  base="$(cat "$dir.base")"
  rm -f "$dir.base"
  # The remote branches here are what was there before, so what each seed's branch sends is read.
  git -C "$dir" update-ref refs/remotes/origin/main "$base"

  local refs="$dir.refs"
  printf 'refs/heads/main-here %s refs/heads/main-here %040d\n' "$(git -C "$dir" rev-parse main-here)" 0 >"$refs"
  if ! said="$(cd "$dir" && scan "$refs" 2>&1)"; then
    echo "  a push carrying only a test database on this machine was refused: $said"
    faults=$((faults + 1))
  fi
  local i=1
  while git -C "$dir" rev-parse -q --verify "seed-$i" >/dev/null; do
    printf 'refs/heads/seed-%s %s refs/backup/a-host/seed-%s %040d\n' "$i" "$(git -C "$dir" rev-parse "seed-$i")" "$i" 0 >"$refs"
    if said="$(cd "$dir" && scan "$refs" 2>&1)"; then
      echo "  seed $i, put in and taken out again on a backup ref, was passed"
      faults=$((faults + 1))
    elif [[ "$said" == *value=* ]]; then
      echo "  seed $i was refused and the refusal printed what it found"
      faults=$((faults + 1))
    fi
    i=$((i + 1))
  done
  rm -rf "$dir" "$refs"
  if [ "$faults" -ne 0 ]; then
    echo "no secret pushed, self-test: $faults fault(s)"
    return 1
  fi
  echo "no secret pushed, self-test: a clean push passes, and each of $((i - 1)) kinds of credential is refused on a backup ref after the next commit took it out"
}

case "${1:-}" in
  --self-test) self_test ;;
  '') scan '' ;;
  *) [ -r "$1" ] || stop "$1 cannot be read"; scan "$1" ;;
esac
