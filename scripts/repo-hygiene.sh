#!/usr/bin/env bash
# Four rules about what this repository may contain, checked over the tree and over the whole
# history rather than over the tip.
#
# Each is stated as what belongs rather than as what does not. A list of things to keep out has to be
# guessed at and goes stale; a list of what is allowed refuses everything nobody has thought about,
# which is the direction that fails safe.
#
#     scripts/repo-hygiene.sh                    the repository this file sits in
#     scripts/repo-hygiene.sh --repo <path>      another clone of it, which the self-test uses
#     scripts/repo-hygiene.sh --message <file>   one commit message, before it is made
#     scripts/repo-hygiene.sh --self-test        a scratch clone seeded with one breach of each rule
#
# Three exits and each means one thing: 0 is clean, 1 is a rule broken with the breach named, and 2
# is a check that could not run. The third is the one this file was rewritten for on 2026-09-15.
# Until then the message rule piped `git log` into `grep -q` under `pipefail`, and when grep matched
# and exited first the producer died of SIGPIPE, the pipeline read 141, and the `if` read no match:
# 2 of 10 runs on the one message in the history that carried a byte outside ASCII. Every rule below
# now reads its population into a variable first, counts what it read and holds the count to what git
# says is there, and reads grep's three answers by name, so a grep that could not run stops the check
# rather than passing it. `scripts/guard-lint.sh` refuses the two shapes that did this.

set -uo pipefail

repo=""
mode="tree"
message_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)
      repo="${2:?--repo needs a path}"
      shift
      ;;
    --message)
      mode="message"
      message_file="${2:?repo-hygiene.sh --message needs the path to a message file}"
      shift
      ;;
    --self-test) mode="self-test" ;;
    *)
      echo "repo hygiene: $1 is not an option this takes" >&2
      exit 2
      ;;
  esac
  shift
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "$repo" ]; then
  repo="$(cd "$here/.." && pwd)"
fi
cd "$repo" || { echo "repo hygiene: $repo is not a folder" >&2; exit 2; }

fail=0

report() {
  echo "repo hygiene: $1" >&2
  fail=1
}

# A check that could not run. Never a pass and never a plain failure: the reader has to be able to
# tell a rule that was broken from a rule that was never read.
stop() {
  echo "repo hygiene: $1, so nothing was checked" >&2
  exit 2
}

# How many lines of `$2` match the pattern `$1`, left in MATCH_COUNT, with grep's three answers read
# by name. 0 and 1 are a count; anything else is a grep that could not run.
#
# **The count comes back in a variable, because `stop` inside `$( )` stops nothing.** This read
# `printf '%s' "$n"` and both callers were `[ "$(count_matching ...)" -ne 0 ]`. A command
# substitution is a subshell, so `stop`'s exit ended the subshell, the caller compared an empty
# string against a number, `test` errored, the `if` body was skipped and the run carried on to print
# that the repository was clean. The pattern is `grep -P`, so any grep with no PCRE compiled into it
# does that: busybox, Alpine, and the BSD grep on macOS. On the `--message` path, which is the
# `commit-msg` hook, a real message carrying a byte outside ASCII went from refused to accepted.
# Corrected 2026-09-19.
MATCH_COUNT=0
count_matching() {
  local pattern="$1" text="$2" status
  MATCH_COUNT="$(printf '%s\n' "$text" | grep -cP -- "$pattern")"
  status=$?
  [ "$status" -le 1 ] || stop "grep could not run over the text it was given (exit $status)"
}

# The lines of `$2` matching `$1`, for printing beside a report.
lines_matching() {
  printf '%s\n' "$2" | grep -nP -- "$1" || true
}

# Checking one message before it becomes a commit, which is what `--message` is for.
#
# The two rules that read a commit message, the footer rule and the ASCII rule, used to be found
# after the push. Run from a `commit-msg` hook they are found in the editor instead. The hook is
# machine-local, a fresh clone does not have it, and it is two lines:
#
#     printf '#!/bin/sh\nexec scripts/repo-hygiene.sh --message "$1"\n' > .git/hooks/commit-msg
#     chmod +x .git/hooks/commit-msg
check_message() {
  local message
  message="$(git stripspace --strip-comments <"$1")" || stop "the message at $1 could not be read"

  if [ -n "$(printf '%s\n' "$message" | git interpret-trailers --parse)" ]; then
    report "this message carries a footer, and messages here are prose"
  fi
  count_matching '[^\x09\x0a\x20-\x7E]' "$message"
  if [ "$MATCH_COUNT" -ne 0 ]; then
    report "this message carries a byte that is not tab, newline or printable ASCII"
    lines_matching '[^\x09\x0a\x20-\x7E]' "$message" >&2
  fi
}

if [ "$mode" = "message" ]; then
  check_message "$message_file"
  [ "$fail" -eq 0 ] || exit 1
  exit 0
fi

if [ "$mode" = "self-test" ]; then
  # A scratch clone of this repository with one breach of each rule that reads the history or the
  # tree planted in it, then this script run over the clone through the same code path a build
  # runs it through. Passes only when every planted breach is reported by its own sentence. The
  # planted commits are made with the committer this repository requires, so that only the rule
  # each one is for fires on it.
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  git clone --quiet "$repo" "$work/clone" || stop "the scratch clone could not be made"
  (
    cd "$work/clone" || exit 2
    git config user.name "Nik Kairinos"
    git config user.email "nik@fountech.ai"
    git config commit.gpgsign false
    printf 'a line with a dash that is not a hyphen: \xe2\x80\x94\n' >docs/a-seeded-file.md
    printf 'a file the allowlist has never heard of\n' >somewhere-else.txt
    git add -A
    git commit --quiet -m "$(printf 'A seeded message with an em dash \xe2\x80\x94 in it')" || exit 2
    printf 'seed\n' >docs/a-second-seed.md
    git add -A
    git commit --quiet -m "$(printf 'A seeded message with a footer\n\nSigned-off-by: somebody <somebody@example.com>')" || exit 2
    printf 'seed\n' >docs/a-third-seed.md
    git add -A
    git -c user.email="somebody@example.com" -c user.name="Somebody Else" commit --quiet -m "A seeded commit by somebody else" || exit 2
  ) || stop "the seeds could not be planted"

  said="$(bash "$here/repo-hygiene.sh" --repo "$work/clone" 2>&1)"
  status=$?
  if [ "$status" -ne 1 ]; then
    printf '%s\n' "$said" >&2
    stop "the seeded clone came back exit $status rather than 1"
  fi
  expected=(
    "a commit message carries a byte that is not tab, newline or printable ASCII"
    "carries a footer, and messages here are prose"
    "is authored by 'Somebody Else <somebody@example.com>'"
    "a tracked file carries a byte that is not tab, newline or printable ASCII"
    "'somewhere-else.txt' is tracked and is not one of the things this repository holds"
    "'somewhere-else.txt' is in the history and is not one of the things this repository holds"
  )
  missed=0
  for sentence in "${expected[@]}"; do
    case "$said" in
      *"$sentence"*) ;;
      *)
        echo "repo hygiene: the seeded clone was not refused for: $sentence" >&2
        missed=1
        ;;
    esac
  done
  # And the message path, with its two seeds.
  printf 'A message with a footer\n\nSigned-off-by: somebody <somebody@example.com>\n' >"$work/footer"
  if bash "$here/repo-hygiene.sh" --message "$work/footer" 2>/dev/null; then
    echo "repo hygiene: --message passed a footer" >&2
    missed=1
  fi
  printf 'A message with \xe2\x80\x94 in it\n' >"$work/dash"
  if bash "$here/repo-hygiene.sh" --message "$work/dash" 2>/dev/null; then
    echo "repo hygiene: --message passed a byte outside ASCII" >&2
    missed=1
  fi
  printf 'A plain message\n\nWith prose under it.\n' >"$work/plain"
  if ! bash "$here/repo-hygiene.sh" --message "$work/plain" 2>/dev/null; then
    echo "repo hygiene: --message refused a plain message" >&2
    missed=1
  fi
  if [ "$missed" -ne 0 ]; then
    printf '%s\n' "$said" >&2
    exit 1
  fi
  echo "repo hygiene: every seed refused by its own rule, and the plain message passed"
  exit 0
fi

# The populations every rule below reads, read once and counted. A rule that reads an empty list
# passes, so each list is held to what git says is there before any rule runs over it.
commits="$(git log --all --format='%H|%an|%ae|%cn|%ce')" || stop "git log could not list the commits"
commit_count="$(git rev-list --all --count)" || stop "git rev-list could not count the commits"
[ "$commit_count" -ge 1 ] || stop "this repository has no commits"
[ "$(printf '%s\n' "$commits" | grep -c .)" -eq "$commit_count" ] || stop "git log listed a different number of commits from git rev-list"

tracked="$(git -c core.quotePath=false ls-files)" || stop "git ls-files could not list the tree"
tracked_count="$(printf '%s\n' "$tracked" | grep -c .)"
[ "$tracked_count" -ge 1 ] || stop "this repository tracks no file"

eol="$(git -c core.quotePath=false ls-files --eol)" || stop "git ls-files --eol could not read the tree"
[ "$(printf '%s\n' "$eol" | grep -c .)" -eq "$tracked_count" ] || stop "git ls-files --eol listed a different number of files from git ls-files"

# 1. One author.
#
# Both fields on every commit, across every branch. They differ more often than people expect, and a
# branch nobody has merged is still in a clone.
while IFS='|' read -r sha an ae cn ce; do
  [ -n "$sha" ] || continue
  if [ "$ae" != "nik@fountech.ai" ] || [ "$ce" != "nik@fountech.ai" ]; then
    report "a commit is authored by '$an <$ae>' and committed by '$cn <$ce>'"
  fi
done <<<"$commits"

# 2. No trailers.
#
# A commit message is a subject, then prose. Nothing in this repository has a reason to carry a
# machine-readable footer, so the rule is that there are none rather than a list of which ones are
# not allowed.
#
# What counts as a footer is git's answer and not ours. This used to grep every body line for a word
# and a colon at the start, which is a different question: it fired on a wrapped sentence whose
# second line began "not: it is narrower", and it fired after the commit had been pushed, so fixing
# it meant amending and force-pushing. A trailer lives in the last paragraph, git knows where that
# is, and `%(trailers)` is that knowledge. The subject is exempt either way, because a subject may
# legitimately be prefixed.
while IFS='|' read -r sha rest; do
  [ -n "$sha" ] || continue
  trailers="$(git log -1 --format='%(trailers:only=true)' "$sha")" || stop "git log could not read $sha"
  if [ -n "$trailers" ]; then
    report "the commit message of $sha carries a footer, and messages here are prose"
  fi
done <<<"$commits"

# 3. Plain ASCII, everywhere, and one line ending.
#
# One rule covering several habits at once, and cheaper to hold than any of them separately: no
# emoji, no dashes that are not hyphens, no quotation marks that are not quotation marks, in a file
# or in a commit message. Every quantity this product deals in is written in ASCII already.
#
# It names the bytes that belong rather than the ones that do not: tab, newline, and the printable
# range. Written the other way round, as everything outside `[^\x00-\x7F]`, it permitted every
# control byte in ASCII, which is how a raw NUL sat in the format specification for a day. A
# carriage return fails the same rule, so `.gitattributes` now has something enforcing it rather
# than only stating it.
#
# The whole tree is one text file after another, with one exception, which is named here so that
# adding a second is a deliberate act. Anything else git classes as binary fails on that state
# alone, before its contents are read, because that is the state the NUL hid behind: git calls such
# a file binary, `git grep -I` skips it, and every rule here that greps then goes blind on it.
# Failing on the state is louder than failing on the contents, and it fails for a file nobody has
# thought about yet.
#
# Every grep below reads the index rather than the working tree. What the repository holds is the
# question, and a checkout is free to differ: `core.autocrlf` on Windows hands the working tree
# CRLF from an index that is LF, and a rule reading the working tree would then fail on every line
# of every file on one machine and pass on another.
binary='crates/verify/tests/data/a-real-stamp/receipt.cbor'

while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  info="${entry%%$'\t'*}"
  path="${entry#*$'\t'}"
  case "${info%% *}" in
    i/lf | i/none) ;;
    i/-text)
      if [ "$path" != "$binary" ]; then
        report "'$path' is tracked and git classes it as binary, so every rule here that greps is blind to it"
      fi
      ;;
    *)
      report "'$path' is committed with ${info%% *} line endings, and .gitattributes says lf"
      ;;
  esac
done <<<"$eol"

non_ascii_files="$(git grep --cached -l -P '[^\x09\x0a\x20-\x7E]' -- . ":!$binary")"
status=$?
[ "$status" -le 1 ] || stop "git grep could not read the index (exit $status)"
if [ "$status" -eq 0 ]; then
  report "a tracked file carries a byte that is not tab, newline or printable ASCII"
  git grep --cached -n -P '[^\x09\x0a\x20-\x7E]' -- . ":!$binary" >&2 || true
fi

messages="$(git log --all --format='%an%ae%s%b')" || stop "git log could not read the messages"
count_matching '[^\x09\x0a\x20-\x7E]' "$messages"
if [ "$MATCH_COUNT" -ne 0 ]; then
  report "a commit message carries a byte that is not tab, newline or printable ASCII"
fi

# 4. What a tracked path may be.
#
# Anything genuinely new goes in this line, in a commit whose message says why it belongs.
#
# `verifier-page/` is the source of the one HTML file a stranger downloads to check a receipt: the
# markup, the glue, and the brand tokens and lockup it embeds. The built file itself is not tracked,
# because it is an output. `action.yml` sits at the root because that is the only place a workflow
# step can reference it from. `.cargo/audit.toml` is the list of advisories `check-advisories.sh`
# passes over, and cargo-audit reads it from that path and no other; it is one named file rather
# than the whole directory, because `.cargo/config.toml` changes how every build here compiles and
# nothing should be able to add one without saying so. `LICENSE` and `NOTICE` sit at the root
# because that is where every tool that reads a licence looks: GitHub, cargo, and the section 4d
# propagation rule in the licence itself all take the root copy and nothing else.
#
# `deploy/` is how the two Roughtime servers of ours are built and configured, which belongs
# in the repository for the same reason the workflows do: a deployment nobody can read is a
# deployment whose behaviour nothing describes. It holds no key and never will, since the
# hosts take theirs from a secret store. `.dockerignore` sits at the root because a container
# build reads it from the build context root and from nowhere else; without it a remote build
# uploads `target/`, which is gigabytes on any machine that has built this workspace.
allowed='^(crates/|docs/|deploy/|scripts/|verifier-page/|\.github/(workflows/)?[A-Za-z0-9._-]+$|\.cargo/audit\.toml$|action\.yml$|Cargo\.(toml|lock)$|README\.md$|LICENSE$|NOTICE$|\.gitignore$|\.dockerignore$|\.gitattributes$|rustfmt\.toml$|rust-toolchain\.toml$)'

while IFS= read -r path; do
  [ -z "$path" ] && continue
  if ! [[ "$path" =~ $allowed ]]; then
    report "'$path' is tracked and is not one of the things this repository holds"
  fi
done <<<"$tracked"

# Every name a file was ever stored under, not only the names it was added at. With rename
# detection on, which is git's default, a file moved to a new name is a rename and never an
# addition, and a merge shows no names at all, so both used to go past this unread. Renames are
# switched off and every merge is read against each of its parents.
history_paths="$(git -c core.quotePath=false log --all --no-renames -m --root --name-only --format='' | sort -u)" || stop "git log could not list the paths in the history"
history_count="$(printf '%s\n' "$history_paths" | grep -c .)"
[ "$history_count" -ge "$tracked_count" ] || stop "the history names $history_count paths and the tree $tracked_count, so the history was not read whole"
while IFS= read -r path; do
  [ -z "$path" ] && continue
  if ! [[ "$path" =~ $allowed ]]; then
    report "'$path' is in the history and is not one of the things this repository holds"
  fi
done <<<"$history_paths"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "repo hygiene: clean over $commit_count commits, $tracked_count tracked files and $history_count paths in the history"
