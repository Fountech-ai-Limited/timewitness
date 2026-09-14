#!/usr/bin/env bash
# Four rules about what this repository may contain, checked over the tree and over the whole
# history rather than over the tip.
#
# Each is stated as what belongs rather than as what does not. A list of things to keep out has to be
# guessed at and goes stale; a list of what is allowed refuses everything nobody has thought about,
# which is the direction that fails safe.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

fail=0

report() {
  echo "repo hygiene: $1" >&2
  fail=1
}

# Checking one message before it becomes a commit, which is what `--message` is for.
#
# The two rules that read a commit message, the footer rule and the ASCII rule, used to be found
# after the push. Run from a `commit-msg` hook they are found in the editor instead. The hook is
# machine-local, a fresh clone does not have it, and it is two lines:
#
#     printf '#!/bin/sh\nexec scripts/repo-hygiene.sh --message "$1"\n' > .git/hooks/commit-msg
#     chmod +x .git/hooks/commit-msg
if [ "${1:-}" = "--message" ]; then
  message_file="${2:?repo-hygiene.sh --message needs the path to a message file}"
  message="$(git stripspace --strip-comments <"$message_file")"

  if [ -n "$(printf '%s\n' "$message" | git interpret-trailers --parse)" ]; then
    report "this message carries a footer, and messages here are prose"
  fi
  if printf '%s\n' "$message" | grep -qP '[^\x09\x0a\x20-\x7E]'; then
    report "this message carries a byte that is not tab, newline or printable ASCII"
    printf '%s\n' "$message" | grep -nP '[^\x09\x0a\x20-\x7E]' >&2 || true
  fi
  if [ "$fail" -ne 0 ]; then
    exit 1
  fi
  exit 0
fi

# 1. One author.
#
# Both fields on every commit, across every branch. They differ more often than people expect, and a
# branch nobody has merged is still in a clone.
while IFS='|' read -r an ae cn ce; do
  if [ "$ae" != "nik@fountech.ai" ] || [ "$ce" != "nik@fountech.ai" ]; then
    report "a commit is authored by '$an <$ae>' and committed by '$cn <$ce>'"
  fi
done < <(git log --all --format='%an|%ae|%cn|%ce')

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
while read -r sha; do
  if [ -n "$(git log -1 --format='%(trailers:only=true)' "$sha")" ]; then
    report "the commit message of $sha carries a footer, and messages here are prose"
  fi
done < <(git log --all --format='%H')

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
done < <(git ls-files --eol)

if git grep --cached -l -P '[^\x09\x0a\x20-\x7E]' -- . ":!$binary" >/dev/null 2>&1; then
  report "a tracked file carries a byte that is not tab, newline or printable ASCII"
  git grep --cached -n -P '[^\x09\x0a\x20-\x7E]' -- . ":!$binary" >&2 || true
fi
if git log --all --format='%an%ae%s%b' | grep -qP '[^\x09\x0a\x20-\x7E]'; then
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

while read -r path; do
  [ -z "$path" ] && continue
  if ! printf '%s' "$path" | grep -Eq "$allowed"; then
    report "'$path' is tracked and is not one of the things this repository holds"
  fi
done < <(git ls-files)

# Every name a file was ever stored under, not only the names it was added at. With rename
# detection on, which is git's default, a file moved to a new name is a rename and never an
# addition, and a merge shows no names at all, so both used to go past this unread. Renames are
# switched off and every merge is read against each of its parents.
while read -r path; do
  [ -z "$path" ] && continue
  if ! printf '%s' "$path" | grep -Eq "$allowed"; then
    report "'$path' is in the history and is not one of the things this repository holds"
  fi
done < <(git -c core.quotePath=false log --all --no-renames -m --root --name-only --format='' | sort -u)

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "repo hygiene: clean"
