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

    # Rule 1 allows one shape besides the one author, so the seeds for it are five merges that differ
    # from each other in one condition each. Four have to be refused and the fifth has to be
    # allowed, and a rule that lets the fifth through while letting any of the four through as well
    # is worth nothing. Each sha is written out so the caller names the commit rather than the
    # identity, because two of these carry identities the allowed one also carries.
    seed_a_merge() {
      local name="$1" author="$2" committer="$3" subject="$4" parents="$5"
      printf 'seed\n' >"docs/a-seed-from-$name.md"
      git add -A
      git commit --quiet -m "A seeded commit for $name" || return 1
      if [ "$parents" = "one" ]; then
        GIT_AUTHOR_NAME="${author%% <*}" GIT_AUTHOR_EMAIL="$(printf '%s' "${author##*<}" | tr -d '>')" \
        GIT_COMMITTER_NAME="${committer%% <*}" GIT_COMMITTER_EMAIL="$(printf '%s' "${committer##*<}" | tr -d '>')" \
          git commit --quiet --amend --reset-author -m "$subject" || return 1
      else
        git checkout --quiet -b "$name" || return 1
        printf 'seed\n' >"docs/a-branch-seed-from-$name.md"
        git add -A
        git commit --quiet -m "A seeded commit on the $name branch" || return 1
        git checkout --quiet - || return 1
        GIT_AUTHOR_NAME="${author%% <*}" GIT_AUTHOR_EMAIL="$(printf '%s' "${author##*<}" | tr -d '>')" \
        GIT_COMMITTER_NAME="${committer%% <*}" GIT_COMMITTER_EMAIL="$(printf '%s' "${committer##*<}" | tr -d '>')" \
          git merge --quiet --no-ff -m "$subject" "$name" || return 1
      fi
      git rev-parse HEAD >"$work/sha-$name" || return 1
    }
    nik_on_github="nikkai1007 <76212305+nikkai1007@users.noreply.github.com>"
    github="GitHub <noreply@github.com>"

    # Refused: a robot account opened it, which is the shape every dependency bump arrives in.
    seed_a_merge robot-author "a-robot[bot] <49699333+a-robot[bot]@users.noreply.github.com>" \
      "$github" "Merge pull request #101 from Fountech-ai-Limited/a-seeded-branch" two || exit 2
    # Refused: somebody put the two identities on a commit of their own, with no pull request in it.
    seed_a_merge hand-written "$nik_on_github" "$github" "A merge written by hand" two || exit 2
    # Refused: a pull request from a fork, which is somebody else's branch however it is merged.
    seed_a_merge outside-the-org "$nik_on_github" "$github" \
      "Merge pull request #103 from somebody-else/a-seeded-branch" two || exit 2
    # Refused: everything the button writes except the committer, so somebody merged it themselves.
    seed_a_merge foreign-committer "$nik_on_github" "Somebody Else <somebody@example.com>" \
      "Merge pull request #102 from Fountech-ai-Limited/a-seeded-branch" two || exit 2
    # Refused: one parent, so it is an ordinary commit wearing the merge button's identities.
    seed_a_merge one-parent "$nik_on_github" "$github" \
      "Merge pull request #104 from Fountech-ai-Limited/a-seeded-branch" one || exit 2
    # Refused: a name carrying the separators of the line this rule used to read, laid out so the
    # fields after it say the merge button wrote a commit that somebody else wrote.
    seed_a_merge bar-dressed-as-the-button \
      "nikkai1007|76212305+nikkai1007@users.noreply.github.com|GitHub|noreply@github.com|Merge pull request #106 from Fountech-ai-Limited/a-seeded-branch <somebody@example.com>" \
      "Somebody Else <somebody@example.com>" "A merge by somebody else" two || exit 2
    # Allowed: what the button itself writes, and the only thing this rule lets past.
    seed_a_merge the-button "$nik_on_github" "$github" \
      "Merge pull request #105 from Fountech-ai-Limited/a-seeded-branch" two || exit 2

    # Refused: a name that holds a bar. Git refuses only `<`, `>` and a newline in a name, and until
    # 2026-09-21 rule 1 split every commit's line on bars, so each of these three set both addresses
    # the rule compares to the one this repository requires. Each is written out by sha.
    seed_an_identity() {
      local name="$1"
      printf 'seed\n' >"docs/a-seed-from-$name.md"
      git add -A
      GIT_AUTHOR_NAME="$2" GIT_AUTHOR_EMAIL="$3" GIT_COMMITTER_NAME="$4" GIT_COMMITTER_EMAIL="$5" \
        git commit --quiet -m "A seeded commit for $name" || return 1
      git rev-parse HEAD >"$work/sha-$name" || return 1
    }
    seed_an_identity bar-in-the-author-name \
      "Somebody Else|nik@fountech.ai|Somebody Else|nik@fountech.ai" "somebody@example.com" \
      "Somebody Else" "somebody@example.com" || exit 2
    seed_an_identity bar-in-the-committer-name "Nik Kairinos" "nik@fountech.ai" \
      "Somebody|nik@fountech.ai|" "somebody@example.com" || exit 2
    seed_an_identity an-address-for-a-name "Somebody|nik@fountech.ai" "somebody@example.com" \
      "nik@fountech.ai" "somebody@example.com" || exit 2
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
  # The near misses of the merge button and the three names that hold a bar, named by sha rather
  # than by identity, because several carry the identities an allowed commit carries and the
  # sentence would not tell them apart.
  for seed in robot-author foreign-committer hand-written outside-the-org one-parent \
    bar-dressed-as-the-button bar-in-the-author-name bar-in-the-committer-name an-address-for-a-name; do
    seeded_sha="$(cat "$work/sha-$seed" 2>/dev/null)"
    if [ -z "$seeded_sha" ]; then
      echo "repo hygiene: the $seed seed was never planted, so nothing was watched refusing it" >&2
      missed=1
      continue
    fi
    case "$said" in
      *"$seeded_sha is authored by"*) ;;
      *)
        echo "repo hygiene: the seeded clone was not refused for the $seed seed, $seeded_sha" >&2
        missed=1
        ;;
    esac
  done
  # And the one shape the rule allows, which has to come back unreported or the allowance is a hole
  # that happens to be quiet today.
  button_sha="$(cat "$work/sha-the-button" 2>/dev/null)"
  if [ -z "$button_sha" ]; then
    echo "repo hygiene: the merge button seed was never planted, so nothing proved it is allowed" >&2
    missed=1
  else
    case "$said" in
      *"$button_sha"*)
        echo "repo hygiene: the merge button's own commit was refused, $button_sha" >&2
        missed=1
        ;;
    esac
  fi
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
  echo "repo hygiene: every seed refused by its own rule, the merge button's own commit allowed, and the plain message passed"
  exit 0
fi

# The populations every rule below reads, read once and counted. A rule that reads an empty list
# passes, so each list is held to what git says is there before any rule runs over it.
#
# The commits are read as seven fields each, and every field is ended by a NUL. Git writes no NUL
# inside a name, an address or a subject, so no value can move another. Until 2026-09-21 this was
# one line per commit joined by bars, and git accepts a bar in a name: a name laid out as
# `Somebody|nik@fountech.ai|Somebody|nik@fountech.ai` set both addresses rule 1 compares, and a
# commit by anybody went through. The fields are then held three ways, so a value that did move
# another stops the check rather than passing it: seven fields for every commit git counts, a full
# commit id in every first field, and nothing but commit ids in every second.
commit_count="$(git rev-list --all --count)" || stop "git rev-list could not count the commits"
[ "$commit_count" -ge 1 ] || stop "this repository has no commits"
fields_per_commit=7
commit_file="$(mktemp)" || stop "no scratch file could be made for the commit list"
trap 'rm -f "$commit_file"' EXIT
git log --all -z --format='%H%x00%P%x00%an%x00%ae%x00%cn%x00%ce%x00%s' >"$commit_file" || stop "git log could not list the commits"
commit_fields=()
while IFS= read -r -d '' field; do
  commit_fields+=("$field")
done <"$commit_file"
[ "${#commit_fields[@]}" -eq $((commit_count * fields_per_commit)) ] || stop "git log gave ${#commit_fields[@]} fields for $commit_count commits, where $fields_per_commit each were asked for, so one commit's fields cannot be told from the next"
commit_ids=()
for ((i = 0; i < ${#commit_fields[@]}; i += fields_per_commit)); do
  [[ "${commit_fields[i]}" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || stop "field $i of the commit list should be a commit id and is '${commit_fields[i]}'"
  [[ "${commit_fields[i + 1]}" =~ ^(([0-9a-f]{40}|[0-9a-f]{64})( |$))*$ ]] || stop "the parents of ${commit_fields[i]} read '${commit_fields[i + 1]}', which is not a list of commit ids"
  commit_ids+=("${commit_fields[i]}")
done

tracked="$(git -c core.quotePath=false ls-files)" || stop "git ls-files could not list the tree"
tracked_count="$(printf '%s\n' "$tracked" | grep -c .)"
[ "$tracked_count" -ge 1 ] || stop "this repository tracks no file"

eol="$(git -c core.quotePath=false ls-files --eol)" || stop "git ls-files --eol could not read the tree"
[ "$(printf '%s\n' "$eol" | grep -c .)" -eq "$tracked_count" ] || stop "git ls-files --eol listed a different number of files from git ls-files"

# 1. One author.
#
# Both fields on every commit, across every branch. They differ more often than people expect, and a
# branch nobody has merged is still in a clone.
#
# One other identity is allowed and it is GitHub itself, on the one commit the merge button writes.
# Merging a pull request on the website produces a commit authored by the account that opened it and
# committed by `GitHub <noreply@github.com>`, and no setting on the repository changes that
# committer: the merge commit, the squash and the rebase all carry it. So the choice is between
# allowing that one shape and never merging a pull request here at all. It is the platform recording
# a merge the owner of this repository asked for, not a second person and not a tool writing code,
# and refusing it says nothing true about who wrote what is here.
#
# It was refused twice before the allowance went in. Pull request 2 on 2026-09-19 merged as
# `92c9299` and the run on `main` failed here; the commit was taken off `main` by a force push
# twenty-four minutes later and nothing was written down. Pull request 3 on 2026-09-20 merged as
# `502071a` and sat at the head of `main` with the required check red, so nothing else could merge
# either, because the protection has `strict` on and every branch has to carry `main`'s head before
# it goes in. The force push is the argument for the allowance rather than against it: it changed
# what `main` reaches and removed nothing, `git fetch origin 92c9299` still answering with the
# commit a day later.
#
# The allowance is four conditions and every one of them has to hold: the committer is exactly
# GitHub's own identity, the author is the one account that owns this repository or the one address
# every other commit here carries, the commit has two parents or more, and the subject is the
# sentence GitHub writes when it merges a pull request of this organisation's own. Anything
# missing one of them is refused, which includes a commit that copies
# the two identities on to work somebody wrote by hand. An identity is a string anybody with push
# rights can write, so what this refuses is a mistake or a stranger's commit, not somebody forging
# all four on purpose.

# GitHub's own merge commit on the four conditions above. Returns 0 only when all four hold.
is_the_merge_button() {
  local parents="$1" an="$2" ae="$3" cn="$4" ce="$5" subject="$6" parent_count=0 parent
  [ "$cn <$ce>" = "GitHub <noreply@github.com>" ] || return 1
  case "$an <$ae>" in
    "Nik Kairinos <nik@fountech.ai>") ;;
    "nikkai1007 <76212305+nikkai1007@users.noreply.github.com>") ;;
    *) return 1 ;;
  esac
  # `%P` is the parents separated by spaces, so counting the words is counting the parents.
  for parent in $parents; do
    parent_count=$((parent_count + 1))
  done
  [ "$parent_count" -ge 2 ] || return 1
  count_matching '^Merge pull request #[0-9]+ from Fountech-ai-Limited/' "$subject"
  [ "$MATCH_COUNT" -eq 1 ]
}

# Each field is compared whole, as git wrote it, so an address matches only when it is the address.
for ((i = 0; i < ${#commit_fields[@]}; i += fields_per_commit)); do
  sha="${commit_fields[i]}" parents="${commit_fields[i + 1]}"
  an="${commit_fields[i + 2]}" ae="${commit_fields[i + 3]}"
  cn="${commit_fields[i + 4]}" ce="${commit_fields[i + 5]}" subject="${commit_fields[i + 6]}"
  [ "$ae" = "nik@fountech.ai" ] && [ "$ce" = "nik@fountech.ai" ] && continue
  is_the_merge_button "$parents" "$an" "$ae" "$cn" "$ce" "$subject" && continue
  report "$sha is authored by '$an <$ae>' and committed by '$cn <$ce>'"
done

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
for sha in "${commit_ids[@]}"; do
  trailers="$(git log -1 --format='%(trailers:only=true)' "$sha")" || stop "git log could not read $sha"
  if [ -n "$trailers" ]; then
    report "the commit message of $sha carries a footer, and messages here are prose"
  fi
done

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
