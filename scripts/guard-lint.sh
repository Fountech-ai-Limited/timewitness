#!/usr/bin/env bash
# The shapes a guard may not be written in, read over every script in a folder.
#
#     scripts/guard-lint.sh <folder> [more folders]      exit 0 clean, 1 with the lines named, 2 could not run
#     scripts/guard-lint.sh --self-test                  one seed per rule, each watched refused
#
# Every guard in this repository is a script whose exit code is read by a build, and a guard that
# reads clean when it could not run is worse than no guard: the board goes green and nobody looks.
# Two shapes of shell produce exactly that, and both were found in the message rule of
# `repo-hygiene.sh` on 2026-09-15, in both repositories.
#
# 1. A pipe into `grep -q` under `set -o pipefail`. `grep -q` exits the moment it matches, the
#    producer is still writing, it dies of SIGPIPE, the pipeline's status is 141, and the `if` reads
#    that as no match. Measured at 2 of 10 runs on one copy and 5 of 12 on the other, on the one
#    commit message in the history that carried a byte outside ASCII. Capture the producer's output
#    first, then grep the capture; the producer's own exit is then read on its own.
#
# 2. `grep`, `git grep` or `git log` with its output thrown away and its exit code read as the
#    answer. grep has three answers, not two: 0 is a match, 1 is no match, and anything above is a
#    grep that could not run, and a condition reads the third the same as the second. Count with
#    `grep -c` into a variable and read the status by name, so a grep that could not run stops the
#    check with exit 2 rather than passing it.
#
# A tool check, `command -v x >/dev/null 2>&1`, is the two-valued kind and is not caught. Nor is a
# comment. The rule is read per line, so a shape split across lines is not caught either; a script
# that hides one that way has read this file and disagreed with it.

set -uo pipefail

# The two shapes, each as a pattern and the sentence printed beside a line that has it.
PIPE_INTO_GREP_Q='\|[[:space:]]*(command[[:space:]]+)?grep[[:space:]]+(-[A-Za-z]*q|-[A-Za-z]+[[:space:]]+-[A-Za-z]*q)'
GREP_EXIT_AS_ANSWER='(^|[[:space:]!(])(git[[:space:]]+)?grep[[:space:]][^|;&]*(>[[:space:]]*/dev/null[[:space:]]+2>&1|2>[[:space:]]*/dev/null)'

# The lines of a file that carry a shape, numbered, with comment lines left out. A comment says what
# a script must not do and is allowed to spell it. grep's three answers are read by name: a grep
# that could not run stops this lint with exit 2, which is the rule this lint holds others to.
lines_with() {
  local pattern="$1" file="$2" found status
  found="$(grep -nE -- "$pattern" "$file")"
  status=$?
  if [ "$status" -gt 1 ]; then
    echo "guard lint: grep could not read $file (exit $status), so nothing was checked" >&2
    exit 2
  fi
  [ "$status" -eq 0 ] || return 0
  local line body
  while IFS= read -r line; do
    body="${line#*:}"
    body="${body#"${body%%[![:space:]]*}"}"
    case "$body" in
      '#'*) ;;
      *) printf '%s\n' "$line" ;;
    esac
  done <<<"$found"
}

lint_file() {
  local file="$1" hits=0 line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "guard lint: $file:${line%%:*} pipes into grep -q, which under pipefail reads a match as no match when the producer dies of SIGPIPE" >&2
    hits=$((hits + 1))
  done <<<"$(lines_with "$PIPE_INTO_GREP_Q" "$file")"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "guard lint: $file:${line%%:*} reads grep's exit as the answer with its output thrown away, so a grep that could not run reads as no match" >&2
    hits=$((hits + 1))
  done <<<"$(lines_with "$GREP_EXIT_AS_ANSWER" "$file")"
  return "$hits"
}

# The patterns above spell the shapes they ban, so this file is not linted over itself, and it is
# named here so that the exception is a sentence rather than a surprise.
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

if [ "${1:-}" = "--self-test" ]; then
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  seeds=(
    'if git log --all --format=%s | grep -qP "[^\x20-\x7E]"; then fail; fi'
    'printf "%s" "$text" | grep -qi -F -- "$name" && fail'
    'if git grep --cached -l -P "x" -- . >/dev/null 2>&1; then fail; fi'
    'if grep -rn -F "$shape" crates/ 2>/dev/null; then fail; fi'
  )
  failed=0
  for i in "${!seeds[@]}"; do
    printf '#!/usr/bin/env bash\n%s\n' "${seeds[$i]}" >"$work/seed-$i.sh"
    if lint_file "$work/seed-$i.sh" 2>/dev/null; then
      echo "guard lint: seed $i passed, and it is the shape this lint exists to refuse: ${seeds[$i]}" >&2
      failed=1
    fi
  done
  honest=(
    'matches="$(printf "%s\n" "$messages" | grep -cP "[^\x20-\x7E]")"'
    'if ! command -v gh >/dev/null 2>&1; then exit 2; fi'
    '# a comment may say: never pipe into grep -q'
    'count="$(git ls-files | grep -c .)"'
  )
  printf '#!/usr/bin/env bash\n' >"$work/honest.sh"
  printf '%s\n' "${honest[@]}" >>"$work/honest.sh"
  if ! lint_file "$work/honest.sh"; then
    echo "guard lint: an honest line was refused, so the lint cannot tell the shapes apart" >&2
    failed=1
  fi
  [ "$failed" -eq 0 ] && echo "guard lint: every seed refused, every honest line passed"
  exit "$failed"
fi

[ $# -ge 1 ] || { echo "guard lint: name at least one folder of scripts to read" >&2; exit 2; }

read_count=0
hits=0
for folder in "$@"; do
  [ -d "$folder" ] || { echo "guard lint: $folder is not a folder" >&2; exit 2; }
  for file in "$folder"/*.sh; do
    [ -f "$file" ] || continue
    [ "$(cd "$(dirname "$file")" && pwd)/$(basename "$file")" = "$self" ] && continue
    read_count=$((read_count + 1))
    lint_file "$file" || hits=$((hits + $?))
  done
done

# A folder with no script in it is not a clean folder, it is the wrong folder.
if [ "$read_count" -eq 0 ]; then
  echo "guard lint: no shell script was read under $*, so nothing was checked" >&2
  exit 2
fi
if [ "$hits" -ne 0 ]; then
  echo "guard lint: $hits lines over $read_count scripts" >&2
  exit 1
fi
echo "guard lint: $read_count scripts read, none pipes into grep -q or reads grep's exit as the answer"
