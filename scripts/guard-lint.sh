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
# 3. A helper that ends the run with `exit`, called inside `$( )`. A command substitution is a
#    subshell, so the exit ends the subshell and nothing else: the caller reads an empty string,
#    counts nought and carries on, and the run prints that it checked something it never read. This
#    rule went in on 2026-09-19 after the shape was found at eleven sites across both repositories,
#    the first of them in this file. It needs the whole file rather than one line, so it is read
#    separately from the two above.
#
# A tool check, `command -v x >/dev/null 2>&1`, is the two-valued kind and is not caught. Nor is a
# comment. Rules 1 and 2 are read per line, so a shape split across lines is not caught either; a
# script that hides one that way has read this file and disagreed with it.

set -uo pipefail

# The two shapes, each as a pattern and the sentence printed beside a line that has it.
PIPE_INTO_GREP_Q='\|[[:space:]]*(command[[:space:]]+)?grep[[:space:]]+(-[A-Za-z]*q|-[A-Za-z]+[[:space:]]+-[A-Za-z]*q)'
GREP_EXIT_AS_ANSWER='(^|[[:space:]!(])(git[[:space:]]+)?grep[[:space:]][^|;&]*(>[[:space:]]*/dev/null[[:space:]]+2>&1|2>[[:space:]]*/dev/null)'

# The status `lint_file` returns for a file it could not read, which a caller must not add to a
# count of hits. It is above any hit count a file can produce and the cap below keeps it that way.
UNREADABLE=254

# The lines of a file that carry a shape, numbered, with comment lines left out, left in
# LINES_FOUND. A comment says what a script must not do and is allowed to spell it. grep's three
# answers are read by name: a grep that could not run returns 2.
#
# **The answer comes back in a variable and the verdict in the return value, and that is the whole
# point of the shape.** This helper ended `exit 2` and both its callers invoked it as
# `<<<"$(lines_with ...)"`. A command substitution is a subshell, so the exit ended the subshell and
# nothing else: the caller read an empty string, counted nought hits and returned success. This
# file, whose job is to refuse guards that answer clean where they could not read, carried that
# shape until 2026-09-19 and printed "9 scripts read, none pipes into grep -q" over a tree with a
# planted violation in it. Nothing inside `$( )` may decide this run.
LINES_FOUND=''
lines_with() {
  local pattern="$1" file="$2" found status line body
  LINES_FOUND=''
  found="$(grep -nE -- "$pattern" "$file")"
  status=$?
  if [ "$status" -gt 1 ]; then
    echo "guard lint: grep could not read $file (exit $status), so nothing was checked" >&2
    return 2
  fi
  [ "$status" -eq 0 ] || return 0
  while IFS= read -r line; do
    body="${line#*:}"
    body="${body#"${body%%[![:space:]]*}"}"
    case "$body" in
      '#'*) ;;
      *) LINES_FOUND="${LINES_FOUND}${line}
" ;;
    esac
  done <<<"$found"
  return 0
}

# The call sites in a file where a function that can `exit` is run inside `$( )`, numbered.
#
# Which functions those are is worked out from the file rather than listed here: a function whose
# body calls `exit`, or calls a function already known to, is one. The fixpoint is two lines of awk
# and it matters, because the shape in this repository was always one function calling another, a
# helper calling `stop` rather than exiting itself.
#
# What it cannot see: a helper in another file, and a function called through a variable. Both are
# outside what reading one file can answer, and saying so is better than implying otherwise.
exits_inside_a_substitution() {
  awk '
    # The name a function definition opens, or the empty string.
    #
    # Both spellings, because both are shell. `name() {` is the one this repository uses and
    # `function name {` is the one it did not, which is how the second went unread until 2026-09-19:
    # a helper written that way could end the run and nothing here knew it was a function at all.
    function opened(line,   name) {
      if (match(line, /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(\)[[:space:]]*\{/)) {
        name = substr(line, RSTART, RLENGTH)
        sub(/^[[:space:]]*/, "", name)
        sub(/[[:space:]]*\(\).*$/, "", name)
        return name
      }
      if (match(line, /^[[:space:]]*function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*([[:space:]]*\(\))?[[:space:]]*\{/)) {
        name = substr(line, RSTART, RLENGTH)
        sub(/^[[:space:]]*function[[:space:]]+/, "", name)
        sub(/[[:space:]]*(\(\))?[[:space:]]*\{.*$/, "", name)
        return name
      }
      return ""
    }
    # A line with every single-quoted run taken out of it.
    #
    # An awk or python program written inside single quotes has its own exit, and that one ends the
    # program rather than the run. The comment below has claimed that exemption since this rule was
    # written and nothing was making it: `field()` in key-log.sh, whose awk program ends `; exit 1`,
    # was reported as a violation, and so was every call site of it. A lint that reports the honest
    # shape teaches people to ignore it, which costs more than the rule buys.
    function outside_quotes(line,   out, at, rest) {
      out = ""
      rest = line
      while ((at = index(rest, "'"'"'")) > 0) {
        out = out substr(rest, 1, at - 1)
        rest = substr(rest, at + 1)
        at = index(rest, "'"'"'")
        if (at == 0) return out
        rest = substr(rest, at + 1)
      }
      return out rest
    }
    # Whether a run of shell ends the run.
    #
    # It has to be the start of a shell statement and not any appearance of the word. The openers
    # are a statement separator, a keyword that introduces one, an opening brace, and the bracket
    # that closes a case label: `fatal) exit 2 ;;` is the commonest way a shell helper ends the run
    # and it was invisible here until 2026-09-19, because the exit follows a bracket rather than a
    # keyword.
    function ends_the_run(text,   seen) {
      seen = outside_quotes(text)
      return seen ~ /(^|;|&&|\|\||\))[[:space:]]*exit([[:space:]]|;|$)/ ||
             seen ~ /(then|else|do|\{)[[:space:]]+exit([[:space:]]|;|$)/
    }
    # Whether this line opens a heredoc, and the word that closes it.
    #
    # A heredoc body is data. `usage()` printing a fragment of shell out of one was read as a
    # function that ends the run, which made every caller of it a violation. Taking the body out is
    # the only answer that does not depend on what the text happens to say.
    function heredoc_word(line,   word) {
      if (!match(line, /<<-?[[:space:]]*['"'"'"]?[A-Za-z_][A-Za-z0-9_]*['"'"'"]?/)) return ""
      word = substr(line, RSTART, RLENGTH)
      sub(/^<<-?[[:space:]]*/, "", word)
      gsub(/['"'"'"]/, "", word)
      return word
    }
    { all[NR] = $0 }
    {
      line = $0
      # Inside a heredoc nothing is shell, including a line that closes a function or opens one.
      if (waiting != "") {
        stripped = line
        sub(/^[[:space:]]*/, "", stripped)
        if (stripped == waiting) waiting = ""
        next
      }
      stripped = line
      sub(/^[[:space:]]*/, "", stripped)
      if (substr(stripped, 1, 1) == "#") next

      name = opened(line)
      if (name != "") {
        inside = name
        rest = substr(line, RSTART + RLENGTH)
        body[inside] = body[inside] "\n" rest
        if (ends_the_run(rest)) stops[inside] = 1
        # A function written on one line closes on it.
        if (rest ~ /\}[[:space:]]*$/) inside = ""
        waiting = heredoc_word(line)
        next
      }
      if (inside != "") {
        if (line ~ /^\}/) { inside = ""; waiting = ""; next }
        body[inside] = body[inside] "\n" line
        if (ends_the_run(line)) stops[inside] = 1
      }
      waiting = heredoc_word(line)
    }
    END {
      # A function that calls one that ends the run ends the run too. Repeat until nothing new,
      # because the shape here was always one helper calling another rather than one exiting.
      do {
        again = 0
        for (f in body) {
          if (f in stops) continue
          for (g in stops) {
            if (body[f] ~ ("(^|[^A-Za-z0-9_])" g "([^A-Za-z0-9_]|$)")) { stops[f] = 1; again = 1 }
          }
        }
      } while (again)
      for (n = 1; n <= NR; n++) {
        line = all[n]
        stripped = line
        sub(/^[[:space:]]*/, "", stripped)
        if (substr(stripped, 1, 1) == "#") continue
        # A definition line is not a call site, even where it mentions the name.
        if (opened(line) != "") continue
        for (f in stops) {
          # Both spellings of a command substitution. Backticks are the older one and they are still
          # shell, and a call through them was invisible here until 2026-09-19 for no better reason
          # than that this repository does not write them.
          if (line ~ ("[$]\\([[:space:]]*" f "([[:space:]]|\\))") ||
              line ~ ("`[[:space:]]*" f "([[:space:]]|`)")) {
            print n ":" f
            break
          }
        }
      }
    }
  ' "$1"
}

lint_file() {
  local file="$1" hits=0 line
  lines_with "$PIPE_INTO_GREP_Q" "$file" || return "$UNREADABLE"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "guard lint: $file:${line%%:*} pipes into grep -q, which under pipefail reads a match as no match when the producer dies of SIGPIPE" >&2
    hits=$((hits + 1))
  done <<<"$LINES_FOUND"
  lines_with "$GREP_EXIT_AS_ANSWER" "$file" || return "$UNREADABLE"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "guard lint: $file:${line%%:*} reads grep's exit as the answer with its output thrown away, so a grep that could not run reads as no match" >&2
    hits=$((hits + 1))
  done <<<"$LINES_FOUND"
  local found
  found="$(exits_inside_a_substitution "$file")" || return "$UNREADABLE"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    echo "guard lint: $file:${line%%:*} runs ${line#*:}, which can end the run, inside a command substitution, where the exit ends the subshell and the caller reads an empty string" >&2
    hits=$((hits + 1))
  done <<<"$found"
  # A file with more hits than the sentinel would be reported as unreadable, which is the one wrong
  # answer this whole file is about. The lines are already printed; only the count is capped.
  [ "$hits" -lt "$UNREADABLE" ] || hits=$((UNREADABLE - 1))
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
  # The third rule needs a whole file rather than one line, so its seeds are files.
  wholes=(
    'stop() { echo "$1" >&2; exit 2; }
count() { local n; n="$(wc -l)"; [ -n "$n" ] || stop "nothing"; printf "%s" "$n"; }
if [ "$(count < f)" -ne 0 ]; then fail; fi'
    'reader() { grep -c x "$1" || exit 2; }
n="$(reader f)"'
    # The four shapes this rule could not see until 2026-09-19. Each is a helper that ends the run
    # and a caller that reads it inside a command substitution, which is the same fault in four
    # spellings the rule had no seed for.
    'stop() {
  case "$1" in
    fatal) exit 2 ;;
    *) return 1 ;;
  esac
}
count() { local n; n="$(wc -l < "$1")" || stop fatal; printf "%s" "$n"; }
if [ "$(count f)" -ne 0 ]; then fail; fi'
    'reader() {
  case "$1" in
    "") exit 2 ;;
  esac
  grep -c x "$1"
}
n="$(reader f)"'
    'stop() { echo "$1" >&2; exit 2; }
count() { local n; n="$(wc -l < "$1")" || stop "unreadable"; printf "%s" "$n"; }
if [ `count f` -ne 0 ]; then fail; fi'
    'function stop { echo "$1" >&2; exit 2; }
function count { local n; n="$(wc -l < "$1")" || stop "unreadable"; printf "%s" "$n"; }
if [ "$(count f)" -ne 0 ]; then fail; fi'
  )
  # Whole files that are honest and were refused as violations until 2026-09-19. A heredoc body is
  # data and a single-quoted awk program has its own exit, and reading either as shell made the
  # rule report the shape its own comment claimed to exempt.
  honest_wholes=(
    'usage() {
  cat <<"TXT"
  if [ -z "$x" ]; then exit 1; fi
TXT
  printf "usage"
}
msg="$(usage)"
echo "$msg"'
    'field() {
  awk -v k="$1" '"'"'BEGIN{FS="="} $1==k {print $2; found=1} END{ if (!found) ; exit 1 }'"'"' "$2"
}
v="$(field name f)" || echo "no field"'
  )
  failed=0
  for i in "${!seeds[@]}"; do
    printf '#!/usr/bin/env bash\n%s\n' "${seeds[$i]}" >"$work/seed-$i.sh"
    if lint_file "$work/seed-$i.sh" 2>/dev/null; then
      echo "guard lint: seed $i passed, and it is the shape this lint exists to refuse: ${seeds[$i]}" >&2
      failed=1
    fi
  done
  for i in "${!wholes[@]}"; do
    printf '#!/usr/bin/env bash\n%s\n' "${wholes[$i]}" >"$work/whole-$i.sh"
    if lint_file "$work/whole-$i.sh" 2>/dev/null; then
      echo "guard lint: whole seed $i passed, and a helper that exits inside \$( ) is the shape this lint exists to refuse" >&2
      failed=1
    fi
  done
  for i in "${!honest_wholes[@]}"; do
    printf '#!/usr/bin/env bash
%s
' "${honest_wholes[$i]}" >"$work/honest-whole-$i.sh"
    if ! lint_file "$work/honest-whole-$i.sh"; then
      echo "guard lint: honest whole $i was refused, and a heredoc body and a quoted awk program are not shell this rule is about" >&2
      failed=1
    fi
  done
  honest=(
    'matches="$(printf "%s\n" "$messages" | grep -cP "[^\x20-\x7E]")"'
    'if ! command -v gh >/dev/null 2>&1; then exit 2; fi'
    '# a comment may say: never pipe into grep -q'
    'count="$(git ls-files | grep -c .)"'
    'COUNT=0'
    'counter() { COUNT="$(git ls-files | grep -c .)"; }'
    'counter'
    'if [ "$COUNT" -ne 0 ]; then true; fi'
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

# Whether a file is a shell script, by its name or by its first line.
#
# The walk below read `$folder/*.sh` until 2026-09-19, which is 9 of 17 files in this repository's
# scripts folder and 3 of 21 in the site's, while two workflows said in terms that every script
# under `scripts/` is read. A shell script with no extension was never opened, and the shapes these
# patterns describe are shell shapes, so a file that is not shell is skipped by name rather than
# read and reported on.
is_shell() {
  local file="$1" first
  case "$file" in
    *.sh|*.bash) return 0 ;;
  esac
  first="$(head -n 1 -- "$file" 2>/dev/null)" || return 1
  case "$first" in
    '#!'*sh|'#!'*sh\ *) return 0 ;;
  esac
  return 1
}

read_count=0
skipped=0
hits=0
for folder in "$@"; do
  [ -d "$folder" ] || { echo "guard lint: $folder is not a folder" >&2; exit 2; }
  for file in "$folder"/*; do
    [ -f "$file" ] || continue
    [ "$(cd "$(dirname "$file")" && pwd)/$(basename "$file")" = "$self" ] && continue
    if ! is_shell "$file"; then
      skipped=$((skipped + 1))
      continue
    fi
    read_count=$((read_count + 1))
    lint_file "$file"
    status=$?
    if [ "$status" -eq "$UNREADABLE" ]; then
      echo "guard lint: $file could not be read, so this run checked nothing and is not a pass" >&2
      exit 2
    fi
    hits=$((hits + status))
  done
done

# A folder with no script in it is not a clean folder, it is the wrong folder.
if [ "$read_count" -eq 0 ]; then
  echo "guard lint: no shell script was read under $*, so nothing was checked" >&2
  exit 2
fi
if [ "$hits" -ne 0 ]; then
  echo "guard lint: $hits lines over $read_count shell scripts, with $skipped other files skipped" >&2
  exit 1
fi
echo "guard lint: $read_count shell scripts read and $skipped other files skipped, and none pipes into grep -q, reads grep's exit as the answer, or ends the run from inside \$( )"
