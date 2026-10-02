#!/usr/bin/env bash
# The newest release, against what its own limitation list says about order.
#
# A reader who has not built anything from source has one thing: the newest release. So the two
# surfaces that have to agree about what this product can do are the code in that release and the
# limitation list in that same release, and they can be held to each other without asking anything
# about the world, because they are two files in one tree.
#
# The rule is one sentence. **Where the released tree can put two receipts in order, the released
# tree's limitation list may not say nothing can.**
#
# ## Why this exists rather than a note to whoever cuts the release
#
# `timewitness order` went onto `main` on 2026-09-20 and the list item saying nothing compares two
# receipts stayed, deliberately. The item is about what a reader can do, no release carried the
# command, and the served copy of that list moves only when a release goes out, so changing the
# markdown at the merge would have put the scheduled wire guard red for however long the release
# took. The decision was to move the item in the same act as the release.
#
# A decision of that shape is a note somebody has to remember, and this product has been bitten
# three times in a fortnight by exactly that: a numbered citation, a tracked mail shape and a
# sentence in another file each went stale in silence because the thing that made them stale was
# somewhere else. So the decision is written as a check instead. It is green while no release carries the
# command, it goes red the moment one does with the old sentence still in it, and nobody has to
# have read this file.
#
# ## What it does not do
#
# It says nothing about `main`, on purpose. The tree ahead of a release is allowed to carry work a
# reader cannot have yet, and a check that refused that would refuse every build between two
# releases. It also says nothing about the site, which is `scripts/three-surfaces.sh`.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

list_path='docs/what-timewitness-cannot-prove.md'
readme_path='README.md'

# The sentence that stops being true when a release ships the command. It is spelled here once and
# read out of the released tree, never recomputed: a guard that works out for itself what the list
# ought to say agrees with the wrong world and stays green.
says_nothing_does='no code anywhere compares two receipts'

# What the code answering the question looks like in a tree. Two of them, because one is the
# reading and the other is the way a reader reaches it, and a release carrying either of them is a
# release that can put two receipts in order.
reading_module='crates/verify/src/order.rs'
subcommand_marker='"order",'

usage() {
  cat <<'TXT'
the order item matches the release: holds a released tree's limitation list to what that same
release can do.

  scripts/the-order-item-matches-the-release.sh [<tag>]
  scripts/the-order-item-matches-the-release.sh --self-test

With no tag it takes the newest release tag this clone can see. With --self-test it plants both
worlds and watches the rule refuse the one it exists to refuse.
TXT
}

# The newest release tag, by the date it was created rather than by its name, so a tag named out of
# sequence does not become the newest release.
newest_tag() {
  local tag
  tag="$(git tag --sort=-creatordate | head -1)"
  if [ -z "$tag" ]; then
    # A shallow clone with no tags cannot see the releases, and saying so and exiting 0 is how a
    # guard is quietly absent. So it fetches, and a fetch that cannot run is a failure.
    if ! git fetch --tags --quiet 2>/dev/null; then
      echo "the order item: there are no tags here and they could not be fetched, so nothing about the newest release can be read" >&2
      return 1
    fi
    tag="$(git tag --sort=-creatordate | head -1)"
  fi
  if [ -z "$tag" ]; then
    echo "the order item: this repository has no release tags at all" >&2
    return 1
  fi
  printf '%s\n' "$tag"
}

# Whether a tree carries the code that puts two receipts in order.
#
# Every grep below counts into a variable and reads its status by name, because grep has three
# answers and a condition reads "could not run" the same as "no match". A guard that answered no
# because it could not look would say a release is clean when nobody read it.
tree_compares_two_receipts() {
  local tag="$1" args found status
  if git cat-file -e "$tag:$reading_module" 2>/dev/null; then
    return 0
  fi
  args="$(git show "$tag:crates/cli/src/args.rs" 2>/dev/null || true)"
  if [ -z "$args" ]; then
    echo "the order item: $tag has no crates/cli/src/args.rs to read" >&2
    exit 2
  fi
  found="$(printf '%s' "$args" | grep -cF "$subcommand_marker")" && status=0 || status=$?
  if [ "$status" -gt 1 ]; then
    echo "the order item: the search of $tag for the subcommand could not run" >&2
    exit 2
  fi
  [ "$found" -gt 0 ]
}

# Whether a tree's limitation list still says nothing compares two receipts. Both surfaces are
# asked, because the README carries a precis of the same list and a release shipping one of them
# corrected and the other not is the same fault twice.
list_says_nothing_does() {
  local tag="$1" file text found status
  for file in "$list_path" "$readme_path"; do
    text="$(git show "$tag:$file" 2>/dev/null | tr '\n' ' ' | tr -s ' ' || true)"
    if [ -z "$text" ]; then
      echo "the order item: $tag has no $file to read" >&2
      exit 2
    fi
    found="$(printf '%s' "$text" | grep -cF "$says_nothing_does")" && status=0 || status=$?
    if [ "$status" -gt 1 ]; then
      echo "the order item: the search of $tag:$file could not run" >&2
      exit 2
    fi
    if [ "$found" -gt 0 ]; then
      return 0
    fi
  done
  return 1
}

# The rule itself, over two facts rather than over a tree, so that every setting of it can be
# watched. It is the only place the two are put together.
refuses() {
  local compares="$1" says="$2"
  [ "$compares" = yes ] && [ "$says" = yes ]
}

check_tag() {
  local tag="$1" compares=no says=no
  if tree_compares_two_receipts "$tag"; then compares=yes; fi
  if list_says_nothing_does "$tag"; then says=yes; fi

  if refuses "$compares" "$says"; then
    cat >&2 <<TXT
the order item: release $tag ships the code that puts two receipts in order, and its own limitation
list still says "$says_nothing_does".

A reader holding $tag can run the command and is told by the list that nothing can. Move the item in
$list_path and its precis in $readme_path, and the site copy in
../timewitness-web/content/cannot-prove.json with them, and cut the release again.
TXT
    return 1
  fi

  echo "the order item: release $tag, compares two receipts: $compares, list says nothing does: $says"
  return 0
}

self_test() {
  local failures=0

  # The rule at every setting. Four of them, and only one refuses.
  local compares says expected got
  for compares in yes no; do
    for says in yes no; do
      if [ "$compares" = yes ] && [ "$says" = yes ]; then expected=refuse; else expected=allow; fi
      if refuses "$compares" "$says"; then got=refuse; else got=allow; fi
      if [ "$got" != "$expected" ]; then
        echo "the order item: with compares=$compares and says=$says the rule $got and it should $expected" >&2
        failures=$((failures + 1))
      else
        echo "the order item: compares=$compares says=$says -> $got"
      fi
    done
  done

  # And the whole path, against real bytes rather than against two words. The working tree today is
  # the world this guard exists to refuse: the code is here and the list still says nothing
  # compares two receipts. A temporary tag makes that world a release for as long as the test runs.
  #
  # The tag goes into a scratch clone and never into this repository. Planted here, a run killed
  # before its trap left the tag behind, and a run beside it read the planted tag as the newest
  # release, which is the one thing this guard reads. Found 2026-09-21.
  local planted="tw-order-item-self-test-$$"
  local scratch
  scratch="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$scratch'" EXIT
  if ! git clone --quiet --shared --no-checkout "$root" "$scratch/repo" 2>/dev/null; then
    echo "the order item: no scratch clone could be made to plant a release in" >&2
    failures=$((failures + 1))
  else
    (
      cd "$scratch/repo" || exit 1
      git tag -f "$planted" HEAD >/dev/null 2>&1
      if check_tag "$planted" >/dev/null 2>&1; then
        if tree_compares_two_receipts "$planted" && list_says_nothing_does "$planted"; then
          echo "the order item: a planted release carrying both the command and the old sentence was allowed" >&2
          exit 1
        fi
        echo "the order item: the head carries only one of the two today, so the planted release is not the world this refuses. Read the two facts printed above rather than trusting this line"
        check_tag "$planted" || true
      else
        echo "the order item: a planted release carrying both was refused, on real bytes"
      fi
    ) || failures=$((failures + 1))
  fi
  rm -rf "$scratch"
  trap - EXIT

  if [ "$failures" -ne 0 ]; then
    echo "the order item: $failures of the self test went the wrong way" >&2
    return 1
  fi
  echo "the order item: the rule refuses what it is for and allows what it is not"
  return 0
}

case "${1:-}" in
  --help | -h)
    usage
    exit 0
    ;;
  --self-test)
    self_test
    exit $?
    ;;
  '')
    tag="$(newest_tag)"
    check_tag "$tag"
    exit $?
    ;;
  *)
    check_tag "$1"
    exit $?
    ;;
esac
