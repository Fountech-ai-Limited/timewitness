#!/usr/bin/env bash
# The guard that reads the served page is still running.
#
# `scripts/three-surfaces.sh` was split in two on 2026-09-11, because the markdown and the README
# are in a commit and the deployed page is not. The build job grades what the commit ships. The served page
# is held to `main` by `.github/workflows/surfaces.yml`, on a schedule, and that is the half this
# checks is still there.
#
# It is here because of what a scheduled workflow does when nobody is looking. GitHub disables cron
# on a repository with no activity for sixty days, and a person can disable one from the Actions tab
# in two clicks. Either way the wire half stops running and nothing says so: the build stays green,
# the board stays green, and the only guard in either repository that compares the markdown with the
# page a reader is handed is quietly absent. That is how the site comparison was lost until
# 2026-09-10, which took a week to notice, and the split would have opened the door to it again.
#
# What it asserts and what it deliberately does not. It asserts the workflow exists, is active, and
# has finished a run recently. It says nothing about whether that run passed. A red wire guard is
# already a red run on `main` and it says the surfaces disagree in its own words; failing the build
# on it as well would put the code repository's own continuous integration back to reporting a state
# it does not control and cannot fix, which is the whole of what the split was about.
#
#     scripts/wire-guard-is-alive.sh
#
# `TW_WIRE_WORKFLOW` names the workflow file and `TW_WIRE_MAX_AGE_HOURS` how stale is too stale. The
# default is twelve hours against a three-hour schedule, which is four missed firings before this
# speaks, because GitHub's cron runs late under load and a guard that cries about that teaches people
# to ignore it.

set -euo pipefail

workflow="${TW_WIRE_WORKFLOW:-surfaces.yml}"
max_age_hours="${TW_WIRE_MAX_AGE_HOURS:-12}"

if ! command -v gh >/dev/null 2>&1; then
  echo "wire guard: there is no gh here, so nothing checked that the scheduled guard is still running. That is a failure and not a skip: this is the only thing standing between a disabled workflow and a limitation list nobody is comparing with the site" >&2
  exit 1
fi

repo="${GITHUB_REPOSITORY:-}"
if [ -z "$repo" ]; then
  repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi

# The exit status rather than the output, because `gh api` prints the error body on standard output
# and a 404 would otherwise arrive here as the state of a workflow that is not there.
state=''
if answer="$(gh api "repos/$repo/actions/workflows/$workflow" --jq .state 2>/dev/null)"; then
  state="$answer"
fi
if [ -z "$state" ]; then
  echo "wire guard: $repo has no workflow called $workflow, and it is the only thing that reads the served page. Either it was removed or it was renamed without this being told" >&2
  exit 1
fi
if [ "$state" != "active" ]; then
  echo "wire guard: $workflow is \"$state\" rather than active on $repo, so the served page is being compared with nothing. Turn it back on from the Actions tab, or with: gh workflow enable $workflow" >&2
  exit 1
fi

last=''
if answer="$(gh api "repos/$repo/actions/workflows/$workflow/runs?status=completed&per_page=1" \
             --jq '.workflow_runs[0].updated_at // empty' 2>/dev/null)"; then
  last="$answer"
fi
if [ -z "$last" ]; then
  echo "wire guard: $workflow is active on $repo and has never finished a run, so nothing has yet compared the markdown with the served page. Fire it once and watch it: gh workflow run $workflow" >&2
  exit 1
fi

# Both times in seconds since the epoch, so the arithmetic is the same on this desktop and on a
# runner. BSD date would need a different flag and neither machine here has one.
last_seconds="$(date -u -d "$last" +%s)"
age_hours=$(( ( $(date -u +%s) - last_seconds ) / 3600 ))

if [ "$age_hours" -gt "$max_age_hours" ]; then
  echo "wire guard: $workflow last finished a run ${age_hours}h ago on $repo, over the ${max_age_hours}h this allows. A scheduled workflow that has stopped firing looks exactly like one that is passing" >&2
  exit 1
fi

echo "wire guard: $workflow is active on $repo and last finished a run ${age_hours}h ago, inside the ${max_age_hours}h this allows"
