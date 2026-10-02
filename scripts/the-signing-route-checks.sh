#!/usr/bin/env bash
# The checks on the signing route, from one list that CI and the push check both run. The push
# check ran the first of them alone until this file, so a change could pass it and go red in CI on
# a clause the self-test no longer held or a workflow the route check refused.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 scripts/the-binaries-are-signed.py --self-test
python3 scripts/the-signing-self-test-notices-each-clause-removed.py
python3 scripts/the-release-route-holds.py --self-test --need-yaml
python3 scripts/the-release-route-holds.py --tree --need-yaml
