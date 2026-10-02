#!/usr/bin/env python3
"""Say whether what keeps the signing identities to code an administrator landed is still in place.

The release workflow's signing secrets sit on the `release` environment. What keeps them to reviewed
code is mostly not in any workflow: it is the environment's branch policy, the rulesets on `main` and
on release tags, the branch protection on `main`, the subject GitHub writes into the token Azure
trusts, and the shape of `release.yml` itself. Every one of the settings can be changed in the
repository's settings with no commit, and nothing else would notice. So this reads each of them from
GitHub, and the workflows from the tree, and fails on any difference from what is written here.

    python scripts/the-release-route-holds.py
    python scripts/the-release-route-holds.py --tree
    python scripts/the-release-route-holds.py --self-test

`--tree` reads only the workflows in this checkout, with no network. A setting changed on purpose is
changed here in the same act, which is the point: the change then has a commit and a review.

Everything read here is public for a public repository except who may bypass a ruleset, which
GitHub shows only to an administrator. So the time each ruleset and the environment were last
changed is held as well, which anybody can read and any edit moves, a bypass list included. Run with
an administrator's token in `GH_TOKEN`, the bypass lists are compared too; without one, each is
printed as UNSEEN, and it is the time that catches a change to it.

It prints a line per clause, PASS, FAIL or UNSEEN, and exits 0 when nothing failed and 1 when
anything did. A clause that could not be read at all is a failure.
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.request

REPO = "Fountech-ai-Limited/timewitness"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The signing action and the pin this file reads it at. Moving the pin in `release.yml` without
# moving it here fails, so the action's own file is read again at every bump.
SIGNING_ACTION = "azure/artifact-signing-action"
SIGNING_ACTION_PIN = "c7ab2a863ab5f9a846ddb8265964877ef296ee82"

# The environment: runs from `main` only, and not even an administrator steps round that.
ENVIRONMENT = {
    "updated_at": "2026-09-25T10:14:13Z",
    "can_admins_bypass": False,
    "protection_rules": ["branch_policy"],
    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    "branch_policies": [("main", "branch")],
}

# Every ruleset on the repository, by name. Bypass lists are GitHub's own shape.
ADMIN = {"actor_id": 5, "actor_type": "RepositoryRole"}
RULESETS = {
    "A release tag stays where it was put": {
        "updated_at": "2026-09-25T10:15:52.526Z",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": ["refs/tags/v*-*"], "include": ["refs/tags/v*"]}},
        "rules": [{"type": "update"}, {"type": "deletion"}],
        "bypass_actors": [],
    },
    "Only an administrator makes a release tag": {
        "updated_at": "2026-09-25T10:15:24.161Z",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": ["refs/tags/v*-*"], "include": ["refs/tags/v*"]}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [dict(ADMIN, bypass_mode="always")],
    },
    "Only an administrator moves main": {
        "updated_at": "2026-09-29T11:03:22.678Z",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/main"]}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}],
        "bypass_actors": [dict(ADMIN, bypass_mode="pull_request")],
    },
}

# Branch protection on `main`, as GitHub shows it to anybody.
PROTECTION = {"enabled": True, "required_status_checks": {"enforcement_level": "everyone",
                                                         "contexts": ["build, lint and test"]}}

# The subject GitHub writes into the token the Windows signing job trades with Azure. The federated
# credential on the Entra app trusts exactly this subject followed by `:environment:release`, so a
# change here breaks signing or, worse, widens it.
OIDC_SUBJECT = {"use_default": True, "use_immutable_subject": True,
                "sub_claim_prefix": "repo:Fountech-ai-Limited@110895113/timewitness@1369238629"}

# How the release workflow may be started: by hand, and nothing else.
ON_BLOCK = """on:
  workflow_dispatch:
    inputs:
      tag:
        description: 'The release tag to build, which has to exist already'
        required: true
        type: string
      rehearsal:
        description: 'Do everything but attach, and check what would have been attached'
        required: false
        type: boolean
        default: false
"""

# The jobs that enter the `release` environment, all in `release.yml`.
RELEASE_JOBS = ["tag", "sign-macos", "sign-windows"]

# Every action `release.yml` may use, each at the pin it has been read at. Anything else in a job of
# that file, a cache or a toolchain installer among them, is a change this has not read.
RELEASE_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
    "azure/login@a641126d1b8aa4d1fa005f4f92df94a3a4c4c906",
    SIGNING_ACTION + "@" + SIGNING_ACTION_PIN,
    "./.github/workflows/binaries-check.yml",
}


# The judgements, each a pure function of what was read, so the self-test can put them to shapes.

def instant(text):
    """A time GitHub wrote, as UTC, whichever offset it was written in for the token that asked."""
    try:
        return datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(datetime.timezone.utc)
    except ValueError:
        return text


def judge_environment(environment, policies):
    problems = []
    if instant(environment.get("updated_at")) != instant(ENVIRONMENT["updated_at"]):
        problems.append("it was changed at %s, after %s" % (environment.get("updated_at"), ENVIRONMENT["updated_at"]))
    if environment.get("can_admins_bypass") is not ENVIRONMENT["can_admins_bypass"]:
        problems.append("administrators may bypass the environment's rules")
    kinds = sorted(r.get("type") for r in environment.get("protection_rules", []))
    if kinds != ENVIRONMENT["protection_rules"]:
        problems.append("its protection rules are %s, not %s" % (kinds, ENVIRONMENT["protection_rules"]))
    if environment.get("deployment_branch_policy") != ENVIRONMENT["deployment_branch_policy"]:
        problems.append("its deployment policy is %s" % environment.get("deployment_branch_policy"))
    named = sorted((p.get("name"), p.get("type")) for p in policies.get("branch_policies", []))
    if named != ENVIRONMENT["branch_policies"]:
        problems.append("it admits runs from %s, not from main alone" % named)
    return problems


def judge_ruleset(name, ruleset):
    """What differs in one ruleset, and whether its bypass list could be read at all."""
    want = RULESETS.get(name)
    if want is None:
        return ["a ruleset nobody wrote down here"], True
    problems = []
    if instant(ruleset.get("updated_at")) != instant(want["updated_at"]):
        problems.append("it was changed at %s, after %s" % (ruleset.get("updated_at"), want["updated_at"]))
    for key in ("target", "enforcement", "conditions", "rules"):
        if ruleset.get(key) != want[key]:
            problems.append("its %s reads %s, not %s" % (key, json.dumps(ruleset.get(key)), json.dumps(want[key])))
    if "bypass_actors" not in ruleset:
        return problems, False
    seen = [{k: a.get(k) for k in ("actor_id", "actor_type", "bypass_mode")} for a in ruleset["bypass_actors"]]
    if seen != want["bypass_actors"]:
        problems.append("it may be bypassed by %s, not %s" % (json.dumps(seen), json.dumps(want["bypass_actors"])))
    return problems, True


def judge_rulesets_present(names):
    return ["no ruleset called [%s]" % n for n in sorted(set(RULESETS) - set(names))]


def judge_protection(branch):
    problems = []
    protection = branch.get("protection") or {}
    if not branch.get("protected") or not protection.get("enabled"):
        return ["main is not protected"]
    checks = protection.get("required_status_checks") or {}
    want = PROTECTION["required_status_checks"]
    if checks.get("enforcement_level") != want["enforcement_level"]:
        problems.append("its required check holds %s, not everyone" % checks.get("enforcement_level"))
    if checks.get("contexts") != want["contexts"]:
        problems.append("its required checks are %s, not %s" % (checks.get("contexts"), want["contexts"]))
    return problems


def judge_subject(subject):
    return [] if subject == OIDC_SUBJECT else ["the token subject reads %s, not %s" % (json.dumps(subject), json.dumps(OIDC_SUBJECT))]


def on_block(text):
    """The workflow's `on:` block, from its line to the next line that starts a top-level key."""
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.rstrip("\n") == "on:":
            block = [line]
            for rest in lines[i + 1:]:
                if rest.strip() and not rest[0].isspace():
                    break
                block.append(rest)
            return "".join(block).rstrip("\n") + "\n"
    return None


def judge_on_block(text):
    found = on_block(text)
    if found is None:
        return ["release.yml has no on: block this can read"]
    return [] if found == ON_BLOCK else ["release.yml starts on:\n" + found]


def jobs_in_environment(text):
    """Each job of a workflow that names an environment, with the environment's name."""
    found, job = [], None
    for line in text.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            job = m.group(1)
        m = re.match(r"""^\s+['"]?environment['"]?\s*:\s*(\S.*)?$""", line)
        if m:
            found.append((job, (m.group(1) or "").strip().strip("'\"")))
    return found


def judge_environment_users(workflows):
    problems = []
    for name, text in sorted(workflows.items()):
        used = jobs_in_environment(text)
        if name == "release.yml":
            if used != [(job, "release") for job in RELEASE_JOBS]:
                problems.append("release.yml enters environments from %s, not from %s alone" % (used, RELEASE_JOBS))
        elif used:
            problems.append("%s enters an environment, from %s" % (name, used))
    return problems


def steps_using(text, action):
    """The text of every step that uses `action`, from its `- ` to the next step or job."""
    lines, found = text.splitlines(), []
    for i, line in enumerate(lines):
        if re.search(r"\buses:\s*%s@" % re.escape(action), line):
            start = i
            while start > 0 and not lines[start].lstrip().startswith("- "):
                start -= 1
            indent = len(lines[start]) - len(lines[start].lstrip())
            end = i + 1
            while end < len(lines):
                stripped = lines[end].lstrip()
                depth = len(lines[end]) - len(stripped)
                if stripped and depth <= indent:
                    break
                end += 1
            found.append("\n".join(lines[start:end]))
    return found


def judge_no_cache(release):
    problems = []
    for used in re.findall(r"""^\s*(?:-\s*)?['"]?uses['"]?\s*:\s*['"]?([^\s'"#]+)""", release, re.M):
        if used not in RELEASE_ACTIONS:
            problems.append("release.yml uses %s, which this has not read" % used)
    signing = steps_using(release, SIGNING_ACTION)
    if not signing:
        problems.append("release.yml does not use %s" % SIGNING_ACTION)
    for step in signing:
        if not re.search(r"^\s+cache-dependencies:\s*'false'\s*$", step, re.M):
            problems.append("the signing action runs with its cache on")
        if "@" + SIGNING_ACTION_PIN not in step:
            problems.append("the signing action is pinned somewhere this file has not read")
    return problems


def judge_no_client_secret(workflows):
    problems = []
    for name, text in sorted(workflows.items()):
        if re.search(r"AZURE_CLIENT_SECRET|azure-client-secret|client-secret:", text):
            problems.append("%s names an Azure client secret" % name)
    release = workflows.get("release.yml", "")
    login = steps_using(release, "azure/login")
    if not login:
        problems.append("release.yml does not sign in to Azure with azure/login")
    if not re.search(r"^  sign-windows:(?:\n(?!  \S).*)*\n\s+id-token: write", release, re.M):
        problems.append("sign-windows does not ask for the token Azure trades for a sign-in")
    return problems


def judge_action(action_text):
    """Every step of the pinned signing action that restores from the cache waits on its input."""
    problems = []
    steps = re.split(r"\n(?=    - )", action_text)
    for step in steps:
        uses = re.search(r"uses:\s*(\S+)", step)
        if not uses:
            continue
        what = uses.group(1).split("@")[0]
        if what not in ("actions/cache", "actions/cache/restore"):
            problems.append("the action uses %s, which this has not read" % what)
            continue
        if not re.search(r"if:\s*\$\{\{\s*inputs\.cache-dependencies == 'true'\s*\}\}", step):
            problems.append("the action restores from the cache whatever cache-dependencies says")
    if not re.search(r"cache-dependencies:\s*\n(?:.*\n)*?\s+default:", action_text):
        problems.append("the action has no cache-dependencies input")
    return problems


# Reading the world.

def get(url, accept="application/vnd.github+json"):
    request = urllib.request.Request(url, headers={"User-Agent": "timewitness-release-route", "Accept": accept})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def api(path):
    return json.loads(get("https://api.github.com/repos/%s/%s" % (REPO, path)))


def workflows_in_tree():
    out = {}
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
                out[name] = f.read()
    return out


def run(tree_only):
    results = []

    def say(state, line):
        results.append(state)
        print("%s: %s" % (state, line), flush=True)

    def clause(what, problems):
        if problems:
            say("FAIL", "%s: %s" % (what, "; ".join(problems)))
        else:
            say("PASS", what)

    workflows = workflows_in_tree()
    release = workflows.get("release.yml", "")
    clause("release.yml is started by hand and by nothing else", judge_on_block(release))
    clause("only release.yml's tag, sign-macos and sign-windows jobs enter an environment", judge_environment_users(workflows))
    clause("no job in release.yml restores from the Actions cache, the signing action included", judge_no_cache(release))
    clause("no workflow names an Azure client secret, and Windows signing signs in by a federated token",
           judge_no_client_secret(workflows))
    if tree_only:
        return 1 if "FAIL" in results else 0

    try:
        action = get("https://raw.githubusercontent.com/%s/%s/action.yml" % (SIGNING_ACTION, SIGNING_ACTION_PIN), "text/plain")
        clause("the pinned signing action restores from the cache only when asked to", judge_action(action))

        clause("the release environment admits runs from main alone, administrators included",
               judge_environment(api("environments/release"), api("environments/release/deployment-branch-policies")))

        listed = api("rulesets?includes_parents=false")
        clause("every ruleset written down here is on the repository", judge_rulesets_present([r["name"] for r in listed]))
        for summary in listed:
            problems, seen = judge_ruleset(summary["name"], api("rulesets/%d" % summary["id"]))
            clause("ruleset [%s] is as written here" % summary["name"], problems)
            if not seen:
                say("UNSEEN", "ruleset [%s]: who may bypass it is shown only to an administrator" % summary["name"])

        clause("main is protected, and its required build holds everyone", judge_protection(api("branches/main")))
        clause("the token Azure trusts names this repository as written here", judge_subject(api("actions/oidc/customization/sub")))
    except (OSError, urllib.error.URLError, ValueError, KeyError) as e:
        say("FAIL", "the settings could not all be read: %s" % e)
    return 1 if "FAIL" in results else 0


# The self-test's own shapes.

def self_test():
    wrong = []

    def expect(name, problems, refused):
        if bool(problems) != refused:
            wrong.append("%s: judged %s" % (name, problems or "sound"))

    environment = {"updated_at": ENVIRONMENT["updated_at"], "can_admins_bypass": False, "protection_rules": [{"type": "branch_policy"}],
                   "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
    policies = {"branch_policies": [{"name": "main", "type": "branch"}]}
    expect("the environment as it is", judge_environment(environment, policies), False)
    expect("administrators may bypass it", judge_environment(dict(environment, can_admins_bypass=True), policies), True)
    expect("a branch pattern added", judge_environment(environment, {"branch_policies": policies["branch_policies"] + [{"name": "*", "type": "branch"}]}), True)
    expect("a tag policy added", judge_environment(environment, {"branch_policies": policies["branch_policies"] + [{"name": "v*", "type": "tag"}]}), True)
    expect("every branch admitted", judge_environment(dict(environment, deployment_branch_policy=None, protection_rules=[]), {"branch_policies": []}), True)
    expect("the environment edited since", judge_environment(dict(environment, updated_at="2026-10-01T00:00:00Z"), policies), True)
    expect("a wait timer added", judge_environment(dict(environment, protection_rules=[{"type": "branch_policy"}, {"type": "wait_timer"}]), policies), True)

    for name, want in RULESETS.items():
        problems, seen = judge_ruleset(name, dict(want))
        expect("ruleset [%s] as written" % name, problems, False)
        local = instant(want["updated_at"]).astimezone(datetime.timezone(datetime.timedelta(hours=3))).isoformat()
        expect("ruleset [%s] as written, its time given in another offset" % name, judge_ruleset(name, dict(want, updated_at=local))[0], False)
        expect("ruleset [%s] edited since, its bypass list unseen" % name, judge_ruleset(name, {k: v for k, v in dict(want, updated_at="2026-10-01T00:00:00Z").items() if k != "bypass_actors"})[0], True)
        expect("ruleset [%s] disabled" % name, judge_ruleset(name, dict(want, enforcement="disabled"))[0], True)
        expect("ruleset [%s] set to evaluate only" % name, judge_ruleset(name, dict(want, enforcement="evaluate"))[0], True)
        expect("ruleset [%s] with a rule gone" % name, judge_ruleset(name, dict(want, rules=want["rules"][1:]))[0], True)
        expect("ruleset [%s] on another ref" % name, judge_ruleset(name, dict(want, conditions={"ref_name": {"exclude": [], "include": ["refs/heads/other"]}}))[0], True)
        expect("ruleset [%s] bypassed by anyone who can write" % name, judge_ruleset(name, dict(want, bypass_actors=want["bypass_actors"] + [{"actor_id": 4, "actor_type": "RepositoryRole", "bypass_mode": "always"}]))[0], True)
        hidden = {k: v for k, v in want.items() if k != "bypass_actors"}
        problems, seen = judge_ruleset(name, hidden)
        expect("ruleset [%s] with its bypass list hidden reads nothing wrong" % name, problems, False)
        if seen:
            wrong.append("ruleset [%s] with its bypass list hidden: read as seen" % name)
    main = RULESETS["Only an administrator moves main"]
    expect("the main ruleset bypassed by a push rather than a pull request",
           judge_ruleset("Only an administrator moves main", dict(main, bypass_actors=[dict(ADMIN, bypass_mode="always")]))[0], True)
    expect("a ruleset nobody wrote down", judge_ruleset("Something else", {})[0], True)
    expect("every ruleset there", judge_rulesets_present(list(RULESETS)), False)
    expect("the main ruleset gone", judge_rulesets_present([n for n in RULESETS if "main" not in n]), True)

    branch = {"protected": True, "protection": {"enabled": True, "required_status_checks": {
        "enforcement_level": "everyone", "contexts": ["build, lint and test"]}}}
    expect("main protected", judge_protection(branch), False)
    expect("main unprotected", judge_protection({"protected": False}), True)
    expect("the check held for everyone but administrators", judge_protection({"protected": True, "protection": {
        "enabled": True, "required_status_checks": {"enforcement_level": "non_admins", "contexts": ["build, lint and test"]}}}), True)
    expect("no required check", judge_protection({"protected": True, "protection": {
        "enabled": True, "required_status_checks": {"enforcement_level": "everyone", "contexts": []}}}), True)

    expect("the subject as it is", judge_subject(dict(OIDC_SUBJECT)), False)
    expect("a custom subject", judge_subject({"use_default": False, "include_claim_keys": ["repo"]}), True)
    expect("the old subject", judge_subject({"use_default": True}), True)

    with open(os.path.join(WORKFLOWS, "release.yml"), encoding="utf-8") as f:
        release = f.read()
    workflows = workflows_in_tree()
    expect("release.yml as it is, started by hand", judge_on_block(release), False)
    expect("started by a pushed tag as well", judge_on_block(release.replace("on:\n", "on:\n  push:\n    tags: ['v*']\n", 1)), True)
    expect("started on a schedule as well", judge_on_block(release.replace("on:\n", "on:\n  schedule:\n    - cron: '0 0 * * *'\n", 1)), True)
    expect("the workflows as they are", judge_environment_users(workflows), False)
    expect("another workflow entering release", judge_environment_users(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    runs-on: ubuntu-latest\n    environment: release\n"})), True)
    expect("another workflow entering it under a quoted key", judge_environment_users(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    'environment' : release\n"})), True)
    expect("another workflow entering it by name", judge_environment_users(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    environment:\n      name: release\n"})), True)
    expect("the build job entering release", judge_environment_users(dict(workflows, **{"release.yml": release.replace("    needs: tag\n    runs-on: ${{ matrix.runner }}\n", "    needs: tag\n    runs-on: ${{ matrix.runner }}\n    environment: release\n", 1)})), True)
    expect("release.yml as it is, no cache", judge_no_cache(release), False)
    expect("the signing action's cache left on", judge_no_cache(release.replace("cache-dependencies: 'false'", "cache-dependencies: 'true'")), True)
    expect("the signing action's cache left at its default", judge_no_cache(re.sub(r"\n\s+cache-dependencies: 'false'", "", release)), True)
    expect("a toolchain cache in release.yml", judge_no_cache(release.replace("      - name: Say so when it cannot be signed\n", "      - uses: Swatinem/rust-cache@v2\n      - name: Say so when it cannot be signed\n", 1)), True)
    expect("an action moved to a pin this has not read", judge_no_cache(release.replace("azure/login@a641126d", "azure/login@00000000", 1)), True)
    expect("a cache step in a signing job", judge_no_cache(release.replace("      - name: Say so when it cannot be signed\n", "      - uses: actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830\n      - name: Say so when it cannot be signed\n", 1)), True)
    expect("the signing action moved to another pin", judge_no_cache(release.replace(SIGNING_ACTION_PIN, "0" * 40)), True)
    expect("no client secret, and a federated sign-in", judge_no_client_secret(workflows), False)
    expect("a client secret named", judge_no_client_secret(dict(workflows, **{"release.yml": release + "\n# AZURE_CLIENT_SECRET\n"})), True)
    expect("no azure/login", judge_no_client_secret(dict(workflows, **{"release.yml": release.replace("azure/login@", "azure/logout@")})), True)
    expect("no id-token for sign-windows", judge_no_client_secret(dict(workflows, **{"release.yml": release.replace("      id-token: write\n    outputs:\n      signed: ${{ steps.done", "    outputs:\n      signed: ${{ steps.done", 1)})), True)

    action = """inputs:
  cache-dependencies:
    description: x
    required: false
    default: 'true'
runs:
  using: 'composite'
  steps:
    - name: Cache module
      id: cache-module
      uses: actions/cache@668228422ae6a00e4ad889ee87cd7109ec5666a7 # v5.0.4
      with:
        path: x
      if: ${{ inputs.cache-dependencies == 'true' }}

    - name: Install
      shell: 'pwsh'
      run: |
        Install-Module x
"""
    expect("an action whose cache waits on its input", judge_action(action), False)
    expect("an action that restores whatever the input says", judge_action(action.replace("      if: ${{ inputs.cache-dependencies == 'true' }}\n", "")), True)
    expect("an action that uses something new", judge_action(action + "    - uses: someone/else@1234\n"), True)
    expect("an action with no cache input", judge_action(action.replace("cache-dependencies:\n", "other:\n", 1)), True)

    for line in wrong:
        print("self-test: " + line)
    if wrong:
        print("self-test: %d judged wrongly" % len(wrong))
        return 1
    print("self-test: every shape judged as it should be; refused among them an environment widened, a ruleset "
          "disabled or bypassed by writers, main unprotected, another workflow entering release, release.yml "
          "started by a tag, the signing action's cache left on, and a client secret named")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", action="store_true", help="read only the workflows in this checkout")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    return run(args.tree)


if __name__ == "__main__":
    sys.exit(main())
