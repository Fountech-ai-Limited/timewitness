#!/usr/bin/env python3
"""Say whether what keeps the signing identities to code an administrator landed is still in place.

The release workflow's signing secrets sit on the `release` environment. What keeps them to reviewed
code is mostly not in any workflow: it is the environment's branch policy, the rulesets on `main` and
on release tags, the branch protection on `main`, the subject GitHub writes into the token Azure
trusts, and the shape of `release.yml` itself. Every one of the settings can be changed in the
repository's settings with no commit, and nothing else would notice. So this reads each of them from
GitHub, and the workflows from the tree, and fails on any difference from what is written here.

A setting changed and put back between two reads leaves nothing here changed. So, the record GitHub
keeps of the jobs that entered `release` or `linux-signing` is read as well, and fails on one made
since the policy was set by anybody not written down as starting releases, or one that got in from a
ref other than `main`. That is seen after the fact and stops nothing. A record deleted afterwards is
not seen, and nor is a job that asked for no record, as GitHub lets a workflow do.

    python scripts/the-release-route-holds.py
    python scripts/the-release-route-holds.py --tree
    python scripts/the-release-route-holds.py --self-test

`--tree` reads only the workflows in this checkout, with no network. A setting changed on purpose is
changed here in the same act, which is the point: the change then has a commit and a review.

The workflows are read twice where PyYAML is installed: by pattern, line by line, and as YAML reads
them. A job or a step written as a flow mapping, `{environment: release}` or `- {uses: x}`, is one
line the patterns do not take apart, and GitHub reads it all the same. Where PyYAML is not installed
the run says so and reads what it can by pattern, and the clauses that only a parse can answer, the
starter steps among them, fail; so a run without PyYAML never passes. `--need-yaml` fails it on the
missing PyYAML as well, and CI and the push check both pass it.

Everything read here is public for a public repository except who may bypass a ruleset, which
GitHub shows only to an administrator. So the time each ruleset and the environment were last
changed is held as well, which anybody can read and any edit moves, a bypass list included. Run with
an administrator's token in `GH_TOKEN`, the bypass lists are compared too; without one, each is
printed as UNSEEN, and it is the time that catches a change to it.

Some of what keeps the route is shown to an administrator alone, and no workflow token is one: the
Actions settings, who administers the repository, which secrets are stored where, and whether the
organisation requires two-factor sign-in. Each is read where the token can read it and printed as
UNSEEN where it cannot, so the scheduled run in `surfaces.yml` holds the rest and an administrator's
run holds these too. GitHub answers a workflow's own token with an empty list of administrators rather
than refusing it, and no repository of an organisation has none, so an empty list is read as one this
token was not shown. Nothing a GitHub token can read says how the Entra app Windows signing signs in
as is set up, or who else may sign with our certificate profile; `--azure` reads both from a file
written by an identity that can read them, its shape written beside `AZURE_LISTED` below, and
without one it is UNSEEN as well.

An app installed on the organisation is the one holder of a write here that is not a person. With
write on the repository's administration, environments, secrets, contents, workflows or Actions, it
can change what keeps the route with no commit and no owner, so the organisation's installations are
read as well, and an app holding any of those on this repository fails, as does one holding a write
on the organisation that reaches every repository whatever it is installed on. No app needs one
here, so no app is written down. GitHub lists the repositories an app is installed on only to a
personal access token, so for an app installed on a list of them that list is read with the token
`TW_INSTALLATIONS_TOKEN` names. Where it names none, or GitHub refuses it, that app is UNSEEN.

    python scripts/the-release-route-holds.py --need-admin

is the administrator's run, and under it anything GitHub did not show is a failure rather than
UNSEEN, so a token short of a scope, or one that is not an administrator's, fails rather than
passing on what it could not read. No GitHub token reads the Entra app, so without `--azure` it is
UNSEEN under this run too, but only while the release environment is read to hold nothing Windows
signing reads. Once anything it reads is stored there, the Azure identifiers it signs in with
included, or where what the environment holds could not be read, an administrator's run without
`--azure` fails on the Entra app unread. So the run made before the first signing value is stored
fails as well.

It is run with our GitHub account's token every day, and before any value the release workflow reads
is stored. `--tree` with `--need-admin` is refused, since a run that reads no setting would pass it.

A 404 is taken for a setting hidden from this token only where the Actions settings were hidden from
it as well. Where GitHub showed this token those and answers another read with a 404, the address
has moved or the thing is gone, and that is a failure. Every list is read to its last page.

    python scripts/the-release-route-holds.py --may-start LOGIN NUMBER

is what the release workflow's guard asks: whether that account is one written down here as starting
releases. An administrator can be added in the settings with no commit, and this list moves only by a
pull request to `main`.

    python scripts/the-release-route-holds.py --token-subject AUDIENCE ENVIRONMENT

is what a job that signs with a token asks before anything else: whether the token GitHub gives it
for that audience names that environment, `main` and `release.yml`, as the subject written here
does. It reads the token as a job reads one, and prints the subject it read.

It prints a line per clause, PASS, FAIL or UNSEEN, and exits 0 when nothing failed and 1 when
anything did. A clause that could not be read at all is a failure. The self-test runs every clause
of the whole check over GitHub's answers as written here, and fails if any is not run.
"""

import argparse
import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

try:
    import yaml
except ImportError:
    yaml = None

REPO = "Fountech-ai-Limited/timewitness"
# The organisation and this repository by number, which GitHub writes into the subject of every
# token a job here asks for, and which no rename or repository made again under the same name
# carries. The repository's number is written here and nowhere else in this file: a repository made
# again moves it here, and `LINUX_SUBJECT` in `scripts/the-binaries-are-signed.py`, which is held to
# what this file says, fails the check until it moves too.
ORG_NUMBER = 110895113
REPO_NUMBER = 1401363610
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The signing action and the pin this file reads it at. Moving the pin in `release.yml` without
# moving it here fails, so the action's own file is read again at every bump.
SIGNING_ACTION = "azure/artifact-signing-action"
SIGNING_ACTION_PIN = "c7ab2a863ab5f9a846ddb8265964877ef296ee82"

# The environment: runs from `main` only, and no run from another branch reaches it while the policy stands.
ENVIRONMENT = {
    "updated_at": "2026-10-02T18:55:54Z",
    "can_admins_bypass": False,
    "protection_rules": ["branch_policy"],
    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    "branch_policies": [("main", "branch")],
}

# Who entered the two signing environments, from the record GitHub keeps of the jobs that asked to.
# The policy keeps a run from another branch out, but an organisation owner can widen it, run a
# workflow from another branch, and put it back between two reads of the settings, which then read
# the same as before. Each record holds the job's ref, who made it, and its statuses, and for a public
# repository anybody can read the list. So, every record made since the policy was first set is held
# to an account written down as starting releases, and to having run only from `main`.
#
# That moment is held here on its own, and does not follow the environment's time above. Putting a
# widened policy back can move that time, and writing the new time there to clear the environment's
# line must not move this window past the run it was meant to catch. The three records from v0.4,
# made at 04:44 to 04:46 on 2026-09-25, ran before the policy was set at 10:14:13 that day, and pass
# by their date. This sees an entry after the fact and stops nothing: a run it fails on has had the
# environment already.
#
# What it cannot see. GitHub's REST API lets a deployment be deleted once it is inactive, or where it
# is the repository's only one, and an account that can write to the repository makes one inactive
# by giving it a status that is not a success, so a record deleted afterwards is not seen here. A job
# written with `deployment: false` under its environment gets the environment's secrets and makes no
# record at all, which GitHub refuses only where the environment has a custom deployment protection
# rule, and this one has none. A ref is the short name, so a run from a tag named `main` would read as
# one from the branch. No such tag can be made, since a ruleset below refuses every tag whose name does
# not start with `v` to everybody, and the tags clause reads that none stands.
#
# So this is a tripwire, and an owner of the organisation can blind it: widen the policy, run a job
# that asks for no record, and put the policy back, with nothing read here moving. A protection rule
# would not hold either, since the same owner removes it in the same act. For Windows the line is in
# Azure, whose federated credential is to trust only the token subject written below, naming `main`
# and `release.yml`. Nothing outside GitHub holds the Apple certificate, so for macOS this tripwire is
# all there is.
DEPLOYMENT_ENVIRONMENTS = ("release", "linux-signing")
DEPLOYMENTS_SINCE = "2026-09-25T10:14:13Z"
# The states a job reaches only once it is inside the environment. A record the policy refused goes
# from waiting to failure and reaches neither.
RAN = {"in_progress", "success"}

# Every ruleset on the repository, by name. Bypass lists are GitHub's own shape.
ADMIN = {"actor_id": 5, "actor_type": "RepositoryRole"}
RULESETS = {
    "A release tag stays where it was put": {
        "updated_at": "2026-10-02T18:56:02.884Z",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": ["refs/tags/v*-*"], "include": ["refs/tags/v*"]}},
        "rules": [{"type": "update"}, {"type": "deletion"}],
        "bypass_actors": [],
    },
    # A pre-release tag included: it can be moved, so that a candidate can be cut again, but only an
    # administrator makes one.
    "Only an administrator makes a release tag": {
        "updated_at": "2026-10-02T18:56:03.853Z",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/tags/v*"]}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [dict(ADMIN, bypass_mode="always")],
    },
    # Every other tag, by anybody. Git takes a bare name for a tag before a branch, so a tag called
    # `main` could answer wherever `main` is asked for by name.
    "Only a release tag can be made": {
        "updated_at": "2026-10-02T18:56:04.898Z",
        "target": "tag",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": ["refs/tags/v*"], "include": ["~ALL"]}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [],
    },
    "Only an administrator moves main": {
        "updated_at": "2026-10-02T18:58:05.395Z",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/main"]}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}],
        "bypass_actors": [dict(ADMIN, bypass_mode="pull_request")],
    },
    # Not part of the signing route: a branch whose name holds a slash cannot be made, by anybody. It
    # is written down so that it reads as ours, and so that it cannot be loosened or bypassed unseen.
    "A new branch has no slash in its name": {
        "updated_at": "2026-10-02T18:56:01.919Z",
        "target": "branch",
        "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["refs/heads/*/**/*"]}},
        "rules": [{"type": "creation"}],
        "bypass_actors": [],
    },
}

# Branch protection on `main`, as GitHub shows it to anybody.
PROTECTION = {"enabled": True, "required_status_checks": {"enforcement_level": "everyone",
                                                         "contexts": ["build, lint and test"]}}

# How GitHub writes the subject of every token a job here asks for. It names this repository and its
# owner by number as well as by name, the environment the job entered, the ref the run is from, and
# the workflow file at that ref. The federated credential on the Entra app is to trust exactly the
# subject `token_subject("release")` gives, and nothing shorter, so Azure signs in a job of
# `release.yml` run from `main` and refuses one from any other ref or workflow, whatever the release
# environment's policy reads at the time. An owner of the organisation can still change this template,
# or what lands on `main`, and this reads both after the fact. GitHub writes a colon in an
# environment's name as `%3A`, measured on 2026-10-01, so no environment can be named to spell the
# rest of the subject. A change here breaks signing or, worse, widens it.
OIDC_SUBJECT = {"use_default": False, "use_immutable_subject": True,
                "include_claim_keys": ["repo", "context", "ref", "job_workflow_ref"],
                "sub_claim_prefix": "repo:%s@%d/%s@%d" % (REPO.split("/")[0], ORG_NUMBER, REPO.split("/")[1], REPO_NUMBER)}
# The workflow by its file at `main`, not by a commit. A run of an older `main`, run again inside
# GitHub's thirty days, is given the same subject, which is one reason the signing values are read
# under names no older run reads.
RELEASE_WORKFLOW_REF = "Fountech-ai-Limited/timewitness/.github/workflows/release.yml@refs/heads/main"


def token_subject(environment):
    """The subject of the token a job of `release.yml`, run from `main`, is given in `environment`."""
    return "%s:environment:%s:ref:refs/heads/main:job_workflow_ref:%s" % (
        OIDC_SUBJECT["sub_claim_prefix"], environment, RELEASE_WORKFLOW_REF)

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
      linux_only:
        description: 'Attach the Linux binaries alone, signed, and no macOS or Windows binary'
        required: false
        type: boolean
        default: false
"""

# The jobs that enter an environment, all in `release.yml`, and the environment each enters. Three
# enter `release`, where the signing secrets are. `publish` enters `linux-signing`, which holds no
# secret: the token it signs the Linux archives with then names an environment no other job enters,
# and the signature check holds a Linux certificate to that token's subject.
ENVIRONMENT_JOBS = [("tag", "release"), ("sign-macos", "release"), ("sign-windows", "release"),
                    ("publish", "linux-signing")]
LINUX_SIGNING_JOB = "publish"
SIGNATURE_CHECK = os.path.join(ROOT, "scripts", "the-binaries-are-signed.py")

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

# Who may start a release, by login and by account number, since a login given up can be taken by
# somebody else. The guard refuses anybody else, an administrator included: an administrator can be
# added in the settings with no commit, and this moves only by a pull request an administrator
# merges. Every one of them must administer the repository as well.
RELEASE_STARTERS = {"nikkai1007": 76212305}

# Who administers the repository, as GitHub lists the collaborators with the admin role, which takes
# in the organisation's owners. Any of them may merge to `main`, and so change what a release runs.
ORG = "Fountech-ai-Limited"
ADMINISTRATORS = {"nikkai1007": 76212305, "nicolekairo": 236548393}

# What no app installed on the organisation may hold on this repository. `administration` edits the
# release environment's branch policy and the rulesets, `environments` and `secrets` what the
# environment holds, and `contents`, `workflows` and `actions` what a release runs. For macOS nothing
# outside GitHub holds the certificate, so an app that widened the environment and put it back would
# blind this check as an owner could, with no owner. And what reaches this repository whatever an app
# is installed on: `members` makes an owner, `organization_administration` sets the organisation's
# Actions policy, and `organization_secrets` shares a secret into the repository.
ROUTE_WRITES = ("actions", "administration", "contents", "environments", "secrets", "workflows")
ORGANISATION_WRITES = ("members", "organization_administration", "organization_secrets")
WRITES = ("write", "admin")
INSTALLATIONS_TOKEN = "TW_INSTALLATIONS_TOKEN"

# The repository's Actions settings. Every action a workflow names must be named by a full commit,
# and a reusable workflow from another repository, which could enter `release`, by one too; the tree
# refuses those outright.
ACTIONS_PERMISSIONS = {"enabled": True, "allowed_actions": "all", "sha_pinning_required": True}

# Every secret `release.yml` reads, and the names older runs of it read the signing values under. A
# run, or any one job of it, can be run again for 30 days with the workflow it first ran and by any
# administrator. Runs from before 2026-09-26 sign macOS with whatever they find under the old Apple
# names, held to no team and no digest, and runs from before 2026-09-30 sign Windows for whoever runs
# them again, asking nobody who may start a release. So the values are read under names no older run
# reads, and nothing may be stored under the old ones, in the environment, the repository or the
# organisation.
RELEASE_SECRETS = {
    "MACOS_CERTIFICATE_P12", "MACOS_CERTIFICATE_PASSWORD", "MACOS_TEAM_ID",
    "MACOS_NOTARY_KEY_P8", "MACOS_NOTARY_KEY_ID", "MACOS_NOTARY_ISSUER_ID",
    "WINDOWS_AZURE_TENANT_ID", "WINDOWS_AZURE_CLIENT_ID", "WINDOWS_AZURE_SUBSCRIPTION_ID",
    "WINDOWS_SIGNING_ENDPOINT", "WINDOWS_SIGNING_ACCOUNT", "WINDOWS_SIGNING_PROFILE",
}
RETIRED_SECRETS = {
    "APPLE_CERTIFICATE_P12", "APPLE_CERTIFICATE_PASSWORD", "APPLE_TEAM_ID",
    "APPLE_API_KEY_P8", "APPLE_API_KEY_ID", "APPLE_API_ISSUER_ID", "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_SUBSCRIPTION_ID",
    "AZURE_SIGNING_ENDPOINT", "AZURE_SIGNING_ACCOUNT", "AZURE_SIGNING_PROFILE",
}

# What the repository and the organisation may hold as secrets: nothing. A signing value stored there
# is read by `release.yml` where the environment lacks it, and by any workflow on any branch, so it
# never needs the environment at all; and no workflow here reads any other secret.
REPOSITORY_SECRETS = set()
ORGANISATION_SECRETS = set()
# The same holds for every environment but `release`, which any workflow on a branch its policy
# admits may enter, and for the secrets Dependabot's runs read in place of the repository's. The
# organisation's Dependabot secrets are shared across its repositories, so there only the signing
# names are refused.
OTHER_ENVIRONMENT_SECRETS = set()
DEPENDABOT_SECRETS = set()

# The Azure side of Windows signing, as the Entra app and its role should read: one federated
# credential, trusting GitHub's token for the `release` environment of this repository alone, from
# `main` and `release.yml` alone; no password and no certificate, on the app or on its service
# principal, that would sign it in without GitHub; and no role but the signer role on one certificate
# profile, which it is given only once the rest has been read sound. None of it can be read with a
# GitHub token, so it is read from a file written by an identity that can read the app, passed with
# `--azure`.
AZURE_ISSUER = "https://token.actions.githubusercontent.com"
AZURE_AUDIENCES = ["api://AzureADTokenExchange"]
AZURE_SIGNER_ROLES = {"Artifact Signing Certificate Profile Signer", "Trusted Signing Certificate Profile Signer"}
AZURE_PROFILE_SCOPE = (r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.CodeSigning/"
                       r"codeSigningAccounts/[^/]+/certificateProfiles/[^/]+$")

# Who else may sign there. Anybody holding a role that signs on our certificate profile signs as our
# Windows publisher, and the signature check cannot tell their binary from ours: a user, another
# service principal, a managed identity or a group, given the role on the profile, on the signing
# account, on its resource group, on the subscription, on a management group above it or at the root.
# So the file names the signing account, the app's service principal, the subscription it listed,
# and every role assignment it found there, active and eligible, each with its role's name and the
# data actions of every permission the role holds, and says how it listed them: the subscription with
# no filter, and the signing account and each of its profiles with `atScope()`, which Azure documents
# as at and above, every page, the reads joined. A list read with a filter on the app, or at the
# profile alone, would read the same as one with nobody else on it.
#
# A role signs where it is one of the signer roles by name, or where any of its data actions, with
# its wildcards, reaches the sign action, which is how a custom role signs. Its role not read is a
# failure. Nobody but the app may hold a role that signs anywhere reaching the signing account, and
# nobody, the app included, may be eligible for one. What this does not see: an account that may
# give roles, an Owner or a User Access Administrator among them, can give itself the signer role,
# sign, and take the role away again between two reads, and a read sees only what stands when it
# is made.
AZURE_ACCOUNT_SCOPE = (r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.CodeSigning/"
                       r"codeSigningAccounts/[^/]+$")
AZURE_SUBSCRIPTION_SCOPE = r"^/subscriptions/[^/]+$"
# The sign action as Azure's signer role carries it, read on 2026-10-02, and the same written with the
# account in it, in case a role is ever written that way.
AZURE_SIGN_ACTIONS = ("Microsoft.CodeSigning/certificateProfiles/Sign/action",
                      "Microsoft.CodeSigning/codeSigningAccounts/certificateProfiles/Sign/action")
AZURE_LISTED = ("the subscription with no filter, and the signing account and each of its profiles at and above, "
                "active and eligible, every page")
# The shape of a scope this can place: the root, a management group, or the subscription and anything
# under it, one name between each pair of slashes. Any other is taken to reach the signing account.
AZURE_SCOPE_SHAPE = r"^(?:/providers/microsoft\.management/managementgroups/[^/\s]+|/subscriptions/[^/\s]+(?:/[^/\s]+)*)?$"


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


def judge_tag_rulesets(rulesets):
    """What is written down for tags: no tag whose name does not start with `v` is made by anybody, and
    a tag whose name does, a pre-release among them, by an administrator alone. Each ruleset is then
    held to GitHub as written, so this is what keeps a tag called `main` from being made at all."""
    def making(ruleset, include, exclude, bypass):
        return (ruleset.get("target") == "tag" and ruleset.get("enforcement") == "active"
                and ruleset.get("conditions") == {"ref_name": {"exclude": exclude, "include": include}}
                and {"type": "creation"} in (ruleset.get("rules") or []) and ruleset.get("bypass_actors") == bypass)
    problems = []
    if not any(making(r, ["~ALL"], ["refs/tags/v*"], []) for r in rulesets.values()):
        problems.append("nothing written here refuses every tag outside v* to everybody, so a tag called main can be made")
    if not any(making(r, ["refs/tags/v*"], [], [dict(ADMIN, bypass_mode="always")]) for r in rulesets.values()):
        problems.append("nothing written here keeps every tag starting v, a pre-release among them, to an administrator")
    return problems


# A release tag's name, as the guard reads the tag it is asked for.
RELEASE_TAG = r"^refs/tags/v[0-9]+(\.[0-9]+){0,2}(-[0-9A-Za-z.-]+)?$"


def judge_tags(listed):
    """Every tag that stands is named as a release tag: none was made before the ruleset that refuses
    the rest, or while it was off."""
    if not isinstance(listed, list):
        return ["GitHub's answer for the repository's tags is no list of them"]
    return ["%s stands, and is not named as a release tag" % (t.get("ref") if isinstance(t, dict) else t)
            for t in listed if not (isinstance(t, dict) and re.match(RELEASE_TAG, str(t.get("ref"))))]


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


def parsed(text):
    """The workflow as YAML reads it, None where PyYAML is not installed here, and the parser's
    complaint where it cannot be read."""
    if yaml is None:
        return None
    if text not in PARSED:
        try:
            doc = yaml.safe_load(text)
            PARSED[text] = doc if isinstance(doc, dict) else "it is not a mapping"
        except yaml.YAMLError as e:
            PARSED[text] = "it is not YAML this can read: %s" % str(e).splitlines()[0]
    return PARSED[text]


# Each text parsed once, since every clause reads release.yml and the self-test reads it hundreds of
# times. Nothing that reads a parse changes it.
PARSED = {}


def parsed_jobs(doc):
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return [(name, job) for name, job in jobs.items() if isinstance(job, dict)] if isinstance(jobs, dict) else []


def jobs_in_environment_parsed(doc):
    """Each job that names an environment, as YAML reads the file."""
    found = []
    for name, job in parsed_jobs(doc):
        if "environment" not in job:
            continue
        environment = job["environment"]
        if isinstance(environment, dict):
            environment = environment.get("name")
        found.append((str(name), "" if environment is None else str(environment)))
    return found


def uses_parsed(doc):
    """Every action and reusable workflow a file uses, at job level and in steps, as YAML reads it."""
    found = []
    for _, job in parsed_jobs(doc):
        if "uses" in job:
            found.append(str(job["uses"]))
        for step in job.get("steps") or []:
            if isinstance(step, dict) and "uses" in step:
                found.append(str(step["uses"]))
    return found


def judge_environment_users(workflows):
    problems = []
    for name, text in sorted(workflows.items()):
        reads = [jobs_in_environment(text)]
        doc = parsed(text)
        if isinstance(doc, str):
            problems.append("%s: %s" % (name, doc))
        elif doc is not None:
            reads.append(jobs_in_environment_parsed(doc))
        for used in reads:
            if name == "release.yml":
                if used != ENVIRONMENT_JOBS:
                    problems.append("release.yml enters environments from %s, not from %s alone" % (used, ENVIRONMENT_JOBS))
            elif used:
                problems.append("%s enters an environment, from %s" % (name, used))
    return sorted(set(problems), key=problems.index)


def judge_linux_subject(check_text):
    """The subject the signature check holds a Linux certificate to is the one GitHub gives the job
    that signs the Linux archives, in its own environment, from `main` and `release.yml`."""
    found = re.findall(r'^LINUX_SUBJECT = "([^"]*)"$', check_text, re.M)
    want = token_subject(dict(ENVIRONMENT_JOBS)[LINUX_SIGNING_JOB])
    if found != [want]:
        return ["the signature check holds a Linux certificate to %s, not to %s" % (found or "no subject", want)]
    return []


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
    used = re.findall(r"""^\s*(?:-\s*)?['"]?uses['"]?\s*:\s*['"]?([^\s'"#]+)""", release, re.M)
    doc = parsed(release)
    if isinstance(doc, str):
        problems.append("release.yml: %s" % doc)
    elif doc is not None:
        used += uses_parsed(doc)
        for step in [s for _, job in parsed_jobs(doc) for s in job.get("steps") or [] if isinstance(s, dict)]:
            if str(step.get("uses", "")).startswith(SIGNING_ACTION + "@"):
                if str((step.get("with") or {}).get("cache-dependencies")) != "false":
                    problems.append("the signing action runs with its cache on")
    for used in sorted(set(used), key=used.index):
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


def judge_reusable(workflows):
    """No job in any workflow calls a reusable workflow from another repository. Such a job enters
    whatever environment that file names, `release` among them, and nothing in this tree would say so."""
    problems = []
    for name, text in sorted(workflows.items()):
        calls, job = [], None
        for line in text.splitlines():
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
            m = re.match(r"""^    ['"]?uses['"]?\s*:\s*['"]?([^\s'"#]+)""", line)
            if m and job:
                calls.append((job, m.group(1)))
        doc = parsed(text)
        if isinstance(doc, dict):
            calls += [(str(job_name), str(job["uses"])) for job_name, job in parsed_jobs(doc) if "uses" in job]
        for job_name, called in calls:
            if not called.startswith("./"):
                problems.append("%s: job %s calls %s, a workflow another repository holds" % (name, job_name, called))
    return sorted(set(problems), key=problems.index)


def judge_starter(login, number):
    """Whether the account `login`, number `number`, may start a release."""
    for name, known in RELEASE_STARTERS.items():
        if name.lower() == str(login).lower():
            if str(number) != str(known):
                return ["%s is account %s, and the %s written down here is account %s" % (login, number, name, known)]
            return []
    return ["%s is not one of the accounts written down as starting releases, %s" % (login, ", ".join(sorted(RELEASE_STARTERS)))]


# How the guard asks whether the tag's commit is on main, exactly. Main is read as the commit the
# branch is on and never by its name, since git takes a bare name for a tag before a branch, and a
# tag called `main` on unreviewed code could otherwise answer for it. Only `ahead` and `identical`
# mean the tag's commit is one main already holds.
GUARD_ON_MAIN = """          commit="$(gh api "repos/$REPO/commits/refs/tags/$TAG" --jq .sha 2>/dev/null)" || refuse "there is no tag called $TAG"
          [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || refuse "$TAG reads as $commit, which is not a commit"
          # Main by the commit the branch is on, and never by its name: git takes a bare name for a
          # tag before a branch, so a tag called `main` on unreviewed code could answer for it.
          main_commit="$(gh api "repos/$REPO/git/ref/heads/main" --jq .object.sha)" || refuse "could not read the commit main is on"
          [[ "$main_commit" =~ ^[0-9a-f]{40}$ ]] || refuse "main reads as $main_commit, which is not a commit"
          on_main="$(gh api "repos/$REPO/compare/$commit...$main_commit" --jq .status)" || refuse "could not compare $TAG with main"
          case "$on_main" in
            ahead|identical) ;;
            *) refuse "$TAG is on ${commit:0:12}, which is not on main, so it was never reviewed" ;;
          esac
"""


# What the guard is given and how it refuses, exactly. The compare above is only as good as the
# repository it asks about and the refusal it ends in: `REPO` pointed at another repository asks
# about somebody else's commits, and a `refuse` that returns rather than exits prints its sentence
# and lets the run carry on. `ACTOR` is who ran it this time, not who first started the run: a
# second administrator running a run again is `triggering_actor`, and would be checked as the first
# under `actor`.
GUARD_HEAD = """      - id: guard
        env:
          GH_TOKEN: ${{ github.token }}
          EVENT: ${{ github.event_name }}
          REF: ${{ github.ref }}
          ACTOR: ${{ github.triggering_actor }}
          TAG: ${{ inputs.tag }}
          REHEARSAL: ${{ inputs.rehearsal }}
          LINUX_ONLY: ${{ inputs.linux_only }}
          REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          refuse() {
            echo "::error::$1"
            echo "### Refused: $1" >> "$GITHUB_STEP_SUMMARY"
            exit 1
          }
"""


def judge_guard(release):
    """The guard asks this file who may start a release, from main, and refuses anybody else; and
    everybody written down as starting releases administers the repository as well."""
    problems = []
    guard = release.split("\n  tag:\n", 1)[0]
    if guard.count(GUARD_HEAD) != 1:
        problems.append("the guard's environment and its refusal are not as written here")
    if "            scripts/the-release-route-holds.py\n" not in guard:
        problems.append("the guard does not check out scripts/the-release-route-holds.py from main")
    if not re.search(r'actor_id="\$\(gh api "users/\$ACTOR" --jq \.id\)"', guard):
        problems.append("the guard does not read the number of the account that started the run")
    if not re.search(r'python3 scripts/the-release-route-holds\.py --may-start "\$ACTOR" "\$actor_id" \\\n\s+\|\| refuse ', guard):
        problems.append("the guard does not refuse an account this file does not name as starting releases")
    if not re.search(r'\[ "\$role" = admin \] \|\| refuse ', guard):
        problems.append("the guard does not refuse an account that does not administer the repository")
    # Whether the tag's commit is on main, to the byte, and nothing in the guard setting again what it
    # reads, so no line before or after it can change the answer.
    if guard.count(GUARD_ON_MAIN) != 1:
        problems.append("the guard does not ask, as written here, whether the tag's commit is on the commit main is on")
    assigned = re.findall(r"^[ \t]*(?:(?:export|declare|local|readonly)[ \t]+)?(commit|main_commit|on_main)\+?=", guard, re.M)
    if sorted(assigned) != ["commit", "main_commit", "on_main"]:
        problems.append("the guard sets %s, where it sets commit, main_commit and on_main once each" % sorted(assigned))
    if re.search(r"(?:^|[;&|({]|\bdo|\bthen|\belse)[ \t]*(?:read|mapfile|readarray)\b[^\n]*\b(?:commit|main_commit|on_main)\b",
                 "\n".join(line for line in guard.splitlines() if not line.lstrip().startswith("#")), re.M):
        problems.append("the guard reads into commit, main_commit or on_main as well as setting them")
    for name, number in RELEASE_STARTERS.items():
        if ADMINISTRATORS.get(name) != number:
            problems.append("%s starts releases and is not written down as administering the repository" % name)
    return problems


# The guard job, held whole. Holding the compare and the refusal to the byte holds nothing around
# them. A line added to the guard step, a variable given to the whole job, or a step before the guard
# that writes to GITHUB_ENV or GITHUB_PATH can each stand a `gh` of its own in front of the compare,
# by BASH_ENV, PATH, eval, source, hash or a trap, and a tag that is not on main would then build and
# sign. A list of such shapes is never finished, so the job is held as the Attach step is: its own
# keys and what each says, exactly two steps, the pinned checkout of main's checks and the guard, and
# each step by the digest of the step as YAML reads it. Any change to the job at all is a change made
# here in the same commit and read in that review. The checks above still say what the guard has to
# do, so a digest moved here for a change that drops any of it fails as well.
GUARD_JOB = {"name": "may this run build and sign", "runs-on": "ubuntu-latest",
             "outputs": {name: "${{ steps.guard.outputs.%s }}" % name
                         for name in ("tag", "commit", "prerelease", "rehearsal", "apple_team", "linux_only")}}
GUARD_STEPS_SHA256 = ("e72dd30a1ced455d046c6c6a7642d84ed33ff7d39ccd4ee1b5c872c46f429c56",
                      "514dd75b7748ce0a38626df1a28286be4e2b4851f8a265092689411c66012022")


def digest_of(step):
    """A step's digest, over the step as YAML reads it."""
    return hashlib.sha256(json.dumps(step, sort_keys=True).encode("utf-8")).hexdigest()


def guard_job(release):
    """The guard job as YAML reads it, or why it cannot be read."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return "PyYAML is not installed here" if doc is None else "release.yml: %s" % doc
    job = dict(parsed_jobs(doc)).get("guard")
    return job if isinstance(job, dict) else "release.yml has no guard job it can run"


def judge_guard_held(release):
    """Nothing is in the guard job but what is written here, so no line anywhere in it, before the
    compare or after it, can change what the compare's answer comes from."""
    job = guard_job(release)
    if isinstance(job, str):
        return [job]
    problems = []
    own = {key: value for key, value in job.items() if key != "steps"}
    if own != GUARD_JOB:
        problems.append("the guard job says %s of itself, not %s as written here"
                        % (json.dumps(own, sort_keys=True), json.dumps(GUARD_JOB, sort_keys=True)))
    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != len(GUARD_STEPS_SHA256):
        problems.append("the guard job has %s steps, where it has two, the checkout and the guard"
                        % (len(steps) if isinstance(steps, list) else "no list of"))
    else:
        for which, step, held in zip(("checkout", "guard"), steps, GUARD_STEPS_SHA256):
            digest = digest_of(step)
            if digest != held:
                problems.append("the guard job's %s step reads %s, not %s as written here" % (which, digest, held))
    return problems


# The two steps every job that enters an environment starts with, exactly: nothing that lets the
# second be skipped or its failure ignored, `if:` and `continue-on-error:` among them, and nothing
# that changes whom it asks about.
STARTER_STEPS = [
    {"uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
     "with": {"persist-credentials": False, "ref": "main", "path": "starter",
              "sparse-checkout": "scripts/the-release-route-holds.py\n", "sparse-checkout-cone-mode": False}},
    {"name": "Started by an account written down as starting releases", "shell": "bash",
     "env": {"GH_TOKEN": "${{ github.token }}", "ACTOR": "${{ github.triggering_actor }}"},
     "run": "set -euo pipefail\npy=python3\n\"$py\" -c 'import sys' >/dev/null 2>&1 || py=python\n"
            "actor_id=\"$(gh api \"users/$ACTOR\" --jq .id)\" || { echo \"::error::could not read who $ACTOR is\"; exit 1; }\n"
            "\"$py\" starter/scripts/the-release-route-holds.py --may-start \"$ACTOR\" \"$actor_id\"\n"},
]

# The step each job that signs with a token takes straight after the starter steps, exactly. It asks
# GitHub for the token the job signs with, for the audience it signs for, and holds the token's
# subject to the one written here. So every run, a rehearsal included, shows the subject before Azure
# or Sigstore is asked for anything, and a subject template changed in the settings stops the job
# rather than signing with whatever GitHub now writes.
TOKEN_AUDIENCES = {"sign-windows": "api://AzureADTokenExchange", "publish": "sigstore"}


def token_step(job):
    """The step `job` holds the subject of its token with."""
    return {"name": "The token this job signs with names main and release.yml", "shell": "bash",
            "run": "set -euo pipefail\npy=python3\n\"$py\" -c 'import sys' >/dev/null 2>&1 || py=python\n"
                   "\"$py\" starter/scripts/the-release-route-holds.py --token-subject %s %s\n"
                   % (TOKEN_AUDIENCES[job], dict(ENVIRONMENT_JOBS)[job])}


# What else a job that enters an environment may say about itself, and nothing more. A container or
# a service, a shell set for the whole job, an environment variable set for every step, BASH_ENV or
# PYTHONPATH among them, or another runner would each run the starter steps with a tool or a setting
# the job chose. And a step that runs whatever came before it, by any of GitHub's four status
# functions, or one whose failure is ignored, would carry on past a starter step that refused.
ENVIRONMENT_JOB_KEYS = {"name", "needs", "runs-on", "environment", "outputs", "env", "permissions", "steps"}
ENVIRONMENT_JOB_RUNNERS = {"tag": "ubuntu-latest", "sign-macos": "macos-15", "sign-windows": "windows-2022",
                           "publish": "ubuntu-latest"}
ENVIRONMENT_JOB_ENV = {"tag": set(), "sign-macos": {"TARGETS", "WANT_x86_64_apple_darwin", "WANT_aarch64_apple_darwin"},
                       "sign-windows": set(), "publish": set()}
# The same of the workflow as a whole, whose keys and environment every job takes in.
WORKFLOW_KEYS = {"name", "on", "permissions", "concurrency", "env", "jobs"}
WORKFLOW_ENV = {"CARGO_TERM_COLOR", "FOLDER_DIGEST"}
STATUS_FUNCTIONS = re.compile(r"\b(?:success|always|failure|cancelled)\s*\(", re.I)

# The Attach step, as YAML reads it, by its digest. What it does when a run stops partway is read
# below clause by clause, but a clause reads for text and the step is a program, so any change to it
# at all is also a change to this digest, made here in the same commit and read in that review.
ATTACH_SHA256 = "ccc415b5cda9e9710b2244d36ba235ad2f3d0dac872158c62d1ccc9600054703"


def judge_starter_steps(release):
    """Every job that enters an environment asks, before anything else, whether the account that
    started this run of it may start a release. A job run again on its own reuses the guard's answer
    and never asks the guard again."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return ["PyYAML is not installed here" if doc is None else "release.yml: %s" % doc]
    problems = []
    jobs = dict(parsed_jobs(doc))
    for name, _ in ENVIRONMENT_JOBS:
        job = jobs.get(name) or {}
        if (job.get("steps") or [])[:2] != STARTER_STEPS or "continue-on-error" in job:
            problems.append("%s does not ask first, and without a way round, whether the account that started it may "
                            "start a release" % name)
    return problems


def asks_for_a_token(permissions):
    """Whether a job or a workflow given `permissions` may ask GitHub for a token."""
    if isinstance(permissions, dict):
        return permissions.get("id-token") == "write"
    return permissions is not None and permissions != "read-all"


def judge_token_steps(release):
    """Each job that signs with a token holds its subject before any other step after the starter
    steps, for the audience it signs for and the environment it is in; and no other job may ask for a
    token at all, since Azure would sign in any job of `release.yml` at `main` that enters `release`."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return ["PyYAML is not installed here" if doc is None else "release.yml: %s" % doc]
    jobs = dict(parsed_jobs(doc))
    problems = ["%s does not hold the subject of its token for %s first, after its starter steps" % (name, audience)
                for name, audience in TOKEN_AUDIENCES.items()
                if ((jobs.get(name) or {}).get("steps") or [])[2:3] != [token_step(name)]]
    if asks_for_a_token(doc.get("permissions")):
        problems.append("release.yml lets every job ask GitHub for a token")
    problems += ["%s may ask GitHub for a token, and only %s may" % (name, " and ".join(TOKEN_AUDIENCES))
                 for name, job in jobs.items() if name not in TOKEN_AUDIENCES and asks_for_a_token(job.get("permissions"))]
    return problems


def token_claims(audience, opener=None):
    """The claims of the token GitHub gives this job for `audience`, asked for as a job asks for one.
    The token is read here and never printed."""
    url, bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"), os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not bearer:
        raise ValueError("this job may not ask GitHub for a token")
    request = urllib.request.Request("%s&audience=%s" % (url, urllib.parse.quote(audience, safe="")),
                                     headers={"Authorization": "Bearer " + bearer})
    with (opener or urllib.request.urlopen)(request, timeout=60) as answer:
        token = json.load(answer)["value"]
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def judge_token(claims, environment):
    """The token a job of `release.yml` was given in `environment` names that environment, `main`
    and `release.yml` at `main`, and this repository by number."""
    subject = claims.get("sub") if isinstance(claims, dict) else None
    want = token_subject(environment)
    return [] if subject == want else ["the token this job was given names %s, not %s" % (subject, want)]


def names_of(mapping):
    """The keys of a mapping as text, with the one YAML reads as true written as `on`, or None where
    it is not a mapping at all."""
    if not isinstance(mapping, dict):
        return None
    return {"on" if key is True else str(key) for key in mapping}


def judge_nothing_past_the_starter(release):
    """No job that enters an environment can run on past a starter step that refused, or run that
    step with a tool or a setting of its own, and nor can the workflow for all of them."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return ["PyYAML is not installed here" if doc is None else "release.yml: %s" % doc]
    problems = []
    extra = names_of(doc) - WORKFLOW_KEYS
    if extra:
        problems.append("release.yml sets %s for every job" % sorted(extra))
    names = names_of(doc.get("env") or {})
    if names is None or names - WORKFLOW_ENV:
        problems.append("release.yml gives every job the environment %s" % (sorted(names - WORKFLOW_ENV) if names else doc.get("env")))
    jobs = dict(parsed_jobs(doc))
    for name, _ in ENVIRONMENT_JOBS:
        job = jobs.get(name)
        if not isinstance(job, dict):
            problems.append("%s is not a job release.yml can run: %s" % (name, json.dumps(job)))
            continue
        extra = names_of(job) - ENVIRONMENT_JOB_KEYS
        if extra:
            problems.append("%s sets %s for the whole job" % (name, sorted(extra)))
        if job.get("runs-on") != ENVIRONMENT_JOB_RUNNERS[name]:
            problems.append("%s runs on %s, not %s" % (name, json.dumps(job.get("runs-on")), ENVIRONMENT_JOB_RUNNERS[name]))
        names = names_of(job.get("env") or {})
        if names is None or names - ENVIRONMENT_JOB_ENV[name]:
            problems.append("%s gives each of its steps the environment %s" % (name, sorted(names - ENVIRONMENT_JOB_ENV[name]) if names else job.get("env")))
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                problems.append("%s has a step that is not a mapping: %s" % (name, json.dumps(step)))
                continue
            said = step.get("name") or step.get("uses") or step.get("id")
            if "continue-on-error" in step:
                problems.append("%s: the step [%s] carries on whatever it meets" % (name, said))
            if STATUS_FUNCTIONS.search(str(step.get("if", ""))):
                problems.append("%s: the step [%s] runs when an earlier one failed, by [%s]" % (name, said, step.get("if")))
    return problems


def environment_job_actions(release):
    """Every action a job that enters an environment uses, as `owner/name@pin`, or why they cannot be
    read."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return "PyYAML is not installed here" if doc is None else "release.yml: %s" % doc
    jobs = dict(parsed_jobs(doc))
    used = set()
    for name, _ in ENVIRONMENT_JOBS:
        job = jobs.get(name) if isinstance(jobs.get(name), dict) else {}
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str) and not step["uses"].startswith("./"):
                used.add(step["uses"])
    return sorted(used)


# What in an action's `runs:` starts something when the job starts, before every step of the job and
# so before the starter steps: a JavaScript action's `pre`, a container action's `pre-entrypoint`, and
# `pre-if`, which says when either runs and is `always()` where it says nothing. GitHub's runner reads
# each key as written here, in this case alone.
PRE_KEYS = ("pre", "pre-if", "pre-entrypoint")

# A composite action starts the pre steps of every action its own steps use, when the job starts, as
# its own. So, each of those is read and held to the same, and so are the ones they use, this many
# actions deep and no further: one deeper is not read, and fails rather than passing unread.
NESTED_DEPTH = 3

# An action named by its owner, its repository, any folder in it, and a full commit.
PINNED_ACTION = re.compile(r"^(?!.*(?:^|/)\.\.?(?:/|@))[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}\Z")

# Everything else an action's `runs:` may hold, the ways of running it may name, and what a composite
# action's step may hold. An action's file is read here as GitHub serves it, and the runner reads it
# from the repository's archive, which `.gitattributes` can make read otherwise; so a key or a way of
# running this does not know is refused rather than taken for nothing.
RUNS_KEYS = {"using", "main", "pre", "pre-if", "post", "post-if", "image", "args", "entrypoint", "env", "pre-entrypoint",
             "post-entrypoint", "steps"}
RUNS_USING = {"node12", "node16", "node20", "node24", "docker", "composite"}
STEP_KEYS = {"id", "if", "name", "uses", "run", "shell", "with", "env", "working-directory", "continue-on-error"}


def actions_inside(runs):
    """The actions a composite action's steps use, as written, none for any other action, or None
    where its steps are not a list of steps."""
    if not isinstance(runs, dict) or str(runs.get("using")).lower() != "composite":
        return []
    steps = runs.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) and set(s) <= STEP_KEYS for s in steps):
        return None
    return [str(s["uses"]) for s in steps if "uses" in s]


def judge_no_pre_step(runs_of, used=None):
    """No action a job in an environment uses starts anything of its own when the job starts, and nor
    does any action a composite one among them uses, as deep as NESTED_DEPTH. `runs_of` maps each
    action read to its `runs:` as YAML reads it, and `used` names the ones the jobs use, every one
    in `runs_of` where it is not given."""
    problems = []

    def judge(uses, depth, inside):
        said = " inside ".join([uses] + inside[::-1])
        if uses not in runs_of:
            problems.append("%s was not read, so whether it starts anything when the job starts is not known" % said)
        elif not isinstance(runs_of[uses], dict):
            problems.append("%s says nothing this can read about how it runs" % said)
        else:
            runs = runs_of[uses]
            using = str(runs.get("using")).lower()
            if using not in RUNS_USING:
                problems.append("%s runs by [%s], which this does not know" % (said, runs.get("using")))
            unknown = sorted(str(key) for key in runs if key not in RUNS_KEYS)
            if unknown:
                problems.append("%s says %s of how it runs, which this does not know" % (said, unknown))
            # The runner builds a container action's image from its Dockerfile while it sets the job
            # up, before the first step, and an image named `docker://` it only pulls.
            if using == "docker" and not str(runs.get("image")).startswith("docker://"):
                problems.append("%s is built from its Dockerfile when the job starts, before the starter steps" % said)
            early = [key for key in PRE_KEYS if key in runs]
            if early:
                problems.append("%s runs [%s] when the job starts, before the starter steps" % (
                    said, ", ".join("%s: %s" % (key, runs[key]) for key in early)))
            nested = actions_inside(runs)
            if nested is None:
                problems.append("%s is a composite action whose steps this cannot read" % said)
            for each in nested or []:
                if not PINNED_ACTION.match(each):
                    problems.append("%s uses %s, which is not an action named by a full commit" % (said, each))
                elif depth >= NESTED_DEPTH:
                    problems.append("%s uses %s, more than %d actions deep, which is not read" % (said, each, NESTED_DEPTH))
                else:
                    judge(each, depth + 1, inside + [uses])

    for uses in sorted(runs_of if used is None else used):
        judge(uses, 1, [])
    return sorted(set(problems), key=problems.index)


def attach_step(release):
    """The Attach step as YAML reads it, or why it cannot be read."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return "PyYAML is not installed here" if doc is None else "release.yml: %s" % doc
    steps = [s for s in (dict(parsed_jobs(doc)).get("publish") or {}).get("steps") or [] if isinstance(s, dict)]
    attach = [s for s in steps if s.get("name") == "Attach"]
    if len(attach) != 1:
        return "release.yml's publish job has %d steps called Attach, where one belongs" % len(attach)
    return attach[0]


def judge_attach_pinned(release):
    step = attach_step(release)
    if isinstance(step, str):
        return [step]
    digest = digest_of(step)
    return [] if digest == ATTACH_SHA256 else ["the Attach step reads %s, not %s as written here" % (digest, ATTACH_SHA256)]


def judge_attach(release):
    """A release this workflow makes is a draft until it carries every file, and nothing is attached
    to a tag that no longer names the commit the run built."""
    step = attach_step(release)
    if isinstance(step, str):
        return [step]
    text, commit = str(step.get("run", "")), str((step.get("env") or {}).get("COMMIT"))
    problems = []
    if commit != "${{ needs.tag.outputs.commit }}":
        problems.append("the Attach step is not given the commit the guard read")
    if not re.search(r'now="\$\(gh api "repos/\$REPO/commits/refs/tags/\$TAG" --jq \.sha\)"', text) \
            or '[ "$now" != "$COMMIT" ]' not in text:
        problems.append("the Attach step does not read again which commit the tag names")
    # Read in the order the step runs them: made as a draft, given every file by its number, held to
    # carrying all of them, the tag read again, and only then published, by that number.
    order = [r'made="\$\(gh api -X POST "repos/\$REPO/releases" -f tag_name="\$TAG" -f target_commitish="\$COMMIT"',
             r'-F draft=true ', r'\n\s+upload_to "\$made"\n',
             r'if \[ "\$\(cat carried\.txt\)" != "\$\(ls dist \| sort \| xargs\)" \]', r"\n\s+names_what_was_built\n\s+gh api -X PATCH ",
             r'gh api -X PATCH "repos/\$REPO/releases/\$made" -F draft=false']
    at = [m.start() if m else -1 for m in (re.search(piece, text) for piece in order)]
    if -1 in at or at != sorted(at) or "gh release create" in text or text.count("-X POST") != 2:
        problems.append("a release is not made as a draft, given every file, the tag read again, and only then published")
    if "gh release upload" in text or 'gh api -X POST "https://uploads.github.com/repos/$REPO/releases/$1/assets?name=' not in text:
        problems.append("files are attached by the tag, which another release on it could answer to, and not by number")
    if not re.search(r'\n\s+upload_to "\$number"\n\s+names_what_was_built\n', text):
        problems.append("files attached to a release that was public already are not held to the tag read again")
    # Only GitHub's own "release not found" is taken for there being none; anything else stops.
    if "2> release.err" not in text or not re.search(r'elif \[ "\$\(cat release\.err\)" = "release not found" \]', text):
        problems.append("a failure to read the release could be taken for there being none")
    # What a failure undoes: a draft the step made, by its number and only while it is a draft; on
    # a public release, the files the step uploaded and no other, and nothing before the upload.
    undo = text[text.find("undo() {"):text.find("trap undo EXIT")]
    if "trap undo EXIT" not in text or not all(piece in undo for piece in (
            'state="$(gh api "repos/$REPO/releases/$made" --jq .draft)" || state=unread\n', 'if [ "$state" = true ]; then\n',
            'gh api -X DELETE "repos/$REPO/releases/$made"', '[ "$attaching" = true ] || return',
            'gh api "repos/$REPO/releases/$number" --jq', 'grep -qx "$id" before.txt',
            'gh api -X DELETE "repos/$REPO/releases/assets/$id"')) \
            or "gh release delete" in undo or not re.search(r"\n\s+attaching=true\n", text):
        problems.append("a run that stops partway does not take off exactly what it attached, and only that")
    # A file taken off a public release is one this run's upload answered with, or one whose answer
    # was lost that this workflow's own account put there; never one somebody else put there under
    # one of the same names.
    if not re.search(r'answer="\$\(gh api -X POST "https://uploads[^\n]*\n[^\n]* --jq \.id 2> upload\.err\)"', text) \
            or 'echo "$answer" >> uploaded.txt' not in text or not re.search(
            r'gh api -X DELETE "repos/\$REPO/releases/assets/\$id"[^\n]*\n\s+done < uploaded\.txt', undo):
        problems.append("a run that stops partway does not take off its files by the numbers their uploads answered with")
    if 'basename "$f" >> tried.txt\n' not in text \
            or not re.search(r'\[ -s lost\.txt \] \|\| return\n(?:\s+#.*\n)*(?:\s+: > \w+\.txt\n)+\s+for try in 1 2 3; do\n', undo) \
            or not re.search(r'\n\s+\[ -z "\$\(grep -vxF -f found\.txt lost\.txt\)" \] && break\n\s+\[ "\$try" = 3 \] \|\| sleep 5\n', undo):
        problems.append("a run that stops partway reads the release once for a file whose upload got no answer, "
                        "which GitHub can take seconds to list")
    # gh prints GitHub's own error where the number asked for would be, so an upload's or a draft's
    # answer counts only when it is a number, and only a number is ever deleted.
    if 'a_number() { [[ "$1" =~ ^[0-9]+$ ]]; }' not in text \
            or not re.search(r'\n\s+if a_number "\$answer"; then\n\s+echo "\$answer" >> uploaded\.txt\n', text) \
            or not re.search(r'\n\s+no_number "the upload of [^\n]*\n\s+exit 1\n\s+done\n\s*\}\n', text) \
            or not re.search(r' --jq \.id 2> draft\.err\)" \|\| true\n\s+if ! a_number "\$made"; then\n\s+no_number [^\n]*\n'
                             r'\s+exit 1\n\s+fi\n\s+upload_to "\$made"\n', text) \
            or 'if ! a_number "$made" && [ "$asked" = true ]; then' not in undo or 'if a_number "$made"; then' not in undo \
            or not re.search(r'\n\s+a_number "\$id" \|\| continue\n\s+gh api -X DELETE "repos/\$REPO/releases/assets/\$id"', undo):
        problems.append("an upload or a draft is taken as answered by whatever gh printed, which on a failure is GitHub's error and not a number")
    # The uploads looked for are those tried and not answered with a number, and a grep that fails
    # makes every upload one to look for rather than none.
    if not re.search(r'\n\s*: > answered\.txt\n', text) or not re.search(
            r'\n\s+if a_number "\$answer"; then\n\s+echo "\$answer" >> uploaded\.txt\n\s+basename "\$f" >> answered\.txt\n\s+continue\n', text) \
            or 'grep -vxF -f answered.txt tried.txt > lost.txt || [ $? = 1 ] || cp tried.txt lost.txt\n' not in undo:
        problems.append("a run that stops partway could look for none of the uploads that got no number back")
    if 'ours="github-actions[bot]"' not in text or not re.search(
            r'if \[ "\$who" = "\$ours" \] && ! grep -qx "\$id" before\.txt && ! grep -qx "\$id" uploaded\.txt'
            r' && grep -qxF "\$name" lost\.txt;', undo):
        problems.append("a run that stops partway could take off a file somebody else put on the release under one of its names")
    # A draft asked for whose answer was lost is found again, and only a draft this workflow made.
    if not re.search(r'\n\s+asked=true\n\s+made="\$\(gh api -X POST', text) \
            or '.author.login == \\"$ours\\" and .updated_at >= \\"$began\\"' not in undo \
            or 'if [ "$(grep -c . drafts.txt)" = 1 ]; then' not in undo \
            or not re.search(r'for try in 1 2 3 4 5 6; do\n(?:.*\n){3}\s+\[ -s drafts\.txt \] && break\n\s+\[ "\$try" = 6 \] \|\| sleep 5\n', undo):
        problems.append("a draft asked for whose answer was lost is left on the tag, or a draft somebody else made could be deleted")
    return problems


# What carries the guard's answer to the jobs that act on it, held as the guard job is. The guard
# reads which commit a tag names and refuses one that is not on main, and that answer is worth
# something only while every job that builds, signs or publishes waits on it and builds what it read.
# Each joint between them is a line a pull request can change with every other clause still passing:
# the tag job no longer waiting on the guard, or handing on the tag rather than the commit; the build
# checking out the tag by name; a folder held to a digest program that prints a constant. A tag with
# a pre-release name can be moved by anybody who can write, so any one of those builds and signs a
# commit nobody reviewed. So the route is held by value: which jobs there are and what each waits on,
# the tag job and the build job whole, every other checkout to main's scripts, every folder one job
# takes from another to the digest that job said, and the workflow's permissions and environment.
# Any change to any of it is a change made here in the same commit and read in that review.
ROUTE_NEEDS = {"guard": [], "tag": ["guard"], "build": ["tag"], "sign-macos": ["build", "tag"],
               "sign-windows": ["build", "tag"], "pack-linux": ["build", "tag"],
               "publish": ["pack-linux", "sign-macos", "sign-windows", "tag"], "check": ["publish", "tag"]}
# What the workflow and each job may do with the run's own token. Write on the repository's contents
# would let a job attach files past the Attach step, and write on Actions would let it replace or
# delete what another job uploaded.
WORKFLOW_PERMISSIONS = {"contents": "read"}
JOB_PERMISSIONS = {"sign-windows": {"contents": "read", "id-token": "write"},
                   "publish": {"contents": "write", "id-token": "write"}}
# The workflow's environment by value, and FOLDER_DIGEST by the digest of its program.
WORKFLOW_COLOUR = "always"
FOLDER_DIGEST_SHA256 = "80b4f84ceb1c14c0b55d68d5a9302022bf15eb3be82e8294e2365301c81839b3"
# The jobs neither held whole nor entering an environment, and what each may say of itself.
OTHER_JOB_KEYS = {"pack-linux": {"name", "needs", "runs-on", "outputs", "env", "steps"},
                  "check": {"name", "needs", "if", "uses", "with"}}
OTHER_JOB_RUNNERS = {"pack-linux": "ubuntu-latest"}

# The tag job, whole: what it says of itself, each of the guard's answers handed on as the guard gave
# it, and its steps, the starter steps and the one that says which signing sets are complete.
TAG_JOB = {"name": "which tag, and what can be signed", "needs": "guard", "runs-on": "ubuntu-latest",
           "environment": "release",
           "outputs": dict({name: "${{ needs.guard.outputs.%s }}" % name for name in GUARD_JOB["outputs"]},
                           apple="${{ steps.secrets.outputs.apple }}", azure="${{ steps.secrets.outputs.azure }}")}
TAG_SECRETS_SHA256 = "97f3b862bbc024182cb409520df6a8827ae6f057048c839f7534383aa7a42420"
# The build job, whole: what it says of itself, its matrix among it, by one digest, and each step by
# its own. It is the job that turns the commit the guard read into bytes, so a step that checks out or
# fetches anything else is a change to one of these.
BUILD_JOB_SHA256 = "b44da45c3865a5050c0eb69aabc72da0caa1373ac6356b9812234804ac2d428d"
BUILD_STEPS_SHA256 = ("6876f534463c307acb266ddc2ba2dcd0265c7ddc2e720ffa2888004ace55bda2",
                      "72d98c8080e8567d51a76e82dfbb6176b054d1923618c286593fe0e5fd17a399",
                      "e6a3f0ebd17971ba67e8c41d6cd91c4469b2de2060072cbc213d62fc22ea8862",
                      "34cee6800f1cbff4e2d1a30695f1fd6f966dea676fb37ea3cd65f9ce514a69a5",
                      "07694b94e18068199798a651cbdc19f12dc2aa91498f38cad367dc6ef014cdb7",
                      "2c1aa3c4af4f78ef2df0c8a5dad22ec10316d6c6883c7c4f90303da3dc2cb557")
CHECKOUT = "actions/checkout@"
# The one thing the build checks out, and the only two things any other job may: main's own scripts,
# by the starter checkout and by the one the signature check is read from.
BUILD_CHECKOUT = {"ref": "${{ needs.tag.outputs.commit }}", "persist-credentials": False}
SCRIPT_CHECKOUTS = [STARTER_STEPS[0]["with"],
                    {"persist-credentials": False, "path": "check",
                     "sparse-checkout": "scripts/the-binaries-are-signed.py\nscripts/signing-identities.json\n",
                     "sparse-checkout-cone-mode": False}]

# Every folder one job takes from another, by name and where it goes, the step that holds them to the
# digests their jobs said, by its digest, and where that step reads those digests from. No other job
# downloads anything.
DOWNLOAD = "actions/download-artifact@"
DOWNLOADS = {
    "sign-macos": [{"name": "unsigned-x86_64-apple-darwin", "path": "in/unsigned-x86_64-apple-darwin"},
                   {"name": "unsigned-aarch64-apple-darwin", "path": "in/unsigned-aarch64-apple-darwin"}],
    "sign-windows": [{"name": "unsigned-x86_64-pc-windows-msvc", "path": "in"}],
    "pack-linux": [{"name": "unsigned-x86_64-unknown-linux-gnu", "path": "in/unsigned-x86_64-unknown-linux-gnu"},
                   {"name": "unsigned-aarch64-unknown-linux-gnu", "path": "in/unsigned-aarch64-unknown-linux-gnu"}],
    "publish": [{"name": "asset-linux", "path": "from/linux"}, {"name": "asset-macos", "path": "from/macos"},
                {"name": "asset-windows", "path": "from/windows"}],
}
HOLD_STEPS_SHA256 = {"sign-macos": "48f99632390016606bca51fb2171d6cb72807823b48a20a16d53bd30ff25d2a3",
                     "sign-windows": "744831f76eb765768c1f6ad714964964cd02cc1d6ebb05afb15cb03c5d9e4cab",
                     "pack-linux": "4b0d92cd9b63ff2f9d882a81f3e1ed6fb763a0d5332ed596e8bf34e45a35e86d",
                     "publish": "96ad0dfa3146a1894cf9491d9e1ed410ba5118fca433f3babe97bdac8346c304"}
HOLDING_ENV = {
    "sign-macos": {"TARGETS": "x86_64-apple-darwin aarch64-apple-darwin",
                   "WANT_x86_64_apple_darwin": "${{ needs.build.outputs.x86_64-apple-darwin }}",
                   "WANT_aarch64_apple_darwin": "${{ needs.build.outputs.aarch64-apple-darwin }}"},
    "pack-linux": {"TARGETS": "x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu",
                   "WANT_x86_64_unknown_linux_gnu": "${{ needs.build.outputs.x86_64-unknown-linux-gnu }}",
                   "WANT_aarch64_unknown_linux_gnu": "${{ needs.build.outputs.aarch64-unknown-linux-gnu }}"},
}


def route_jobs(release):
    """Every job of release.yml as YAML reads it, by name, or why they cannot be read."""
    doc = parsed(release)
    if not isinstance(doc, dict):
        return "PyYAML is not installed here" if doc is None else "release.yml: %s" % doc
    return doc


def waits_on(job):
    """What a job waits on, as a sorted list of names, or None where it is neither a name nor a list."""
    needs = job.get("needs", []) if isinstance(job, dict) else None
    if isinstance(needs, str):
        return [needs]
    return sorted(str(n) for n in needs) if isinstance(needs, list) else None


def not_reaching_the_guard(jobs):
    """Each job, by name, that does not wait on the guard directly or through the jobs it waits on."""
    waits = {str(name): waits_on(job) or [] for name, job in jobs.items()}
    reached, changed = {"guard"} & set(waits), True
    while changed:
        changed = False
        for name, needs in waits.items():
            if name not in reached and any(n in reached for n in needs):
                reached.add(name)
                changed = True
    return sorted(name for name in waits if name not in reached)


def judge_waits_on_guard(release):
    """No job of release.yml runs but after the guard has answered, so no job builds, signs or
    publishes while the guard refuses."""
    doc = route_jobs(release)
    if isinstance(doc, str):
        return [doc]
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return ["release.yml has no jobs this can read"]
    late = [name for name in not_reaching_the_guard(jobs) if name != "guard"]
    if late:
        return ["%s run without waiting on the guard, directly or through the jobs they wait on" % ", ".join(late)]
    return []


def judge_route_joined(release):
    """release.yml runs the jobs written here, each waiting on what is written here, and none of them
    or the workflow is given a permission or an environment value that is not written here."""
    doc = route_jobs(release)
    if isinstance(doc, str):
        return [doc]
    problems = []
    named = doc.get("jobs")
    jobs = dict(parsed_jobs(doc))
    if not isinstance(named, dict) or sorted(map(str, named)) != sorted(ROUTE_NEEDS) or len(jobs) != len(named):
        problems.append("release.yml runs the jobs %s, where it runs %s" % (
            sorted(map(str, named)) if isinstance(named, dict) else json.dumps(named), sorted(ROUTE_NEEDS)))
    for name, want in ROUTE_NEEDS.items():
        if name in jobs and waits_on(jobs[name]) != want:
            problems.append("%s waits on %s, not on %s as written here" % (name, json.dumps(jobs[name].get("needs")), want))
    if doc.get("permissions") != WORKFLOW_PERMISSIONS:
        problems.append("release.yml gives every job %s, not %s" % (json.dumps(doc.get("permissions")), WORKFLOW_PERMISSIONS))
    for name, job in jobs.items():
        if job.get("permissions") != JOB_PERMISSIONS.get(name):
            problems.append("%s is given %s, not %s" % (name, json.dumps(job.get("permissions")), JOB_PERMISSIONS.get(name)))
    env = doc.get("env") if isinstance(doc.get("env"), dict) else {}
    if env.get("CARGO_TERM_COLOR") != WORKFLOW_COLOUR:
        problems.append("release.yml sets CARGO_TERM_COLOR to %s, not %s" % (json.dumps(env.get("CARGO_TERM_COLOR")), WORKFLOW_COLOUR))
    program = env.get("FOLDER_DIGEST")
    digest = hashlib.sha256(program.encode("utf-8")).hexdigest() if isinstance(program, str) else None
    if digest != FOLDER_DIGEST_SHA256:
        problems.append("FOLDER_DIGEST reads %s, not %s as written here" % (digest, FOLDER_DIGEST_SHA256))
    for name, keys in OTHER_JOB_KEYS.items():
        extra = (names_of(jobs[name]) or set()) - keys if name in jobs else set()
        if extra:
            problems.append("%s sets %s for the whole job" % (name, sorted(extra)))
    for name, runner in OTHER_JOB_RUNNERS.items():
        if name in jobs and jobs[name].get("runs-on") != runner:
            problems.append("%s runs on %s, not %s" % (name, json.dumps(jobs[name].get("runs-on")), runner))
    return problems


def judge_commit_carried(release):
    """The tag job hands on each of the guard's answers as the guard gave it, the build checks out the
    commit the guard read and nothing else, and no other job checks out anything but main's scripts."""
    doc = route_jobs(release)
    if isinstance(doc, str):
        return [doc]
    problems = []
    jobs = dict(parsed_jobs(doc))
    outputs = (jobs.get("tag") or {}).get("outputs")
    outputs = outputs if isinstance(outputs, dict) else {}
    for name in GUARD_JOB["outputs"]:
        if outputs.get(name) != "${{ needs.guard.outputs.%s }}" % name:
            problems.append("the tag job hands on %s as %s, not as the guard gave it" % (name, json.dumps(outputs.get(name))))
    for name, job in jobs.items():
        checkouts = [step.get("with") for step in job.get("steps") or []
                     if isinstance(step, dict) and str(step.get("uses", "")).lower().startswith(CHECKOUT)]
        if name == "build":
            if checkouts != [BUILD_CHECKOUT]:
                problems.append("the build checks out %s, where it checks out the commit the guard read and nothing else"
                                % json.dumps(checkouts))
        elif name != "guard":
            other = [c for c in checkouts if c not in SCRIPT_CHECKOUTS]
            if other:
                problems.append("%s checks out %s, where it checks out main's scripts alone" % (name, json.dumps(other)))
    return problems


def judge_tag_and_build_held(release):
    """The tag job and the build job are the ones written down here, each step to the byte."""
    doc = route_jobs(release)
    if isinstance(doc, str):
        return [doc]
    problems = []
    jobs = dict(parsed_jobs(doc))
    tag = jobs.get("tag") or {}
    own = {key: value for key, value in tag.items() if key != "steps"}
    if own != TAG_JOB:
        problems.append("the tag job says %s of itself, not %s as written here"
                        % (json.dumps(own, sort_keys=True), json.dumps(TAG_JOB, sort_keys=True)))
    steps = tag.get("steps")
    if not isinstance(steps, list) or len(steps) != 3 or steps[:2] != STARTER_STEPS:
        problems.append("the tag job has %s steps, where it has its starter steps and the one that says which signing "
                        "sets are complete" % (len(steps) if isinstance(steps, list) else "no list of"))
    elif digest_of(steps[2]) != TAG_SECRETS_SHA256:
        problems.append("the tag job's secrets step reads %s, not %s as written here" % (digest_of(steps[2]), TAG_SECRETS_SHA256))
    build = jobs.get("build") or {}
    own = digest_of({key: value for key, value in build.items() if key != "steps"})
    if own != BUILD_JOB_SHA256:
        problems.append("the build job says %s of itself, not %s as written here" % (own, BUILD_JOB_SHA256))
    steps = build.get("steps")
    if not isinstance(steps, list) or len(steps) != len(BUILD_STEPS_SHA256):
        problems.append("the build job has %s steps, where it has %d" % (
            len(steps) if isinstance(steps, list) else "no list of", len(BUILD_STEPS_SHA256)))
    else:
        for at, (step, held) in enumerate(zip(steps, BUILD_STEPS_SHA256)):
            if digest_of(step) != held:
                problems.append("the build job's step %d reads %s, not %s as written here" % (at + 1, digest_of(step), held))
    return problems


def judge_folders_held(release):
    """Every folder a job takes from another is the one written here, put where it is written here,
    and held, after the last of them is in and before anything else, by the step written here to the
    digests the jobs that made them said."""
    doc = route_jobs(release)
    if isinstance(doc, str):
        return [doc]
    problems = []
    for name, job in parsed_jobs(doc):
        steps = [step if isinstance(step, dict) else {} for step in job.get("steps") or []]
        at = [i for i, step in enumerate(steps) if str(step.get("uses", "")).lower().startswith(DOWNLOAD)]
        taken = [steps[i].get("with") for i in at]
        if taken != DOWNLOADS.get(name, []):
            problems.append("%s takes %s, not %s as written here" % (name, json.dumps(taken), json.dumps(DOWNLOADS.get(name, []))))
        if name not in DOWNLOADS:
            continue
        holds = [i for i, step in enumerate(steps)
                 if 'got="$(' in str(step.get("run", "")) and '"$FOLDER_DIGEST"' in str(step.get("run", ""))]
        if len(holds) != 1:
            problems.append("%s has %d steps holding what it took to a digest, where it has one" % (name, len(holds)))
        elif not at or holds[0] != at[-1] + 1:
            problems.append("%s does not hold what it took straight after the last of it is in" % name)
        elif digest_of(steps[holds[0]]) != HOLD_STEPS_SHA256[name]:
            problems.append("%s holds what it took by a step reading %s, not %s as written here"
                            % (name, digest_of(steps[holds[0]]), HOLD_STEPS_SHA256[name]))
        if job.get("env") != HOLDING_ENV.get(name):
            problems.append("%s gives its steps %s, not %s as written here" % (name, json.dumps(job.get("env")), json.dumps(HOLDING_ENV.get(name))))
    return problems


def judge_secrets_read(release):
    """release.yml reads the secrets written down here and no others, and none an older run reads."""
    read = set(re.findall(r"(?<![\w.-])secrets\.([A-Za-z0-9_]+)", release))
    problems = ["release.yml reads %s, a name an older run of it reads too" % n for n in sorted(read & RETIRED_SECRETS)]
    # Any other way of reaching the secrets hands over names this list never sees: by index, all of
    # them at once, or every one to a called workflow.
    for expression in re.findall(r"\$\{\{(.*?)\}\}", release, re.S):
        if re.search(r"(?<![\w.-])secrets\b(?!\.[A-Za-z0-9_])", expression):
            problems.append("release.yml reaches the secrets as [%s], not by name" % " ".join(expression.split()))
    if re.search(r"""^\s*['"]?secrets['"]?\s*:\s*['"]?inherit""", release, re.M):
        problems.append("release.yml hands every secret to a workflow it calls")
    if read - RETIRED_SECRETS != RELEASE_SECRETS:
        problems.append("release.yml reads the secrets %s, not %s" % (sorted(read - RETIRED_SECRETS), sorted(RELEASE_SECRETS)))
    return problems


def judge_actions_permissions(permissions):
    seen = {k: permissions.get(k) for k in ACTIONS_PERMISSIONS}
    return [] if seen == ACTIONS_PERMISSIONS else ["the Actions settings read %s, not %s" % (json.dumps(seen), json.dumps(ACTIONS_PERMISSIONS))]


def administrators_shown(collaborators):
    """Whether GitHub showed this token who administers the repository. A workflow's own token is
    answered with an empty list rather than refused, and the organisation's owners administer every
    repository it holds, so an empty list is never the true one."""
    return collaborators != []


def judge_administrators(collaborators):
    if not isinstance(collaborators, list) or not all(isinstance(c, dict) for c in collaborators):
        return ["GitHub's answer for who administers the repository is no list of them"]
    seen = {c.get("login"): c.get("id") for c in collaborators}
    return [] if seen == ADMINISTRATORS else ["the administrators are %s, not %s" % (json.dumps(seen, sort_keys=True), json.dumps(ADMINISTRATORS, sort_keys=True))]


def listed_names(listed, where):
    """The names of the secrets GitHub listed for one level, or the reason the answer cannot be
    taken for what that level holds: no list, or fewer than GitHub counts."""
    secrets = listed.get("secrets") if isinstance(listed, dict) else None
    if not isinstance(secrets, list) or not all(isinstance(s, dict) for s in secrets):
        return None, ["GitHub's answer for %s holds no list of secrets, so what it holds was not read" % where]
    if listed.get("total_count") != len(secrets):
        return None, ["GitHub says %s holds %s secrets and listed %d, so what it holds was not all read" % (
            where, listed.get("total_count"), len(secrets))]
    return {s.get("name") for s in secrets}, []


def judge_secret_names(listed, where, allowed):
    """The secrets stored at one level: none under a name an older run reads, no signing value outside
    the release environment, and nothing but the names written down for that level."""
    names, problems = listed_names(listed, where)
    if names is None:
        return problems
    problems = ["%s holds %s, a name an older run of release.yml reads" % (where, n) for n in sorted(names & RETIRED_SECRETS)]
    problems += ["%s holds %s, a signing value release.yml reads there without entering the release environment" % (where, n)
                 for n in sorted((names & RELEASE_SECRETS) - allowed)]
    others = names - allowed - RETIRED_SECRETS - RELEASE_SECRETS
    if others:
        problems.append("%s holds %s, which nothing written down here reads" % (where, sorted(others)))
    return problems


def judge_other_environments(held):
    """The secrets of every environment but `release`, by name: none at all."""
    if not isinstance(held, dict):
        return ["the environments were not read"]
    problems = []
    for name in sorted(held):
        problems += judge_secret_names(held[name], "the %s environment" % name, OTHER_ENVIRONMENT_SECRETS)
    return problems


def judge_shared_dependabot(listed):
    """The organisation's Dependabot secrets: none under a signing name, old or new."""
    names, problems = listed_names(listed, "the organisation's Dependabot secrets")
    if names is None:
        return problems
    return ["the organisation holds %s for Dependabot, a signing name any repository's Dependabot run reads" % n
            for n in sorted(names & (RELEASE_SECRETS | RETIRED_SECRETS))]


def route_writes(installation):
    """The writes an installation holds that reach the route, where it is installed on this repository."""
    permissions = installation.get("permissions") if isinstance(installation, dict) else None
    return [p for p in ROUTE_WRITES if permissions.get(p) in WRITES] if isinstance(permissions, dict) else []


def judge_installations(listed, reached):
    """Whether any app installed on the organisation can write to what keeps the route. `listed` is
    GitHub's answer for the organisation's installations, and `reached` maps the id of each installed
    on a list of repositories, and holding a route write, to GitHub's answer for that list or to the
    reason it was not read. Returns what fails, and what could not be read: an app with a route write
    on a list nobody read may reach this repository or may not, and the run cannot say which."""
    installations = listed.get("installations") if isinstance(listed, dict) else None
    if not isinstance(installations, list) or not all(isinstance(i, dict) for i in installations):
        return ["GitHub's answer for the organisation's app installations holds no list of them"], []
    if listed.get("total_count") != len(installations):
        return ["GitHub says the organisation has %s app installations and listed %d, so they were not all read" % (
            listed.get("total_count"), len(installations))], []
    problems, unread = [], []
    for each in installations:
        # By number: a run's log may be public, and the app's name is not this file's to print.
        app = "app %s, installation %s," % (each.get("app_id"), each.get("id"))
        permissions = each.get("permissions")
        if not isinstance(permissions, dict):
            problems.append("%s is listed with no permissions, so what it may write was not read" % app)
            continue
        wide = [p for p in ORGANISATION_WRITES if permissions.get(p) in WRITES]
        if wide:
            problems.append("%s holds write on %s, which reaches this repository whatever it is installed on" % (app, ", ".join(wide)))
        route = route_writes(each)
        if not route:
            continue
        held = "%s holding write on %s," % (app, ", ".join(route))
        selection = each.get("repository_selection")
        if selection == "all":
            problems.append("%s is installed on every repository, this one among them" % held)
        elif selection == "selected":
            answer = reached.get(each.get("id"))
            repositories = answer.get("repositories") if isinstance(answer, dict) else None
            if isinstance(answer, str):
                unread.append("%s is installed on a list of repositories that was not read: %s" % (held, answer))
            elif not isinstance(repositories, list) or not all(isinstance(r, dict) for r in repositories):
                unread.append("%s is installed on a list of repositories GitHub answered with no list" % held)
            elif [r for r in repositories if r.get("id") == REPO_NUMBER or str(r.get("full_name")).lower() == REPO.lower()]:
                problems.append("%s is installed on this repository" % held)
            elif answer.get("total_count") != len(repositories):
                unread.append("%s is installed on %s repositories and GitHub listed %d, so whether this is one was not read" % (
                    held, answer.get("total_count"), len(repositories)))
        else:
            problems.append("%s is installed on %s, which is neither every repository nor a list of them" % (held, json.dumps(selection)))
    return problems, unread


def judge_azure(app):
    """The Entra app Windows signing signs in as, from the file `--azure` names."""
    problems = []
    federated = app.get("federated_credentials")
    want = token_subject("release")
    if not isinstance(federated, list) or len(federated) != 1:
        problems.append("the app has %s federated credentials, where one belongs" % (len(federated) if isinstance(federated, list) else "no list of"))
    elif (federated[0].get("issuer"), federated[0].get("subject"), federated[0].get("audiences")) != (AZURE_ISSUER, want, AZURE_AUDIENCES):
        problems.append("its federated credential trusts %s from %s for %s, not %s from %s for %s" % (
            federated[0].get("subject"), federated[0].get("issuer"), federated[0].get("audiences"), want, AZURE_ISSUER, AZURE_AUDIENCES))
    for kind in ("password_credentials", "key_credentials", "service_principal_password_credentials",
                 "service_principal_key_credentials"):
        if app.get(kind) != []:
            problems.append("the app has %s %s, and signs in by GitHub's token alone" % (
                len(app.get(kind)) if isinstance(app.get(kind), list) else "unread", kind.replace("_", " ")))
    # Giving the app its signer role is what arms Windows signing, so the app is read before that, with
    # no role, and passes: what it trusts and how it signs in are shown sound before it can sign.
    roles = app.get("role_assignments")
    if not isinstance(roles, list) or len(roles) > 1:
        problems.append("the app holds %s roles, where one at most belongs" % (len(roles) if isinstance(roles, list) else "an unread list of"))
    elif roles and (roles[0].get("roleDefinitionName") not in AZURE_SIGNER_ROLES
                    or not re.match(AZURE_PROFILE_SCOPE, str(roles[0].get("scope")))):
        problems.append("its role is %s on %s, not the signer role on one certificate profile" % (
            roles[0].get("roleDefinitionName"), roles[0].get("scope")))
    return problems + judge_azure_holders(app, roles)


def azure_signs(assignment):
    """Whether the role of an assignment signs: True or False, or None where what it may do was not read."""
    name, actions = assignment.get("roleDefinitionName"), assignment.get("dataActions")
    if not isinstance(name, str) or not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
        return None
    return name in AZURE_SIGNER_ROLES or any(wildcard_reaches(a, sign) for a in actions for sign in AZURE_SIGN_ACTIONS)


def wildcard_reaches(pattern, action):
    """Whether a data action written with `*` wildcards takes in `action`, without regard to case. Each
    piece between the stars is found in order, so a pattern of many stars costs no more than its length."""
    pieces, text = pattern.lower().split("*"), action.lower()
    if len(pieces) == 1:
        return pieces[0] == text
    if len(text) < len(pieces[0]) + len(pieces[-1]) or not text.startswith(pieces[0]) or not text.endswith(pieces[-1]):
        return False
    at, end = len(pieces[0]), len(text) - len(pieces[-1])
    for piece in pieces[1:-1]:
        found = text.find(piece, at, end)
        if found < 0:
            return False
        at = found + len(piece)
    return True


def azure_reaches(scope, account):
    """Whether an assignment at `scope` applies to the signing account or to anything inside it. Azure
    reads an address without regard to case, and a scope that is not text, or not of a shape this can
    place, is taken to reach it."""
    if not isinstance(scope, str):
        return True
    s, a = scope.rstrip("/").lower(), str(account).lower()
    if not re.match(AZURE_SCOPE_SHAPE, s):
        return True
    return (s == a or a.startswith(s + "/") or s.startswith(a + "/")
            or s.startswith("/providers/microsoft.management/managementgroups/"))


def judge_azure_holders(app, roles):
    """Nobody but the app holds a role that signs anywhere reaching the signing account, nobody is
    eligible for one, and the app's roles read the same in the whole list as in its own."""
    account, principal, every = app.get("signing_account"), app.get("service_principal_id"), app.get("every_role_assignment")
    if not isinstance(account, str) or not re.match(AZURE_ACCOUNT_SCOPE, account):
        return ["the file names no signing account, so who else may sign there has not been read"]
    if not isinstance(principal, str) or not principal:
        return ["the file names no service principal for the app, so its roles cannot be told from anybody else's"]
    if not isinstance(every, dict) or every.get("listed") != AZURE_LISTED:
        return ["the file does not say its role assignments are %s, and a list read short reads the same as one with "
                "nobody else on it" % AZURE_LISTED]
    within = every.get("subscription")
    if (not isinstance(within, str) or not re.match(AZURE_SUBSCRIPTION_SCOPE, within)
            or not str(account).lower().startswith(within.lower() + "/")):
        return ["the file lists the role assignments of %s, and the signing account is %s" % (within, account)]
    problems, ours = [], []
    for kind in ("active", "eligible"):
        listed = every.get(kind)
        if not isinstance(listed, list) or not all(isinstance(a, dict) for a in listed):
            problems.append("its %s role assignments are no list of them" % kind)
            continue
        for a in listed:
            mine = str(a.get("principalId")).lower() == str(principal).lower()
            if kind == "active" and mine:
                ours.append((a.get("roleDefinitionName"), str(a.get("scope")).lower()))
            if not azure_reaches(a.get("scope"), account):
                continue
            signs = azure_signs(a)
            said = "%s %s, %s for %s on %s" % (a.get("principalType"), a.get("principalId"), kind,
                                                a.get("roleDefinitionName"), a.get("scope"))
            if signs is None:
                problems.append("%s: what its role may do was not read" % said)
            elif signs and (kind == "eligible" or not mine):
                problems.append("%s: it may sign as our Windows publisher, and only the app may" % said)
    if isinstance(roles, list) and all(isinstance(r, dict) for r in roles):
        theirs = sorted(((r.get("roleDefinitionName"), str(r.get("scope")).lower()) for r in roles), key=repr)
        if sorted(ours, key=repr) != theirs:
            problems.append("the app holds %s by its own list and %s by the whole one, so one of the two reads is short"
                            % (theirs, sorted(ours, key=repr)))
        for r in roles:
            if not str(r.get("scope")).lower().startswith(str(account).lower() + "/certificateprofiles/"):
                problems.append("the app's role is on %s, outside the signing account %s" % (r.get("scope"), account))
    return problems


def statuses_needed(deployment, since=DEPLOYMENTS_SINCE):
    """Whether the judgement of one deployment record turns on its statuses: one made since the
    policy was set, from a ref other than main. A main record is judged by who made it alone."""
    if not isinstance(deployment, dict):
        return False
    created = instant(deployment.get("created_at"))
    return deployment.get("ref") != "main" and (not isinstance(created, datetime.datetime) or created >= instant(since))


def judge_deployments(listed, statuses, since=DEPLOYMENTS_SINCE):
    """Every record of a job asking to enter a signing environment, made since `since`: made by an
    account written down as starting releases, and inside the environment only from main. `listed`
    maps each environment to GitHub's list of its deployments, and `statuses` maps a deployment's
    number, as text, to GitHub's list of its statuses, read where `statuses_needed` says."""
    problems = []
    for environment in DEPLOYMENT_ENVIRONMENTS:
        deployments = listed.get(environment)
        if not isinstance(deployments, list) or not all(isinstance(d, dict) for d in deployments):
            problems.append("GitHub's answer for the %s environment's deployments is no list of them" % environment)
            continue
        for d in deployments:
            created = instant(d.get("created_at"))
            creator = d.get("creator") if isinstance(d.get("creator"), dict) else {}
            said = "deployment %s to %s, from %s at %s" % (d.get("id"), environment, d.get("ref"), d.get("created_at"))
            if not isinstance(created, datetime.datetime):
                problems.append("%s: when it was made could not be read" % said)
                continue
            if created < instant(since):
                continue
            if judge_starter(creator.get("login"), creator.get("id")):
                problems.append("%s: made by %s, account %s, who is not written down as starting releases" % (
                    said, creator.get("login"), creator.get("id")))
            if d.get("ref") != "main":
                states = statuses.get(str(d.get("id")))
                if not isinstance(states, list) or not all(isinstance(s, dict) and isinstance(s.get("state"), str)
                                                           for s in states):
                    problems.append("%s: its statuses were not read, so whether it ran is not known" % said)
                elif RAN & {s.get("state") for s in states}:
                    problems.append("%s: it ran, from a ref other than main" % said)
    if problems:
        problems.append("this is seen after the fact, and stopped nothing")
    return problems


def judge_azure_unread(listed):
    """Why an administrator's run cannot leave the Entra app unread: anything Windows signing reads is
    stored on the release environment, or the list of what it stores was not read. `listed` is
    GitHub's answer for that list, or None where it gave none. The three Azure identifiers sign
    nothing on their own, but the run that admits the first signing value is made while they alone
    are stored, so they count: that run must fail with the Entra app unread, and not the one after."""
    if listed is None:
        return ["the release environment's secrets were not read, so whether a Windows signing value is stored "
                "there is not known, and the Entra app it would sign in as has not been read; pass --azure"]
    names, problems = listed_names(listed, "the release environment")
    if names is None:
        return problems + ["so the Entra app has not been read where a Windows signing value may be stored; pass --azure"]
    stored = sorted(n for n in names if isinstance(n, str) and (n.startswith("WINDOWS_SIGNING_") or n.startswith("WINDOWS_AZURE_")))
    if stored:
        return ["what Windows signing reads is stored on the release environment (%s), and the Entra app it signs in "
                "as has not been read; pass --azure" % ", ".join(stored)]
    return []


# Reading the world.

def get(url, accept="application/vnd.github+json", with_headers=False, token=None):
    request = urllib.request.Request(url, headers={"User-Agent": "timewitness-release-route", "Accept": accept})
    token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        body = response.read().decode("utf-8")
        return (body, response.headers) if with_headers else body


NEXT_PAGE = re.compile(r'<([^>]+)>;\s*rel="next"')


# The lists GitHub hands back inside an object rather than as the answer itself.
PAGED_KEYS = ("secrets", "environments", "installations", "repositories")


def github(path, page=None):
    """GitHub's answer to `path`, read to its last page. A list's pages are joined, and so are the
    pages of the list of secrets, environments, installations or repositories an answer holds, so
    nothing past the first page goes unread. A page of another shape than the first is refused rather
    than dropped."""
    page = page or (lambda url: get(url, with_headers=True))
    url, whole, pages = "https://api.github.com/" + path, None, 0
    while url:
        body, headers = page(url)
        value = json.loads(body)
        if whole is None:
            whole = value
        elif isinstance(whole, list) and isinstance(value, list):
            whole += value
        elif isinstance(whole, dict) and isinstance(value, dict) and [k for k in PAGED_KEYS if isinstance(whole.get(k), list)
                                                                        and isinstance(value.get(k), list)]:
            for key in PAGED_KEYS:
                if isinstance(whole.get(key), list):
                    whole[key] += value[key]
        else:
            raise ValueError("%s answered a page of another shape than its first" % path)
        found = NEXT_PAGE.search(headers.get("Link") or "")
        url = found.group(1) if found else None
        pages += 1
        if url and (pages >= 100 or not url.startswith("https://api.github.com/")):
            raise ValueError("%s goes on to %s, which is not read" % (path, url))
    return whole


def installations_reader(token):
    """GitHub's answer to a path, read to its last page with `token` in place of `GH_TOKEN`: the
    personal access token GitHub lists an installation's repositories to."""
    return lambda path: github(path, page=lambda url: get(url, with_headers=True, token=token))


def workflows_in_tree():
    out = {}
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
                out[name] = f.read()
    return out


def run(tree_only, need_yaml=False, github=github, fetch=get, azure=None, need_admin=False, reach=None):
    """Every clause, read from GitHub through `github` and `fetch` unless `tree_only`, and the Azure
    side from the file `azure` names. `reach` reads the repositories an app is installed on, and is
    None where no token here can. With `need_admin`, a clause GitHub did not show this token fails.
    Returns the exit code and the name of every clause it ran, in order, so the self-test can hold
    this to running each of them."""
    results, ran = [], []
    # Whether GitHub hid the Actions settings from this token, the first thing read that only an
    # administrator is shown; empty until they are asked for.
    settings_hidden = []
    # GitHub's answer for the release environment's secrets, once it is read, which says whether a
    # Windows signing value is stored there for the Entra app's line below.
    release_listed = []

    def api(path):
        return github("repos/%s/%s" % (REPO, path))

    def say(state, line):
        results.append(state)
        print("%s: %s" % (state, line), flush=True)

    def clause(what, problems):
        ran.append(what)
        if problems:
            say("FAIL", "%s: %s" % (what, "; ".join(problems)))
        else:
            say("PASS", what)

    def unseen(what, why):
        """What GitHub did not show this token: UNSEEN, or a failure where --need-admin asks for it."""
        if need_admin:
            say("FAIL", "%s: %s, and --need-admin needs it read" % (what, why))
        else:
            say("UNSEEN", "%s: %s" % (what, why))

    def other_environments(path):
        """The secrets of every environment but `release`, by name. The list of environments is
        public; each one's secrets are shown only to an administrator."""
        listed = github(path)
        names = [e.get("name") for e in listed.get("environments", [])] if isinstance(listed, dict) else None
        if not isinstance(names, list) or listed.get("total_count") != len(names) or not all(isinstance(n, str) for n in names):
            raise ValueError("%s answered no whole list of environments" % path)
        return {n: github("repos/%s/environments/%s/secrets?per_page=100" % (REPO, urllib.parse.quote(n, safe=""))) for n in names if n != "release"}

    def installations(path):
        """The organisation's app installations, and the repositories each is installed on where it
        holds a route write on a list of them. Those lists are read through `reach`, and GitHub
        refusing it, or there being none, is said for each; anything else it answers fails the run."""
        listed = github(path)
        reached = {}
        for each in (listed.get("installations") if isinstance(listed, dict) else None) or []:
            if not isinstance(each, dict) or each.get("repository_selection") != "selected" or not route_writes(each):
                continue
            number = each.get("id")
            if reach is None:
                reached[number] = ("%s names no token, and GitHub lists the repositories an app is installed on "
                                   "only to a personal access token" % INSTALLATIONS_TOKEN)
                continue
            try:
                reached[number] = reach("user/installations/%s/repositories?per_page=100" % urllib.parse.quote(str(number), safe=""))
            except urllib.error.HTTPError as e:
                if e.code not in (401, 403, 404):
                    raise ValueError("GitHub answered %d for the repositories installation %s is on" % (e.code, number))
                reached[number] = "GitHub answered the token %s names %d" % (INSTALLATIONS_TOKEN, e.code)
        return listed, reached

    def unless_hidden(what, path, judge, read=None, shown=None):
        """A clause on something GitHub shows only to an administrator, said as UNSEEN to any other.
        GitHub answers 404 for a thing it hides as well as for a thing that is not there, so a 404 is
        taken for hidden only where the Actions settings were hidden from this token too. `read`,
        where given, reads `path` and whatever else the clause needs in place of one read. `shown`,
        where given, says whether an answer is one GitHub shows this token, for a read it answers
        with an empty list rather than refuse. `judge` may say what it could not read beside what
        fails, and a clause with nothing failing and something unread is UNSEEN."""
        try:
            value = (read or github)(path)
        except urllib.error.HTTPError as e:
            hidden = e.code in (401, 403) or (e.code == 404 and settings_hidden[:1] != [False])
            if not settings_hidden:
                settings_hidden.append(hidden)
            if not hidden:
                raise
            ran.append(what)
            unseen(what, "GitHub shows this only to an administrator, and answered this token %d" % e.code)
            return
        if not settings_hidden:
            settings_hidden.append(False)
        # Taken for hidden, as a 404 is, only where the Actions settings were hidden from this token too.
        if shown and not shown(value) and settings_hidden[:1] != [False]:
            ran.append(what)
            unseen(what, "GitHub answered this token with an empty list, which is how it hides this from a token "
                         "that is not an administrator's")
            return
        judged = judge(value)
        problems, unread = judged if isinstance(judged, tuple) else (judged, [])
        if problems or not unread:
            clause(what, problems + unread)
        else:
            ran.append(what)
            unseen(what, "; ".join(unread))

    if yaml is not None:
        say("PASS", "the workflows are read as YAML reads them, and by pattern")
    elif need_yaml:
        say("FAIL", "PyYAML is not installed here, so a job or step written as a flow mapping would not be read")
    else:
        say("NOT PARSED", "PyYAML is not installed here, so the workflows are read by pattern alone")
    workflows = workflows_in_tree()
    release = workflows.get("release.yml", "")
    clause("release.yml is started by hand and by nothing else", judge_on_block(release))
    clause("only release.yml's tag, sign-macos and sign-windows jobs enter release, and only its publish job enters "
           "linux-signing", judge_environment_users(workflows))
    try:
        with open(SIGNATURE_CHECK, encoding="utf-8") as f:
            check_text = f.read()
    except OSError as e:
        check_text = ""
        say("FAIL", "the signature check could not be read: %s" % e)
    clause("the signature check holds a Linux signature to the token of the job that alone enters linux-signing",
           judge_linux_subject(check_text))
    clause("no job in release.yml restores from the Actions cache, the signing action included", judge_no_cache(release))
    clause("no workflow names an Azure client secret, and Windows signing signs in by a federated token",
           judge_no_client_secret(workflows))
    clause("no workflow calls a reusable workflow from another repository", judge_reusable(workflows))
    clause("release.yml reads the signing values under the names written here, and none an older run of it reads",
           judge_secrets_read(release))
    clause("the guard refuses anybody not written down here as starting releases", judge_guard(release))
    clause("the guard job is the one written down here, and each of its two steps to the byte", judge_guard_held(release))
    clause("what is written here lets nobody make a tag outside v*, and only an administrator one inside it",
           judge_tag_rulesets(RULESETS))
    clause("every job that enters an environment asks the same of whoever started it", judge_starter_steps(release))
    clause("each job that signs with a token holds its subject to main and release.yml before anything else",
           judge_token_steps(release))
    clause("no job that enters an environment runs on past its starter steps, or runs them with a tool or a setting "
           "of its own", judge_nothing_past_the_starter(release))
    clause("a release is a draft until it carries every file, and is attached only to the commit the run built",
           judge_attach(release))
    clause("the Attach step is the one written down here, to the byte", judge_attach_pinned(release))
    clause("every job of release.yml waits on the guard, directly or through the jobs it waits on",
           judge_waits_on_guard(release))
    clause("release.yml runs the jobs written here, each waiting on what is written here and given no more than is "
           "written here", judge_route_joined(release))
    clause("the tag job hands on the commit the guard read, the build checks out that commit and nothing else, and "
           "no other job checks out anything but main's scripts", judge_commit_carried(release))
    clause("the tag job and the build job are the ones written down here, each step to the byte",
           judge_tag_and_build_held(release))
    clause("every folder a job takes from another is held to the digest that job said, by the step written here",
           judge_folders_held(release))
    code = 1 if "FAIL" in results else 0
    if tree_only:
        return code, ran

    try:
        action = fetch("https://raw.githubusercontent.com/%s/%s/action.yml" % (SIGNING_ACTION, SIGNING_ACTION_PIN), "text/plain")
        clause("the pinned signing action restores from the cache only when asked to", judge_action(action))

        used = environment_job_actions(release)
        if isinstance(used, str):
            clause("no action a job in an environment uses runs a step before the starter steps", [used])
        else:
            # Each action is read once however many use it, the actions a composite one uses after
            # the ones the jobs use, and none deeper than the judgement reads.
            runs_of, waiting = {}, [(uses, 1) for uses in used]
            while waiting:
                uses, depth = waiting.pop(0)
                if uses in runs_of:
                    continue
                # owner/repository@pin, or owner/repository/folder@pin for an action in a folder.
                name, _, pin = uses.partition("@")
                parts = name.split("/")
                where = "/".join(parts[:2] + [pin] + parts[2:])
                try:
                    text = fetch("https://raw.githubusercontent.com/%s/action.yml" % where, "text/plain")
                except urllib.error.HTTPError as e:
                    if e.code != 404:
                        raise
                    text = fetch("https://raw.githubusercontent.com/%s/action.yaml" % where, "text/plain")
                read = parsed(text)
                runs_of[uses] = read.get("runs") if isinstance(read, dict) else None
                if depth < NESTED_DEPTH:
                    waiting += [(each, depth + 1) for each in (actions_inside(runs_of[uses]) or []) if PINNED_ACTION.match(each)]
            clause("no action a job in an environment uses runs a step before the starter steps", judge_no_pre_step(runs_of, used))

        clause("the release environment admits runs from main alone, administrators included",
               judge_environment(api("environments/release"), api("environments/release/deployment-branch-policies")))
        # Who entered the signing environments; what this sees and cannot see is written beside
        # DEPLOYMENT_ENVIRONMENTS. Statuses are read only where the judgement turns on them, so a run
        # with no token stays well inside the 60 requests an hour GitHub allows one; today that is two.
        deployments = {e: api("deployments?environment=%s&per_page=100" % e) for e in DEPLOYMENT_ENVIRONMENTS}
        statuses = {str(d.get("id")): api("deployments/%s/statuses?per_page=100" % urllib.parse.quote(str(d.get("id")), safe=""))
                    for listed in deployments.values() if isinstance(listed, list) for d in listed if statuses_needed(d)}
        clause("since the policy was set, only an account written down as starting releases asked to enter release or "
               "linux-signing, and only from main did one get in", judge_deployments(deployments, statuses))

        listed = api("rulesets?includes_parents=false")
        clause("every ruleset written down here is on the repository", judge_rulesets_present([r["name"] for r in listed]))
        for summary in listed:
            problems, seen = judge_ruleset(summary["name"], api("rulesets/%d" % summary["id"]))
            clause("ruleset [%s] is as written here" % summary["name"], problems)
            if not seen:
                unseen("ruleset [%s]" % summary["name"], "who may bypass it is shown only to an administrator")
        clause("every tag that stands is named as a release tag", judge_tags(api("git/matching-refs/tags/")))

        clause("main is protected, and its required build holds everyone", judge_protection(api("branches/main")))
        clause("the token Azure trusts names this repository as written here", judge_subject(api("actions/oidc/customization/sub")))

        unless_hidden("every action a workflow uses is named by a full commit", "repos/%s/actions/permissions" % REPO,
                      judge_actions_permissions)
        unless_hidden("the repository is administered by the accounts written here, and nobody else",
                      "repos/%s/collaborators?permission=admin&per_page=100" % REPO, judge_administrators,
                      shown=administrators_shown)
        unless_hidden("the release environment holds no secret but the ones release.yml reads, and none an older run of it reads",
                      "repos/%s/environments/release/secrets?per_page=100" % REPO,
                      lambda listed: release_listed.append(listed) or judge_secret_names(listed, "the release environment", RELEASE_SECRETS))
        unless_hidden("the repository holds no secret, so no signing value is read outside the release environment",
                      "repos/%s/actions/secrets?per_page=100" % REPO,
                      lambda listed: judge_secret_names(listed, "the repository", REPOSITORY_SECRETS))
        unless_hidden("the organisation shares no secret, so no signing value is read outside the release environment",
                      "repos/%s/actions/organization-secrets?per_page=100" % REPO,
                      lambda listed: judge_secret_names(listed, "the organisation", ORGANISATION_SECRETS))
        unless_hidden("no environment but release holds a secret", "repos/%s/environments?per_page=100" % REPO,
                      judge_other_environments, read=other_environments)
        unless_hidden("the repository holds no Dependabot secret", "repos/%s/dependabot/secrets?per_page=100" % REPO,
                      lambda listed: judge_secret_names(listed, "the repository's Dependabot secrets", DEPENDABOT_SECRETS))
        unless_hidden("the organisation holds no Dependabot secret under a signing name",
                      "orgs/%s/dependabot/secrets?per_page=100" % ORG, judge_shared_dependabot)

        # Shown to the organisation's owners alone, and left out for anybody else rather than refused.
        required = github("orgs/%s" % ORG).get("two_factor_requirement_enabled")
        if required is None:
            ran.append("the organisation requires two-factor sign-in of every member")
            unseen("the organisation requires two-factor sign-in of every member", "GitHub shows this only to an owner")
        else:
            clause("the organisation requires two-factor sign-in of every member",
                   [] if required is True else ["it does not, so one administrator's password alone starts a signed release"])
        # Shown to the organisation's owners alone. The organisation's own apps are installed on it, so
        # an empty list is taken for hidden where the Actions settings were hidden as well.
        unless_hidden("no app installed on the organisation holds a write that reaches this repository's signing route",
                      "orgs/%s/installations?per_page=100" % ORG, lambda read: judge_installations(*read),
                      read=installations, shown=lambda read: not (isinstance(read[0], dict) and read[0].get("total_count") == 0))
    except (OSError, urllib.error.URLError, ValueError, KeyError) as e:
        say("FAIL", "the settings could not all be read: %s" % e)

    if azure is None:
        ran.append("the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there")
        # The Entra app is the one boundary on Windows signing that no GitHub token reads. So, once
        # anything Windows signing reads is stored, the Azure identifiers included, the administrator's
        # run fails here without an Azure file, and so does the one made before the first signing value.
        unread = judge_azure_unread(release_listed[0] if release_listed else None) if need_admin else []
        if unread:
            say("FAIL", "the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there: %s"
                % "; ".join(unread))
        else:
            say("UNSEEN", "the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there: no GitHub "
                          "token reads it, and no --azure file was given")
    else:
        try:
            with open(azure, encoding="utf-8") as f:
                app = json.load(f)
            problems = judge_azure(app) if isinstance(app, dict) else ["%s is not one JSON object" % azure]
        except (OSError, ValueError, TypeError, AttributeError) as e:
            problems = ["%s could not be read: %s" % (azure, e)]
        clause("the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there", problems)
        if not problems and app.get("role_assignments") == []:
            print("NOTE: the Entra app holds no role yet, so Windows signing is not armed", flush=True)
    return (1 if "FAIL" in results else 0), ran


# The self-test's own shapes.

def self_test(need_yaml=False):
    wrong = []

    def held(*names):
        """GitHub's answer for a level holding these secrets."""
        return {"total_count": len(names), "secrets": [{"name": n} for n in names]}

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
    moves_main = RULESETS["Only an administrator moves main"]
    expect("the main ruleset bypassed by a push rather than a pull request",
           judge_ruleset("Only an administrator moves main", dict(moves_main, bypass_actors=[dict(ADMIN, bypass_mode="always")]))[0], True)
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
    expect("the default subject, naming the environment alone", judge_subject(
        {"use_default": True, "use_immutable_subject": True, "sub_claim_prefix": OIDC_SUBJECT["sub_claim_prefix"]}), True)
    expect("a subject missing the ref", judge_subject(dict(OIDC_SUBJECT, include_claim_keys=["repo", "context", "job_workflow_ref"])), True)
    expect("a subject missing the workflow", judge_subject(dict(OIDC_SUBJECT, include_claim_keys=["repo", "context", "ref"])), True)
    expect("a subject without the numbers", judge_subject(dict(OIDC_SUBJECT, use_immutable_subject=False)), True)
    for label, claims, entered, refused in (
            ("sign-windows' token as it is", {"sub": token_subject("release")}, "release", False),
            ("publish's token as it is", {"sub": token_subject("linux-signing")}, "linux-signing", False),
            ("a token from another branch", {"sub": token_subject("release").replace(":ref:refs/heads/main:", ":ref:refs/heads/other:")}, "release", True),
            ("a token missing the ref", {"sub": token_subject("release").replace(":ref:refs/heads/main:", ":")}, "release", True),
            ("a token naming another workflow", {"sub": token_subject("release").replace("/release.yml@", "/other.yml@")}, "release", True),
            ("a token naming the environment alone", {"sub": OIDC_SUBJECT["sub_claim_prefix"] + ":environment:release"}, "release", True),
            ("sign-windows' token held as publish's", {"sub": token_subject("release")}, "linux-signing", True),
            ("a token with no subject", {}, "release", True),
            ("claims that are not a mapping", ["sub"], "release", True)):
        expect(label, judge_token(claims, entered), refused)

    # The token is asked for as a job asks for one. Its signature is not checked: only its subject is
    # compared, and nothing is signed with it here.
    asked, given = [], ["s"]

    def opener(request, timeout):
        asked.append((request.full_url, request.get_header("Authorization")))
        payload = base64.urlsafe_b64encode(json.dumps({"sub": given[0]}).encode("utf-8")).decode("ascii").rstrip("=")
        return io.BytesIO(json.dumps({"value": "h.%s.sig" % payload}).encode("utf-8"))

    def asked_in_a_job(subject, audience, entered):
        """What `--token-subject` says in a job GitHub gives a token naming `subject`."""
        given[0], out, real = subject, io.StringIO(), urllib.request.urlopen
        urllib.request.urlopen = opener
        try:
            with contextlib.redirect_stdout(out):
                code = main(["--token-subject", audience, entered])
        finally:
            urllib.request.urlopen = real
        return code, out.getvalue().strip()
    runner = {"ACTIONS_ID_TOKEN_REQUEST_URL": "https://runner.invalid/token?api-version=2.0",
              "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "b"}
    saved = {k: os.environ.get(k) for k in runner}
    try:
        os.environ.update(runner)
        if token_claims("api://AzureADTokenExchange", opener) != {"sub": "s"} or asked != [(
                "https://runner.invalid/token?api-version=2.0&audience=api%3A%2F%2FAzureADTokenExchange", "Bearer b")]:
            wrong.append("a token asked for: read as %s" % asked)
        for label, subject, audience, entered, code in (
                ("sign-windows given its own subject", token_subject("release"), "api://AzureADTokenExchange", "release", 0),
                ("publish given its own subject", token_subject("linux-signing"), "sigstore", "linux-signing", 0),
                ("sign-windows given a subject naming the environment alone",
                 OIDC_SUBJECT["sub_claim_prefix"] + ":environment:release", "api://AzureADTokenExchange", "release", 1),
                ("publish given sign-windows' subject", token_subject("release"), "sigstore", "linux-signing", 1)):
            said = asked_in_a_job(subject, audience, entered)
            if said[0] != code or said[1].startswith("PASS: ") == bool(code) or subject not in said[1]:
                wrong.append("--token-subject, %s: judged %s" % (label, said))
        del os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        if asked_in_a_job(token_subject("release"), "api://AzureADTokenExchange", "release")[0] != 1:
            wrong.append("--token-subject in a job that may not ask for a token: passed")
        try:
            token_claims("sigstore", opener)
            wrong.append("a job that may not ask for a token: read one")
        except ValueError:
            pass
        except Exception as e:
            wrong.append("a job that may not ask for a token: %r" % e)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

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
    expect("publish entering no environment", judge_environment_users(dict(workflows, **{"release.yml": release.replace("    environment: linux-signing\n", "", 1)})), True)
    expect("publish entering release", judge_environment_users(dict(workflows, **{"release.yml": release.replace("    environment: linux-signing\n", "    environment: release\n", 1)})), True)
    expect("sign-windows entering linux-signing", judge_environment_users(dict(workflows, **{"release.yml": release.replace("    runs-on: windows-2022\n    environment: release\n", "    runs-on: windows-2022\n    environment: linux-signing\n", 1)})), True)
    expect("another workflow entering linux-signing", judge_environment_users(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    environment: linux-signing\n"})), True)
    with open(SIGNATURE_CHECK, encoding="utf-8") as f:
        check_text = f.read()
    ours = token_subject("linux-signing")
    expect("the signature check as it is", judge_linux_subject(check_text), False)
    expect("the signature check held to sign-windows' subject", judge_linux_subject(check_text.replace(ours, token_subject("release"))), True)
    expect("the signature check held to a job in no environment", judge_linux_subject(check_text.replace(
        ours, OIDC_SUBJECT["sub_claim_prefix"] + ":ref:refs/heads/main:ref:refs/heads/main:job_workflow_ref:" + RELEASE_WORKFLOW_REF)), True)
    expect("the signature check held to the environment alone", judge_linux_subject(check_text.replace(
        ours, OIDC_SUBJECT["sub_claim_prefix"] + ":environment:linux-signing")), True)
    expect("the signature check held to the default subject", judge_linux_subject(check_text.replace(ours, "repo:Fountech-ai-Limited/timewitness:environment:linux-signing")), True)
    expect("the signature check with no subject", judge_linux_subject(check_text.replace("LINUX_SUBJECT = ", "OTHER_SUBJECT = ")), True)
    expect("the build job entering release", judge_environment_users(dict(workflows, **{"release.yml": release.replace("    needs: tag\n    runs-on: ${{ matrix.runner }}\n", "    needs: tag\n    runs-on: ${{ matrix.runner }}\n    environment: release\n", 1)})), True)
    # Written so no line holds a key the patterns know, which only a parse takes apart.
    flow_job = "jobs:\n  steal: {runs-on: ubuntu-latest, environment: release}\n"
    flow_step = release.replace("      - name: Say so when it cannot be signed\n",
                                "      - {uses: Swatinem/rust-cache@v2}\n      - name: Say so when it cannot be signed\n", 1)
    if yaml is None:
        parse_shapes_run = False
    else:
        parse_shapes_run = True
        expect("another workflow entering release from a flow mapping", judge_environment_users(dict(workflows, **{"x.yml": flow_job})), True)
        expect("a toolchain cache in release.yml as a flow mapping", judge_no_cache(flow_step), True)
        expect("a workflow that is not YAML", judge_environment_users(dict(workflows, **{"x.yml": "jobs: [\n"})), True)
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

    # A reusable workflow from another repository enters whatever environment it names.
    foreign = "someone-else/tools/.github/workflows/sign.yml@" + "0" * 40
    expect("no workflow calls one from another repository", judge_reusable(workflows), False)
    expect("a job calling another repository's workflow", judge_reusable(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    uses: %s\n" % foreign})), True)
    expect("the same, its key quoted", judge_reusable(dict(workflows, **{"x.yml": "jobs:\n  steal:\n    'uses': '%s'\n" % foreign})), True)
    expect("a job calling a workflow of this repository", judge_reusable(dict(workflows, **{"x.yml": "jobs:\n  mine:\n    uses: ./.github/workflows/ci.yml\n"})), False)
    if parse_shapes_run:
        expect("a job calling another repository's workflow from a flow mapping",
               judge_reusable(dict(workflows, **{"x.yml": "jobs:\n  steal: {uses: %s}\n" % foreign})), True)

    # Who may start a release: the account written down, by its name in any case and its number.
    (login, number), = RELEASE_STARTERS.items()
    expect("the account written down", judge_starter(login, str(number)), False)
    expect("the account written down, its name in another case", judge_starter(login.upper(), number), False)
    expect("another administrator", judge_starter("nicolekairo", "236548393"), True)
    expect("the name written down on another account", judge_starter(login, "1"), True)
    expect("nobody", judge_starter("", ""), True)
    expect("the guard as it is", judge_guard(release), False)
    expect("the guard asking nobody who may start", judge_guard(re.sub(r"\n\s+python3 scripts/the-release-route-holds\.py --may-start.*\n.*\n", "\n", release, count=1)), True)
    expect("the guard not reading the account's number", judge_guard(release.replace('actor_id="$(gh api "users/$ACTOR" --jq .id)"', 'actor_id=0', 1)), True)
    expect("the guard not checking out this file", judge_guard(release.replace("            scripts/the-release-route-holds.py\n", "", 1)), True)
    expect("the guard letting any role start", judge_guard(release.replace('[ "$role" = admin ] || refuse ', 'true || refuse ', 1)), True)
    # What acts on the compare's answer: the refusal and the repository it asks.
    for label, old, new in (
            ("refusing and carrying on", '            exit 1\n          }\n', '            return 0\n          }\n'),
            ("asking another repository", "          REPO: ${{ github.repository }}\n", "          REPO: someone-else/timewitness\n"),
            ("given one more variable", "          REPO: ${{ github.repository }}\n",
             "          REPO: ${{ github.repository }}\n          BASH_ENV: ./answers.sh\n")):
        if release.count(old) < 1:
            wrong.append("the guard %s: the text it changes is not in release.yml" % label)
        expect("the guard %s" % label, judge_guard(release.replace(old, new, 1)), True)
    # The guard job held whole: anything that could stand a `gh` of its own in front of the compare, in
    # the guard step, on the job or in a step before it, and anything else that changes the job. Each
    # changed file still reads as YAML, so none is refused only for being unreadable.
    expect("the guard job as written down", judge_guard_held(release), False)
    expect("a release.yml with no guard job", judge_guard_held(release.replace("\n  guard:\n", "\n  guarded:\n", 1)), True)
    expect("a release.yml that is not YAML", judge_guard_held(release + "jobs: [\n"), True)
    first_line = '          [ "$EVENT" = workflow_dispatch ] || refuse '
    job_head = "  guard:\n    name: may this run build and sign\n    runs-on: ubuntu-latest\n"
    guard_id = "      - id: guard\n"
    job_end = "          } >> \"$GITHUB_OUTPUT\"\n\n  tag:\n"
    sparse = "          persist-credentials: false\n          sparse-checkout: |\n"
    for label, old, new in (
            ("defining gh, which answers every compare", first_line, '          gh() { echo identical; }\n' + first_line),
            ("defining gh with the function keyword", first_line, '          function gh { echo identical; }\n' + first_line),
            ("defining gh on a line of its own after another command", first_line,
             '          true; gh () { echo identical; }\n' + first_line),
            ("defining refuse a second time", first_line, '          refuse() { echo "$1"; }\n' + first_line),
            ("aliasing gh", first_line, "          alias gh='echo identical'\n" + first_line),
            ("running refuse past itself with command", '            *) refuse "$TAG is on',
             '            *) command refuse "$TAG is on'),
            ("reaching a builtin past a function", first_line, '          builtin echo ready\n' + first_line),
            ("switching a builtin off", first_line, '          enable -n exit\n' + first_line),
            ("making gh with eval", first_line, "          eval 'gh() { echo identical; }'\n" + first_line),
            ("sourcing a file", first_line, "          source ./answers.sh\n" + first_line),
            ("sourcing a file with a dot", first_line, "          . ./answers.sh\n" + first_line),
            ("putting a folder of its own first on the path", first_line, '          export PATH="$PWD/bin:$PATH"\n' + first_line),
            ("setting the path with no export", first_line, "          PATH=/tmp/b:$PATH\n" + first_line),
            ("pointing gh elsewhere with hash", first_line, "          hash -p /tmp/b/gh gh\n" + first_line),
            ("passing every failure with a trap", first_line, "          trap 'exit 0' ERR\n" + first_line),
            ("turning every refusal into a success with a trap on exit", first_line,
             "          trap 'echo tag=$TAG >> \"$GITHUB_OUTPUT\"; exit 0' EXIT\n" + first_line),
            ("given BASH_ENV for every step", job_head, job_head + "    env:\n      BASH_ENV: /tmp/answers.sh\n"),
            ("given a shell of its own for every step", job_head,
             job_head + "    defaults:\n      run:\n        shell: bash --rcfile /tmp/answers.sh {0}\n"),
            ("run in a container", job_head, job_head + "    container: ubuntu:24.04\n"),
            ("carrying on whatever it meets", job_head, job_head + "    continue-on-error: true\n"),
            ("run on a runner of its own", job_head, job_head.replace("ubuntu-latest", "self-hosted")),
            ("handing on an output of its own", "      apple_team: ${{ steps.guard.outputs.apple_team }}\n",
             "      apple_team: identical\n"),
            ("after a step that writes BASH_ENV to GITHUB_ENV", guard_id,
             "      - run: echo BASH_ENV=/tmp/answers.sh >> \"$GITHUB_ENV\"\n" + guard_id),
            ("after a step that writes a folder to GITHUB_PATH", guard_id,
             "      - run: echo /tmp/b >> \"$GITHUB_PATH\"\n" + guard_id),
            ("with a step after the guard", job_end, "          } >> \"$GITHUB_OUTPUT\"\n      - run: echo after\n\n  tag:\n"),
            ("checking out another ref", sparse, "          ref: someone-else\n" + sparse),
            ("the guard step given a shell of its own", guard_id + "        env:\n",
             guard_id + "        shell: bash --rcfile /tmp/answers.sh {0}\n        env:\n")):
        if release.count(old) < 1:
            wrong.append("the guard job %s: the text it changes is not in release.yml" % label)
        changed = release.replace(old, new, 1)
        if parse_shapes_run and not isinstance(guard_job(changed), dict):
            wrong.append("the guard job %s: release.yml no longer reads as a workflow with a guard job" % label)
        expect("the guard job %s" % label, judge_guard_held(changed), True)
    # Main asked for by name, which a tag called `main` answers before the branch does.
    for label, old, new in (
            ("comparing the tag with main by name", "compare/$commit...$main_commit", "compare/$commit...main"),
            ("comparing the tag with the branch by its full name", "compare/$commit...$main_commit", "compare/$commit...refs/heads/main"),
            ("reading main's commit by name", "git/ref/heads/main", "commits/main"),
            ("reading main's commit and carrying on when it cannot",
             '--jq .object.sha)" || refuse "could not read the commit main is on"', '--jq .object.sha)" || true'),
            ("not refusing a main read as something other than a commit", '[[ "$main_commit" =~ ^[0-9a-f]{40}$ ]] || refuse ',
             '[[ "$main_commit" =~ ^[0-9a-f]* ]] || refuse '),
            ("comparing twice, once with main by name", '          case "$on_main" in\n',
             '          gh api "repos/$REPO/compare/$commit...main" >/dev/null\n          case "$on_main" in\n'),
            ("setting main to its name before the compare", '          on_main="$(gh api',
             '          main_commit=main\n          on_main="$(gh api'),
            ("exporting the tag's commit again after the compare", '          rehearsal="${REHEARSAL:-false}"\n',
             '          export commit=$main_commit\n          rehearsal="${REHEARSAL:-false}"\n'),
            ("setting the answer before it is read", '          case "$on_main" in\n',
             '          on_main=ahead\n          case "$on_main" in\n'),
            ("reading the tag's commit in again after the compare", '          rehearsal="${REHEARSAL:-false}"\n',
             '          read -r commit <<< "$main_commit"\n          rehearsal="${REHEARSAL:-false}"\n'),
            ("setting the tag's commit again after the compare", '          rehearsal="${REHEARSAL:-false}"\n',
             '          commit="$(gh api "repos/$REPO/commits/$TAG" --jq .sha)"\n          rehearsal="${REHEARSAL:-false}"\n'),
            ("taking every answer the compare gives", "            ahead|identical) ;;", "            ahead|identical|behind|diverged) ;;"),
            ("carrying on past a commit not on main", '            *) refuse "$TAG is on', '            *) echo "$TAG is on'),
            ("reading the tag by its short name", 'commits/refs/tags/$TAG', 'commits/$TAG'),
            ("not refusing a tag read as something other than a commit", '[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || refuse ',
             '[[ "$commit" =~ . ]] || refuse ')):
        if release.count(old) < 1:
            wrong.append("the guard %s: the text it changes is not in release.yml" % label)
        expect("the guard %s" % label, judge_guard(release.replace(old, new, 1)), True)
    tag_rulesets = {n: r for n, r in RULESETS.items() if r["target"] == "tag"}
    expect("the tag rulesets as written", judge_tag_rulesets(RULESETS), False)
    for label, name, change in (
            ("a tag outside v* made by anybody", "Only a release tag can be made", {"conditions": {"ref_name": {"exclude": ["refs/tags/*"], "include": ["~ALL"]}}}),
            ("a tag outside v* made by an administrator", "Only a release tag can be made", {"bypass_actors": [dict(ADMIN, bypass_mode="always")]}),
            ("a tag outside v* refused only in evaluation", "Only a release tag can be made", {"enforcement": "evaluate"}),
            ("a tag outside v* moved rather than made", "Only a release tag can be made", {"rules": [{"type": "update"}]}),
            ("every branch outside v*, in place of every tag", "Only a release tag can be made", {"target": "branch"}),
            ("a pre-release tag made by anybody", "Only an administrator makes a release tag",
             {"conditions": {"ref_name": {"exclude": ["refs/tags/v*-*"], "include": ["refs/tags/v*"]}}}),
            ("a release tag made by anybody who can write", "Only an administrator makes a release tag",
             {"bypass_actors": [{"actor_id": 4, "actor_type": "RepositoryRole", "bypass_mode": "always"}]})):
        expect("the tag rulesets with %s" % label, judge_tag_rulesets(dict(tag_rulesets, **{name: dict(RULESETS[name], **change)})), True)
    expect("the tag rulesets with every tag outside v* left out", judge_tag_rulesets(
        {n: r for n, r in RULESETS.items() if n != "Only a release tag can be made"}), True)
    tags = [{"ref": "refs/tags/v0"}, {"ref": "refs/tags/v0.6"}, {"ref": "refs/tags/v0.7-rc1"}]
    expect("the tags as they stand", judge_tags(tags), False)
    for label, listed in (("a tag called main", tags + [{"ref": "refs/tags/main"}]),
                          ("a tag whose name starts with anything but v", tags + [{"ref": "refs/tags/release-1"}]),
                          ("a tag whose name starts with v and is no release", tags + [{"ref": "refs/tags/vmain"}]),
                          ("a tag whose name holds a folder", tags + [{"ref": "refs/tags/v/x"}]),
                          ("a list that is not one", {"message": "x"}), ("an empty answer that is not a list", {}),
                          ("a tag with no name", tags + [{}]), ("a tag that is not one", tags + ["refs/tags/v1"])):
        expect("the tags with %s" % label, judge_tags(listed), True)

    # The secrets release.yml reads, and none an older run of it reads.
    expect("the secrets as they are", judge_secrets_read(release), False)
    expect("an Apple value read under its old name", judge_secrets_read(release + "\n# ${{ secrets.APPLE_TEAM_ID }}\n"), True)
    expect("a signing value no longer read", judge_secrets_read(release.replace("secrets.MACOS_NOTARY_ISSUER_ID", "secrets.OTHER")), True)

    # A release is a draft until it is whole, and goes only onto the commit built.
    expect("the Attach step as it is", judge_attach(release), False)
    expect("a release made public before its files", judge_attach(release.replace("-F draft=true ", "-F draft=false ", 1)), True)
    expect("a release made by gh release create, with no number kept", judge_attach(release.replace(
        'made="$(gh api -X POST "repos/$REPO/releases"', 'gh release create "$TAG" --draft; made="$(gh api -X POST "repos/$REPO/releases"', 1)), True)
    expect("a draft published before the tag is read again", judge_attach(release.replace(
        "            names_what_was_built\n            gh api -X PATCH", "            gh api -X PATCH", 1)), True)
    expect("a draft published without holding it to every file", judge_attach(release.replace(
        'if [ "$(cat carried.txt)" != "$(ls dist | sort | xargs)" ]', "if false", 1)), True)
    expect("files on a public release not held to the tag read again", judge_attach(release.replace(
        'upload_to "$number"\n            names_what_was_built\n', 'upload_to "$number"\n', 1)), True)
    expect("files uploaded to whichever release answers to the tag", judge_attach(release.replace(
        'upload_to "$made"\n', 'gh release upload "$TAG" --repo "$REPO" dist/*\n', 1)), True)
    expect("each file handed to whichever release answers to the tag", judge_attach(release.replace(
        "/releases/$1/assets?name=", "/releases/tags/$TAG/assets?name=", 1)), True)
    expect("a release that cannot be read taken for a draft", judge_attach(release.replace("|| state=unread", "|| state=true", 1)), True)
    expect("the Attach step as written down, to the byte", judge_attach_pinned(release), False)
    expect("the Attach step changed by one space", judge_attach_pinned(release.replace(
        "not every file packed for it", "not every  file packed for it", 1)), True)
    expect("the Attach step's condition changed", judge_attach_pinned(release.replace(
        "      - name: Attach\n        if: steps.decide.outputs.published == 'true'\n",
        "      - name: Attach\n        if: always()\n", 1)), True)
    expect("the tag's commit read and not compared", judge_attach(release.replace('[ "$now" != "$COMMIT" ]', '[ -z "$now" ]', 1)), True)
    expect("the Attach step not given the commit built", judge_attach(release.replace("          COMMIT: ${{ needs.tag.outputs.commit }}\n", "", 1)), True)
    expect("nothing taken off when a run stops partway", judge_attach(release.replace("trap undo EXIT", "true", 1)), True)
    # The guard reads the release the same way, earlier in the file, so the Attach step's is the last.
    expect("a failure to read the release taken for there being none", judge_attach("elif true; then".join(
        release.rsplit('elif [ "$(cat release.err)" = "release not found" ]; then', 1))), True)
    expect("the undo armed before the refusals", judge_attach(release.replace("            attaching=true\n", "", 1)), True)
    expect("a release deleted without asking whether it is still a draft", judge_attach(release.replace(
        'if [ "$state" = true ]; then', "if true; then", 1)), True)
    expect("files taken off that were there before this run", judge_attach(release.replace(
        ' && ! grep -qx "$id" before.txt && ! grep', ' && ! grep', 1)), True)
    expect("a release deleted by its tag", judge_attach(release.replace(
        'gh api -X DELETE "repos/$REPO/releases/$made"', 'gh release delete "$TAG" --yes', 1)), True)
    expect("uploads that keep no number", judge_attach(release.replace("--jq .id 2> upload.err", "--jq .name 2> upload.err", 1)), True)
    expect("what gh printed for an upload kept whatever it was", judge_attach(release.replace(
        'if a_number "$answer"; then', "if true; then", 1)), True)
    expect("anything at all taken for a number", judge_attach(release.replace(
        'a_number() { [[ "$1" =~ ^[0-9]+$ ]]; }', "a_number() { [ -n \"$1\" ]; }", 1)), True)
    expect("what gh printed for a draft taken for its number", judge_attach(release.replace(
        '            if ! a_number "$made"; then', "            if false; then", 1)), True)
    expect("an upload that got no number back passed over", judge_attach(release.replace(
        "              exit 1\n            done\n          }", "              continue\n            done\n          }", 1)), True)
    expect("a lost draft looked for only when nothing was printed for it", judge_attach(release.replace(
        'if ! a_number "$made" && [ "$asked" = true ]; then', 'if [ -z "$made" ] && [ "$asked" = true ]; then', 1)), True)
    expect("a draft read and deleted by whatever was printed for it", judge_attach(release.replace(
        'if a_number "$made"; then', 'if [ -n "$made" ]; then', 1)), True)
    expect("a DELETE sent for a line that is not a number", judge_attach(release.replace(
        '              a_number "$id" || continue\n', "", 1)), True)
    expect("the uploads that got no number back worked out from nothing", judge_attach(release.replace(
        "grep -vxF -f answered.txt tried.txt > lost.txt", "grep -vxF -f tried.txt tried.txt > lost.txt", 1)), True)
    expect("a grep that fails taken for no upload having got no number back", judge_attach(release.replace(
        " || [ $? = 1 ] || cp tried.txt lost.txt", " || true", 1)), True)
    expect("the uploads answered never started afresh", judge_attach(release.replace("          : > answered.txt\n", "", 1)), True)
    expect("an upload counted as answered before its answer is read", judge_attach(release.replace(
        '              if a_number "$answer"; then\n                echo "$answer" >> uploaded.txt\n                basename "$f" >> answered.txt\n',
        '              basename "$f" >> answered.txt\n              if a_number "$answer"; then\n                echo "$answer" >> uploaded.txt\n', 1)), True)
    expect("the search for a lost upload stopped while one is still missing", judge_attach(release.replace(
        '[ -z "$(grep -vxF -f found.txt lost.txt)" ] && break', '[ -z "$(grep -vxF -f found.txt lost.txt)" ] || break', 1)), True)
    expect("uploads not counted before each is sent", judge_attach(release.replace('              basename "$f" >> tried.txt\n', "", 1)), True)
    expect("a file whose upload got no answer looked for once", judge_attach(release.replace("for try in 1 2 3; do", "for try in 1; do", 1)), True)
    expect("files taken off by name, not by the numbers the uploads answered with", judge_attach(release.replace(
        "done < uploaded.txt", "done < /dev/null", 1)), True)
    expect("a file of one of our names taken off whoever put it there", judge_attach(release.replace(
        'if [ "$who" = "$ours" ] && ! grep', 'if ! grep', 1)), True)
    expect("a file taken off that this run's own upload answered for and another took the place of", judge_attach(release.replace(
        ' && ! grep -qx "$id" uploaded.txt && grep -qxF', ' && grep -qxF', 1)), True)
    expect("a file taken off whose upload was answered and not lost", judge_attach(release.replace(
        ' && grep -qxF "$name" lost.txt; then', ' && [ -f "dist/$name" ]; then', 1)), True)
    expect("this workflow's account taken to be anybody", judge_attach(release.replace('ours="github-actions[bot]"', 'ours="$(whoami)"', 1)), True)
    expect("a draft whose answer was lost looked for without asking whether one was asked for", judge_attach(release.replace(
        "            asked=true\n", "", 1)), True)
    expect("any draft on the tag taken for the one this run asked for", judge_attach(release.replace(
        ' and .author.login == \\"$ours\\" and .updated_at >= \\"$began\\"', "", 1)), True)
    expect("a draft whose answer was lost looked for once, before the list shows it", judge_attach(release.replace(
        "[ -s drafts.txt ] && break", "break", 1)), True)
    expect("the first of several drafts taken for the one this run asked for", judge_attach(release.replace(
        'if [ "$(grep -c . drafts.txt)" = 1 ]; then', 'if [ -s drafts.txt ]; then', 1)), True)

    # Every job that enters an environment asks about whoever started it, as the guard does.
    expect("every environment job asks who started it", judge_starter_steps(release), False)
    for job in ("tag", "sign-macos", "sign-windows", "publish"):
        at = release.index("\n  %s:\n" % job)
        cut = release.index("      - name: Started by an account written down as starting releases\n", at)
        end = release.index("\n      - ", cut + 10)
        expect("%s not asking who started it" % job, judge_starter_steps(release[:cut] + release[end + 1:]), True)
    asks = "      - name: Started by an account written down as starting releases\n"
    expect("a job's question skipped when the job is run again", judge_starter_steps(release.replace(
        asks, asks + "        if: github.run_attempt == 1\n", 1)), True)
    expect("a job's question whose failure is ignored", judge_starter_steps(release.replace(
        asks, asks + "        continue-on-error: true\n", 1)), True)
    expect("a job whose failures are all ignored", judge_starter_steps(release.replace(
        "\n  publish:\n", "\n  publish:\n    continue-on-error: true\n", 1)), True)
    expect("a job asking about an account named in its own step", judge_starter_steps(release.replace(
        '--may-start "$ACTOR" "$actor_id"\n', '--may-start nikkai1007 76212305\n', 2)), True)
    expect("a job asking about who first started the run", judge_starter_steps(release.replace(
        "          ACTOR: ${{ github.triggering_actor }}\n", "          ACTOR: ${{ github.actor }}\n")), True)
    expect("the guard asking about who first started the run", judge_guard(release.replace(
        "          ACTOR: ${{ github.triggering_actor }}\n", "          ACTOR: ${{ github.actor }}\n", 1)), True)

    # Each job that signs with a token holds its subject first, for its own audience and environment.
    holds = "      - name: The token this job signs with names main and release.yml\n"
    windows_holds = "--token-subject api://AzureADTokenExchange release\n"
    expect("each job that signs with a token holds its subject", judge_token_steps(release), False)
    for job in TOKEN_AUDIENCES:
        cut = release.index(holds, release.index("\n  %s:\n" % job))
        end = release.index("\n      - ", cut + 10)
        expect("%s not holding its token's subject" % job, judge_token_steps(release[:cut] + release[end + 1:]), True)
    expect("sign-windows holding the subject of a token for Sigstore", judge_token_steps(release.replace(
        windows_holds, "--token-subject sigstore release\n", 1)), True)
    expect("sign-windows holding its token to publish's environment", judge_token_steps(release.replace(
        windows_holds, "--token-subject api://AzureADTokenExchange linux-signing\n", 1)), True)
    expect("publish holding its token to sign-windows' environment", judge_token_steps(release.replace(
        "--token-subject sigstore linux-signing\n", "--token-subject sigstore release\n", 1)), True)
    expect("tag asking for a token", judge_token_steps(release.replace(
        "    environment: release\n    outputs:\n      tag: ", "    environment: release\n    permissions:\n      id-token: write\n"
        "    outputs:\n      tag: ", 1)), True)
    expect("sign-macos given every permission", judge_token_steps(release.replace(
        "    runs-on: macos-15\n    environment: release\n", "    runs-on: macos-15\n    environment: release\n    permissions: write-all\n", 1)), True)
    expect("a job given only what it reads", judge_token_steps(release.replace(
        "    runs-on: macos-15\n    environment: release\n", "    runs-on: macos-15\n    environment: release\n    permissions: read-all\n", 1)), False)
    expect("every job let ask for a token", judge_token_steps(release.replace(
        "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n", 1)), True)
    expect("a token's subject held only on the first run of a job", judge_token_steps(release.replace(
        holds, holds + "        if: github.run_attempt == 1\n", 1)), True)
    expect("a token's subject held after the binary is fetched", judge_token_steps(release.replace(
        "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
        "        with:\n          name: unsigned-x86_64-pc-windows-msvc\n", "", 1).replace(
        holds, "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
        "        with:\n          name: unsigned-x86_64-pc-windows-msvc\n          path: in\n" + holds, 1).replace(
        "          path: in\n      - name: Only what was expected\n", "      - name: Only what was expected\n", 1)), True)

    # The first starter step, which checks out the list as main has it now, held in each of its parts.
    expect("a job checking out the list without asking for main", judge_starter_steps(release.replace(
        "          ref: main\n          path: starter\n", "          path: starter\n", 1)), True)
    expect("a job checking out the list from another ref", judge_starter_steps(release.replace(
        "          ref: main\n          path: starter\n", "          ref: ${{ github.sha }}\n          path: starter\n", 1)), True)
    expect("a job checking out the list into another folder", judge_starter_steps(release.replace(
        "          ref: main\n          path: starter\n", "          ref: main\n          path: other\n", 1)), True)

    # Nothing in a job that enters an environment runs past a starter step that refused, and nothing
    # the job sets reaches the starter steps. Each shape is written after the job's starter steps.
    starter_end = '          "$py" starter/scripts/the-release-route-holds.py --may-start "$ACTOR" "$actor_id"\n'

    def after_starter(job, text):
        at = release.index(starter_end, release.index("\n  %s:\n" % job)) + len(starter_end)
        return release[:at] + text + release[at:]

    def job_sets(job, text):
        at = release.index("\n  %s:\n" % job) + len("\n  %s:\n" % job)
        return release[:at] + text + release[at:]

    expect("no environment job runs past its starter steps", judge_nothing_past_the_starter(release), False)
    expect("actions that run nothing when the job starts", judge_no_pre_step({"a/b@1": {"using": "node24", "main": "m.js", "post": "p.js"},
                                                                          "c/d@2": {"using": "composite", "steps": []}}), False)
    expect("an action that runs a step when the job starts", judge_no_pre_step({"a/b@1": {"using": "node24", "pre": "p.js", "main": "m.js"}}), True)
    expect("an action whose pre step says when it runs", judge_no_pre_step({"a/b@1": {"using": "node24", "pre-if": "always()", "main": "m.js"}}), True)
    expect("an action whose way of running cannot be read", judge_no_pre_step({"a/b@1": None}), True)
    expect("a container action that runs an entrypoint when the job starts", judge_no_pre_step(
        {"a/b@1": {"using": "docker", "image": "Dockerfile", "pre-entrypoint": "/pre.sh"}}), True)
    expect("the same, its way of running written in capitals", judge_no_pre_step(
        {"a/b@1": {"using": "Docker", "image": "docker://alpine:3.20", "pre-entrypoint": "/bin/sh"}}), True)
    # A composite action starts the pre steps of the actions it uses, as deep as they go.
    pin = "@" + "0123456789abcdef" * 2 + "01234567"
    clean = {"using": "node24", "main": "m.js", "post": "p.js"}

    def composite(*uses, using="composite"):
        return {"using": using, "steps": [{"run": "true", "shell": "bash"}] + [{"uses": u} for u in uses]}
    expect("a composite action over actions that run nothing when the job starts", judge_no_pre_step(
        {"c/d@2": composite("e/f" + pin, "g/h/in-a-folder" + pin), "e/f" + pin: clean, "g/h/in-a-folder" + pin: clean},
        ["c/d@2"]), False)
    for label, runs in (("a pre step", {"using": "node24", "pre": "p.js", "main": "m.js"}),
                        ("an entrypoint", {"using": "docker", "image": "Dockerfile", "pre-entrypoint": "/pre.sh"})):
        expect("a composite action over an action that runs %s when the job starts" % label, judge_no_pre_step(
            {"c/d@2": composite("e/f" + pin), "e/f" + pin: runs}, ["c/d@2"]), True)
        expect("the same, its way of running written in capitals", judge_no_pre_step(
            {"c/d@2": composite("e/f" + pin, using="Composite"), "e/f" + pin: runs}, ["c/d@2"]), True)
        expect("the same, three actions deep", judge_no_pre_step(
            {"c/d@2": composite("e/f" + pin), "e/f" + pin: composite("g/h" + pin), "g/h" + pin: runs}, ["c/d@2"]), True)
    expect("composite actions three deep over actions that run nothing when the job starts", judge_no_pre_step(
        {"c/d@2": composite("e/f" + pin), "e/f" + pin: composite("g/h" + pin), "g/h" + pin: clean}, ["c/d@2"]), False)
    expect("a composite action four deep, read or not", judge_no_pre_step(
        {"c/d@2": composite("e/f" + pin), "e/f" + pin: composite("g/h" + pin), "g/h" + pin: composite("i/j" + pin),
         "i/j" + pin: clean}, ["c/d@2"]), True)
    expect("a composite action over an action that was not read", judge_no_pre_step({"c/d@2": composite("e/f" + pin)}), True)
    for unpinned in ("e/f@v4", "e/f@" + "0" * 39, "e/f@" + "A" * 40, "./local", "docker://alpine:3.20", "e/f/../../x/y" + pin):
        expect("a composite action over [%s]" % unpinned, judge_no_pre_step(
            {"c/d@2": composite(unpinned), unpinned: clean}, ["c/d@2"]), True)
    expect("a composite action whose steps are not a list of steps", judge_no_pre_step({"c/d@2": {"using": "composite", "steps": ["x"]}}), True)
    expect("a composite action with no steps", judge_no_pre_step({"c/d@2": {"using": "composite"}}), True)
    expect("a composite action over an action named by a full commit and a line's end",
           judge_no_pre_step({"c/d@2": composite("e/f" + pin + "\n"), "e/f" + pin + "\n": clean}, ["c/d@2"]), True)
    # What the archive the runner reads can say otherwise than the file served here.
    expect("an action with a key in how it runs that this does not know", judge_no_pre_step(
        {"a/b@1": dict(clean, **{"$Format:%x70re$": "evil.js"})}), True)
    expect("an action run by a way this does not know", judge_no_pre_step(
        {"c/d@2": dict(composite("e/f" + pin), using="$Format:%x63omposite$"), "e/f" + pin: clean}, ["c/d@2"]), True)
    expect("a composite action with a step holding a key this does not know", judge_no_pre_step(
        {"c/d@2": {"using": "composite", "steps": [{"$Format:%x75ses$": "e/f" + pin}]}}), True)
    expect("a composite action whose steps hold only what a step may", judge_no_pre_step(
        {"c/d@2": {"using": "composite", "steps": [
            {"run": "true", "shell": "bash", "working-directory": "w", "env": {}},
            {"id": "i", "name": "n", "if": "true", "uses": "e/f" + pin, "with": {}, "continue-on-error": False}]},
         "e/f" + pin: dict(clean, using="Node24")}, ["c/d@2"]), False)
    # The runner builds a container action's image from its Dockerfile while it sets the job up.
    expect("a container action built from its Dockerfile", judge_no_pre_step({"a/b@1": {"using": "docker", "image": "Dockerfile"}}), True)
    expect("a container action whose image is only pulled", judge_no_pre_step(
        {"a/b@1": {"using": "docker", "image": "docker://alpine:3.20", "entrypoint": "/x", "args": [], "env": {}}}), False)
    if parse_shapes_run:
        expect("the actions release.yml's environment jobs use", [] if environment_job_actions(release) and all(
            "@" in u and not u.startswith("./") for u in environment_job_actions(release)) else ["read %s" % environment_job_actions(release)], False)
    for job, condition in (("sign-windows", "always()"), ("tag", "failure()"), ("publish", "${{ !cancelled() }}"),
                           ("sign-macos", "success() || !success()"), ("tag", "Always ()")):
        expect("a later step in %s run by [%s], reading a secret" % (job, condition), judge_nothing_past_the_starter(after_starter(
            job, "      - if: %s\n        env:\n          Z: ${{ secrets.MACOS_TEAM_ID }}\n        run: echo \"$Z\"\n" % condition)), True)
    expect("a later step whose failure is ignored", judge_nothing_past_the_starter(after_starter(
        "publish", "      - run: true\n        continue-on-error: true\n")), True)
    expect("a later step that is not a mapping", judge_nothing_past_the_starter(after_starter(
        "publish", "      - just words\n")), True)
    for job, keys in (("sign-macos", "    container: ghcr.io/someone/tools:latest\n"),
                      ("tag", "    services:\n      side:\n        image: ghcr.io/someone/side:latest\n"),
                      ("tag", "    defaults:\n      run:\n        shell: sh\n"),
                      ("tag", "    env:\n      BASH_ENV: /tmp/x\n"),
                      ("publish", "    env:\n      PYTHONPATH: /tmp\n"),
                      ("sign-windows", "    env: ${{ fromJSON(needs.tag.outputs.tag) }}\n"),
                      ("sign-windows", "    if: always()\n"),
                      ("publish", "    strategy:\n      matrix:\n        x: [1]\n")):
        expect("%s setting [%s] for the whole job" % (job, keys.strip().splitlines()[0]), judge_nothing_past_the_starter(job_sets(job, keys)), True)
    expect("sign-macos given PYTHONPATH beside its own", judge_nothing_past_the_starter(release.replace(
        "    env:\n      TARGETS: ", "    env:\n      PYTHONPATH: /tmp\n      TARGETS: ", 1)), True)
    expect("tag run on a self-hosted runner", judge_nothing_past_the_starter(release.replace(
        "    needs: guard\n    runs-on: ubuntu-latest\n    environment: release\n", "    needs: guard\n    runs-on: self-hosted\n    environment: release\n", 1)), True)
    expect("sign-windows run on another Windows", judge_nothing_past_the_starter(release.replace(
        "    runs-on: windows-2022\n    environment: release\n", "    runs-on: windows-latest\n    environment: release\n", 1)), True)
    expect("a shell set for every job", judge_nothing_past_the_starter(release.replace(
        "\njobs:\n", "\ndefaults:\n  run:\n    shell: sh\njobs:\n", 1)), True)
    expect("BASH_ENV set for every job", judge_nothing_past_the_starter(release.replace(
        "\nenv:\n  CARGO_TERM_COLOR: always\n", "\nenv:\n  BASH_ENV: /tmp/x\n  CARGO_TERM_COLOR: always\n", 1)), True)
    if parse_shapes_run:
        # The starter steps first, and not anywhere: a step moved above them runs before anybody is asked.
        doc = yaml.safe_load(release)
        for job in ("tag", "publish"):
            steps = doc["jobs"][job]["steps"]
            doc["jobs"][job]["steps"] = [steps[2]] + steps[:2] + steps[3:]
            expect("%s running a step before its starter steps" % job, judge_starter_steps(yaml.safe_dump(doc, sort_keys=False)), True)
            doc["jobs"][job]["steps"] = steps
        # A step that runs past a refused starter step is refused wherever it sits in the job, not only
        # straight after the starter steps.
        for job, _ in ENVIRONMENT_JOBS:
            steps = doc["jobs"][job]["steps"]
            for where, at in (("last", len(steps)), ("in the middle", 2 + (len(steps) - 2) // 2)):
                for label, step in (("run by [always()]", {"if": "always()", "run": "echo"}),
                                    ("whose failure is ignored", {"run": "true", "continue-on-error": True})):
                    doc["jobs"][job]["steps"] = steps[:at] + [step] + steps[at:]
                    expect("a step in %s %s, %s" % (job, label, where),
                           judge_nothing_past_the_starter(yaml.safe_dump(doc, sort_keys=False)), True)
            doc["jobs"][job]["steps"] = steps
        # The workflow's own environment given as an expression rather than as names, and a job
        # given as a word rather than as a mapping.
        saved_env = doc["env"]
        doc["env"] = "${{ fromJSON(vars.EVERY_JOB) }}"
        expect("every job's environment given as an expression", judge_nothing_past_the_starter(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["env"] = saved_env
        saved_job = doc["jobs"]["tag"]
        doc["jobs"]["tag"] = "x"
        expect("an environment job given as a word", judge_nothing_past_the_starter(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["tag"] = saved_job

    if parse_shapes_run:
        # What carries the guard's answer to the jobs that act on it. Each shape still reads as YAML,
        # and each is refused by the clause it is listed under, so none passes for being unreadable
        # and none rests on another clause catching it.
        for judge in (judge_waits_on_guard, judge_route_joined, judge_commit_carried, judge_tag_and_build_held,
                      judge_folders_held):
            expect("%s over release.yml as it is" % judge.__name__, judge(release), False)
            expect("%s over a release.yml that is not YAML" % judge.__name__, judge(release + "jobs: [\n"), True)
        expect("every job written here reaching the guard", not_reaching_the_guard(
            {name: {"needs": needs} for name, needs in ROUTE_NEEDS.items()}), False)
        expect("two jobs waiting on each other and not on the guard", not_reaching_the_guard(
            {"guard": {}, "a": {"needs": "b"}, "b": {"needs": ["a"]}}) != ["a", "b"], False)
        expect("a job waiting on a job that waits on the guard", not_reaching_the_guard(
            {"guard": {}, "a": {"needs": ["b"]}, "b": {"needs": "guard"}}), False)
        expect("a job waiting on nothing", not_reaching_the_guard({"guard": {}, "a": {}}) != ["a"], False)
        expect("a job waiting on a guard that is not there", not_reaching_the_guard({"a": {"needs": "guard"}}) != ["a"], False)
        expect("a job waiting on a job that is not there", not_reaching_the_guard({"guard": {}, "a": {"needs": "z"}}) != ["a"], False)
        tag_needs = "  tag:\n    name: which tag, and what can be signed\n    needs: guard\n"
        guard_head = "\n  guard:\n    name: may this run build and sign\n"
        build_needs = "    needs: tag\n    runs-on: ${{ matrix.runner }}\n"
        tag_commit = "      commit: ${{ needs.guard.outputs.commit }}\n"
        build_ref = "          ref: ${{ needs.tag.outputs.commit }}\n"
        perm = "\npermissions:\n  contents: read\n"
        colour = "\nenv:\n  CARGO_TERM_COLOR: always\n"
        program = "    import hashlib, os, sys\n    whole = hashlib.sha256()\n"
        pack_head = "    needs: [tag, build]\n    runs-on: ubuntu-latest\n    outputs:\n      packed: "
        check_head = "    needs: [tag, publish]\n    if: needs.publish.outputs.published == 'true'\n"
        publish_needs = "    needs: [tag, sign-macos, sign-windows, pack-linux]\n"
        macos_needs = "    needs: [tag, build]\n    runs-on: macos-15\n"
        secrets_step = "      - id: secrets\n"
        build_step = '          cargo build --release --locked --bin timewitness --target "$TARGET"\n'
        windows_hold = "      - name: Say so when it cannot be signed\n"
        resolve = ("      - id: resolve\n        env:\n          GH_TOKEN: ${{ github.token }}\n          TAG: ${{ needs.guard.outputs.tag }}\n"
                   "          REPO: ${{ github.repository }}\n        run: |\n"
                   "          echo \"commit=$(gh api \"repos/$REPO/commits/refs/tags/$TAG\" --jq .sha)\" >> \"$GITHUB_OUTPUT\"\n")
        for judge, label, old, new in (
                (judge_waits_on_guard, "the tag job waiting on nothing", tag_needs, tag_needs.replace("needs: guard", "needs: []")),
                (judge_waits_on_guard, "the tag job waiting on the build", tag_needs, tag_needs.replace("needs: guard", "needs: build")),
                (judge_waits_on_guard, "the build waiting on nothing", build_needs, build_needs.replace("needs: tag", "needs: []")),
                (judge_waits_on_guard, "the check of what was attached waiting on nothing", check_head,
                 check_head.replace("needs: [tag, publish]", "needs: []")),
                (judge_waits_on_guard, "a job added that waits on nothing", guard_head,
                 "\n  early:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n" + guard_head),
                (judge_waits_on_guard, "no guard job", guard_head, guard_head.replace("guard:", "guarded:")),
                (judge_route_joined, "the tag job waiting on the guard and on a copy of it", tag_needs,
                 tag_needs.replace("needs: guard", "needs: [guard, guard2]")),
                (judge_route_joined, "a job added that waits on the guard", guard_head,
                 "\n  guard2:\n    needs: guard\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n" + guard_head),
                (judge_route_joined, "sign-macos waiting on the build alone", macos_needs, macos_needs.replace("[tag, build]", "[build]")),
                (judge_route_joined, "publish no longer waiting on the tag job", publish_needs, publish_needs.replace("[tag, ", "[")),
                (judge_route_joined, "the workflow given write on contents", perm, "\npermissions:\n  contents: write\n"),
                (judge_route_joined, "the workflow given write on Actions", perm, "\npermissions:\n  contents: read\n  actions: write\n"),
                (judge_route_joined, "the workflow given write on everything", perm, "\npermissions: write-all\n"),
                (judge_route_joined, "sign-macos given write on contents", macos_needs,
                 macos_needs + "    permissions:\n      contents: write\n"),
                (judge_route_joined, "publish given write on Actions", "      contents: write\n      id-token: write\n",
                 "      contents: write\n      id-token: write\n      actions: write\n"),
                (judge_route_joined, "CARGO_TERM_COLOR given a value of its own", colour,
                 "\nenv:\n  CARGO_TERM_COLOR: $(gh() { echo identical; })\n"),
                (judge_route_joined, "FOLDER_DIGEST printing a constant", program,
                 "    import sys\n    sys.stdout.write('0' * 64); sys.exit(0)\n    import hashlib, os\n    whole = hashlib.sha256()\n"),
                (judge_route_joined, "FOLDER_DIGEST changed by one space", program, program.replace("whole = ", "whole  = ")),
                (judge_route_joined, "pack-linux run whatever the jobs before it did", pack_head,
                 pack_head.replace("    outputs:\n", "    if: always()\n    outputs:\n")),
                (judge_route_joined, "pack-linux run on a runner of its own", pack_head, pack_head.replace("ubuntu-latest", "self-hosted")),
                (judge_route_joined, "the check of what was attached handed every secret", check_head, check_head + "    secrets: inherit\n"),
                (judge_commit_carried, "the tag job handing on the tag asked for as the commit", tag_commit,
                 "      commit: ${{ inputs.tag }}\n"),
                (judge_commit_carried, "the tag job handing on the guard's tag as the commit", tag_commit,
                 "      commit: ${{ needs.guard.outputs.tag }}\n"),
                (judge_commit_carried, "the tag job handing on a rehearsal of its own",
                 "      rehearsal: ${{ needs.guard.outputs.rehearsal }}\n", "      rehearsal: false\n"),
                (judge_commit_carried, "the tag job reading the tag again after the guard and handing that on",
                 tag_commit + "      prerelease:", "      commit: ${{ steps.resolve.outputs.commit }}\n      prerelease:"),
                (judge_commit_carried, "the build checking out the tag by name", build_ref, "          ref: ${{ needs.tag.outputs.tag }}\n"),
                (judge_commit_carried, "the build checking out the tag asked for", build_ref, "          ref: ${{ inputs.tag }}\n"),
                (judge_commit_carried, "the build checking out from another repository", build_ref,
                 build_ref + "          repository: someone/timewitness\n"),
                (judge_commit_carried, "the build checking out a second time", "      - name: Build\n",
                 "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n"
                 "          ref: ${{ needs.tag.outputs.tag }}\n          persist-credentials: false\n      - name: Build\n"),
                (judge_tag_and_build_held, "the tag job handing on the tag asked for as the commit", tag_commit,
                 "      commit: ${{ inputs.tag }}\n"),
                (judge_tag_and_build_held, "the tag job given a step that reads the tag again", secrets_step, resolve + secrets_step),
                (judge_tag_and_build_held, "the tag job's secrets step changed", "          apple=true\n", "          apple=false\n"),
                (judge_tag_and_build_held, "the build checking out the tag by name", build_ref, "          ref: ${{ needs.tag.outputs.tag }}\n"),
                (judge_tag_and_build_held, "the build checking out the tag again before it builds", build_step,
                 '          git fetch --depth 1 origin "refs/tags/$TAG" && git checkout FETCH_HEAD\n' + build_step),
                (judge_tag_and_build_held, "the build given a step of its own", "      - name: Build\n",
                 "      - run: echo more\n      - name: Build\n"),
                (judge_tag_and_build_held, "the build run on a runner of its own",
                 "          - { target: x86_64-unknown-linux-gnu, runner: ubuntu-22.04, exe: timewitness }\n",
                 "          - { target: x86_64-unknown-linux-gnu, runner: self-hosted, exe: timewitness }\n"),
                (judge_tag_and_build_held, "the build saying a digest of its own", "      x86_64-apple-darwin: ${{ matrix.target == ",
                 "      x86_64-apple-darwin: ${{ matrix.target != "),
                (judge_folders_held, "sign-macos holding a build to a digest written in", "${{ needs.build.outputs.x86_64-apple-darwin }}",
                 "'%s'" % ("0" * 64)),
                (judge_folders_held, "pack-linux holding one build to another's digest",
                 "      WANT_aarch64_unknown_linux_gnu: ${{ needs.build.outputs.aarch64-unknown-linux-gnu }}\n",
                 "      WANT_aarch64_unknown_linux_gnu: ${{ needs.build.outputs.x86_64-unknown-linux-gnu }}\n"),
                (judge_folders_held, "sign-windows taking a folder after it held what it took", windows_hold,
                 "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\n        with:\n"
                 "          name: other\n          path: in\n" + windows_hold),
                (judge_folders_held, "sign-windows taking a folder of another name",
                 "          name: unsigned-x86_64-pc-windows-msvc\n", "          name: unsigned-other\n"),
                (judge_folders_held, "the build taking a folder", "      - name: Build\n",
                 "      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c\n        with:\n"
                 "          name: asset-linux\n          path: staged\n      - name: Build\n"),
                (judge_folders_held, "publish holding nothing it took", 'got="$(python3 -c "$FOLDER_DIGEST" "from/$kind")"',
                 'got="${!want}"')):
            if release.count(old) != 1:
                wrong.append("%s: the text it changes is not in release.yml once" % label)
            changed = release.replace(old, new, 1)
            if not isinstance(parsed(changed), dict):
                wrong.append("%s: release.yml no longer reads as YAML" % label)
            expect("%s, by %s" % (label, judge.__name__), judge(changed), True)
        # The hold moved ahead of the last folder it holds, and pack-linux's environment given as a word.
        doc = yaml.safe_load(release)
        steps = doc["jobs"]["pack-linux"]["steps"]
        doc["jobs"]["pack-linux"]["steps"] = [steps[0], steps[2], steps[1]] + steps[3:]
        expect("pack-linux holding what it took before the last of it is in", judge_folders_held(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["pack-linux"]["steps"] = steps
        saved_env = doc["jobs"]["pack-linux"]["env"]
        doc["jobs"]["pack-linux"]["env"] = "${{ fromJSON(vars.WANT) }}"
        expect("pack-linux's environment given as an expression", judge_folders_held(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["pack-linux"]["env"] = saved_env
        saved_steps = doc["jobs"]["publish"]["steps"]
        doc["jobs"]["publish"]["steps"] = saved_steps + [saved_steps[7]]
        expect("publish holding what it took twice", judge_folders_held(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["publish"]["steps"] = saved_steps
        for job in ("tag", "build"):
            saved_steps = doc["jobs"][job]["steps"]
            doc["jobs"][job]["steps"] = saved_steps + [{"run": "true"}]
            expect("the %s job given a step after its last" % job, judge_tag_and_build_held(yaml.safe_dump(doc, sort_keys=False)), True)
            doc["jobs"][job]["steps"] = saved_steps
        saved_job = doc["jobs"]["check"]
        doc["jobs"]["check"] = "x"
        expect("the check of what was attached given as a word", judge_route_joined(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["check"] = saved_job
        held_step = doc["jobs"]["sign-macos"]["steps"][4]
        doc["jobs"]["sign-macos"]["steps"][4] = dict(held_step, run=held_step["run"].replace(
            'if [ -z "${!want}" ] || [ "$got" != "${!want}" ]; then', "if false; then"))
        expect("sign-macos no longer comparing what it took", judge_folders_held(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["sign-macos"]["steps"][4] = held_step
        doc["jobs"]["pack-linux"]["steps"] = [{"uses": CHECKOUT + "3d3c42e5aac5ba805825da76410c181273ba90b1",
                                               "with": {"ref": "${{ needs.tag.outputs.tag }}", "persist-credentials": False}}] + steps
        expect("pack-linux checking out the tag", judge_commit_carried(yaml.safe_dump(doc, sort_keys=False)), True)
        doc["jobs"]["pack-linux"]["steps"] = steps

    # The patterns alone, as a run without PyYAML reads the workflows, refuse what the parse does.
    def by_pattern_alone(judge, *given):
        global yaml
        saved, yaml = yaml, None
        try:
            return judge(*given)
        finally:
            yaml = saved

    expect("a job calling another repository's workflow, read by pattern alone",
           by_pattern_alone(judge_reusable, dict(workflows, **{"x.yml": "jobs:\n  steal:\n    uses: %s\n" % foreign})), True)
    expect("the same, its key quoted, read by pattern alone",
           by_pattern_alone(judge_reusable, dict(workflows, **{"x.yml": "jobs:\n  steal:\n    'uses': '%s'\n" % foreign})), True)
    expect("another workflow entering release, read by pattern alone",
           by_pattern_alone(judge_environment_users, dict(workflows, **{"x.yml": "jobs:\n  steal:\n    environment: release\n"})), True)
    expect("the workflows as they are, read by pattern alone", by_pattern_alone(judge_reusable, workflows)
           + by_pattern_alone(judge_environment_users, workflows), False)

    # Secrets reached other than by a name written down.
    expect("a secret read by index", judge_secrets_read(release + "\n        env:\n          X: ${{ secrets['APPLE_TEAM_ID'] }}\n"), True)
    expect("every secret handed to a step", judge_secrets_read(release + "\n        env:\n          X: ${{ toJSON(secrets) }}\n"), True)
    expect("every secret handed to a called workflow", judge_secrets_read(release + "\n    secrets: inherit\n"), True)

    # The settings only an administrator is shown, and the Azure side.
    expect("the Actions settings as they are", judge_actions_permissions(dict(ACTIONS_PERMISSIONS)), False)
    expect("actions named by a tag allowed", judge_actions_permissions(dict(ACTIONS_PERMISSIONS, sha_pinning_required=False)), True)
    admins = [{"login": name, "id": number} for name, number in ADMINISTRATORS.items()]
    expect("the administrators as they are", judge_administrators(admins), False)
    expect("an administrator added", judge_administrators(admins + [{"login": "someone", "id": 7}]), True)
    expect("an administrator's name on another account", judge_administrators([dict(admins[0], id=7)] + admins[1:]), True)
    expect("an administrator gone", judge_administrators(admins[1:]), True)
    expect("an answer for the administrators that is no list", judge_administrators({}), True)
    expect("an answer for the administrators that is a list of names", judge_administrators([a["login"] for a in admins]), True)
    expect("an empty list of administrators read as not shown, and theirs as shown",
           [] if (administrators_shown([]), administrators_shown(admins)) == (False, True) else ["read otherwise"], False)
    expect("the release environment's secrets", judge_secret_names(held(*RELEASE_SECRETS), "e", RELEASE_SECRETS), False)
    expect("an Apple value stored under its old name", judge_secret_names(held("APPLE_CERTIFICATE_P12"), "r", REPOSITORY_SECRETS), True)
    expect("a secret release.yml does not read", judge_secret_names(held("OTHER"), "e", RELEASE_SECRETS), True)
    # Outside the environment, a signing value under its own name is read all the same.
    expect("the repository holding no secret", judge_secret_names(held(), "r", REPOSITORY_SECRETS), False)
    expect("the organisation sharing no secret", judge_secret_names(held(), "o", ORGANISATION_SECRETS), False)
    expect("a signing value stored as a repository secret", judge_secret_names(held("MACOS_TEAM_ID"), "r", REPOSITORY_SECRETS), True)
    expect("a signing value shared by the organisation", judge_secret_names(held("WINDOWS_SIGNING_PROFILE"), "o", ORGANISATION_SECRETS), True)
    expect("any other secret stored in the repository", judge_secret_names(held("OTHER"), "r", REPOSITORY_SECRETS), True)
    expect("any other secret shared by the organisation", judge_secret_names(held("OTHER"), "o", ORGANISATION_SECRETS), True)
    # An answer that does not say what a level holds is not taken for one holding nothing.
    for where, allowed in (("e", RELEASE_SECRETS), ("r", REPOSITORY_SECRETS), ("o", ORGANISATION_SECRETS)):
        expect("an answer with no list of secrets, at [%s]" % where, judge_secret_names({}, where, allowed), True)
        expect("an answer with a message and no list, at [%s]" % where, judge_secret_names({"message": "x"}, where, allowed), True)
        expect("an answer counting none and holding no list, at [%s]" % where, judge_secret_names({"total_count": 0}, where, allowed), True)
        expect("an answer listing fewer secrets than it counts, at [%s]" % where,
               judge_secret_names({"total_count": 3, "secrets": []}, where, allowed), True)
        # A list of names rather than of secrets is refused for its shape; a judgement that dies on
        # it has judged nothing, so it counts as one that passed it.
        try:
            names_alone = judge_secret_names({"total_count": 1, "secrets": ["MACOS_TEAM_ID"]}, where, allowed)
        except (AttributeError, TypeError):
            names_alone = []
        expect("an answer listing names rather than secrets, at [%s]" % where, names_alone, True)
    expect("no other environment holding a secret", judge_other_environments({"linux-signing": held()}), False)
    expect("a signing value stored on another environment", judge_other_environments({"linux-signing": held("MACOS_TEAM_ID")}), True)
    expect("any secret stored on another environment", judge_other_environments({"linux-signing": held("OTHER")}), True)
    expect("another environment's secrets not read", judge_other_environments({"linux-signing": {}}), True)
    expect("a signing value stored for Dependabot", judge_secret_names(held("MACOS_TEAM_ID"), "d", DEPENDABOT_SECRETS), True)
    expect("the organisation holding no Dependabot secret", judge_shared_dependabot(held()), False)
    expect("the organisation holding another repository's Dependabot secret", judge_shared_dependabot(held("NPM_TOKEN")), False)
    expect("a signing value the organisation holds for Dependabot", judge_shared_dependabot(held("MACOS_TEAM_ID")), True)
    expect("an old signing name the organisation holds for Dependabot", judge_shared_dependabot(held("APPLE_TEAM_ID")), True)
    expect("the organisation's Dependabot secrets not all read", judge_shared_dependabot({"total_count": 1, "secrets": []}), True)
    # The data action Azure's signer role carries, written out here rather than taken from the constant,
    # so a constant written wrongly is not then agreed with.
    SIGN = "Microsoft.CodeSigning/certificateProfiles/Sign/action"
    app = {"federated_credentials": [{"issuer": AZURE_ISSUER, "subject": token_subject("release"),
                                      "audiences": list(AZURE_AUDIENCES)}],
           "password_credentials": [], "key_credentials": [],
           "service_principal_password_credentials": [], "service_principal_key_credentials": [],
           "role_assignments": [{"roleDefinitionName": "Artifact Signing Certificate Profile Signer",
                                 "scope": "/subscriptions/s/resourceGroups/g/providers/Microsoft.CodeSigning/codeSigningAccounts/a/certificateProfiles/p"}],
           "signing_account": "/subscriptions/s/resourceGroups/g/providers/Microsoft.CodeSigning/codeSigningAccounts/a",
           "service_principal_id": "sp-ours",
           "every_role_assignment": {"listed": AZURE_LISTED, "subscription": "/subscriptions/s", "eligible": [], "active": [
               {"principalId": "sp-ours", "principalType": "ServicePrincipal", "roleDefinitionName": "Artifact Signing Certificate Profile Signer",
                "dataActions": [SIGN],
                "scope": "/subscriptions/s/resourceGroups/g/providers/Microsoft.CodeSigning/codeSigningAccounts/a/certificateProfiles/p"},
               # Who administers the subscription signs nothing until it gives itself a role that signs.
               {"principalId": "user-owner", "principalType": "User", "roleDefinitionName": "Owner", "dataActions": [],
                "scope": "/subscriptions/s"},
               # A role that signs, on a signing account of somebody else's in another resource group.
               {"principalId": "sp-other", "principalType": "ServicePrincipal", "roleDefinitionName": "Artifact Signing Certificate Profile Signer",
                "dataActions": [SIGN],
                "scope": "/subscriptions/s/resourceGroups/g2/providers/Microsoft.CodeSigning/codeSigningAccounts/a"},
               # Reading the resource group signs nothing.
               {"principalId": "user-reader", "principalType": "User", "roleDefinitionName": "Reader", "dataActions": [],
                "scope": "/subscriptions/s/resourceGroups/g"}]}}
    expect("the Entra app as it should be", judge_azure(app), False)
    expect("a second federated credential", judge_azure(dict(app, federated_credentials=app["federated_credentials"] * 2)), True)
    for label, subject in (
            ("a credential trusting any job on main outside an environment",
             OIDC_SUBJECT["sub_claim_prefix"] + ":ref:refs/heads/main:ref:refs/heads/main:job_workflow_ref:" + RELEASE_WORKFLOW_REF),
            ("a credential trusting the release environment from any ref", OIDC_SUBJECT["sub_claim_prefix"] + ":environment:release"),
            ("a credential missing the ref", token_subject("release").replace(":ref:refs/heads/main:", ":")),
            ("a credential naming another workflow", token_subject("release").replace("/release.yml@", "/other.yml@")),
            ("a credential trusting another branch", token_subject("release").replace("refs/heads/main", "refs/heads/other")),
            ("a credential trusting publish's token", token_subject("linux-signing"))):
        expect(label, judge_azure(dict(app, federated_credentials=[dict(app["federated_credentials"][0], subject=subject)])), True)
    expect("a client secret on the app", judge_azure(dict(app, password_credentials=[{"keyId": "k"}])), True)
    expect("a certificate on the app", judge_azure(dict(app, key_credentials=[{"keyId": "k"}])), True)
    expect("a client secret on the app's service principal", judge_azure(dict(app, service_principal_password_credentials=[{"keyId": "k"}])), True)
    expect("a certificate on the app's service principal", judge_azure(dict(app, service_principal_key_credentials=[{"keyId": "k"}])), True)
    expect("the service principal's credentials not read", judge_azure({k: v for k, v in app.items()
                                                                        if not (k.startswith("service_principal") and k.endswith("credentials"))}), True)

    def app_holding(*roles):
        """The app holding `roles`, each a role's name, what it may do and a scope, read the same in both lists."""
        listed = [a for a in app["every_role_assignment"]["active"] if a["principalId"] != "sp-ours"]
        return dict(app, role_assignments=[{"roleDefinitionName": n, "scope": at} for n, _, at in roles],
                    every_role_assignment=dict(app["every_role_assignment"], active=listed + [
                        {"principalId": "sp-ours", "principalType": "ServicePrincipal", "roleDefinitionName": n,
                         "dataActions": actions, "scope": at} for n, actions, at in roles]))
    held_role = ("Artifact Signing Certificate Profile Signer", [SIGN], app["role_assignments"][0]["scope"])
    expect("the app holding its signer role, read the same in both lists", judge_azure(app_holding(held_role)), False)
    expect("the signer role on the whole signing account", judge_azure(app_holding(
        held_role[:2] + ("/subscriptions/s/resourceGroups/g/providers/Microsoft.CodeSigning/codeSigningAccounts/a",))), True)
    expect("the signer role on something inside a profile", judge_azure(app_holding(held_role[:2] + (held_role[2] + "/x",))), True)
    expect("a second role", judge_azure(app_holding(held_role, ("Contributor", [], "/"))), True)
    expect("a second role on the same profile", judge_azure(app_holding(held_role, ("Reader", [], held_role[2]))), True)
    expect("a second role with no name", judge_azure(app_holding(held_role, (None, [], held_role[2]))), True)
    unarmed = dict(app, role_assignments=[], every_role_assignment=dict(app["every_role_assignment"], active=[
        a for a in app["every_role_assignment"]["active"] if a["principalId"] != "sp-ours"]))
    expect("the app before its signer role is given", judge_azure(unarmed), False)
    expect("the app given its signer role by its own list and not by the whole one",
           judge_azure(dict(unarmed, role_assignments=app["role_assignments"])), True)
    expect("the app given its signer role by the whole list and not by its own", judge_azure(dict(app, role_assignments=[])), True)
    expect("another role in place of the signer's", judge_azure(app_holding(("Contributor", [], held_role[2]))), True)
    expect("the app's roles not read", judge_azure({k: v for k, v in app.items() if k != "role_assignments"}), True)

    # Who else may sign with our certificate profile, and how the list of them was read.
    every, account = app["every_role_assignment"], app["signing_account"]
    profile = app["role_assignments"][0]["scope"]
    other = app["role_assignments"][0]["scope"].replace("/resourceGroups/g/", "/resourceGroups/g2/")
    signer = {"principalId": "user-x", "principalType": "User", "roleDefinitionName": "Artifact Signing Certificate Profile Signer",
              "dataActions": [SIGN], "scope": profile}

    def holding(base=app, active=(), eligible=(), **listing):
        """`base` with these assignments added to its whole list, and that list's other keys as given."""
        whole = dict(base["every_role_assignment"], **listing)
        whole["active"] = whole["active"] + list(active) if isinstance(whole.get("active"), list) else whole.get("active")
        whole["eligible"] = whole["eligible"] + list(eligible) if isinstance(whole.get("eligible"), list) else whole.get("eligible")
        return dict(base, every_role_assignment=whole)
    for label, given in (
            ("another user with the signer role on the profile", dict(signer)),
            ("another user with the signer role on the signing account", dict(signer, scope=account)),
            ("another user with the signer role on the resource group", dict(signer, scope="/subscriptions/s/resourceGroups/g")),
            ("another user with the signer role on the subscription", dict(signer, scope="/subscriptions/s")),
            ("another user with the signer role on a management group",
             dict(signer, scope="/providers/Microsoft.Management/managementGroups/m")),
            ("another user with the signer role at the root", dict(signer, scope="/")),
            ("another user with the signer role on the resource group, written in other case",
             dict(signer, scope="/subscriptions/S/resourceGroups/G")),
            ("another user with the signer role by its old name", dict(signer, roleDefinitionName="Trusted Signing Certificate Profile Signer")),
            ("another user with the signer role, its data actions read short", dict(signer, dataActions=[])),
            ("a group with the signer role on the profile", dict(signer, principalId="group-x", principalType="Group")),
            ("a managed identity with the signer role on the profile", dict(signer, principalId="mi-x", principalType="ServicePrincipal")),
            ("a custom role that signs, on the signing account", dict(signer, roleDefinitionName="Ours too", scope=account)),
            ("a custom role signing by a wildcard", dict(signer, roleDefinitionName="Ours too", dataActions=["Microsoft.CodeSigning/*"])),
            ("a custom role allowed every data action", dict(signer, roleDefinitionName="Everything", dataActions=["*"])),
            ("a custom role whose action is written in other case", dict(signer, roleDefinitionName="Ours too",
                                                                         dataActions=[SIGN.lower()])),
            ("another user whose role was not read for what it may do", {k: v for k, v in dict(signer, roleDefinitionName="Reader").items()
                                                                          if k != "dataActions"}),
            ("another user whose role has no name", dict(signer, roleDefinitionName=None, dataActions=[])),
            ("another user with the signer role on no scope this can read", dict(signer, scope=None)),
            ("another user with the signer role on a scope led by a space", dict(signer, scope=" /subscriptions/s")),
            ("another user with the signer role on a scope with an empty name in it", dict(signer, scope="/subscriptions/s//resourceGroups/g")),
            ("a custom role signing by the action the signer role carries",
             dict(signer, roleDefinitionName="Ours too", dataActions=["Microsoft.CodeSigning/certificateProfiles/Sign/action"])),
            ("a custom role signing with the action written with the account in it", dict(signer, roleDefinitionName="Ours too",
             dataActions=["Microsoft.CodeSigning/codeSigningAccounts/certificateProfiles/Sign/action"])),
            ("a custom role allowed everything on a profile", dict(signer, roleDefinitionName="Ours too",
                                                                   dataActions=["Microsoft.CodeSigning/certificateProfiles/*"])),
            ("a custom role allowed to sign anything", dict(signer, roleDefinitionName="Ours too", dataActions=["Microsoft.CodeSigning/*/Sign/action"])),
            ("a custom role allowed every action ending as signing does", dict(signer, roleDefinitionName="Ours too",
                                                                              dataActions=["*/sign/*"]))):
        expect("the Entra app, with %s" % label, judge_azure(holding(active=[given])), True)
        expect("the Entra app before its role, with %s" % label, judge_azure(holding(unarmed, active=[given])), True)
    for label, given in (
            ("another user with a role whose data actions do not sign, on the profile",
             dict(signer, roleDefinitionName="Blob reader", dataActions=["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"])),
            ("another user with the signer role on a signing account in another resource group", dict(signer, scope=other)),
            ("another user with the signer role on a resource group whose name starts as ours does",
             dict(signer, scope="/subscriptions/s/resourceGroups/g2")),
            ("another user with a role of many wildcards that does not sign",
             dict(signer, roleDefinitionName="Odd", dataActions=["*" * 40 + "x", "Microsoft.CodeSigning/*/Verify/action"])),
            ("another user with a role whose data actions name signing something else",
             dict(signer, roleDefinitionName="Odd", dataActions=["Microsoft.CodeSigning/certificateProfiles/Sign/action/more"]))):
        expect("the Entra app, with %s" % label, judge_azure(holding(active=[given])), False)
    expect("the Entra app, eligible for the signer role besides holding it",
           judge_azure(holding(eligible=[dict(signer, principalId="sp-ours", principalType="ServicePrincipal")])), True)
    expect("the Entra app, with another user eligible for the signer role", judge_azure(holding(eligible=[signer])), True)
    expect("the Entra app, its role on a profile of another signing account", judge_azure(dict(app, role_assignments=[
        dict(app["role_assignments"][0], scope=other)], every_role_assignment=dict(every, active=[
            dict(every["active"][0], scope=other)] + every["active"][1:]))), True)
    for label, change in (
            ("naming no signing account", {"signing_account": None}),
            ("naming a profile as the signing account", {"signing_account": profile}),
            ("naming no service principal", {"service_principal_id": ""}),
            ("not saying how its role assignments were listed", {"every_role_assignment": {k: v for k, v in every.items() if k != "listed"}}),
            ("listing the app's own role assignments alone", {"every_role_assignment": dict(every, listed="every role assignment of the app")}),
            ("naming no subscription it listed", {"every_role_assignment": {k: v for k, v in every.items() if k != "subscription"}}),
            ("listing another subscription", {"every_role_assignment": dict(every, subscription="/subscriptions/t")}),
            ("listing a resource group as the subscription", {"every_role_assignment": dict(every, subscription="/subscriptions/s/resourceGroups/g")}),
            ("holding no list of the active role assignments", {"every_role_assignment": dict(every, active={"value": []})}),
            ("holding no list of the eligible role assignments", {"every_role_assignment": {k: v for k, v in every.items() if k != "eligible"}}),
            ("holding an assignment that is not one", {"every_role_assignment": dict(every, eligible=["user-x"])})):
        expect("the Entra file %s" % label, judge_azure(dict(app, **change)), True)
        expect("the Entra file before the app's role, %s" % label, judge_azure(dict(unarmed, **{
            k: (dict(v, active=unarmed["every_role_assignment"]["active"]) if k == "every_role_assignment" and isinstance(v.get("active"), list) else v)
            for k, v in change.items()})), True)

    # Who entered the signing environments, as GitHub records each job that asked to.
    starter = {"login": login, "id": number}

    def deployment(number, ref, created, creator=starter):
        return {"id": number, "ref": ref, "created_at": created, "creator": dict(creator), "environment": "release"}

    def statuses_of(*states):
        return [{"state": state} for state in reversed(states)]
    after, before = "2026-09-30T23:50:05Z", "2026-09-25T04:44:00Z"
    on_main = deployment(1, "main", after)
    for label, given, read, refused in (
            ("a run from main by the account written down", [on_main], {}, False),
            ("a run from a tag before the policy was set", [deployment(2, "v0.4", before)], {}, False),
            ("a run from a tag before the policy was set, its time given in another offset",
             [deployment(2, "v0.4", "2026-09-25T07:44:00+03:00")], {}, False),
            ("a tag the policy refused", [deployment(3, "v0.0.4243", after)], {"3": statuses_of("waiting", "failure")}, False),
            ("a branch that ran", [deployment(4, "widened", after)], {"4": statuses_of("waiting", "queued", "in_progress", "success")}, True),
            ("a tag that ran", [deployment(5, "v0.5", after)], {"5": statuses_of("queued", "success")}, True),
            ("a tag that got in and then failed", [deployment(6, "v0.5", after)], {"6": statuses_of("waiting", "in_progress", "failure")}, True),
            ("a tag whose statuses were not read", [deployment(7, "v0.5", after)], {}, True),
            ("a tag whose statuses are no list", [deployment(7, "v0.5", after)], {"7": {"message": "x"}}, True),
            ("a tag whose statuses are not each one", [deployment(7, "v0.5", after)], {"7": ["success"]}, True),
            ("a tag whose status is no word", [deployment(7, "v0.5", after)], {"7": [{"state": ["success"]}]}, True),
            ("a branch whose name ends in main, that ran", [deployment(15, "fix-main", after)],
             {"15": statuses_of("in_progress", "success")}, True),
            ("a run from main by another account", [deployment(8, "main", after, {"login": "someone", "id": 7})], {}, True),
            ("a run from main by the account written down under another login",
             [deployment(9, "main", after, {"login": "someone", "id": number})], {}, True),
            ("a branch named after main that ran", [deployment(12, "main-widened", after)],
             {"12": statuses_of("waiting", "in_progress", "success")}, True),
            ("a tag that ran in the second the policy was set", [deployment(13, "v0.5", DEPLOYMENTS_SINCE)],
             {"13": statuses_of("in_progress", "success")}, True),
            ("a tag whose statuses hold a state that is no word", [deployment(14, "v0.5", after)],
             {"14": [{"state": ["success"]}, {"state": "in_progress"}]}, True),
            ("a run from main by the login written down on another account",
             [deployment(9, "main", after, {"login": login, "id": 1})], {}, True),
            ("a tag the policy refused, asked for by another account",
             [deployment(10, "v0.5", after, {"login": "someone", "id": 7})], {"10": statuses_of("waiting", "failure")}, True),
            ("a run from main by nobody GitHub names", [dict(on_main, creator=None)], {}, True),
            ("a run from main whose maker is a name and no account", [dict(on_main, creator=login)], {}, True),
            ("a run whose time cannot be read", [dict(on_main, created_at="yesterday")], {}, True)):
        expect("deployments: %s" % label, judge_deployments({"release": given, "linux-signing": []}, read), refused)
        expect("deployments: %s, on linux-signing" % label, judge_deployments({"release": [], "linux-signing": given}, read), refused)
    expect("deployments: an environment's list not read", judge_deployments({"release": {"message": "x"}, "linux-signing": []}, {}), True)
    expect("deployments: an environment's list missing", judge_deployments({"release": []}, {}), True)
    expect("deployments: the window opens no later than the environment's time",
           [] if instant(DEPLOYMENTS_SINCE) <= instant(ENVIRONMENT["updated_at"]) else ["it opens at %s" % DEPLOYMENTS_SINCE], False)
    expect("deployments: statuses asked for a tag since the policy, and no more",
           [] if [statuses_needed(d) for d in (on_main, deployment(2, "v0.4", before), deployment(3, "v0.0.4243", after),
                                               deployment(8, "main", after, {"login": "someone", "id": 7}),
                                               deployment(13, "v0.5", DEPLOYMENTS_SINCE))]
           == [False, False, True, False, True] else ["asked otherwise"], False)

    # run() itself, over GitHub's answers as they stand: every clause runs, in its order, and one
    # setting moved fails it. A clause taken out of run() is a clause no check makes.
    answers = {"environments/release": environment, "environments/release/deployment-branch-policies": policies,
               "rulesets?includes_parents=false": [{"name": n, "id": i} for i, n in enumerate(RULESETS)],
               "git/matching-refs/tags/": [{"ref": "refs/tags/v0"}, {"ref": "refs/tags/v0.6"}],
               "branches/main": branch, "actions/oidc/customization/sub": dict(OIDC_SUBJECT),
               "actions/permissions": dict(ACTIONS_PERMISSIONS),
               "collaborators?permission=admin&per_page=100": admins,
               "environments/release/secrets?per_page=100": held(*sorted(RELEASE_SECRETS)),
               "actions/secrets?per_page=100": held(), "actions/organization-secrets?per_page=100": held(),
               "environments?per_page=100": {"total_count": 2, "environments": [{"name": "linux-signing"}, {"name": "release"}]},
               "environments/linux-signing/secrets?per_page=100": held(), "dependabot/secrets?per_page=100": held(),
               # As GitHub listed them on 2026-10-01, a few of each: a run from main, the two tags the
               # policy refused just after it was set, and v0.4, which ran before it was.
               "deployments?environment=release&per_page=100": [
                   deployment(6772695802, "main", "2026-09-30T23:50:05Z"),
                   deployment(6658511404, "v0.0.4243", "2026-09-25T10:15:41Z"),
                   deployment(6658495204, "v0.0.4242", "2026-09-25T10:14:39Z"),
                   deployment(6653884571, "v0.4", "2026-09-25T04:44:00Z")],
               "deployments?environment=linux-signing&per_page=100": [
                   dict(deployment(6772702511, "main", "2026-09-30T23:50:35Z"), environment="linux-signing")],
               "deployments/6658511404/statuses?per_page=100": statuses_of("waiting", "failure"),
               "deployments/6658495204/statuses?per_page=100": statuses_of("waiting", "failure")}
    answers.update({"rulesets/%d" % i: dict(RULESETS[n], name=n) for i, n in enumerate(RULESETS)})
    answers = {"repos/%s/%s" % (REPO, k): v for k, v in answers.items()}
    answers["orgs/%s" % ORG] = {"two_factor_requirement_enabled": True}
    answers["orgs/%s/dependabot/secrets?per_page=100" % ORG] = held()
    hidden_from_writers = ["repos/%s/%s" % (REPO, k) for k in ("actions/permissions", "collaborators?permission=admin&per_page=100",
                           "environments/release/secrets?per_page=100", "actions/secrets?per_page=100",
                           "actions/organization-secrets?per_page=100", "environments/linux-signing/secrets?per_page=100",
                           "dependabot/secrets?per_page=100")] + ["orgs/%s/dependabot/secrets?per_page=100" % ORG]

    # The organisation's app installations as they stood on 2026-10-02, less their names: one holding
    # no route write, and three holding one on lists of repositories this one is not on.
    elsewhere = {"total_count": 2, "repositories": [{"id": 1, "full_name": ORG + "/web"}, {"id": 2, "full_name": ORG + "/app"}]}
    apps = [{"id": 11, "app_slug": "checks", "repository_selection": "selected",
             "permissions": {"checks": "write", "contents": "read", "metadata": "read", "statuses": "write"}},
            {"id": 12, "app_slug": "deploys", "repository_selection": "selected",
             "permissions": {"administration": "write", "contents": "write", "members": "read", "metadata": "read"}},
            {"id": 13, "app_slug": "edits", "repository_selection": "selected",
             "permissions": {"actions": "write", "contents": "write", "members": "read", "workflows": "write"}},
            {"id": 14, "app_slug": "administers", "repository_selection": "selected",
             "permissions": {"administration": "write", "metadata": "read"}}]
    installed = "orgs/%s/installations?per_page=100" % ORG
    answers[installed] = {"total_count": len(apps), "installations": apps}
    answers.update({"user/installations/%d/repositories?per_page=100" % a["id"]: elsewhere for a in apps[1:]})
    hidden_from_writers.append(installed)
    this_one = {"total_count": 3, "repositories": elsewhere["repositories"] + [{"id": REPO_NUMBER, "full_name": REPO}]}

    def one_app(permissions, selection="selected", reached=elsewhere):
        """judge_installations over one app, its list of repositories answered as `reached`."""
        app = {"id": 99, "app_slug": "x", "repository_selection": selection, "permissions": permissions}
        return judge_installations({"total_count": 1, "installations": [app]}, {99: reached})

    def unread_only(judged):
        return judged[0] + ([] if judged[1] else ["nothing said unread"])
    got = judge_installations(answers[installed], {a["id"]: elsewhere for a in apps[1:]})
    expect("installations: as they are", got[0] + got[1], False)
    # Each written out here rather than read from the lists the check holds, so a name taken off one
    # of those lists is a shape that fails.
    for permission in ("actions", "administration", "contents", "environments", "secrets", "workflows"):
        for value in ("write", "admin"):
            held_here = {permission: value, "metadata": "read"}
            expect("installations: %s %s on every repository" % (permission, value), one_app(held_here, "all")[0], True)
            expect("installations: %s %s on a list holding this repository" % (permission, value),
                   one_app(held_here, reached=this_one)[0], True)
            expect("installations: %s %s on a list holding this repository by its number alone" % (permission, value),
                   one_app(held_here, reached={"total_count": 1, "repositories": [{"id": REPO_NUMBER, "full_name": ORG + "/renamed"}]})[0], True)
            expect("installations: %s %s on a list holding this repository by its name alone" % (permission, value),
                   one_app(held_here, reached={"total_count": 1, "repositories": [{"id": 3, "full_name": REPO.upper()}]})[0], True)
            got = one_app(held_here)
            expect("installations: %s %s on a list without this repository" % (permission, value), got[0] + got[1], False)
            expect("installations: %s %s on a list nobody read" % (permission, value), unread_only(one_app(held_here, reached="not read")), False)
        got = one_app({permission: "read"}, "all")
        expect("installations: %s read on every repository" % permission, got[0] + got[1], False)
    for permission in ("members", "organization_administration", "organization_secrets"):
        for value in ("write", "admin"):
            expect("installations: %s %s on the organisation" % (permission, value), one_app({permission: value})[0], True)
        got = one_app({permission: "read"}, "all")
        expect("installations: %s read on the organisation" % permission, got[0] + got[1], False)
    expect("installations: a route write on neither every repository nor a list", one_app({"contents": "write"}, "none")[0], True)
    expect("installations: a route write with no selection said", one_app({"contents": "write"}, None)[0], True)
    expect("installations: a route write on a list counting more than it lists",
           unread_only(one_app({"contents": "write"}, reached={"total_count": 3, "repositories": elsewhere["repositories"]})), False)
    expect("installations: a route write on a list answered with none", unread_only(one_app({"contents": "write"}, reached={"message": "x"})), False)
    expect("installations: listed as fewer than GitHub counts", judge_installations({"total_count": 5, "installations": apps}, {})[0], True)
    expect("installations: answered with no list", judge_installations({"message": "x"}, {})[0], True)
    expect("installations: one listed with no permissions",
           judge_installations({"total_count": 1, "installations": [{"id": 1, "repository_selection": "all"}]}, {})[0], True)

    printed = []
    # The action files, as the actions release.yml uses answer: the signing action is the composite
    # one above, over the cache action, and every other is a JavaScript action with no pre step. Each
    # file asked for is counted, so the self-test can hold run() to reading each once.
    signing_at = "https://raw.githubusercontent.com/%s/%s/" % (SIGNING_ACTION, SIGNING_ACTION_PIN)
    node_action = "runs:\n  using: node24\n  main: m.js\n  post: p.js\n"
    asked_for = []

    def served(url, accept=None):
        asked_for.append(url)
        return action if url.startswith(signing_at) else node_action

    def run_over(changed=None, hidden=(), azure=None, need_admin=False, code=403, broken=None, fetch=None, unlisted=False):
        """run() over GitHub's answers, each path in `hidden` refused with `code`, and the one path
        `broken` names failing with the error it gives. Every action's file is as `served` answers
        unless `fetch` says otherwise, and the apps' lists of repositories are read from the same
        answers unless `unlisted`, as where no token reads them. What it printed is kept in `printed`."""
        said = dict(answers, **(changed or {}))

        def answer(path):
            if broken and path == broken[0]:
                raise broken[1]
            if path in hidden:
                raise urllib.error.HTTPError("https://api.github.com/" + path, code, "Refused", {}, None)
            return said[path]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = run(False, need_yaml, github=answer, fetch=fetch or served, azure=azure,
                         need_admin=need_admin, reach=None if unlisted else answer)
        printed[:] = out.getvalue().splitlines()
        return result

    every_clause = [
        "release.yml is started by hand and by nothing else",
        "only release.yml's tag, sign-macos and sign-windows jobs enter release, and only its publish job enters linux-signing",
        "the signature check holds a Linux signature to the token of the job that alone enters linux-signing",
        "no job in release.yml restores from the Actions cache, the signing action included",
        "no workflow names an Azure client secret, and Windows signing signs in by a federated token",
        "no workflow calls a reusable workflow from another repository",
        "release.yml reads the signing values under the names written here, and none an older run of it reads",
        "the guard refuses anybody not written down here as starting releases",
        "the guard job is the one written down here, and each of its two steps to the byte",
        "what is written here lets nobody make a tag outside v*, and only an administrator one inside it",
        "every job that enters an environment asks the same of whoever started it",
        "each job that signs with a token holds its subject to main and release.yml before anything else",
        "no job that enters an environment runs on past its starter steps, or runs them with a tool or a setting of its own",
        "a release is a draft until it carries every file, and is attached only to the commit the run built",
        "the Attach step is the one written down here, to the byte",
        "every job of release.yml waits on the guard, directly or through the jobs it waits on",
        "release.yml runs the jobs written here, each waiting on what is written here and given no more than is "
        "written here",
        "the tag job hands on the commit the guard read, the build checks out that commit and nothing else, and "
        "no other job checks out anything but main's scripts",
        "the tag job and the build job are the ones written down here, each step to the byte",
        "every folder a job takes from another is held to the digest that job said, by the step written here",
        "the pinned signing action restores from the cache only when asked to",
        "no action a job in an environment uses runs a step before the starter steps",
        "the release environment admits runs from main alone, administrators included",
        "since the policy was set, only an account written down as starting releases asked to enter release or "
        "linux-signing, and only from main did one get in",
        "every ruleset written down here is on the repository",
    ] + ["ruleset [%s] is as written here" % n for n in RULESETS] + [
        "every tag that stands is named as a release tag",
        "main is protected, and its required build holds everyone",
        "the token Azure trusts names this repository as written here",
        "every action a workflow uses is named by a full commit",
        "the repository is administered by the accounts written here, and nobody else",
        "the release environment holds no secret but the ones release.yml reads, and none an older run of it reads",
        "the repository holds no secret, so no signing value is read outside the release environment",
        "the organisation shares no secret, so no signing value is read outside the release environment",
        "no environment but release holds a secret",
        "the repository holds no Dependabot secret",
        "the organisation holds no Dependabot secret under a signing name",
        "the organisation requires two-factor sign-in of every member",
        "no app installed on the organisation holds a write that reaches this repository's signing route",
        "the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there",
    ]
    def fails(result):
        return [] if result[0] == 1 else ["exit %d" % result[0]]

    def passes(result):
        return ["exit %d" % result[0]] if result[0] else []

    work = tempfile.mkdtemp(prefix="tw-route-self-test-")
    try:
        good_app = os.path.join(work, "app.json")
        with open(good_app, "w", encoding="utf-8") as f:
            json.dump(app, f)
        code, ran = run_over(azure=good_app)
        expect("run() over the settings as they are", ["exit %d" % code] if code else [], False)
        if ran != every_clause:
            wrong.append("run() ran %s, not every clause in order: missing %s" % (len(ran), [c for c in every_clause if c not in ran]))
        # An Azure file of the wrong shape inside fails its line, and does not stop the check.
        odd_app = os.path.join(work, "odd.json")
        with open(odd_app, "w", encoding="utf-8") as f:
            json.dump(dict(app, role_assignments=["a role"]), f)
        run_over(azure=odd_app)
        expect("run() with an Azure file whose role is not an object",
               [] if any(line.startswith("FAIL: the Entra app") for line in printed) else ["printed %s" % printed], False)
        code, ran = run_over(hidden=hidden_from_writers)
        expect("run() with a token that is not an administrator's, and no Azure file", ["exit %d" % code] if code else [], False)
        expect("and it still names every clause", [] if ran == every_clause else ["ran %d" % len(ran)], False)
        expect("run() with an administrator added", fails(run_over({hidden_from_writers[1]: admins + [{"login": "x", "id": 1}]})), False)
        expect("run() with an administrator added, asked for all of them",
               fails(run_over({hidden_from_writers[1]: admins + [{"login": "x", "id": 1}]}, need_admin=True, azure=good_app)), False)
        expect("run() with an administrator gone", fails(run_over({hidden_from_writers[1]: admins[1:]})), False)
        expect("run() with the administrators answered as no list", fails(run_over({hidden_from_writers[1]: {}})), False)
        # The workflow's own token is answered with an empty list of administrators: not shown to it,
        # so UNSEEN, and a failure only where --need-admin asks for every setting read.
        administered = "the repository is administered by the accounts written here, and nobody else"

        def administrators_line(state):
            lines = [line for line in printed if line.startswith("%s: %s" % (state, administered))]
            return [] if len(lines) == 1 else ["printed %s" % printed]
        result = run_over({hidden_from_writers[1]: []}, hidden=hidden_from_writers[:1], azure=good_app)
        expect("run() with the Actions settings hidden and the administrators answered as an empty list",
               passes(result) + administrators_line("UNSEEN") + ([] if result[1] == every_clause else ["ran %d" % len(result[1])]), False)
        expect("run() with the Actions settings hidden and the administrators answered as an empty list, asked for all of them",
               fails(run_over({hidden_from_writers[1]: []}, hidden=hidden_from_writers[:1], need_admin=True, azure=good_app))
               + administrators_line("FAIL"), False)
        expect("run() with the Actions settings shown and the administrators answered as an empty list",
               fails(run_over({hidden_from_writers[1]: []}, azure=good_app)) + administrators_line("FAIL"), False)
        expect("run() with the administrators as they are, asked for all of them",
               passes(run_over(need_admin=True, azure=good_app)) + administrators_line("PASS"), False)
        expect("run() with an Apple value stored under its old name",
               fails(run_over({hidden_from_writers[3]: held("APPLE_TEAM_ID")})), False)
        # Which actions' files run() reads, and how far into composite actions.
        early_clause = "no action a job in an environment uses runs a step before the starter steps"
        pre_action = "runs:\n  using: node24\n  pre: evil.js\n  main: m.js\n"
        entrypoint_action = "runs:\n  using: docker\n  image: Dockerfile\n  pre-entrypoint: /evil.sh\n"

        def address(uses):
            """Where run() reads an action's file from, less the file's name."""
            name, _, at = uses.partition("@")
            parts = name.split("/")
            return "https://raw.githubusercontent.com/%s/" % "/".join(parts[:2] + [at] + parts[2:])

        def answering(files):
            """A fetch over `served`, where an address starting with a key of `files` is answered with
            its value instead, or refused with a 404 where the value is None."""
            def fetch(url, accept=None):
                for start, text in files.items():
                    if url.startswith(start):
                        asked_for.append(url)
                        if text is None:
                            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
                        return text
                return served(url)
            return fetch

        def early_line(*names):
            lines = [line for line in printed if line.startswith("FAIL: " + early_clause)]
            return [] if len(lines) == 1 and all(n in lines[0] for n in names) else ["printed %s" % printed]
        # Every action the environment jobs use is read, each in turn starting a step first.
        for uses in environment_job_actions(release) if parse_shapes_run else []:
            expect("run() with %s running a step when the job starts" % uses,
                   fails(run_over(fetch=answering({address(uses): pre_action}))) + early_line(uses), False)
        checkout = address(min(u for u in RELEASE_ACTIONS if u.startswith("actions/checkout@")))
        expect("run() with the checkout action's file named action.yaml and running a step when the job starts",
               fails(run_over(fetch=answering({checkout + "action.yml": None, checkout: pre_action}))) + early_line("actions/checkout@"), False)
        expect("run() with the checkout action's file named action.yaml and running nothing first",
               passes(run_over(fetch=answering({checkout + "action.yml": None, checkout: node_action}))), False)
        # An action used by one environment job alone is read, whichever job it is.
        if parse_shapes_run:
            saved_tree = globals()["workflows_in_tree"]
            try:
                for job, _ in ENVIRONMENT_JOBS:
                    early = "someone/early-in-%s%s" % (job, pin)
                    planted = dict(workflows, **{"release.yml": after_starter(job, "      - uses: %s\n" % early)})
                    globals()["workflows_in_tree"] = lambda: planted
                    run_over(fetch=answering({address(early): pre_action}))
                    expect("run() with an action only %s uses running a step when the job starts" % job, early_line(early), False)
            finally:
                globals()["workflows_in_tree"] = saved_tree
        # The actions a composite action uses, as the signing action uses the cache action.
        cache = re.search(r"uses:\s*(\S+)", action).group(1)
        inside_signing = "%s inside %s@%s" % (cache, SIGNING_ACTION, SIGNING_ACTION_PIN)
        for label, files in (("running a step", {address(cache): pre_action}),
                             ("starting a container entrypoint", {address(cache): entrypoint_action}),
                             ("running a step, its file named action.yaml", {address(cache) + "action.yml": None, address(cache): pre_action})):
            expect("run() with the action the signing action uses %s when the job starts" % label,
                   fails(run_over(fetch=answering(files))) + early_line(inside_signing), False)
        one, two = "someone/one" + pin, "someone/two" + pin
        expect("run() with composite actions three deep over one that runs nothing when the job starts", passes(run_over(
            fetch=answering({address(cache): "runs:\n  using: composite\n  steps:\n    - uses: %s\n" % one}))), False)
        expect("run() with composite actions three deep over one that runs a step when the job starts", fails(run_over(
            fetch=answering({address(cache): "runs:\n  using: composite\n  steps:\n    - uses: %s\n" % one,
                             address(one): pre_action}))) + early_line(one), False)
        asked_for[:] = []
        expect("run() with composite actions four deep", fails(run_over(fetch=answering({
            address(cache): "runs:\n  using: composite\n  steps:\n    - uses: %s\n" % one,
            address(one): "runs:\n  using: composite\n  steps:\n    - uses: %s\n" % two}))) + early_line(
            "uses %s, more than %d actions deep" % (two, NESTED_DEPTH)) + (
            ["read %s" % two] if any(u.startswith(address(two)) for u in asked_for) else []), False)
        asked_for[:] = []
        expect("run() with a composite action over an action not named by a full commit", fails(run_over(fetch=answering({
            address(cache): "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n"}))) + early_line(
            "uses actions/cache@v4, which is not an action named by a full commit") + (
            ["read actions/cache@v4"] if any("/v4/" in u for u in asked_for) else []), False)
        # Each action's file is read once in a run, however many steps use it.
        twice = action + "    - name: Cache again\n      uses: %s\n      if: ${{ inputs.cache-dependencies == 'true' }}\n" % cache
        asked_for[:] = []
        expect("run() with the signing action using the cache action twice", passes(run_over(fetch=answering({signing_at: twice}))) + (
            [] if asked_for.count(address(cache) + "action.yml") == 1 else ["read %s" % asked_for]), False)
        expect("run() with two-factor sign-in not required", fails(run_over({"orgs/%s" % ORG: {"two_factor_requirement_enabled": False}})), False)
        expect("run() with actions named by a tag allowed",
               fails(run_over({hidden_from_writers[0]: dict(ACTIONS_PERMISSIONS, sha_pinning_required=False)})), False)
        expect("run() with a signing value stored as a repository secret",
               fails(run_over({hidden_from_writers[3]: held("MACOS_TEAM_ID")})), False)
        expect("run() with a signing value shared by the organisation",
               fails(run_over({hidden_from_writers[4]: held("MACOS_TEAM_ID")})), False)
        expect("run() with a signing value stored on another environment",
               fails(run_over({hidden_from_writers[5]: held("MACOS_TEAM_ID")})), False)
        expect("run() with a signing value stored for Dependabot",
               fails(run_over({hidden_from_writers[6]: held("MACOS_TEAM_ID")})), False)
        expect("run() with a signing value the organisation holds for Dependabot",
               fails(run_over({hidden_from_writers[7]: held("MACOS_TEAM_ID")})), False)
        expect("run() with the environments not listed whole",
               fails(run_over({"repos/%s/environments?per_page=100" % REPO: {"total_count": 3, "environments": [{"name": "release"}]}})), False)
        # Every environment but release is read, the last listed as well as the first.
        third = {"repos/%s/environments?per_page=100" % REPO: {"total_count": 3, "environments": [
                     {"name": "linux-signing"}, {"name": "release"}, {"name": "staging"}]},
                 "repos/%s/environments/staging/secrets?per_page=100" % REPO: held("MACOS_TEAM_ID")}
        expect("run() with a signing value stored on a third environment, listed last",
               fails(run_over(third)) + ([] if any(line.startswith("FAIL: no environment but release holds a secret")
                                                   for line in printed) else ["printed %s" % printed]), False)
        # An action's file that YAML cannot read says nothing about whether it runs a step first.
        expect("run() with the checkout action's file not YAML this can read", fails(run_over(
            fetch=answering({checkout: "runs: [using, node24\n"}))) + early_line("actions/checkout@"), False)
        # Both signing environments' records are read, and a tag's statuses where it was made since.
        entered = "since the policy was set, only an account written down as starting releases asked to enter release"
        for environment in DEPLOYMENT_ENVIRONMENTS:
            listed = "repos/%s/deployments?environment=%s&per_page=100" % (REPO, environment)
            widened = {listed: answers[listed] + [dict(deployment(11, "widened", "2026-10-01T02:00:00Z"), environment=environment)],
                       "repos/%s/deployments/11/statuses?per_page=100" % REPO: statuses_of("waiting", "in_progress", "success")}
            expect("run() with a branch that ran in %s since the policy was set" % environment, fails(run_over(widened)) + (
                [] if any(line.startswith("FAIL: " + entered) and line.endswith("this is seen after the fact, and stopped nothing")
                          for line in printed) else ["printed %s" % printed]), False)
        # Both tags the policy refused in the minutes after it was set fall inside the window.
        expect("run() asks the statuses of both tags the policy refused, and of nothing else", [] if [
            statuses_needed(d) for d in answers["repos/%s/deployments?environment=release&per_page=100" % REPO]]
            == [False, True, True, False] else ["asked otherwise"], False)
        expect("run() with a refused tag's statuses saying it ran", fails(run_over({
            "repos/%s/deployments/6658511404/statuses?per_page=100" % REPO: statuses_of("waiting", "in_progress", "success")})), False)

        # What GitHub did not show: UNSEEN on a run that does not ask, and a failure on one that does.
        expect("run() with every setting shown, asked for all of them", passes(run_over(azure=good_app, need_admin=True)), False)
        # No GitHub token reads the Entra app. An administrator's run passes without it only while
        # nothing Windows signing reads is stored, and fails on it, by that line and no other, once
        # any one of those names is stored, each of them alone, and the three Azure identifiers as they
        # stood on 2026-10-01 before the first signing value.
        release_secrets = "repos/%s/environments/release/secrets?per_page=100" % REPO
        azure_ids = ("WINDOWS_AZURE_CLIENT_ID", "WINDOWS_AZURE_SUBSCRIPTION_ID", "WINDOWS_AZURE_TENANT_ID")
        windows = sorted(n for n in RELEASE_SECRETS if n.startswith("WINDOWS_"))
        macos = sorted(n for n in RELEASE_SECRETS if n.startswith("MACOS_"))
        entra = "the Entra app signs in by GitHub's token alone, with the signer role on one profile, and nobody else may sign there"

        def entra_line(state):
            lines = [line for line in printed if line.startswith("%s: %s" % (state, entra))]
            others = [line for line in printed if line.startswith("FAIL") and entra not in line]
            return [] if len(lines) == 1 and not others else ["printed %s" % printed]
        expect("every Windows signing name the release environment may hold is one of six", [] if len(windows) == 6 else [windows], False)
        for label, stored in (("nothing", ()), ("the macOS values", macos)):
            expect("run() asked for all of them, with no Azure file and %s stored" % label,
                   passes(run_over({release_secrets: held(*stored)}, need_admin=True)) + entra_line("UNSEEN"), False)
        for label, stored in [("the three Azure identifiers", azure_ids), ("the macOS values and the Azure identifiers", macos + list(azure_ids)),
                              ("every value", sorted(RELEASE_SECRETS))] + [(name + " alone", (name,)) for name in windows]:
            expect("run() asked for all of them, with no Azure file and %s stored" % label,
                   fails(run_over({release_secrets: held(*stored)}, need_admin=True)) + entra_line("FAIL"), False)
            expect("run() asked for all of them, with a sound Azure file and %s stored" % label,
                   passes(run_over({release_secrets: held(*stored)}, need_admin=True, azure=good_app)) + entra_line("PASS"), False)
            expect("run() not asked for all of them, with no Azure file and %s stored" % label,
                   passes(run_over({release_secrets: held(*stored)})) + entra_line("UNSEEN"), False)
        # A list nobody saw whole is not taken for one holding no Windows signing value.
        # The names it does list are the macOS ones, so the list counting more than it lists fails the
        # line and not a Windows name in it.
        for label, listed in (("counting more than it lists", {"total_count": len(macos) + 1, "secrets": [{"name": n} for n in macos]}),
                              ("holding no list", {"message": "x"})):
            run_over({release_secrets: listed}, need_admin=True)
            expect("run() asked for all of them, with no Azure file and the release environment's secrets %s" % label,
                   [] if any(line.startswith("FAIL: %s" % entra) for line in printed) else ["printed %s" % printed], False)
        run_over(hidden=[release_secrets], need_admin=True)
        expect("run() asked for all of them, with no Azure file and the release environment's secrets hidden",
               [] if any(line.startswith("FAIL: %s" % entra) for line in printed) else ["printed %s" % printed], False)
        for code in (401, 403, 404):
            expect("run() with a token GitHub answers %d, not asked for all of them" % code,
                   passes(run_over(hidden=hidden_from_writers, code=code)), False)
            expect("run() with a token GitHub answers %d, asked for all of them" % code,
                   fails(run_over(hidden=hidden_from_writers, code=code, need_admin=True)), False)
        for path in hidden_from_writers:
            expect("run() asked for all of them, with only [%s] hidden" % path.split("/", 3)[-1],
                   fails(run_over(hidden=[path], need_admin=True, azure=good_app)), False)
        expect("run() asked for all of them, with two-factor sign-in hidden",
               fails(run_over({"orgs/%s" % ORG: {}}, need_admin=True, azure=good_app)), False)
        unseen_bypass = {"repos/%s/rulesets/%d" % (REPO, i): {k: v for k, v in dict(RULESETS[n], name=n).items() if k != "bypass_actors"}
                         for i, n in enumerate(RULESETS)}
        expect("run() with the rulesets' bypass lists hidden, not asked for them",
               passes(run_over(unseen_bypass)), False)
        expect("run() asked for all of them, with the rulesets' bypass lists hidden",
               fails(run_over(unseen_bypass, need_admin=True, azure=good_app)), False)

        # A 404 is GitHub hiding a thing only where it hid the Actions settings as well.
        expect("run() with a later read answering 404 to a token shown the Actions settings",
               fails(run_over(hidden=hidden_from_writers[1:2], code=404)), False)
        expect("run() with the Actions settings answering 404 and nothing else hidden",
               passes(run_over(hidden=hidden_from_writers[:1], code=404)), False)

        # Anything else GitHub answers, on a read it hides or one it shows anybody, fails the run.
        for path in (hidden_from_writers[0], hidden_from_writers[2]):
            expect("run() with GitHub answering 500 to [%s]" % path.split("/", 3)[3], fails(run_over(
                broken=(path, urllib.error.HTTPError("https://api.github.com/" + path, 500, "Server Error", {}, None)))), False)
        expect("run() with GitHub out of reach for the environment", fails(run_over(
            broken=("repos/%s/environments/release" % REPO, urllib.error.URLError("no route to host")))), False)
        expect("run() with GitHub out of reach for the organisation", fails(run_over(
            broken=("orgs/%s" % ORG, urllib.error.URLError("no route to host")))), False)

        # The organisation's apps. Which repositories each is on is read with the token
        # TW_INSTALLATIONS_TOKEN names, and a run that cannot read them says so, which --need-admin fails.
        apps_clause = "no app installed on the organisation holds a write that reaches this repository's signing route"

        def apps_line(state):
            lines = [line for line in printed if line.startswith("%s: %s" % (state, apps_clause))]
            others = [line for line in printed if line.startswith("FAIL") and apps_clause not in line]
            return [] if len(lines) == 1 and not others else ["printed %s" % printed]
        expect("run() with the apps' lists read, asked for all of them",
               passes(run_over(need_admin=True, azure=good_app)) + apps_line("PASS"), False)
        expect("run() with no token to read the apps' lists, not asked for all of them",
               passes(run_over(unlisted=True, azure=good_app)) + apps_line("UNSEEN"), False)
        expect("run() with no token to read the apps' lists, asked for all of them",
               fails(run_over(unlisted=True, need_admin=True, azure=good_app)) + apps_line("FAIL"), False)
        one_list = "user/installations/13/repositories?per_page=100"
        for code in (401, 403, 404):
            expect("run() with GitHub answering %d for one app's list, asked for all of them" % code,
                   fails(run_over(hidden=[one_list], code=code, need_admin=True, azure=good_app)) + apps_line("FAIL"), False)
            expect("run() with GitHub answering %d for one app's list, not asked for all of them" % code,
                   passes(run_over(hidden=[one_list], code=code, azure=good_app)) + apps_line("UNSEEN"), False)
        expect("run() with GitHub answering 500 for one app's list", fails(run_over(
            broken=(one_list, urllib.error.HTTPError("https://api.github.com/" + one_list, 500, "Server Error", {}, None)),
            azure=good_app)), False)
        expect("run() with an app that edits workflows installed on this repository",
               fails(run_over({one_list: this_one}, azure=good_app)) + apps_line("FAIL"), False)
        expect("run() with an app that edits workflows installed on every repository",
               fails(run_over({installed: dict(answers[installed], installations=[dict(a, repository_selection="all") if a["id"] == 13 else a
                                                                                    for a in apps])}, azure=good_app)) + apps_line("FAIL"), False)
        expect("run() with the app that held no route write given administration, on this repository",
               fails(run_over({installed: dict(answers[installed], installations=[dict(apps[0], permissions=dict(apps[0]["permissions"], administration="write"))]
                                               + apps[1:]),
                               "user/installations/11/repositories?per_page=100": this_one}, azure=good_app)) + apps_line("FAIL"), False)
        expect("run() with the apps answered as an empty list to a token not shown the Actions settings",
               passes(run_over({installed: {"total_count": 0, "installations": []}}, hidden=hidden_from_writers[:1], azure=good_app))
               + apps_line("UNSEEN"), False)
        expect("run() with the apps answered as an empty list to a token shown the Actions settings",
               passes(run_over({installed: {"total_count": 0, "installations": []}}, azure=good_app)) + apps_line("PASS"), False)

        with open(good_app, "w", encoding="utf-8") as f:
            json.dump(dict(app, password_credentials=[{"keyId": "k"}]), f)
        expect("run() with a client secret on the Entra app", fails(run_over(azure=good_app)), False)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    # Every list is read to its last page, and only from GitHub's API.
    def paged(bodies, last_link=None):
        served = []

        def page(url):
            served.append(url)
            at = len(served) - 1
            if at >= len(bodies):
                return "[]", {}
            more = at + 1 < len(bodies)
            link = '<https://api.github.com/next?page=%d>; rel="next", <https://api.github.com/last>; rel="last"' % (at + 2)
            return json.dumps(bodies[at]), {"Link": link if more else (last_link or "")}
        return page, served

    page, served = paged([[{"login": "a"}], [{"login": "b"}], [{"login": "c"}]])
    got = [c["login"] for c in github("repos/x/collaborators", page)]
    expect("a list on three pages read whole", [] if got == ["a", "b", "c"] else ["read %s" % got], False)
    page, served = paged([{"total_count": 2, "secrets": [{"name": "A"}]}, {"total_count": 2, "secrets": [{"name": "MACOS_TEAM_ID"}]}])
    got = [x["name"] for x in github("repos/x/actions/secrets", page)["secrets"]]
    expect("secrets on two pages read whole", [] if got == ["A", "MACOS_TEAM_ID"] else ["read %s" % got], False)
    for key in ("installations", "repositories"):
        page, served = paged([{"total_count": 2, key: [{"id": 1}]}, {"total_count": 2, key: [{"id": REPO_NUMBER}]}])
        try:
            got = [x["id"] for x in github("orgs/x/" + key, page)[key]]
        except ValueError as e:
            got = str(e)
        expect("%s on two pages read whole" % key, [] if got == [1, REPO_NUMBER] else ["read %s" % got], False)
    # The apps' lists are read with the token that can list them, and everything else with GH_TOKEN.
    sent = []

    class Answer:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *raised):
            return False

        def read(self):
            return b'{"total_count": 0, "repositories": []}'
    saved_open, saved_owner = urllib.request.urlopen, os.environ.get("GH_TOKEN")
    urllib.request.urlopen = lambda request, timeout=None: sent.append(request.get_header("Authorization")) or Answer()
    os.environ["GH_TOKEN"] = "owner"
    try:
        installations_reader("lister")("user/installations/1/repositories?per_page=100")
        get("https://api.github.com/orgs/x")
    finally:
        urllib.request.urlopen = saved_open
        if saved_owner is None:
            os.environ.pop("GH_TOKEN", None)
        else:
            os.environ["GH_TOKEN"] = saved_owner
    expect("the apps' lists read with their own token, and the rest with GH_TOKEN",
           [] if sent == ["Bearer lister", "Bearer owner"] else ["sent %s" % sent], False)
    # A page of another shape than the first is refused rather than dropped, and so is a list that
    # never ends.
    for label, bodies in (("a list whose second page is not a list", [[{"login": "a"}], {"login": "b"}]),
                          ("secrets whose second page holds no list of them", [{"total_count": 2, "secrets": [{"name": "A"}]},
                                                                                {"total_count": 2}])):
        page, served = paged(bodies)
        try:
            github("repos/x/actions/secrets", page)
            wrong.append("%s: read, should be refused" % label)
        except ValueError:
            pass

    def endless(url):
        return "[1]", {"Link": '<https://api.github.com/again>; rel="next"'}
    try:
        github("repos/x/rulesets", endless)
        wrong.append("a list linking to a next page for ever: read, should be refused")
    except ValueError:
        pass
    page, served = paged([[1]], last_link='<https://example.com/next>; rel="next"')
    try:
        github("repos/x/rulesets", page)
        wrong.append("a list going on to a page off GitHub's API: read, should be refused")
    except ValueError:
        pass

    def may_start(login, number):
        done = subprocess.run([sys.executable, os.path.abspath(__file__), "--may-start", login, number],
                              capture_output=True, text=True, timeout=120)
        return done.returncode

    expect("--may-start for the account written down", may_start(login, str(number)), 0)
    expect("--may-start for another administrator", may_start("nicolekairo", "236548393"), 1)
    expect("--may-start for the name written down on another account", may_start(login, "1"), 1)

    # --tree exits 1 on a failure, run as CI runs it. A copy of this file reads its workflows from the
    # folder it sits in, so one more workflow entering release is planted beside the copy's.
    tree = tempfile.mkdtemp(prefix="tw-route-tree-self-test-")
    try:
        os.makedirs(os.path.join(tree, "scripts"))
        shutil.copy(os.path.abspath(__file__), os.path.join(tree, "scripts", "the-release-route-holds.py"))
        shutil.copy(SIGNATURE_CHECK, os.path.join(tree, "scripts"))
        shutil.copytree(WORKFLOWS, os.path.join(tree, ".github", "workflows"))

        def tree_run():
            done = subprocess.run([sys.executable, os.path.join(tree, "scripts", "the-release-route-holds.py"), "--tree"]
                                  + (["--need-yaml"] if yaml is not None else []), capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=120)
            return done.returncode, done.stdout
        if yaml is not None:
            code, out = tree_run()
            expect("--tree over the workflows as they are", [] if code == 0 else ["exit %d: %s" % (code, out)], False)
        with open(os.path.join(tree, ".github", "workflows", "x.yml"), "w", encoding="utf-8", newline="\n") as f:
            f.write("on: push\njobs:\n  steal:\n    runs-on: ubuntu-latest\n    environment: release\n    steps:\n      - run: true\n")
        code, out = tree_run()
        expect("--tree with another workflow entering release", [] if code == 1 and re.search(
            r"^FAIL: only release\.yml's .*x\.yml enters an environment", out, re.M) else ["exit %d: %s" % (code, out)], False)
    finally:
        shutil.rmtree(tree, ignore_errors=True)

    # --need-admin reaches run(), and only when it is asked for.
    asked = []
    saved = globals()["run"]
    globals()["run"] = lambda *given, **named: asked.append(named.get("need_admin")) or (0, [])
    try:
        globals()["main"](["--need-admin"])
        globals()["main"]([])
    finally:
        globals()["run"] = saved
    expect("--need-admin handed to run(), and not otherwise", [] if asked == [True, False] else ["handed %s" % asked], False)
    # The token that lists the apps' repositories reaches run() as a reader, and nothing does without it.
    handed, saved_lister = [], os.environ.pop(INSTALLATIONS_TOKEN, None)
    globals()["run"] = lambda *given, **named: handed.append(named.get("reach")) or (0, [])
    try:
        globals()["main"]([])
        os.environ[INSTALLATIONS_TOKEN] = "lister"
        globals()["main"]([])
    finally:
        globals()["run"] = saved
        os.environ.pop(INSTALLATIONS_TOKEN, None)
        if saved_lister is not None:
            os.environ[INSTALLATIONS_TOKEN] = saved_lister
    expect("%s handed to run() as a reader, and nothing without it" % INSTALLATIONS_TOKEN,
           [] if len(handed) == 2 and handed[0] is None and callable(handed[1]) else ["handed %s" % handed], False)
    # main() exits with what run() found, so a failure reaches CI, the push check, and the release workflow.
    globals()["run"] = lambda *given, **named: (1, [])
    try:
        exited = globals()["main"]([])
    finally:
        globals()["run"] = saved
    expect("main() over a run that failed", [] if exited == 1 else ["exit %s" % exited], False)
    # And refused beside --tree, where it would pass having read no setting at all.
    globals()["run"] = lambda *given, **named: asked.append("ran") or (0, [])
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            globals()["main"](["--tree", "--need-admin"])
        refused = None
    except SystemExit as e:
        refused = e.code
    finally:
        globals()["run"] = saved
    expect("--need-admin beside --tree refused before anything runs",
           [] if refused == 2 and asked[-1] != "ran" else ["exit %s, ran %s" % (refused, asked[-1] == "ran")], False)

    if not parse_shapes_run:
        print("self-test: PyYAML is not installed here, so the shapes only a parse refuses were not run")
        if need_yaml:
            wrong.append("the shapes only a parse refuses could not be run")
    for line in wrong:
        print("self-test: " + line)
    if wrong:
        print("self-test: %d judged wrongly" % len(wrong))
        return 1
    print("self-test: every shape judged as it should be; refused among them an environment widened, a ruleset "
          "disabled or bypassed by writers, main unprotected, another workflow entering release, release.yml "
          "started by a tag, the signing action's cache left on, a client secret named, the Linux signature held "
          "to a job other than the one that signs Linux archives, a tag called main answering for main, and anybody "
          "but the Entra app holding a role that signs on our certificate profile, and an app able to write to the route")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tree", action="store_true", help="read only the workflows in this checkout")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--need-yaml", action="store_true", help="fail where PyYAML is not installed")
    parser.add_argument("--need-admin", action="store_true", help="fail on any setting GitHub did not show this token, "
                                                                   "rather than print it as UNSEEN")
    parser.add_argument("--azure", help="a JSON file holding the Entra app's federated, password and key "
                                        "credentials and its role assignments, the signing account, and every role "
                                        "assignment on the subscription, as an identity that can read them wrote it")
    parser.add_argument("--may-start", nargs=2, metavar=("LOGIN", "NUMBER"),
                        help="say whether this account may start a release, exit 0 when it may and 1 when not")
    parser.add_argument("--token-subject", nargs=2, metavar=("AUDIENCE", "ENVIRONMENT"),
                        help="in a job of release.yml, ask GitHub for this job's token for AUDIENCE and say whether "
                             "it names ENVIRONMENT, main and release.yml, exit 0 when it does and 1 when not")
    args = parser.parse_args(argv)
    if args.token_subject:
        audience, environment = args.token_subject
        try:
            claims = token_claims(audience)
        except (OSError, urllib.error.URLError, ValueError, KeyError, IndexError, TypeError) as e:
            print("FAIL: the token this job is given for %s could not be read: %s" % (audience, e))
            return 1
        problems = judge_token(claims, environment)
        if problems:
            print("FAIL: %s" % problems[0])
            return 1
        print("PASS: the token this job is given for %s names %s" % (audience, claims["sub"]))
        return 0
    if args.may_start:
        problems = judge_starter(*args.may_start)
        print(problems[0] if problems else "%s may start a release" % args.may_start[0])
        return 1 if problems else 0
    if args.self_test:
        return self_test(args.need_yaml)
    if args.need_admin and args.tree:
        parser.error("--need-admin asks for settings read from GitHub, and --tree reads none")
    token = os.environ.get(INSTALLATIONS_TOKEN)
    code, _ = run(args.tree, args.need_yaml, azure=args.azure, need_admin=args.need_admin,
                  reach=installations_reader(token) if token else None)
    return code


if __name__ == "__main__":
    sys.exit(main())
