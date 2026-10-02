#!/usr/bin/env node
// The pre-push hook runs what the build runs, and this is what holds the two lists to each other.
//
// `scripts/before-push.sh` says at its head that every step in it is one step of the workflow, in
// the order the workflow runs them, and that a step added there and not here shows up as a
// difference between two lists rather than as silence. Until 2026-09-15 nothing compared the lists,
// so the sentence was a promise and the difference was silence after all.
//
//     node scripts/steps-match.mjs              exit 0 when the lists agree, 1 with the difference named, 2 could not run
//     node scripts/steps-match.mjs --self-test  three seeds, each watched refused
//
// What is compared: every `- name:` under the workflow's steps, in order, against every top-level
// `step "..."` in the hook, in order. A hook step whose name begins with two spaces is a part of the
// step above it and is not compared. Three lists below say where the two are allowed to differ, each
// entry with its reason, and an entry naming a step that no longer exists is itself a failure, so
// the exceptions cannot outlive what they excuse.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = '.github/workflows/ci.yml';
const HOOK = 'scripts/before-push.sh';

// Steps the workflow runs and the hook does not, with why.
const WORKFLOW_ONLY = {
  'Install the toolchain': 'a runner starts with nothing on it and this desktop does not',
  'Cache the build': 'a runner starts with nothing on it and this desktop does not',
  'That script still refuses what it is built to refuse': 'the hook runs the same four refusals as parts of the step above it',
  'That check still catches a verifier that reaches out': 'it needs a Linux network namespace, which this desktop has not, and the hook says so in its own output',
  'Cache the advisory reader': 'a runner starts with nothing on it and this desktop does not',
  'Install the advisory reader': 'a runner starts with nothing on it and this desktop does not',
  'Build the command line': 'the every-bit job builds only the release binary it sweeps, and the hook has built the workspace already',
  'Every single-bit change to a receipt is refused, with no network': 'it needs a Linux network namespace, which this desktop has not; the suite runs the same sweep in one process',
  'That check still stops where the network is in reach': 'it is the sweep above run backwards, so it needs what the sweep needs',
};

// Steps the hook runs and the workflow does not, with why.
const HOOK_ONLY = {};

// Steps both run under different names, workflow name to hook name, with why in the name itself.
const RENAMED = {
  Lints: 'Lints, on Linux',
  'The limitation list, on the surfaces this commit ships': 'The limitation list, on all three surfaces',
};

function workflowSteps(text) {
  return [...text.matchAll(/^\s*-\s*name:\s*(.+?)\s*$/gm)].map((m) => m[1]);
}

function hookSteps(text) {
  return [...text.matchAll(/^\s*step\s+"([^"]+)"/gm)].map((m) => m[1]).filter((name) => !name.startsWith('  '));
}

function compare(workflowText, hookText) {
  const problems = [];
  const workflow = workflowSteps(workflowText);
  const hook = hookSteps(hookText);
  if (workflow.length < 5) problems.push(`only ${workflow.length} named steps were read from ${WORKFLOW}, so the reader has gone wrong`);
  if (hook.length < 5) problems.push(`only ${hook.length} steps were read from ${HOOK}, so the reader has gone wrong`);
  if (problems.length) return problems;

  for (const name of Object.keys(WORKFLOW_ONLY)) {
    if (!workflow.includes(name)) problems.push(`the exception for "${name}" names a step ${WORKFLOW} no longer has`);
  }
  for (const name of Object.keys(HOOK_ONLY)) {
    if (!hook.includes(name)) problems.push(`the exception for "${name}" names a step ${HOOK} no longer has`);
  }
  for (const [theirs, ours] of Object.entries(RENAMED)) {
    if (!workflow.includes(theirs)) problems.push(`the renaming of "${theirs}" names a step ${WORKFLOW} no longer has`);
    if (!hook.includes(ours)) problems.push(`the renaming to "${ours}" names a step ${HOOK} no longer has`);
  }

  const expected = workflow.filter((name) => !(name in WORKFLOW_ONLY)).map((name) => RENAMED[name] || name);
  const actual = hook.filter((name) => !(name in HOOK_ONLY));
  const length = Math.max(expected.length, actual.length);
  for (let i = 0; i < length; i += 1) {
    if (expected[i] === actual[i]) continue;
    if (expected[i] === undefined) problems.push(`${HOOK} runs "${actual[i]}" and ${WORKFLOW} has no such step; add it there or name it in HOOK_ONLY with its reason`);
    else if (actual[i] === undefined) problems.push(`${WORKFLOW} runs "${expected[i]}" and ${HOOK} does not; add it there or name it in WORKFLOW_ONLY with its reason`);
    else problems.push(`at position ${i + 1} ${WORKFLOW} runs "${expected[i]}" and ${HOOK} runs "${actual[i]}"; the order or a name differs`);
    break;
  }
  return problems;
}

function read(path) {
  const full = join(root, path);
  if (!existsSync(full)) {
    console.error(`steps match: there is no ${path}, so nothing was compared`);
    process.exit(2);
  }
  return readFileSync(full, 'utf8');
}

const workflowText = read(WORKFLOW);
const hookText = read(HOOK);

if (process.argv[2] === '--self-test') {
  const seeds = [
    ['a step added to the workflow', workflowText.replace(/(\n\s*-\s*name:\s*Tests\s*\n)/, '$1      - name: A step nobody put in the hook\n        run: true\n'), hookText, 'A step nobody put in the hook'],
    ['a step added to the hook', workflowText, `${hookText}\nstep "A step nobody put in the workflow" true\n`, 'A step nobody put in the workflow'],
    ['two steps swapped in the hook', workflowText, hookText.replace('step "Formatting"', 'step "Formatting-swapped"').replace('step "Build"', 'step "Formatting"').replace('step "Formatting-swapped"', 'step "Build"'), 'differs'],
  ];
  let failed = 0;
  for (const [name, workflowSeed, hookSeed, reason] of seeds) {
    const problems = compare(workflowSeed, hookSeed);
    if (!problems.some((p) => p.includes(reason))) {
      console.error(`steps match: the seed "${name}" was not refused for "${reason}": ${JSON.stringify(problems)}`);
      failed = 1;
    }
  }
  const clean = compare(workflowText, hookText);
  if (clean.length) {
    console.error(`steps match: the lists as they stand are refused, so the self-test cannot tell a seed from the tree: ${clean.join('; ')}`);
    failed = 1;
  }
  if (!failed) console.log('steps match: every seed refused, and the lists as they stand agree');
  process.exit(failed);
}

const problems = compare(workflowText, hookText);
if (problems.length) {
  for (const p of problems) console.error(`steps match: ${p}`);
  process.exit(1);
}
console.log(`steps match: ${hookSteps(hookText).length} hook steps stand in for ${workflowSteps(workflowText).length} workflow steps, in the same order`);
