#!/usr/bin/env node
// A figure about how much checking happens says where it came from, or it does not go out.
//
// Checking a receipt is free, needs no account and reaches nothing of ours, so most of it happens
// where we cannot see it and never will. What can be counted is a check run through the hosted
// checker, and that is the only figure this product has. A sentence saying how many verifications
// happened, full stop, claims every one of them, including the ones nobody counted, and that is a
// traction number nobody could stand behind.
//
// So the rule: any count of checks or verifications on a surface carries the words "through the
// hosted checker" in the same sentence. What one counted verification is, how repeats are handled
// and what is permanently outside the figure are in docs/counting-verifications.md, which is the one
// place that says it.
//
// Nothing is counted today and no such figure exists anywhere, which is the cheapest moment to write
// this, for the same reason the price rules went in before there was a pricing page.
//
//     node scripts/a-verification-figure-names-the-checker.mjs
//     node scripts/a-verification-figure-names-the-checker.mjs --tree <path> --surfaces <pattern>
//
// It proves itself twice, the same way the price rules do. Every run first puts the rule to the
// sentences it exists to refuse and to the honest ones it must let through, and stops if either
// answer is wrong, so a rule broken by an edit cannot print clean. `TW_COUNT_PROVE=1` then adds a
// refused sentence to the README as read, and the run has to refuse it; CI runs that too and reads
// the reason.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = join(dirname(fileURLToPath(import.meta.url)), '..');

const argv = process.argv.slice(2);
const option = (name) => {
  const at = argv.indexOf(`--${name}`);
  return at === -1 ? null : argv[at + 1];
};
const elsewhere = option('tree');
const pattern = option('surfaces');
if ((elsewhere === null) !== (pattern === null)) {
  console.error('a verification figure: --tree and --surfaces are given together or not at all');
  process.exit(2);
}
const root = elsewhere ?? here;

// RULES BEGIN
// The words that make a figure honest. They are required in the same sentence as the count, and
// they are required word for word: "on the checker" and "through our checker" are not this phrase,
// and a reader who has to work out which checker was meant is a reader being asked to guess.
const SAYS_WHERE = /\bthrough the hosted checker\b/i;

// A number, in figures or in words. The figures form needs a boundary before its first digit so a
// digit inside a digest is not read as one. The words form is large quantities only: a traction
// figure is written in thousands and millions, and "three checks" is ordinary prose about three
// checks, so reading small numbers in words would stop the rule at every sentence in this tree.
const NUMBER =
  '(?:\\d[\\d.,]*\\s*(?:k|thousand|million|m)?' +
  '|\\b(?:thousand|million|hundreds|thousands|millions|dozens)\\b)';
const CHECKS = '(?:verifications?|checks?)';
const CHECKED = '(?:verified|checked)';

// The three shapes a count of checks is written in, and each is kept tight on purpose. A rule that
// stopped every sentence with a number and the word check in it would be switched off by whoever it
// stopped next, and a rule nobody runs is worse than no rule.
const COUNTS = [
  // "4,000 verifications", "ten thousand checks", "dozens of checks". A number that is a label
  // rather than a quantity is not one of these: "every version 0 check" counts nothing, and both
  // readers in this repository carry that sentence.
  new RegExp(
    `(?<!\\b(?:version|row|line|step|item|page|figure|table|phase|ring|wave)\\s)\\b${NUMBER}\\s+(?:of\\s+)?${CHECKS}\\b`,
    'i',
  ),
  // "Verifications this month: 4,000", "checks run so far, 4,000". The number comes straight after
  // the punctuation, so "three checks, and each fails on its own" is not one of these.
  new RegExp(`\\b${CHECKS}\\b[^.;:]{0,20}[:,]\\s*${NUMBER}\\b`, 'i'),
  // "checked 12,000 receipts", "verified 900 times". What is being counted has to be named after the
  // number, which is what keeps a date out of it: "checked on 2026-09-09" counts nothing.
  new RegExp(`\\b${CHECKED}\\b[^.;]{0,20}?\\b${NUMBER}\\s+(?:times|receipts?|stamps?|${CHECKS})\\b`, 'i'),
];
// RULES END

function sentences(text) {
  return text
    .split(/(?<=[.!?])\s+|\n\s*\n|\n\s*[-*]\s+/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

function refuses(sentence) {
  if (SAYS_WHERE.test(sentence)) return false;
  return COUNTS.some((shape) => shape.test(sentence));
}

function refusals(text) {
  return sentences(text).filter(refuses);
}

const SEED = 'It has done 4,000 verifications this month.';
const REFUSED = [
  SEED,
  'Readers have checked 12,000 receipts so far.',
  'Ten thousand verifications and counting.',
  'Verifications this month: 4,000.',
  'A thousand checks a day.',
  'It has been verified 900 times.',
  'Checks run so far, 4,000.',
  'Two million verifications since launch.',
  'Dozens of checks an hour.',
];
const HONEST = [
  'It has done 4,000 verifications through the hosted checker this month.',
  'Four thousand checks through the hosted checker in September, and no figure at all for the ones run offline.',
  'Verifying a receipt costs nothing and needs no account.',
  'Checking a receipt reaches nothing of ours, so most checking is not counted and never will be.',
  'The verifier checks the signature and the payload hash.',
  'The suite runs 111 test binaries with 0 failures.',
  'Nine public servers behind six operators, at sixteen polling rounds.',
  'A check on a coarser interval is never sold to somebody who has not paid.',
  'This check reads 9 surfaces.',
  'The page checks the sha256 of the module before it runs it.',
  'Three checks, and each of the three fails on its own.',
  'Every check runs in CI on both repositories.',
  'An offline verification is never counted, estimated or extrapolated.',
];

const broken = [];
for (const line of REFUSED) if (!refuses(line)) broken.push(`a sentence the rule exists to refuse passes: "${line}"`);
for (const line of HONEST) if (refuses(line)) broken.push(`an honest sentence is refused: "${line}"`);
if (broken.length) {
  for (const line of broken) console.error(`a verification figure: ${line}`);
  console.error('a verification figure: the rule cannot tell an attributed figure from a bare one, so nothing was checked');
  process.exit(1);
}

const SURFACE = /(^|\/)[^/]+\.(md|markdown|txt|text)$|^(LICENSE|NOTICE|action\.yml|verifier-page\/[^/]+\.html|scripts\/action-[^/]+\.(sh|py)|crates\/cli\/src\/render\.rs|crates\/verify\/src\/[^/]+\.rs)$/i;
const READ = pattern === null ? SURFACE : new RegExp(pattern, 'i');
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
  .split('\n')
  .filter((path) => READ.test(path) && existsSync(join(root, path)));

if (!files.includes('README.md') || files.length < 5) {
  console.error(`a verification figure: only ${files.length} surfaces were found, so the list of what to read has gone wrong`);
  process.exit(1);
}

const prove = process.env.TW_COUNT_PROVE ? SEED : null;
let failures = 0;
for (const path of files) {
  let text = readFileSync(join(root, path), 'utf8')
    .replace(/<[^>]+>/g, ' ')
    .replace(/`/g, '');
  if (prove && path === 'README.md') text += `\n\n${prove}\n`;
  for (const sentence of refusals(text)) {
    console.error(
      `a verification figure: ${path} states how much checking happens without saying where the figure came from, ` +
        `and most checking is not counted: "${sentence}"`,
    );
    failures += 1;
  }
}

if (failures) {
  console.error(`a verification figure: ${failures} refused over ${files.length} surfaces`);
  console.error('a verification figure: what may be said is in docs/counting-verifications.md');
  process.exit(1);
}
console.log(
  `a verification figure: ${files.length} surfaces read${elsewhere ? ` in ${elsewhere}` : ''}, ` +
    'every count of checks says it is through the hosted checker',
);
