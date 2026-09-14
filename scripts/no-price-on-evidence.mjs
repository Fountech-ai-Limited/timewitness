#!/usr/bin/env node
// No surface may sell precision or put a price on a receipt.
//
// Two of the oldest commitments this product has, and until this file nothing checked either.
//
// Full precision for everybody. A trust product that shows a coarser bound to people who have not
// paid is hiding evidence at the moment somebody is deciding whether to believe it, and that reads as
// a trick. "Full precision only with the tool" was put to four reviewers in the feasibility work and
// all four turned it down. A plan may differ in how much it covers; it never differs in how good the
// bound is.
//
// Never a price per receipt. Pricing each receipt makes people ration them, and the value of the
// thing is a receipt on every event rather than on the ones somebody decided were worth paying for.
//
// No pricing page and no tier exists yet, which is the cheapest moment to write this. The same rules
// read the site in the other repository, from `scripts/no-price-on-evidence.mjs` there, and the block
// between the two RULES markers below is the same text in both. Where the other repository is checked
// out beside this one, this run holds the two blocks to each other; in CI it is not, and the run says
// so rather than pretending it compared them.
//
// What it reads here: the README, everything under `docs/`, `action.yml`, the verifier page, the
// scripts that write the Action's summary, and the verdict text the command line prints. Those are
// the words a reader of this repository or of a receipt is handed.
//
//     node scripts/no-price-on-evidence.mjs
//
// It proves itself twice. Every run first puts its own rules to a seed sentence for each and to the
// honest sentences this product does say, and stops if a seed passes or an honest one is refused, so a
// rule broken by an edit cannot print clean. `TW_PRICE_PROVE=precision` or `per-receipt` then adds a
// seed to the README as read, and the run has to refuse; CI runs both and reads the reason.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// RULES BEGIN
// A sentence that says one of these things is refused, unless the same sentence denies it. The
// denying words are few on purpose: every one added is a way to write the refused thing past the rule.
const DENYING = /\b(never|not|no|nothing|without|everybody|everyone|alike|same)\b|n't\b/i;
const OFFERED_BY_PLAN = /\b(paid|premium|pro|plus|enterprise|business|upgrade[sd]?|subscribers?|subscriptions?)\b/i;
const EVIDENCE = '(?:receipts?|stamps?|countersign\\w*|verifications?|timestamps?|signatures?)';

const RULES = [
  {
    name: 'a reduced-precision tier',
    why: 'the bound is the same for everybody, and a plan may differ only in how much it covers',
    refuses: (s) =>
      /\b(reduced|lower|limited|coarser?|degraded|rounded|truncated|basic|partial)\s+(precision|resolution)\b/i.test(s) ||
      /\b(precision|resolution)\s+(tiers?|plans?|add-ons?|upgrades?|levels?)\b/i.test(s) ||
      (/\b(full|higher|finer|better|tighter|narrower|extra)\s+(precision|resolution|bounds?)\b/i.test(s) &&
        OFFERED_BY_PLAN.test(s)),
  },
  {
    name: 'a price per receipt',
    why: 'a price on each receipt makes people ration them, and a receipt on every event is the point',
    refuses: (s) =>
      new RegExp(`(?:[$\\u00a3\\u20ac]|\\b(?:USD|GBP|EUR)\\s?)\\d[\\d.,]*\\s*(?:/|per\\b|a\\b|each\\b|for each\\b)\\s*${EVIDENCE}\\b`, 'i').test(s) ||
      /\b(priced|charged|billed|metered|pay|paying|costs?|fees?|prices?|pricing|billing)\b[^.]{0,40}\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\b/i.test(s) ||
      /\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\s+(price|pricing|fees?|charges?|costs?|billing|rates?)\b/i.test(s),
  },
];

const SEEDS = {
  precision: 'Full precision is available on the Pro plan.',
  'per-receipt': 'Stamping costs $0.01 per receipt.',
};

const HONEST = [
  'Nothing is ever priced per receipt.',
  'Full precision for everybody, always.',
  'The free tier gets the same bound as a paid one.',
  'The reading is taken at nanosecond resolution.',
  'Verifying costs nothing and needs no account.',
];

function sentences(text) {
  return text
    .split(/(?<=[.!?])\s+|\n\s*\n|\n\s*[-*]\s+/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

function refusals(text) {
  const found = [];
  for (const sentence of sentences(text)) {
    if (DENYING.test(sentence)) continue;
    for (const rule of RULES) {
      if (rule.refuses(sentence)) found.push({ rule, sentence });
    }
  }
  return found;
}

function selfTest() {
  const broken = [];
  const seedFor = { 'a reduced-precision tier': SEEDS.precision, 'a price per receipt': SEEDS['per-receipt'] };
  for (const rule of RULES) {
    if (!refusals(seedFor[rule.name]).some((r) => r.rule === rule)) {
      broken.push(`the rule against ${rule.name} passes its own seed: "${seedFor[rule.name]}"`);
    }
  }
  for (const line of HONEST) {
    if (refusals(line).length) broken.push(`an honest sentence is refused: "${line}"`);
  }
  return broken;
}
// RULES END

function rulesBlock(text) {
  const start = text.indexOf('// RULES BEGIN');
  const end = text.indexOf('// RULES END');
  return start >= 0 && end > start ? text.slice(start, end) : null;
}

const broken = selfTest();
if (broken.length) {
  for (const line of broken) console.error(`no price on evidence: ${line}`);
  console.error('no price on evidence: the rules cannot tell a refused sentence from an honest one, so nothing was checked');
  process.exit(1);
}

const prove = process.env.TW_PRICE_PROVE || '';
if (prove && !SEEDS[prove]) {
  console.error(`no price on evidence: TW_PRICE_PROVE is precision or per-receipt, not ${prove}`);
  process.exit(1);
}

const SURFACE = /^(README\.md|action\.yml|docs\/.+\.md|verifier-page\/[^/]+\.html|scripts\/action-[^/]+\.(sh|py)|crates\/cli\/src\/render\.rs)$/;
const files = execFileSync('git', ['ls-files'], { cwd: root, encoding: 'utf8' })
  .split('\n')
  .filter((path) => SURFACE.test(path));

if (!files.includes('README.md') || files.length < 5) {
  console.error(`no price on evidence: only ${files.length} surfaces were found, so the list of what to read has gone wrong`);
  process.exit(1);
}

let failures = 0;
for (const path of files) {
  let text = readFileSync(join(root, path), 'utf8')
    .replace(/<[^>]+>/g, ' ')
    .replace(/`/g, '');
  if (prove && path === 'README.md') text += `\n\n${SEEDS[prove]}\n`;
  for (const { rule, sentence } of refusals(text)) {
    console.error(`no price on evidence: ${path} offers ${rule.name}, and ${rule.why}: "${sentence}"`);
    failures += 1;
  }
}

const twin = join(root, '..', 'timewitness-web', 'scripts', 'no-price-on-evidence.mjs');
if (existsSync(twin)) {
  const ours = rulesBlock(readFileSync(fileURLToPath(import.meta.url), 'utf8'));
  const theirs = rulesBlock(readFileSync(twin, 'utf8'));
  if (!ours || ours !== theirs) {
    console.error('no price on evidence: the rules here and the rules the site is read with have drifted apart; the block between the RULES markers is the same text in both repositories');
    failures += 1;
  } else {
    console.log('no price on evidence: the rules the site is read with are the same text as these');
  }
} else {
  console.log('no price on evidence: the site repository is not beside this one, so the two copies of the rules were not compared here; its own build reads the site with its copy');
}

if (failures) {
  console.error(`no price on evidence: ${failures} refused over ${files.length} surfaces`);
  process.exit(1);
}
console.log(`no price on evidence: ${files.length} surfaces read, no tier on precision and no price per receipt`);
