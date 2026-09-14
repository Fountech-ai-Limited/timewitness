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
// What it reads here: every markdown and text file in the tree, the licence files, `action.yml`, the
// verifier page, the scripts that write the Action's summary, and the verdict text the command line
// prints. Those are the words a reader of this repository or of a receipt is handed. A file not yet
// committed is read too, so the check says no before a commit rather than after one.
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
// A sentence that offers one of these things is refused, unless the offer itself is denied.
//
// Until 2026-09-14 a denying word anywhere in a sentence exempted the whole of it, so "Stamping costs
// $0.01 per receipt, with no minimum." went through on its "no", and a price had to be a currency
// sign and a number with the unit straight after it, so "$10 per 1,000 receipts" and "1 cent each"
// went through as well. A denial now counts only where it governs the offer: a word such as never,
// not, no or nothing shortly before it in the same clause, a negated verb straight after it, or a
// sentence saying the bound is the same on every plan. The words are few on purpose: every one added
// is a way to write the refused thing past the rule.
const NEGATOR = /\b(never|not|no|nothing|none|neither|nor)\b|n't\b/i;
const WITHOUT = /\bwithout\b/i;
const NEGATED_AFTER = /^\W*(\w+\s+){0,2}?(is|are|was|were|will|would|can|could|does|do|has|have|be)\s+(never|not)\b|^\W*(\w+\s+){0,2}?\w+n't\b|^\W*(\w+\s+){0,1}?never\b/i;
const SAME_FOR_ALL = /\b(same|identical|equal)\s+(\w+\s+)?(bounds?|precision|resolution|accuracy|intervals?|widths?|evidence)\b|\bfor (everybody|everyone|all)\b|\balike\b|\b(every|all|each|any)\s+(plans?|tiers?)\b/i;
const CLAUSE_BREAK = new RegExp('[,;:()]|\\s[-\u2013\u2014]\\s|\\b(?:and|but|with|while|though|although|plus|except|unless|whereas)\\b', 'gi');
const OFFERED_BY_PLAN = /\b(paid|premium|pro|plus|enterprise|business|upgrade[sd]?|subscribers?|subscriptions?|tiers?|plans?)\b/i;
const EVIDENCE = '(?:receipts?|stamps?|countersign\\w*|verifications?|timestamps?|signatures?)';
const MONEY =
  '(?:[$\\u00a3\\u20ac]\\s?\\d[\\d.,]*|\\b(?:USD|GBP|EUR)\\s?\\d[\\d.,]*' +
  '|\\b\\d[\\d.,]*\\s*(?:USD|GBP|EUR|dollars?|pounds?|euros?|cents?|pence)\\b' +
  '|\\b(?:a|one|half a)\\s+(?:cent|penny|dollar|pound|euro)\\b)';
const QUANTITY = '(?:\\d[\\d.,]*\\s*(?:k|thousand|million)?|(?:a|one)\\s+(?:hundred|thousand|million)|hundred|thousand|million)';
const SHARPER = '(?:full|higher|finer|better|tighter|narrower|smaller|sharper|extra|increased|improved|enhanced|more\\s+(?:precise|accurate|exact))';
const BOUND_WORD = '(?:precision|resolution|accuracy|bounds?|intervals?|widths?|error\\s+bars?|uncertainty)';
const SCALE = '(?:sub-?(?:millisecond|ms|microsecond)|(?:milli|micro|nano)second)';

const RULES = [
  {
    name: 'a reduced-precision tier',
    why: 'the bound is the same for everybody, and a plan may differ only in how much it covers',
    offers: [
      /\b(reduced|lower|limited|coarser?|degraded|rounded|truncated|basic|partial)\s+(precision|resolution|accuracy|bounds?|intervals?)\b/gi,
      /\b(precision|resolution|accuracy)\s+(tiers?|plans?|add-ons?|upgrades?|levels?)\b/gi,
    ],
    // Sharper evidence is refused only where a plan is named beside it. "Full precision" on its own
    // is the promise, and "the Pro plan unlocks tighter intervals" is the thing the promise forbids.
    offeredByPlan: [
      new RegExp(`\\b${SHARPER}\\s+${BOUND_WORD}\\b`, 'gi'),
      new RegExp(`\\b${SCALE}[- ]${BOUND_WORD}\\b`, 'gi'),
    ],
  },
  {
    name: 'a price per receipt',
    why: 'a price on each receipt makes people ration them, and a receipt on every event is the point',
    offers: [
      new RegExp(`${MONEY}\\s*(?:/|per\\b|a\\b|each\\b|for each\\b|for every\\b|for\\b)?\\s*(?:${QUANTITY}\\s+)?${EVIDENCE}\\b`, 'gi'),
      new RegExp(`\\b(?:each|every|per|a single|one)\\s+${EVIDENCE}\\b[^.]{0,40}?\\b(?:costs?|is|are|priced|billed|charged|at|for)\\b[^.]{0,20}?${MONEY}`, 'gi'),
      /\b(priced|charged|billed|metered|pay|paying|costs?|fees?|prices?|pricing|billing)\b[^.]{0,40}\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\b/gi,
      /\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\s+(price|pricing|fees?|charges?|costs?|billing|rates?)\b/gi,
      /\b(priced|charged|billed|metered|pay|paying)\b[^.]{0,20}\bby the (receipt|stamp)\b/gi,
    ],
    // A sum with each or apiece prices a unit, and in a sentence about receipts the unit is a receipt.
    withEvidence: [new RegExp(`${MONEY}\\s*(?:each|apiece|a piece|per piece|per unit|a pop)\\b`, 'gi')],
  },
];

// The sentences the rules have to refuse, and they are the seeds the test run of 2026-09-14 wrote.
// The first two are what `TW_PRICE_PROVE` and `PRICE_CHECK_PROVE` add to a surface as read.
const SEEDS = {
  precision: 'Full precision is available on the Pro plan.',
  'per-receipt': 'Stamping costs $0.01 per receipt.',
};
const REFUSED = [
  'A reduced precision tier is included on the free plan.',
  'Receipts are priced at $0.01 per receipt.',
  'Stamping costs $0.01 per receipt, with no minimum.',
  'The free plan gets reduced precision on the same agent.',
  'Stamping is $10 per 1,000 receipts.',
  'Receipts are $10 per 1,000 receipts.',
  'Receipts are 1 cent each.',
  'Each receipt costs 1 cent.',
  'Stamping is 0.01 USD per receipt.',
  'The Pro plan unlocks tighter intervals.',
  'Stamps at $0.01 per stamp.',
  'Receipts at $0.01 apiece.',
  'Enterprise customers get sub-millisecond bounds.',
];

const HONEST = [
  'Nothing is ever priced per receipt.',
  'Full precision for everybody, always.',
  'The free tier gets the same bound as a paid one.',
  'The reading is taken at nanosecond resolution.',
  'Verifying costs nothing and needs no account.',
  'No plan gets reduced precision.',
  'Reduced precision is never offered.',
  'Full precision on every plan.',
  'Every plan, paid or free, gets full precision.',
  'There is no fee and no price per receipt.',
  'A plan may differ in how much it covers, never in how narrow the bound is.',
  'A wider interval says something true and a narrow wrong one does not.',
];

function sentences(text) {
  return text
    .split(/(?<=[.!?])\s+|\n\s*\n|\n\s*[-*]\s+/)
    .map((s) => s.replace(/\s+/g, ' ').trim())
    .filter(Boolean);
}

// The clause a match sits in, split into what comes before the match and what comes after it.
function clause(sentence, index, length) {
  let start = 0;
  let end = sentence.length;
  for (const b of sentence.matchAll(CLAUSE_BREAK)) {
    if (b.index + b[0].length <= index) start = b.index + b[0].length;
    else if (b.index >= index + length) {
      end = b.index;
      break;
    }
  }
  return { before: sentence.slice(start, index), after: sentence.slice(index + length, end) };
}

function denied(sentence, index, length) {
  const { before, after } = clause(sentence, index, length);
  const words = before.trim().split(/\s+/);
  return (
    NEGATOR.test(words.slice(-5).join(' ')) ||
    WITHOUT.test(words.slice(-2).join(' ')) ||
    NEGATED_AFTER.test(after) ||
    SAME_FOR_ALL.test(sentence)
  );
}

function offered(sentence, patterns) {
  for (const pattern of patterns || []) {
    for (const m of sentence.matchAll(pattern)) {
      if (!denied(sentence, m.index, m[0].length)) return true;
    }
  }
  return false;
}

function refuses(rule, sentence) {
  return (
    offered(sentence, rule.offers) ||
    (OFFERED_BY_PLAN.test(sentence) && offered(sentence, rule.offeredByPlan)) ||
    (new RegExp(`\\b${EVIDENCE}\\b`, 'i').test(sentence) && offered(sentence, rule.withEvidence))
  );
}

function refusals(text) {
  const found = [];
  for (const sentence of sentences(text)) {
    for (const rule of RULES) {
      if (refuses(rule, sentence)) found.push({ rule, sentence });
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
  for (const line of REFUSED) {
    if (!refusals(line).length) broken.push(`a sentence the rules exist to refuse passes: "${line}"`);
  }
  for (const line of HONEST) {
    if (refusals(line).length) broken.push(`an honest sentence is refused: "${line}"`);
  }
  return broken;
}

// Character references, so a price written as `&#36;0.01` is read as the sum a reader sees.
function decodeEntities(text) {
  return text
    .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&dollar;/g, '$')
    .replace(/&pound;/g, String.fromCharCode(0xa3))
    .replace(/&euro;/g, String.fromCharCode(0x20ac))
    .replace(/&cent;/g, ' cent')
    .replace(/&amp;/g, '&');
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

// Every markdown and text file the repository tracks, wherever it sits, and the licence files, which
// are text with no extension. The rest are named because they print words to a reader: the Action,
// the verifier page, the scripts that write the Action's summary, and the command line's verdicts.
// Until 2026-09-14 this was README.md and docs/ alone, so a PRICING.md at the root was never read.
const SURFACE = /(^|\/)[^/]+\.(md|markdown|txt|text)$|^(LICENSE|NOTICE|action\.yml|verifier-page\/[^/]+\.html|scripts\/action-[^/]+\.(sh|py)|crates\/cli\/src\/render\.rs)$/i;
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
  .split('\n')
  .filter((path) => SURFACE.test(path) && existsSync(join(root, path)));

if (!files.includes('README.md') || files.length < 5) {
  console.error(`no price on evidence: only ${files.length} surfaces were found, so the list of what to read has gone wrong`);
  process.exit(1);
}

let failures = 0;
for (const path of files) {
  let text = decodeEntities(
    readFileSync(join(root, path), 'utf8')
      .replace(/<[^>]+>/g, ' ')
      .replace(/`/g, ''),
  );
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
