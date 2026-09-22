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
// between the two RULES markers below is the same text in both. That side holds the two blocks to
// each other, in its build and before its pushes, because it can check this repository out and this
// one cannot check it out: a comparison of two trees runs where both trees are. Until 2026-09-15
// this side compared them where the other repository happened to be on disk and said "not compared
// here" and passed where it was not, which was every build.
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

const here = join(dirname(fileURLToPath(import.meta.url)), '..');

// Which tree to read, and what counts as a surface in it.
//
// By default this repository, with the list further down. `--tree <path> --surfaces <pattern>`
// reads somewhere else instead, which is how the app is held to these rules without a third copy of
// them: one set of rules, read wherever the tree happens to be. The two options are given together
// or not at all, because a tree read with this repository's list would find almost nothing, and a
// check that reads nothing and prints clean is worse than no check at all.
const argv = process.argv.slice(2);
const option = (name) => {
  const at = argv.indexOf(`--${name}`);
  return at === -1 ? null : argv[at + 1];
};
const elsewhere = option('tree');
const pattern = option('surfaces');
if ((elsewhere === null) !== (pattern === null)) {
  console.error('no price on evidence: --tree and --surfaces are given together or not at all');
  process.exit(2);
}
const root = elsewhere ?? here;

// RULES BEGIN
// A sentence that offers one of these things is refused, unless the offer itself is denied.
//
// Until 2026-09-14 a denying word anywhere in a sentence exempted the whole of it, so "Stamping costs
// $0.01 per receipt, with no minimum." went through on its "no", and a price had to be a currency
// sign and a number with the unit straight after it, so "$10 per 1,000 receipts" and "1 cent each"
// went through as well. A denial now counts only where it governs the offer: a word such as never,
// not, no or nothing shortly before it in the same clause, a negated verb straight after it, or, for
// the precision rule alone, a sentence saying the bound is the same on every plan. The words are few
// on purpose: every one added is a way to write the refused thing past the rule.
//
// Until 2026-09-15 the rule against a price per receipt was a list of price shapes: a sum followed
// by a unit, a unit followed by a sum, and the words per receipt and by the receipt. Twelve of the
// seventeen ordinary pricing sentences the test run of that day wrote went through it, "Pricing:
// 1,000 receipts for $10." and "Receipts are 10c each." among them, because a copywriter does not
// write to a list. The rule is now the class. Any sum of money, in figures or in words, in a sentence
// that names a receipt or a stamp prices it, whatever sits between the two; and any count of receipts
// in a sentence carrying a word of paying, billing or charging is a quota, which is the same price
// with the arithmetic left to the reader. The denial words are what keep the honest sentences green,
// so a sentence saying the thing costs nothing is read as saying so.
const NEGATOR = /\b(never|not|no|nothing|none|neither|nor)\b|n't\b/i;
const WITHOUT = /\bwithout\b/i;
const NEGATED_AFTER = /^\W*(\w+\s+){0,2}?(?:(?:is|are|was|were|will|would|can|could|does|do|has|have|be|costs?)\s+(?:never|not|nothing|no)\b|\w+n't\b|never\b|(?:is|are|stays?|remains?)\s+free\b)/i;
const SAME_FOR_ALL = /\b(same|identical|equal)\s+(\w+\s+)?(bounds?|precision|resolution|accuracy|intervals?|widths?|evidence)\b|\bfor (everybody|everyone|all)\b|\balike\b|\b(every|all|each|any)\s+(plans?|tiers?)\b/i;
const CLAUSE_BREAK = new RegExp('[,;:()]|\\s[-\u2013\u2014]\\s|\\b(?:and|but|with|while|though|although|plus|except|unless|whereas)\\b', 'gi');
const OFFERED_BY_PLAN = /\b(paid|premium|pro|plus|enterprise|business|upgrade[sd]?|subscribers?|subscriptions?|tiers?|plans?)\b/i;
// A word of paying, which turns a count of receipts into a quota.
const PAYING = /\b(billed|billing|bills?|paid|pay|pays|paying|payments?|charged|charges?|charging|overage|priced|prices?|pricing|costs?|fees?|invoiced?|metered)\b/i;
const EVIDENCE = '(?:receipts?|stamps?|stamping|countersign\\w*|verifications?|timestamps?|signatures?)';
const NUMBER_WORD =
  '(?:a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|fifteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|million|half a|a few)';
// A sum of money, in figures or in words: a currency sign and a number, USD 0.01, 0.01 USD,
// 10 cents, 10c, 0.5p, a number and the cent sign, ten cents, a penny, twenty five dollars, half a
// cent. A sum in figures needs a boundary before its first digit, so a digit run inside a digest is
// not read as one. Every sign is written as an escape, because this file is held to ASCII.
const MONEY =
  '(?:[$\\u00a3\\u20ac]\\s?\\d[\\d.,]*' +
  '|\\b(?:USD|GBP|EUR)\\s?\\d[\\d.,]*' +
  '|\\b\\d[\\d.,]*\\s*(?:USD|GBP|EUR|dollars?|pounds?|euros?|cents?|pence|bucks?|quid)\\b' +
  '|\\b\\d[\\d.,]*\\s*\\u00a2' +
  '|\\b\\d[\\d.,]*[cp]\\b' +
  `|\\b${NUMBER_WORD}(?:\\s+${NUMBER_WORD})?\\s+(?:cents?|penny|pennies|pence|dollars?|pounds?|euros?|bucks?|quid)\\b)`;
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
    // A sentence saying the bound is the same on every plan is the promise itself, so it denies
    // this rule. It denies no other: "$1 each for everybody" is a price on everybody's receipts.
    deniedBySameness: true,
  },
  {
    name: 'a price per receipt',
    why: 'a price on each receipt makes people ration them, and a receipt on every event is the point',
    // The words that price a receipt with no sum in the sentence.
    offers: [
      /\b(priced|charged|billed|metered|pay|paying|costs?|fees?|prices?|pricing|billing)\b[^.]{0,40}\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\b/gi,
      /\bper[- ](receipt|stamp|countersign\w*|verification|timestamp)\s+(price|pricing|fees?|charges?|costs?|billing|rates?)\b/gi,
      /\b(priced|charged|billed|metered|pay|paying)\b[^.]{0,20}\bby the (receipt|stamp)\b/gi,
    ],
    // Any sum of money in a sentence that names a receipt or a stamp.
    withEvidence: [new RegExp(MONEY, 'gi')],
    // Any count of receipts in a sentence that also carries a word of paying: a plan of so many
    // receipts, and receipts free up to so many.
    withEvidencePaid: [
      new RegExp(`\\b${QUANTITY}\\s+${EVIDENCE}\\b`, 'gi'),
      new RegExp(`\\b${EVIDENCE}\\b[^.;]{0,40}?\\bup to\\s+${QUANTITY}`, 'gi'),
    ],
  },
];

// The sentences the rules have to refuse. The first two are what `TW_PRICE_PROVE` and
// `PRICE_CHECK_PROVE` add to a surface as read. The rest are the seeds of the test runs of
// 2026-09-14 and 2026-09-15, twelve of which passed until the second of those days, and a further
// set of the same class written the way a price is written rather than the way a rule is.
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
  'Pricing: 1,000 receipts for $10.',
  'Receipts are 10c each.',
  'Stamps cost 0.5p per stamp.',
  'You pay for what you stamp, $0.001 a go.',
  'Plans start at 10,000 receipts a month for $49.',
  'Each receipt is ten cents.',
  'A thousand receipts cost ten dollars.',
  'One penny a receipt, billed monthly.',
  'EUR 0.01 per receipt.',
  'USD 0.01/receipt, no minimum.',
  'Pay as you go: 1\u00a2 a stamp.',
  '\u00a35 a month buys 500 receipts.',
  'Receipt packs: 100 for \u00a31.',
  'The Team plan includes 50,000 receipts; each one after that is billed.',
  'Overage is charged per receipt above your plan.',
  'Metered billing, by the receipt.',
  'Receipts are free up to 1,000 a month, then paid.',
  'Ten receipts for a dollar.',
  'From $9 a month for 5,000 receipts.',
  'Stamping costs a penny.',
  'Receipts: 2p each.',
  'Bulk receipts at \u20ac0.005.',
  'Twenty five cents a stamp, billed monthly.',
  'The Team plan includes 50,000 receipts, and each one after that is billed.',
  'Receipts are free up to 1,000 a month and metered after that.',
  'Overage runs 0.1 cents per receipt.',
  'Pay per stamp: 1c.',
  'Receipts cost half a cent.',
  'USD 5 buys a thousand stamps.',
  'Each verification is $0.10.',
  'Stamps are a cent apiece.',
  'Receipts are $1 each for everybody.',
  'It works out at about a tenth of a cent a receipt.',
];

// The sentences this product does say, or could say, and the rules have to let through: a denial
// beside a sum, a count of receipts beside nothing anybody pays, and the promise in its own words.
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
  'Verifying a receipt costs nothing, not $1 and not a cent.',
  'You pay nothing for 1,000 receipts or a million.',
  'No plan caps how many receipts you can make, and none is billed by the receipt.',
  'A receipt is about 10 KB and costs nothing to check.',
  'Stamping is free in phase one.',
  'The Action costs nothing to run, and neither does a receipt.',
  'Nine servers behind six operators, and a receipt of 9765 bytes.',
  'The bound is the same for everybody, paid or not.',
  'Verifying 1,000 receipts costs nothing.',
  'A receipt is never sold, and a stamp is never charged for.',
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

function denied(rule, sentence, index, length) {
  const { before, after } = clause(sentence, index, length);
  const words = before.trim().split(/\s+/);
  return (
    NEGATOR.test(words.slice(-5).join(' ')) ||
    WITHOUT.test(words.slice(-2).join(' ')) ||
    NEGATED_AFTER.test(after) ||
    (rule.deniedBySameness === true && SAME_FOR_ALL.test(sentence))
  );
}

function offered(rule, sentence, patterns) {
  for (const pattern of patterns || []) {
    for (const m of sentence.matchAll(pattern)) {
      if (!denied(rule, sentence, m.index, m[0].length)) return true;
    }
  }
  return false;
}

function refuses(rule, sentence) {
  const aboutEvidence = new RegExp(`\\b${EVIDENCE}\\b`, 'i').test(sentence);
  return (
    offered(rule, sentence, rule.offers) ||
    (OFFERED_BY_PLAN.test(sentence) && offered(rule, sentence, rule.offeredByPlan)) ||
    (aboutEvidence && offered(rule, sentence, rule.withEvidence)) ||
    (aboutEvidence && PAYING.test(sentence) && offered(rule, sentence, rule.withEvidencePaid))
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
const SURFACE = /(^|\/)[^/]+\.(md|markdown|txt|text)$|^(LICENSE|NOTICE|action\.yml|verifier-page\/[^/]+\.html|scripts\/action-[^/]+\.(sh|py)|crates\/cli\/src\/render\.rs|crates\/verify\/src\/[^/]+\.rs)$/i;
const READ = pattern === null ? SURFACE : new RegExp(pattern, 'i');
const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { cwd: root, encoding: 'utf8' })
  .split('\n')
  .filter((path) => READ.test(path) && existsSync(join(root, path)));

// Every tree this reads carries a README and more than a handful of surfaces, so too few of them
// means the pattern is wrong rather than that the tree has nothing to say.
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

if (failures) {
  console.error(`no price on evidence: ${failures} refused over ${files.length} surfaces`);
  process.exit(1);
}
console.log(
  `no price on evidence: ${files.length} surfaces read${elsewhere ? ` in ${elsewhere}` : ''}, ` +
    'no tier on precision and no price per receipt',
);
