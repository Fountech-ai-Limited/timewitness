// Run the page's own module and its own glue, outside a browser, against a real receipt.
//
// The page and the command line are two shells around one core, and the reason for that is that two
// implementations drift and the day they drift is the day the page says a receipt is good and the
// binary says it is not. This is what checks that they have not: the same signed receipt goes
// through the WebAssembly module here and through `timewitness verify --json` there, and the two
// verdicts, the two interval widths and the two lists of what was checked have to agree.
//
// It pulls the module and the glue out of the built page rather than out of the source tree, so what
// is tested is the file somebody would actually download.
//
// One fixture was not enough. On 2026-09-08 the page hashed an empty file as one `0x00` byte, where
// the command line hashed it as the empty string, and against a receipt over a single zero byte the
// page accepted what the command line refused. This script existed to catch that and could not see
// it, for two reasons: it ran one subject of 58 bytes, and it compared the name and the state of
// each step and never the sentence the step prints. That sentence carries the digest, which is the
// number the two shells were disagreeing about. So it now runs four subjects, and compares the whole
// of every step.

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pageFile = join(root, "verifier-page", "verifier.html");
const page = readFileSync(pageFile, "utf8");

// The module, taken out of the page as a browser would find it.
const encoded = page.match(/const WASM_BASE64 = "([A-Za-z0-9+/=]+)";/);
if (!encoded) throw new Error("the built page carries no module");
const moduleBytes = Buffer.from(encoded[1], "base64");

const instance = (await WebAssembly.instantiate(moduleBytes, {})).instance.exports;

function put(bytes) {
  const address = instance.tw_alloc(bytes.length);
  new Uint8Array(instance.memory.buffer, address, bytes.length).set(bytes);
  return address;
}

function take(address) {
  if (address === 0) return null;
  const length = new DataView(instance.memory.buffer, address, 4).getUint32(0, true);
  const bytes = new Uint8Array(instance.memory.buffer, address + 4, length);
  const text = new TextDecoder().decode(bytes);
  instance.tw_free(address);
  return JSON.parse(text);
}

// A receipt to check. By default the one committed under the verifier's test data, which was taken
// from the real servers and carries three real attestations. A live stamp would make this depend on
// a UDP port a build runner may not open, and what is being checked here is that the two shells
// agree rather than that the network is up. Pass a receipt and its subject to check those instead.
const binary = join(root, "target", "release", process.platform === "win32" ? "timewitness.exe" : "timewitness");
const fixture = join(root, "crates", "verify", "tests", "data", "a-real-stamp");
const receiptFile = process.argv[2] ?? join(fixture, "receipt.cbor");
const receipt = readFileSync(receiptFile);

// The subjects to run the receipt against. The first is the thing the receipt actually stamps, so
// it is the case where every step holds. The other three are the edges the one-fixture version of
// this script could not see: nothing at all, a file of no bytes, and a file of one zero byte. The
// last two are the pair that has to stay apart, because a shell that cannot tell them apart hashes
// an empty file as `6e340b9c` where the other hashes it as `e3b0c442`.
const scratch = join(root, "target", "verifier-page-check");
mkdirSync(scratch, { recursive: true });
const emptyFile = join(scratch, "empty");
const zeroByteFile = join(scratch, "one-zero-byte");
writeFileSync(emptyFile, Buffer.alloc(0));
writeFileSync(zeroByteFile, Buffer.from([0x00]));

const supplied = process.argv[3];
const subjects = supplied
  ? [{ what: "the subject given on the command line", file: supplied }]
  : [
      { what: "the subject this receipt stamps", file: join(fixture, "subject.bin") },
      { what: "no subject at all", file: null },
      { what: "a file of no bytes", file: emptyFile },
      { what: "a file of one zero byte", file: zeroByteFile },
    ];

const problems = [];

function agree(what, a, b) {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    problems.push(`${what}: the page says ${JSON.stringify(a)} and the command line says ${JSON.stringify(b)}`);
  }
}

function fromPageFor(subjectFile) {
  const receiptAt = put(receipt);
  const bytes = subjectFile === null ? null : readFileSync(subjectFile);
  const subjectAt = bytes === null ? 0 : put(bytes);
  const result = take(instance.tw_verify(receiptAt, subjectAt, bytes === null ? 0 : 1));
  instance.tw_free(receiptAt);
  if (subjectAt !== 0) instance.tw_free(subjectAt);
  return result;
}

function fromCommandLineFor(subjectFile) {
  const argv = ["verify", receiptFile, "--json"];
  if (subjectFile !== null) argv.push("--subject", subjectFile);
  // A refused receipt exits 1 and prints its JSON on the error stream, and two of the four subjects
  // below are meant to be refused, so the exit code is read rather than thrown on.
  const options = { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] };
  try {
    return JSON.parse(execFileSync(binary, argv, options));
  } catch (e) {
    const printed = e.stdout || e.stderr;
    if (printed) return JSON.parse(printed);
    throw e;
  }
}

let ran = 0;
for (const { what, file } of subjects) {
  const fromPage = fromPageFor(file);
  const fromCommandLine = fromCommandLineFor(file);
  if (fromPage === null) {
    problems.push(`${what}: the page returned nothing`);
    continue;
  }
  ran += 1;

  agree(`${what}, the verdict`, fromPage.accepted, fromCommandLine.accepted);
  // The sentence as well as the boolean, because the sentence now carries how many attestations
  // were checked and a page saying "all 3" beside a command line saying "none" is the drift this
  // script exists to catch.
  agree(`${what}, the verdict line`, fromPage.verdict, fromCommandLine.verdict);
  // And the line under it, which says how wide the checked outside evidence brackets the moment and
  // whose the width is. It is the line that stops the one above reading as a third party vouching
  // for the width, so a page printing it differently, or not at all, is a page telling a reader less.
  agree(`${what}, the line under the verdict`, fromPage.bracket, fromCommandLine.bracket);
  // A receipt refused before it was read carries no claim on either side, and the case most likely
  // to disagree is a refused one, so the two are compared as absent rather than thrown on.
  agree(`${what}, the interval`, fromPage.claim?.width_ns, fromCommandLine.claim?.width_ns);
  agree(`${what}, the reading`, fromPage.claim?.reading_ns, fromCommandLine.claim?.reading_ns);
  agree(`${what}, the receipt digest`, fromPage.receipt_sha256, fromCommandLine.receipt_sha256);
  // Every step in full, sentence included. The sentence is where the digest of what the reader
  // supplied is printed, so comparing only the state is what let the two shells disagree about the
  // subject and still pass this script.
  agree(`${what}, what was checked`, fromPage.steps, fromCommandLine.steps);
  agree(
    `${what}, the evidence`,
    (fromPage.evidence || []).map((e) => [e.role, e.checked]),
    (fromCommandLine.evidence || []).map((e) => [e.role, e.checked]),
  );
}

// A receipt backdated three years on genuine evidence, which both shells accept and both have to
// say is bracketed to years rather than to seconds. Only when this script chose its own receipt,
// since a receipt handed in on the command line is the one being asked about.
if (!process.argv[2]) {
  // Kept as hex, since the tree holds one binary file and holds it on purpose.
  const hex = readFileSync(join(root, "crates", "verify", "tests", "data", "a-backdated-receipt", "receipt.hex"), "utf8");
  const backdated = Buffer.from(hex.replace(/[^0-9a-fA-F]/g, ""), "hex");
  const backdatedFile = join(scratch, "backdated.cbor");
  writeFileSync(backdatedFile, backdated);
  const receiptAt = put(backdated);
  const fromPage = take(instance.tw_verify(receiptAt, 0, 0));
  instance.tw_free(receiptAt);
  let fromCommandLine;
  try {
    fromCommandLine = JSON.parse(execFileSync(binary, ["verify", backdatedFile, "--json"], { encoding: "utf8" }));
  } catch (e) {
    fromCommandLine = JSON.parse(e.stdout || e.stderr || "null");
  }
  agree("the backdated receipt, the verdict", fromPage?.accepted, fromCommandLine?.accepted);
  agree("the backdated receipt, the verdict line", fromPage?.verdict, fromCommandLine?.verdict);
  agree("the backdated receipt, the line under the verdict", fromPage?.bracket, fromCommandLine?.bracket);
  // "about 2.95 years" until 2026-09-19. The width was the 2023 beacon against a
  // 2026 token whose authority states no accuracy, so one of its edges was an assumption of ours
  // rather than anything a third party signed. The token bounds nothing from above and the page
  // says so, which is the plainer warning and the true one.
  for (const [what, words] of [["nothing above it", "nothing outside bounds the moment from above."], ["no corridor", "It carries no Roughtime corridor."], ["whose the width is", "is the signer's own claim."]]) {
    if (!String(fromPage?.bracket).includes(words)) {
      problems.push(`the backdated receipt: the page's line under the verdict does not say ${what}: ${JSON.stringify(fromPage?.bracket)}`);
    }
  }
  ran += 1;
}

// And the receipt with one byte changed has to be refused by the page, not only by the binary.
const altered = Buffer.from(receipt);
altered[Math.floor(altered.length / 2)] ^= 0x01;
const tampered = take(instance.tw_verify(put(altered), 0, 0));
if (tampered.accepted) problems.push("the page accepted a receipt with one byte changed");

// The list of limitations is in the page's own output rather than under it.
const limits = take(instance.tw_cannot_prove());
if (!Array.isArray(limits) || limits.length < 20) {
  problems.push(`the page carries ${limits ? limits.length : 0} limitations and the document has more`);
}

if (problems.length > 0) {
  for (const problem of problems) console.error("  " + problem);
  console.error("the page and the command line disagree");
  process.exit(1);
}

console.log(
  `the page and the command line agree on ${ran} subject${ran === 1 ? "" : "s"} of this receipt, ` +
  `and the page prints ${limits.length} limitations`,
);
