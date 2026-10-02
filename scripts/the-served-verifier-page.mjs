#!/usr/bin/env node
// A stranger checks a receipt on a page we host, and the page a host serves is held to what it says.
//
//     node scripts/the-served-verifier-page.mjs <address>        the page as a host serves it
//     node scripts/the-served-verifier-page.mjs --self-test      served from this machine, and seeded
//
// Every other check of the verifier page reads the file this tree builds. A host can serve something
// else: an older build, a build of another commit, a page with a line added in front of it. So this
// asks the host for the page and reads what comes back, the way somebody would who had only the
// address. Five things have to hold, and every one is read, so a run names all that is wrong rather
// than the first thing:
//
//   1. The page says which commit it was built from, and it is a commit. A page built from a tree
//      with changes nobody committed is a page nobody else can build, so there is nothing to hold it
//      to.
//   2. The page as served is, byte for byte, the page that commit builds. This builds it, in a clone
//      of this repository at that commit, the way `page-for-a-host.sh` built it for the host, with
//      the compiler the page's own module says built it, and builds that commit's command line beside
//      it. Nothing is normalised. The build writes the same bytes every time for one commit and one
//      compiler, so a changed word fails whatever it says. Where the two differ, the lines are named,
//      or the module is, and so is the one thing the build takes from the machine it runs on, which
//      is where cargo keeps the libraries' sources, when that is part of what differs.
//   3. The page as served passes `verifier-page-offline.mjs`, which reads it for any way it could ask
//      a network for something.
//   4. The checking code inside the served page, run on its own, gives the answer of the command line
//      built at the same commit on every receipt below, in every field the two both carry.
//   5. In a real browser at that address, handed the same bytes this read, choosing the receipt and
//      the file it stamps and clicking the button shows the command line's verdict and width, and
//      the page asks for nothing at all once it is open: no request, no socket, no worker, no window,
//      while it checks and while it is left. A request carrying the file is named as that.
//
// So it runs from any checkout of this repository that carries it, and not only from the commit the
// page names. The receipts are this checkout's: the one committed in this repository, the same
// receipt against a file it does not stamp, which has to be refused, and one stamped here and now
// with the command line, which needs the network the way stamping always does. `--no-fresh` leaves
// the last one out, and `--fresh <receipt> <subject>` hands one in rather than taking one.
//
// A walled host answers its own sign-in page rather than this one. Where the host is walled, put the
// wall's read-only check in TIMEWITNESS_APP_WALL_COOKIE, as `name=value`. It is sent with this
// script's own request for the page and set in the browser for that host alone. The app
// repository's `npm run wall-check` prints one.
//
// `--self-test` serves the page this tree built on the loopback address, holds it to that same file
// and to the command line built here, runs the whole check on it, and then runs it on eight seeds,
// each of which has to be refused by the part written for it: a page that shows the wrong verdict,
// one that shows the wrong width, one that sends the file it was given when the button is clicked,
// one that sends it as the page is left, one that runs a module other than the one it carries, one
// built from another commit, one with a line of words its build never had, and one carrying a module
// its build never made. The two that send are written so the page check's spellings cannot see them and the policy
// is taken out so the browser lets them go, and the server has to receive the file, so each is shown
// connected before its refusal is believed. A guard nobody has seen fail is not evidence.
//
// Exit 0 when everything holds, 1 when something does not, 2 when the check could not run: no browser,
// a commit that would not build, a compiler this machine does not have, a host that would not answer,
// or no fresh receipt. Never a pass.

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, "target", "served-verifier-page");
const executable = process.platform === "win32" ? "timewitness.exe" : "timewitness";
const binary = join(root, "target", "release", executable);
const fixture = join(root, "crates", "verify", "tests", "data", "a-real-stamp");
const versionOne = join(root, "crates", "verify", "tests", "data", "a-version-1-stamp");
const BUILT_FROM = /<meta name="tw-built-from" content="([^"]*)">/;
const MODULE = /const WASM_BASE64 = "([A-Za-z0-9+/=]+)";/g;
const MODULE_LINE = /^const WASM_BASE64 = "([A-Za-z0-9+/=]+)";$/;
const POLICY = /<meta http-equiv="Content-Security-Policy" content="[^"]*">\n/;

class CouldNotRun extends Error {}

// ---------------------------------------------------------------------------------------------------
// What this checkout is, and the command line built from it.

function git(...args) {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
}

// The same words the page build writes into the page, worked out the same way.
function builtFromHere() {
  const head = git("rev-parse", "HEAD");
  return git("status", "--porcelain", "--untracked-files=no") === "" ? head : `${head}-modified`;
}

function theCommandLine() {
  try {
    execFileSync("cargo", ["build", "-p", "timewitness-cli", "--release"], { cwd: root, stdio: ["ignore", "ignore", "inherit"] });
  } catch {
    throw new CouldNotRun("the command line would not build here, so there is nothing to hold the page to");
  }
  if (!existsSync(binary)) throw new CouldNotRun(`the command line was not built at ${binary}`);
  return binary;
}

function fromCommandLine(cli, receiptFile, subjectFile) {
  const argv = ["verify", receiptFile, "--json", "--subject", subjectFile];
  // A refused receipt exits 1 and prints its JSON on the error stream, and one case below is meant to
  // be refused, so the exit code is read rather than thrown on.
  let printed;
  try {
    printed = execFileSync(cli, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    printed = e.stdout || e.stderr;
  }
  try {
    return JSON.parse(printed);
  } catch {
    throw new CouldNotRun(`the command line gave no answer to read on ${receiptFile}: ${String(printed).slice(0, 200)}`);
  }
}

// ---------------------------------------------------------------------------------------------------
// The page the named commit builds, and the command line built beside it.

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// The compiler a module names in its own producers section, the way rustc writes it there:
// "1.98.1 (48a229cea 2026-09-01)". Null where it names none.
function theCompilerOf(module) {
  try {
    const [section] = WebAssembly.Module.customSections(new WebAssembly.Module(module), "producers");
    if (!section) return null;
    return Buffer.from(section).toString("latin1").match(/rustc[\s\S]([0-9]+\.[0-9]+\.[0-9]+ \([0-9a-f]+ [0-9-]+\))/)?.[1] ?? null;
  } catch {
    return null;
  }
}

function theOnlyModuleIn(page) {
  const found = [...page.matchAll(MODULE)];
  return found.length === 1 ? Buffer.from(found[0][1], "base64") : null;
}

// Where cargo keeps the libraries' sources on this machine. The build writes that folder into the
// module wherever a library can panic, so it is the one part of the page the machine decides.
function theLibrariesHere() {
  return join(process.env.CARGO_HOME || join(homedir(), ".cargo"), "registry", "src") + sep;
}

// Built in a clone of this repository at the commit, kept under `target/` so the next run builds only
// what moved, and cleaned of everything but its own `target/` before every build, so nothing left from
// another commit is in what comes out. The commit's own build script does the building, the one
// `page-for-a-host.sh` runs, and it builds the command line too.
function theBuildAt(commit, compiler) {
  const has = () => {
    try {
      git("cat-file", "-e", `${commit}^{commit}`);
      return true;
    } catch {
      return false;
    }
  };
  if (!has()) {
    try {
      execFileSync("git", ["-C", root, "fetch", "--quiet", "origin", commit], { stdio: "ignore" });
    } catch {
      // A commit nobody has is answered below.
    }
  }
  if (!has()) return null;

  const at = join(work, "the-build");
  if (!existsSync(join(at, ".git"))) {
    rmSync(at, { recursive: true, force: true });
    execFileSync("git", ["clone", "--quiet", "--shared", "--no-checkout", root, at]);
  }
  execFileSync("git", ["-C", at, "checkout", "--quiet", "--force", "--detach", commit]);
  execFileSync("git", ["-C", at, "clean", "-dfxq", "-e", "target"]);

  const env = { ...process.env };
  // The build script reads the module from `target/` whatever this says, so it is not passed on.
  delete env.CARGO_TARGET_DIR;
  if (compiler) {
    const toolchain = compiler.split(" ")[0];
    const version = (extra) => {
      try {
        return execFileSync("rustc", ["--version"], { cwd: at, env: { ...env, ...extra }, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
      } catch {
        return null;
      }
    };
    // The compiler the commit asks for is used when it is the one the module names. Otherwise that
    // exact release is asked for by name.
    if (version({}) !== `rustc ${compiler}`) {
      if (version({ RUSTUP_TOOLCHAIN: toolchain }) !== `rustc ${compiler}`) {
        throw new CouldNotRun(
          `the page's module was built by rustc ${compiler}, which this machine does not have. ` +
            `rustup toolchain install ${toolchain} --profile minimal --target wasm32-unknown-unknown`,
        );
      }
      env.RUSTUP_TOOLCHAIN = toolchain;
    }
  }
  try {
    execFileSync("bash", ["scripts/build-verifier-page.sh"], { cwd: at, env, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28 });
  } catch (e) {
    const said = `${e.stdout || ""}${e.stderr || ""}`.trim().split("\n").slice(-4).join(" / ");
    throw new CouldNotRun(`the page would not build at ${commit}${compiler ? ` with rustc ${compiler}` : ""}: ${said}`);
  }
  const page = join(at, "verifier-page", "verifier.html");
  const cli = join(at, "target", "release", executable);
  if (!existsSync(page) || !existsSync(cli)) throw new CouldNotRun(`the build at ${commit} left no page or no command line`);
  return { page: readFileSync(page), cli, compiler };
}

// Where the page as served and the page as built part company, said so somebody can see it without
// either file open: the lines, or the module when that is all that differs.
function whereTheyDiffer(served, built, commit) {
  if (served.equals(built)) return null;
  const opening =
    `the served page is not the page ${commit} builds: ${served.length} bytes, sha256 ${sha256(served)}, ` +
    `where the build is ${built.length} bytes, sha256 ${sha256(built)}`;
  // Read as latin1 so every byte is one character and nothing is lost to decoding on the way.
  const ours = served.toString("latin1").split("\n");
  const theirs = built.toString("latin1").split("\n");
  let first = 0;
  while (first < ours.length && first < theirs.length && ours[first] === theirs[first]) first += 1;
  let endOurs = ours.length;
  let endTheirs = theirs.length;
  while (endOurs > first && endTheirs > first && ours[endOurs - 1] === theirs[endTheirs - 1]) {
    endOurs -= 1;
    endTheirs -= 1;
  }
  const onlyOurs = ours.slice(first, endOurs);
  const onlyTheirs = theirs.slice(first, endTheirs);
  const show = (line) => {
    const text = Buffer.from(line, "latin1").toString("utf8").trim();
    return JSON.stringify(text.length > 160 ? `${text.slice(0, 160)}...` : text);
  };
  const lines = (n) => (n === 1 ? "1 line" : `${n} lines`);

  if (onlyOurs.length === 1 && onlyTheirs.length === 1 && MODULE_LINE.test(onlyOurs[0]) && MODULE_LINE.test(onlyTheirs[0])) {
    const a = Buffer.from(onlyOurs[0].match(MODULE_LINE)[1], "base64");
    const b = Buffer.from(onlyTheirs[0].match(MODULE_LINE)[1], "base64");
    let same = 0;
    while (same < a.length && same < b.length && a[same] === b[same]) same += 1;
    let said =
      `${opening}. Only the module differs: the module in the served page is ${a.length} bytes, sha256 ${sha256(a)}, ` +
      `and the build's is ${b.length} bytes, sha256 ${sha256(b)}, the two the same for their first ${same} bytes`;
    const [compilerA, compilerB] = [theCompilerOf(a), theCompilerOf(b)];
    if (compilerA !== compilerB) said += `. The served module names rustc ${compilerA ?? "nowhere"} and the build's rustc ${compilerB ?? "nowhere"}`;
    const here = theLibrariesHere();
    const text = a.toString("latin1");
    if (/registry[\\/]src[\\/]/.test(text) && !text.includes(here)) {
      said +=
        `. The served module names its libraries' sources somewhere other than ${here}, where this machine keeps them, ` +
        "and that folder is written into the module, so a build here cannot give its bytes. Run this where they are kept in the same place";
    }
    return said;
  }
  if (onlyTheirs.length === 0) return `${opening}. It has ${lines(onlyOurs.length)} the build does not, from line ${first + 1}: ${show(onlyOurs[0])}`;
  if (onlyOurs.length === 0) return `${opening}. The build has ${lines(onlyTheirs.length)} it does not, from line ${first + 1}: ${show(onlyTheirs[0])}`;
  return (
    `${opening}. From line ${first + 1}, ${lines(onlyOurs.length)} of it stand where the build has ${lines(onlyTheirs.length)}: ` +
    `it says ${show(onlyOurs[0])} where the build says ${show(onlyTheirs[0])}`
  );
}

// ---------------------------------------------------------------------------------------------------
// The receipts put to the page.

function theCases(options) {
  mkdirSync(work, { recursive: true });
  const oneZeroByte = join(work, "one-zero-byte");
  writeFileSync(oneZeroByte, Buffer.from([0x00]));
  const cases = [
    { what: "the committed receipt", receipt: join(fixture, "receipt.cbor"), subject: join(fixture, "subject.bin") },
    { what: "the committed receipt against a file it does not stamp", receipt: join(fixture, "receipt.cbor"), subject: oneZeroByte },
  ];
  if (options.selfTest) {
    const v1 = join(work, "a-version-1-stamp.cbor");
    writeFileSync(v1, Buffer.from(readFileSync(join(versionOne, "receipt.hex"), "utf8").replace(/\s+/g, ""), "hex"));
    cases.push({ what: "the committed version 1 receipt", receipt: v1, subject: join(versionOne, "subject.bin") });
  } else if (options.fresh) {
    cases.push({ what: "the receipt handed in", receipt: options.fresh[0], subject: options.fresh[1] });
  } else if (options.takeFresh) {
    cases.push(aFreshReceipt(options.cli));
  }
  return cases;
}

// Stamped now, over bytes nobody has seen before, with a key made for it. It uses the network the
// way stamping does, and the page and the command line are both then handed a receipt that did not
// exist when either was built.
function aFreshReceipt(cli) {
  const at = join(work, "fresh");
  rmSync(at, { recursive: true, force: true });
  mkdirSync(at, { recursive: true });
  const subject = join(at, "subject.bin");
  writeFileSync(subject, randomBytes(64));
  const receipt = join(at, "receipt.cbor");
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      execFileSync(cli, ["stamp", "--subject", subject, "--key", join(at, "key"), "--out", receipt], {
        stdio: ["ignore", "ignore", "ignore"],
        timeout: 120000,
      });
      if (existsSync(receipt)) return { what: `a receipt stamped at ${new Date().toISOString()}`, receipt, subject };
    } catch {
      // Stamping refuses when the sources disagree or too few answer, and a second try is ordinary.
    }
  }
  throw new CouldNotRun("no fresh receipt could be stamped here in three tries. Stamping needs the sources to answer");
}

// ---------------------------------------------------------------------------------------------------
// The checking code inside the served page, run on its own.

// Exactly one module, because a page carrying two would have this check read one and the browser run
// the other.
async function theModuleIn(page, problems) {
  const found = [...page.matchAll(MODULE)];
  if (found.length !== 1) {
    problems.push(`the served page carries ${found.length} modules where the build embeds exactly one`);
    return null;
  }
  const bytes = Buffer.from(found[0][1], "base64");
  const instance = (await WebAssembly.instantiate(bytes, {})).instance.exports;
  const put = (bytes) => {
    const address = instance.tw_alloc(bytes.length);
    new Uint8Array(instance.memory.buffer, address, bytes.length).set(bytes);
    return address;
  };
  const take = (address) => {
    if (address === 0) return null;
    const length = new DataView(instance.memory.buffer, address, 4).getUint32(0, true);
    const text = new TextDecoder().decode(new Uint8Array(instance.memory.buffer, address + 4, length));
    instance.tw_free(address);
    return JSON.parse(text);
  };
  const run = (receiptFile, subjectFile) => {
    const receiptAt = put(readFileSync(receiptFile));
    const subjectAt = put(readFileSync(subjectFile));
    const result = take(instance.tw_verify(receiptAt, subjectAt, 1));
    instance.tw_free(receiptAt);
    instance.tw_free(subjectAt);
    return result;
  };
  run.sha256 = createHash("sha256").update(bytes).digest("hex");
  return run;
}

function agree(problems, what, page, commandLine) {
  if (JSON.stringify(page) !== JSON.stringify(commandLine)) {
    problems.push(`${what}: the served page says ${JSON.stringify(page)} and the command line says ${JSON.stringify(commandLine)}`);
  }
}

// The fields only one shell carries, because each adds words of its own for its reader: the page its
// widths in words, its floor and each check's own lines, the command line its limitation list and
// two labels on the claim. Read off both on 2026-09-24 over the committed receipts and a fresh one.
// Any other field on one side and not the other is a disagreement, because a field one side drops is
// the quietest way for the two to differ.
const PAGE_ONLY = [".claim.breakdown", ".claim.width_in_words", ".floor", ".evidence[].checks", ".evidence[].detail"];
const COMMAND_LINE_ONLY = [".claim.kind", ".claim.reading_is_display_only", ".cannot_prove"];

function fieldsOf(value, path = "", into = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) fieldsOf(item, `${path}[]`, into);
  } else if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      into.add(`${path}.${key}`);
      fieldsOf(value[key], `${path}.${key}`, into);
    }
  }
  return into;
}

const under = (field, allowed) => allowed.some((a) => field === a || field.startsWith(`${a}.`) || field.startsWith(`${a}[]`));

// Every field the two both carry, all the way down. The two are one core behind two shells, and each
// shell adds words of its own for its reader, the page its widths in words and the command line its
// limitation list, so a field only one side carries is not a disagreement. A field both carry that
// differs by a character is.
function sharedFieldsAgree(problems, what, page, commandLine, path = "") {
  if (Array.isArray(page) && Array.isArray(commandLine)) {
    if (page.length !== commandLine.length) {
      problems.push(`${what}, ${path || "the answer"}: the served page lists ${page.length} and the command line ${commandLine.length}`);
      return;
    }
    page.forEach((item, i) => sharedFieldsAgree(problems, what, item, commandLine[i], `${path}[${i}]`));
    return;
  }
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  if (isObject(page) && isObject(commandLine)) {
    for (const key of Object.keys(page)) {
      if (key in commandLine) sharedFieldsAgree(problems, what, page[key], commandLine[key], path ? `${path}.${key}` : key);
    }
    return;
  }
  agree(problems, `${what}, ${path || "the answer"}`, page, commandLine);
}

function theModuleAgrees(problems, what, fromPage, cli) {
  if (fromPage === null) {
    problems.push(`${what}: the checking code in the served page returned nothing`);
    return;
  }
  const onThePage = fieldsOf(fromPage);
  const onTheCommandLine = fieldsOf(cli);
  for (const field of onThePage) {
    if (!onTheCommandLine.has(field) && !under(field, PAGE_ONLY)) problems.push(`${what}, ${field}: the served page carries it and the command line does not`);
  }
  for (const field of onTheCommandLine) {
    if (!onThePage.has(field) && !under(field, COMMAND_LINE_ONLY)) problems.push(`${what}, ${field}: the command line carries it and the served page does not`);
  }
  sharedFieldsAgree(problems, what, fromPage, cli);
}

// ---------------------------------------------------------------------------------------------------
// A real browser at the address.

function chrome() {
  if (process.env.CHROME) return process.env.CHROME;
  const candidates = [
    "google-chrome",
    "google-chrome-stable",
    "chromium-browser",
    "chromium",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ];
  for (const candidate of candidates) {
    if (candidate.includes("\\")) {
      if (existsSync(candidate)) return candidate;
      continue;
    }
    try {
      execFileSync(candidate, ["--version"], { stdio: "ignore", timeout: 10000 });
      return candidate;
    } catch {
      // Not this one.
    }
  }
  return null;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function until(what, test, seconds = 30) {
  const by = Date.now() + seconds * 1000;
  while (Date.now() < by) {
    if (await test()) return;
    await sleep(100);
  }
  throw new CouldNotRun(`the browser did not get as far as ${what} within ${seconds} seconds`);
}

// Headless, in a profile of its own under `target/` that is thrown away afterwards, driven over its own
// debugging protocol. No window opens. Whatever goes wrong on the way up, the browser is stopped and
// its profile taken away before the failure is reported.
async function aBrowser(address) {
  if (typeof WebSocket === "undefined") throw new CouldNotRun(`this Node, ${process.version}, has no WebSocket to drive a browser with. Use 22 or later`);
  const browser = chrome();
  if (!browser) throw new CouldNotRun("no Chrome was found to drive. Name one with CHROME");
  mkdirSync(work, { recursive: true });
  const profile = mkdtempSync(join(work, "profile-"));
  const child = spawn(
    browser,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-component-update",
      "--disable-sync",
      `--user-data-dir=${profile}`,
      "--remote-debugging-port=0",
      // Only the address's own host resolves, so nothing the page names by another name is looked up,
      // and no peer connection goes out except through a proxy, which there is none of.
      `--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE ${new URL(address).hostname}`,
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  let socket = null;

  const stop = async () => {
    socket?.close();
    const gone = () => child.exitCode !== null || child.signalCode !== null;
    for (let i = 0; i < 50 && !gone(); i += 1) await sleep(100);
    if (!gone()) {
      try {
        process.kill(child.pid);
      } catch {
        // Gone between the two lines.
      }
    }
    // The profile is a scratch folder under target/. A browser still letting go of a file in it is
    // no reason to fail a check, and the next run's clean takes what is left.
    try {
      rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    } catch {
      // Left for the next run.
    }
  };

  let next = 0;
  const waiting = new Map();
  const listeners = new Set();
  const requestListeners = new Set();
  const send = (method, params = {}, sessionId) => {
    next += 1;
    const id = next;
    socket.send(JSON.stringify({ id, method, params, sessionId }));
    return new Promise((resolve, reject) => {
      waiting.set(id, { resolve, reject });
      setTimeout(() => {
        if (waiting.delete(id)) reject(new CouldNotRun(`the browser did not answer ${method}`));
      }, 30000);
    });
  };

  try {
    const portFile = join(profile, "DevToolsActivePort");
    await until("opening its debugging port", () => existsSync(portFile) && readFileSync(portFile, "utf8").includes("\n"));
    const [port, path] = readFileSync(portFile, "utf8").split("\n");
    socket = new WebSocket(`ws://127.0.0.1:${port}${path}`);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve, { once: true });
      socket.addEventListener("error", () => reject(new CouldNotRun("the browser's debugging port would not take a connection")), { once: true });
    });
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id !== undefined && waiting.has(message.id)) {
        const { resolve, reject } = waiting.get(message.id);
        waiting.delete(message.id);
        if (message.error) reject(new Error(`${message.error.message}`));
        else resolve(message.result);
      } else if (message.method) {
        for (const listener of listeners) listener(message);
      }
    });
    // Every new target the browser makes is announced, so a window the page opens is seen.
    await send("Target.setDiscoverTargets", { discover: true });
    // Every request the browser makes, from any page, frame or worker and at any moment, is held at
    // the browser itself until it is read and let go. A tab's own list of requests misses the ones a
    // page sends as it is left, which is exactly when a page that wanted to hide a send would send,
    // so that list is not the one this reads.
    listeners.add((message) => {
      if (message.method !== "Fetch.requestPaused") return;
      for (const listener of requestListeners) listener(message.params);
      send("Fetch.continueRequest", { requestId: message.params.requestId }, message.sessionId).catch(() => {});
    });
    await send("Fetch.enable", { patterns: [{ urlPattern: "*" }] });
    // A browser that says it is headless is one a page could behave differently for.
    const { userAgent } = await send("Browser.getVersion");
    const ordinary = userAgent.replace("HeadlessChrome", "Chrome");
    return {
      send,
      listeners,
      requestListeners,
      ordinary,
      close: async () => {
        await send("Browser.close").catch(() => {});
        await stop();
      },
    };
  } catch (e) {
    await stop();
    throw e;
  }
}

// Put into every document the tab opens, before the page's own scripts run. It keeps a copy of every
// module the page hands WebAssembly, so the one the browser ran can be held to the one step 3 checked,
// and it notes every peer connection or transport the page makes, which no request list shows.
const WATCH = `(() => {
  const modules = [];
  const reached = [];
  Object.defineProperty(window, "__twWatched", { value: { modules, reached } });
  const copy = (source) => {
    if (source instanceof ArrayBuffer) return new Uint8Array(source.slice(0));
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer.slice(source.byteOffset, source.byteOffset + source.byteLength));
    return null;
  };
  const note = (source) => modules.push(source instanceof WebAssembly.Module ? "an already compiled module" : copy(source) || "something that is not bytes");
  const wrap = (name) => {
    const original = WebAssembly[name];
    WebAssembly[name] = function (source, ...rest) { note(source); return original.call(this, source, ...rest); };
  };
  wrap("instantiate");
  wrap("compile");
  for (const name of ["instantiateStreaming", "compileStreaming"]) {
    const original = WebAssembly[name];
    if (original) WebAssembly[name] = function (...args) { modules.push("a module streamed from an address"); return original.apply(this, args); };
  }
  const Module = WebAssembly.Module;
  WebAssembly.Module = new Proxy(Module, { construct(target, args) { note(args[0]); return new target(...args); } });
  for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport"]) {
    const original = window[name];
    if (original) window[name] = new Proxy(original, { construct(target, args) { reached.push(name); return new target(...args); } });
  }
})();`;

// What the watcher saw, with each module as its sha256.
const WATCHED = `(async () => {
  const watched = window.__twWatched || { modules: [], reached: [] };
  const modules = [];
  for (const m of watched.modules) {
    if (typeof m === "string") { modules.push(m); continue; }
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", m));
    modules.push(Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join(""));
  }
  return JSON.stringify({ modules, reached: watched.reached });
})()`;

// One receipt, in a tab of its own. What the page shows, the bytes the browser was handed, the module
// it ran, and everything the tab reached for, with the moment it reached for it.
async function inTheBrowser(browser, address, cookie, receiptFile, subjectFile) {
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId, flatten: true });
  const tab = (method, params) => browser.send(method, params, sessionId);
  const requests = [];
  const others = [];
  let phase = "while the page was loading";
  let loaded = false;
  let left = false;
  let documentId = null;
  const listener = (message) => {
    const { method, params } = message;
    // A window the page opened, which is a way of sending the reader, and anything they chose, away.
    if (method === "Target.targetCreated" && params.targetInfo.openerId === targetId) {
      others.push({ kind: `a ${params.targetInfo.type}`, url: params.targetInfo.url, phase });
    }
    if (message.sessionId !== sessionId) return;
    if (method === "Page.loadEventFired") loaded = true;
    if (method === "Page.frameNavigated" && !params.frame.parentId && params.frame.url === "about:blank" && phase === "while the page was being left") left = true;
    // A page that asks to stay open, or asks anything at all, is holding the reader rather than
    // checking a receipt. It is answered so the tab can go, and it is counted.
    if (method === "Page.javascriptDialogOpening") {
      others.push({ kind: `a ${params.type} dialog`, url: params.url, phase });
      tab("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
    }
    // The tab's own list is read for one thing only, which request brought the document the tab ended
    // up showing, so the bytes it was handed can be read back. The last one is that document.
    if (method === "Network.requestWillBeSent" && params.type === "Document" && phase === "while the page was loading") documentId = params.requestId;
    if (method === "Network.webSocketCreated") requests.push({ phase, type: "WebSocket", method: "WEBSOCKET", url: params.url });
    // A worker, a shared worker, a service worker or a frame in a process of its own: each runs code
    // the tab's own request list cannot see, and the page has none of them.
    if (method === "Target.attachedToTarget") others.push({ kind: `a ${params.targetInfo.type}`, url: params.targetInfo.url, phase });
  };
  const recorder = (paused) => {
    const { request, resourceType } = paused;
    requests.push({ phase, type: resourceType, method: request.method, url: request.url, entries: request.postDataEntries, postData: request.postData });
  };
  browser.listeners.add(listener);
  browser.requestListeners.add(recorder);
  try {
    await tab("Network.enable");
    await tab("Page.enable");
    await tab("DOM.enable");
    await tab("Runtime.enable");
    await tab("Page.addScriptToEvaluateOnNewDocument", { source: WATCH });
    await tab("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
    await tab("Network.setUserAgentOverride", { userAgent: browser.ordinary });
    if (cookie) {
      const split = cookie.indexOf("=");
      const { success } = await tab("Network.setCookie", {
        name: cookie.slice(0, split),
        value: cookie.slice(split + 1),
        url: new URL("/", address).href,
        path: "/",
        secure: new URL(address).protocol === "https:",
        httpOnly: true,
      });
      if (!success) throw new CouldNotRun("the browser would not take the wall's check for that host");
    }
    const evaluate = async (expression) =>
      (await tab("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result.value;

    await tab("Page.navigate", { url: address });
    await until("the page loading", () => loaded);
    await until("the page's checking code coming up", () => evaluate('!!document.getElementById("go") && !document.getElementById("go").disabled'));
    phase = "after the page had loaded";
    let loadedBytes = null;
    if (documentId) {
      const body = await tab("Network.getResponseBody", { requestId: documentId });
      loadedBytes = Buffer.from(body.body, body.base64Encoded ? "base64" : "utf8");
    }

    const { root: documentNode } = await tab("DOM.getDocument", { depth: 1 });
    for (const [selector, file] of [["#receipt", receiptFile], ["#subject", subjectFile]]) {
      const { nodeId } = await tab("DOM.querySelector", { nodeId: documentNode.nodeId, selector });
      if (!nodeId) throw new CouldNotRun(`the page has no ${selector} to choose a file with`);
      await tab("DOM.setFileInputFiles", { nodeId, files: [file] });
    }
    phase = "after the files were chosen";

    // Clicked as a person clicks, with the mouse, so the page has the user activation a real click
    // gives it and cannot tell this from one.
    const at = JSON.parse(
      await evaluate(
        '(() => { const b = document.getElementById("go"); b.scrollIntoView({ block: "center" }); const r = b.getBoundingClientRect(); return JSON.stringify({ x: r.x + r.width / 2, y: r.y + r.height / 2 }); })()',
      ),
    );
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
      await tab("Input.dispatchMouseEvent", { type, x: at.x, y: at.y, button: type === "mouseMoved" ? "none" : "left", clickCount: 1 });
    }
    await until("a verdict on the page", () =>
      evaluate(
        '!document.getElementById("result").hidden && document.getElementById("go").textContent !== "Checking" && document.getElementById("verdict").textContent !== ""',
      ),
    );
    const read = async () =>
      JSON.parse(
        await evaluate(`JSON.stringify({
          verdict: document.getElementById("verdict").textContent,
          state: document.getElementById("verdict").className.replace("verdict", "").trim(),
          bracket: document.getElementById("verdict-bracket").textContent,
          claim: (document.querySelector("#claim p") || { textContent: "" }).textContent,
        })`),
      );
    const shown = await read();
    // A page that waits before it sends is given the time to, and what it shows is read again, so a
    // verdict that changes after the first look is not taken at the first look.
    await sleep(3000);
    const shownLater = await read();
    const watched = JSON.parse(await evaluate(WATCHED));

    // Then the page is left, which is when a page that sends on the way out would, and the tab is
    // only let go once the browser has really moved on and closed it.
    phase = "while the page was being left";
    await tab("Page.navigate", { url: "about:blank" });
    await until("leaving the page", () => left, 15);
    await sleep(1500);
    await browser.send("Target.closeTarget", { targetId }).catch(() => {});
    await sleep(1000);
    return { shown, shownLater, watched, requests, others, loadedBytes };
  } finally {
    browser.listeners.delete(listener);
    browser.requestListeners.delete(recorder);
    await browser.send("Target.closeTarget", { targetId }).catch(() => {});
  }
}

// What the page says it shows for a verdict, worked out from the command line's answer. The rule is
// the page's own: a receipt graded as a certificate that does not hold leads with that, an accepted
// receipt shows its verdict line, and a refused one says Refused.
function whatThePageShouldShow(cli) {
  const grade = cli.certificate;
  if (cli.accepted && grade && !grade.holds) {
    return { state: "refused", verdict: grade.headline, bracket: `${cli.verdict} ${cli.bracket || ""}` };
  }
  if (cli.accepted) return { state: "held", verdict: grade ? grade.headline : cli.verdict, bracket: cli.bracket || "" };
  return { state: "refused", verdict: "Refused.", bracket: "" };
}

// The width the page wrote in words, held to the command line's nanoseconds in the form the verifier
// writes a width: three decimals in seconds, milliseconds or microseconds, or whole nanoseconds below
// that. A figure that rounds the right way either side of a tie passes, and nothing coarser does.
function widthAgrees(claimLine, widthNs) {
  const size = Math.abs(widthNs);
  const [unit, per] = size >= 1e9 ? ["s", 1e9] : size >= 1e6 ? ["ms", 1e6] : size >= 1e3 ? ["us", 1e3] : ["ns", 1];
  const said = claimLine.match(unit === "ns" ? /interval (-?[0-9]+) ns wide/ : new RegExp(`interval (-?[0-9]+\\.[0-9]{3}) ${unit} wide`));
  if (!said) return false;
  if (unit === "ns") return Number(said[1]) === widthNs;
  return Math.abs(Number(said[1]) * 1000 - (widthNs / per) * 1000) <= 0.5 + 1e-9;
}

function whatTheBrowserShowed(problems, what, seen, cli, fetched, run) {
  if (seen.loadedBytes === null) {
    problems.push(`${what}: the browser's copy of the page could not be read back, so what it ran is not known to be what this read`);
  } else if (!seen.loadedBytes.equals(fetched)) {
    problems.push(`${what}: the browser was handed ${seen.loadedBytes.length} bytes that are not the ${fetched.length} this check read and held to the rules above`);
  }
  // The module the browser ran is the one step 3 checked, and it ran exactly one.
  if (run && JSON.stringify(seen.watched.modules) !== JSON.stringify([run.sha256])) {
    problems.push(`${what}: the browser ran ${JSON.stringify(seen.watched.modules)} where the page's own module is ${run.sha256}`);
  }
  if (JSON.stringify(seen.shownLater) !== JSON.stringify(seen.shown)) {
    problems.push(`${what}: the page showed ${JSON.stringify(seen.shown)} and three seconds later ${JSON.stringify(seen.shownLater)}`);
  }
  const expected = whatThePageShouldShow(cli);
  agree(problems, `${what}, the verdict shown in the browser`, seen.shown.verdict, expected.verdict);
  agree(problems, `${what}, the state shown in the browser`, seen.shown.state, expected.state);
  agree(problems, `${what}, the line under the verdict in the browser`, seen.shown.bracket, expected.bracket);
  if (cli.claim && !widthAgrees(seen.shown.claim, cli.claim.width_ns)) {
    problems.push(`${what}: the browser shows "${seen.shown.claim}" and the command line's width is ${cli.claim.width_ns} ns`);
  }
}

// A file of a byte or two is in every body by chance, so it is looked for as bytes only where it is
// long enough to mean something. Its digest is always looked for. A short file sent is still caught,
// as a request made after the page loaded, and named as that rather than as the file.
function carries(request, subject) {
  const texts = [request.url, request.postData ?? ""];
  const marks = [createHash("sha256").update(subject).digest("hex")];
  const bodies = (request.entries || []).map((entry) => Buffer.from(entry.bytes || "", "base64"));
  if (request.postData) bodies.push(Buffer.from(request.postData, "latin1"));
  if (subject.length >= 16) marks.push(subject.toString("hex"), subject.toString("base64"));
  return (
    texts.some((text) => marks.some((mark) => text.includes(mark))) ||
    (subject.length >= 16 && bodies.some((body) => body.includes(subject)))
  );
}

// The page asks for itself and nothing else. Once it is open it asks for nothing at all, and a request
// carrying the file it was given, or its digest, is named as that whenever it was made. A `data:`
// address carries its own bytes and reaches nobody, which is how the page carries its lockup, so the
// browser reading one is not a request of anybody. Leaving for `about:blank` is this check's own act.
function whatTheBrowserSent(problems, what, seen, address, subject) {
  const asked = new Set();
  for (const request of seen.requests) {
    const shown = request.url.length > 120 ? `${request.url.slice(0, 120)}...` : request.url;
    if (carries(request, subject)) {
      problems.push(`${what}: the page sent the file it was given, ${request.method} ${shown}, ${request.phase}`);
      continue;
    }
    if (request.url.startsWith("data:") && request.method === "GET") continue;
    // The browser's own parts, which reach no network and are none of the page's doing.
    if (/^(chrome|chrome-extension|devtools):/.test(request.url)) continue;
    // The page itself, once for each address on the way to it, so a host's slash is allowed and a
    // page that loads itself a second time is not: the second load is one this check never read.
    if (request.phase === "while the page was loading" && request.type === "Document" && sameAddress(request.url, address) && !asked.has(request.url)) {
      asked.add(request.url);
      continue;
    }
    if (request.phase === "while the page was being left" && request.type === "Document" && request.url === "about:blank") continue;
    problems.push(`${what}: the page asked for ${request.method} ${shown} ${request.phase}, and it asks for nothing but itself`);
  }
  for (const name of seen.watched.reached) {
    problems.push(`${what}: the page made a ${name}, which reaches another machine without a request any list shows`);
  }
  for (const other of seen.others) {
    problems.push(`${what}: the page started ${other.kind} at ${other.url || "no address"} ${other.phase}, and it starts nothing`);
  }
}

// The address asked for, with or without the slash a host adds, is the page. Anywhere else is not.
function sameAddress(a, b) {
  const tidy = (url) => new URL(url).href.replace(/\/$/, "");
  return tidy(a) === tidy(b);
}

// ---------------------------------------------------------------------------------------------------
// The whole check, against one address.

async function check(address, options) {
  const problems = [];
  const cookie = options.cookie;

  let response;
  try {
    response = await fetch(address, { headers: cookie ? { cookie } : {}, redirect: "follow" });
  } catch (e) {
    throw new CouldNotRun(`${address} did not answer: ${e.message}`);
  }
  if (response.status !== 200) {
    throw new CouldNotRun(
      `${address} answered ${response.status}${cookie ? "" : ". A walled host needs its read-only check in TIMEWITNESS_APP_WALL_COOKIE"}`,
    );
  }
  const fetched = Buffer.from(await response.arrayBuffer());
  const page = fetched.toString("utf8");
  mkdirSync(work, { recursive: true });
  const saved = join(work, "served.html");
  writeFileSync(saved, fetched);

  // 1. Which commit. The self-test serves this tree's own page, which names this tree, changes and all.
  const builtFrom = page.match(BUILT_FROM)?.[1];
  let commit = null;
  if (!builtFrom) {
    problems.push("the served page names no commit it was built from, so there is nothing to build it again from");
  } else if (options.selfTest) {
    const here = builtFromHere();
    if (builtFrom !== here) problems.push(`the served page was built from ${builtFrom} and this checkout is ${here}`);
  } else if (builtFrom.endsWith("-modified")) {
    problems.push(`the served page was built from ${builtFrom}, a tree with changes nobody committed, so nobody else can build it`);
  } else if (!/^[0-9a-f]{40}$/.test(builtFrom)) {
    problems.push(`the served page says it was built from ${JSON.stringify(builtFrom)}, which is not a commit`);
  } else {
    commit = builtFrom;
  }

  // 2. The page that commit builds, byte for byte. The self-test hands in this tree's own build.
  let build = options.build ?? null;
  if (!build && commit) {
    build = theBuildAt(commit, theCompilerOf(theOnlyModuleIn(page) ?? Buffer.alloc(0)));
    if (!build) problems.push(`the served page was built from ${commit}, which this repository does not have, so nobody can build it`);
  }
  if (build) {
    const differs = whereTheyDiffer(fetched, build.page, builtFrom);
    if (differs) problems.push(differs);
  }
  if (!build) {
    problems.push("with no build to hold it to there is no command line either, so the receipts were not put to it");
    return { problems, builtFrom, cases: [] };
  }

  // 3. Nothing in it could ask a network for anything.
  try {
    execFileSync(process.execPath, [join(root, "scripts", "verifier-page-offline.mjs"), saved], { stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    problems.push(`the served page does not pass verifier-page-offline.mjs: ${String(e.stderr || "").trim().split("\n").join(" / ")}`);
  }

  // 4 and 5. The receipts, held to the command line built at the same commit as the page.
  const cases = options.casesFor(build.cli);
  const run = await theModuleIn(page, problems);
  const browser = await aBrowser(address);
  try {
    for (const { what, receipt, subject } of cases) {
      const cli = fromCommandLine(build.cli, receipt, subject);
      if (run) theModuleAgrees(problems, what, run(receipt, subject), cli);
      const seen = await inTheBrowser(browser, address, cookie, receipt, subject);
      whatTheBrowserShowed(problems, what, seen, cli, fetched, run);
      whatTheBrowserSent(problems, what, seen, address, readFileSync(subject));
      options.said?.(what, cli, seen);
    }
  } finally {
    await browser.close();
  }
  return { problems, builtFrom, cases };
}

// ---------------------------------------------------------------------------------------------------
// The self-test: this tree's own page on the loopback address, as built and seeded.

const SENDS_ON_CLICK =
  '<script>document.getElementById("form").addEventListener("submit", async () => { const f = document.getElementById("subject").files[0]; if (f) globalThis["fe" + "tch"]("/collect/", { method: "POST", body: await f.arrayBuffer() }); });</script>';
// A file cannot be read once its page is going, so this one reads it when the button is clicked and
// holds the bytes until then.
const SENDS_ON_LEAVING =
  '<script>let held = null; document.getElementById("form").addEventListener("submit", async () => { const f = document.getElementById("subject").files[0]; if (f) held = await f.arrayBuffer(); }); addEventListener("pagehide", () => { if (held) navigator["send" + "Beacon"]("/collect/", held); });</script>';

const CHANGED_WORDS = '<p class="mono">Certified exact to the nanosecond. This page proves the precise time.</p>';

async function selfTest(cli) {
  const built = join(root, "verifier-page", "verifier.html");
  if (!existsSync(built)) throw new CouldNotRun("verifier-page/verifier.html is not there. Build it first: bash scripts/build-verifier-page.sh");
  const page = readFileSync(built, "utf8");
  const seeds = {
    "/verify/": page,
    "/wrong-verdict/": page.replace("    renderResult(result);", "    renderResult(Object.assign(result, { accepted: !result.accepted }));"),
    "/wrong-width/": page.replace('"UTC was somewhere in an interval " + c.width_in_words', '"UTC was somewhere in an interval 1" + c.width_in_words'),
    "/sends-on-click/": page.replace(POLICY, "").replace("</body>", `${SENDS_ON_CLICK}\n</body>`),
    "/sends-on-leaving/": page.replace(POLICY, "").replace("</body>", `${SENDS_ON_LEAVING}\n</body>`),
    // The same checking code with an empty custom section on the end, so it answers exactly as the
    // page's own does and only the module's identity differs.
    "/runs-another-module/": page.replace(
      "WebAssembly.instantiate(bytesFromBase64(WASM_BASE64), {})",
      "WebAssembly.instantiate((() => { const b = bytesFromBase64(WASM_BASE64); const c = new Uint8Array(b.length + 3); c.set(b); c.set([0, 1, 0], b.length); return c; })(), {})",
    ),
    "/another-commit/": page.replace(BUILT_FROM, `<meta name="tw-built-from" content="${"0".repeat(40)}">`),
    // A claim the page was never built to make, in words, with the module, the policy and the commit
    // it names all left as they were.
    "/changed-words/": page.replace("<footer>", `<footer>\n  ${CHANGED_WORDS}`),
    // The module with an empty custom section on the end, carried in the page itself this time, so the
    // page runs it, the check runs it and the two agree. Only the bytes say it is not the build's.
    "/another-build-of-the-module/": page.replace(MODULE, (_, encoded) => {
      const bytes = Buffer.from(encoded, "base64");
      return `const WASM_BASE64 = "${Buffer.concat([bytes, Buffer.from([0, 1, 0])]).toString("base64")}";`;
    }),
  };
  for (const [path, text] of Object.entries(seeds)) {
    if (path !== "/verify/" && text === page) throw new CouldNotRun(`the seed at ${path} found nowhere to go in the page`);
  }
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      if (req.url === "/collect/") {
        received.push({ from: req.headers.referer || "", body: Buffer.concat(chunks) });
        res.writeHead(204).end();
      } else if (seeds[req.url]) {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(seeds[req.url]);
      } else {
        res.writeHead(404).end();
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const at = (path) => `http://127.0.0.1:${server.address().port}${path}`;
  const cases = theCases({ selfTest: true });
  // The build every seed is held to is the file this tree built, and the command line built beside it.
  const options = { build: { page: readFileSync(built), cli }, casesFor: () => cases, selfTest: true };
  const subjects = cases.map((c) => readFileSync(c.subject));
  const failures = [];
  const expectations = [
    ["/wrong-verdict/", "a page showing the wrong verdict", (p) => p.includes("the verdict shown in the browser")],
    ["/wrong-width/", "a page showing the wrong width", (p) => p.includes("the browser shows") && p.includes("width is")],
    ["/sends-on-click/", "a page sending the file when the button is clicked", (p) => p.includes("the page sent the file it was given") && p.includes("after the files were chosen")],
    ["/sends-on-leaving/", "a page sending the file as it is left", (p) => p.includes("the page sent the file it was given") && p.includes("while the page was being left")],
    ["/runs-another-module/", "a page running a module other than the one it carries", (p) => p.includes("the browser ran")],
    ["/another-commit/", "a page built from another commit", (p) => p.includes(`built from ${"0".repeat(40)}`)],
    ["/changed-words/", "a page with words its build never had", (p) => p.includes("is not the page") && p.includes("Certified exact")],
    ["/another-build-of-the-module/", "a page carrying a module its build never made", (p) => p.includes("the module in the served page is")],
  ];
  try {
    const clean = await check(at("/verify/"), options);
    if (clean.problems.length) failures.push(...clean.problems.map((p) => `the page as built was refused: ${p}`));

    for (const [path, what, caught] of expectations) {
      const before = received.length;
      const seeded = await check(at(path), options);
      if (!seeded.problems.some(caught)) {
        failures.push(`${what} was not refused by the part written for it: ${seeded.problems.join(" | ") || "nothing refused it"}`);
      } else {
        console.log(`refused ${what}: ${seeded.problems.find(caught)}`);
      }
      // A seed that sends only shows the check refusing if the file really went.
      if (path.startsWith("/sends-") && !received.slice(before).some((r) => subjects.some((subject) => r.body.equals(subject)))) {
        failures.push(`${what} never reached the server with the file, so it proves nothing about the check`);
      }
    }
  } finally {
    server.close();
  }

  // And the comparison itself, on an answer moved by one character, deep in the answer and at the top.
  const cli0 = fromCommandLine(cli, cases[0].receipt, cases[0].subject);
  for (const [where, moved] of [
    ["the verdict line", { ...cli0, verdict: `${cli0.verdict}.` }],
    ["a step's sentence", { ...cli0, steps: cli0.steps.map((s, i) => (i === 0 ? { ...s, detail: `${s.detail}.` } : s)) }],
  ]) {
    const found = [];
    theModuleAgrees(found, "an answer moved by one character", moved, cli0);
    if (found.length !== 1) failures.push(`an answer moved by one character in ${where} was read as ${found.length} differences rather than one`);
  }
  const added = [];
  theModuleAgrees(added, "an answer with a field added", { ...cli0, certificate: { holds: true } }, cli0);
  if (added.length === 0) failures.push("a certificate on one side and not the other was not read as a difference");
  const { width_ns: _, ...narrower } = cli0.claim;
  const dropped = [];
  theModuleAgrees(dropped, "an answer with a field dropped", { ...cli0, claim: narrower }, cli0);
  if (!dropped.some((d) => d.includes(".claim.width_ns"))) failures.push("a width on one side and not the other was not read as a difference");

  if (failures.length) {
    for (const f of failures) console.error(`  ${f}`);
    console.error("the served page check is not connected the way it says");
    return 1;
  }
  console.log(`the served page check passed this tree's page on ${cases.length} receipts and refused all ${expectations.length} seeds, each by its own part`);
  return 0;
}

// ---------------------------------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "--self-test") return selfTest(theCommandLine());

  const address = args.find((a) => !a.startsWith("--") && /^https?:\/\//.test(a));
  if (!address) {
    console.error("name the address the page is served at, for example https://dev.timewitness.dev/verify/");
    return 2;
  }
  const at = args.indexOf("--fresh");
  const fresh = at === -1 ? null : [args[at + 1], args[at + 2]];
  if (fresh && !(fresh[0] && fresh[1] && existsSync(fresh[0]) && existsSync(fresh[1]))) {
    console.error("--fresh takes a receipt and the file it stamps, both on disk");
    return 2;
  }
  const { problems, builtFrom, cases } = await check(address, {
    casesFor: (cli) => theCases({ cli, fresh, takeFresh: !args.includes("--no-fresh") }),
    cookie: process.env.TIMEWITNESS_APP_WALL_COOKIE || null,
    said: (what, cli, seen) =>
      console.log(
        `${what}: ${cli.accepted ? "accepted" : "refused"} by both, ${cli.claim ? `${cli.claim.width_ns} ns wide, ` : ""}` +
          `the browser showed "${seen.shown.verdict}", and the tab asked a network for ` +
          seen.requests
            .filter((r) => !r.url.startsWith("data:"))
            .map((r) => `${r.method} ${r.url} ${r.phase}`)
            .join(", "),
      ),
  });
  if (problems.length) {
    for (const p of problems) console.error(`  ${p}`);
    console.error(`the page served at ${address} does not hold`);
    return 1;
  }
  console.log(
    `the page served at ${address} is byte for byte the page ${builtFrom} builds, asks for nothing, and gives the verdict and width ` +
      `of the command line built beside it` +
      ` on ${cases.length} receipts in a browser, never sending the file`,
  );
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e instanceof CouldNotRun ? `the served page check could not run: ${e.message}` : e.stack || String(e));
    process.exit(2);
  },
);
