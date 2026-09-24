#!/usr/bin/env node
// A stranger checks a receipt on a page we host, and the page a host serves is held to what it says.
//
//     node scripts/the-served-verifier-page.mjs <address>        the page as a host serves it
//     node scripts/the-served-verifier-page.mjs --self-test      served from this machine, and seeded
//
// Every other check of the verifier page reads the file this tree builds. A host can serve something
// else: an older build, a build of another commit, a page with a line added in front of it. So this
// asks the host for the page and reads what comes back, the way somebody would who had only the
// address. Four things have to hold, and every one is read, so a run names all that is wrong rather
// than the first thing:
//
//   1. The page says which commit it was built from, and it is the commit this checkout is at. The
//      command line built here is the one the page has to agree with, so a page built anywhere else
//      is not the page under test, and a page built from a tree with changes nobody committed is a
//      page nobody else can reproduce.
//   2. The page as served passes `verifier-page-offline.mjs`, which reads it for any way it could ask
//      a network for something.
//   3. The checking code inside the served page, run on its own, gives the command line's verdict,
//      width, reading and steps on every receipt below.
//   4. In a real browser at that address, choosing the receipt and the file it stamps and pressing
//      the button shows the command line's verdict and width, and the page asks for nothing at all
//      once it is open. A request carrying the file is named as that.
//
// The receipts are the one committed in this repository, the same receipt against a file it does not
// stamp, which has to be refused, and one stamped here and now with the command line, which needs the
// network the way stamping always does. `--no-fresh` leaves the last one out, and `--fresh <receipt>
// <subject>` hands one in rather than taking one.
//
// A walled host answers its own sign-in page rather than this one. Where the host is walled, put the
// wall's read-only check in TIMEWITNESS_APP_WALL_COOKIE, as `name=value`, and it is sent with the
// page request and nothing else. The app repository's `npm run wall-check` prints one.
//
// `--self-test` serves the page this tree built on the loopback address, runs the whole check on it,
// and then runs it on four seeds, each of which has to be refused by the part written for it: a page
// that shows the wrong verdict, one that shows the wrong width, one that sends the file it was given,
// and one built from another commit. The seed that sends the file is written so the page check's spellings cannot see it and the
// policy is taken out so the browser lets it go, and the server has to receive the file, so the seed
// is shown connected before its refusal is believed. A guard nobody has seen fail is not evidence.
//
// Exit 0 when everything holds, 1 when something does not, 2 when the check could not run: no browser,
// no command line, a host that would not answer, or no fresh receipt. Never a pass.

import { execFileSync, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = join(root, "target", "served-verifier-page");
const binary = join(root, "target", "release", process.platform === "win32" ? "timewitness.exe" : "timewitness");
const fixture = join(root, "crates", "verify", "tests", "data", "a-real-stamp");
const versionOne = join(root, "crates", "verify", "tests", "data", "a-version-1-stamp");
const BUILT_FROM = /<meta name="tw-built-from" content="([^"]*)">/;
const MODULE = /const WASM_BASE64 = "([A-Za-z0-9+/=]+)";/;
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
  try {
    return JSON.parse(execFileSync(cli, argv, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  } catch (e) {
    const printed = e.stdout || e.stderr;
    if (printed) return JSON.parse(printed);
    throw e;
  }
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

async function theModuleIn(page) {
  const encoded = page.match(MODULE);
  if (!encoded) return null;
  const instance = (await WebAssembly.instantiate(Buffer.from(encoded[1], "base64"), {})).instance.exports;
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
  return (receiptFile, subjectFile) => {
    const receiptAt = put(readFileSync(receiptFile));
    const subjectAt = put(readFileSync(subjectFile));
    const result = take(instance.tw_verify(receiptAt, subjectAt, 1));
    instance.tw_free(receiptAt);
    instance.tw_free(subjectAt);
    return result;
  };
}

function agree(problems, what, page, commandLine) {
  if (JSON.stringify(page) !== JSON.stringify(commandLine)) {
    problems.push(`${what}: the served page says ${JSON.stringify(page)} and the command line says ${JSON.stringify(commandLine)}`);
  }
}

function theModuleAgrees(problems, what, fromPage, cli) {
  if (fromPage === null) {
    problems.push(`${what}: the checking code in the served page returned nothing`);
    return;
  }
  agree(problems, `${what}, the verdict`, fromPage.accepted, cli.accepted);
  agree(problems, `${what}, the verdict line`, fromPage.verdict, cli.verdict);
  agree(problems, `${what}, the line under the verdict`, fromPage.bracket, cli.bracket);
  agree(problems, `${what}, the width`, fromPage.claim?.width_ns, cli.claim?.width_ns);
  agree(problems, `${what}, the reading`, fromPage.claim?.reading_ns, cli.claim?.reading_ns);
  agree(problems, `${what}, the receipt digest`, fromPage.receipt_sha256, cli.receipt_sha256);
  agree(problems, `${what}, what was checked`, fromPage.steps, cli.steps);
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
// debugging protocol. No window opens.
async function aBrowser() {
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
      "about:blank",
    ],
    { stdio: "ignore" },
  );
  const portFile = join(profile, "DevToolsActivePort");
  await until("opening its debugging port", () => existsSync(portFile) && readFileSync(portFile, "utf8").includes("\n"));
  const [port, path] = readFileSync(portFile, "utf8").split("\n");
  const socket = new WebSocket(`ws://127.0.0.1:${port}${path}`);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new CouldNotRun("the browser's debugging port would not take a connection")), { once: true });
  });

  let next = 0;
  const waiting = new Map();
  const listeners = new Set();
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

  const close = async () => {
    try {
      await send("Browser.close");
    } catch {
      // Already going.
    }
    socket.close();
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
  return { send, listeners, close };
}

// One receipt, in a tab of its own. What the page shows, and every request the tab made, with the
// moment it made it.
async function inTheBrowser(browser, address, cookie, receiptFile, subjectFile) {
  const { targetId } = await browser.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId, flatten: true });
  const tab = (method, params) => browser.send(method, params, sessionId);
  const requests = [];
  let phase = "while the page was loading";
  let loaded = false;
  const listener = (message) => {
    if (message.sessionId !== sessionId) return;
    if (message.method === "Page.loadEventFired") loaded = true;
    if (message.method === "Network.requestWillBeSent") {
      const { requestId, request, type } = message.params;
      requests.push({ requestId, phase, type, method: request.method, url: request.url, hasPostData: request.hasPostData, entries: request.postDataEntries, postData: request.postData });
    }
  };
  browser.listeners.add(listener);
  try {
    await tab("Network.enable");
    await tab("Page.enable");
    await tab("DOM.enable");
    await tab("Runtime.enable");
    if (cookie) await tab("Network.setExtraHTTPHeaders", { headers: { Cookie: cookie } });
    const evaluate = async (expression) => (await tab("Runtime.evaluate", { expression, returnByValue: true })).result.value;

    await tab("Page.navigate", { url: address });
    await until("the page loading", () => loaded);
    await until("the page's checking code coming up", () => evaluate('!!document.getElementById("go") && !document.getElementById("go").disabled'));
    phase = "after the page had loaded";

    const { root: documentNode } = await tab("DOM.getDocument", { depth: 1 });
    for (const [selector, file] of [["#receipt", receiptFile], ["#subject", subjectFile]]) {
      const { nodeId } = await tab("DOM.querySelector", { nodeId: documentNode.nodeId, selector });
      if (!nodeId) throw new CouldNotRun(`the page has no ${selector} to choose a file with`);
      await tab("DOM.setFileInputFiles", { nodeId, files: [file] });
    }
    phase = "after the files were chosen";
    await evaluate('document.getElementById("go").click()');
    await until("a verdict on the page", () =>
      evaluate(
        '!document.getElementById("result").hidden && document.getElementById("go").textContent !== "Checking" && document.getElementById("verdict").textContent !== ""',
      ),
    );
    // Anything the page sends on the way to its verdict has been sent by now; a moment more is given
    // for a send that waits on something.
    await sleep(750);
    const shown = await evaluate(`JSON.stringify({
      verdict: document.getElementById("verdict").textContent,
      state: document.getElementById("verdict").className.replace("verdict", "").trim(),
      bracket: document.getElementById("verdict-bracket").textContent,
      claim: (document.querySelector("#claim p") || { textContent: "" }).textContent,
    })`);
    for (const request of requests) {
      if (request.hasPostData && request.postData === undefined && request.entries === undefined) {
        try {
          request.postData = (await tab("Network.getRequestPostData", { requestId: request.requestId })).postData;
        } catch {
          // The body is gone with the request; the request is still counted.
        }
      }
    }
    return { shown: JSON.parse(shown), requests };
  } finally {
    browser.listeners.delete(listener);
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

const UNITS = { ns: 1, us: 1e3, ms: 1e6, s: 1e9 };

// The width the page wrote in words, held to the command line's in nanoseconds to the last digit the
// page printed.
function widthAgrees(claimLine, widthNs) {
  const said = claimLine.match(/interval ([0-9]+(?:\.([0-9]+))?) (ns|us|ms|s) wide/);
  if (!said) return false;
  const unit = UNITS[said[3]];
  const lastDigit = unit / 10 ** (said[2] ? said[2].length : 0);
  return Math.abs(Number(said[1]) * unit - widthNs) <= lastDigit / 2 + 1e-6;
}

function whatTheBrowserShowed(problems, what, seen, cli) {
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
// browser reading one is not a request of anybody.
function whatTheBrowserSent(problems, what, requests, address, subject) {
  for (const request of requests) {
    const shown = request.url.length > 120 ? `${request.url.slice(0, 120)}...` : request.url;
    if (carries(request, subject)) {
      problems.push(`${what}: the page sent the file it was given, ${request.method} ${shown}, ${request.phase}`);
      continue;
    }
    if (request.url.startsWith("data:") && request.method === "GET") continue;
    if (request.phase === "while the page was loading" && request.type === "Document" && sameAddress(request.url, address)) continue;
    problems.push(`${what}: the page asked for ${request.method} ${shown} ${request.phase}, and it asks for nothing but itself`);
  }
}

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
  const page = await response.text();
  mkdirSync(work, { recursive: true });
  const saved = join(work, "served.html");
  writeFileSync(saved, page);

  // 1. Which commit.
  const builtFrom = page.match(BUILT_FROM)?.[1];
  const here = builtFromHere();
  if (!builtFrom) {
    problems.push("the served page names no commit it was built from, so there is no command line to hold it to");
  } else if (builtFrom.endsWith("-modified") && !options.selfTest) {
    problems.push(`the served page was built from ${builtFrom}, a tree with changes nobody committed, so nobody else can build it`);
  } else if (builtFrom !== here) {
    problems.push(`the served page was built from ${builtFrom} and this checkout is ${here}. Run this at the commit the page names`);
  }

  // 2. Nothing in it could ask a network for anything.
  try {
    execFileSync(process.execPath, [join(root, "scripts", "verifier-page-offline.mjs"), saved], { stdio: ["ignore", "pipe", "pipe"] });
  } catch (e) {
    problems.push(`the served page does not pass verifier-page-offline.mjs: ${String(e.stderr || "").trim().split("\n").join(" / ")}`);
  }

  // 3 and 4. The receipts.
  const run = await theModuleIn(page);
  if (!run) problems.push("the served page carries no checking code");
  const browser = await aBrowser();
  try {
    for (const { what, receipt, subject } of options.cases) {
      const cli = fromCommandLine(options.cli, receipt, subject);
      if (run) theModuleAgrees(problems, what, run(receipt, subject), cli);
      const seen = await inTheBrowser(browser, address, cookie, receipt, subject);
      whatTheBrowserShowed(problems, what, seen, cli);
      whatTheBrowserSent(problems, what, seen.requests, address, readFileSync(subject));
      options.said?.(what, cli, seen);
    }
  } finally {
    await browser.close();
  }
  return { problems, builtFrom };
}

// ---------------------------------------------------------------------------------------------------
// The self-test: this tree's own page on the loopback address, as built and seeded.

const SENDS_THE_FILE =
  '<script>document.getElementById("form").addEventListener("submit", async () => { const f = document.getElementById("subject").files[0]; if (f) globalThis["fe" + "tch"]("/collect/", { method: "POST", body: await f.arrayBuffer() }); });</script>';

async function selfTest(cli) {
  const built = join(root, "verifier-page", "verifier.html");
  if (!existsSync(built)) throw new CouldNotRun("verifier-page/verifier.html is not there. Build it first: bash scripts/build-verifier-page.sh");
  const page = readFileSync(built, "utf8");
  const seeds = {
    "/verify/": page,
    "/wrong-verdict/": page.replace("    renderResult(result);", "    renderResult(Object.assign(result, { accepted: !result.accepted }));"),
    "/wrong-width/": page.replace('"UTC was somewhere in an interval " + c.width_in_words', '"UTC was somewhere in an interval 1" + c.width_in_words'),
    "/sends-the-file/": page.replace(POLICY, "").replace("</body>", `${SENDS_THE_FILE}\n</body>`),
    "/another-commit/": page.replace(BUILT_FROM, `<meta name="tw-built-from" content="${"0".repeat(40)}">`),
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
        received.push(Buffer.concat(chunks));
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
  const options = { cli, cases, selfTest: true };
  const failures = [];
  try {
    const clean = await check(at("/verify/"), options);
    if (clean.problems.length) failures.push(...clean.problems.map((p) => `the page as built was refused: ${p}`));

    const expectations = [
      ["/wrong-verdict/", "a page showing the wrong verdict", (p) => p.includes("the verdict shown in the browser")],
      ["/wrong-width/", "a page showing the wrong width", (p) => p.includes("the browser shows") && p.includes("width is")],
      ["/sends-the-file/", "a page sending the file", (p) => p.includes("the page sent the file it was given")],
      ["/another-commit/", "a page built from another commit", (p) => p.includes(`built from ${"0".repeat(40)}`)],
    ];
    for (const [path, what, caught] of expectations) {
      const seeded = await check(at(path), options);
      if (!seeded.problems.some(caught)) {
        failures.push(`${what} was not refused by the part written for it: ${seeded.problems.join(" | ") || "nothing refused it"}`);
      } else {
        console.log(`refused ${what}: ${seeded.problems.find(caught)}`);
      }
    }
    // The seed that sends the file only shows the check refusing if the file really went.
    const subjects = cases.map((c) => readFileSync(c.subject));
    if (!received.some((body) => subjects.some((subject) => body.equals(subject)))) {
      failures.push("the seed that sends the file never reached the server with it, so it proves nothing about the check");
    }
  } finally {
    server.close();
  }

  // And the comparison itself, on an answer moved by one character.
  const cli0 = fromCommandLine(cli, cases[0].receipt, cases[0].subject);
  const moved = [];
  theModuleAgrees(moved, "an answer moved by one character", { ...cli0, verdict: `${cli0.verdict}.` }, cli0);
  if (moved.length !== 1) failures.push(`an answer moved by one character was read as ${moved.length} differences rather than one`);

  if (failures.length) {
    for (const f of failures) console.error(`  ${f}`);
    console.error("the served page check is not connected the way it says");
    return 1;
  }
  console.log(`the served page check passed this tree's page on ${cases.length} receipts and refused all four seeds, each by its own part`);
  return 0;
}

// ---------------------------------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const cli = theCommandLine();
  if (args[0] === "--self-test") return selfTest(cli);

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
  const cases = theCases({ cli, fresh, takeFresh: !args.includes("--no-fresh") });
  const { problems, builtFrom } = await check(address, {
    cli,
    cases,
    cookie: process.env.TIMEWITNESS_APP_WALL_COOKIE || null,
    said: (what, cli, seen) =>
      console.log(
        `${what}: ${cli.accepted ? "accepted" : "refused"} by both, ${cli.claim ? `${cli.claim.width_ns} ns wide, ` : ""}` +
          `the browser showed "${seen.shown.verdict}", ${seen.requests.length} request${seen.requests.length === 1 ? "" : "s"} made`,
      ),
  });
  if (problems.length) {
    for (const p of problems) console.error(`  ${p}`);
    console.error(`the page served at ${address} does not hold`);
    return 1;
  }
  console.log(
    `the page served at ${address}, built from ${builtFrom}, asks for nothing, and gives the command line's verdict and width ` +
      `on ${cases.length} receipts in a browser, never sending the file`,
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
