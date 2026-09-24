#!/usr/bin/env node
// The verifier page refuses a request in a real browser, and its own module still runs there.
//
// `verifier-page-offline.mjs` reads the built page for spellings, and a call assembled from two
// strings walks past a spelling. So the page carries a Content-Security-Policy that tells the
// browser to refuse every request, and this drives a headless Chrome at the page as built to see
// the browser do it: a fetch reached through `globalThis['fe' + 'tch']`, which no regex on the
// page's text can see, has to be refused by the policy, and the page's own WebAssembly has to have
// come up under the same policy, or the policy is not the one this page needs.
//
//     node scripts/verifier-page-in-a-browser.mjs [path]    the built page, verifier-page/verifier.html
//
// Three runs of the same page, each read off the document the browser ends up with. The page as
// built, seeded with the split-string fetch of a data: address, has to say the fetch was refused
// and has to say its module came up and name, under its form, the receipt formats that module reads.
// The same seed with the policy taken out has to say the fetch went through, which is what proves the seed is connected and the policy is doing the refusing:
// a data: address needs no network, so a refusal there is the policy and not the runner being
// offline. Exit 0 when all three hold, 1 when one does not, 2 when no browser could be found or
// driven, which is a check that could not run and never a pass.
//
// The browser is the Chrome on the machine: CHROME names it, and otherwise the usual names and
// places are tried. It runs headless in a profile of its own, opens no window, and is handed a
// file, never an address.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const POLICY = /<meta http-equiv="Content-Security-Policy" content="[^"]*">\n/;
const SEED =
  '<script>globalThis["fe" + "tch"]("data:,x").then(() => { document.title = "the fetch went through"; }, () => { document.title = "the fetch was refused"; });</script>';
const MODULE_CAME_UP = "kilobytes of WebAssembly";
// The line under the form, which the page fills from the module's own list of the formats it reads.
const FORMATS_READ = /<p class="detail" id="formats">The checking code in this page reads receipt formats? (v\d+(?: and v\d+)*)\.<\/p>/;

function chrome() {
  const named = process.env.CHROME;
  if (named) return named;
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

function rendered(browser, page, work, name) {
  const file = join(work, `${name}.html`);
  writeFileSync(file, page);
  const profile = join(work, `${name}-profile`);
  const dom = execFileSync(
    browser,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-first-run",
      "--disable-extensions",
      `--user-data-dir=${profile}`,
      "--virtual-time-budget=10000",
      "--dump-dom",
      pathToFileURL(file).href,
    ],
    { encoding: "utf8", timeout: 60000, maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] },
  );
  const title = dom.match(/<title>([^<]*)<\/title>/);
  return { title: title ? title[1] : "", dom };
}

const args = process.argv.slice(2);
const target = args[0] ? resolve(args[0]) : join(root, "verifier-page", "verifier.html");
const shown = relative(root, target).replace(/\\/g, "/");
if (!existsSync(target)) {
  console.error(`${shown} is not there. Build it first: bash scripts/build-verifier-page.sh`);
  process.exit(2);
}
const page = readFileSync(target, "utf8");
if (!POLICY.test(page)) {
  console.error(`${shown} carries no Content-Security-Policy meta, so there is nothing for the browser to enforce`);
  process.exit(1);
}

const browser = chrome();
if (!browser) {
  console.error("no Chrome was found to drive, so the page was not run in a browser. Name one with CHROME. That is a failure and not a skip");
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), "timewitness-page-"));
const problems = [];
let readsLine = "";
try {
  const seeded = page.replace("</body>", `${SEED}\n</body>`);
  if (seeded === page) throw new Error("the seed found nowhere to go in the page");

  const under = rendered(browser, seeded, work, "under-the-policy");
  if (under.title !== "the fetch was refused") {
    problems.push(`under the policy the seeded fetch was not refused: the title reads "${under.title}"`);
  }
  if (!under.dom.includes(MODULE_CAME_UP)) {
    problems.push("under the policy the page's own module did not come up, so the policy is refusing the page as well as the network");
  }
  const formats = under.dom.match(FORMATS_READ);
  if (formats) {
    readsLine = formats[1];
  } else {
    problems.push("under the policy the page did not name, under its form, the receipt formats its module reads");
  }

  const without = rendered(browser, seeded.replace(POLICY, ""), work, "without-the-policy");
  if (without.title !== "the fetch went through") {
    problems.push(`without the policy the seeded fetch did not go through, so the seed is not connected: the title reads "${without.title}"`);
  }
} catch (e) {
  console.error(`the browser could not be driven at the page: ${e.message}`);
  rmSync(work, { recursive: true, force: true });
  process.exit(2);
}
rmSync(work, { recursive: true, force: true });

if (problems.length > 0) {
  for (const p of problems) console.error("  " + p);
  console.error("the verifier page's policy does not hold in a browser");
  process.exit(1);
}
console.log(`${shown} in ${browser.split(/[\\/]/).pop()}: a fetch reached through a split string was refused by the policy, the same fetch went through without it, and the module came up under it and named the formats it reads, ${readsLine}`);
