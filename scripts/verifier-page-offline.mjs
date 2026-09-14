#!/usr/bin/env node
// The verifier page asks nothing of any network, read off the page as built.
//
// The page is the verifier a reader downloads once and opens years later on a machine with nobody
// left to ask, and `/cannot-prove` on the site says it runs from a local disk with no network. Until
// this file that held because nobody had added a request, and nothing would have noticed the day
// somebody did: the architecture test reads the page's source for a handful of spellings, and a test
// run on 2026-09-14 put a dynamic `import()` with its host split across two strings and an image
// beacon into the page and both went through.
//
// So this reads the file somebody would actually download, `verifier-page/verifier.html`, with the
// module, the brand tokens and the lockup already embedded, and refuses anything in it that could
// make the browser ask for something: a network primitive, a way of loading code or a stylesheet, an
// element or an attribute that fetches, a CSS `url()`, a navigation, an address. The one kind of
// reference allowed is a `data:` address, which carries its bytes with it. It also asks the module
// what it imports, and requires the answer to be nothing: the page hands the module an empty import
// object, and a module that imports is one somebody could hand `fetch` to.
//
//     node scripts/verifier-page-offline.mjs [path]    the built page, verifier-page/verifier.html
//     node scripts/verifier-page-offline.mjs --self-test
//
// The self-test puts one seed for every rule into the real page, in memory, and passes only if each
// is refused by the rule it was written for and the page as built is not refused at all. A guard
// nobody has seen fail is a guard nobody knows is connected.
//
// It does not run the page in a browser. What a browser does with the page, at several widths, is a
// separate check this repository does not yet have.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const MODULE = /const WASM_BASE64 = "([A-Za-z0-9+/=]*)";/g;

// Each rule names what it refuses and why, so an honest change that trips one can say which rule it
// is arguing with.
const RULES = [
  { name: "fetch", why: "fetches from a network", test: /\bfetch\b/ },
  {
    name: "a connection",
    why: "opens a connection to somebody",
    test: /\b(XMLHttpRequest|WebSocket|EventSource|sendBeacon|WebTransport|RTCPeerConnection)\b/,
  },
  { name: "import", why: "loads code or a stylesheet from an address", test: /\bimport\b/ },
  { name: "an image", why: "loads an image from an address, which is how a beacon is sent", test: /\bnew\s+Image\b|\bImage\s*\(/ },
  { name: "a worker", why: "runs a script loaded from an address", test: /\b(Worker|SharedWorker|importScripts|serviceWorker)\b/ },
  { name: "src", why: "loads from an address that is not carried in the page", test: /\bsrc(set)?\b(?!\s*=\s*["']data:)/ },
  { name: "href", why: "points at an address outside the page", test: /\bhref\b(?!\s*=\s*["']#)/ },
  { name: "url(", why: "loads from an address that is not carried in the page", test: /\burl\(\s*["']?(?!data:|#)/i },
  {
    name: "an element that loads",
    why: "fetches whatever it names",
    test: /<\s*(link|iframe|frame|object|embed|base|audio|video|source|track|portal)\b/i,
  },
  // The page's own form is allowed and is why this is a rule of its own. It has no action, so the
  // most it could ever send is the page's own address, and its submit is stopped in the script
  // before that happens. A form that names somewhere to send to is refused.
  {
    name: "a form that sends",
    why: "sends what the reader chose to an address",
    test: /\b(form)?action\s*=|<\s*form\b[^>]*\bmethod\s*=/i,
  },
  { name: "a refresh", why: "sends the browser somewhere else", test: /http-equiv\s*=\s*["']?refresh/i },
  {
    name: "a navigation",
    why: "sends the browser somewhere else",
    test: /\blocation\s*(\.\s*(assign|replace|href)\b|=(?!=))|\bwindow\s*\.\s*open\b/,
  },
  { name: "an address", why: "names an address on a network, and nothing on this page needs one", test: /\b(https?|wss?|ftp):\/\//i },
];

// The policy the page has to carry, word for word, and it is asserted before anything else is read.
// The rules below read the page's text for ways it could ask for something; this is the line that
// makes the browser refuse the ways they cannot see. A page carrying a different policy, or none,
// is refused whatever else it says. `verifier-page-in-a-browser.mjs` is where the policy is watched
// doing the refusing.
const POLICY =
  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\' \'wasm-unsafe-eval\'; style-src \'unsafe-inline\'; img-src data:; form-action \'none\'; base-uri \'none\'; frame-ancestors \'none\'">';

// What is wrong with a built page, one line per finding.
function findings(page, shown) {
  const found = [];

  const policies = [...page.matchAll(/<meta http-equiv="Content-Security-Policy"[^>]*>/g)];
  if (policies.length !== 1 || policies[0][0] !== POLICY) {
    found.push(
      `${shown}: the policy carries ${policies.length} Content-Security-Policy metas and the page needs exactly this one: ${POLICY}`,
    );
  } else if (page.indexOf(POLICY) > page.indexOf("<script")) {
    found.push(`${shown}: the policy comes after a script, and a policy the browser reads late is one a script ran before`);
  }

  const modules = [...page.matchAll(MODULE)];
  if (modules.length !== 1) {
    found.push(`${shown}: carries ${modules.length} modules where the build embeds exactly one`);
  } else {
    let imports = null;
    try {
      imports = WebAssembly.Module.imports(new WebAssembly.Module(Buffer.from(modules[0][1], "base64")));
    } catch (e) {
      found.push(`${shown}: the embedded module does not compile: ${e.message}`);
    }
    if (imports && imports.length > 0) {
      const names = imports.map((i) => `${i.module}.${i.name}`).join(", ");
      found.push(
        `${shown}: the module imports ${names}, and a module that imports is one the page could hand ` +
          "fetch to; the page hands it nothing and it should ask for nothing",
      );
    }
  }

  // The module and every data: address carry their bytes with them, and their base64 would spell
  // any short word by chance, so they are blanked before the words are read. Nothing else is.
  // The policy names sources by words such as `default-src`, which the `src` rule would read as a
  // load, so it is blanked too, after it has been held to the one line above.
  const read = page
    .replace(/<meta http-equiv="Content-Security-Policy"[^>]*>/g, "")
    .replace(MODULE, 'const WASM_BASE64 = "";')
    .replace(/data:[^"'\s)]*/g, "data:");
  read.split("\n").forEach((line, i) => {
    for (const rule of RULES) {
      const hit = line.match(rule.test);
      if (hit) {
        const at = Math.max(0, hit.index - 30);
        const excerpt = line.slice(at, hit.index + 50).trim();
        found.push(`${shown} line ${i + 1}: ${rule.name} ${rule.why}: ${excerpt}`);
      }
    }
  });
  return found;
}

// A module that asks for one function, `env.f`, and does nothing else. Eight bytes of header, a type
// section holding one empty function type, and an import section holding the one import.
const IMPORTING_MODULE = Buffer.from([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02, 0x09,
  0x01, 0x03, 0x65, 0x6e, 0x76, 0x01, 0x66, 0x00, 0x00,
]).toString("base64");

// One seed for every rule, each with the rule it has to be refused by. The first two are the ones the
// test run of 2026-09-14 put into the page and watched go through.
const SEEDS = [
  { rule: "import", body: '<script type="module">import("https://app" + ".timewitness.dev/k.js");</script>' },
  { rule: "an image", body: '<script>new Image().src = "https://timewitness.dev/px?r=" + location.hash;</script>' },
  { rule: "fetch", body: '<script>fetch("https://app.timewitness.dev/keys");</script>' },
  { rule: "url(", style: ".x { background: url(https://example.org/p.png); }" },
  { rule: "a connection", body: "<script>navigator.sendBeacon(where, what);</script>" },
  { rule: "a connection", body: "<script>new XMLHttpRequest();</script>" },
  { rule: "a connection", body: "<script>new WebSocket(where);</script>" },
  { rule: "a connection", body: "<script>new EventSource(where);</script>" },
  { rule: "import", style: '@import "fonts.css";' },
  { rule: "src", body: '<script src="verifier.js"></script>' },
  { rule: "href", body: '<a href="https://github.com/Fountech-ai-Limited/timewitness">source</a>' },
  { rule: "an element that loads", body: '<link rel="stylesheet" href="a.css">' },
  { rule: "an element that loads", body: "<iframe></iframe>" },
  { rule: "a form that sends", body: '<form action="/keys" method="post"></form>' },
  { rule: "a form that sends", body: '<button formaction="/keys">Send</button>' },
  { rule: "a refresh", head: '<meta http-equiv="refresh" content="0; url=elsewhere">' },
  { rule: "a navigation", body: "<script>location.assign(where);</script>" },
  { rule: "a worker", body: "<script>new Worker(where);</script>" },
  { rule: "an address", body: '<script>const where = "https://keys.example.org";</script>' },
  { rule: "the module", module: IMPORTING_MODULE },
  { rule: "the policy", policy: "" },
  { rule: "the policy", policy: POLICY.replace("default-src 'none'; ", "") },
  { rule: "the policy", policy: `<script></script>\n${POLICY}`, late: true },
];

function seeded(page, seed) {
  if (seed.late) return page.replace(POLICY, "").replace("</head>", `${seed.policy}\n</head>`);
  if (seed.policy !== undefined) return page.replace(POLICY, seed.policy);
  if (seed.module) return page.replace(MODULE, `const WASM_BASE64 = "${seed.module}";`);
  if (seed.style) return page.replace("</style>", `${seed.style}\n</style>`);
  if (seed.head) return page.replace("</head>", `${seed.head}\n</head>`);
  return page.replace("</body>", `${seed.body}\n</body>`);
}

function pageAt(path) {
  if (!existsSync(path)) {
    console.error(`${relative(root, path)} is not there. Build it first: bash scripts/build-verifier-page.sh`);
    process.exit(2);
  }
  return readFileSync(path, "utf8");
}

const args = process.argv.slice(2);
const path = join(root, "verifier-page", "verifier.html");

if (args[0] === "--self-test") {
  const page = pageAt(path);
  const problems = [];
  const clean = findings(page, "the page as built");
  if (clean.length > 0) problems.push(...clean.map((f) => `refused the page as built: ${f}`));
  for (const seed of SEEDS) {
    const text = seeded(page, seed);
    if (text === page) {
      problems.push(`the seed for ${seed.rule} found nowhere to go in the page`);
      continue;
    }
    const found = findings(text, "seeded");
    const byRule = seed.module
      ? found.some((f) => f.includes("the module imports"))
      : seed.policy !== undefined
        ? found.some((f) => f.includes("Content-Security-Policy") || f.includes("the policy comes after"))
        : found.some((f) => f.includes(`: ${seed.rule} `));
    if (!byRule) {
      problems.push(`the seed for ${seed.rule} was not refused by that rule: ${found.join(" | ") || "nothing refused it"}`);
    }
  }
  if (problems.length > 0) {
    for (const p of problems) console.error("  " + p);
    console.error("the page check is not connected the way it says");
    process.exit(1);
  }
  console.log(`the page check refused all ${SEEDS.length} seeds, each by its own rule, and passed the page as built`);
  process.exit(0);
}

const target = args[0] ? resolve(args[0]) : path;
const found = findings(pageAt(target), relative(root, target).replace(/\\/g, "/"));
if (found.length > 0) {
  for (const f of found) console.error("  " + f);
  console.error("the verifier page could ask a network for something, and it has to run with none");
  process.exit(1);
}
console.log("the verifier page asks for nothing: no request, no address, and a module that imports nothing");
