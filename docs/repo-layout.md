# Repository layout, and what each module may import

Written 2026-09-07, with the first commit. This is the canonical version and it lives here because a
rule about the code belongs beside the code. `crates/architecture/tests/module_boundaries.rs`
enforces it on every build, so this document and the dependency graph cannot drift apart without the
suite going red.

## Why the boundary exists at all

Two modules carry the product and they fail in opposite ways.

The clock model carries the arithmetic. If it is wrong, it is wrong quietly, and every receipt it
feeds is a false claim that looks exactly like a true one.

The receipt format carries the evidence. If it shifts under a receipt that was issued last year,
that receipt stops meaning what it meant when it was signed.

Keeping them apart means a change to how a bound is computed cannot alter what a receipt says, and a
change to what a receipt says cannot alter how a bound is computed. If they shared files, neither
change would announce itself.

## The crates

| Crate | Directory | What it is | May import |
|---|---|---|---|
| `timewitness-core` | `crates/core` | Plain data types: the reading, the bound and its breakdown, an offset interval, source state, the refusal states. No work is done here. | nothing of ours |
| `timewitness-sources` | `crates/sources` | What a time source is, and the raw four-timestamp exchange one produces. The Roughtime, freshness beacon and final witness clients arrive here as implementations. | `core` |
| `timewitness-clock` | `crates/clock` | The clock model: per-source windows, Marzullo intersection with our own stricter selection rule on top, inverse-square weighting, regression, rate discipline, holdover, the refusal path. | `core`, `sources` |

The selection rule departs from textbook Marzullo, decided 2026-09-09, and `crates/clock/src/marzullo.rs` states the departure at the head of the file. A majority that exists only because of sources that could not have been put in the minority is refused rather than signed. It only ever turns an answer into a refusal; no region moves.
| `timewitness-receipt` | `crates/receipt` | Receipt format v0: the schema, deterministic CBOR, the COSE envelope, the validator. | `core` |
| `timewitness-verify` | `crates/verify` | The verifier. Ships as a thing that runs with none of our infrastructure and no account. | `core`, `receipt` |
| `timewitness-verify-web` | `crates/verify-web` | The verifier core as WebAssembly. Converts bytes to bytes across the boundary a page calls through, and checks nothing itself. | `core`, `receipt`, `verify` |
| `timewitness-cli` | `crates/cli` | The command line. Wires the others together and does no work of its own. | all of the above |
| `timewitness-roughtime-server` | `crates/roughtime-server` | A Roughtime server of our own: the long-term key, the delegation it signs, the socket loop, the rate limit and the refusals. The wire format is not here. | `core` |
| `timewitness-architecture` | `crates/architecture` | No code. The tests that enforce this table. | nothing |

## The rules, stated rather than inferred

1. **The clock model may not import the receipt.** It hands out a `Stamp`, which is a reading, a
   bound and the state of the sources. What a receipt looks like is not its business.

2. **The receipt may not import the clock model or the source pool.** It carries a bound and it
   never learns how one is computed. A verifier holding only `core` and `receipt` can read a receipt
   with none of the agent present, and that is what makes the verifier independent rather than a
   second copy of us.

3. **The shared types live in `core` and nothing else is shared.** The rule as first written allowed
   the receipt to import a plain reading-and-bound type from the clock model. Putting those types in
   a third crate that both depend on is the same rule enforced more tightly: the two crates now
   import nothing from each other at all, in either direction.

4. **The verifier may not import the clock model or the source pool.** Same reason as rule 2, stated
   as its own rule because it is the one somebody will be tempted to break to reuse a helper.

5. **The two verifier shells share one core.** `crates/verify` holds every check. `crates/verify-web`
   and `crates/cli` are shells around it and neither may decide anything. Two implementations of the
   checking logic drift, and the day they drift is the day the page says a receipt is good and the
   binary says it is not; `scripts/check-verifier-page.mjs` puts one receipt through both and fails
   the build where the two disagree.

6. **`verify-web` is the one crate that does not forbid `unsafe`.** It denies it and allows it by
   name on four exported functions, because exporting a function to WebAssembly at all needs an
   attribute this compiler classes as unsafe. Nothing in it dereferences a pointer: buffers handed to
   a page stay owned by the module. The exception is four lines a reader can count and the manifest
   says so where somebody adding a fifth would see it.

7. **Presentation is separated from the first line.** Everything the command line prints goes
   through `crates/cli/src/render.rs`. Nothing outside that file formats anything for a person to
   read, and nothing inside it decides anything. When the brand arrives it lands there and touches
   no logic.

## What the tests check

`crates/architecture/tests/module_boundaries.rs` parses every crate manifest and compares the
`timewitness-*` dependencies against the table above.

`scripts/repo-hygiene.sh` runs in CI over the tree and the whole history. One author on every commit,
prose in every commit message rather than a machine-readable footer, plain ASCII in every file, and a
tracked path that is one of the things this repository holds. Each rule says what belongs rather than
what does not, so a shape nobody has thought about is refused rather than admitted.

## Where new work goes

- A time source client, meaning Roughtime, a freshness beacon, or a final witness: `crates/sources`,
  as an implementation of `TimeSource` or of whatever narrower trait that role needs. None of them
  changes the clock model.
- Anything about how the bound is computed or when it is refused: `crates/clock`.
- Anything about what a receipt carries: `crates/receipt`, and the schema document beside it.
- Anything a stranger runs to check a receipt: `crates/verify`.
- The countersign protocol is phase 2 and has no folder here yet. It gets one when phase 2 opens and
  not before.
