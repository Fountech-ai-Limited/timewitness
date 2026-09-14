#!/usr/bin/env bash
# Build the verifier as one HTML file that runs from a local disk with no server of anybody's.
#
# The output is a single file. The WebAssembly module, the brand tokens and the lockup are all
# embedded, because a page that fetches its own parts cannot be saved and opened later, and cannot be
# opened at all from a `file://` address without a browser refusing the fetch. The reason to want
# that is the whole argument of the thing: a reader downloads this once, and can check a receipt
# years later on a machine with no network and nobody left to ask.
#
# Run it from anywhere. Output: verifier-page/verifier.html.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

target="wasm32-unknown-unknown"
wasm="target/$target/release/timewitness_verify_web.wasm"
page="verifier-page/page.html"
out="verifier-page/verifier.html"

# Two different things, and saying the wrong one sends a reader to install something they already
# have. `rustup` not being on PATH is the ordinary case in a shell that has cargo and nothing else.
if ! command -v rustup >/dev/null 2>&1; then
    echo "rustup is not on PATH, so this cannot tell whether the $target target is installed." >&2
    echo "add the cargo bin directory to PATH, usually ~/.cargo/bin" >&2
    exit 1
fi
if ! rustup target list --installed | grep -qx "$target"; then
    echo "the $target target is not installed. rustup target add $target" >&2
    exit 1
fi

echo "building the module"
cargo build -p timewitness-verify-web --release --target "$target"

bytes=$(wc -c < "$wasm" | tr -d ' ')
echo "module is $bytes bytes"

echo "assembling the page"
python - "$page" "$wasm" "verifier-page/brand/tokens.css" \
         "verifier-page/brand/timewitness-lockup-on-dark.svg" "$out" <<'PYTHON'
import base64
import sys

page_path, wasm_path, tokens_path, lockup_path, out_path = sys.argv[1:6]

page = open(page_path, encoding="utf-8").read()
tokens = open(tokens_path, encoding="utf-8").read()
lockup = open(lockup_path, encoding="utf-8").read()
encoded = base64.b64encode(open(wasm_path, "rb").read()).decode("ascii")

# The lockup goes in as a data address rather than as inline markup, so nothing in it can reach the
# page's own identifiers or styles.
lockup_src = "data:image/svg+xml;base64," + base64.b64encode(lockup.encode("utf-8")).decode("ascii")

page = page.replace("<!-- BRAND-TOKENS -->", "<style>\n" + tokens + "</style>")
page = page.replace(
    "<!-- BRAND-LOCKUP -->",
    '<img src="' + lockup_src + '" alt="TimeWitness">',
)
page = page.replace("<!-- WASM-BASE64 -->", encoded)

for marker in ("<!-- BRAND-TOKENS -->", "<!-- BRAND-LOCKUP -->", "<!-- WASM-BASE64 -->"):
    assert marker not in page, marker + " was not filled in"

open(out_path, "w", encoding="utf-8", newline="\n").write(page)
print("wrote", out_path, len(page), "characters")
PYTHON

# A page that fetches anything cannot be opened years later on a machine with no network, so the page
# as assembled is read for any way it could ask for something before it is compared with anything.
echo "checking the page asks for nothing"
node scripts/verifier-page-offline.mjs

# The comparison is only worth anything if both sides are this working tree. The checker runs
# `target/release/timewitness`, and that binary is whatever was built last, so a run that changed a
# sentence in the verifier and rebuilt only the module compared a fresh page against a stale command
# line and reported four subjects agreeing. Build the other side too, here, where the page is built.
echo "building the command line to compare against"
cargo build -p timewitness-cli --release

echo "checking it against the command line on the same receipt"
node scripts/check-verifier-page.mjs

echo "verifier page: built"
