#!/usr/bin/env bash
# Build the verifier page at a tag or a commit, for a host to serve.
#
#     bash scripts/page-for-a-host.sh <tag or commit> <folder>
#
# Writes two files into the folder: `verifier.html`, the page as `build-verifier-page.sh` builds it at
# that commit, and `record.json`, naming the ref asked for, the commit it resolved to, and the size and
# sha256 of the page. A host serves the first and checks it against the second when it builds.
#
# The page is built in a clone of this repository at that commit, under `target/`, so nothing in the
# working tree moves and what is built is exactly what anybody checking out the commit would build.
# The build compares the page with the command line built beside it, so a page that disagrees with
# its own commit's command line never reaches the folder.
#
# A page built before pages named their commit is refused, because a host serving it could not say
# which command line it agrees with, and `the-served-verifier-page.mjs` could not hold it to one.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="${1:?page-for-a-host.sh needs a tag or a commit}"
out="${2:?page-for-a-host.sh needs the folder to write the page into}"

commit="$(git -C "$root" rev-parse --verify --quiet "$ref^{commit}")" || {
    echo "$ref is not a tag or a commit this clone has. Fetch first." >&2
    exit 1
}

scratch="$root/target/page-for-a-host/$commit"
rm -rf "$scratch"
mkdir -p "$(dirname "$scratch")"
git clone --quiet --shared --no-checkout "$root" "$scratch"
git -C "$scratch" checkout --quiet --detach "$commit"

echo "building the page at $ref ($commit)"
(cd "$scratch" && bash scripts/build-verifier-page.sh)

mkdir -p "$out"
python - "$scratch/verifier-page/verifier.html" "$out" "$ref" "$commit" <<'PYTHON'
import datetime
import hashlib
import json
import os
import sys

page, out, ref, commit = sys.argv[1:5]
data = open(page, "rb").read()
if ('<meta name="tw-built-from" content="%s">' % commit).encode("ascii") not in data:
    print("the page built at %s does not name %s, so no host can say which command line it agrees with"
          % (ref, commit), file=sys.stderr)
    sys.exit(1)
open(os.path.join(out, "verifier.html"), "wb").write(data)
record = {
    "ref": ref,
    "commit": commit,
    "page": "verifier.html",
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
    "built_on": datetime.date.today().isoformat(),
}
with open(os.path.join(out, "record.json"), "w", encoding="utf-8", newline="\n") as handle:
    handle.write(json.dumps(record, indent=2) + "\n")
print("wrote", os.path.join(out, "verifier.html"), len(data), "bytes, sha256", record["sha256"][:16])
PYTHON

rm -rf "$scratch"
