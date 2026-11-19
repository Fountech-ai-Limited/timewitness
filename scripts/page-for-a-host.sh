#!/usr/bin/env bash
# Build the verifier page at a tag or a commit, for a host to serve.
#
#     bash scripts/page-for-a-host.sh <tag or commit> <folder>
#
# Writes three files into the folder: `verifier.html`, the page as `build-verifier-page.sh` builds it
# at that commit; `third-party-notices.html`, the notices for the crates in its module as that commit
# has them; and `record.json`, naming the ref asked for, the commit it resolved to, and the size and
# sha256 of the other two. A host serves the first two and checks them against the third when it
# builds. The page names the address of the notices, so a host serving one serves both.
#
# The page is built in a clone of this repository at that commit, under `target/`, so nothing in the
# working tree moves and what is built is exactly what anybody checking out the commit would build.
# The build compares the page with the command line built beside it, so a page that disagrees with
# its own commit's command line never reaches the folder.
#
# A page built before pages named their commit is refused, because a host serving it could not say
# which command line it agrees with, and `the-served-verifier-page.mjs` could not hold it to one. A
# commit from before the notices were written is refused too, because a host would serve the
# module's BSD code without the notice its licence asks to go with it.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ref="${1:?page-for-a-host.sh needs a tag or a commit}"
out="${2:?page-for-a-host.sh needs the folder to write the page into}"

# A tag or a commit, and nothing that moves. A branch name, or HEAD, names a different commit tomorrow,
# and a record naming one would say where the page came from only on the day it was written.
if git -C "$root" rev-parse --verify --quiet "refs/tags/$ref" >/dev/null 2>&1; then
    kind="tag"
elif [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]]; then
    kind="commit"
else
    echo "$ref is neither a tag nor a commit. Name one of those, since a branch or HEAD moves." >&2
    exit 1
fi
commit="$(git -C "$root" rev-parse --verify --quiet "$ref^{commit}")" || {
    echo "$ref is not a $kind this clone has. Fetch first." >&2
    exit 1
}

scratch="$root/target/page-for-a-host/$commit"
rm -rf "$scratch"
mkdir -p "$(dirname "$scratch")"
# The clone goes whether the build passes or not, so a failed run leaves nothing to be mistaken for
# the page next time.
trap 'rm -rf "$scratch"' EXIT
git clone --quiet --shared --no-checkout "$root" "$scratch"
git -C "$scratch" checkout --quiet --detach "$commit"

echo "building the page at $ref ($commit)"
(cd "$scratch" && bash scripts/build-verifier-page.sh)

mkdir -p "$out"
python - "$scratch/verifier-page/verifier.html" "$scratch/verifier-page/third-party-notices.html" \
         "$out" "$ref" "$commit" <<'PYTHON'
import datetime
import hashlib
import json
import os
import sys

page, notices, out, ref, commit = sys.argv[1:6]
data = open(page, "rb").read()
if ('<meta name="tw-built-from" content="%s">' % commit).encode("ascii") not in data:
    print("the page built at %s does not name %s, so no host can say which command line it agrees with"
          % (ref, commit), file=sys.stderr)
    sys.exit(1)
if not os.path.isfile(notices):
    print("%s has no verifier-page/third-party-notices.html, so a host would serve its module without "
          "the notices its licences ask for. Bring a page from a later commit." % ref, file=sys.stderr)
    sys.exit(1)
told = open(notices, "rb").read()
open(os.path.join(out, "verifier.html"), "wb").write(data)
open(os.path.join(out, "third-party-notices.html"), "wb").write(told)
record = {
    "ref": ref,
    "commit": commit,
    "page": "verifier.html",
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
    "notices": "third-party-notices.html",
    "notices_bytes": len(told),
    "notices_sha256": hashlib.sha256(told).hexdigest(),
    "built_on": datetime.date.today().isoformat(),
}
with open(os.path.join(out, "record.json"), "w", encoding="utf-8", newline="\n") as handle:
    handle.write(json.dumps(record, indent=2) + "\n")
print("wrote", os.path.join(out, "verifier.html"), len(data), "bytes, sha256", record["sha256"][:16])
PYTHON

