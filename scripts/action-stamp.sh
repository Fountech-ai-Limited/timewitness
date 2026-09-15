#!/usr/bin/env bash
# What the Action does, once the agent is built.
#
# Take a receipt over the subject, check it with the same verifier a consumer would use, write it
# into the provenance that already ships, and say in the workflow summary what the receipt does and
# does not establish.
#
# The self-check is not ceremony. A receipt this Action produced and never read is a receipt nobody
# has confirmed is readable, and the first person to find out would be the consumer. It runs the
# public verifier against the public trust material, which is what a stranger runs.
#
# Nothing here needs a tool the runner might not have. The verifier prints `name=value` lines for
# exactly this, so there is no JSON tool between a workflow and the numbers, and the only outside
# thing touched is `python3` for editing somebody else's provenance file, which is JSON we did not
# write and have no business editing with a text substitution.

set -euo pipefail

subject="${TW_SUBJECT:?the Action needs a subject to stamp}"
event="${TW_EVENT:-build}"
output="${TW_OUTPUT:-timewitness-receipt.cbor}"
key="${TW_KEY:-timewitness-agent.key}"
rounds="${TW_ROUNDS:-16}"
max_width="${TW_MAX_WIDTH:-30000000000}"
previous="${TW_PREVIOUS:-}"
sequence="${TW_SEQUENCE:-1}"
provenance="${TW_PROVENANCE:-}"
image="${TW_IMAGE:-}"
action_path="${TW_ACTION_PATH:-.}"

binary="$action_path/target/release/timewitness"
[ -x "$binary" ] || binary="$action_path/target/release/timewitness.exe"

if [ ! -f "$subject" ]; then
    echo "timewitness: there is no file at $subject to stamp" >&2
    exit 1
fi

stamp_args=(stamp --subject "$subject" --key "$key" --out "$output"
            --rounds "$rounds" --max-width "$max_width" --sequence "$sequence")
if [ -n "$previous" ]; then
    stamp_args+=(--previous "$previous")
fi

echo "stamping $event over $subject"
"$binary" "${stamp_args[@]}"

# The same check a consumer makes, with the same published trust material and no account.
report="$(mktemp)"
if ! "$binary" verify "$output" --subject "$subject" --fields > "$report"; then
    echo "timewitness: this Action produced a receipt its own verifier refuses, which is a fault here rather than in the receipt" >&2
    "$binary" verify "$output" --subject "$subject" --quiet >&2 || true
    exit 1
fi

# Every value is a whole number or a single word, so reading them as shell variables is safe.
earliest=$(sed -n 's/^earliest_ns=//p' "$report")
latest=$(sed -n 's/^latest_ns=//p' "$report")
width=$(sed -n 's/^width_ns=//p' "$report")
width_words=$(sed -n 's/^width_in_words=//p' "$report")
reading=$(sed -n 's/^reading_ns=//p' "$report")
digest=$(sed -n 's/^receipt_sha256=//p' "$report")
subject_digest=$(sed -n 's/^payload_hash=//p' "$report")
checked=$(sed -n 's/^attestations_checked=//p' "$report")
carried=$(sed -n 's/^attestations_carried=//p' "$report")

# The verifier's own first two lines, quoted rather than composed here: the verdict, and under it how
# wide the checked outside evidence brackets the moment and whose the width is. A summary writing its
# own version of either is how it would come to say something the verifier does not.
said="$("$binary" verify "$output" --subject "$subject" --quiet)"
said="$(printf '%s\n' "$said" | sed -n '1,2p')"

receipt_base64=$(base64 -w 0 < "$output" 2>/dev/null || base64 < "$output" | tr -d '\n')

# 1. The outputs, for the workflow to use.
{
    echo "receipt=$output"
    echo "earliest-ns=$earliest"
    echo "latest-ns=$latest"
    echo "width-ns=$width"
    echo "attestations=$checked"
} >> "${GITHUB_OUTPUT:-/dev/null}"

# 2. SLSA provenance, where one was named.
#
# The receipt goes into the predicate of the statement that already ships rather than into a new
# artefact type beside it. The ecosystem has a place built for metadata about how something was
# produced, and the whole point of this Action is to make the timestamp in that place checkable, not
# to add a competing format nobody consumes.
if [ -n "$provenance" ] && [ -f "$provenance" ]; then
    TW_P="$provenance" TW_R="$receipt_base64" TW_E="$event" \
    TW_EARLIEST="$earliest" TW_LATEST="$latest" TW_WIDTH="$width" TW_READING="$reading" \
    python3 "$action_path/scripts/action-provenance.py"
    echo "wrote the receipt into $provenance"
fi

# 3. Container image labels, where an image was named.
#
# Written out rather than applied. Applying a label means rebuilding or repushing an image, which
# belongs to whatever built it; this Action's job ends at handing over the arguments.
labels=""
if [ -n "$image" ]; then
    labels="--label org.opencontainers.image.created.bounded.earliest=$earliest"
    labels="$labels --label org.opencontainers.image.created.bounded.latest=$latest"
    labels="$labels --label ai.fountech.timewitness.receipt=$receipt_base64"
    echo "labels=$labels" >> "${GITHUB_OUTPUT:-/dev/null}"
fi

# 4. The summary, which is where the honesty has to be rather than in a document nobody opens.
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
{
    echo "## Bounded time on this $event"
    echo
    echo "UTC was somewhere in an interval **$width_words** wide."
    echo "That width is the claim. It is not an accuracy and there is no tighter number in here."
    echo
    echo "What the verifier says about it, word for word:"
    echo
    printf '%s\n' "$said" | sed 's/^/> /'
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| earliest UTC | \`$earliest\` ns |"
    echo "| latest UTC | \`$latest\` ns |"
    echo "| the reading, display only | \`$reading\` ns |"
    echo "| what it stamps | \`$subject_digest\` |"
    echo "| the receipt | \`$output\`, sha-256 \`$digest\` |"
    echo "| third-party attestations | $checked of $carried checked |"
    echo
    echo "### What this does not establish"
    echo
    echo "The width above is a reading from this runner on this run, at $rounds polling rounds. It is"
    echo "not a figure for any other machine. What sets it is which time sources this runner can"
    echo "reach, and that is something you can measure on your own network and we cannot."
    echo
    echo "A runner that reaches only the public Roughtime servers is seconds wide whatever else is"
    echo "done to it, because a Roughtime server states its own uncertainty as a radius in whole"
    echo "seconds and nothing narrows that. Ours, on GitHub-hosted runners, each a reading from the"
    echo "day it names: 211.3 ms on 2026-09-09 at sixteen rounds with Roughtime and plain NTP servers"
    echo "answering, and 16.219 s on 2026-09-08 at the four rounds this Action shipped that day,"
    echo "against Roughtime alone. Those two are not a series and are not a trend: the rounds differ."
    echo
    echo "The figures usually quoted for ordinary machines, 5 to 50 ms on the public internet with no"
    echo "special hardware and about 1 ms on a good local network against a stratum-1 source, are"
    echo "quoted from public research. Neither has been measured by us and neither is ours."
    echo
    echo "This receipt does not prevent anything. It records that a stamp was taken; there is no"
    echo "enforcement path in this design. It establishes no legal weight: standing in this area comes"
    echo "from accreditation and not from engineering."
    echo
    echo "The agent key that signed it proves that one agent held that key and nothing about who that"
    echo "was. There is no public log of agent keys to check it against yet."
    echo
    echo "### Checking it"
    echo
    echo "\`\`\`"
    echo "timewitness verify $output --subject $subject"
    echo "\`\`\`"
    echo
    echo "That needs nothing of ours, no account and no network. The full list of what TimeWitness"
    echo "cannot prove is \`timewitness cannot-prove\`, and it ships with the claim rather than under it."
} >> "$summary"

rm -f "$report"
echo "timewitness: $event stamped, interval $width ns wide, $checked of $carried attestations checked"
