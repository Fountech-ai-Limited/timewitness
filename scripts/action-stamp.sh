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
deadline="${TW_DEADLINE:-300}"
max_width="${TW_MAX_WIDTH:-2000000000}"
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
            --rounds "$rounds" --deadline "$deadline" --max-width "$max_width"
            --sequence "$sequence")
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

# Every value is a whole number or a single word, so reading them as shell variables is safe. Two
# things are not, and both have bitten.
#
# An empty one: `sed` exits 0 when it matches nothing, so a field the verifier has renamed leaves
# the variable empty, the step goes green, and the workflow gets `earliest-ns=` with nothing after
# it and a summary reading "UTC was somewhere in an interval **** wide". Every read below is
# asserted non-empty before anything is published, which is the check that was missing until
# 2026-09-19.
#
# And more than one: `sed -n 's/^name=//p'` prints every line that matches, so two lines named
# `earliest_ns` put two values in one variable and the non-empty assertion passes, because the
# variable is not empty, it is two values. On 2026-09-19 a receipt whose first source carried a
# newline in its `kind` put a second `earliest_ns` and a second `width_ns` into that report and so
# into this file's outputs. The verifier refuses such a receipt now, and this reads one line per
# field anyway, because this script is the worked example a consumer copies and the report it reads
# will not always be one this Action produced.
# It returns rather than ending the run, and every caller ends the run itself. A command
# substitution is a subshell, so an exit here would end the subshell and hand the caller an empty
# string, which is the shape the non-empty assertion below was written for in the first place.
field() {
    local name="$1" found count
    found=$(sed -n "s/^$name=//p" "$report")
    count=$(printf '%s' "$found" | grep -c '' || true)
    if [ "$count" -gt 1 ]; then
        echo "timewitness: the verifier's report carries $count lines named $name and a field has one. The report it read is below" >&2
        cat "$report" >&2
        return 1
    fi
    printf '%s' "$found"
}

earliest=$(field earliest_ns) || exit 1
latest=$(field latest_ns) || exit 1
width=$(field width_ns) || exit 1
width_words=$(field width_in_words) || exit 1
reading=$(field reading_ns) || exit 1
digest=$(field receipt_sha256) || exit 1
subject_digest=$(field payload_hash) || exit 1
checked=$(field attestations_checked) || exit 1
carried=$(field attestations_carried) || exit 1

missing=''
for pair in "earliest_ns=$earliest" "latest_ns=$latest" "width_ns=$width" \
            "width_in_words=$width_words" "reading_ns=$reading" "receipt_sha256=$digest" \
            "payload_hash=$subject_digest" "attestations_checked=$checked" \
            "attestations_carried=$carried"; do
    [ -n "${pair#*=}" ] || missing="$missing ${pair%%=*}"
done
if [ -n "$missing" ]; then
    echo "timewitness: the verifier's report carries nothing for$missing, so this step will not publish an output a workflow gates on with nothing in it" >&2
    echo "timewitness: the report it read is below" >&2
    cat "$report" >&2
    exit 1
fi

# The verifier's own first two lines, quoted rather than composed here: the verdict, and under it how
# wide the checked outside evidence brackets the moment and whose the width is. A summary writing its
# own version of either is how it would come to say something the verifier does not.
said="$("$binary" verify "$output" --subject "$subject" --quiet)"
said="$(printf '%s\n' "$said" | sed -n '1,2p')"
if [ -z "$said" ]; then
    echo "timewitness: the verifier printed nothing, so the summary would quote it saying nothing." >&2
    exit 1
fi

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
# A provenance file that was named and is not there is a workflow asking for something this step
# then did not do. It skipped the whole write with no note and exited 0 until 2026-09-19: the
# success path printed a line and the failure path printed nothing at all, so the only way to tell
# them apart was to know which line to look for.
if [ -n "$provenance" ]; then
    if [ ! -f "$provenance" ]; then
        echo "timewitness: provenance was named as $provenance and there is no file there, so the receipt was not written into anything" >&2
        exit 1
    fi
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
    echo "A runner that reaches only the three public Roughtime servers gets no receipt: that is three"
    echo "operators, under the floor of four the agent signs on, so this step fails there rather than"
    echo "signing. Ours, on GitHub-hosted runners at sixteen rounds, each a reading from the day it"
    echo "names: a bound of 211.3 ms on 2026-09-09 with Roughtime and plain NTP servers answering, and a bound of 287.147 ms"
    echo "on 2026-09-14 from the public install check. Those two are not a series and are not a trend."
    echo "This step refuses a width over $max_width ns."
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
    echo "was. A log of our keys is served at timewitness.dev/key-log.txt and names the keys of our two"
    echo "Roughtime servers and no agent key, so there is nothing yet to check this key against."
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
