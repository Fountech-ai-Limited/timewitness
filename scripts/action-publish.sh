#!/usr/bin/env bash
# What the Action does after the stamp, where the receipt is to have a page of its own.
#
#     scripts/action-publish.sh               run by action.yml, reading TW_* from the step
#     scripts/action-publish.sh --self-test   each case below run against a stand-in for curl
#
# It sends the receipt to the app as {"receipt": "<base64>"} and prints the address of the page that
# checks it, timewitness.dev/r/<the receipt's sha-256>, in the log and in the job summary. The
# receipt carries the hash of the file it stamps and never the file, so nothing of the file goes.
#
# **Nothing here can fail the job.** The receipt is written and checked before this runs, and it
# checks the same with the free verifier whether or not it has a page. So every way this can go
# wrong ends in a warning and exit 0: no curl, no answer, a refusal, or an answer naming a page that
# is not this receipt's.
#
# **Off for a private repository unless the workflow asks.** A page is public, and a receipt names
# the hash of what a private build made and when. With `publish: auto`, the default, a receipt is
# sent only where the event says the repository is public. Where the event does not say, it is not
# sent, and the log says how to turn it on.
#
# **The address printed is worked out here and only checked against the answer.** The app names the
# page by the sha-256 of the bytes it was sent, so this takes that hash itself and prints the page
# only where the answer names that one. Nothing the app sends back is echoed into the log or the
# summary, so an answer cannot write a workflow command or a line of markdown into either.

set -uo pipefail

publish_receipt() {
    local receipt="${TW_RECEIPT:-}" publish="${TW_PUBLISH:-auto}"
    local visibility="${TW_VISIBILITY:-}" private="${TW_PRIVATE:-}"
    local url="${TIMEWITNESS_RECEIPTS_URL:-https://app.timewitness.dev/api/public/receipts/}"
    local summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
    local work id expected status permalink size b64

    case "$publish" in
        false) return 0 ;;
        true) ;;
        auto)
            if [ "$visibility" = public ] || { [ -z "$visibility" ] && [ "$private" = false ]; }; then
                :
            else
                echo "timewitness: the receipt was not given a page, because this repository is not public or the event did not say. Set publish: true to give it one anyway."
                return 0
            fi
            ;;
        *)
            echo "::warning title=TimeWitness::publish is auto, true or false, so the receipt was not given a page. It is written and unaffected."
            return 0
            ;;
    esac

    if [ -z "$receipt" ] || [ ! -f "$receipt" ]; then
        echo "::warning title=TimeWitness::There was no receipt to give a page to. This job carries on."
        return 0
    fi
    if ! command -v curl >/dev/null 2>&1; then
        echo "::warning title=TimeWitness::This runner has no curl, so the receipt was not given a page. It is written and unaffected, and this job carries on."
        return 0
    fi

    size=$(wc -c < "$receipt" | tr -d ' ')
    if [ "$size" -gt 40960 ]; then
        echo "::warning title=TimeWitness::The receipt is larger than the app takes, so it was not given a page. It is written and unaffected."
        return 0
    fi

    id=$( { sha256sum "$receipt" 2>/dev/null || shasum -a 256 "$receipt" 2>/dev/null; } | cut -c1-64)
    if ! [[ "$id" =~ ^[0-9a-f]{64}$ ]]; then
        echo "::warning title=TimeWitness::This runner could not take the receipt's sha-256, so it was not given a page. It is written and unaffected."
        return 0
    fi
    expected="https://timewitness.dev/r/$id"

    work=$(mktemp -d) || {
        echo "::warning title=TimeWitness::No scratch folder for the request, so the receipt was not given a page."
        return 0
    }
    b64=$(base64 -w 0 < "$receipt" 2>/dev/null || base64 < "$receipt" | tr -d '\n')
    printf '{"receipt":"%s"}' "$b64" > "$work/body"

    status=$(curl -sS --max-time 30 -o "$work/answer" -w '%{http_code}' \
        -H 'content-type: application/json' --data-binary "@$work/body" "$url" 2>"$work/error")
    if [ $? -ne 0 ]; then
        echo "::warning title=TimeWitness::The app could not be reached, so the receipt was not given a page. It is written and unaffected, and this job carries on."
        rm -rf "$work"
        return 0
    fi

    case "$status" in
        200|201) ;;
        429)
            echo "::warning title=TimeWitness::The app is taking no more receipts from this network for now, so this one was not given a page. It is written and unaffected."
            rm -rf "$work"
            return 0
            ;;
        *)
            echo "::warning title=TimeWitness::The app answered $status, so the receipt was not given a page. It is written and unaffected, and this job carries on."
            rm -rf "$work"
            return 0
            ;;
    esac

    permalink=$(tr -d '\r\n' < "$work/answer" | sed -n 's/.*"permalink"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    rm -rf "$work"
    if [ "$permalink" != "$expected" ]; then
        echo "::warning title=TimeWitness::The app answered with a page that is not this receipt's, so no page is named here. The receipt is written and unaffected."
        return 0
    fi

    echo "timewitness: the receipt's page is $expected"
    echo "::notice title=TimeWitness::The receipt's page is $expected"
    {
        echo
        echo "### The receipt's page"
        echo
        echo "$expected"
        echo
        echo "Anybody with the address can open it. It runs the verifier timewitness.dev/verify serves"
        echo "on the receipt alone, in the reader's browser. The page is not evidence of anything; the"
        echo "receipt is, and it checks the same without the page."
    } >> "$summary"
    return 0
}

self_test() {
    local scratch fails=0 out summary receipt id
    scratch=$(mktemp -d) || { echo "self-test: no scratch folder" >&2; return 2; }
    receipt="$scratch/receipt.cbor"
    printf 'a receipt, for the test' > "$receipt"
    id=$( { sha256sum "$receipt" 2>/dev/null || shasum -a 256 "$receipt" 2>/dev/null; } | cut -c1-64)
    mkdir -p "$scratch/bin"

    # A stand-in for curl that writes FAKE_ANSWER to the -o file, prints FAKE_STATUS, keeps the
    # body it was sent, and exits FAKE_EXIT.
    cat > "$scratch/bin/curl" <<'EOF'
#!/usr/bin/env bash
out='' body=''
while [ $# -gt 0 ]; do
    case "${1}" in
        -o) out="${2}"; shift ;;
        --data-binary) body="${2#@}"; shift ;;
    esac
    shift
done
[ -n "$body" ] && cp "$body" "$FAKE_SEEN"
[ -n "$out" ] && printf '%s' "$FAKE_ANSWER" > "$out"
printf '%s' "$FAKE_STATUS"
exit "${FAKE_EXIT:-0}"
EOF
    chmod +x "$scratch/bin/curl"

    # One case: the environment, then what the log and the summary must and must not say.
    case_of() {
        local name="${1}" want_page="${2}" want_line="${3}"
        shift 3
        summary="$scratch/summary"
        : > "$summary"
        rm -f "$scratch/seen"
        out=$(env -u TW_PUBLISH -u TW_VISIBILITY -u TW_PRIVATE -u TIMEWITNESS_RECEIPTS_URL \
            PATH="$scratch/bin:$PATH" TW_RECEIPT="$receipt" GITHUB_STEP_SUMMARY="$summary" \
            FAKE_SEEN="$scratch/seen" "$@" bash "${0}")
        local code=$?
        local summary_text
        summary_text=$(cat "$summary")
        if [ "$code" -ne 0 ]; then
            echo "self-test: $name: exited $code, and nothing here may fail the job" >&2
            fails=$((fails + 1))
        fi
        if [ "$want_page" = yes ]; then
            case "$summary_text" in
                *"https://timewitness.dev/r/$id"*) ;;
                *) echo "self-test: $name: the summary does not name the page" >&2; fails=$((fails + 1)) ;;
            esac
        else
            case "$summary_text$out" in
                *"timewitness.dev/r/"*) echo "self-test: $name: a page was named where none should be" >&2; fails=$((fails + 1)) ;;
            esac
        fi
        case "$out" in
            *"$want_line"*) ;;
            *) echo "self-test: $name: the log does not say \"$want_line\": $out" >&2; fails=$((fails + 1)) ;;
        esac
    }

    local good="{\"id\":\"$id\",\"permalink\":\"https://timewitness.dev/r/$id\",\"receipt\":\"x\",\"published\":true}"
    local base64_of
    base64_of=$(base64 -w 0 < "$receipt" 2>/dev/null || base64 < "$receipt" | tr -d '\n')

    case_of "a public repository" yes "the receipt's page is https://timewitness.dev/r/$id" \
        TW_PUBLISH=auto TW_VISIBILITY=public FAKE_STATUS=201 FAKE_ANSWER="$good"
    if [ "$(cat "$scratch/seen" 2>/dev/null)" != "{\"receipt\":\"$base64_of\"}" ]; then
        echo "self-test: a public repository: the body sent is not the receipt alone" >&2
        fails=$((fails + 1))
    fi
    case_of "one published before" yes "the receipt's page is" \
        TW_PUBLISH=auto TW_VISIBILITY=public FAKE_STATUS=200 FAKE_ANSWER="$good"
    case_of "an event that says only that it is not private" yes "the receipt's page is" \
        TW_PUBLISH=auto TW_PRIVATE=false FAKE_STATUS=201 FAKE_ANSWER="$good"
    case_of "a private repository" no "not public" \
        TW_PUBLISH=auto TW_VISIBILITY=private TW_PRIVATE=true FAKE_STATUS=201 FAKE_ANSWER="$good"
    if [ -e "$scratch/seen" ]; then
        echo "self-test: a private repository: something was sent" >&2
        fails=$((fails + 1))
    fi
    case_of "an internal repository" no "not public" \
        TW_PUBLISH=auto TW_VISIBILITY=internal TW_PRIVATE=false FAKE_STATUS=201 FAKE_ANSWER="$good"
    case_of "an event that does not say" no "not public" \
        TW_PUBLISH=auto FAKE_STATUS=201 FAKE_ANSWER="$good"
    case_of "a private repository that asks" yes "the receipt's page is" \
        TW_PUBLISH=true TW_VISIBILITY=private FAKE_STATUS=201 FAKE_ANSWER="$good"
    case_of "a word that is not one of the three" no "auto, true or false" \
        TW_PUBLISH=yes TW_VISIBILITY=public FAKE_STATUS=201 FAKE_ANSWER="$good"
    case_of "too many from one network" no "taking no more receipts" \
        TW_PUBLISH=true FAKE_STATUS=429 FAKE_ANSWER='{"error":"slow down"}'
    case_of "a refusal" no "The app answered 422" \
        TW_PUBLISH=true FAKE_STATUS=422 FAKE_ANSWER='{"error":"no"}'
    case_of "no answer" no "could not be reached" \
        TW_PUBLISH=true FAKE_STATUS=000 FAKE_EXIT=28 FAKE_ANSWER=''
    case_of "a page that is not this receipt's" no "not this receipt's" \
        TW_PUBLISH=true FAKE_STATUS=201 \
        FAKE_ANSWER="{\"permalink\":\"https://timewitness.dev/r/$(printf '%064d' 0)\"}"
    case_of "an answer that tries to write a command" no "not this receipt's" \
        TW_PUBLISH=true FAKE_STATUS=201 \
        FAKE_ANSWER='{"permalink":"https://timewitness.dev/r/x\n::error::planted"}'
    case_of "no receipt" no "no receipt" \
        TW_PUBLISH=true TW_RECEIPT="$scratch/missing.cbor" FAKE_STATUS=201 FAKE_ANSWER="$good"

    rm -rf "$scratch"
    if [ "$fails" -ne 0 ]; then
        echo "self-test: $fails failed" >&2
        return 1
    fi
    echo "self-test: fourteen cases, each answered as it should be, and none failed the job"
    return 0
}

if [ "${1:-}" = --self-test ]; then
    self_test
    exit $?
fi
publish_receipt
exit 0
