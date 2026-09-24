"""Put a receipt into the provenance a build already ships.

The receipt goes into the predicate of the in-toto statement that is already being produced, rather
than into a new artefact type beside it. The ecosystem has a place built for metadata about how
something was produced, and this product's whole argument is that the timestamp already sitting in
that place is not checkable by anybody. Adding a competing format nobody consumes would fix nothing.

Everything comes in through the environment rather than the command line, so a base64 receipt of nine
kilobytes never has to survive a shell.

Read as JSON and written back as JSON, rather than edited as text, because this is somebody else's
file and a text substitution into it is a guess about its shape.

The format is the one the receipt is written in, as the verifier read it off the receipt's own bytes
a moment earlier, and never a constant here. Until 2026-09-24 this file wrote
`timewitness-receipt-v0` around every receipt, while every receipt the `v0.2` release writes is
version 1. A consumer choosing a reader by this field would have chosen a version 0 reader, and the
`v0.1` verifier refuses a version 1 receipt by name.
"""

import json
import os
import sys

path = os.environ["TW_P"]

# A whole number and nothing else, or the label would be a guess written where a fact belongs.
version = os.environ.get("TW_FORMAT", "")
if not version.isascii() or not version.isdigit():
    sys.exit("timewitness: the verifier gave no format version for this receipt, so the provenance "
             "was not written: [%s]" % version)

with open(path, encoding="utf-8") as handle:
    statement = json.load(handle)

statement.setdefault("predicate", {})["boundedTime"] = {
    "format": "timewitness-receipt-v%d" % int(version),
    "event": os.environ["TW_E"],
    "earliestNs": int(os.environ["TW_EARLIEST"]),
    "latestNs": int(os.environ["TW_LATEST"]),
    "widthNs": int(os.environ["TW_WIDTH"]),
    "readingNs": int(os.environ["TW_READING"]),
    "readingIsDisplayOnly": True,
    # Beside the numbers rather than in a document somewhere, because a consumer who reads one field
    # of this object should read a true sentence rather than a tight-looking number.
    "claim": (
        "UTC was somewhere in [earliestNs, latestNs] when this event happened. That interval is the "
        "claim. readingNs is a point inside it, at nanosecond resolution because it is a local "
        "counter read, and it is not an accuracy. Check the receipt rather than these fields: "
        "timewitness verify"
    ),
    "receiptBase64": os.environ["TW_R"],
}

with open(path, "w", encoding="utf-8") as handle:
    json.dump(statement, handle, indent=2)
    handle.write("\n")
