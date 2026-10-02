# Two receipts refused before their evidence is listed

Both are the receipt in `../a-real-stamp/` with one thing changed and signed again by a key of their
own, written as hex because the tree holds one binary file and holds it on purpose. Each carries the
real stamp's three attestations, and the verifier refuses each before it lists them.

`a-field-carrying-a-newline.hex` has its first source's kind changed to a string carrying newlines and
two field names, `"ntp\nearliest_ns=1\nwidth_ns=1"`. It is refused as a field this format cannot
read, because a report is written a line at a time and a receipt that could write its own lines into
one is refused rather than read. Its attestations are never looked at.

`a-sandwich-on-one-edge.hex` claims its bound rests on a sandwich of outside evidence. The
not-later-than attestation in it is DigiCert's, which states no accuracy, so it bounds nothing in UTC
and the sandwich has one edge. It is refused as the agent's own bound placed where third-party
evidence goes. Its attestations are checked on the way to that refusal, and the refusal says so, but
none of them is listed.

Neither verdict is in question here. What these hold is the sentence under the evidence heading.
Until 2026-10-01 the verifier page told both that they carried no third-party evidence at all, which
was false of both. A refusal before the evidence is listed now says that, on the page, and the
command line prints no evidence section for it. `crates/cli/tests/what_the_evidence_list_says_of_a_refusal.rs`
and `scripts/the-served-verifier-page.mjs` hold the two routes to it, beside
`../a-receipt-with-no-evidence/`, which keeps the sentence because it is true of that one.
