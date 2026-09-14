# One of each role, about one subject, at one moment

Captured on 2026-09-07 within four seconds of each other by

```text
cargo test -p timewitness-sources --test evidence_capture -- --ignored --nocapture
```

Three files, three roles, all about the same subject, which is thirty-two bytes of `0x5a` standing in
for the hash of whatever is being stamped.

| File | Role | Signed by | The moment it states |
|---|---|---|---|
| `drand.hex` | not-earlier-than | drand quicknet, round 32000947 | 1788806205 |
| `roughtime.hex` | authenticated corridor | roughtime.se, radius one second | 1788806207 |
| `rfc3161.hex` | not-later-than | DigiCert | 1788806208 |

They are separate from the corpora under `crates/core/tests/data/`, which exist to test the checks
themselves and were each captured on their own. These three exist to test something the others
cannot: whether a receipt may say its bound rests on outside signatures. That question is only
answerable with three pieces of evidence taken together, about one subject, close enough in time to
enclose one reading. Three real signatures gathered on different days about different things are all
genuine and make no sandwich at all, which is the shape of the fraud the check exists to refuse.

The trust anchors these are checked against are the same ones any deployment holds: the published
long-term key of `roughtime.se`, the group key of the drand quicknet chain, and the SHA-256 of the
certificate DigiCert was signing with on that day.

`roughtime-nonce.hex` and `rfc3161-nonce.hex` are the nonces inside those two captures, kept beside
them because a receipt carrying one of these blobs has to print the same value, and a validator now
refuses one that prints anything else. They are written out rather than derived in the test, so a
fixture drifting away from its own capture fails instead of agreeing with itself.
