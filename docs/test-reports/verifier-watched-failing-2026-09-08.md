# The verifier, watched failing first

2026-09-08. Supersedes nothing. The same discipline was applied the day before to the fixes for a
hostile source and for a change of rate.

Two properties are the whole of the free public verifier, and neither is worth anything unless
somebody has seen the code without them. A test that has only ever passed is a test nobody has
measured.

## 1. A receipt altered by one byte is refused

`crates/verify/tests/one_byte.rs`. The watching is permanent and it is in the file rather than in this
document: `parse_only` is the verifier this product would be if it checked that a receipt is well
formed and stopped. It decodes the COSE envelope, checks it is four parts, decodes the payload and
reads every field into the typed `Receipt`, which is more than a careless implementation would do.
Every case asserts that the stub accepts the altered receipt before asserting that the real verifier
refuses it, so a case that stops being sharp fails rather than passing quietly.

The receipt under test is the one at `crates/verify/tests/common/mod.rs`: 100 ms wide, three sources,
carrying three attestations captured from three unrelated parties four seconds apart, correctly
signed. It is accepted untouched, which is asserted first so that nothing below passes for the wrong
reason.

| What moved | How it was located | Stub | Verifier |
|---|---|---|---|
| the reading | re-encode with `utc_estimate + 1` and take the one byte that moved | accepted | refused |
| the earliest edge | the encoding of that value, unambiguous | accepted | refused |
| the latest edge | the same | accepted | refused |
| the sequence number | re-encode with `sequence = 0` | accepted | refused |
| the payload hash | re-encode with byte 16 flipped | accepted | refused |
| the corridor attestation | a byte a third of the way into the blob | accepted | refused |
| the freshness beacon value | the same | accepted | refused |
| the final witness token | the same | accepted | refused |
| the agent's public key | the copy inside the signed payload | accepted | refused |
| the signature | byte 30 of the 64 | accepted | refused |
| the algorithm in the protected header | the last byte of the header | refused | refused |

The last row is the one the stub also refuses, and it is asserted the other way round for that
reason. It is here because the protected header is inside what is signed, which is the point of the
COSE `Signature1` structure: without it a signature could be moved onto a receipt naming a weaker
algorithm, and that attack is older than this format.

Two of the eleven had to change how they find their byte. The reading and the corridor's own instant
are the same nanosecond, and the hash of what is being stamped appears again inside the timestamp
token taken over it, so searching for the value found two places. `byte_that_carries` re-encodes the
receipt with one field different and takes the single byte that moved, which is exact. The ambiguity
guard that caught this is still in `byte_of` and still fires.

**Then every bit.** `every_single_bit_of_the_signed_payload_is_refused` flips each of the 7,088 bits
of the signed payload one at a time. None is accepted. It runs against a receipt resting on its own
model, read by a reader holding nothing, so that seven thousand third-party signature checks are not
repeated to establish something the signature over the whole payload already settles; the anchored
path is what the eleven named cases exercise.

**What this does not cover, and it is a test rather than a footnote.**
`what_this_battery_does_not_cover_is_stated_rather_than_assumed`. The COSE unprotected header sits
outside the signature by design, so a byte changed there does not break it. Today such a receipt is
still refused, and only because `cose::open` compares the key identifier outside the signature against
the key inside it. That comparison is the whole of what stands between here and a holder restating a
receipt as different bytes carrying the same claim. The test asserts the refusal and then asserts
that the two spellings hash differently, which is what a chain link is taken over.

**Timing.** The battery took 452 seconds in a debug build, because unoptimised Ed25519 verification
runs at about sixty milliseconds a signature and there are seven thousand of them. A test that slow
gets weakened by whoever is waiting for it, so dependencies are now built optimised in the dev profile
and nothing of ours is: `[profile.dev.package."*"] opt-level = 3`. The same battery takes 8.5 seconds.

## 2. A receipt that keeps every promise it makes is still refused where the numbers do not hold

`crates/verify/tests/the_floor.rs`. Every case is correctly signed, internally consistent, and passes
every check the receipt crate makes, because the receipt crate checks a receipt against the policy the
receipt states for itself and each of these states a policy it keeps to.

The watching here is the floor lifted rather than a stub: `lifted()` is a `Floor` that refuses
nothing, and every case asserts it is accepted under that before asserting it is refused under the
shipped one, and that the refusal comes from the floor rather than from something else the validator
already catches.

| The receipt | Floor lifted | Floor in place |
|---|---|---|
| a bound zero nanoseconds wide, every breakdown part zero | accepted | refused |
| two nanoseconds wide | accepted | refused |
| a hundred nanoseconds wide | accepted | refused |
| one source, stating `min_sources: 1` and keeping to it | accepted | refused |
| wider than an hour | accepted | refused |
| padded to 128 KiB past the end | accepted | refused at the first question |
| two hundred microseconds, the product's own tightest condition | accepted | **accepted** |

The last row is the one that says the floor is set in the right place. A hundred microseconds of
accuracy on a cloud instance with a hypervisor clock is the tightest figure in the product's own
documents, and a whole interval around it is two hundred. A floor that refused that would look
identical to catching a lie, and the refusal would be ours.

`a_reader_who_wants_a_tighter_floor_sets_one` is the same lever the other way, because the floor is
the reader's and is printed beside the verdict rather than compiled into what a receipt means.

## 3. The page and the command line are one implementation

`node scripts/check-verifier-page.mjs`, run in CI. It pulls the WebAssembly module out of the built
page rather than out of the source tree, so what is checked is the file somebody would download, and
puts one receipt through it and through `timewitness verify --json`. The verdict, the interval, the
reading, the receipt digest, every step's state and every evidence entry have to match. It also
requires the page to refuse a receipt with one byte changed and to carry the whole limitation list.

Run on 2026-09-08 against `crates/verify/tests/data/a-real-stamp/receipt.cbor`:

```
the page and the command line agree on this receipt: held, 16.424 s wide,
3 of 3 attestations checked, 30 limitations printed
```

## 4. End to end, from a machine that is not this one

`Fountech-ai-Limited/timewitness-consumer-proof`, workflow run 34194401773, 2026-09-08. A repository
holding nothing of ours but one line of YAML built an archive, installed the Action, and published
the archive with its receipt. Downloaded here and checked with the release binary:

- accepted, three of three attestations verified offline against published keys, 16.219 s wide;
- the corridor's nonce recomputed from the hash of the artefact, so the response is about that
  archive and not something else;
- the drand round's signature checked by pairing against the group key;
- DigiCert's token checked against a pinned certificate, its imprint being the SHA-256 of the
  artefact;
- one byte changed in the middle of the receipt: refused, naming the signature;
- `--no-anchors`: accepted, with all three attestations reported as unchecked, which is what that
  reader actually knows.
