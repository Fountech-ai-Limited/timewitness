# Receipt format v0

Frozen 2026-09-07. Canonical version; the product folder carries a copy of the field tables and
names this file as the one that binds.

A receipt is a long-lived artefact. Once one is issued it has to keep meaning what it meant, years
later, to somebody who never spoke to us. So the format is frozen and it carries its own version
number, and a reader that meets a version it does not know refuses rather than guessing at what the
fields mean.

## What a receipt says, and what it does not

A receipt says three things and it keeps them apart.

**The reading.** A local counter read, at nanosecond resolution, and the model's estimate of where
that moment sits on UTC. The estimate is a display value. It is flagged as one in the format itself,
because several independent reviews of this design landed on the midpoint as the field most likely
to be read as the answer.

**The claim.** The agent's own interval: the earliest and the latest UTC the reading could
correspond to, and every part of how that width was arrived at. It is the most precise number in the
receipt and it is the only one that rests on trusting us.

**The evidence.** Third-party attestations, each labelled with what it proves, each carrying the
signed response in full so a stranger checks the signature rather than taking our word for it.

The claim and the evidence are different shapes on purpose. Presenting the first as the second is
the central dishonesty available to a product in this field, and this format is built so that it
cannot be done by accident and is caught when it is done deliberately.

## Encoding

Deterministic CBOR, per RFC 8949 core deterministic encoding, signed with COSE_Sign1 per RFC 9052.
A JSON rendering exists for a person to read and is never parsed, never hashed and never signed.

The deterministic rules, and this implementation is stricter than the specification in one place:

- definite lengths only, never indefinite;
- the shortest form of every integer argument;
- map keys sorted by their own encoded bytes, and never repeated;
- **no floating point at all**, which is the stricter part. Every quantity in a receipt is a whole
  number of nanoseconds or a count, and a float would introduce a value that does not round-trip.

The decoder refuses anything not encoded that way. It also re-encodes what it decoded and compares
the bytes, so a spelling the decoder has not been taught about still cannot get through. That matters
because the bytes are what gets hashed, signed and compared: a format with two valid spellings of one
receipt gives an attacker a second receipt that means the same thing and hashes differently.

## The signature

COSE_Sign1: a four element array of the protected header as a byte string, the unprotected header as
a map, the payload as a byte string, and the signature.

- Protected header: `{1: -8}`, Ed25519, which COSE calls EdDSA.
- Unprotected header: `{4: <the agent's public key>}`, that entry and no other.
- Payload: the deterministic CBOR of the receipt body below.
- What is signed: the `Sig_structure` of RFC 9052, being `["Signature1", protected, h'', payload]`,
  encoded deterministically. Signing the payload alone would let a signature be moved onto a receipt
  with a different algorithm in its header.

The agent's public key travels inside the signed body as well as in the header, and the two must
agree. A receipt therefore proves that whoever held that key signed it. Whether that key is one of
ours is a separate question, answered by a public key log, which is a later piece of work.

The signature is checked strictly, in the sense RFC 8032 discusses: a public key or a signature
commitment with a small order component is refused. No honest agent produces one, and they are the
case in which one signed message has more than one valid signature.

### A receipt is one byte string

The unprotected header is outside the signature. That is RFC 9052 working as designed and it has a
consequence the format has to answer rather than inherit: a holder could otherwise restate a receipt
as different bytes carrying the same claim and verifying identically. Drop the key identifier,
relabel it, or pad a label nobody reads with a megabyte, and each gives a second spelling of one
receipt. The chain link is the hash of the spelling, so a holder could break, fork or bloat a chain
without ever holding the agent's key, and unbroken order is half of what this product claims.

So a reader refuses an unprotected header that is anything other than the single key identifier
entry, whose value has to be the key inside the signature. Everything else in the envelope is either
covered by the signature or is canonical CBOR the decoder re-encodes and compares against what it
read, so with that entry pinned an accepted receipt has exactly one valid spelling.

**The chain link is the SHA-256 of the whole signed receipt, those bytes exactly.** The alternative
was to hash the `Sig_structure`, which the signature genuinely covers rather than by a rule that has
to be applied. It was not chosen because the link would then be a quantity that is not the file: two
people holding the same receipt could not compare what `sha256sum` prints, and the padding and the
relabelling would still be accepted while producing an identical link, which is a worse answer than
the one being replaced. Pinning the header refuses those instead, so the two properties are settled
by one rule.

**A signed receipt is no larger than 64 KiB**, checked before anything is decoded. A receipt carrying
three real attestations is a little over three kilobytes. Nothing legitimate approaches the ceiling,
and a reader must not have to parse a megabyte to find out that it is a megabyte.

## The body

| Field | Type | Meaning |
|---|---|---|
| `v` | int | The format version. `0`. |
| `seq` | uint | Where this receipt sits in a chain. |
| `prev` | bstr, optional | The SHA-256 of the previous signed receipt in the chain. 32 bytes. |
| `payload` | map | What is being stamped. |
| `payload.alg` | text | `sha-256`, `sha-384` or `sha-512`. |
| `payload.hash` | bstr | The hash, whose length must match the algorithm. |
| `reading` | map | The local read. |
| `reading.mono_ns` | uint | The raw monotonic counter value, in nanoseconds. |
| `reading.utc_ns` | int | The estimate of UTC, in nanoseconds from the Unix epoch. |
| `reading.midpoint_display_only` | bool | Always true. The claim is the interval. |
| `claim` | map | The agent's own bound. See below. |
| `evidence` | array | Third-party attestations. See below. |
| `agent.public_key` | bstr | The Ed25519 public key that signed this, 32 bytes. |

### `claim`, the agent's own bound

| Field | Type | Meaning |
|---|---|---|
| `kind` | text | Always `agent-bound`. The discriminant. |
| `earliest_ns` | int | The earliest UTC the reading could correspond to. |
| `latest_ns` | int | The latest. |
| `basis` | text | `local-model-only` or `third-party-sandwich`. |
| `fusion` | text | How the sources were combined. `marzullo-then-inverse-square`. The selection is Marzullo's with two rules of ours on top. The first refuses a majority that exists only because of sources that could not have disagreed with anybody; it turns some answers into refusals and never changes a receipt that was signed. The second, from 2026-09-11, keeps those sources out of the decision about which other source is in the minority, so a server that agrees with every answer on offer cannot keep a liar in the round; it can narrow an interval only by throwing a source out. The rule is stated in full in `crates/clock/src/marzullo.rs`. |
| `sources_offered` | uint | How many sources answered, which is the length of the `sources` array beside it and includes any source that answered and was not a candidate for the intersection. A source that reported its own clock unsynchronised is one of those: it is in the array with `kept` false, and it is not in the count the majority is taken over. That count is not a field. A reader takes it from the array, the same way they take the count of operators, because a stated count is the agent's arithmetic and a reader would be checking it against itself. The agent wrote the number of candidates here until 2026-09-10, which made a receipt from such a round disagree with its own source list. |
| `sources_kept` | uint | How many survived selection. |
| `breakdown` | map | Where the width came from, part by part. |
| `since_last_sync_ns` | int | The age of the newest exchange the interval rests on. Measured from the exchange and not from the selection round that used it. |
| `frequency_ppb` | int | The measured frequency error, in parts per billion, and zero where none was measured. |
| `boot_generation` | uint | Which boot of the machine. |
| `resume_generation` | uint | Which resume within that boot. |
| `sources` | array | One entry per source: `id`, `operator`, `kind`, `timescale`, `smear`, `leap`, `kept`, and `first_party` where it is true. `operator` is who runs the source, and it is null where the agent could not say and absent altogether on a receipt written before 2026-09-09. `first_party` says the party running that source is the party that issued this receipt, and it is written only when true, so a deployment that runs no servers of its own encodes exactly the bytes it encoded before the field existed. A first-party source disciplines the clock and is selected like any other; what it is not is an independent chance to be wrong, so a reader counting operators leaves it out of the count and says how many it left out. There is deliberately no count of operators beside `sources_kept`: a count is our arithmetic and a reader would be checking it against itself, where the labels let them count for themselves. |
| `policy` | map | `max_bound_width_ns`, `min_sources`, `min_operators` and `max_holdover_ns`, being what this agent would sign for. `min_operators` is the floor on distinct operators among the sources that survived selection, which is the floor that means anything: several addresses at one company clear a floor on sources without adding a chance to disagree. `max_holdover_ns` is absent on a receipt written before 2026-09-08 and `min_operators` on one written before 2026-09-09; both are left out of the map rather than written as nought, because absent and nought are different facts. |

`frequency_ppb` is zero in two cases and a reader cannot tell them apart, which is deliberate. The
agent had not yet fitted a rate, or it fitted one its own baseline could not support and refused to
report it. A fit taken over two seconds against sources whose midpoints move by seconds produces a
slope in the thousands of parts per million, which is the sources' jitter divided by a short
baseline rather than a fact about the oscillator, and a figure is quoted with the
conditions it was measured under or it is not quoted at all. Zero here therefore reads as "no rate
is claimed" and never as "the clock is perfect". Nothing is concealed by it: whatever the fit
allowed is already inside the width, and the reader is looking at that width. A reader who wants to
know how good the rate estimate was reads `breakdown.oscillator_holdover_ns` against
`since_last_sync_ns`, which is where it shows.

`breakdown` carries `intersection_half_ns`, `network_half_ns`, `scheduling_ns`,
`oscillator_holdover_ns`, `model_residual_ns` and `safety_margin_ns`. All but the network figure add
to half the width. The network figure is reported so a reader can see how much of the width is the
path, and it is deliberately not in the sum, because it already sits inside the intersection term
and counting it twice would make the bound look more careful than it is.

`claim` has no `role` and no `blob`. That is what stops it being read as evidence, and the validator
refuses a receipt where either has been added.

### `evidence`, third-party attestations

| Field | Type | Meaning |
|---|---|---|
| `role` | text | What this proves. One of the three below. |
| `scheme` | text | What it actually is. |
| `at_ns` | int | The instant it pins. |
| `radius_ns` | int, optional | Half the width of the interval it asserts. Required on a corridor entry. |
| `blob` | bstr | The signed response in full, in the container that scheme stores. See below. |
| `nonce` | bstr, optional | The nonce we generated, where the scheme signs over one. |
| `detail` | text, optional | Which server or round, for a person reading the receipt. |

An evidence entry has no `kind`, no `earliest_ns`, no `latest_ns` and no `breakdown`. A receipt where
one has been added is refused.

### What a `blob` holds, per scheme

A blob is the scheme's own bytes, plus whatever else a stranger needs to check them without asking
anybody. That second part is easy to leave out and it is what makes the difference between a receipt
that looks portable and one that is.

**`roughtime`.** Eight bytes `TWRTEVD0`, then three little-endian lengths, then the nonce binding,
the request packet and the reply packet. The request has to be there: a Roughtime server does not
sign the nonce, it signs the root of a tree whose leaf is the hash of the whole request packet, so a
reader holding only the reply cannot get from the nonce to the root. The binding is
`subject_hash || salt` where the nonce was derived from what is being stamped, and empty where the
nonce was random; the nonce is the first thirty-two bytes of the SHA-512 of
`"TimeWitness Roughtime nonce v0\x00"` followed by the binding. That context string
is thirty-one bytes: the thirty printable ones, then a single zero byte. The `\x00` is an
escape for that byte and not four characters, and a reader who drops it derives a different
nonce, so every corridor check they write fails against every receipt we issue.

**`drand`.** Eight bytes `TWDREVD0`, the round number as a little-endian sixty-four bit number, the
chain hash, then the length of the signature and the signature. The message the signature covers is
the round number alone, so there is nothing else to keep, and the randomness a relay prints beside it
is the SHA-256 of the signature and is recomputed rather than stored.

**`rfc3161`.** Eight bytes `TWTSEVD0`, two little-endian lengths, then the request and the reply, both
whole. The request carries the nonce and the hash that was asked about, and a reader holding only the
reply is taking our word for what was asked.

### Which schemes can support which role

This table is the whole format in one place.

| Role | What it proves | Schemes that can support it |
|---|---|---|
| `authenticated-utc-corridor` | The interval itself, with outside support | `roughtime` |
| `not-earlier-than` | The receipt cannot have been made before a public moment | `drand`, `nist-beacon`, `uchile-beacon` |
| `not-later-than` | The receipt cannot have been made after a public moment | `rfc3161`, `rfc9921`, `transparency-log`, `opentimestamps` |

Anything else proves nothing here. An unknown scheme is refused rather than assumed honest, because
a format that trusts a name it has never seen is a format an attacker chooses the name in.

**Network time security is refused as evidence, by name.** So are plain NTP, the agent's own bound,
and anything else of ours. NTS improves the clock and can never be portable evidence: it
authenticates packets with a symmetric key the client also holds, so a client could forge a response
to itself and a stranger has no signature to check. Only Roughtime, RFC 3161 and public anchors carry
a signature a third party can verify.

## What the validator refuses

Everything below is checked on every receipt that is read, after the signature and before the
contents are believed.

**A file that is not one receipt.** More than 64 KiB, before anything is decoded. An unprotected
header holding anything other than the single key identifier entry, or one naming a key that is not
the key inside the signature.

**Mislabelling.** An evidence entry whose scheme cannot support the role it claims. An entry naming a
scheme this format does not know.

**Our own claim as evidence.** An entry whose scheme is ours rather than a third party's. An entry
carrying the agent claim's discriminant or its fields. A claim carrying a role or a signed blob.

**A sandwich that is not one.** A receipt whose basis says `third-party-sandwich` while it does not
carry all three of a corridor, a not-earlier-than and a not-later-than. Without all three the basis
is the local model and the receipt has to say so.

**A sandwich whose signatures nobody checked.** This is the check the whole format turns on, and it
changed on 2026-09-07 when the evidence clients arrived. Until then no reader of this format could
verify a signed response of any kind, so the basis was refused outright: three entries carrying the
right words were being read as proof of cryptography, and a basis nothing can test is not granted.

It is now a precondition with four parts, and all four have to hold before a receipt may say its
bound rests on outside signatures.

1. One entry in each of the three roles.
2. Every one of those three verified, by the reader, against a key it chose in advance. An entry
   nobody checked supports nothing, however honest it is. A reader holding no keys grants no
   sandwich, and says so.
3. The sandwich the right way round, so the not-later-than attestation is not dated before the
   not-earlier-than value.
4. The two outside signatures no more than an hour apart. An agent fetches both around the moment it
   stamps, so a real sandwich is seconds wide. A genuine beacon from the morning and a genuine token
   from the evening are both real and both signed, and between them they say nothing about a stamp
   taken at noon that a calendar would not.

An entry that has a matching key and fails against it refuses the whole receipt, rather than
downgrading it. A receipt carrying a signature that does not check out is not a receipt with a
weaker claim; it is a receipt that is wrong.

**Numbers printed beside a signature that the signature does not support.** Each entry states an
instant, and a corridor also states a radius. Those are what a person reads and what the interval
arithmetic uses, so each is compared against what the signed response actually says. A genuine
response with a moved number beside it is refused.

**A corridor bound to somebody else's subject.** Where a Roughtime nonce was derived from a subject,
that subject has to be what this receipt is stamping. Otherwise the response is a real signature
about a different document.

**A receipt that contradicts itself.** The reading outside its own interval. The ends of the interval
the wrong way round. Stated parts that do not add to the claimed width. A source count that does not
match the list. Fewer sources kept than a majority, with no exemption for a receipt that offered no
sources at all. Stated parts that add to more than the claimed width, which is a receipt claiming
precision its own arithmetic does not support. A payload hash of the wrong length for its
algorithm. A chain link that is not 32 bytes. A negative part of a width.

**A receipt that breaks its own stated policy.** Every receipt carries the widest interval its agent
said it would sign for, the fewest sources it said it would answer on, and the longest it said it
would extrapolate from an exchange. A receipt wider than its own ceiling, resting on fewer sources
than its own floor, or older than its own holdover ceiling, is refused on its own numbers. A stated
ceiling of zero is refused outright, for either ceiling: read as written it says the agent would sign
no interval at all, and it is also what the field holds when nobody filled it in. A holdover ceiling
that is absent rather than nought is not checked and the verifier says so, because a limit nobody
stated is not a limit that was broken.

**Evidence that cannot be about this reading.** A not-earlier-than value whose earliest instant is
after the latest time the receipt claims. A not-later-than attestation whose latest instant is before
the earliest. A corridor whose own interval and the receipt's interval have no instant in common. An
entry stating a negative radius.

**A corridor entry with no nonce.** Without a nonce we generated, a signed response could have been
made for somebody else at some other time and replayed in.

**A corridor entry with no radius.** A Roughtime response is a midpoint and a radius. An entry
carrying only the midpoint cannot say what interval it proves, so nothing can check it against the
interval it is offered as support for, and the check that ought to catch a corridor from last year
has nothing to compare.

## The floor a reader brings

Everything above is the receipt being checked against itself. That is not enough on its own, and the
reason is short: a receipt claiming an interval zero nanoseconds wide, resting on one source, and
stating a ceiling of zero keeps every promise it makes. It is internally consistent and it is a claim
nothing in this field can support. A reader who only checks a document against the document's own
opinion of itself will accept it.

So the format states a floor, and it states it here rather than leaving each implementation to pick
its own. Two verifiers reading the same receipt have to reach the same verdict, and they will not if
the numbers live in one implementation's source.

| Threshold | Value | Why this number |
|---|---|---|
| Narrowest whole interval | 1 us | The tightest condition this product quotes anywhere is about a hundred microseconds to UTC on a cloud instance with a hypervisor clock, and certified microseconds need hardware. A microsecond is two orders of magnitude below that, which keeps it a backstop rather than an answer. |
| Widest whole interval | 1 hour | Past an hour an interval says nothing about when something happened that a calendar would not. It is also the ceiling on how far apart the two outside signatures of a sandwich may sit. |
| Fewest sources answering | 3 | With three, a majority beats one bad clock, which is the whole reason the selection rule exists. Two is two clocks agreeing. One is a clock. |
| Fewest operators behind the sources kept | 3 | The row above counts names and names are free: one company answering on nine addresses clears it with six to spare and is one chance to be wrong. A fault happens to whoever runs a server, so this is the count Marzullo's guarantee actually rests on. Three rather than the four the shipped agent requires, because four is chosen against the server lists this product ships with today and three is arithmetic that holds whatever anybody points an agent at. Counted by the reader from the `operator` labels, never read out of the receipt. A receipt naming no operator anywhere does not clear this: it is judged on everything else by the checks above, whose question is whether the agent kept its own word, and refused here, where the question is whether the reader has any reason to believe the sources failed separately. |
| Largest encoded receipt | 64 KiB | The format's own ceiling, repeated here because a reader applies it. A receipt carrying three real attestations is a little over three kilobytes, so nothing legitimate approaches it. A reader may set a smaller one and cannot set a larger, since a file over the format's ceiling is not a receipt. |

A stated ceiling of zero is refused as unset rather than read as unlimited. Zero is what the field
holds when nobody filled it in, so the deliberate reading and the oversight are the same value, and
an unset field is not a permission.

**Every one of these only ever refuses.** That is what makes it safe to state a threshold on a
quantity nobody has measured. Being wrong in one direction refuses an honest receipt, which the
reader sees and can act on. Being wrong in the other accepts a false one silently, and nobody finds
out.

### A sound receipt this floor refuses

The narrowest interval is the one to be careful about, and it will refuse receipts that are true.

An agent on better hardware, years from now, may honestly bound a reading to less than a microsecond.
Its receipt keeps every promise it makes, its evidence checks out, and a reader applying the floor
above refuses it. That refusal is the floor doing what it was set to do and it is not a finding that
the receipt is dishonest. There is no way to tell the two apart from inside one receipt, which is why
the number is deliberately two orders of magnitude below the best case the product acknowledges
rather than at it: at today's policy value of two hundred microseconds the floor would refuse an
honest future receipt often, and the refusal would look identical to catching a lie.

A reader who is satisfied that such a receipt is genuine lowers their own floor and checks it again.
The floor is the reader's number, and the reader may tighten it or loosen it; what the format fixes
is where a reader starts, so that two of them who have changed nothing agree.

### What the policy block does not carry

A receipt states the widest interval its agent would sign for, the fewest sources it would answer on,
and the longest it would extrapolate from an exchange, and those three are checkable by anybody.
Three other numbers set the width of a bound and none of them is in the receipt: the floor under an
individual source's interval, and the two that bound how far an oscillator's rate may have moved
during holdover. A reader can check the three the receipt carries and cannot check the three that
decide what they are looking at.

That is a limit of v0, stated here rather than left to be discovered.

**`first_party` was added on 2026-09-12, and it is the one optional field whose
absence and whose stated value mean the same thing.** Everywhere else in this format absent is a
different fact from a value, and the paragraphs below turn on that. Here it is not: a receipt that
could not have said so was issued by a deployment that had no servers of its own to declare, because
the field was written on the day this product first had any. Reading absent as true would refuse
every receipt ever issued, and reading it as unknown would make the operator counts unanswerable.
So absent is false, and the encoder writes the key only when it is true.

What it is for is keeping our own word from passing as third-party evidence. A deployment may run
its own time servers, and this product is about to. Such a server answers like anybody else's and its signature checks like anybody else's, and the
party behind it is the party issuing the receipt, so counting it among the independent operators
would put the issuer's own word inside the number that is supposed to be free of it, with every
signature still verifying. A reader leaves it out of both operator counts and is told how many it
left out, which is the difference between a round of three strangers and a round of two strangers
and one of the issuer's own.

**`operator` and `min_operators` were added on 2026-09-09, on the same reasoning
as the paragraph below and with the same test applied.** Both are optional and both are read as
absent rather than as nought on a receipt that predates them, so every receipt already issued goes on
verifying and the fixture that predates them is checked on everything else. What a validator does
with an absent operator is the conservative thing: every unnamed source in one receipt is counted as
one party between them rather than one each, so a gap in the labels can only cost a receipt the
operator tests and never win them.

**`max_holdover_ns` was added on 2026-09-08, and this paragraph used to say the
body was frozen and that adding a field was version 1.** That sentence was written on the assumption
that receipts were in somebody's hands. None are: both repositories are private, nothing is deployed,
and the only receipt outside a test in this tree is the fixture at
`crates/verify/tests/data/a-real-stamp/`, which predated the field when this was written and has
been re-taken twice since, so it now carries the ceiling and `timewitness verify` prints it. The freeze starts at the first release rather than at the first version number, and after
that a new field is version 1.

## What a stranger does with one

1. Recompute the hash of the artefact locally. Never upload the artefact.
2. Check the bytes are in the one canonical spelling this format allows.
3. Check the COSE signature against the public key inside the receipt.
4. Run the refusals above.
5. Check each piece of evidence independently: a Roughtime signature against that server's published
   key with the nonce bound to this receipt, a timestamp token against its authority's root, a log
   inclusion proof against an independent mirror.
6. Confirm the interval contains what the evidence says it should.

All six run today. Steps 1 to 4 are the receipt crate, step 5 is the evidence clients, and step 6 is
the verifier, which is a command and a single HTML file that works with the network off. `crates/verify`
holds the floor above as the numbers it ships with, and `docs/verifier.md` is how it is run.

## What is frozen and what may still be added

Frozen: every field above, the role table, the scheme table, the encoding rules and the signature
structure. A change to any of them is version 1, not a change to version 0.

A later version may add fields. A v0 reader meeting a v1 receipt refuses it rather than reading the
fields it recognises, because a receipt is evidence and half-reading evidence is worse than not
reading it.

Two things this format deliberately leaves out because they belong to phase 2: anything about the
countersign exchange between two agents, and anything about time domains. Adding them here would be
designing phase 2 in advance and getting it wrong.
