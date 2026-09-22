# The countersign wire form, v1

Supersedes nothing. First version, written 2026-09-20 and extended five times the same day: the
request half signed, the receive half built, the ordering answer, receiver-only mode held by a
check rather than by a sentence, and the pair attacked. Extended again on 2026-09-22 with the send
half on the command line, which is what lets two machines exchange heartbeats with the shipped
binary alone. It is the shape that travels between two agents and the signature over it. Deciding
an order is a separate piece built on top of this one and is not described here.

The version on the wire is `tw1`. The receipt format beside it is `v0` and the two numbers are not
related; they version different things and they move separately.

## What a countersigned exchange proves, said before the format

Two parties who each hold a key each signed a statement about their own clock, and the two
statements are consistent with an ordering.

That is the whole of it, and the limits below are part of the claim rather than a footnote to it.

- **Neither party's interval is third-party evidence for the other**, whatever the two of them agree
  between themselves, and an exchange does not become evidence by being countersigned. The
  third-party evidence lives in the receipt each side's claim came from, which this form names by
  hash and does not carry.
- **Two intervals are never averaged and never intersected into a narrower one.** Where two moments
  are further apart than the two bounds added together, their order is known. Where they are not,
  the order is undecided and the answer says so rather than picking one.
- **A receiver that will not countersign records a refusal and stops nothing.** There is no
  enforcement here and there is none anywhere else in this product.
- **None of this is a claim about accuracy.** It is a claim about order, and about the width of two
  intervals.

## The form

```text
X-Bounded-Time: tw1.<base64url, no padding, of a signed COSE_Sign1>
```

On an MCP tool call the same signed bytes travel as a field rather than as a header, and everything
below the encoding is identical. A test holds the two routes to each other, so the protocol cannot
come to mean two things.

**An unsigned body is refused rather than read.** Until 2026-09-20 the value was the body on its
own, which made it a claim about somebody's clock that anybody on the path could have written. What
travels now is that body inside a signature, and a value that is not a signed one gets the same
silence any other unreadable value gets.

### The prefix

`tw1.` is readable without decoding anything, so a receiver refuses a version it does not know
before it parses a byte. The version is **also** inside the encoding, as `v`, because a version
carried only outside the signed payload is a version anybody on the path can rewrite. Both are
checked and they have to agree.

### The body

A CBOR map with text keys, encoded to the same deterministic rules receipt format v0 uses: definite
lengths only, the shortest form of every integer, keys sorted by their own encoded bytes and never
repeated, and no floating point at all. The reader re-encodes what it decoded and requires the same
bytes, so a spelling it has not been taught about cannot get through by being accepted and then
re-emitted differently.

**A key the form does not name is refused.** That is the one second spelling the re-encode rule
above cannot see: an unknown field is part of the decoded value, so it encodes back to the bytes it
arrived as and the comparison passes. A reader that then looked up only the names it knows would
drop the field and re-emit the clean spelling, which is two values meaning the same thing and
hashing differently. The version is read before the walk over the keys, so a later version of this
form is refused for its version rather than for the fields it carries.

| Key | Type | What it is |
|---|---|---|
| `v` | integer | The wire version, `1`. |
| `role` | text | `request` or `response`. |
| `hash` | 32 bytes | The payload this half is about: what is being sent, or what came back. |
| `seq` | integer, not negative | Where this sits in the signing agent's own chain of receipts. |
| `lo` | integer | The earliest UTC the moment could have been, in nanoseconds since the Unix epoch. |
| `mid` | integer | The model's own estimate. **A display value, never the claim**, exactly as in a receipt. |
| `hi` | integer | The latest UTC the moment could have been. |
| `rcpt` | 32 bytes | The full signed receipt this claim was taken from, named by hash. |
| `key` | 32 bytes | The Ed25519 public key of the agent that signs this half. |
| `req` | 32 bytes | On a response only: the request it answers, by the sha256 of the signed request as it travelled. See "The receive half". |

`lo <= mid <= hi` or the value is refused. A response without `req` is refused, because a response
that names no request can be pasted onto any request at all. A request carrying `req` is refused,
because a request answers nothing.

## Why it names the receipt rather than carrying it

Measured rather than assumed. The committed real receipt in this repository is **9,765 bytes**, and
base64url of it is **13,020 characters**, read 2026-09-20 off
`crates/countersign/tests/the_wire_form.rs`, which reads the file rather than quoting a number.

Common servers refuse a single header line at 8 KB and a request's whole header block at 8 to 16 KB.
A receipt with its attestations in it therefore cannot travel in a header at all. Putting it there
anyway would mean the protocol worked on a test rig and was dropped by the first load balancer in
front of a real service.

So what travels is the claim, the hashes that bind it to a payload and to a receipt, and the key
that signs it. A holder of the full receipt ties the two together by hashing it. A holder of only
the exchange has the ordering argument and knows it has nothing else, because the format gives it
nowhere to pretend otherwise.

**The ceiling is 4,096 characters** and a longer value is refused before anything decodes it. That is
half the smaller of the two server limits above, and a request carries other headers. An exchange
that has to be larger than this has stopped being a claim and started being a receipt, and receipts
travel in bodies.

What one actually measures, on the same run: a request is **238 characters** and a response is **290**,
the difference being the one extra field. Both are under a sixteenth of the ceiling.

## What a receiver does with one it cannot read

It carries on. A request with an unreadable `X-Bounded-Time` is the same request it would have been
with no header at all. What the receiver records is that no exchange happened and why.

A receiver that failed the request would be enforcing, and this product does not enforce and does not
claim to.

The reasons are kept apart so the reason can be recorded, not so that any of them can be treated
differently:

| Refusal | When |
|---|---|
| not this version | it does not start `tw1.`, or `v` inside is not 1 |
| too long | past 4,096 characters |
| not base64 | the part after the prefix is not base64url without padding |
| not deterministic CBOR | the bytes are not the deterministic encoding of what they decode to |
| not signed | it is not a `COSE_Sign1` of this shape, or the header names another algorithm |
| signature does not match | it was altered after it was signed, or signed by a different key |
| unknown field | a key the form does not name is in the body |
| key is not text | a key on the wire is not text, and every field this form names is |
| missing field | one the form requires is not there |
| wrong type | one is there and is the wrong shape |
| incoherent | the values decode and say something that cannot be true |

## base64url, and why it is written here rather than taken from a crate

Forty lines, on the path a stranger's bytes take into this product, which is the one place where a
dependency costs more than it saves.

The decoder refuses anything that is not the exact spelling it would have emitted: no padding, no
line breaks, no whitespace, no standard-alphabet `+` or `/`, and no bits set in the tail of the last
character below the bits that became bytes. A decoder that accepts two spellings of one value hands
an attacker a second header that means the same thing and hashes differently, which is the fault
deterministic CBOR is chosen to avoid one layer up.

## The signature

The body is signed through the same envelope a receipt is, `COSE_Sign1` from RFC 9052 with Ed25519,
which COSE numbers minus eight. What is signed is the `Sig_structure` the specification defines,
being the literal text `Signature1`, the protected header bytes, an empty external-data byte string
and the payload. It is one function shared with the receipt format rather than a second copy, because
two readers of one signature format is two chances to disagree about what was signed.

**The key a signature is checked against is the `key` field inside the signed body.** It is never the
key identifier in the unprotected header, which sits outside the signature and is anybody's to
rewrite. That header carries a copy so a reader can see whose it claims to be before doing the work,
and the copy is held to the signed one: it holds that one entry and nothing else, or the value is
refused. Without that rule a holder could restate one signed exchange as several byte strings that
all verify, by dropping the identifier, relabelling it, or padding a label nobody reads, and a
response names its request by the hash of what travelled.

A signed request is **383 characters** on the wire, read 2026-09-20 off
`crates/countersign/tests/the_signed_request.rs`, against a ceiling of 4,096.

A stranger checks one with the shipped binary and no network:

```text
timewitness countersign <the header value>
timewitness countersign --from a-file-holding-it.txt
```

**What a verified signature establishes, and it is less than it looks.** The party holding that key
signed that statement about its own clock. It is not evidence that the clock was right, and it is not
third-party evidence for anybody: the evidence for the interval is in the receipt the claim came
from, which this form names by hash and does not carry. Fetch that receipt, run `timewitness verify`
on it, and check its hash against the one in the exchange.

## The receive half

The receiver reads the request **on the bytes it arrived as**, checks the signature over those
bytes, and then makes its own half: the hash of what it is sending back, where that sits in its own
chain, the interval its own clock gives it, the receipt that interval came from, and the name of the
request it is answering. It signs that with its own key. The two halves together are the
countersigned exchange.

The request is read from its bytes rather than taken as something already parsed, because the
property the pair rests on is about bytes. A caller that had parsed the request elsewhere and passed
the parsed thing in could hand the receiver a claim that never travelled in this spelling.

### What `req` names, and it changed on 2026-09-20

**`req` is the sha256 of the signed request as it travelled: the whole `COSE_Sign1`, not the body
inside it.** Until the receive half was built it was the hash of the body, and the reason for the
change is short. Ed25519 verification asks only that a signature is valid, not that it is the one a
well behaved signer would have produced, so one body can carry more than one valid signature. Under a
body hash both of those are the same request to a response, and the sender then holds two byte
strings and can present either as the thing that was answered. Naming the envelope closes it: one
response names exactly one signed request. It is the same rule the unprotected header already applies
one layer in, followed through one layer out.

A reader reproduces the name with no special tooling: sha256 of the bytes the base64url in the header
decodes to.

### What a pair is checked for, and the one thing it is not

Three checks, and each has its own refusal so the reason can be recorded:

| Refusal | When |
|---|---|
| does not answer this request | the response names something other than the signed request beside it |
| one key signed both halves | there is one party here and not two |
| incoherent | the half given as the request is not a request, or the half given as the response is not a response |

**The two intervals are not compared and nothing about their order is checked.** That is deliberate
and it is the part to get right. Two intervals that overlap leave the order undecided, so a reader
that refused a pair unless the response were later would have answered the ordering question at parse
time, always in the same direction, and nobody would see it happen. A pair whose intervals overlap
reads exactly like one whose intervals do not, and so does a pair whose receive interval is wholly
earlier than its send interval. Both have tests of their own saying so.

**Nothing is signed that this reader would refuse.** The writer runs the reader over what it is about
to sign and refuses where the reader would, rather than keeping a second list of the same conditions
beside it. Without that a caller can sign an exchange whose edges are out of order, or a response
naming no request, and get a value that goes out and that nobody on earth can read back, this side
included.

A signed response is **435 characters** on the wire and a signed request is **383**, read 2026-09-20
off `crates/countersign/tests/the_countersigned_pair.rs`, which measures them rather than quoting
them, against a ceiling of 4,096. The response is the longer because it carries the extra field
naming the request.

A stranger checks a whole pair with the shipped binary and no network:

```text
timewitness countersign <the request> <the response>
timewitness countersign --from a-file-holding-both.txt
```

The file holds one header value to a line, so a request and the response to it sit in one file the
way they sit in a log. One line is still one half, and one value on the command line still reads as
one half, so the two routes have not come apart.

**What a checked pair establishes.** Two parties who each hold a key each signed a statement about
its own clock, and those two statements are the whole of what a reader has. Neither interval is
evidence for the other party and countersigning does not make it so. The evidence for each interval
is in the receipt that half names by hash, which this form does not carry.

## The ordering answer

Two moments are in a known order when every moment one of them could have been is before every
moment the other could have been. Anything else is undecided. That is the whole rule, and it is
interval disjointness rather than anything cleverer.

It is the same statement as "the two readings are further apart than the two bounds added together",
which is how the claim is usually said in words, except that the disjointness version stays correct
when an interval is not centred on its reading, and an interval here is never promised to be.

The arithmetic lives in one place, `crates/core/src/order.rs`, so that every surface answering this
question answers it the same way. A second copy of it is a second answer waiting to disagree with the
first.

### The three things a pair can say

| Verdict | When | What it means |
|---|---|---|
| `established` | the send interval is wholly before the receive interval | the order holds whatever either clock was really doing inside its own stated bound |
| `undecided` | the two intervals touch or overlap | the request was made before the response in the world, and these two claims do not establish it |
| `contradicted` | the receive interval is wholly before the send interval | the two claims cannot both be true, and the pair cannot say which one is wrong |

**Touching at a point is undecided and not an order.** Where one interval ends exactly where the
other begins, the two moments could be the same instant, so the comparison is strict. A comparison
that was not strict would call that an order and be quietly wrong from then on.

**Undecided is an answer.** The alternative, comparing the two readings, would answer every question
and would be wrong a share of the time nobody could afterwards measure. The reading is a display
value here exactly as it is in a receipt, and it takes no part in this arithmetic.

**Contradicted is not "the response came first".** A response names its request by the hash of bytes
that had to exist before the response was made, so a receive moment wholly before a send moment
cannot really have happened. One of the two clocks is outside the bound its own agent stated, or one
of the two parties is lying. Which of those it is does not follow from the pair, and the answer does
not guess.

**Nothing narrows one bound with the other.** Two agents each disciplined their own clock against
their own sources, and neither one's bound is evidence about the other's. Combining them would be
inventing accuracy out of two claims, which is the one thing this product exists not to do. So a
widened bound on either side loses an order that a narrower one had, and no amount of countersigning
gets it back.

The answer is on the command line in words and as lines a script reads:

```text
timewitness countersign <the request> <the response>
timewitness countersign <the request> <the response> --fields
```

The words and the fields open with the same verdict word, because two surfaces over one answer is
two answers waiting to disagree. The number beside the verdict is `gap_ns` where there is an order
and `overlap_ns` where there is not, named differently so a script cannot read one as the other.

## Receiver-only mode, and what makes it free

A receiver countersigns with no account, no certificate and no relationship with us, and it costs it
nothing. That is not a pricing promise, it is what the protocol is: the exchange is between two
agents and there is nothing of ours in it. It is the reason a sender can ask anybody to countersign.

**It is checked rather than asserted, from 2026-09-20.**
`crates/architecture/tests/verify_path_needs_nothing_of_ours.rs` held the verify path to three rules
and nothing held this one. It now holds both: the countersign crate and everything it links, and
every file of the command line that `timewitness countersign` reaches, may not link a package that
exists to reach a network, may not name an address of ours, open a socket, start another program or
read the environment, and may not carry the name of a credential.

Two faults were seeded on the countersign path and watched turning the build red: an address of ours
in the countersign crate, and a credential read in the countersign command. The same seed was then
watched **passing** with the countersign entry taken out of the check, which is what says the entry
is doing the work rather than the verify path happening to cover it.

**A receiver makes its own half with the shipped binary, from 2026-09-20.**

```
timewitness stamp --subject the-reply --key agent.key --out reply-receipt.cbor
timewitness countersign <the request> --answer --receipt reply-receipt.cbor --key agent.key
```

The second line prints the response value to send back as the header on the reply, and then the
pair as `countersign` reads it, because the writer runs the reader over its own output before
printing a word of it.

**Everything the response says about the receiver's clock comes out of that receipt and none of it
can be given on the command line.** `Countersigned::answer` takes an interval, a sequence and a
receipt hash, and a command that took those three as arguments would let a receiver state an
interval no clock of its ever read. So the interval is the receipt's interval, the sequence is the
receipt's place in the receiver's own chain, the hash is the hash of those exact signed bytes, and
the payload is what the receipt is a receipt for. The only things the command takes are the request
and the key.

**The key is read and never made, and it has to be the key that signed the receipt.** `stamp`
generates a key where the file is absent, because a build runner has nobody to ask for one; here
that would be the one key certain not to have signed the receipt being named. And a response signed
by one key while naming a receipt signed by another would hand a reader two parties where they were
told there was one, with nothing on the wire to say so, because the wire carries the receipt by hash
rather than by content. The party that holds both is the only one that can see it, so it is refused
there. It was watched refusing: with the check taken out of the build, one test goes red and it is
the one written for it.

Nothing in that path asks for an account, a certificate or a payment, and nothing in it reaches the
network.

**A sender makes its own half with the same binary, from 2026-09-22.**

```
timewitness stamp --subject what-we-are-sending --key agent.key --out sending-receipt.cbor
timewitness countersign --ask --receipt sending-receipt.cbor --key agent.key
```

Until this, the command line could answer an exchange and not start one, so two machines could
countersign each other only through a program somebody had written against the library. The shape of
`--ask` is the shape of `--answer` and deliberately so: it takes no exchange value, because it makes
a half rather than reading one, and the interval, the sequence, the receipt hash and the payload all
come out of the receipt. Neither side can be told what its own clock read, and one function reads the
receipt for both of them, because two copies of that reading are two places for the property to stop
being true.

`--ask` and `--answer` together are refused rather than resolved in some order, and so is `--ask`
with an exchange value beside it. Both were watched refusing: with either check taken out of the
build, one test goes red and it is the one written for it.

**What this pair of commands is for.** Two machines in a fleet exchange heartbeats with these two
lines and nothing else. There is no account in it, no host of ours, and no service either machine
has to be able to reach: an exchange made while our app is switched off, unreachable or never
deployed is the same exchange. A machine may file the pair with the app afterwards, and filing is a
separate act that the exchange does not wait for and does not depend on.

**A request is not an instruction.** A machine that is asked to countersign and does not is a
machine that did nothing wrong, and the words the command prints say so. Nothing here obliges
anybody to answer, and an unanswered request is the request it would have been with no header on it.

## Attacking a pair

Written 2026-09-20, with the attacks in `crates/countersign/tests/attacking_a_countersigned_pair.rs`.
A test that only shows the honest case working is a test that would pass over a reader checking
nothing, so each of these starts from a pair that is known good and changes one thing about it.

**Every bit of either half, flipped in turn.** Over four thousand single-bit changes across the two
signed byte strings, and every one of them is refused: a change either breaks the signature, breaks
the shape, or changes the bytes the other half names. The battery counts what it tried and fails if
the number is small, because a battery that silently tried nothing passes and looks exactly like one
that tried everything. With the signature check taken out of the build it goes red, along with the
payload case below and nothing else.

**A response moved onto another request of the same sender.** Two requests differing in one field,
each signed, and the response to the first offered against the second. Refused, because the response
names the bytes of the request it answered.

**What a response names, proved as arithmetic.** The hash it carries is the sha256 of the whole
signed request and not of the claim inside it. Ed25519 asks that a signature is valid rather than
that it is the one a well behaved signer would have produced, so one body can carry more than one
valid signature, and a response naming the body would leave a sender holding two spellings it could
each present as the thing that was answered.

**Two of the attacks on the list are not attacks.** Swapping which key signs which half is an
exchange between the same two parties in the other direction, and it reads as one: the protocol
names roles, not parties. Sending one request twice and having it answered twice gives two valid
pairs, which is a retry. Both are tested to read as valid, deliberately.

**So a replayed request is not visible to a holder of one exchange**, and that is a limitation of
the form rather than a hole in it. An exchange carries nothing about any other exchange, so a reader
holding one cannot tell whether there were others. A reader holding both can see that the two
responses answer the same request, because both name it by the same hash.

**A pair signed by two keys nobody has heard of is a valid pair.** There is no key list to fail, and
what such a pair establishes is that two keys signed two statements about two clocks. Whether either
key belongs to anybody is a question this form does not answer, and the report to a reader says so
rather than implying otherwise.

## What is not here yet

**A second valid signature over one body, built rather than reasoned about.** The case above is
proved by showing what the response names; showing the two spellings themselves needs a signer that
picks its own nonce, which means curve arithmetic this repository does not carry today. It is worth
building when something else needs that dependency, and it would strengthen a decision rather than
change it.
