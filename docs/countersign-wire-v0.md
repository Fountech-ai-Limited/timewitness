# The countersign wire form, v1

Supersedes nothing. First version, written 2026-09-20. It is the shape that travels between two
agents and nothing else: signing, verifying a signature and deciding an order are separate pieces
built on top of this one, and none of them is described here.

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
X-Bounded-Time: tw1.<base64url, no padding, of deterministic CBOR>
```

On an MCP tool call the same CBOR body travels as a field rather than as a header, and everything
below the encoding is identical. A test holds the two routes to each other, so the protocol cannot
come to mean two things.

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
| `req` | 32 bytes | On a response only: the request it answers, by the hash of the request's own encoded body. |

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

## What is not here yet

Signing, verifying a signature, the receive half, the ordering answer, receiver-only mode, and the
work of attacking all of it. They are the rest of the protocol and each is its own piece of work. Nothing in
this file signs anything, and an exchange read back by this code is a shape that parsed and not a
statement anybody has vouched for.
