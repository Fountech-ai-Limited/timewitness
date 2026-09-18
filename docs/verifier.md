# The verifier, and how to check a receipt without asking us anything

Written 2026-09-08. Supersedes nothing.

A receipt only we can check is not evidence. It is a request to be trusted, and this product's whole
argument is that a stranger who trusts neither party can check one for themselves. So the verifier is
built as a thing that runs with none of our infrastructure and no account, and it is tested that way.

There are two of them and they are one implementation. `crates/verify` holds every check;
`crates/cli` and `crates/verify-web` are shells around it. `scripts/check-verifier-page.mjs` puts one
receipt through both and fails the build if the two disagree about anything, because two
implementations drift and the day they drift is the day the page says a receipt is good and the
binary says it is not.

## The two ways to run it

**The command line.**

```
cargo build --release -p timewitness-cli
./target/release/timewitness verify a-receipt.cbor --subject the-thing-it-stamps
```

**The page.** `bash scripts/build-verifier-page.sh` produces `verifier-page/verifier.html`, which is
one file with the checking code inside it as WebAssembly. Save it, open it from your own disk, and it
works with the network off. It makes no request of any kind.

Neither needs an account, a key from us, or a route to anything of ours.

## What it checks, in the order it checks it

1. **Is this a receipt or an unbounded file.** Size first, because everything after it allocates from
   what the file says about itself.
2. **Was this signed by the key it names, over exactly these bytes.** Ed25519 over the COSE
   `Signature1` structure, which covers the protected header as well as the payload. Signing the
   payload alone would let a signature be moved onto a receipt naming a weaker algorithm.
3. **Is that key one of ours.** Unanswered for a reader who has only the receipt, and said so
   rather than skipped. The receipt proves that whoever signed it held that key. A reader who
   recognises the key can compare it and a reader who does not learns that one key signed this.

   A reader handed a key log can pass it with `--key-log <file>`. The log we serve is at
   `https://timewitness.dev/key-log.txt`, a `timewitness-key-log v1` file, and the `v0` release
   refuses that format by name, so until a later release a reader checks it with a verifier built
   from `main`. The head of the log is checked
   first, under the key this reader holds for us: one ships in the trust material below and
   `--anchors` or `--key-log-signer` replaces it. A head signed by any other key answers nothing,
   and the step says whose it was not, because whatever that list says, it is not us saying it. A
   log with no head is signed by nobody and answers nothing either.

   Under a head of ours the step reads the entries that name agent keys. Held where one names the
   receipt's key over a window the reading falls in. Refused where the key was retired before the
   reading, where every window naming it falls elsewhere, where the log names it as a server key,
   or where the log names agent keys and not this one. Not checked, and not refused, where the log
   holds no agent entry at all, which is what the log we serve first looks like: it carries the keys
   of our two Roughtime servers, and a list of server keys has nothing to say about the key that
   signed a receipt.

   **The answer is worth what a list we signed is worth**, and the step says so in the words it
   gives back. What a log buys is that a key we published is one we cannot quietly unpublish,
   because a reader who kept an earlier head can prove the log was rewritten. It is not third-party
   evidence and it never becomes any. The window is judged on the receipt's own reading, which
   whoever holds the key wrote, so this step catches a receipt that says it was signed outside the
   window and not one that lies about when.

   **Proving a rewrite.** A reader who kept the log we served last time passes both,
   `--key-log <new> --kept-log <old>`, and a further step, *is this log an extension of the one you
   kept*, holds the old entries as the first entries of the new log, rebuilds the old root from
   them, checks the old head under the same key, and runs the RFC 6962 consistency proof between
   the two heads. A removed, changed or reordered entry is a refusal that names the entry.
4. **Do the receipt's own numbers support each other.** The reading inside the interval, the parts of
   the width adding to the width and to no more than it, a majority of the sources that answered
   kept, the agent keeping to the policy it states, every evidence entry in a role its scheme can
   support, and each entry's own instant consistent with the interval it is offered as support for.
5. **Does the bound clear this reader's own floor.** See below.
6. **Is the thing you have the thing this receipt stamps.** Hashed where the file sits.
7. **Does this receipt sit where it says in a chain.** Never answered on one receipt, and said so:
   placing two receipts in order needs both of them.

Then every evidence entry is checked against the trust material the reader holds, and the report says
which entries were checked, against whose key, and what each check established, line by line.

## The first two lines

The verdict comes first. It says whether anything refused the receipt and how many of its
attestations were checked. The line under it says how wide the checked outside evidence brackets the
moment, which is the latest checked not-earlier-than against the earliest checked not-later-than. On a
receipt resting on its agent's own model it names the width as the signer's own claim, and it says so
where the receipt carries no Roughtime corridor or carries one nobody checked.

On the receipt committed at `crates/verify/tests/data/a-real-stamp/` that line is a 2 s bracket round a width of 153.875 ms. On the one at `crates/verify/tests/data/a-backdated-receipt/`, whose
attestations are all genuine and whose reading was moved back three years, it is about 2.95 years.
Both pass every check, and until 2026-09-15 both printed the same first line and nothing under it.

The second line goes wherever the verdict goes. The command line prints it under `--quiet` as well,
`--json` carries it as `bracket`, `--fields` carries the span as `outside_bracket_ns`, the page prints
it under its own verdict, and the Action quotes both lines in its job summary.

## The reader's own floor

Every plausibility test has two possible sources for its threshold. One is the receipt, which states
the widest bound its agent would sign for and the fewest sources it would answer on. The other is the
reader, who decided in advance.

Checking only against the first is checking a document against its own opinion of itself. A receipt
claiming a bound zero nanoseconds wide, resting on one source, and stating a width ceiling of zero
passes every check inside the receipt crate, because it kept every promise it made. It is also a
claim nothing in this field can support, and passing it would put a figure no measurement supports
under our name.

So the reader holds numbers of their own. The shipped ones:

| | | Why |
|---|---|---|
| narrowest interval | a ceiling of 1 us | Two orders of magnitude under the tightest condition the product quotes, which is about 100 us to UTC on a cloud instance with a hypervisor clock. That figure is quoted from public research and has not been measured by this product or by us. Deliberately not set at the 200 us today's agent policy cannot beat, because a future agent on better hardware honestly will, and refusing those would look identical to catching a lie. |
| widest interval | 1 hour | Past an hour an interval says nothing a calendar would not. |
| fewest sources answering | 3 | With three, a majority beats one bad clock. Two is two clocks agreeing. |
| fewest operators behind the sources kept | 3 | The row above counts names and names are free: nine addresses at one company clear it with six to spare and are one chance to be wrong. A fault happens to whoever runs a server, so this is the count Marzullo's guarantee rests on. Three and not the four the shipped agent requires, because four is chosen against the server lists this product ships against today and a verifier is read years later by somebody pointing an agent at their own. Counted by the reader from the `operator` labels and never read out of the receipt. A receipt naming no operator anywhere does not clear it: the receipt crate accepts such a receipt, because its question is whether the agent kept its own word, and this question is whether there is any reason to believe the sources failed separately. |
| largest receipt | 64 KiB | A receipt with three real attestations is about nine kilobytes. This refuses one padded to a megabyte through a header nobody reads. |

**Every one of these only ever refuses**, which is what makes it safe to set a threshold on a
quantity nobody has measured. Being wrong in one direction refuses an honest receipt, which the
reader sees and can act on by supplying their own. Being wrong in the other accepts a false one
silently, and nobody finds out.

The floor is printed beside the verdict, and `--min-width` moves the first of them. The others are
fields on `Floor` for a reader driving the library, and there is deliberately no option for the
operator one on the command line: lowering it is a thing to do knowingly, and when the floor was
written nobody outside held a receipt that needed it.

## Trust material, and what offline actually means

The verifier checks three kinds of third-party signature and needs a key for each: a Roughtime
server's long-term key, a drand chain's group key, a timestamp authority's signing certificate.

Three Roughtime keys, one drand chain and two certificate pins ship with the code. Every one of them
is published by somebody who has never heard of this product, and shipping a copy is not being the
root of trust for it: a reader can compare each against the publisher's own list.

One more key ships beside them and is different in kind: the key that signs the head of our key
log. It is ours, it vouches for no evidence, and it is not counted among the trust material the
evidence is checked against. What it decides is whether a key log in front of the reader is one we
signed, so that step 3 is answered off our list rather than off a list anybody made.

A reader who would rather not take the shipped copy supplies their own with `--anchors <file>`:

```
# One anchor per line. Blank lines and lines from a # are ignored.
roughtime <name> <32 bytes of hex>
drand     <name> <chain hash, 32 bytes> <group key, 96 bytes> <period seconds> <genesis second>
rfc3161   <name> <certificate sha-256> [more certificate digests]
keylog    <name> <32 bytes of hex, the key that signs the head of our key log>
```

A line nobody can parse refuses the file rather than being skipped, because a skipped line is a key
the reader meant to trust and would go on believing they had.

`--no-anchors` trusts nothing. That is a legitimate state and not a degraded one: every arithmetic
claim the receipt makes about itself is still checked, and every attestation is reported as unchecked
rather than glossed over, which is what that reader actually knows.

A file holding some keys and not others gets the same answer entry by entry. Who signed an
attestation is written in the attestation before any key is chosen: a Roughtime request names its
server by the hash of the server's long-term key, a drand round names its chain, and a timestamp
token carries the certificates it was signed under. An entry naming a party the file holds nothing
for is reported as not checked, saying what it names and that the file holds no key for it, and the
receipt is not refused for the reader's choice of keys. An entry naming a party the file does hold a
key for, whose bytes do not verify under that key, refuses the whole receipt, because a signature
that does not check out is a fault in the receipt and not a fact about the reader. Until 2026-09-15
a file lacking one signer's key refused an intact receipt as contradicting itself, and the only way
past it was to hold every key the shipped set holds.

**What a key decides, and what it does not.** The name an attestation gives for its signer sits in
bytes whoever wrote the receipt controls, so it decides one thing only: whether the signature is
checked. Every check whose inputs are all inside the receipt runs on every entry whatever the reader
holds, and an entry failing one is refused at every setting, `--no-anchors` included, with a
sentence saying the fault needs no key to see. For a corridor that is the framing, the encoding, the
nonce and its binding to this receipt's subject, the delegation window, the signed part of the
response under the key the delegation names, the version, the radius, the Merkle path from the
stored request to the signed root, and the moment, radius and nonce the receipt prints beside it.
For a token it is the reply parsing as a granted timestamp response, the request and the token both
being about this receipt's subject, the two carrying the same nonce, the signed attributes carrying
the digest of the token, and the moment, interval and nonce printed beside it. For a round it is the
shape alone, that the signature is 48 bytes and a point on the curve: which moment a round falls at
is arithmetic on the chain's schedule, which is part of the anchor, so a round from a chain the reader
does not hold has its printed moment held to the receipt's interval and to nothing else. Until
2026-09-15 the name was read first and nothing after it ran, so a reply of zeros behind a renamed
server was reported not checked, exit 0. A renamed Roughtime server is refused on its own now
whatever else is done to the response: the request is the Merkle leaf, so a request that names a
different key no longer hashes into the root the server signed.

## What is deliberately not a boolean

The answer to "is this receipt good" is a list. Three evidence roles do three different jobs, and a
report that collapses them into one badge has hidden the only thing a careful reader wants. Every
step comes back as held, failed, or not checked, and not-checked is never a pass.

The exit code is there for a script: zero where nothing was refused, one where something was, two
where the command line itself was wrong.

## What this does not do

- It does not check that the agent's key belongs to anybody. It can check a key against a log a
  reader was handed, `--key-log`, and that is a list we signed rather than anybody else's word for
  it: our own word, checked under our own key, and never third-party evidence. A log signed by
  anybody else answers nothing, and a log holding no agent key, which is the log we serve first,
  answers nothing about a receipt and does not refuse it.
- It does not catch a stolen key by the window in that log. The window is compared with the
  receipt's own reading, which whoever holds the key wrote. What the log's window does catch is a
  receipt that says it was signed after the key was retired.
- It does not prove the log is honest to a reader seeing it for the first time. What it proves, to
  a reader who kept an earlier copy and passes it as `--kept-log`, is that nothing they held has
  been removed, changed or reordered since.
- It does not check order. `sequence` and `chain_previous` are signed and are reported; nothing
  compares two receipts, and one verifier run has one receipt.
- It does not check that a receipt sits in a chain, which is the point above. What it does check is
  that the receipt in front of it has one spelling: the COSE unprotected header is outside the
  signature by design, so the format pins it to the single key identifier entry and a restated
  receipt is refused rather than accepted with a chain link of its own. The digest the verifier
  prints is therefore the chain link, and two readers holding what they believe is the same receipt
  can compare one number.
- It does not chain a timestamp authority's certificate to a commercial root. It pins a leaf, which
  is narrower than trusted.

The full list of what the product cannot prove is `timewitness cannot-prove`, and it is printed with
every result rather than under it.
