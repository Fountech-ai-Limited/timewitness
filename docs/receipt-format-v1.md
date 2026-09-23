# Receipt format v1

Written 2026-09-21. It adds to `docs/receipt-format-v0.md` and changes nothing in it: everything that
document says of version 0 holds of version 1 except where a section below says otherwise, and
version 0 itself never moves. This file is the one that binds for what version 1 adds.

## Why there is a version 1

A stranger holding a version 0 receipt can check the limits its agent kept to and not the terms that
set its width. Version 0 said so, in "What the policy block does not carry", as a limit rather than a
secret. Version 1 carries those terms, and three more things version 0 could not say: how much of the
holdover is a rate the agent is not correcting for, which of two trust paths the reading came by, and
an outside witness over the receipt's own signature rather than only over what it stamps.

## Versions, and what a reader does with one it does not know

This code writes version 1 and reads versions 0 and 1. A reader meeting any other number refuses the
receipt and names the number, rather than reading the fields it recognises: a receipt is evidence and
half reading evidence is worse than not reading it. That is what the released `v0.1` does with every
version 1 receipt, in these words: "this receipt says it is version 1 and this code reads version 0,
so it will not guess at what the fields mean". A version 1 reader says the same of version 2 and names
the versions it reads.

**There is no negotiation beyond that, and no option to write version 0.** A receipt written in
version 0 withholds the width terms, and an option to withhold them is an option to be less checkable.
A reader who holds an older verifier upgrades the verifier, which is free and needs no account. The
resident agent's answer crosses to the stamp command as a receipt body carrying its version; a stamp
command handed a reading in any version other than the one it writes refuses it and says to run the
agent from the same release, because the width terms are the agent's to state.

## What version 1 adds to the body

All whole numbers or text, like everything else in the body. Each is required on a version 1 receipt
and absent on a version 0 one, and absent is never read as nought.

| Field | Type | Meaning |
|---|---|---|
| `claim.policy.source_interval_floor_ns` | int | The narrowest half width the agent lets any one source's answer support. A source claiming less is widened to this before it is compared with anybody. |
| `claim.policy.frequency_slew_ppb_per_s` | int | How fast the agent assumes its oscillator's rate can move, in parts per billion a second. The agent holds it in parts per million; the receipt carries it to the nearest part per billion. |
| `claim.policy.frequency_span_ppb` | int | The band the agent assumes its oscillator's rate stays inside, end to end, in parts per billion. Half of it is the largest rate the agent allows for before it has fitted one. |
| `claim.breakdown.unclaimed_rate_ns` | int | The part of `oscillator_holdover_ns` that covers a rate the agent is not correcting for: half the band before any fit, and the larger of that and the fitted magnitude where the model refused the fit. Reported and not added, like `network_half_ns`, because it is already inside the holdover term. |
| `claim.taken_by` | text | `one-shot` where the process that signed polled the sources itself, `resident-agent` where it read a resident agent's answer on the same machine. Set by the stamp command from the path it took, never by the answer. |

The three policy terms are the agent's assumptions, not measurements. Stating them does not make them
true of the machine. It makes them checkable: a reader can see what the width rests on, and a reader
who thinks a band of a hundred parts per million is wrong for the hardware can say so with the number
in front of them.

`claim.policy.max_holdover_ns` and `claim.policy.min_operators`, optional in version 0 because the
oldest version 0 receipts predate them, are required in version 1.

## What version 1 refuses that version 0 read past

- **A key the format does not define**, anywhere in the body. The decoded receipt written back out has
  to be the bytes that were signed. Version 0 read past an extra key, and still does.
- **A source whose `kind` the format does not know.** Version 0 reads one as plain NTP, which proves
  nothing and so is the safe direction only until the format gains a kind that signs; an older reader
  would then downgrade it without a word. Version 1 refuses it and names it. The kinds are `ntp`,
  `nts`, `roughtime` and `local-hardware`.
- **An unclaimed part that is negative, larger than the holdover, or beside a claimed rate.** A model
  claims a rate or does not.
- **A band of nought or less, or a negative floor or slew.** A band of nought is what the field holds
  when nobody set it, which is the reason a ceiling of nought is refused in version 0.
- **A version 1 receipt missing any field this document requires.** The signer refuses to sign one as
  well, so it is caught where it is made.

## The signature witness

A decision of 2026-09-19 put a not-later-than signature over the receipt's own signature into
version 1. Every outside signature in a version 0 receipt is bound to the thing
stamped: the timestamp token is over the subject's hash, and the Roughtime nonce is derived from it. So
outside evidence can place the subject and cannot place the signing. A key used after a moment can sign
a receipt over any subject whose evidence was gathered before it.

**The field.** An RFC 3161 token over the SHA-256 of the receipt's own 64 signature bytes, in the same
container the `rfc3161` scheme stores (`TWTSEVD0`, the request and the reply), carried in the
unprotected header of the COSE envelope under the text label `signature_witness`. It cannot be inside
the signed body, because it is about the signature. It is optional: a receipt is signed whether or not
an authority answered, and one without a witness says nothing about when it was signed.

**What a reader does with it.** The token is held to everything its own bytes can be held to, whatever
the reader holds, including that it is about this receipt's signature and no other. Where the reader
holds a pin for the authority it is checked under it, and a token that fails under a held key refuses
the whole receipt, as an evidence entry does. A checked witness says the receipt was signed no later
than the edge it supports. Where the receipt also carries a checked beacon, the signing now has a
bracket of its own: after the beacon, whose value is inside the signature, and before the witness. A
witness dated before that beacon is refused.

**The unprotected header.** A version 1 header holds the key identifier and at most this one entry.
Anything else is refused, as in version 0.

**The hash of a version 1 receipt is of the receipt as its agent signed it.** The witness sits
outside the signature, so a holder can drop it, or swap in a later genuine token over the same
signature, without the agent's key. A timestamp token also carries plenty its own signature does not
cover: the request stored beside it, certificates besides the one a reader pins, fields nobody reads.
Until 2026-09-23 the chain link was the SHA-256 of the whole file, and on that day a third of the
single-bit flips inside the committed receipt's witness still verified, each as a file with a hash of
its own, so a holder with no key could fork or break a chain.

So the chain link, the next receipt's `prev` and the hash the verifier prints are the SHA-256 of the
file with the `signature_witness` entry taken out of the unprotected header, which is the file the
agent wrote before the witness came back. Every other byte of that form is covered by the signature
or is canonical CBOR the decoder re-encodes and compares, so it has exactly one spelling, as version 0
does. Dropping the witness, swapping it or respelling it changes what the verifier reports about the
signing and never which receipt it is. None of them can move the signing earlier, since a token
cannot be dated before the signature it is over existed.

What this gives up is the property version 0 chose its link for: for a version 1 receipt carrying a
witness, the hash is not what `sha256sum` prints of the file, and the verifier says so on the line
that prints it. A receipt with no witness, and every version 0 receipt, still hashes as the file it
is. Version 0 is untouched: its header holds the key identifier and nothing else.

## What version 1 still does not do

- The terms are stated, and nothing yet checks the width against them. A reader can see that the
  holdover before a fit ought to be at least half the band over the time since the last exchange; the
  verifier does not yet do that arithmetic for them.
- The witness places the signing no later than a moment. It does not say whose key signed; that is the
  key log's question, and the key log is ours rather than third-party evidence.
- Nothing about the countersign exchange or time domains, which are phase 2 and are not designed here.
