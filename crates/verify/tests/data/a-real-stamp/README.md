# One receipt, taken from the real servers

`receipt.cbor` was produced on 2026-09-09 at 21:41 on that machine's clock, 18:41 UTC, by
`timewitness stamp` on an ordinary machine on an ordinary internet connection, at the sixteen rounds
the agent defaults to. `subject.bin` is the fifty-eight bytes it stamps, unchanged since 2026-09-08.

Everything in it is real. Nine public servers disciplined the clock, three of each of the three
kinds this product speaks: Roughtime, plain NTP and NTS. One of the Roughtime servers signed over a
nonce derived from the hash of `subject.bin`, a drand quicknet round pins it no earlier, and
DigiCert's timestamp authority signed for the payload hash to pin it no later. None of those has
heard of this product.

The bound is 153.875 ms wide. Read off `timewitness verify` on this file, which prints half widths:
35.081 ms is the sources overlapping, 38.011 ms is the model's own regression residual doubled by
the coverage factor, 3.586 ms is the oscillator over the 461 ms since the newest exchange, and
0.250 ms is the fixed safety margin. It is a figure from this desktop on this connection and it is
not a figure for anybody else's machine.

It was signed under a ceiling of 30 s, the widest bound the one-shot command would sign for until
2026-09-15, and `timewitness verify` prints that ceiling off the receipt in its floor step. The
one-shot default is 2 s from that date and the agent holds itself to 250 ms, so this width sits
inside both, and the ceiling it states is the older one.

The nine servers stand behind six operators, and this file is the first receipt that says so. Every
source in it carries who runs it, the policy block carries the floor of four operators the agent
signed under, and `timewitness verify` prints both counts beside the count of sources, so a reader
does the arithmetic rather than taking a number of ours.

**And it is the third re-take on one day, which is one more than the last version said there would
be.** The reason is the same shape as the second: the fixture stands for what this product produces,
and what it produces now carries an operator on every source. The receipt it replaces was still
verified by the format when this was written, because a receipt naming no operator is read there as
predating the field rather than as hiding something. That is still true of the format and it stopped
being true of the reader on 2026-09-10: the verifier's own floor asks for three distinct operators
behind the sources that were kept, and a receipt with no labels cannot show three. The two questions
are different on purpose and `crates/verify/src/floor.rs` says which is which.
What did not move is the width. 149.842 ms then against 153.875 ms here, with the sources overlapping
at 34.947 ms then and 35.081 ms now: enforcing independence refuses rounds, it does not narrow them,
and a reader comparing the two files should expect exactly that.

**Read the two receipts side by side before concluding a third kind of source narrowed anything.**
The one this replaces was 176.741 ms with six servers of two kinds at 15:05 the same day, and the
term a new kind of source would have moved is the sources overlapping: 34.463 ms then against
34.947 ms here. It did not move. What moved is the oscillator, 17.287 ms against 0.501 ms, and that
is how long after the newest exchange each stamp happened to be taken rather than anything about the
sources. NTS buys an answer nobody on the path can write. It does not buy a narrower one, and this
file is the evidence for both halves of that sentence.

## Why it was re-taken twice on one day, having said it never would be

The second re-take, at 20:32, is the one above and its reason is smaller than the first: a third
kind of source joined the round, and a fixture standing for what this product produces should be
what this product produces. The receipt it replaced still verified. The paragraphs below are about
the first re-take, at 15:05, where the old file no longer verified at all.


The version of this file written on 2026-09-08 said the receipt stays as it was, because it is the
artefact three real third parties signed. That reasoning was right and it stopped being available on
2026-09-09.

The receipt taken on 2026-09-08 no longer verifies. Its not-later-than entry prints the instant
DigiCert's token names, and that token writes its time to whole seconds and states no accuracy at
all, so the moment it actually commits to is somewhere in that second rather than at its start.
Printing the start of the second is claiming a tighter edge than the signature supports, which is an
overclaim by up to a second, and the verifier now refuses it. Running the old file through
`timewitness verify` returns REFUSED at "do the receipt's own numbers support each other".

**What this receipt's witness bounds, corrected 2026-09-19.** The token states no
accuracy, which is a statement DigiCert did not make rather than a statement of nought, so it puts
no number on how wrong its own clock could be and bounds nothing in UTC. Until that day the
arithmetic read the absent field as nought and the verifier printed a 2 s bracket round this
receipt. It now says that a not-later-than signature was checked, that its authority states no
accuracy of its own, and that nothing outside bounds the moment from above. The receipt's own bytes
did not move and neither did its width: the instant printed beside the entry is what the token
states, which is the written second plus the second it is written to, and that was already the
value this receipt carries.

So the choice was not between an old artefact and a new one. It was between a fixture that verifies
and one that does not, and a receipt this product's own verifier turns down cannot stand for a
receipt a stranger accepts.

The width also moved, and by a factor of about seventy: 16.424 s on 2026-09-08 at four rounds
against public Roughtime servers alone, 12.0 s at sixteen rounds the same day, and 176.741 ms here,
where three NTP servers are in the round as well. A Roughtime server states its uncertainty as a
radius in whole seconds, so a bound resting on Roughtime alone is seconds wide whatever else is done
to it. That is why the second kind of source exists.

## What it is for

`scripts/check-verifier-page.mjs` puts one receipt through the page and through the command line and
compares them, on a build machine with no route to a Roughtime server. Taking a live stamp for that
would make the check depend on a UDP port a runner may not open, and the thing being checked is that
the two shells agree rather than that the network is up.
