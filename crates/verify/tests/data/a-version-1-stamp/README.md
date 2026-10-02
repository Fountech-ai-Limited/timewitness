# One version 1 receipt, taken from the real servers

`receipt.hex` is the receipt, as hex so the repository stays text. It was produced on 2026-09-21
at 17:24 UTC by `timewitness stamp`, built from the branch that introduced receipt format
version 1, on a desktop that was running another long measurement at the same time. `subject.bin` is the sixty-one bytes it stamps.

`xxd -r -p receipt.hex receipt.cbor` gives back the file `timewitness verify` reads.

It is here for what it carries, not for its width. It is the first receipt with the fields version 1
added: the three terms that set the width, the part of the holdover covering a rate the agent was not
correcting for, the path its reading came by, and a witness over its own signature. Nine public
servers disciplined the clock, one Roughtime server signed a corridor, a drand quicknet round pins it
no earlier, DigiCert's timestamp authority signed for the payload hash, and DigiCert signed a second
time over the SHA-256 of the receipt's own signature. None of those has heard of this product.

The bound it states is 186.008 ms wide. That is a figure from a busy desktop on one evening and it is
not a figure for anybody else's machine, or for this one when it is quiet. Nothing quotes it.

The key that signed it was generated for this one run and has been thrown away, so no receipt will
ever follow it in a chain.
