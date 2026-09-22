# What a counted verification is

One place, and there is not a second. Every figure this product ever states about how much checking
happens is defined here, and `scripts/a-verification-figure-names-the-checker.mjs` refuses a surface
that states one without saying where it came from.

## The thing being counted

**One counted verification is one receipt put through the hosted checker on `timewitness.dev`, from
a reader's browser, with an answer given.** Nothing else is counted, ever.

That is the whole definition. What follows is what it excludes, which is the part that matters.

## What is outside it, permanently

**Every offline verification.** `timewitness verify` on a command line, the `timewitness-verify`
library inside somebody else's program, and the single-file checker page a reader downloads and runs
from their own disk with the network off are all outside this figure. They make no call, so there is
nothing to count, and that is the point rather than a gap: a verifier that had to tell us it ran
would be a verifier we could switch off.

Those are never estimated, extrapolated, modelled or guessed at. A figure of the shape "and
presumably as many again offline" is not a figure, and no document, deck or page of this product may
carry one.

**Anything about who checked.** The count is an integer going up. It records no reader, no address,
no browser, no receipt, no hash, no payload, no verdict and no time of day. A count of checks is not
a log of checks, and nothing here becomes one later without this document changing first.

**A check that was not asked for.** Loading the page is not a verification. Opening it, reading it
and leaving counts nothing.

## How repeats are handled

**They are counted.** The same reader checking the same receipt five times is five counted
verifications.

This is stated plainly rather than quietly fixed, because the honest way to make it fewer would be to
tell one reader from another, which means recording something about them, and that is a worse thing
to do than to have a figure that counts a reload. The figure is a count of checks and it is never
described as a count of people, of readers, of receipts or of anything else. A sentence saying how
many people checked something is not a sentence this figure supports.

## How it may be said

**A published figure carries the words "through the hosted checker".** Not "verifications", not
"checks run", not "times checked": those all read as a total, and the total is unknown and always
will be.

Honest: "4,000 verifications through the hosted checker in September."
Not honest: "4,000 verifications in September", which claims every check that happened.

The check that holds this is `scripts/a-verification-figure-names-the-checker.mjs`, which reads the
surfaces of whichever tree it is given, refuses a sentence stating a count of checks without those
words, and proves itself on every run against sentences it must refuse and sentences it must let
through.

## What the page tells a reader

The checker page says, where a reader can see it before they use it, that a check there is counted,
that the count is one number going up, and that it records nothing about them or about the receipt.
A page that counted without saying so would be collecting something quietly, which is the thing this
product argues against everywhere else.
