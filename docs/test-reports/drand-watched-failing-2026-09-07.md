# The drand checks, watched failing first

Run on 2026-09-07, the same day the rounds were captured.

## What the corpus is

Three real rounds from the drand quicknet chain, at
`crates/core/tests/data/drand/rounds.txt`: round one from 2023, round one million from the middle of
the chain, and a round from the day of capture. Fetched over plain HTTP from `api.drand.sh` and
cross-checked against `api2` and `api3`, which served identical bytes for the same round.
`crates/core/tests/drand_corpus.rs` reads them and checks them with no network at all.

There is no fake server in that file and there cannot be, because building one would mean holding
the group's signing key. Everything hostile is therefore done to a real round. That is the honest
shape anyway: an attacker cannot forge a drand round either, so the attacks worth testing are the
ones that reuse a genuine signature in the wrong place.

## The two checks that carry the weight

| The check planted out | The test that then failed |
|---|---|
| The pairing is computed and the answer is never compared | `moving_the_round_number_under_a_real_signature_is_refused` |
| The pairing is computed and the answer is never compared | `swapping_two_real_signatures_is_refused_both_ways` |
| The chain the round names is not compared with the chain we hold | `a_round_offered_under_a_different_chain_is_refused_before_any_pairing` |

## Three checks that are not isolated by any test, and why that is fine

Each of these was planted out and the corpus stayed green, because an earlier check catches the same
input first. They are listed rather than quietly counted, because a report that says nine of nine
when three of them were carried by something else is the kind of number that gets quoted later.

- **A flipped bit in a signature.** Almost every single bit flip takes the compressed point off the
  curve, so `from_compressed` refuses before the pairing is reached. The two tests above reach the
  pairing with a point that is genuinely on the curve, which is the case that matters.
- **A round off the schedule.** Round zero is refused because its signature does not verify, well
  before the schedule arithmetic is asked for a time. The schedule check is a second line.
- **A signature of the wrong length.** Padded to 48 bytes it is not a point either, so the same
  refusal fires first.

## What this evidence proves and what it does not

Three things belong in what the product says it cannot prove, and all three come from this work
rather than from a document.

**The signature does not cover the time.** It covers the round number. The moment a round belongs to
is arithmetic on the chain's published genesis and period, which a verifier holds as part of the
chain definition alongside the group key. A verifier that disagrees about the genesis gets a
different answer and the signature will not tell it so.

**A coalition holding enough shares could compute rounds ahead.** The quicknet chain signs the round
number alone, with no dependence on the previous round, so a group that could reconstruct the secret
could produce any future round today. Not-earlier-than therefore rests on that group not existing,
not on mathematics. The older chained scheme ties each round to the one before it and makes that
harder, at the cost of a thirty second period rather than three seconds.

**It pins the receipt and not the thing being stamped.** A receipt containing a round from three
o'clock was finished after three o'clock. The file it is about could be from any time at all.

## What was not built, and why

The design asks for at least two of drand, the NIST beacon and the UChile beacon. One was built.
The other two were probed on 2026-09-07 and neither can be verified today.

**The NIST beacon contradicts its own specification.** Its published rule is that `outputValue` is
the SHA-512 of `signatureValue`. It is not, for the latest pulse, for the pulse before it, or for
pulse one of chain two from 2022, under any byte ordering tried. Separately, the certificate the
pulse names by hash carries a 2048-bit key while the signature is 4096 bits, and those two cannot
both be right. A client written against the specification would either fail on every pulse or be
written to whatever made the numbers agree, and the second of those is how a check that verifies
nothing gets shipped. So no NIST client exists here.

**The UChile beacon is not serving its API.** `random.uchile.cl/beacon/2.0/pulse/last` answers 502
and the 2.1 path answers with the site's own HTML rather than a pulse.

The freshness beacon is therefore delivered on one beacon and not two, and that is written down
rather than rounded up.
