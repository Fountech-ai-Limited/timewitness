# The Roughtime checks, watched failing first

Run on 2026-09-07. Nine checks, each planted out of the source one at a time, the test that exists to
catch it run against the planted build, and the test watched failing. Then the source restored and
the whole file run green again.

A test that has only ever passed proves that the code does what the code does. These nine were each
watched refusing to catch the thing they are named after, which is the only evidence that they are
doing the catching.

## What the corpus is

Three real responses, from three public Roughtime servers, captured on 2026-09-07 by
`cargo test -p timewitness-sources --test roughtime_live -- --ignored --nocapture` and stored exactly
as the client stored them: the nonce binding, the request packet and the reply packet, in the
container `pack_blob` writes. They live at `crates/core/tests/data/roughtime/` with a manifest naming
each server and its published key. `crates/core/tests/roughtime_corpus.rs` reads them with no network
at all.

Against those three, a server of the test's own is built in the same file, with its own signing keys
and its own encoder written out again from the draft. It exists for the four faults no public server
will produce on request: a radius of zero, a response dated outside its own delegation window, a
version this code does not implement, and an index the Merkle path cannot reach.

| Server | Radius it stated | Round trip from this machine | Delegation window |
|---|---|---|---|
| roughtime.int08h.com | 5 s | 129 ms | none at all, `0` to `2^64-1` |
| roughtime.se | 1 s | 107 ms | 2026-01-18 to 2027-01-30 |
| time.txryan.com | 3 s | 148 ms | one day either side |

Those round trips are over the public internet from one machine in one place at one moment. They are
not a figure about this product and they do not appear in any claim.

`roughtime.cloudflare.com:2003` is on the published ecosystem list and answered nothing on either
transport on the same day, across six different version lists. It is deliberately not in the client's
list of servers.

## The nine

| # | The check planted out | The test that then failed |
|---|---|---|
| 1 | The delegation signature is taken on trust | `a_flipped_bit_anywhere_in_a_real_reply_is_refused` |
| 2 | The response signature is taken on trust | `a_response_signed_by_a_key_the_certificate_does_not_name_is_refused` |
| 3 | The path is walked and the root is never compared | `changing_the_nonce_in_the_request_breaks_the_path_to_the_signed_root` |
| 4 | The binding is stored and never recomputed | `a_binding_that_does_not_produce_the_nonce_is_refused` |
| 5 | The echoed nonce is not compared with the one we sent | `a_response_echoing_a_different_nonce_is_refused` |
| 6 | A radius of zero is accepted | `a_radius_of_zero_is_refused` |
| 7 | The delegation window is not enforced | `a_response_dated_outside_its_own_delegation_window_is_refused` |
| 8 | The version on the wire is not enforced | `a_response_in_a_version_this_code_does_not_implement_is_refused` |
| 9 | Index bits the path cannot reach are ignored | `a_path_that_cannot_reach_the_claimed_index_is_refused` |

Nine of nine were watched failing. The file was restored between each and the corpus came back green.

## One check that is not on the list, and why

The client also compares the long-term key named in the stored request against the key the check was
handed, and refuses where they differ. Planting that one out does not fail any test, because the
delegation signature check catches the same case a few lines later. It stays in because it gives a
person a better answer than a signature failure does, and it is honest to say it was not watched
failing on its own.

## Two things the captures showed that are worth carrying forward

**A radius is seconds, not milliseconds.** The three live servers stated one, three and five seconds.
A Roughtime corridor is therefore seconds wide. It authenticates a bound and it does not tighten one,
and the client puts the radius in as dispersion so the inverse-square weighting gives it almost no
say in the combined interval. That is the correct outcome and it is worth being explicit about,
because a reader who expects Roughtime to be the precise source has the roles the wrong way round.

**One public server delegates without a window.** `roughtime.int08h.com` signed a delegation valid
from `0` to `18446744073709551615`, which is the whole representable range. The delegation mechanism
exists so that a key exposed on the public internet can be retired; a delegation with no end date
gives up that property. Nothing in this code can fix somebody else's operational choice, and the
check still runs, so the entry passes it trivially. It is recorded because a reviewer will find it.
