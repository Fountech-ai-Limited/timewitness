# The timestamp token checks, watched failing first

Run on 2026-09-07, the same day the tokens were captured.

## What the corpus is

Two real timestamp tokens, from DigiCert and Sectigo, at `crates/core/tests/data/rfc3161/`, stored
as the client stores them: the request that went out and the reply that came back, both whole.
`crates/core/tests/rfc3161_corpus.rs` checks them with no network at all.

There is no fake authority in that file and there cannot be, because forging a token means holding a
signing key, which is also what an attacker would need. Everything hostile is therefore done to a
real token.

## What was tried, and what each authority turned out to be

Four free authorities were asked for a token, four times each. None of them wanted an account and
none of them charged anything.

| Authority | Answered | Signed with | Certificates over four requests |
|---|---|---|---|
| DigiCert, `timestamp.digicert.com` | yes | SHA-256 with RSA | one, the same every time |
| Sectigo, `timestamp.sectigo.com` | yes | SHA-384 with RSA | one, the same every time |
| freetsa.org, `freetsa.org/tsr` | yes | ECDSA with SHA-512 | not readable by this code |
| GlobalSign through ai.moda, `rfc3161.ai.moda` | yes | SHA-384 with RSA | three different ones |

Two are built in and two are not, for reasons worth writing down.

**freetsa.org signs with ECDSA.** Its certificate chain is full of RSA, which is what made it look
like an RSA authority at first glance, but the signature on the token itself is ECDSA over SHA-512.
This code implements RSA only and refuses that token by name rather than skipping past it, which is
the behaviour that matters: the alternative to a refusal here is a client that quietly produces no
evidence and says nothing.

**ai.moda answers from three different signing certificates.** Four requests produced three
certificates, and one of them was DigiCert's own, so it is a front for several authorities rather
than one of them. That has two consequences. A single pinned certificate refuses most of its
answers, and using it beside DigiCert would not be two independent witnesses.

## The five checks

| The check planted out | The test that then failed |
|---|---|
| The signature is never checked against the certificate | `a_flipped_bit_in_the_signature_itself_is_refused` |
| The certificate is taken from the token rather than from the pin | `a_token_checked_against_a_certificate_nobody_pinned_is_refused` |
| The same | `an_authority_with_no_pins_at_all_accepts_nothing` |
| The nonce that came back is not compared with the one that went out | `changing_the_nonce_in_the_stored_request_is_refused` |
| The same | `a_reply_pasted_onto_a_request_that_asked_about_something_else_is_refused` |
| The digest inside the signed attributes is never compared with the token | `changing_the_moment_the_token_states_is_refused` |

The last one is the one worth understanding, because it is the only place where an edited token could
otherwise pass. The signature is not over the token. It is over a small set of attributes, one of
which is the hash of the token, so a token whose stated moment has been edited still carries a
signature that checks out perfectly. Only the comparison between that attribute and the token in
front of it catches it. Planted out, a token whose year had been moved by a decade was accepted.

## Two checks that no test isolates, and why

The subject hash is compared twice: once against the request that went out and once against the
imprint inside the token. Planting either one out leaves the other, so neither has a test of its own
that fails. That is what redundancy is supposed to look like and it is recorded rather than counted
as a sixth check.

## What a single byte change can and cannot do

A reply carries the certificate chain the authority would like a reader to have, and this check never
looks at those, so a bit flipped inside one of them changes nothing about what was proved and is not
refused. Demanding a refusal there would be demanding that the check care about bytes it is right to
ignore. What the corpus asserts instead is the property one step up, over every 37th byte of both
replies: a change either fails the check, or leaves what the token says exactly as it was. Of forty
probes spread through each reply, eighteen were refused and twenty-two landed in bytes nothing signed
and proved the same thing.

## What this evidence proves, and what it does not

**It proves** that a named authority put its signature to having been shown a particular hash, and
that its clock read a particular moment when it did. Whoever held that hash held it no later than
then.

**It does not prove the authority's clock is right.** Both authorities stated an accuracy of zero,
which is not a claim of perfection: it means neither of them puts a number on its own error at all.

**It carries no legal weight.** Neither is a qualified trust service, and standing of that kind comes
from accreditation rather than from a signature. This product claims none.

**The pin is a leaf certificate and it will go stale.** This code checks that a token was signed by
the key in a certificate whose hash was pinned in advance. It does not walk a chain to a commercial
root, check revocation, or check the timestamping extended key usage. When these certificates expire
and are replaced, fetching a new token starts failing loudly, which is the safe direction; tokens
already inside receipts stay checkable, because the certificate travels inside the token. Chaining to
a root instead of pinning a leaf is the durable answer and is not built.
