# A receipt backdated three years on genuine evidence

`receipt.hex` is the receipt in `../a-real-stamp/` with its reading moved back three years and
signed again by a key of its own, written as hex because the tree holds one binary file and holds it
on purpose. Every attestation in it is real. The DigiCert token is the one the real stamp carries.
The two drand rounds, 1 and 1000000, are real rounds of the quicknet chain and fall at 1692803367
and 1695803364. The Roughtime corridor is gone, because a corridor of the real
day would not overlap a reading three years earlier and the receipt would be refused for it.

It passes every check the verifier makes, and it should. Nothing in it is false about the evidence:
the rounds could not have been known before they were published, and the token says the thing it
stamps existed by 1788979279. What that evidence brackets is the moment to between the later round
and the token, 93175916 s, about 2.95 years, and the 153.875 ms width inside it is whatever the
signer wrote.

Until 2026-09-15 the verifier's first line on this receipt read "all 3 of its attestations were
checked" and no line said how loose they were. It is kept here so the line under the verdict is held
to saying so, on the command line and on the page alike.
