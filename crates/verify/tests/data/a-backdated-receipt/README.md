# A receipt backdated three years on genuine evidence

`receipt.hex` is the receipt in `../a-real-stamp/` with its reading moved back three years and
signed again by a key of its own, written as hex because the tree holds one binary file and holds it
on purpose. Every attestation in it is real. The DigiCert token is the one the real stamp carries.
The two drand rounds, 1 and 1000000, are real rounds of the quicknet chain and fall at 1692803367
and 1695803364. The Roughtime corridor is gone, because a corridor of the real
day would not overlap a reading three years earlier and the receipt would be refused for it.

It passes every check the verifier makes, and it should. Nothing in it is false about the evidence:
the rounds could not have been known before they were published, and the token says the thing it
stamps existed by 1788979279 on DigiCert's own clock.

**What the evidence brackets, corrected 2026-09-19.** It brackets nothing from
above. The line read "93175916 s, about 2.95 years" until that day, being the later round against
the token, and the token's end of it was an assumption rather than a signature: DigiCert states no
accuracy, so it puts no number on how wrong its own clock could be and bounds nothing in UTC. What
the verifier says now is that a not-later-than signature was checked, that its authority states no
accuracy of its own, and that nothing outside bounds the moment from above, with the 153.875 ms
width inside it being whatever the signer wrote. That is the plainer warning and it is the true
one: this receipt's evidence cannot contradict its reading from above at all.

Until 2026-09-15 the verifier's first line on this receipt read "all 3 of its attestations were
checked" and no line said how loose they were. It is kept here so the line under the verdict is held
to saying so, on the command line and on the page alike.
