# One timestamp token over a key log head

`cutoff-head-witness.hex` is an RFC 3161 token from DigiCert's public timestamp authority, taken on
2026-09-21 over the head `crates/verify/tests/certificates.rs` builds in `cutoff_only`: one cutoff
entry stating that certification began a thousand seconds before the drand round in
`crates/receipt/tests/data/sandwich/drand.hex`, under a head signed by a test key and carrying that
round. The token is over the SHA-256 of the head's bytes and its signature together, which is what
`SignedHead::witness_digest` computes.

It is real, and it is the only real thing about that log. The key, the cutoff and the certificates
the tests append are made up. Because every byte of that head is fixed in the test, the token keeps
checking for as long as DigiCert's certificate is pinned; change anything in `cutoff_only` and the
token no longer matches, which is the test saying so rather than a fault in the token.

Written as hex so the tree stays text end to end, as the other fixtures here are.
