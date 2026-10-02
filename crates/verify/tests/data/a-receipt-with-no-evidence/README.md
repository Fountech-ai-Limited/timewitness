# A receipt that carries no evidence

`receipt.hex` is a receipt format version 1 over `subject.txt`, with three sources from three
operators, a width of 120 ms, and no evidence entry at all. It is signed by a key made from a fixed
seed for this purpose and for nothing else, so it is built the same way every time:
`crates/cli/tests/what_the_evidence_list_says_of_a_refusal.rs` builds it and fails where the bytes
here are not what it builds. The sources and operators are invented names and nothing in it was
taken from a server.

It passes every check the verifier makes. It is here for one sentence: read to the end, it carries no
third-party evidence at all, and the command line and the page both have to say so. The receipts in
`../refused-before-its-evidence-is-listed/` are refused before their evidence is listed, and neither
route may say it of them.
