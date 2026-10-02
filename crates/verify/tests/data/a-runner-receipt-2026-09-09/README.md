# One receipt from a GitHub-hosted runner, 2026-09-09

`receipt.hex` is the receipt run 34349361290 of the consumer proof repository produced on
2026-09-09 at 12:09 UTC, at sixteen polling rounds, with Roughtime and plain NTP answering. It is the
artefact behind the 211.3 ms the register at `scripts/figures.json` quotes for a runner that day, and
it is committed here so that figure is held to bytes in this repository rather than to a run id on
another host. The bytes are the run's `widget.tar.gz.receipt` asset, written as hex because the tree
holds one binary file and holds it on purpose; decoded, their sha256 is
`9c112431597c2c0bd052e905226e4adf6790792b1a8566e4c2564e94a304c082`.

`timewitness verify` reads it as 211.315 ms wide, and refuses it: the receipt names no operator for
any of its six sources, because it was taken before this product carried operators at all, and the
verifier that ships will not accept fewer than three. That is the honest outcome for a receipt of its
date. The width is still what the runner reached, and that is the only thing the register quotes it
for.
