# The version 1 receipt, witnessed again by each authority

Both files are the receipt in `../a-version-1-stamp/`, with the witness over its signature replaced by
a new one fetched on 2026-09-24: `sectigo.hex` from Sectigo's timestamp authority, which says 11:22 UTC
on its own clock, and `digicert.hex` from DigiCert's, which says 11:52 UTC. Nothing signed by the agent
changed, so both hash to the same receipt as the original, and `../a-version-1-stamp/subject.bin` is
what all three stamp.

Replacing the witness with a later genuine one is something any holder can do, and the format says
so. What they are here for is the spelling. Each witness is stored the way `timewitness stamp` stores
one from that day, in the one form a reader accepts, and both replies were already in it, so each is
stored byte for byte as it came back. Sectigo names all three certificates it sends, by SHA-1.
DigiCert names only its signing certificate and sends two more beside it, which for that signer are
part of the one spelling.

`xxd -r -p sectigo.hex receipt.cbor` gives back a file `timewitness verify` reads, and the same for
the other.

The witnesses place the signing no later than 2026-09-24, three days after the agent signed. That is
true and weaker than the original witness, which was fetched as the receipt was signed. Neither
authority states an accuracy, so neither bounds anything in UTC.
