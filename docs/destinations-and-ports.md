# Destinations and ports

What a machine running TimeWitness connects to, so an operator can open a firewall from a list
instead of from a packet capture. This file supersedes nothing; nothing listed hosts or ports before
it.

Every line of the table comes from the code, and `crates/sources/tests/the_destinations_table.rs`
holds the two to each other on every build: a destination in the published lists with nothing written
down for it fails, and a line of the table naming a host or a port the code does not carry fails too.
Nothing in this file is a figure for anybody's network. It says what the product connects to, not how
fast the connection is or how well it works.

## The list

| Host | Protocol | Port | Direction | Used by | If it is blocked |
|---|---|---|---|---|---|
| `roughtime.int08h.com` | Roughtime | 2002/udp | outbound | agent, `stamp` | one fewer source, and `int08h.com` is then reached by nothing |
| `roughtime.se` | Roughtime | 2002/udp | outbound | agent, `stamp` | one fewer source; `netnod.se` is still reached over NTS |
| `time.txryan.com` | Roughtime | 2002/udp | outbound | agent, `stamp` | one fewer source, and `txryan.com` is then reached by nothing |
| `time.cloudflare.com` | NTP | 123/udp | outbound | agent, `stamp` | one fewer source; `cloudflare.com` is still reached over NTS |
| `time.google.com` | NTP | 123/udp | outbound | agent, `stamp` | one fewer source, and `google.com` is then reached by nothing |
| `ptbtime1.ptb.de` | NTP | 123/udp | outbound | agent, `stamp` | one fewer source; `ptb.de` is still reached over NTS |
| `time.cloudflare.com` | NTS key exchange, TLS | 4460/tcp | outbound | agent, `stamp` | one fewer source; `cloudflare.com` is still reached over NTP |
| `nts.netnod.se` | NTS key exchange, TLS | 4460/tcp | outbound | agent, `stamp` | one fewer source; `netnod.se` is still reached over Roughtime |
| `ptbtime1.ptb.de` | NTS key exchange, TLS | 4460/tcp | outbound | agent, `stamp` | one fewer source; `ptb.de` is still reached over NTP |
| `time.cloudflare.com` | NTS time exchange | 123/udp | outbound | agent, `stamp` | the key exchange succeeds and the source still answers nothing |
| `nts.netnod.se` | NTS time exchange | 123/udp | outbound | agent, `stamp` | the key exchange succeeds and the source still answers nothing |
| `ptbtime1.ptb.de` | NTS time exchange | 123/udp | outbound | agent, `stamp` | the key exchange succeeds and the source still answers nothing |
| `timestamp.digicert.com` | RFC 3161, plain HTTP | 80/tcp | outbound | `stamp` | the other authority is tried; with both blocked the receipt carries no not-later-than evidence |
| `timestamp.sectigo.com` | RFC 3161, plain HTTP | 80/tcp | outbound | `stamp` | it is the second of the two tried, so nothing changes until DigiCert is blocked too |
| `api.drand.sh` | drand, plain HTTP | 80/tcp | outbound | `stamp` | the next relay is tried; with all three blocked the receipt carries no freshness beacon |
| `api2.drand.sh` | drand, plain HTTP | 80/tcp | outbound | `stamp` | the next relay is tried; with all three blocked the receipt carries no freshness beacon |
| `api3.drand.sh` | drand, plain HTTP | 80/tcp | outbound | `stamp` | the next relay is tried; with all three blocked the receipt carries no freshness beacon |

Nine time servers behind six operators, two timestamp authorities and three relays onto one drand
chain. The three relays are three ways to reach the same chain rather than three beacons, and the
two authorities are tried in order until one answers.

## Four things the table does not say

**It is plain HTTP and not HTTPS, on port 80.** The client speaks nothing else and says so when it is
handed an `https://` address. Everything it fetches is checked against a key or a pinned certificate
this repository carries, so TLS would add a second, weaker opinion about who answered rather than a
first one. An operator who opened 443 for the timestamp authority and the beacon has opened the wrong
port. The client is `crates/sources/src/http.rs`.

**DNS is needed and is not in the table.** Every one of these is a name, resolved by the machine's own
resolver before any of the sockets above are opened. The table lists what the product connects to; the
resolver is the machine's business and a host that cannot resolve a name reaches none of this.

**Nothing listens on a public port.** The resident agent listens on loopback only, `127.0.0.1` on a
port the operating system picks, and the port it picked is written into the endpoint file the caller
reads. A host firewall does not need a rule for it and an inbound rule from anywhere else would not
reach it.

**`verify` connects to nothing at all.** Checking a receipt needs no destination on this list, no
account and no call to us, and `crates/architecture/tests/verify_path_needs_nothing_of_ours.rs`
refuses a build where that stops being true. A machine that verifies receipts and does not issue them
needs no rule from this file.

## What a blocked destination costs, stated properly

The "if it is blocked" column is about one destination at a time. The thing that decides whether a
reading is signed at all is the operator floor: a round is refused unless the sources that survive
selection stand behind at least four distinct operators, which is `min_operators` in
`crates/clock/src/policy.rs`. A round short of it refuses. It does not widen the bound and carry on.

So blocking one host costs a source and possibly an operator, and the bound gets slightly wider.
Blocking enough of them costs every reading, and the agent says so by name rather than by signing
something it cannot stand behind: the refusal is `InsufficientOperators` in
`crates/core/src/refusal.rs` and it carries how many were present and how many were required.

The two evidence destinations are different in kind. They are not sources and they do not narrow
anything, so blocking them never refuses a stamp. What it does is leave the receipt without the
third-party evidence that would otherwise be in it, and the receipt says which role is missing.
