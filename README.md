# TimeWitness

TimeWitness proves when something happened.

A machine's recorded time looks precise and is not. The event happens at one moment, the clock is
asked at another, the answer comes back over a path nobody measured, and the stamp is written later
again. TimeWitness never asks for the time at stamp time. An agent disciplines the machine's clock
continuously against four to six independent sources and keeps a running measure of how wrong that
clock could be. Through the agent a stamp is then a local read with no network in it, and it says
three things: the reading, a bound on the error, which is our own claim, and third-party signed
evidence of when it was taken. That evidence is checked and it does not vouch for the bound. On the
receipt committed here it holds the moment from below and not from above: the beacon says the reading
was not earlier than its round, and the timestamp authority states no accuracy of its own, so nothing
here puts a number on how wrong that authority's clock could be. A bound resting on that evidence is
what this is being built towards.

The claim is bounded time and unbroken order. It is not accurate time.

## What is built today

This repository is early and it says so rather than describing a finished product.

| Part | State |
|---|---|
| Shared types | built |
| Source interface and the four-timestamp exchange | built |
| A continuously running agent | built as a foreground process, `timewitness agent`. It holds one clock model, disciplines it on a schedule and answers a reading to `timewitness stamp --agent` with no network call in the reading. It installs no service and starts at no boot, so it runs only while somebody keeps it running, and the Action below does not use it |
| Four to six independent sources | built, on the count this product defines and enforces. Independent is the operator: a source names who runs it, the selection counts operators rather than names, a majority resting on a minority of operators is refused, and the shipped floor is four, so a round short of it declines to sign rather than widening. Nine servers reach six operators, so two can go dark and the agent carries on. Two things the count cannot see, both on the limitation list: it is an upper bound, since a shared upstream, path, constellation or implementation is one fault however many companies it is; and three programs stand behind the nine names, so a defect in one of them is one fault across three at once. The fourth source kind, local hardware, has no client and needs a receiver this product cannot assume anybody has |
| Clock model: selection, weighting, regression, holdover | built |
| Receipt format | version 0 built and frozen, and it is what the `v0` and `v0.1` releases write, `docs/receipt-format-v0.md`. Version 1 is what the `v0.2` release writes: it states the three terms that set a receipt's width, the part of the holdover covering a rate the agent is not correcting for, and which path the reading came by, and it can carry a witness over the receipt's own signature. `v0.2` reads both versions and `v0.1` refuses version 1 by name, `docs/receipt-format-v1.md` |
| Roughtime client, the authenticated corridor | built, proved against three public servers |
| NTS client, an authenticated source that is never evidence | built, proved against three public servers. Its keys are symmetric, so it improves the clock and can never be shown to a stranger |
| Freshness beacon client, not-earlier-than | built for drand, one beacon of the two the design asks for |
| Final witness client, not-later-than | built for RFC 3161, proved against two free authorities. No OpenTimestamps anchor |
| Public verifier | built, as a command line tool and as one HTML page that runs from a local disk with no network. `docs/verifier.md` |
| GitHub Action | built. One line in a workflow, and the receipt goes into the SLSA provenance and the container image labels that already ship |
| A bound resting on outside evidence | not built. Every receipt says its bound rests on the agent's own model. The outside signatures it carries are checked, and on both timestamp authorities that ship the token states no accuracy of its own, so it bounds nothing in UTC and the receipt is left with one edge rather than two. Nothing issues a receipt whose width rests on outside signatures. The format can say so, the verifier refuses the claim unless all three roles check out, and a reader who has read an authority's published practice can allow for that authority's clock in their own anchors, which gives the edge back as the reader's own figure and never as the authority's |
| Order within a chain | built two receipts at a time, from the `v0.2` release. `timewitness order` reads two receipts offline and keeps two answers apart: the intervals say which moment came first, and a hash link says which of two receipts of one chain was signed first. Nothing walks a whole chain |
| A public log of agent keys | not built. A receipt proves whoever signed it held that key and nothing about who that was. A log of our two Roughtime server keys is served at `timewitness.dev/key-log.txt` and names no agent key, and the `v0` release cannot read it |

`v0`, `v0.1` and `v0.2` are tagged and released as source, with no binary. Both halves are built from source in this
repository, so today a stranger compiles the verifier rather than downloading it.

## The two numbers, which are not the same number

Resolution and accuracy get confused constantly and the confusion is the whole problem this product
exists to fix.

**Nanoseconds is the resolution of the local read.** That is what the hardware counter offers.

**Milliseconds is the accuracy to UTC.** That is what the network path allows. The 5 to 50 ms, the
1 ms and the 100 microsecond figures are quoted from public research and none of them has been
measured by us. They belong, in that order, to the public internet with no hardware of our own, to a
good LAN against a stratum-1 source, and to a cloud instance with a hypervisor clock. Certified
microseconds need hardware. Nanosecond accuracy is a datacentre thing and is not something this
product sells.

**About a sixth of a second is what this code reaches today**, and it was seconds until 2026-09-09.
Measured on an ordinary desktop at the sixteen rounds the Action ships, with all three source kinds
in the round: 149.3 ms, 161.2 ms and 163.2 ms wide over three passes at 21:39, and a bound of 153.9 ms on the receipt
committed in this repository at 21:41. A machine whose only sources are the three public Roughtime
servers gets no receipt at all: three operators is under the shipped floor of four, so it is refused.
Before that floor went in on 2026-09-09 such a machine reached seconds, 12.0 s wide at those same sixteen
rounds on 2026-09-08, because a Roughtime server states its uncertainty as a radius in whole seconds.
The section below says what each figure measures and why the build runner is not the reason.

A figure quoted without the conditions it was measured under is not a figure, and a figure taken
from somebody else's research and presented as ours is worse than no figure.

## How the bound is arrived at

Each source contributes an interval rather than a point: its offset, plus or minus its own stated
uncertainty and half of the round trip we measured. The offset is
`((t2 - t1) + (t3 - t4)) / 2` and the round trip is `(t4 - t1) - (t3 - t2)`, so the source's own
processing time falls out of the arithmetic. What is left unknown is how unevenly the round trip was
split between the two directions, and that residual is at most half the round trip. It is the number
the whole bound rests on and it is why the bound is milliseconds.

Of those four timestamps, two are the source's and two are ours. The two that are ours are taken by
the clock model, off the same anchor the bound is reported against, from the counter marks the source
client took at either end of the round trip. A source client never supplies a local time. A machine
has more than one local clock, the system clock that another time service is usually steering and the
model's own projection over the monotonic counter, and on most machines those two walk apart at the
oscillator's rate. An offset measured against one and an interval anchored to the other describe
nothing at all, so there is one clock in this arithmetic and no way to hand it a second.

Sources are then combined and never averaged. An average of clocks is not a measurement and lets one
bad source drag the answer. Instead the model runs Marzullo's intersection over the intervals, takes
the smallest region a majority of them allow, discards any source whose interval does not overlap
that region, weights the survivors by the inverse square of their widths, and regresses offset and
frequency across a window. A majority rather than the largest overlap is the point: agreement is
free for a source to give, so a server stating no uncertainty at all agrees with everybody and, on
the largest overlap, takes the answer. When contact is lost the bound widens with the measured drift,
which is honest, rather than staying still, which would not be.

One rule here is stricter than the published algorithm, on purpose, and a reader who knows Marzullo
should know where it is. A source whose interval contains every other interval in the round cannot be
put in the minority by any answer the others could have given, so its agreement costs it nothing.
Where setting those sources aside leaves the rest without a majority of their own, this model refuses
rather than signing. Textbook Marzullo signs it: two servers ten seconds apart, each stating three
seconds, agree nowhere, and a third source stating an hour makes two out of three and produces a
bound sixteen seconds wide that neither honest server supports. The published rule is not wrong, it
answers a narrower question, whether the region holds the truth given at most one fault, and it does.
This product also has to answer whether anything corroborated anything, and there the honest answer
is no. The rule can only turn an answer into a refusal: it never moves a region and never accepts
anything the textbook refuses. Decided 2026-09-09. The code and the reasoning are in
`crates/clock/src/marzullo.rs`.

A second rule joined it on 2026-09-11, from the same fact and pointed at a different question. A
source that could not have disagreed with anybody does not get to decide which other source is in
the minority. Three Roughtime servers state a radius of a second each and every NTP interval fits
inside all three, so all three used to take part in deciding which of the narrow sources had lied,
and they kept a liar whose interval sat two hundred milliseconds out: the interval went from 12.52 ms to 223.52 ms wide and the reading moved 82.570909 ms inside that interval. Those figures and the one below come from
`crates/clock/tests/two_kinds_of_source.rs`, which runs on the simulated harness rather than on a real
path, so they are the arithmetic of the model and not a reading from the wire. The sources that could have disagreed now decide who is in the
minority and the interval is swept over what is left standing, which can narrow a region only by
throwing a source out and never any other way. What it does not change is how much room the width
itself allows for a fault: that is still counted over every source that answered, so a wide source
still costs the interval something, 34.52 ms in the same round against the 12.52 ms of width the narrow
sources reach alone.

## The three evidence roles, which are not interchangeable

A receipt is worth something only if a stranger can check it, and that takes three different kinds of
evidence.

- **An authenticated UTC corridor** puts a signed interval round the moment that a stranger can
  check. A Roughtime response,
  where we generate the nonce and the server signs ours. It does not make the bound tighter: a
  Roughtime radius is a whole number of seconds, and the three public servers reachable on
  2026-09-07 were stating one, three and five.
- **A public freshness beacon** proves not-earlier-than, because the beacon value could not have been
  known before its round was published. A drand round, whose signature covers the round number and
  not the time.
- **An independent final witness** proves not-later-than: an RFC 3161 timestamp authority, a
  transparency log, or an anchor into a public chain.

NTS improves the clock and can never be portable evidence. Its keys are symmetric, so a client
holding one could forge a response to itself and a stranger has no signature to check. The receipt
format refuses an NTS response in an evidence role outright.

The agent's own bound goes in the receipt as well, structurally separate from all three, and labelled
as our claim. It is the most precise number in the receipt and the only one that rests on trusting
us.

## What TimeWitness cannot prove

This is a section of the product rather than a disclaimer at the foot of it. The full list, with the
reasoning and with what each kind of evidence actually says, is
[`docs/what-timewitness-cannot-prove.md`](docs/what-timewitness-cannot-prove.md). A reviewer who
knows this field should find nothing there that we did not say first.

The full list runs to 61 items. What follows groups them and leaves some out, so read the full list
before deciding whether this product does what you need. `scripts/three-surfaces.sh` holds that
number to the list itself, which is how an item added there and not summarised here gets noticed.

The short form:

**About time.** It cannot prove exact UTC over the public internet. The 5 to 50 ms, the 1 ms and the
100 microsecond figures are quoted from public research and none of them has been measured by us.
Nanoseconds is the resolution of the local read and never the accuracy to UTC. It cannot prove
elapsed time from a verifiable delay function, which proves sequential work. It cannot prove a
machine stayed alive through a power cut; it can record the gap. It cannot carry a bound far past
its last synchronisation, because the machine's own oscillator changes rate as it warms and cools:
on the shipped settings the agent refuses about sixteen minutes after the sources last answered
rather than reporting a number too wide to be worth anything, and that figure and the widths behind
it come from the simulated harness rather than from a real network. It cannot prove that this machine's
oscillator is the one the arithmetic assumes: every allowance for the oscillator rests on the rate
staying inside the band the policy states, which comes from a consumer crystal's published
specification and has never been measured by us on real hardware. The agent reads its own fitted
rate back against that band and widens by what it measured where the two disagree and the fit is
sharp enough to say so; where the fit's error bar is wider than the whole band, which is every fit
in the first rounds after a start, it has measured nothing and the widening is half the band.

**About the evidence.** An authenticated corridor makes the moment checkable to within seconds and
does not make the bound tighter, because a Roughtime radius is seconds. A beacon's signature covers a round number and not a
time, and rests on no coalition holding enough of a shared key. A beacon pins the receipt, not the
thing being stamped. A final witness attests the payload rather than the receipt, and is checked
against a certificate pinned in advance rather than chained to a root. Where parties who are meant to
be independent collude, a coherent false history can be manufactured. Using several time sources buys
one thing exactly: while fewer than half of them are wrong, the interval holds true UTC and no source
that disagrees with the others can narrow it, widen it or move it. Half of them wrong is not covered,
a source is not taken at its word about how certain it is, and a source in the minority can still
move the reading inside the interval a majority allows. A source that agrees with everything is a
different case and one the protection does not cover: a server stating a radius of an hour
contradicts nobody, and where two servers disagree and no majority exists without it, its arrival is
what turns a refusal into an interval wider than either of them supports.

**About what is stamped.** It cannot prove a photograph, a document or a recording is real; it binds
a hash to a bounded time. It cannot prove the software describing an event described it truthfully.
It cannot prove intent, cannot prove anything before the agent was installed, and cannot prove that
something did not happen.

**About what it does when something is wrong.** It does not prevent anything: a refusal records that
TimeWitness declined to sign, not that an action was stopped. It does not establish legal weight,
which comes from accreditation rather than engineering, and no regulation we have checked requires
tamper-evidence, cryptographic proof or clock accuracy.

**About what is built today.** Three time source clients exist in this repository, Roughtime, plain NTP and NTS, and only Roughtime signs anything a stranger can check, so the one that can be shown to a stranger is the one that cannot narrow the bound. A Roughtime server states its own uncertainty as a radius in whole seconds,
so a bound resting on Roughtime alone would be seconds wide whatever else is done to it, and the
shipped floor refuses such a round; a plain NTP server states a delay and a dispersion in units of
about fifteen microseconds and signs nothing at all. Measured against Roughtime alone on 2026-09-08, every one of them at the four rounds the Action
shipped that day: a bound of 16.219 s from a GitHub runner, a bound of 16.424 s on an ordinary desktop's receipt committed at that path then and since replaced, and a bound of 16.439 s from that same desktop, stamped at 11:08. Measured against two kinds
on 2026-09-09 at the sixteen rounds the Action ships now, on an ordinary desktop: 153.6 ms and 164.8 ms wide over the first two of three passes at 14:52, and a bound of 176.7 ms on that desktop's receipt committed at that path then and since replaced, taken at 15:05. At 12:09 UTC a GitHub runner reached a bound of 211.3 ms, and that desktop reached the same on the remaining one of its three. Every one of those is our own measurement on
the machine it names, and none of them is a figure for anybody else's machine. Measured with all three kinds on 2026-09-09 at the sixteen rounds the Action ships: 154.1 ms, 159.2 ms and 154.7 ms wide over three passes on an ordinary desktop at 20:28, and a bound of 149.8 ms on the receipt committed at that path then and since replaced, taken at 20:32, nine servers answering and nine kept. Measured again with the independence rule in, on the same desktop at the same sixteen rounds: 149.3 ms, 161.2 ms and 163.2 ms wide over three passes at 21:39, and a bound of 153.9 ms on the receipt committed in this repository at 21:41, nine servers behind six operators and nine kept. Enforcing independence narrowed nothing and was never going to, because the rule refuses rounds rather than narrowing them: the sources overlapping is 35.1 ms of half width on that receipt against 34.9 ms on the one before it. Measured through the resident agent on the same desktop on 2026-09-18, after the ageing of a source's interval over the local counter was bounded by the band, at thirty-six minutes of uptime and a thirty-two second polling cadence: 130.346 ms, 115.308 ms and 115.260 ms wide over three readings at 23:32, nine servers behind six operators and nine kept, with the sources overlapping at 37.991 ms of half width on the first and 36.830 ms on the other two. Measured through the resident agent with the independence rule in, on the same desktop on 2026-09-09, at the same uptime and the same cadence: 128.7 ms, 128.8 ms and 129.1 ms wide over three readings at 22:17, against 122.7 ms, 122.8 ms and 122.6 ms wide from the same agent at the same uptime and the same cadence before the rule at 21:04. The sources overlapping is 38.4 ms of half width there against 37.6 ms before the rule, so the six milliseconds between the two sets is a public network an hour apart rather than anything the rule did. The third kind narrowed nothing and the breakdown says so: the sources overlapping is 34.9 ms of half width on that nine-source receipt against 34.5 ms on the six-source one taken at 15:05, and what moved between the two receipts is the oscillator, 0.5 ms against 17.3 ms, which is how long after the last exchange each stamp was taken. Measured through the resident agent with all three kinds on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 122.7 ms, 122.8 ms and 122.6 ms wide over three readings at 21:04, against 133.5 ms, 136.8 ms and 128.9 ms wide from the same agent at the same uptime and the same cadence with two kinds at 16:27. The sources overlapping did not move there either, 37.6 ms of half width against 37.1 to 38.3 ms, so the ten milliseconds between the two sets is the fit and the oscillator rather than the sources. Measured through the resident agent on the same desktop on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 133.5 ms, 136.8 ms and 128.9 ms wide over three readings at 16:27, against 161.1 ms, 159.4 ms and 162.2 ms wide from the one-shot command on the same machine twelve minutes earlier. What the agent moved is one term: the model's own residual fell from 39.3 to 45.6 ms of half width on those one-shot runs to 24.3 to 25.0 ms, and the sources overlapping did not move at all, so on that machine the width is now set by the sources rather than by the fit. Of the 153.875 ms of width on the receipt committed in this repository, the largest single part is the model's own regression residual doubled by the coverage factor, 38.011 ms of half width, with 35.081 ms of the sources overlapping and 3.586 ms of the oscillator beside it, all four read 2026-09-10 off the verify command run on that receipt, which prints half widths. The ceiling that receipt was signed under was 30 s until 2026-09-15, so a reader reproducing the width today does so under a narrower one. The verify command prints the older ceiling off the receipt itself.
Polling more times does help and it is the shipped default that was wrong about which way: below
three rounds no line is fitted, so the scatter of the measurements is never measured and never
enters the width, and the bound at one round is narrower because less was measured rather than
because the clock is better known. Measured on this desktop at 12:54 and 12:56 on 2026-09-08 against
Roughtime alone, two passes at each setting: 6.2 s wide at one round, 17.4 s wide at three, 16.4 s wide at four,
12.0 s wide at sixteen and 10.4 s wide at thirty-two. So the figure this product leads with is its own bound, about 155 ms at sixteen rounds where the sources that narrow it are reachable. Where only Roughtime is reachable it now refuses, and the 12 s of width it reached there on 2026-09-08 is from before the operator floor. About one second is still the target and it is a target for something else: a bound
resting on third-party evidence rather than on the agent's own model, which nothing outside the
tests constructs, and which a timestamp authority writing whole seconds puts a floor under. That is
the rule underneath it, and it holds for everything this product says about itself: the prose may be
forward-looking and a number may not, because a reader reproduces a number and cannot reproduce a
plan. The agent runs only while somebody keeps it running: it installs no service, starts at no
boot, and is not running after a restart until a person starts it again. Leaving the agent running longer stops narrowing the bound after about thirty minutes. The model's own residual is the largest single part of the bound on the agent's path and it falls as synchronisations pile up, so a reader is likely to assume that an agent left up all day reaches a narrower number. It does not. `Policy::regression_window` is 1800 seconds and the model drops every point older than that before `history_capacity` binds, so at the shipped thirty-two second cadence the fit saturates at about fifty-six points after half an hour and never has more. Measured 2026-09-10 through the model's own simulated harness at that cadence, which is the arithmetic of the model and not a reading from a real path: the residual falls from 13.522 ms of half width at five minutes to 5.802 ms at the window, and is then 5.752 ms at forty minutes, at an hour, at ninety minutes and at two hours, the same number to the nanosecond. Measured the same day on an ordinary desktop through a resident agent against the nine published servers, one reading every three minutes: 47.704 ms of half width at five minutes of uptime, 22.262 ms at thirty-two minutes, and no lower after that. Whether thirty minutes is the right window is an open question about the regression rather than a setting anybody can change from outside. `timewitness agent` holds
one clock model, disciplines it against the sources every thirty-two seconds and answers a reading
to `timewitness stamp --agent`. The one line a workflow installs runs the one-shot command and not
the agent, so every receipt this product has issued in continuous integration came from a model
built and thrown away in the same job. A fresh agent refuses most readings for its first two minutes. The four settling rounds a fraction of a second apart buy the model a line to fit and nothing more. A reading is extrapolated over however long ago the last round was, so once the agent settles into its thirty-two second cadence the width sweeps up across each gap, and a fit whose baseline is under a second is being asked to reach thirty. The residual that comes out of that is far past the shipped 250 ms ceiling, and the agent refuses rather than signing an interval wider than the one it said it would sign. Measured 2026-09-18 on an ordinary Windows desktop against the nine published servers, at the shipped thirty-two second cadence and 250 ms ceiling, on two agents started in the same minute: one asked every five seconds for forty minutes, where the last refusal was at 102 s of uptime and 13 of the first 34 readings were refused, and one asked every ten seconds for seven minutes, where the last refusal was at 101 s and 8 of the first 17 were refused. It can sign once in its first seconds and then stop, which is worse than not signing at all for somebody who reads the first answer as the settled one: the first of those two signed at 3 s of uptime, right after the settling rounds, refused every reading from 9 s to 37 s, signed once at 43 s and refused again from 48 s to 67 s. What the settling rounds buy is a fit that exists, and not a fit worth signing. Measured the same way on the same machine on 2026-09-10, one reading every five seconds for twelve minutes, twice, the last refusal was at 166 s of uptime on one run and 168 s on the other, with 25 and 24 of the first 34 readings refused; the ageing of a source's interval changed on 2026-09-18, and the figures from that day are the ones that describe the code that ships. After it settles the agent still refuses a reading whenever the bound crosses the ceiling, and the share is not a fixed number. The shipped cadence is thirty-two seconds and the shipped ceiling is 250 ms, so the width sweeps up across each polling gap and where the top of that sweep lands is what decides whether a reading is signed. On an ordinary desktop the top of it sits close enough to the ceiling that the answer moves with the network. Measured 2026-09-18 on an ordinary Windows desktop at those settings, one reading every five seconds: nought refused of 101 readings from three to twelve minutes of uptime, at widths of 130.988 to 203.677 ms, and nought of 23 readings ten seconds apart from three to seven minutes on a second agent started in the same minute, at widths of 149.224 to 197.686 ms. Measured 2026-09-10 on the same machine, before the ageing of a source's interval changed, one reading every five seconds: nought refused of 100 readings from three to twelve minutes of uptime on one run and nought of 103 on a second, at widths of 144.636 to 238.409 ms and widths of 140.933 to 217.723 ms, and one refused of forty readings five seconds apart at five to eight minutes, at 254.047 ms of width against the 250 ms ceiling. So the share on one machine, measured on 2026-09-10 and 2026-09-18, is somewhere between nought and one in forty, and a deployment should expect a refusal now and then rather than never. The refusal is the design working rather than a fault: a wider interval says something true and a narrow wrong one does not, and the last good reading is never offered. The agent answers sixty-four callers at once and refuses the sixty-fifth. A cap is a refusal, so it is on this list with the rest of them. Every caller gets a thread of its own from 2026-09-10, and past `CALLERS_AT_ONCE` a caller is turned away in words rather than queued behind the others, because a queue behind a full cap is the same unavailability moved somewhere the caller cannot see it. Before that date the agent answered one caller at a time and its ceiling on waiting for a token before it looked at one was two seconds, so two sockets opened and left silent stopped the machine issuing receipts at all: measured on an ordinary Windows desktop, a legitimate ask took 56 ms alone and 40158 ms behind twenty of them. What the cap does not do is make the agent proof against somebody who already runs code on this machine. It turns a cheap permanent outage into an expensive temporary one: holding all sixty-four now costs a fresh connection every half second rather than two sockets opened once, and the agent stays up, answers the moment a slot frees, and says what happened. Somebody who can run code as this user has a worse move available anyway, which is to write the endpoint file. Three protocol implementations stand behind the nine servers a round asks, so at most three of the nine can fail for a different reason in the code. `SourceKind` names plain NTP, NTS, Roughtime and local hardware, and three of the four have a client, `crates/sources/src/roughtime.rs`, `crates/sources/src/ntp.rs` and `crates/sources/src/nts.rs`. What runs is three servers of each of those three kinds. Local hardware has no client and needs a receiver this product cannot assume anybody has. The README says four to six independent sources, and independent in this product means the operator rather than the protocol, which is the only reading the design supports: `SourceKind` has four variants, so six kinds cannot exist and a claim of four to six kinds could never be met. On the count this product defines and enforces the claim is met, at six operators with the shipped floor refusing below four. A count of protocols is a separate limitation and it is this one. A defect in one of the three source programs is one fault across three of the nine names at once, and no count of operators can see it. Three servers of each kind means three servers running the same protocol against the same client code here. Where the fault is in this repository it reaches every source of that kind whoever runs them, and where it is in a widely deployed server program it reaches every operator running it. The operator floor counts parties and a shared implementation is not a party, so the two limitations sit beside each other rather than one covering the other. What that leaves is three chances to be wrong in code against six chances to be wrong in the world. The nine servers a round asks stand behind six operators, and from 2026-09-09 the selection counts operators rather than names. Cloudflare, PTB and Netnod each answer on two of the three protocols, so three of the nine names were being counted twice. A source carries an operator, a majority of intervals resting on a minority of operators is refused, and the shipped policy will not sign on fewer than four operators standing behind the round, so a deployment pointing all nine servers at one company is refused rather than signed. What an operator count cannot see is a shared upstream, a shared network path, a shared satellite constellation and a shared implementation, so it is an upper bound on how independent a round was rather than a measurement of it. A receipt carries no measurement from any source, so nobody else can recompute its width. A receipt names each source and carries none of its timestamps, so a stranger can check that the parts of the width add up and cannot recompute any of them. The operator names the floor counts are strings the signer wrote. The verifier counts them rather than taking a count, and nothing in any of the three protocols lets it check them. A machine that can reach only the three public Roughtime servers reaches three operators, which is under the shipped floor of four, so it refuses to sign, and nothing that ships lowers the floor. No option on the command line and no input to the Action lowers it. NTS authenticates a source and can never be evidence for a bound. The keys come out of a TLS session and are symmetric, so this machine holds the same secret the server used and could compose any NTS reply it can then check successfully. It improves the clock and it is not a witness. Through the resident agent the reading behind a stamp is taken with no network call at all; through the one-shot command the network call that produced it is part of the same few seconds as the stamp. Every receipt this product issues says its bound rests on the agent's own model, so no
receipt yet carries third-party signed evidence for its bound. The resident agent refuses any interval wider than 250 ms, and the one-shot command, which the GitHub Action runs, refuses one wider than 2 s. Two
seconds is the narrowest interval a Roughtime corridor can state, and the widest receipt a build
runner has given us is 287.147 ms wide, on 2026-09-14 at sixteen rounds.
Order is checked two receipts at a time, and nothing walks a chain. `timewitness order` reads two
receipts offline and keeps two answers apart: the intervals say which moment came first, undecided
where they touch or overlap, and a hash link says which of two receipts of one chain was signed first.
Two receipts signed by different agent keys are not a chain, so only their intervals are compared. A countersigned exchange shows that two claims are consistent with an order and nothing more: neither side's interval is evidence for the other, an overlap is undecided, and the command that reads one ships from `v0.2`. There is no refusal receipt. A refusal is a return value inside the agent. Nothing signed
and nothing portable is produced, so there is no artefact a third party could be shown. There is no
released binary, so a stranger compiles the verifier rather than downloading it. Nothing links an
agent's key to anybody. A log of our keys is served at timewitness.dev/key-log.txt and names the keys of our two Roughtime servers and no agent key. The `v0` release cannot read it. There is no first-run figure from anybody outside.
One freshness beacon works rather than the two the design asks for. One kind of final witness works;
there is no OpenTimestamps anchor. Roughtime is an Internet-Draft and not an RFC: the IETF datatracker showed revision 19 in the RFC Editor Queue on 17 September 2026.
A sleep is detected and has never been watched happening: the agent reads the two counters an
operating system keeps, one that stops while the machine sleeps and one that does not, and refuses
until it has synchronised again, but nothing has put a real machine to sleep to watch it, and a sleep
shorter than a quarter of a second is not seen at all. The Windows path is run by hand on one machine
and not in continuous integration, which runs on Linux only. An agent that starts inside a leap smear
may not know it, because the announcement it would have latched was cleared before it started.
Nothing here stops any of it: a machine suspends, a second time service sets the clock, and a leap
second arrives, and all the agent controls is whether it signs afterwards.

## Checking a receipt

```
cargo build --release -p timewitness-cli
./target/release/timewitness verify a-receipt.cbor --subject the-thing-it-stamps
```

No account, nothing of ours involved, and no network. `bash scripts/build-verifier-page.sh` makes the
same verifier as one HTML file that runs from your own disk. What it checks and what it deliberately
does not is `docs/verifier.md`.

Because a check here reaches nothing of ours, almost none of it can be counted, and none of it is
guessed at. What may ever be counted, and how such a figure may be stated, is
`docs/counting-verifications.md`, held by `scripts/a-verification-figure-names-the-checker.mjs`
before there is anything to count.

## Stamping a build

One line in a workflow file:

```yaml
- uses: Fountech-ai-Limited/timewitness@v0.2
  with:
    subject: dist/widget.tar.gz
```

There is no configuration file and no secret to set. The receipt lands beside the artefact, goes into
the SLSA provenance and container image labels where those are named, and the workflow summary carries
what the receipt does and does not establish. The inputs are the ones in `action.yml` at the tag you
pin, so read that file at `v0.2` rather than here: an input added on `main` reaches a workflow only
with the release after it. `deadline` arrived in `v0.2`, so a workflow pinned to `@v0.1` that sets it
gets a warning from GitHub and no deadline.

On a host behind a firewall, `docs/destinations-and-ports.md` is every host, protocol and port the
agent and `stamp` reach, what each one is for, and what a blocked one costs. Two of them are plain
HTTP on port 80 rather than HTTPS on 443, which is the one people get wrong. Checking a receipt
reaches nothing on that list.

## Whether it still reaches the servers

[![Live](https://github.com/Fountech-ai-Limited/timewitness/actions/workflows/live.yml/badge.svg)](https://github.com/Fountech-ai-Limited/timewitness/actions/workflows/live.yml)

The badge reads the last run of `.github/workflows/live.yml`, once a day, which asks the published
Roughtime, NTP, NTS, drand and timestamp servers and checks each answer the way the agent does. Its
summary names every test and whether it answered, and the date of the run is the last time the live
integrations were seen working. The ordinary build does not ask them, because somebody else's server
being down is not a fault in a commit. Three tests that need a Roughtime server of ours are not run,
because none is deployed.

## Layout

Every module and what it may import from is in `docs/repo-layout.md`, and
`crates/architecture/tests/module_boundaries.rs` enforces it on every build.

## Building

```
cargo build --workspace
cargo test --workspace
```

## Licence

Apache License 2.0, in [LICENSE](LICENSE), copyright Fountech.ai Limited. Apache rather than MIT
because of what this is: the Action goes into other people's workflows and the receipt format is
something other people implement, so the patent grant in section 3 and the retaliation clause beside
it matter, and MIT has neither. [NOTICE](NOTICE) carries the copyright line that section 4d of the
licence propagates into anything derived from this.
