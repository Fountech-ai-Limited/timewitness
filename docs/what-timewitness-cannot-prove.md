# What TimeWitness cannot prove

Version 20, 2026-09-19. Supersedes version 19 of 2026-09-15, which it keeps whole and corrects in two
places, both of them the same fault. The claim at the head of the list said the outside evidence pins
the moment to a few seconds, and the note on version 18 said it again. An authority that states no
accuracy of its own has not stated a nought, so its token bounds nothing in UTC, and both authorities
that ship are in that state: the receipt committed in this repository is left with the beacon's edge
from below and nothing from above. The shipped verifier has said so since 2026-09-19 and these two
sentences had not caught up. The list still runs to 59 items. Six edits between version 19 and this
one carried no version note of their own, so this note covers what it names and the repository's
history covers the rest.

Version 19, 2026-09-15. Supersedes version 18 of the same day, which it keeps whole, corrects in six
places and adds two items to. The Roughtime-only path was called seconds wide in four places and the
shipped product refuses it: three operators is under the floor of four, and nothing that ships lowers
the floor, where this list said one line of configuration did. The front page was said to claim four
to six independent sources, and it is the README that does. A refusal was called a receipt in one
item while a later item says no refusal receipt exists. The one-shot command's ceiling moved from
30 s to 2 s, and the item on the ceilings now says what each path signs up to and why. The key item
names the log of our keys that is served. The two new items are that a receipt carries no
measurement from any source, so nobody can recompute its width, and that the operator names the
floor counts are strings the signer wrote. The list runs to 59 items rather than 57.

Version 18, 2026-09-15. Supersedes version 17 of 2026-09-11, which it keeps whole and corrects in two
places. The claim at the head of the list said the outside evidence in a receipt supports the
interval. It does not: every receipt says its bound rests on the agent's own model, and the outside
signatures say when the reading was taken rather than how wide the interval is. The claim now says
which is which. The item on the corridor said it makes the bound checkable and
that no ordinary time source runs here; it makes the moment checkable, and plain NTP and NTS run in
every stamp. The list still runs to 57 items.

Version 17, 2026-09-11. Supersedes version 16 of 2026-09-10, which it keeps whole and adds two items
to. A source that could not have disagreed with anybody no longer decides which
other source is in the minority, and the two new items say what that fixed and what it did not: three
Roughtime servers were voting on which narrow source had lied and were keeping a liar 200 ms out, and
how much room the width allows for a fault is still counted over every source that answered. The list
runs to 57 items rather than 55. Nothing else about it changed.

Version 16, 2026-09-10. Supersedes version 15 of the same day, which it keeps whole and corrects
in one place. Four figures here were attributed to the receipt committed at
`crates/verify/tests/data/a-real-stamp/receipt.cbor`, in the present tense, and only the last of
them can be reproduced from it: that fixture has been re-taken twice and each re-take left the
figures behind it standing. The three superseded ones stay, because the chronology of what this
product reached and when is the honest half of the item, and each now says in its own sentence that
the receipt it was taken from has been replaced. The sentence that breaks the width down into its
parts was reasoning from the wrong one of the four, and it is re-derived from the receipt that is
actually on disk: 153.875 ms wide, 38.011 ms of the model's own residual, 35.081 ms of the sources
overlapping and 3.586 ms of the oscillator, all four read 2026-09-10 at 17:38 off
`cargo run -q -p timewitness-cli -- verify` on that receipt. Nothing else about the list changed.
`scripts/three-surfaces.sh` moved in the same commit and stopped pinning those figures as prose:
it reads them off the receipt now, which is what would have caught this.

Version 15, 2026-09-10. Supersedes version 14 of the same day, which it keeps whole and adds
three items to, all three about the resident agent and what it refuses. Two of them are about
settling: a fresh agent will not answer at all for its first two or three minutes, and once it settles
it still refuses a reading now and then, at a share that is not a fixed number. Both were measured
twice on an ordinary desktop at the shipped cadence and ceiling, and the second measurement is on
the code that shipped rather than on the code that was read. The third is the cap on callers: the agent
answers sixty-four callers at once and turns the sixty-fifth away, which is a refusal and belongs
here rather than only in the source.

Version 14, 2026-09-10. Supersedes version 13 of the same day, which it keeps whole and adds one
item to. The list already said the agent runs only while somebody keeps it running. What it did not
say is that keeping it running stops helping: the regression looks back thirty minutes and nothing
older is in the fit, so an agent up all day reaches the same number as one up for half an hour. That
was measured rather than reasoned about, on a real desktop and again through the model's own
harness, and both readings are in the item.

Version 13, 2026-09-10. Supersedes version 12 of 2026-09-09, which it keeps whole and changes in one
item, splitting it into two. The item said there are three time source clients rather than the four
to six the design asks for. Four to six is the front page's claim and it is about independent
sources, and independent in this product is the operator: it is carried on the source, counted where
the survivors are counted, and floored at four, so a round short of it refuses rather than widens.
That reading is not a choice made to suit the count. It is the only reading the design supports,
because `SourceKind` has four variants, so a claim of four to six kinds could never be met by any
version of this product. On the count this product defines and enforces, nine servers stand behind
six operators and the claim is met.

What the old item was also carrying is a real limitation, and it is now an item of its own rather
than a clause inside a comparison to the wrong number. Three programs stand behind nine names, so a
defect in one of them is one fault across three of the nine at once, and an operator count cannot
see it. That leaves three chances to be wrong in code against six chances to be wrong in the world,
and both numbers are now on this list.

Version 12, 2026-09-09. Supersedes version 11 of the same day, which it keeps whole and changes in
two items, both of them because the word independent is now enforced in code rather than carried by
prose. A source names who runs it, the selection counts operators rather than names, and a round
that does not span enough of them refuses to be signed.

The count was also wrong, in the direction that flatters, and this list carried it. Version 11 said
the nine servers stand behind five operators. They stand behind six: Cloudflare answers on two of
the three protocols rather than all three, because the Roughtime server it publishes answered nothing
when this product tried it and is deliberately absent. Six is the corrected figure and it was read
off the shipped lists on 2026-09-09.

What has not changed is that an operator count is the most independent a round could have been and
not how independent it was. Two operators disciplined from the same national laboratory, reached over
the same transit, trusting the same satellites or running the same server program are one fault
however many companies they are. Nothing in NTP, NTS or Roughtime states any of those, so nothing
here can enforce them, and the item below says so rather than leaving a count to imply otherwise.

Version 11 superseded version 10 of the same day, which it kept whole and changed in
two items, both of them because a third kind of time source now runs. An NTS client joined the
Roughtime one and the plain NTP one, so the count of clients is three rather than two.

What that third kind buys is not a narrower bound, and this list says so before anything else. An
NTS exchange with a server has the same round trip and the same root distance as a plain NTP
exchange with the same server, so it contributes an interval of the same width, and the measurement
below shows exactly that. What it fixes is who is allowed to write a reply. A plain NTP answer is
unauthenticated, so anybody on the path can compose one, and three composed answers agreeing with
each other are a majority under the selection rule. An NTS answer cannot be composed without a key
held by the server and this machine.

Nor can it ever be evidence a stranger can check, and that is now on this surface rather than only
in the code. The keys are symmetric, so this machine holds the same secret the server used
and could compose any reply it can check. Roughtime remains the only source in the tree whose answer
a stranger can check.

One thing that version added that no earlier one carried: the nine servers behind a round stand
behind fewer operators than names. Its figure was five and the figure is six.

Version 10 superseded version 9 of the same day, which it kept whole and changed in
two items, both of them because a resident agent now runs. `timewitness agent` holds one clock model
between stamps and `timewitness stamp --agent` reads from it, so the item saying there is no
continuously running agent is gone and three narrower items stand where it was: the agent installs
nothing and runs only while somebody keeps it running, the one line a workflow installs does not use
it, and there are still two source clients rather than four to six. The item about a stamp taking a
network reading ten microseconds before the local read is now two cases rather than one, because on
one of the two paths the reading takes no network call at all. The width the agent reaches is
measured on this desktop against the one-shot command on the same machine twelve minutes apart, and
the item carries both sets of figures. Nothing was removed: what the agent buys is one term of the
width and the sources are now the largest.

Version 9 superseded version 8 of 2026-09-08, which it kept whole and changed in
three items, all of them because a second kind of time source now runs. A plain NTP client joined
the Roughtime one, so the count of clients is two rather than one, and the width came down from
seconds to about a fifth of a second on every machine we have measured, which is this desktop, the
receipt committed in the repository and a GitHub runner. Each of those figures says which machine it
came from and at what number of polling rounds, because a number without its conditions is not a
measurement. Nothing was removed from the list: the agent still does not stay
running, the sources are still two rather than the four to six the design asks for, and no receipt
yet rests its bound on anything but our own model.

Version 8 superseded version 7 of the same day, which it kept whole and changed in
three places. The sentence saying polling for longer barely helps was measured and is wrong: more rounds
narrows the bound, and the reason one round looks best is that below three rounds no line is fitted
and the scatter of the measurements never enters the width. And the three seconds-wide figures now
say the number of polling rounds they were taken at, because that number moves them and a figure
ships with the conditions it was measured under. The shipped default moved from four
rounds to sixteen in the same act. And the sentence saying no single source can narrow, widen or
move the interval is about a source that disagrees with the others, so it says that now, and the case
it was never about has an item of its own: a source that agrees with everything can turn a refusal
into an interval wider than any honest source supports.

Version 7 is the first written against
a reading of the product's claims rather than of its code, and it corrects the list rather than
adding to it. Four things it changes. The seconds-wide bound was attributed to the build runner and
is a fact about this product, which has one time source client. The largest part of that width was
said to be the servers' jitter and is the model's own regression residual on a two-second baseline.
The 5 to 50 ms, 1 ms and 100 microsecond figures were presented as ours and are quoted from public
research, and the holdover widths were presented as a reading from ordinary internet paths and come
from the simulated harness. Four things it adds: there is no continuously running agent, a stamp
takes a network reading ten microseconds before the local read, no receipt yet rests its bound on
third-party evidence, and the refusal ceiling ships at 250 ms while the Action raises it to 30 s.

Version 6 of the same day superseded version 5, which superseded version 4 of the same
day, which superseded versions 1 to 3 and section 8 of
the product specification of 2026-09-03. Section 8 had eleven items, written before any of the
evidence clients existed; version 1 added eleven that came out of building them. Versions 2 and 3
add three that came out of attacking the clock model: what using several sources actually buys, what
a source is not taken at its word about, and how far a bound can be carried past the last time the
sources answered. Version 4 moves four items in the built-today section, because the verifier and the
Action shipped on 2026-09-08 and three of the things this list said do not exist now do, and it adds
what a build runner's bound actually is, which is the number a reader of a receipt from CI meets.
Version 5 adds the two the list was missing about its own headline claim: that nothing verifies
order, and that a refusal receipt is a phrase rather than an artefact. Version 6 adds three that came
out of building the detection for the faults the environment causes: what a sleep detector has and
has not been watched doing, which platform the Windows path was run on, and what an agent that
started part way through a leap smear can and cannot see.

This is a section of the product, not a disclaimer at the foot of it. It ships in the README, on the
site and in the specification, in these words. A reviewer who knows this field should find nothing
here that we did not say first.

Read it as a list of things somebody might reasonably expect and will not get. Everything on it is
either a limit of the physics, a limit of what the three kinds of evidence actually say, or a limit
of what is built today. The last group is marked, because those move.

## The claim, so the limits have something to be limits of

TimeWitness says: at this local counter reading, UTC was somewhere in this interval, and here is
signed evidence from three parties who have never heard of us about when that reading was taken.
The interval is our own claim and the outside evidence does not vouch for it. That evidence is
checked, and on the receipt committed in this repository it holds the moment from below and not from
above: the beacon says the reading was not earlier than its round, and the timestamp authority states
no accuracy of its own, so nothing here puts a number on how wrong that authority's clock could be. A
bound resting on that evidence is what we are building towards. Bounded time and unbroken order. Not
accurate time.

## About time itself

**It cannot prove exact UTC over the public internet.** The design's bound is milliseconds and today's is about a sixth of a second on a machine that reaches the sources that narrow it. A machine that reaches only Roughtime is refused rather than given a wider bound, and the section on what is built says why. The 5 to 50 ms, the 1 ms and the 100
microsecond figures are quoted from public research and none of them has been measured by us. They
belong, in that order, to the public internet with no hardware of our own, to a good local network
against a stratum-1 source, and to a cloud instance with a hypervisor clock. A claim needing
microsecond truth needs hardware this product does not sell. Nanoseconds is the resolution of the
local read and never the accuracy to UTC; the two get confused constantly and that confusion is the
problem this product exists to fix.

**It cannot prove a figure that was measured somewhere else.** Every number above carries the
conditions it was measured under and says whose it is. A figure quoted without them is not a figure,
and a figure taken from somebody else's research and presented as ours is worse than no figure.

**It cannot prove elapsed time from a verifiable delay function.** Such a function proves sequential
work, which is a different thing.

**It cannot prove that a machine stayed alive and honest through a power cut or a network outage.**
It can record the gap. A bound says nothing across a suspend, because the machine has no idea how
long it was away.

**It cannot carry a bound far past its last synchronisation.** The machine's own oscillator changes
rate as it warms and cools, and nothing on the machine can see that happening. So the interval widens
as the gap grows, and past the point where it is too wide to be worth anything the agent refuses
rather than reporting a large number. On the shipped settings that point is about sixteen minutes
after the last time the sources answered. That figure and the widths behind it, 26.6 ms at the
moment of synchronising and 234.6 ms at fifteen minutes, come from the simulated harness at
`crates/clock/tests/common/mod.rs`, whose whole purpose is that the true offset is a number the test
wrote down; they are the arithmetic of the model rather than a reading from a real network. An agent
that cannot reach its sources stops issuing receipts; it does not issue worse ones.

**It cannot prove that this machine's oscillator is the one the arithmetic assumes.** Every
allowance the model derives for the oscillator rests on one assumption: that the rate of this
machine's counter stays inside the band the policy states for it, a hundred parts per million from
one end of the band to the other at the shipped settings, so the largest magnitude a part may
honestly show is fifty. Both figures are `Policy::frequency_span_ppm` in this tree. They come from a
consumer crystal's published specification across its temperature range, they are a choice about
hardware rather than a measurement, and nothing in this product has measured either on real
hardware. What the agent does do, from 2026-09-18, is read its own fitted rate back against that
band every time it fits one. Where the fit puts the machine outside the band and is sharp enough to
tell one rate in the band from another, the model stops claiming the rate and widens by the
magnitude it measured instead, so the interval holds what was seen rather than what was assumed.
Where the fit is not that sharp, and that means an error bar wider than the whole band, it has
measured nothing about this counter, so neither the magnitude nor the error bar is carried and the
widening is half the band, exactly as it is before any fit at all. That is what every start
produces, because the first rounds are a fraction of a second apart and a rate fitted across a
fraction of a second is the sources' own scatter divided by almost nothing. So what it cannot do is
see a machine outside the band until there is a fit sharp enough to say so, and there is none in
the first rounds after a start. On a machine outside the
band, nothing on this page is a promise the arithmetic can keep.

## About the evidence, and this is where most of the surprises are

The three evidence roles do different jobs and none of them does another's. Nothing below is a fault
in the parties involved; it is what their signatures actually say.

**An authenticated corridor does not tighten the bound.** A Roughtime server states a midpoint and a
radius in whole seconds, and the three public servers reachable on 2026-09-07 were stating one, three
and five. So a corridor is seconds wide. It puts a signed interval round the moment that a stranger
can check, and the millisecond figure comes from ordinary time sources rather than from it. Plain NTP
and NTS run in every stamp beside the corridor, and neither signs anything a stranger can check.
Anybody who expects Roughtime to be the precise part has the roles the wrong way round.

**A corridor does not prove the server's clock was right.** It proves that the holder of a named key
signed a statement covering a nonce we chose. The draft says so itself. A server whose clock is wrong
produces a perfectly valid response saying something false, which is why more than one is used and
why the corridor is only one of the three roles.

**More than one source is a limit and not a guarantee.** What using several sources buys is exactly
this: while fewer than half of them are wrong, the reported interval holds true UTC, and no source
that disagrees with the others can narrow it, widen it, or move it. That is the whole of the
protection and it stops at the edges. Half of them wrong is not covered. A source list whose names resolve to
one operator is covered from 2026-09-09 and was not before: the selection counts operators rather
than names and refuses a majority resting on too few of them, and what it still cannot see is two
operators sharing an upstream, a path, a constellation or a server program. A
source in the minority can still move the reading inside the interval a majority allows, because the
reading is a weighted summary and the interval is the claim.

**A source that agrees with everything is refused, and that is our own rule.** A server stating a
radius of an hour contradicts nobody, so it is never in the minority and the sentence above is not
about it. Two servers ten seconds apart at a radius of three
seconds agree nowhere, and the agent refuses. Add the hour-wide server and Marzullo's algorithm finds
a majority, because two of the three now allow every point between one server's floor and the other's
ceiling, and it signs an interval sixteen seconds wide where neither honest server supports more than
six. That interval does hold true UTC while at most one of the three is wrong, which is what the
algorithm promises, so nothing signed there is false.

This agent refuses it anyway, decided 2026-09-09. A source whose interval contains every other
interval in the round cannot be put in the minority by any answer the others could have given, so its
agreement costs it nothing; where setting those sources aside leaves the rest without a majority of
their own, nothing corroborated anything and the agent declines to sign. The rule only ever turns an
answer into a refusal. It never moves an interval and it never accepts anything the published
algorithm refuses, so the guarantee here is stricter than the standard rather than different from it.
The code is `crates/clock/src/marzullo.rs` and it states the departure at the head of the file.

**And a source that agrees with everything no longer decides who else has lied.** The rule above is
about a source that manufactures a majority on its own, and three sources can do between them what
none of them does alone. Three Roughtime servers state a radius of a second each and every NTP
interval fits inside all three of them, so none of them contains the other two and none of them was
set aside; all three then took part in deciding which of the narrow sources was in the minority.
They could not have disagreed with any of them. Measured on 2026-09-11 in
`crates/clock/tests/two_kinds_of_source.rs`, which runs on the simulated harness rather than on a real
path, so every figure in this item and the two below it is the arithmetic of the model and not a
reading from the wire: three honest NTP servers throw out a liar whose interval sits two hundred milliseconds off them, and adding three Roughtime servers kept him, taking the interval from 12.52 ms to 223.52 ms wide and moving the reading 82.570909 ms inside that interval. Nothing signed in either round was untrue and both held UTC. What was
wrong is that three faults were tolerated where none of the three had been earned.

From 2026-09-11 the sources that could have disagreed decide who is in the minority, and the interval
is taken over what is left standing. The same round now comes back at 34.52 ms of width with the liar thrown
out and the reading where it was. This can narrow an interval only by throwing a source out: a source
that does not reach the interval contributes nothing inside it, so dropping it cannot move an edge,
and an honest round where nobody is in the minority comes back exactly where it always did.

**What that second rule still does not cover, and it is a figure rather than a caveat.** How much
room the width allows for a fault is still counted over every source that answered, so a source that
could not have disagreed still buys the interval some room: 34.52 ms of width in the round above against the 12.52 ms of width the narrow sources reach on their own. Counting that over the sources that could have
disagreed is the same arithmetic pointed at the width, and it takes an ordinary honest round of four
agreeing servers down to the narrowest of them with no fault tolerance left, so it is a decision
about the claim rather than a defect to fix. It is still open.

**What that rule still does not cover.** It is about a source that could not have disagreed with
anybody, and a source can be informative and still be the one that is wrong. A server that overlaps
two others which contradict each other, without containing either, is doing real work: it excludes
everything outside itself, so it counts, and it can still be the broken one. Half or more of the
sources being wrong is not covered by any of this. A source list whose names resolve to one operator
is covered from 2026-09-09, by the operator count rather than by this rule, and the two are separate
tests that refuse separately.

**A source is not taken at its word about how certain it is.** Two of the four timestamps in an
exchange are the source's, and so is its statement about its own accuracy. A server willing to say it
spent the whole round trip thinking and that it knows its own time exactly is describing a point
rather than an interval, which is why no source's answer is taken narrower than the policy floor and
why a reply whose own two timestamps cannot both be true is dropped rather than reduced to something
usable.

**A beacon's signature does not cover the time.** A drand round signs the round number and nothing
else. The moment that round belongs to is arithmetic on the chain's published genesis and period,
which a verifier holds as part of the chain definition. A verifier that disagrees about the genesis
gets a different answer and no signature will tell it so.

**A beacon rests on a coalition not existing.** The chain used signs each round independently of the
one before it, so a group holding enough of the shared key could compute any future round today and
arbitrarily far ahead. Not-earlier-than therefore rests on that group not existing, not on
mathematics.

**A beacon pins the receipt, not the thing being stamped.** A receipt containing a value published at
three o'clock was finished after three o'clock. The file it is about can be from any time at all.

**A final witness attests the payload, not the receipt.** The timestamp authority is shown the hash
of what is being stamped, before the receipt exists, because a receipt cannot contain a token that
covers itself. So the not-later-than edge is about the payload rather than about the receipt as a
whole.

**A final witness does not prove its own clock either, and on the two authorities used it bounds
nothing at all.** It is that authority's word, signed. Neither of the two authorities used states any
accuracy, which is not a claim of perfection: it means neither puts a number on its own error. So
neither token bounds the moment in UTC, however good its signature is, and the verifier says so
rather than computing an edge. Until 2026-09-19 it did compute one, reading the absent field as a
stated nought, which is the narrowest the token could possibly be read. A reader who has read an
authority's published practice can say what they allow for that authority's clock, in their own
anchors, and the figure is then printed as theirs. Nothing that ships carries one.

**A timestamp token is checked against a pinned certificate, not a chain to a root.** What this code
establishes is that a token was signed by the key in a certificate chosen in advance. It does not
walk a chain to a commercial root, check revocation, or check the timestamping extended key usage.
That is a narrower statement than trusted, and it is the honest one for what the code does.

**Where several parties who are meant to be independent collude, a coherent false history can be
manufactured.** We do not claim to prevent that at runtime.

## About what is being stamped

**It cannot prove that a photograph, a document or a recording is real.** It binds a hash to a
bounded time. What the hash is of is somebody else's problem.

**It cannot prove that the software describing an event described it truthfully.** If the thing
calling the agent has been compromised, a correct receipt attests a false statement, precisely and
verifiably.

**It cannot prove intent.** It cannot show that a person meant to do the thing that was stamped,
without a confirmation step outside this product.

**It cannot prove anything about a time before the agent was installed.**

**It cannot prove that something did not happen.** Absence needs a defined universe of events and
authenticated proof that ingestion was complete, and this product has neither.

## About what it does when something is wrong

**It does not prevent anything.** A refusal records that TimeWitness declined to sign, and today
that record is a return value inside the agent rather than anything a third party can be shown. It
does not record an action being stopped, and there is no enforcement path in this design. A clock
rollback is the same: it is detected and recorded after the event, and nothing it enabled is undone.

**It does not establish legal weight.** Legal standing in this area comes from accreditation, meaning
qualified trust service provider status under eIDAS, and not from engineering. A private root is
admissible and never presumed. No regulation we have checked, including AI Act Article 12, SEC 17a-4
and FINRA 4511 and 6820, requires tamper-evidence, cryptographic proof or clock accuracy, so a
compliance claim built on any of them would be false. The timestamp authorities used here are free
services and none of them is a qualified trust service.

## About what is built today, which is the part that moves

Everything in this section is a fact about 2026-09-09 rather than about the design.

**A bound is about 155 ms where a machine reaches the sources that narrow it, measured 2026-09-09 at sixteen polling rounds on an ordinary desktop, and a machine that reaches only Roughtime is refused, where before the operator floor it got seconds.** Three time source clients exist in this repository, Roughtime, plain NTP
and NTS, and only Roughtime signs anything a stranger can check, so the one that can be shown to a
stranger is the one that cannot narrow the bound. A Roughtime server states its own uncertainty as a radius in whole seconds, so a
bound resting on Roughtime alone would be seconds wide whatever else is done to it, and the shipped
floor refuses such a round; a plain NTP server states a delay and a dispersion in units of about
fifteen microseconds and signs nothing at all.
Measured against Roughtime alone on 2026-09-08, every one of them at the four rounds the Action
shipped that day: a bound of 16.219 s from a GitHub runner, a bound of 16.424 s on an ordinary desktop's receipt committed at that path then and since replaced, and a bound of 16.439 s from that same desktop, stamped at 11:08. Measured against two kinds
on 2026-09-09 at the sixteen rounds the Action ships now, on an ordinary desktop: 153.6 ms and 164.8 ms wide over the first two of three passes at 14:52, and a bound of 176.7 ms on that desktop's receipt committed at that path then and since replaced, taken at 15:05. At 12:09 UTC a GitHub runner reached a bound of 211.3 ms, and that desktop reached the same on the remaining one of its three. Every one of those is our own measurement on
the machine it names, and none of them is a figure for anybody else's machine. Measured with all three kinds on 2026-09-09 at the sixteen rounds the Action ships: 154.1 ms, 159.2 ms and 154.7 ms wide over three passes on an ordinary desktop at 20:28, and a bound of 149.8 ms on the receipt committed at that path then and since replaced, taken at 20:32, nine servers answering and nine kept. Measured again with the independence rule in, on the same desktop at the same sixteen rounds: 149.3 ms, 161.2 ms and 163.2 ms wide over three passes at 21:39, and a bound of 153.9 ms on the receipt committed in this repository at 21:41, nine servers behind six operators and nine kept. Enforcing independence narrowed nothing and was never going to, because the rule refuses rounds rather than narrowing them: the sources overlapping is 35.1 ms of half width on that receipt against 34.9 ms on the one before it. Measured through the resident agent on the same desktop on 2026-09-18, after the ageing of a source's interval over the local counter was bounded by the band, at thirty-six minutes of uptime and a thirty-two second polling cadence: 130.346 ms, 115.308 ms and 115.260 ms wide over three readings at 23:32, nine servers behind six operators and nine kept, with the sources overlapping at 37.991 ms of half width on the first and 36.830 ms on the other two. Measured through the resident agent with the independence rule in, on the same desktop on 2026-09-09, at the same uptime and the same cadence: 128.7 ms, 128.8 ms and 129.1 ms wide over three readings at 22:17, against 122.7 ms, 122.8 ms and 122.6 ms wide from the same agent at the same uptime and the same cadence before the rule at 21:04. The sources overlapping is 38.4 ms of half width there against 37.6 ms before the rule, so the six milliseconds between the two sets is a public network an hour apart rather than anything the rule did. The third kind narrowed nothing and the breakdown says so: the sources overlapping is 34.9 ms of half width on that nine-source receipt against 34.5 ms on the six-source one taken at 15:05, and what moved between the two receipts is the oscillator, 0.5 ms against 17.3 ms, which is how long after the last exchange each stamp was taken. Measured through the resident agent with all three kinds on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 122.7 ms, 122.8 ms and 122.6 ms wide over three readings at 21:04, against 133.5 ms, 136.8 ms and 128.9 ms wide from the same agent at the same uptime and the same cadence with two kinds at 16:27. The sources overlapping did not move there either, 37.6 ms of half width against 37.1 to 38.3 ms, so the ten milliseconds between the two sets is the fit and the oscillator rather than the sources. Measured through the resident agent on the same desktop on 2026-09-09, at thirty-six minutes of uptime and a thirty-two second polling cadence: 133.5 ms, 136.8 ms and 128.9 ms wide over three readings at 16:27, against 161.1 ms, 159.4 ms and 162.2 ms wide from the one-shot command on the same machine twelve minutes earlier. What the agent moved is one term: the model's own residual fell from 39.3 to 45.6 ms of half width on those one-shot runs to 24.3 to 25.0 ms, and the sources overlapping did not move at all, so on that machine the width is now set by the sources rather than by the fit. Of the 153.875 ms of width on the receipt committed in this repository, the largest single part is the model's own regression residual doubled by the coverage factor, 38.011 ms of half width, with 35.081 ms of the sources overlapping and 3.586 ms of the oscillator beside it, all four read 2026-09-10 off the verify command run on that receipt, which prints half widths.
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
plan.

**The agent runs only while somebody keeps it running: it installs no service, starts at no boot,
and is not running after a restart until a person starts it again.** `timewitness agent` holds one
clock model, disciplines it against the sources every thirty-two seconds and answers a reading to
`timewitness stamp --agent`. It is a foreground process and there is no Windows service, no systemd
unit and no scheduler entry anywhere in this repository. So a machine that reboots overnight has no
agent in the morning, and the bound a stamp gets then is whatever a model built from nothing can
support.

**Leaving the agent running longer stops narrowing the bound after about thirty minutes.** The
model's own residual is the largest single part of the bound on the agent's path and it falls as
synchronisations pile up, so a reader is likely to assume that an agent left up all day reaches a
narrower number. It does not. `Policy::regression_window` is 1800 seconds and the model drops every
point older than that before `history_capacity` binds, so at the shipped thirty-two second cadence
the fit saturates at about fifty-six points after half an hour and never has more. Measured
2026-09-10 through the model's own simulated harness at that cadence, which is the arithmetic of the
model and not a reading from a real path: the residual falls from 13.522 ms of half width at five
minutes to 5.802 ms at the window, and is then 5.752 ms at forty minutes, at an hour, at ninety
minutes and at two hours, the same number to the nanosecond. Measured the same day on an ordinary
desktop through a resident agent against the nine published servers, one reading every three
minutes: 47.704 ms of half width at five minutes of uptime, 22.262 ms at thirty-two minutes, and no
lower after that. Whether thirty minutes is the right window is an open question about the
regression rather than a setting anybody can change from outside.

**The one line a workflow installs runs the one-shot command and not the agent, so every receipt
this product has issued in continuous integration came from a model built and thrown away in the
same job.** `action.yml` runs `timewitness stamp` with a polling round count and no `--agent`. A
build runner is a machine that has existed for ninety seconds, so there is nothing for an agent to
be resident on, and the answer to that is not a longer baseline: it is a bound resting on
third-party evidence.

**A fresh agent refuses most readings for its first two minutes.** The four settling rounds a
fraction of a second apart buy the model a line to fit and nothing more. A reading is extrapolated
over however long ago the last round was, so once the agent settles into its thirty-two second
cadence the width sweeps up across each gap, and a fit whose baseline is under a second is being
asked to reach thirty. The residual that comes out of that is far past the shipped 250 ms ceiling,
and the agent refuses rather than signing an interval wider than the one it said it would sign.
Measured 2026-09-18 on an ordinary Windows desktop against the nine published servers, at the
shipped thirty-two second cadence and 250 ms ceiling, on two agents started in the same minute: one
asked every five seconds for forty minutes, where the last refusal was at 102 s of uptime and 13 of
the first 34 readings were refused, and one asked every ten seconds for seven minutes, where the
last refusal was at 101 s and 8 of the first 17 were refused. It can sign once in its first seconds
and then stop, which is worse than not signing at all for somebody who reads the first answer as the
settled one: the first of those two signed at 3 s of uptime, right after the settling rounds,
refused every reading from 9 s to 37 s, signed once at 43 s and refused again from 48 s to 67 s.
What the settling rounds buy is a fit that exists, and not a fit worth signing. Measured the same
way on the same machine on 2026-09-10, one reading every five seconds for twelve minutes, twice, the
last refusal was at 166 s of uptime on one run and 168 s on the other, with 25 and 24 of the first
34 readings refused; the ageing of a source's interval changed on 2026-09-18, and the figures from
that day are the ones that describe the code that ships.

**After it settles the agent still refuses a reading whenever the bound crosses the ceiling, and the
share is not a fixed number.** The shipped cadence is thirty-two seconds and the shipped ceiling is
250 ms, so the width sweeps up across each polling gap and where the top of that sweep lands is what
decides whether a reading is signed. On an ordinary desktop the top of it sits close enough to the
ceiling that the answer moves with the network. Measured 2026-09-18 on an ordinary Windows desktop
at those settings, one reading every five seconds: nought refused of 101 readings from three to
twelve minutes of uptime, at widths of 130.988 to 203.677 ms, and nought of 23 readings ten seconds
apart from three to seven minutes on a second agent started in the same minute, at widths of 149.224
to 197.686 ms. Measured 2026-09-10 on the same machine, before the ageing of a source's interval
changed, one reading every five seconds: nought refused of 100 readings from three to twelve minutes
of uptime on one run and nought of 103 on a second, at widths of 144.636 to 238.409 ms and widths of
140.933 to 217.723 ms, and one refused of forty readings five seconds apart at five to eight
minutes, at 254.047 ms of width against the 250 ms ceiling. So the share on one machine, measured on
2026-09-10 and 2026-09-18, is somewhere between nought and one in forty, and a deployment should
expect a refusal now and then rather than never. The refusal is the design working rather than a
fault: a wider interval says something true and a narrow wrong one does not, and the last good
reading is never offered.

**The agent answers sixty-four callers at once and refuses the sixty-fifth.** A cap is a refusal, so
it is on this list with the rest of them. Every caller gets a thread of its own from 2026-09-10, and
past `CALLERS_AT_ONCE` a caller is turned away in words rather than queued behind the others,
because a queue behind a full cap is the same unavailability moved somewhere the caller cannot see
it. Before that date the agent answered one caller at a time and its ceiling on waiting for a token before it looked at one was two seconds, so two sockets opened and left silent stopped the machine issuing receipts
at all: measured on an ordinary Windows desktop, a legitimate ask took 56 ms alone and 40158 ms
behind twenty of them. What the cap does not do is make the agent proof against somebody who already
runs code on this machine. It turns a cheap permanent outage into an expensive temporary one:
holding all sixty-four now costs a fresh connection every half second rather than two sockets opened
once, and the agent stays up, answers the moment a slot frees, and says what happened. Somebody who
can run code as this user has a worse move available anyway, which is to write the endpoint file.

**Three protocol implementations stand behind the nine servers a round asks, so at most three of the
nine can fail for a different reason in the code.** `SourceKind` names plain NTP, NTS, Roughtime and
local hardware, and three of the four have a client, `crates/sources/src/roughtime.rs`,
`crates/sources/src/ntp.rs` and `crates/sources/src/nts.rs`. What runs is three servers of each of
those three kinds. Local hardware has no client and needs a receiver this product cannot assume
anybody has. The README says four to six independent sources, and independent in this product
means the operator rather than the protocol, which is the only reading the design supports:
`SourceKind` has four variants, so six kinds cannot exist and a claim of four to six kinds could
never be met. On the count this product defines and enforces the claim is met, at six operators with
the shipped floor refusing below four. A count of protocols is a separate limitation and it is this
one.

**A defect in one of the three source programs is one fault across three of the nine names at once,
and no count of operators can see it.** Three servers of each kind means three servers running the
same protocol against the same client code here. Where the fault is in this repository it reaches
every source of that kind whoever runs them, and where it is in a widely deployed server program it
reaches every operator running it. The operator floor counts parties and a shared implementation is
not a party, so the two limitations sit beside each other rather than one covering the other. What
that leaves is three chances to be wrong in code against six chances to be wrong in the world.

**The nine servers a round asks stand behind six operators, and from 2026-09-09 the selection counts
operators rather than names.** Cloudflare, PTB and Netnod each answer on two of the three protocols,
so three of the nine names were being counted twice. The selection rule discards a source whose
interval does not overlap the majority, and that guarantee holds only where fewer than half the
sources are wrong, which needs them to be wrong separately. Sources under one operator fail together
and lie together, so a count of names is not the count the guarantee rests on. Three things now
enforce that rather than describe it: a source carries an operator, a majority of intervals resting
on a minority of operators is refused, and the shipped policy will not sign on fewer than four
operators standing behind the round. A deployment pointing all nine servers at one company is refused
rather than signed. The receipt carries the operator beside each source, and not a count of them, so
a reader does the arithmetic and gets their own answer rather than ours.

**What an operator count cannot see is a shared upstream, a shared network path, a shared satellite
constellation and a shared implementation, so it is an upper bound on how independent a round was
rather than a measurement of it.** Two operators disciplined by the same national laboratory move
together when it moves. Two servers reached over the same transit are one on-path attacker. Most
stratum-1 servers in the world are disciplined by GPS, and one spoofed constellation moves every
operator that trusts it. One defect in a widely deployed server program is one fault across every
operator running it. No field in NTP, NTS or Roughtime states any of the four, so nothing in this
product can check them, and the number it reports is the largest the round could have been rather
than what it was. Where the operator itself is in doubt, two names are treated as one company rather
than two, because merging can only lower the count and refuse, while splitting inflates the very
floor that is supposed to catch it.

**A receipt carries no measurement from any source, so nobody else can recompute its width.** For each source it names an id, a
kind, an operator, a timescale, the leap and smear state and whether the source was kept. It carries
none of the four timestamps of an exchange, no round trip and no uncertainty a source stated. So a
stranger can check that the parts of the width add up to the width and that a majority was kept, and
cannot work out any part of it from what the sources said. The width is the agent's arithmetic on
measurements only the agent saw. A receipt format that carries them would be version 1, and it is
not built.

**The operator names the floor counts are strings the signer wrote.** The verifier counts operators from
the labels in the receipt rather than taking a count the receipt states, which stops the agent's
arithmetic being checked against itself. It does not stop the labels being made up. A signer running
nine servers at one company could name nine companies, and nothing in NTP, NTS or Roughtime lets a
reader see which company answered. A Roughtime corridor, where one is carried and checked, is signed
by a key the reader holds, and every other operator name is the signer's word.

**A machine that can reach only the three public Roughtime servers reaches three operators, which is
under the shipped floor of four, so it refuses to sign, and nothing that ships lowers the floor.**
That path was the seconds-wide one until 2026-09-09. The shipped product now declines it on two
counts: the operator floor refuses the round before any width is looked at, and the width ceilings
refuse it as well, 250 ms through the resident agent and, on the one-shot command the Action runs, a 2 s ceiling.
No option on the command line and no input to the Action lowers the floor. It is `min_operators` in
`Policy::default`, in `crates/clock/src/policy.rs`, so lowering it means building from a changed
source. That is deliberate, because a product whose independence floor bends to whatever the network
gave it today has a floor in name only. Every seconds-wide figure on this list is from before the
floor, and none of them is a receipt the shipped product issues.

**NTS authenticates a source and can never be evidence for a bound.** The keys come out of a TLS
session and are symmetric, so this machine holds the same secret the server used and could compose
any NTS reply it can then check successfully. A signature is evidence because the checker cannot
produce it. `SourceKind::Nts` answers no to `carries_third_party_signature`, an NTS exchange carries
no attestation, and nothing from that client appears in a receipt in any of the three evidence roles.
It improves the clock and it is not a witness.

**Through the resident agent the reading behind a stamp is taken with no network call at all; through the one-shot command the network call that produced it is part of the same few seconds as the stamp.** This is about the reading and the bound and not about the whole run: gathering the three attestations is network work either way, and the receipt says how many it carries. The verifier prints the age of the newest exchange behind the interval on every receipt, so a reader can see how long the model extrapolated for; that age is read off the receipt, and the receipt is the signer's. What the agent buys is not free either: the reading is extrapolated over however long ago the last round was, and the model charges for that, so the term for the oscillator grows as the term for the fit falls.

**Every receipt this product issues says its bound rests on the agent's own model, so no receipt yet
carries third-party signed evidence for its bound.** All three evidence roles are fetched, carried
in the receipt and checked by the verifier against keys a reader chose in advance. What none of them
does is support the width: the receipt's own bound is the agent's claim and is labelled as one. The
format can express a bound resting on outside signatures and nothing issues a receipt that does.

**The resident agent refuses any interval wider than 250 ms, and the one-shot command, which the
GitHub Action runs, refuses one wider than 2 s.** Read on 2026-09-15 off `max_bound_width` in
`Policy::default`, in `crates/clock/src/policy.rs`, off `CI_MAX_BOUND_WIDTH` in
`crates/cli/src/stamp_cmd.rs`, and off the `max-width` input in `action.yml`. Only the agent holds
itself to 250 ms. The one-shot path needs a ceiling of its own, because the widest receipt the one-shot command on a build runner has given us, 287.147 ms wide on 2026-09-14 at sixteen rounds, is already past the agent's. Two
seconds is the narrowest interval a Roughtime corridor can state, a radius of one second either side,
so a bound wider than that says less than one signed corridor already tells a stranger. It is about
seven times that runner's width, and about nine times the bound of 211.3 ms another runner reached on
2026-09-09. The ceiling was 30 s until 2026-09-15, sized for the 16.219 s of width a runner reached against
Roughtime alone on 2026-09-08, a round the operator floor has refused since 2026-09-09. Every receipt
the one-shot command signed before 2026-09-15 states that older ceiling in its own policy, the one at
`crates/verify/tests/data/a-real-stamp/` included.

**Nothing verifies order.** Every receipt carries a sequence number and the hash of the receipt
before it, both signed, and no code anywhere compares two receipts, so nothing that exists today can
put two receipts in order. The claim this product opens with is bounded time and unbroken order, and
the second half of it is carried rather than checked.

**There is no refusal receipt.** A refusal is a return value inside the agent. Nothing signed and
nothing portable is produced, so there is no artefact a third party could be shown. The phrase reads
as a description of something that exists and it describes something that does not.

**There is no released binary, so nothing is downloadable.** The verifier is built and works, as a
command line tool and as one HTML page that runs from a local disk with no network. Both are built
from source in this repository. The `v0` release carries no binary and there is no published page,
so today a stranger compiles it rather than downloading it.

**Nothing links an agent's key to anybody.** A receipt proves that whoever signed it held that key.
A log of our keys is served at timewitness.dev/key-log.txt and names the keys of our two Roughtime servers and no agent key. So a reader who does not already recognise an agent key learns only that one key
signed this. The `v0` release refuses that log's format by name, so reading it takes a verifier built
from `main` until a later release. The Action generates a key on the runner where none is
supplied, which is what keeps the install to one line and is exactly as meaningful as that sounds.

**There is no first-run figure from anybody who is not us.** Nobody outside has run it.

**One freshness beacon works, not two.** The design names drand, the NIST beacon and the UChile
beacon, and asks for at least two. Only drand is verified here. On 2026-09-07 the NIST beacon's
pulses did not satisfy its own published rule that the output value is the SHA-512 of the signature,
and the certificate a pulse names by hash carried a 2048-bit key while the signature was 4096-bit;
those two cannot both be right, so no client was written for it. The UChile beacon was not serving
its interface at all.

**One kind of final witness works, not two.** RFC 3161 timestamp tokens are verified. An
OpenTimestamps anchor into a public chain is named in the design and is not built.

**A sleep is detected and has never been watched happening.** An operating system keeps two counters,
one that stops while the machine is suspended and one that carries on, and the difference between
them is how long the machine was away. The agent reads both; on a resume it throws away everything it
measured before the gap and refuses to stamp until it has synchronised again. The arithmetic is
tested against counters a test wrote down. Nothing has put a real machine to sleep and watched it
come back, because that is not something a test suite does to the machine it is running on. A sleep
shorter than a quarter of a second is below the resolution of the counters being compared and is not
seen at all.

**The Windows path is run by hand on one machine and not in continuous integration.** Continuous
integration runs on Linux only. The Windows time service contends with any other discipliner, which
is why the agent measures and vouches rather than taking the clock, and the counters that see a
suspend are read through Windows interfaces that no build runner in this project executes. They were
run on a Windows desktop on 2026-09-08, and they run there whenever the suite does, which is a
developer's machine rather than a gate.

**An agent that starts inside a leap smear may not know it.** A leap second is announced hours before
it happens and the announcement is cleared the moment it has, which is the moment a source spreading
the second across a day starts diverging from one that inserted it. An agent that was running sees
the announcement, remembers it, and stays on guard for the whole of the window. An agent started
after the announcement cleared never saw it. It can still refuse where the sources disagree about
smearing by an amount that could be one second spread out, and where every source in the pool smears
the same way there is nothing to disagree about: the bound then holds those sources and those sources
are deliberately not on UTC for that day.

**Nothing here stops any of it.** A machine suspends whether the agent likes it or not, a second time
service sets the clock before the agent sees anything, and a leap second arrives on schedule. Every
one of these is recorded after the fact. What the agent controls is whether it puts its name to a
reading taken afterwards.

**Roughtime is an Internet-Draft and not an RFC.** The version implemented is
`draft-ietf-ntp-roughtime-19`, with intended status Experimental. Read off the IETF datatracker on
17 September 2026, that revision was in the RFC Editor Queue, which is where a draft waits before it
is published as an RFC, and a place in that queue is not a publication date. The version number on
the wire is the draft's own testing number rather than the one the published RFC would use, so
publication may change what a server answers on. What moves then is the reference rather than the
receipts: a receipt already issued stays checkable, because the verifier carries the rules it was
signed under.

**Only RSA signatures are checked on timestamp tokens.** One of the four free authorities tried signs
with ECDSA, and its tokens are refused by name rather than skipped past.

**A pinned certificate goes stale.** When a timestamp authority replaces its signing certificate,
fetching a new token starts failing until the pin is updated. Tokens already inside receipts stay
checkable, because the certificate travels inside the token.

## How to check this list rather than believe it

Every claim above about what the code does has a test behind it and the tests are in the repository.
The three reports at `docs/test-reports/roughtime-watched-failing-2026-09-07.md`,
`drand-watched-failing-2026-09-07.md` and `rfc3161-watched-failing-2026-09-07.md` each name a check,
name the test that catches it, and record the run where that check was taken out of the code and the
test watched failing. The evidence itself, captured from the real servers, is committed beside them.
