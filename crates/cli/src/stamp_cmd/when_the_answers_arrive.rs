//! When each answer arrives, which is the one thing a stamp does not get to choose.
//!
//! Every party outside the machine is played here by the test, on a clock the test keeps, so a server
//! that takes five seconds to time out takes five seconds of that clock and none of the test's. What
//! the parties hand back is real: drand rounds fetched from the relays, a Roughtime corridor signed by
//! roughtime.se and a DigiCert token, none of them signed by anybody who has heard of this product.
//! So the receipt each test ends with is read by the verifier that ships, with the keys that ship, and
//! the only thing the test decides is when.
//!
//! The case these were written for was found on 2026-10-08. The released v0.8 stamp took its reading,
//! asked a corridor server, then asked drand for its newest round. Something on the way took long
//! enough for a round to be published after the latest moment the receipt claimed, by 2.204 s, and
//! the stamp wrote the receipt anyway. Its own `verify` refused it.

use std::cell::Cell;
use std::rc::Rc;

use timewitness_core::evidence::drand::{pack_blob, Chain};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI, NANOS_PER_SEC};
use timewitness_core::{Attestation, MonotonicNanos, UnixNanos};
use timewitness_receipt::schema::{Payload, Role};
use timewitness_receipt::AgentKey;
use timewitness_verify::{anchor_file, verify, Assessment, Floor, Subject};

use super::{finish, late_rather_than_wrong, Deadline, Made, Outside, Reading, Signing};

const SECOND: Nanos = NANOS_PER_SEC;

/// The second drand quicknet published round 32000947 in, which every capture here sits round.
const ROUND_32000947: Nanos = 1_788_806_205 * SECOND;

/// The subject every capture is about: thirty-two bytes of 0x5a, standing in for a hash.
const SUBJECT: [u8; 32] = [0x5a; 32];

const ROUNDS_HERE: &str = include_str!("../../tests/data/drand-quicknet-rounds.txt");
const ROUNDS_IN_CORE: &str = include_str!("../../../core/tests/data/drand/rounds.txt");
const CORRIDOR: &str = include_str!("../../../receipt/tests/data/sandwich/roughtime.hex");
const CORRIDOR_NONCE: &str =
    include_str!("../../../receipt/tests/data/sandwich/roughtime-nonce.hex");
const WITNESS: &str = include_str!("../../../receipt/tests/data/sandwich/rfc3161.hex");
const WITNESS_NONCE: &str = include_str!("../../../receipt/tests/data/sandwich/rfc3161-nonce.hex");

/// A receipt a real stamp wrote, whose reading and bound stand in for this machine's.
const A_REAL_READING: &str =
    include_str!("../../../verify/tests/data/a-version-1-stamp/receipt.hex");

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

/// The clock every party in a test reads, in nanoseconds since 1970.
#[derive(Clone)]
struct Clock(Rc<Cell<Nanos>>);

impl Clock {
    fn at(nanos: Nanos) -> Self {
        Self(Rc::new(Cell::new(nanos)))
    }

    fn now(&self) -> Nanos {
        self.0.get()
    }

    fn pass(&self, nanos: Nanos) {
        self.0.set(self.0.get() + nanos);
    }
}

/// One party's answer: how long it takes, and what it gives.
struct Answer<T> {
    takes: Nanos,
    gives: Result<T, String>,
}

fn after<T>(takes: Nanos, gives: Result<T, String>) -> Answer<T> {
    Answer { takes, gives }
}

fn times_out<T>() -> Answer<T> {
    after(5 * SECOND, Err("the source did not answer in time".into()))
}

/// Every party outside the machine, played by the test.
struct Elsewhere {
    clock: Clock,
    /// Every round the relays hold, by number, with its signature.
    rounds: Vec<(u64, Vec<u8>)>,
    /// How long a relay takes to answer.
    beacon_takes: Nanos,
    /// How far behind the chain's schedule the relays are.
    beacon_lag: Nanos,
    corridors: Vec<(String, Answer<Option<Attestation>>)>,
    witnesses: Vec<(String, Answer<(Attestation, bool)>)>,
    /// What every authority hands back when shown the digest of the signature.
    over_the_signature: Result<Vec<u8>, String>,
}

impl Elsewhere {
    fn at(clock: &Clock) -> Self {
        let mut rounds = Vec::new();
        for line in ROUNDS_HERE.lines().chain(ROUNDS_IN_CORE.lines()) {
            let mut words = line.split_whitespace();
            let (Some(round), Some(signature)) = (words.next(), words.next()) else {
                continue;
            };
            if let Ok(round) = round.parse::<u64>() {
                rounds.push((round, unhex(signature)));
            }
        }
        Self {
            clock: clock.clone(),
            rounds,
            beacon_takes: 100 * NANOS_PER_MILLI,
            beacon_lag: 0,
            corridors: Vec::new(),
            witnesses: vec![(
                "DigiCert".into(),
                after(0, Err("did not answer in this test".into())),
            )],
            over_the_signature: Err("did not answer in this test".into()),
        }
    }

    fn take<T: Clone>(&self, answer: &Answer<T>) -> Result<T, String> {
        self.clock.pass(answer.takes);
        answer.gives.clone()
    }
}

fn time_of(round: u64) -> Nanos {
    let seconds = Chain::quicknet()
        .time_of(round)
        .expect("a round on the schedule");
    i128::from(seconds) * SECOND
}

impl Outside for Elsewhere {
    fn beacon(&mut self) -> Result<Attestation, String> {
        self.clock.pass(self.beacon_takes);
        let held_by = self.clock.now() - self.beacon_lag;
        let chain = Chain::quicknet();
        self.rounds
            .iter()
            .filter(|(round, _)| time_of(*round) <= held_by)
            .max_by_key(|(round, _)| *round)
            .map(|(round, signature)| {
                Attestation::at_instant(
                    Vec::new(),
                    pack_blob(&chain.hash, *round, signature),
                    UnixNanos(time_of(*round)),
                )
            })
            .ok_or_else(|| "the relays hold no round yet".into())
    }

    fn beacon_name(&self) -> String {
        Chain::quicknet().name.to_string()
    }

    fn corridor_servers(&self) -> Vec<String> {
        self.corridors
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn corridor(&mut self, server: usize, _: &[u8; 32]) -> Result<Option<Attestation>, String> {
        self.take(&self.corridors[server].1)
    }

    fn authorities(&self) -> Vec<String> {
        self.witnesses
            .iter()
            .map(|(name, _)| name.clone())
            .collect()
    }

    fn witness(&mut self, authority: usize, _: &[u8; 32]) -> Result<(Attestation, bool), String> {
        self.take(&self.witnesses[authority].1)
    }

    fn witness_signature(&mut self, _: usize, _: &[u8; 32]) -> Result<Vec<u8>, String> {
        self.over_the_signature.clone()
    }

    fn now(&self) -> MonotonicNanos {
        // The test's one clock stands in for the monotonic counter as well, which is what makes the
        // time since the reading the time every party took to answer and nothing else.
        MonotonicNanos(u64::try_from(self.clock.now()).expect("a time after 1970"))
    }
}

/// The corridor roughtime.se signed over the subject: a second either side of 1788806207.
fn the_corridor() -> Attestation {
    Attestation::over_interval(
        unhex(CORRIDOR_NONCE),
        unhex(CORRIDOR),
        UnixNanos(1_788_806_207 * SECOND),
        SECOND,
    )
}

/// The token DigiCert signed over the subject, at the end of the second it names.
fn the_witness() -> Attestation {
    Attestation::at_instant(
        unhex(WITNESS_NONCE),
        unhex(WITNESS),
        UnixNanos(1_788_806_209 * SECOND),
    )
}

/// A reading taken now on the test's clock, claiming the moment was `claimed_ago` before it.
///
/// The bound is a real stamp's, moved whole to the moment wanted, so its width and every term in it
/// are ones a model actually produced.
fn a_reading(clock: &Clock, claimed_ago: Nanos) -> impl FnOnce() -> Result<Reading, String> {
    let clock = clock.clone();
    move || {
        let mut carrier = timewitness_receipt::open(&unhex(A_REAL_READING))
            .map_err(|e| format!("the committed receipt would not open: {e}"))?;
        carrier.evidence.clear();
        let shift = clock.now() - claimed_ago - carrier.utc_estimate.as_nanos();
        carrier.utc_estimate = UnixNanos(carrier.utc_estimate.as_nanos() + shift);
        carrier.claim.earliest = UnixNanos(carrier.claim.earliest.as_nanos() + shift);
        carrier.claim.latest = UnixNanos(carrier.claim.latest.as_nanos() + shift);
        clock.pass(NANOS_PER_MILLI);
        Ok(Reading {
            carrier,
            notes: Vec::new(),
        })
    }
}

fn stamp(
    outside: &mut Elsewhere,
    read: impl FnOnce() -> Result<Reading, String>,
) -> Result<Made, String> {
    stamp_with(outside, read, true)
}

fn stamp_with(
    outside: &mut Elsewhere,
    read: impl FnOnce() -> Result<Reading, String>,
    with_evidence: bool,
) -> Result<Made, String> {
    let key = AgentKey::from_seed(&[0x22; 32]);
    let signing = Signing {
        key: &key,
        subject_hash: SUBJECT,
        payload: Payload {
            algorithm: "sha-256".into(),
            hash: SUBJECT.to_vec(),
        },
        sequence: 1,
        previous: None,
    };
    finish(outside, read, signing, with_evidence, Deadline::of(300))
}

/// What `timewitness verify` says, with no options, of the bytes the stamp would write.
fn read_as_a_stranger(made: &Made) -> Assessment {
    verify(
        &made.signed,
        Subject::Digest(&SUBJECT),
        &anchor_file::published(),
        &Floor::default(),
    )
}

fn why_refused(assessment: &Assessment) -> String {
    assessment.refusal().map_or_else(
        || assessment.headline(),
        |step| format!("{}: {}", step.question, step.state.detail()),
    )
}

fn the_beacon(made: &Made) -> Option<UnixNanos> {
    made.receipt
        .evidence
        .iter()
        .find(|e| e.role == Role::NotEarlierThan)
        .map(|e| e.at)
}

#[test]
fn a_slow_corridor_does_not_put_the_beacon_after_the_reading() {
    // A second after round 32000947, and two before the next. Every corridor server times out, five
    // seconds each, which is fifteen seconds in which five more rounds are published.
    let clock = Clock::at(ROUND_32000947 + SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = ["roughtime.int08h.com", "roughtime.se", "time.txryan.com"]
        .iter()
        .map(|name| ((*name).to_string(), times_out()))
        .collect();

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    let beacon = the_beacon(&made).expect("a beacon, fetched before the corridor was asked");
    assert!(
        beacon <= made.receipt.claim.latest,
        "the beacon was published {} ns after the latest moment the receipt claims",
        beacon.as_nanos() - made.receipt.claim.latest.as_nanos()
    );
    assert_eq!(
        beacon.as_nanos(),
        ROUND_32000947,
        "the round published before the reading"
    );
}

#[test]
fn a_corridor_that_answers_too_late_is_set_aside_rather_than_written() {
    // Half a second after round 32000947. roughtime.se takes a second and a half, and the corridor it
    // signs runs from 1788806206, which is after the latest moment the reading can claim.
    let clock = Clock::at(ROUND_32000947 + SECOND / 2);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = vec![
        (
            "roughtime.se".into(),
            after(1_500 * NANOS_PER_MILLI, Ok(Some(the_corridor()))),
        ),
        (
            "time.txryan.com".into(),
            after(50 * NANOS_PER_MILLI, Err("refused".into())),
        ),
    ];

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert!(
        made.receipt
            .evidence
            .iter()
            .all(|e| e.role != Role::AuthenticatedUtcCorridor),
        "a corridor that does not overlap the reading was written into the receipt"
    );
    assert!(
        made.notes
            .iter()
            .any(|note| note.starts_with("no corridor from roughtime.se") && note.contains("late")),
        "the run should say why the corridor it was handed is not there: {:?}",
        made.notes
    );
    assert!(
        made.notes
            .iter()
            .any(|note| note.starts_with("no corridor from time.txryan.com")),
        "the next server should have been asked: {:?}",
        made.notes
    );
}

#[test]
fn parties_that_answer_promptly_are_all_kept_and_each_is_checked() {
    // Two seconds after round 32000947 and one before the next. The corridor covers the reading and
    // the token was signed after it, so all three belong in the receipt.
    let clock = Clock::at(ROUND_32000947 + 2 * SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = vec![(
        "roughtime.se".into(),
        after(50 * NANOS_PER_MILLI, Ok(Some(the_corridor()))),
    )];
    outside.witnesses = vec![(
        "DigiCert".into(),
        after(200 * NANOS_PER_MILLI, Ok((the_witness(), false))),
    )];

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert_eq!(made.receipt.evidence.len(), 3, "{:?}", made.notes);
    assert_eq!(read.checked_entries(), 3, "{}", read.verdict());
}

#[test]
fn a_reading_its_own_beacon_contradicts_writes_no_receipt() {
    // A reading that says the moment was ten seconds before it was taken, which is what a model gone
    // slow, or an agent answering for some other moment, hands over. The round fetched before it is
    // later than anything the reading claims, so the receipt would contradict itself, and the stamp
    // refuses rather than writing it.
    let clock = Clock::at(ROUND_32000947 + 10 * SECOND + SECOND / 2);
    let mut outside = Elsewhere::at(&clock);

    let refused = stamp(&mut outside, a_reading(&clock, 10 * SECOND)).map(|made| {
        let read = read_as_a_stranger(&made);
        format!(
            "a receipt was made, and verify says: {}",
            if read.holds() {
                "it holds".to_string()
            } else {
                why_refused(&read)
            }
        )
    });

    let text = refused.expect_err("no receipt");
    assert!(text.contains("no receipt was written"), "{text}");
    assert!(
        text.contains("a not-earlier-than value was published after the latest time"),
        "{text}"
    );
}

#[test]
fn a_round_the_relays_are_far_behind_on_is_set_aside() {
    // The relays are twenty-six minutes behind the chain, so the newest round they hold is 32000388,
    // published twenty-eight minutes before the reading.
    let clock = Clock::at(ROUND_32000947 + SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.beacon_lag = 1_600 * SECOND;

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert_eq!(the_beacon(&made), None, "a round that old pins nothing");
    assert!(
        made.notes
            .iter()
            .any(|note| note.starts_with("no freshness beacon")
                && note.contains("published")
                && note.contains("before the earliest moment this receipt claims")),
        "the round should be set aside for its age: {:?}",
        made.notes
    );
}

#[test]
fn a_witness_over_the_signature_the_verifier_refuses_is_left_off() {
    // The authority hands back the token it signed over the subject, which is a real DigiCert token
    // and not one over this receipt's signature. With it on, verify refuses the receipt. The token
    // sits outside the signature, so the receipt is written without it and the run says so.
    let clock = Clock::at(ROUND_32000947 + SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.over_the_signature = Ok(unhex(WITNESS));

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt, without the token");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert!(
        timewitness_receipt::without_signature_witness(&made.signed).is_none(),
        "the token verify refuses was put on the receipt"
    );
    assert!(
        made.notes.iter().any(|note| note.contains("left off")),
        "{:?}",
        made.notes
    );
}

#[test]
fn a_stamp_with_no_evidence_asks_nobody_and_still_holds() {
    // `--no-evidence` asks no party outside the machine, the beacon included, which on this clock
    // would have taken a tenth of a second.
    let clock = Clock::at(ROUND_32000947 + SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.beacon_takes = 7 * SECOND;

    let made = stamp_with(&mut outside, a_reading(&clock, 0), false).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert!(made.receipt.evidence.is_empty());
    assert_eq!(
        clock.now(),
        ROUND_32000947 + SECOND + NANOS_PER_MILLI,
        "only the reading took any time, so nothing else was asked"
    );
}

#[test]
fn a_slow_reading_its_prompt_corridor_contradicts_writes_no_receipt() {
    // Two seconds after round 32000947, as in the prompt case above. The reading says the moment was
    // a second and a half before it was taken, which is a model gone slow by more than its own
    // bound. roughtime.se answers in 50 ms with a corridor round the true moment, so the corridor
    // starts after the latest moment the reading claims, by more than 50 ms of waiting can explain.
    // That is the reading being wrong rather than the corridor being late, and until v0.8.2 the
    // stamp set the corridor aside and wrote the receipt.
    let clock = Clock::at(ROUND_32000947 + 2 * SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = vec![(
        "roughtime.se".into(),
        after(50 * NANOS_PER_MILLI, Ok(Some(the_corridor()))),
    )];
    outside.witnesses = vec![(
        "DigiCert".into(),
        after(200 * NANOS_PER_MILLI, Ok((the_witness(), false))),
    )];

    let refused = stamp(&mut outside, a_reading(&clock, 1_500 * NANOS_PER_MILLI)).map(|made| {
        let read = read_as_a_stranger(&made);
        format!(
            "a receipt was made with {} entries ({:?}), and verify says: {}",
            made.receipt.evidence.len(),
            made.notes,
            if read.holds() {
                "it holds".to_string()
            } else {
                why_refused(&read)
            }
        )
    });

    let text = refused.expect_err("no receipt");
    assert!(text.contains("no receipt was written"), "{text}");
    assert!(text.to_lowercase().contains("corridor"), "{text}");
}

#[test]
fn a_corridor_asked_well_after_the_reading_is_still_set_aside() {
    // Half a second after round 32000946. The first server takes five seconds to time out, and
    // roughtime.se then answers in 50 ms with a corridor round the moment it answered. It starts
    // more than three seconds after the latest moment the reading claims, and five seconds of waiting
    // explain that, so it is late rather than a contradiction. It is set aside and the next server
    // is asked, as before.
    let clock = Clock::at(ROUND_32000947 - 3 * SECOND + SECOND / 2);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = vec![
        ("roughtime.int08h.com".into(), times_out()),
        (
            "roughtime.se".into(),
            after(50 * NANOS_PER_MILLI, Ok(Some(the_corridor()))),
        ),
        (
            "time.txryan.com".into(),
            after(50 * NANOS_PER_MILLI, Err("refused".into())),
        ),
    ];

    let made = stamp(&mut outside, a_reading(&clock, 0)).expect("a receipt");
    let read = read_as_a_stranger(&made);

    assert!(read.holds(), "verify refused it: {}", why_refused(&read));
    assert!(
        made.receipt.claim.latest.as_nanos() + 3 * SECOND < the_corridor().earliest().as_nanos(),
        "the corridor should start more than three seconds after the claim"
    );
    assert!(
        made.receipt
            .evidence
            .iter()
            .all(|e| e.role != Role::AuthenticatedUtcCorridor),
        "a corridor that does not overlap the reading was written into the receipt"
    );
    assert!(
        made.notes
            .iter()
            .any(|note| note.starts_with("no corridor from roughtime.se") && note.contains("late")),
        "the run should say why the corridor it was handed is not there: {:?}",
        made.notes
    );
    assert!(
        made.notes
            .iter()
            .any(|note| note.starts_with("no corridor from time.txryan.com")),
        "the next server should have been asked: {:?}",
        made.notes
    );
}

#[test]
fn a_corridor_wholly_before_the_reading_writes_no_receipt() {
    // A reading that says the moment was ten seconds after it was taken. The corridor answers in
    // 50 ms and ends before the earliest moment the reading claims. Asked after the reading, an
    // honest server and an honest model cannot produce that, so the corridor is kept and the check
    // before the file refuses the receipt.
    let clock = Clock::at(ROUND_32000947 + 2 * SECOND);
    let mut outside = Elsewhere::at(&clock);
    outside.corridors = vec![(
        "roughtime.se".into(),
        after(50 * NANOS_PER_MILLI, Ok(Some(the_corridor()))),
    )];

    let refused = stamp(&mut outside, a_reading(&clock, -10 * SECOND)).map(|made| {
        format!(
            "a receipt was made with {} entries ({:?})",
            made.receipt.evidence.len(),
            made.notes
        )
    });

    let text = refused.expect_err("no receipt");
    assert!(text.contains("no receipt was written"), "{text}");
    assert!(text.to_lowercase().contains("corridor"), "{text}");
}

#[test]
fn a_corridor_is_late_up_to_the_wait_and_its_radius_and_no_further() {
    // The edge itself, in nanoseconds. A corridor whose midpoint is past the latest moment the
    // reading claims by exactly the wait and its radius is late. One nanosecond further is not, and
    // nor is one that overlaps the claim, which is kept as evidence and never set aside.
    let claim = timewitness_receipt::open(&unhex(A_REAL_READING))
        .expect("the committed receipt opens")
        .claim;
    let latest = claim.latest.as_nanos();
    let wait = 250 * NANOS_PER_MILLI;
    let corridor = |past: Nanos| {
        Attestation::over_interval(Vec::new(), Vec::new(), UnixNanos(latest + past), SECOND)
    };

    assert!(late_rather_than_wrong(
        &corridor(wait + SECOND),
        &claim,
        wait
    ));
    assert!(!late_rather_than_wrong(
        &corridor(wait + SECOND + 1),
        &claim,
        wait
    ));
    assert!(!late_rather_than_wrong(
        &corridor(wait + SECOND + 1),
        &claim,
        0
    ));
    assert!(!late_rather_than_wrong(&corridor(SECOND), &claim, wait));
}
