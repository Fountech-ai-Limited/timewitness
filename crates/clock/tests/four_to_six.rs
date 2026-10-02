//! Independence, against the policy as it ships.
//!
//! The front page of this product says the agent disciplines the clock against four to six
//! independent sources. Until 2026-09-09 the word independent was carried entirely by prose: the
//! model counted `SourceId`s, and four names at one company satisfied every test it made. Marzullo's
//! guarantee holds while fewer than half the sources are wrong, and that needs them to be wrong
//! separately, so a count of names is not the count the guarantee is about.
//!
//! Every test here runs against `Policy::default()` exactly as it ships, with one thing raised: the
//! width ceiling, because these fixtures are simulated paths rather than a real network and the
//! quantity under test is the selection rather than the width. `min_operators` is never touched. The
//! rest of this crate's tests run on `common::arithmetic_policy()`, which lowers the floor so that
//! fixtures of two and three sources can go on measuring interval arithmetic; that is why this file
//! exists separately, and a change to the shipped floor has to be seen here.

mod common;

use common::{Path, World};

use std::sync::Arc;

use timewitness_clock::monotonic::TestClock;
use timewitness_clock::{ClockModel, MonotonicClock, Policy};
use timewitness_core::time::{Nanos, NANOS_PER_MILLI};
use timewitness_core::{MonotonicNanos, UnixNanos, Validity};

struct ClockHandle(Arc<TestClock>);

impl MonotonicClock for ClockHandle {
    fn now(&self) -> MonotonicNanos {
        self.0.now()
    }
}

/// The shipped policy, wide enough for a simulated path.
///
/// The one field changed is the width ceiling. The floors, the coverage factor and the independence
/// number are the shipped ones, so a test here fails when the product's own numbers move.
fn as_shipped() -> Policy {
    Policy {
        max_bound_width: 30_000 * NANOS_PER_MILLI,
        ..Policy::default()
    }
}

/// One honest source, run by `operator`, offset by `error` from the truth.
fn source(id: &'static str, operator: &'static str, error: Nanos) -> Path {
    Path::honest(id, 20, 1)
        .operated_by(operator)
        .lying_by(error)
}

/// Run one selection round over `paths` against the shipped policy.
fn one_round(paths: &[Path]) -> (ClockModel, Validity, UnixNanos) {
    let world = World::still(0);
    let clock = Arc::new(TestClock::starting_at(world.mono0.as_nanos()));
    let wall = world.system(world.mono0);
    let mut model = ClockModel::new(as_shipped(), Box::new(ClockHandle(clock.clone())), wall, 0);

    let now = clock.now();
    for path in paths {
        model.ingest(&world.exchange(path, now));
    }
    let validity = model.synchronise();
    (model, validity, world.utc(now))
}

/// Nine servers standing behind six operators, which is the shape the three shipped lists reach.
///
/// Two operators answer on two protocols each and one company answers on two names, so the nine
/// names are six chances to disagree. The centres are spread by a few milliseconds so that no
/// interval swallows another whole, which is a different rule with its own file.
fn the_shipped_shape() -> Vec<Path> {
    vec![
        source("roughtime:int08h", "int08h.com", 0),
        source("roughtime:se", "netnod.se", NANOS_PER_MILLI),
        source("roughtime:txryan", "txryan.com", -NANOS_PER_MILLI),
        source("ntp:cloudflare", "cloudflare.com", 2 * NANOS_PER_MILLI),
        source("ntp:google", "google.com", -2 * NANOS_PER_MILLI),
        source("ntp:ptb", "ptb.de", 3 * NANOS_PER_MILLI),
        source("nts:cloudflare", "cloudflare.com", -3 * NANOS_PER_MILLI),
        source("nts:netnod", "netnod.se", 4 * NANOS_PER_MILLI),
        source("nts:ptb", "ptb.de", -4 * NANOS_PER_MILLI),
    ]
}

/// The shipped default signs, which is the first thing a floor has to be checked against.
///
/// A floor that refuses the configuration the product ships with is a worse fault than no floor at
/// all, because the answer to it is always to lower the number rather than to add an operator.
#[test]
fn the_shipped_nine_servers_at_six_operators_are_signed() {
    let (model, validity, truth) = one_round(&the_shipped_shape());
    assert_eq!(validity, Validity::Valid, "the shipped shape has to sign");

    let stamp = model.read().expect("a valid model reads");
    assert!(
        stamp.bound.earliest <= truth && truth <= stamp.bound.latest,
        "the interval has to hold the truth as well as be signed"
    );

    let operators: std::collections::BTreeSet<String> = stamp
        .sources
        .iter()
        .filter(|s| s.kept)
        .map(|s| s.operator.as_str().to_string())
        .collect();
    assert_eq!(
        operators.len(),
        6,
        "nine names, six operators, and the receipt has to let a reader count them"
    );
}

/// The case this whole file is about. One company answering nine times is one chance to be wrong.
///
/// Every interval agrees with every other, so Marzullo signs it without hesitating: nine of nine
/// overlap and nine is a majority of nine. There is one party in the round. The model refuses.
#[test]
fn nine_names_at_one_company_do_not_reach_the_floor() {
    let round: Vec<Path> = (0..9)
        .map(|i| {
            let ids = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
            source(
                ids[i],
                "onecompany.example",
                (i as Nanos - 4) * NANOS_PER_MILLI,
            )
        })
        .collect();

    let (_, validity, _) = one_round(&round);
    assert_eq!(
        validity,
        Validity::InsufficientOperators {
            present: 1,
            required: 4,
        },
        "nine intervals that all agree, and nobody to agree with"
    );
}

/// A majority of intervals that is a minority of operators is refused.
///
/// Six sources at one company, all saying the same wrong thing, against three honest operators. The
/// interval arithmetic hands the region to the six: they overlap each other and they outnumber the
/// rest. Counting parties, one of four kept, which is not a majority, so the round is refused rather
/// than signed on somebody's word given six times.
#[test]
fn one_company_answering_six_times_cannot_outvote_three_honest_operators() {
    let lie = 80 * NANOS_PER_MILLI;
    let round = vec![
        source("loud-1", "loud.example", lie),
        source("loud-2", "loud.example", lie + NANOS_PER_MILLI / 10),
        source("loud-3", "loud.example", lie - NANOS_PER_MILLI / 10),
        source("loud-4", "loud.example", lie + NANOS_PER_MILLI / 5),
        source("loud-5", "loud.example", lie - NANOS_PER_MILLI / 5),
        source("loud-6", "loud.example", lie + NANOS_PER_MILLI / 3),
        source("honest-a", "a.example", 0),
        source("honest-b", "b.example", NANOS_PER_MILLI),
        source("honest-c", "c.example", -NANOS_PER_MILLI),
    ];

    let (_, validity, _) = one_round(&round);
    assert!(
        matches!(validity, Validity::OperatorMajority { .. }),
        "expected a refusal on the operator count and got {validity:?}"
    );
    assert!(
        !validity.is_valid(),
        "the loud company must not get the bound"
    );
}

/// Adding names at a company already in the round never turns a refusal into a signature.
///
/// This is the direction that has to be impossible, and it is the one an attacker controls: whoever
/// wants a bound their own way adds servers, because servers are cheap and operators are not. So it
/// is checked over the whole spread rather than argued for: take a round that refuses, add up to
/// twelve more names at companies already in it, and it has to go on refusing every time.
#[test]
fn extra_names_at_a_company_already_present_never_buy_a_signature() {
    let base = vec![
        source("a-1", "a.example", 0),
        source("b-1", "b.example", NANOS_PER_MILLI),
        source("c-1", "c.example", -NANOS_PER_MILLI),
    ];
    let (_, before, _) = one_round(&base);
    assert!(
        !before.is_valid(),
        "three operators is under the shipped floor of four, so this round starts refused"
    );

    let names = [
        "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
    ];
    let companies = ["a.example", "b.example", "c.example"];
    for extra in 1..=names.len() {
        let mut round = base.clone();
        for i in 0..extra {
            round.push(source(
                names[i],
                companies[i % companies.len()],
                (i as Nanos % 3 - 1) * NANOS_PER_MILLI / 2,
            ));
        }
        let (_, validity, _) = one_round(&round);
        assert!(
            !validity.is_valid(),
            "{extra} extra names at the same three companies bought a signature: {validity:?}"
        );
    }
}

/// A fourth company does buy one, which is the other half of the same claim.
///
/// The refusal has to be about independence rather than about anything else in the round, so the
/// same three sources plus one more operator have to sign. Without this the test above would pass on
/// a model that had simply stopped working.
#[test]
fn a_fourth_company_is_what_turns_that_refusal_into_a_signature() {
    let mut round = vec![
        source("a-1", "a.example", 0),
        source("b-1", "b.example", NANOS_PER_MILLI),
        source("c-1", "c.example", -NANOS_PER_MILLI),
    ];
    assert!(!one_round(&round).1.is_valid());

    round.push(source("d-1", "d.example", 2 * NANOS_PER_MILLI));
    let (_, validity, truth) = one_round(&round);
    assert_eq!(validity, Validity::Valid, "four operators is the floor");

    let (model, _, _) = one_round(&round);
    let stamp = model.read().expect("a valid model reads");
    assert!(stamp.bound.earliest <= truth && truth <= stamp.bound.latest);
}

/// Two of the six shipped operators going dark still leaves a signature, and a third does not.
///
/// This is what the floor was chosen against. Four leaves the shipped lists two operators of room,
/// so an ordinary outage is an outage rather than an agent that has stopped signing; five or six
/// would have made the first unreachable server look like a fault in this product.
#[test]
fn the_shipped_shape_survives_two_operators_going_dark_and_not_three() {
    let whole = the_shipped_shape();

    let two_gone: Vec<Path> = whole
        .iter()
        .filter(|p| p.operator != "ptb.de" && p.operator != "txryan.com")
        .cloned()
        .collect();
    assert_eq!(
        one_round(&two_gone).1,
        Validity::Valid,
        "four operators left is still four"
    );

    let three_gone: Vec<Path> = two_gone
        .iter()
        .filter(|p| p.operator != "google.com")
        .cloned()
        .collect();
    assert_eq!(
        one_round(&three_gone).1,
        Validity::InsufficientOperators {
            present: 3,
            required: 4,
        },
        "three operators is under the floor, however many names they answer on"
    );
}

/// The refusal says it declined to sign, and says nothing about having prevented anything.
///
/// There is no enforcement path anywhere in this design: whatever was going to happen went ahead,
/// unstamped, and a refusal that implies otherwise is the claim this product exists not to make.
#[test]
fn the_refusal_says_it_declined_to_sign_and_claims_nothing_more() {
    let said = timewitness_core::Refusal::new(Validity::InsufficientOperators {
        present: 2,
        required: 4,
    })
    .to_string();

    assert!(said.contains("declined to sign"), "{said}");
    for word in ["prevent", "blocked", "stopped", "refused the"] {
        assert!(
            !said.contains(word),
            "a refusal must not read as an action prevented: {said}"
        );
    }
}
