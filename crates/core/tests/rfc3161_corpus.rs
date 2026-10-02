//! Real timestamp tokens, and every way of spoiling one.
//!
//! Two tokens from two free authorities, captured on 2026-09-07 and checked here with no network at
//! all. There is no fake authority in this file, because forging one would mean holding a signing
//! key, which is also what an attacker would need. So everything hostile is done to a real token:
//! the hash it is about changed, the certificate it is checked against changed, the signature
//! spoiled, the request it came from swapped.

use timewitness_core::evidence::rfc3161::{self, Authority};
use timewitness_core::evidence::EvidenceError;
use timewitness_core::time::NANOS_PER_SEC;

const AUTHORITIES: &str = include_str!("data/rfc3161/authorities.txt");
const DIGICERT: &str = include_str!("data/rfc3161/digicert.hex");
const SECTIGO: &str = include_str!("data/rfc3161/sectigo.hex");

fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        })
        .collect();
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

struct Capture {
    authority: Authority,
    subject: [u8; 32],
    blob: Vec<u8>,
}

fn captures() -> Vec<Capture> {
    AUTHORITIES
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next().expect("a name").to_string();
            let mut pin = [0u8; 32];
            pin.copy_from_slice(&unhex(parts.next().expect("a certificate")));
            let mut subject = [0u8; 32];
            subject.copy_from_slice(&unhex(parts.next().expect("a subject")));
            let file = parts.next().expect("a file");
            let blob = match file {
                "digicert.hex" => unhex(DIGICERT),
                "sectigo.hex" => unhex(SECTIGO),
                other => panic!("{other} is in the manifest and not compiled into this test"),
            };
            Capture {
                authority: Authority {
                    name,
                    url: String::new(),
                    accepted_certificates: vec![pin],
                    accuracy_where_the_token_states_none: None,
                },
                subject,
                blob,
            }
        })
        .collect()
}

#[test]
fn every_captured_token_verifies_with_no_network_at_all() {
    let all = captures();
    assert_eq!(all.len(), 2, "two authorities were captured");
    for c in &all {
        let checked = rfc3161::check(&c.blob, &c.authority, &c.subject).unwrap_or_else(|e| {
            panic!(
                "{} was captured verified and no longer verifies: {e}",
                c.authority.name
            )
        });
        assert_eq!(checked.scheme, "rfc3161");
        assert!(
            checked.checks.len() >= 5,
            "{} verified on {} checks",
            c.authority.name,
            checked.checks.len()
        );
        // Both were captured on the day of the run, so the moment each states has to sit in it.
        // Neither authority states an accuracy, so neither token supports an interval in UTC and
        // `latest` is absent on both. What each one states is still checkable and is what the day
        // is read off, through `inspect`, which needs no key.
        let inspected = rfc3161::inspect(&c.blob, &c.subject).expect("a good token");
        assert_eq!(
            checked.latest(),
            None,
            "{} states no accuracy and must support no edge in UTC",
            c.authority.name
        );
        let seconds = inspected.stated_instant().as_nanos() / NANOS_PER_SEC;
        assert!(
            (1_788_700_000..1_788_900_000).contains(&seconds),
            "{} states {seconds}, which is not the day it was captured",
            c.authority.name
        );
    }
}

#[test]
fn a_token_offered_as_evidence_about_another_document_is_refused() {
    for c in captures() {
        for at in [0usize, 7, 31] {
            let mut other = c.subject;
            other[at] ^= 0x01;
            let err = rfc3161::check(&c.blob, &c.authority, &other)
                .expect_err("a token about a hash the authority never saw");
            assert!(matches!(err, EvidenceError::Inconsistent(_)), "{err}");
        }
    }
}

#[test]
fn a_token_checked_against_a_certificate_nobody_pinned_is_refused() {
    for c in captures() {
        let mut wrong = c.authority.clone();
        wrong.accepted_certificates[0][0] ^= 0x01;
        let err = rfc3161::check(&c.blob, &wrong, &c.subject)
            .expect_err("a token checked against a certificate that is not the pinned one");
        assert!(matches!(err, EvidenceError::BadSignature(_)), "{err}");
    }
}

#[test]
fn an_authority_with_no_pins_at_all_accepts_nothing() {
    // The state a caller reaches by leaving the pin list empty, which would otherwise be the same
    // as trusting whatever certificate arrived.
    for c in captures() {
        let mut open = c.authority.clone();
        open.accepted_certificates.clear();
        assert!(rfc3161::check(&c.blob, &open, &c.subject).is_err());
    }
}

#[test]
fn a_token_swapped_between_two_authorities_is_refused_both_ways() {
    let all = captures();
    let a = rfc3161::check(&all[0].blob, &all[1].authority, &all[1].subject);
    let b = rfc3161::check(&all[1].blob, &all[0].authority, &all[0].subject);
    assert!(
        a.is_err(),
        "one authority's token verified under another's pin"
    );
    assert!(b.is_err(), "and the other way round");
}

#[test]
fn a_reply_pasted_onto_a_request_that_asked_about_something_else_is_refused() {
    let all = captures();
    let first = rfc3161::unpack_blob(&all[0].blob).expect("unpacks");
    let second = rfc3161::unpack_blob(&all[1].blob).expect("unpacks");
    let spliced = rfc3161::pack_blob(second.request, first.reply);
    assert!(
        rfc3161::check(&spliced, &all[0].authority, &all[0].subject).is_err(),
        "a reply verified against a request it was not an answer to"
    );
}

#[test]
fn no_single_byte_change_lets_a_token_say_something_different() {
    // A token carries a certificate chain that this check never looks at, so a bit flipped inside
    // one of those changes nothing about what was proved and is not refused. What has to hold is
    // the property above that: a change either fails the check, or leaves what the token says
    // exactly as it was.
    for c in captures() {
        let original = rfc3161::check(&c.blob, &c.authority, &c.subject).expect("a good token");
        let stored = rfc3161::unpack_blob(&c.blob).expect("unpacks");
        let (request, reply) = (stored.request.to_vec(), stored.reply.to_vec());
        for at in (0..reply.len()).step_by(37) {
            let mut spoiled = reply.clone();
            spoiled[at] ^= 0x01;
            let blob = rfc3161::pack_blob(&request, &spoiled);
            if let Ok(changed) = rfc3161::check(&blob, &c.authority, &c.subject) {
                assert_eq!(
                    (changed.earliest(), changed.latest(), changed.nonce),
                    (
                        original.earliest(),
                        original.latest(),
                        original.nonce.clone()
                    ),
                    "{} accepted byte {at} flipped and said something different",
                    c.authority.name
                );
            }
        }
    }
}

#[test]
fn changing_the_nonce_in_the_stored_request_is_refused() {
    for c in captures() {
        let stored = rfc3161::unpack_blob(&c.blob).expect("unpacks");
        let mut request = stored.request.to_vec();
        // The nonce is the last integer in the request, before the certReq boolean, so the byte
        // three from the end is inside it.
        let at = request.len() - 4;
        request[at] ^= 0x01;
        let blob = rfc3161::pack_blob(&request, stored.reply);
        let err = rfc3161::check(&blob, &c.authority, &c.subject)
            .expect_err("a request whose nonce we changed afterwards");
        assert!(
            matches!(
                err,
                EvidenceError::WrongNonce(_) | EvidenceError::Malformed(_)
            ),
            "{err}"
        );
    }
}

#[test]
fn a_truncated_token_is_refused_at_every_length() {
    let c = &captures()[0];
    for length in (0..c.blob.len()).step_by(11) {
        assert!(
            rfc3161::check(&c.blob[..length], &c.authority, &c.subject).is_err(),
            "a token cut to {length} bytes still verified"
        );
    }
}

#[test]
fn a_flipped_bit_in_the_signature_itself_is_refused() {
    // The signature is the last field of the last structure in a reply, so the reply's own last
    // bytes are inside it. That matters for what this test isolates: everything else about the
    // token is untouched, the pinned certificate still matches by its hash, and the only thing that
    // has changed is the number the signature check does its arithmetic on.
    for c in captures() {
        let stored = rfc3161::unpack_blob(&c.blob).expect("unpacks");
        let (request, reply) = (stored.request.to_vec(), stored.reply.to_vec());
        for from_the_end in [1usize, 2, 9, 40] {
            let mut spoiled = reply.clone();
            let at = spoiled.len() - from_the_end;
            spoiled[at] ^= 0x01;
            let blob = rfc3161::pack_blob(&request, &spoiled);
            let err = rfc3161::check(&blob, &c.authority, &c.subject)
                .expect_err("a token whose signature we edited afterwards");
            assert!(
                matches!(err, EvidenceError::BadSignature(_)),
                "{} refused an edited signature for the wrong reason: {err}",
                c.authority.name
            );
        }
    }
}

/// Where the token's own time sits in the reply.
///
/// A generalized time is fourteen ASCII digits and a `Z`, and the only one in a reply is the moment
/// the authority states. Finding it by its shape rather than by parsing keeps this test independent
/// of the parser it is testing.
fn find_stated_time(reply: &[u8]) -> Option<usize> {
    reply
        .windows(15)
        .position(|w| w[..14].iter().all(u8::is_ascii_digit) && w[14] == b'Z' && w[0] == b'2')
}

#[test]
fn changing_the_moment_the_token_states_is_refused() {
    // The signed attributes are untouched here, so the signature over them still checks out. What
    // has changed is the content those attributes carry a digest of. Nothing but that digest
    // comparison stands between an edited timestamp and a receipt that believes it.
    for c in captures() {
        let stored = rfc3161::unpack_blob(&c.blob).expect("unpacks");
        let (request, reply) = (stored.request.to_vec(), stored.reply.to_vec());
        let at = find_stated_time(&reply)
            .unwrap_or_else(|| panic!("{}: no stated time found in the reply", c.authority.name));
        // The year, so the edit moves the moment by a decade rather than by a second.
        let mut spoiled = reply.clone();
        spoiled[at + 2] = if spoiled[at + 2] == b'9' {
            b'0'
        } else {
            spoiled[at + 2] + 1
        };
        let blob = rfc3161::pack_blob(&request, &spoiled);
        let err = rfc3161::check(&blob, &c.authority, &c.subject)
            .expect_err("a token whose stated moment we edited afterwards");
        assert!(
            matches!(err, EvidenceError::Inconsistent(_)),
            "{} refused an edited moment for the wrong reason: {err}",
            c.authority.name
        );
    }
}

/// Neither captured authority states an accuracy, so neither token supports an edge in UTC.
///
/// Changed 2026-09-19. `stated_width` was `accuracy.unwrap_or(0) + resolution` until that
/// day, so an authority that had put no number on its own clock error was read as having put
/// nought, and both edges came out as narrow as the token could possibly be read. That is the
/// tightening direction and it was every not-later-than edge this product had produced, because
/// both authorities that ship are in this state.
///
/// RFC 3161 section 2.4.2 is what settles it. A missing sub-field of a present accuracy is taken as
/// zero; an absent accuracy field is different, and "the accuracy may be available through other
/// means, e.g., the TSAPolicyId", meaning from the authority's published practice rather than from
/// the token. The same section refuses the other shortcut: the accuracy "is not to be inferred
/// from the syntax", so the resolution the time is written to is not an accuracy either.
#[test]
fn a_token_stating_no_accuracy_supports_no_interval_in_utc() {
    for c in captures() {
        let inspected = rfc3161::inspect(&c.blob, &c.subject).expect("a good token");
        assert!(
            !inspected.states_an_accuracy(),
            "{} states an accuracy, and this test was written against two that do not",
            c.authority.name
        );
        assert_eq!(
            inspected.supports(None),
            None,
            "{} states no accuracy and still supports an interval",
            c.authority.name
        );
        let checked = rfc3161::check(&c.blob, &c.authority, &c.subject).expect("a good token");
        assert_eq!(checked.earliest(), None, "{}", c.authority.name);
        assert_eq!(checked.latest(), None, "{}", c.authority.name);
        assert_eq!(checked.radius(), None, "{}", c.authority.name);
        assert_eq!(checked.midpoint(), None, "{}", c.authority.name);
    }
}

/// What the token states is off its own bytes and does not move with what the reader holds.
///
/// The instant a receipt prints beside a witness entry has to be the same for everybody or a
/// receipt stops being portable, so it is the written time plus the resolution and nothing else.
/// An allowance moves what the token is reported to support and may never move this.
#[test]
fn the_instant_a_token_states_is_the_same_whatever_the_reader_allows() {
    for c in captures() {
        let inspected = rfc3161::inspect(&c.blob, &c.subject).expect("a good token");
        let stated = inspected.stated_instant();
        for allowance in [
            None,
            Some(0),
            Some(1_000_000_000),
            Some(86_400 * NANOS_PER_SEC),
        ] {
            assert_eq!(
                inspected.stated_instant(),
                stated,
                "{} states a different moment once the reader allows {allowance:?}",
                c.authority.name
            );
            let Some((earliest, latest)) = inspected.supports(allowance) else {
                assert_eq!(allowance, None, "{}", c.authority.name);
                continue;
            };
            let allowed = allowance.expect("an interval only comes back with an allowance");
            assert_eq!(
                latest.as_nanos() - stated.as_nanos(),
                allowed,
                "{} widens the not-later edge by something other than what was allowed",
                c.authority.name
            );
            assert!(
                earliest < stated,
                "{} puts the not-earlier edge at or after the instant it states",
                c.authority.name
            );
        }
    }
}

/// A reader's own allowance widens what the token supports and never narrows it.
#[test]
fn a_larger_allowance_never_produces_a_narrower_interval() {
    for c in captures() {
        let inspected = rfc3161::inspect(&c.blob, &c.subject).expect("a good token");
        let mut widest = -1i128;
        for allowance in [0, 1, 1_000, 1_000_000, NANOS_PER_SEC, 3_600 * NANOS_PER_SEC] {
            let (earliest, latest) = inspected
                .supports(Some(allowance))
                .expect("an allowance produces an interval");
            let width = latest.as_nanos() - earliest.as_nanos();
            assert!(
                width > widest,
                "{} answered {width} ns at an allowance of {allowance} ns, after {widest} ns",
                c.authority.name
            );
            widest = width;
        }
    }
}
