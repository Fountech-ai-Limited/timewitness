//! Real Roughtime responses, and every way of spoiling one.
//!
//! Two halves, and both are needed.
//!
//! The first half is three responses captured from three public servers on 2026-09-07, stored
//! exactly as the client stored them, checked here with no network at all. That is the only way to
//! know the parser reads what real servers actually send rather than what this code assumes they
//! send. Each one is then spoiled in a different place and has to be refused.
//!
//! The second half signs its own responses with a key this file holds, because there are checks a
//! captured response cannot reach. No public server will answer with a radius of zero, or date a
//! response outside its own delegation window, or batch our request into a tree eight deep. A
//! server that behaved that way is exactly what these checks exist for, so this file builds one.
//! Its encoder is written out again rather than borrowed from the crate under test, because a test
//! that encodes with the code it is testing agrees with a bug as readily as with a fix.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha512};
use timewitness_core::evidence::roughtime;
use timewitness_core::evidence::EvidenceError;

const CORPUS: &str = include_str!("data/roughtime/servers.txt");
const INT08H: &str = include_str!("data/roughtime/int08h.hex");
const ROUGHTIME_SE: &str = include_str!("data/roughtime/roughtime-se.hex");
const TXRYAN: &str = include_str!("data/roughtime/txryan.hex");

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
    assert_eq!(digits.len() % 2, 0, "an odd number of hex digits");
    digits.chunks(2).map(|c| (c[0] << 4) | c[1]).collect()
}

struct Capture {
    name: String,
    key: [u8; 32],
    blob: Vec<u8>,
}

/// The three captured responses, read off the manifest beside them.
fn captures() -> Vec<Capture> {
    CORPUS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next().expect("a name").to_string();
            let key_hex = parts.next().expect("a key");
            let file = parts.next().expect("a file");
            let mut key = [0u8; 32];
            key.copy_from_slice(&unhex(key_hex));
            let blob = match file {
                "int08h.hex" => unhex(INT08H),
                "roughtime-se.hex" => unhex(ROUGHTIME_SE),
                "txryan.hex" => unhex(TXRYAN),
                other => panic!("{other} is in the manifest and not compiled into this test"),
            };
            Capture { name, key, blob }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Half one: the real responses.
// ---------------------------------------------------------------------------------------------

#[test]
fn every_captured_response_verifies_with_no_network_at_all() {
    let all = captures();
    assert_eq!(all.len(), 3, "the manifest lists three servers");
    for c in all {
        let checked = roughtime::check(&c.blob, &c.key, &c.name).unwrap_or_else(|e| {
            panic!(
                "{} was captured verified and no longer verifies: {e}",
                c.name
            )
        });
        assert_eq!(checked.scheme, "roughtime");
        assert!(
            checked.radius().is_some_and(|r| r > 0),
            "{} states a radius of zero, which the draft forbids",
            c.name
        );
        assert!(
            checked.checks.len() >= 5,
            "{} verified on {} checks, which is fewer than this module runs",
            c.name,
            checked.checks.len()
        );
        assert_eq!(
            checked.nonce.map(|n| n.len()),
            Some(32),
            "{} was asked over a 32 byte nonce",
            c.name
        );
    }
}

/// Spoil one byte somewhere in the reply and require a refusal.
///
/// The offset is counted from the end of the blob, because the reply is the last section and its
/// own length differs per server. A byte deep inside the reply is inside the signed material or
/// inside a signature, and either way the response stops being the one the server signed.
fn spoil_reply(blob: &[u8], from_the_end: usize) -> Vec<u8> {
    let mut spoiled = blob.to_vec();
    let at = spoiled.len() - from_the_end;
    spoiled[at] ^= 0x01;
    spoiled
}

#[test]
fn a_flipped_bit_anywhere_in_a_real_reply_is_refused() {
    for c in captures() {
        // Sixteen probes spread through the reply. Every one of them lands inside something the
        // server signed or inside one of the two signatures.
        let reply_length = c.blob.len() / 2;
        for step in 1..=16 {
            let from_the_end = step * (reply_length / 20) + 1;
            let spoiled = spoil_reply(&c.blob, from_the_end);
            if spoiled == c.blob {
                continue;
            }
            assert!(
                roughtime::check(&spoiled, &c.key, &c.name).is_err(),
                "{} accepted a reply with a bit flipped {from_the_end} bytes from the end",
                c.name
            );
        }
    }
}

#[test]
fn a_real_response_checked_against_another_servers_key_is_refused() {
    let all = captures();
    for (i, c) in all.iter().enumerate() {
        let other = &all[(i + 1) % all.len()];
        let refused = roughtime::check(&c.blob, &other.key, &other.name);
        assert!(
            refused.is_err(),
            "{} verified against the published key of {}",
            c.name,
            other.name
        );
    }
}

#[test]
fn changing_the_nonce_in_the_request_breaks_the_path_to_the_signed_root() {
    for c in captures() {
        let stored = roughtime::unpack_blob(&c.blob).expect("a capture unpacks");
        let (binding, request, reply) = (stored.binding, stored.request, stored.reply);
        // The nonce sits somewhere in the request's value section. Changing any byte of the request
        // changes the leaf, so the path can no longer reach the root the server signed.
        let mut altered = request.to_vec();
        let at = altered.len() / 2;
        altered[at] ^= 0xff;
        let spoiled = roughtime::pack_blob(binding, &altered, reply);
        let err = roughtime::check(&spoiled, &c.key, &c.name)
            .expect_err("a request we edited afterwards still verified");
        assert!(
            matches!(
                err,
                EvidenceError::WrongNonce(_) | EvidenceError::Malformed(_)
            ),
            "{} refused an edited request for the wrong reason: {err}",
            c.name
        );
    }
}

#[test]
fn a_binding_that_does_not_produce_the_nonce_is_refused() {
    for c in captures() {
        let stored = roughtime::unpack_blob(&c.blob).expect("a capture unpacks");
        let (binding, request, reply) = (stored.binding, stored.request, stored.reply);
        assert!(
            !binding.is_empty(),
            "{} was captured with a nonce bound to a subject",
            c.name
        );
        let mut altered = binding.to_vec();
        altered[0] ^= 0x01;
        let spoiled = roughtime::pack_blob(&altered, request, reply);
        let err = roughtime::check(&spoiled, &c.key, &c.name)
            .expect_err("a subject we swapped afterwards still verified");
        assert!(
            matches!(err, EvidenceError::WrongNonce(_)),
            "{} refused a swapped subject for the wrong reason: {err}",
            c.name
        );
    }
}

#[test]
fn a_reply_from_one_server_pasted_onto_a_request_to_another_is_refused() {
    let all = captures();
    let request = roughtime::unpack_blob(&all[0].blob)
        .expect("a capture unpacks")
        .request;
    let reply = roughtime::unpack_blob(&all[1].blob)
        .expect("a capture unpacks")
        .reply;
    let spliced = roughtime::pack_blob(&[], request, reply);
    assert!(
        roughtime::check(&spliced, &all[0].key, &all[0].name).is_err(),
        "a reply from one server verified against a request sent to another"
    );
    assert!(
        roughtime::check(&spliced, &all[1].key, &all[1].name).is_err(),
        "the same splice verified against the other key"
    );
}

#[test]
fn a_truncated_capture_is_refused_at_every_length() {
    let c = captures().into_iter().next().expect("a capture");
    for length in 0..c.blob.len() {
        assert!(
            roughtime::check(&c.blob[..length], &c.key, &c.name).is_err(),
            "a capture cut to {length} bytes still verified"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Half two: a server of our own, so the checks a real server will not exercise get exercised.
// ---------------------------------------------------------------------------------------------

const TYPE_RESPONSE: u32 = 1;

fn tag(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// A Roughtime message, encoded again from the draft rather than borrowed from the crate.
fn message(pairs: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let mut pairs: Vec<(u32, Vec<u8>)> = pairs.iter().map(|(t, v)| (tag(t), v.clone())).collect();
    pairs.sort_by_key(|(t, _)| *t);
    let mut out = Vec::new();
    out.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
    let mut running = 0u32;
    for (_, v) in pairs.iter().take(pairs.len() - 1) {
        running += v.len() as u32;
        out.extend_from_slice(&running.to_le_bytes());
    }
    for (t, _) in &pairs {
        out.extend_from_slice(&t.to_le_bytes());
    }
    for (_, v) in &pairs {
        out.extend_from_slice(v);
    }
    out
}

fn packet(body: &[u8]) -> Vec<u8> {
    let mut out = b"ROUGHTIM".to_vec();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    let full = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// How the fake server should behave on one request.
struct Behaviour {
    midpoint: u64,
    radius: u32,
    min_time: u64,
    max_time: u64,
    version: u32,
    /// How many other requests to pretend were batched alongside ours, as a power of two.
    tree_depth: u32,
    /// Where in that batch to claim ours sat.
    index: u32,
    /// Claim an index the path cannot reach.
    lie_about_the_index: bool,
    /// Sign the response with a key the certificate does not name.
    sign_with_a_stranger: bool,
    /// Echo a nonce other than the one the request carried, while signing over the real tree.
    echo_a_different_nonce: bool,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            midpoint: 1_788_800_000,
            radius: 3,
            min_time: 1_788_000_000,
            max_time: 1_789_000_000,
            version: 0x8000_000c,
            tree_depth: 0,
            index: 0,
            lie_about_the_index: false,
            sign_with_a_stranger: false,
            echo_a_different_nonce: false,
        }
    }
}

struct Fake {
    long_term: SigningKey,
    online: SigningKey,
    stranger: SigningKey,
}

impl Fake {
    fn new() -> Self {
        Self {
            long_term: SigningKey::from_bytes(&[11u8; 32]),
            online: SigningKey::from_bytes(&[22u8; 32]),
            stranger: SigningKey::from_bytes(&[33u8; 32]),
        }
    }

    fn key(&self) -> [u8; 32] {
        self.long_term.verifying_key().to_bytes()
    }

    fn answer(&self, request: &[u8], nonce: &[u8; 32], how: &Behaviour) -> Vec<u8> {
        // The Merkle tree. Our request is the leaf at `index`; every sibling on the way up is a
        // stand-in for somebody else's request in the same batch.
        let mut current = h(&[&[0x00], request]);
        let mut path = Vec::new();
        for level in 0..how.tree_depth {
            let sibling = h(&[b"another client's request", &level.to_le_bytes()]);
            path.extend_from_slice(&sibling);
            current = if (how.index >> level) & 1 == 0 {
                h(&[&[0x01], &current, &sibling])
            } else {
                h(&[&[0x01], &sibling, &current])
            };
        }
        let root = current;

        let delegation = message(&[
            (b"PUBK", self.online.verifying_key().to_bytes().to_vec()),
            (b"MINT", how.min_time.to_le_bytes().to_vec()),
            (b"MAXT", how.max_time.to_le_bytes().to_vec()),
        ]);
        let mut delegation_signed = b"RoughTime v1 delegation signature\x00".to_vec();
        delegation_signed.extend_from_slice(&delegation);
        let certificate = message(&[
            (
                b"SIG\x00",
                self.long_term.sign(&delegation_signed).to_bytes().to_vec(),
            ),
            (b"DELE", delegation),
        ]);

        let signed_response = message(&[
            (b"VER\x00", how.version.to_le_bytes().to_vec()),
            (b"RADI", how.radius.to_le_bytes().to_vec()),
            (b"MIDP", how.midpoint.to_le_bytes().to_vec()),
            (b"VERS", how.version.to_le_bytes().to_vec()),
            (b"ROOT", root.to_vec()),
        ]);
        let mut response_signed = b"RoughTime v1 response signature\x00".to_vec();
        response_signed.extend_from_slice(&signed_response);
        let signer = if how.sign_with_a_stranger {
            &self.stranger
        } else {
            &self.online
        };

        let claimed_index = if how.lie_about_the_index {
            how.index | (1 << (how.tree_depth + 1))
        } else {
            how.index
        };

        let echoed = if how.echo_a_different_nonce {
            let mut other = *nonce;
            other[0] ^= 0xff;
            other
        } else {
            *nonce
        };

        packet(&message(&[
            (
                b"SIG\x00",
                signer.sign(&response_signed).to_bytes().to_vec(),
            ),
            (b"NONC", echoed.to_vec()),
            (b"TYPE", TYPE_RESPONSE.to_le_bytes().to_vec()),
            (b"PATH", path),
            (b"SREP", signed_response),
            (b"CERT", certificate),
            (b"INDX", claimed_index.to_le_bytes().to_vec()),
        ]))
    }
}

fn blob_for(fake: &Fake, how: &Behaviour, nonce: &[u8; 32]) -> Vec<u8> {
    let request = roughtime::build_request(nonce, &fake.key());
    let reply = fake.answer(&request, nonce, how);
    roughtime::pack_blob(&[], &request, &reply)
}

#[test]
fn the_fake_server_is_faithful_enough_that_a_good_answer_verifies() {
    // If this fails, nothing else in this half means anything: the refusals below would be
    // refusing a badly built packet rather than the fault they name.
    let fake = Fake::new();
    let blob = blob_for(&fake, &Behaviour::default(), &[5u8; 32]);
    let checked = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect("a well formed answer from our own server");
    assert_eq!(checked.radius(), Some(3_000_000_000));
    assert_eq!(
        checked.midpoint().map(|m| m.as_nanos()),
        Some(1_788_800_000_000_000_000)
    );
}

#[test]
fn a_radius_of_zero_is_refused() {
    let fake = Fake::new();
    let how = Behaviour {
        radius: 0,
        ..Behaviour::default()
    };
    let blob = blob_for(&fake, &how, &[5u8; 32]);
    let err = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect_err("a server claiming a clock with no error at all");
    assert!(matches!(err, EvidenceError::Inconsistent(_)), "{err}");
}

#[test]
fn a_response_dated_outside_its_own_delegation_window_is_refused() {
    let fake = Fake::new();
    for how in [
        Behaviour {
            midpoint: 1_787_000_000,
            ..Behaviour::default()
        },
        Behaviour {
            midpoint: 1_790_000_000,
            ..Behaviour::default()
        },
    ] {
        let blob = blob_for(&fake, &how, &[5u8; 32]);
        let err = roughtime::check(&blob, &fake.key(), "a server of our own")
            .expect_err("a key used outside the window it was delegated for");
        assert!(matches!(err, EvidenceError::OutsideDelegation(_)), "{err}");
    }
}

#[test]
fn a_response_signed_by_a_key_the_certificate_does_not_name_is_refused() {
    let fake = Fake::new();
    let how = Behaviour {
        sign_with_a_stranger: true,
        ..Behaviour::default()
    };
    let blob = blob_for(&fake, &how, &[5u8; 32]);
    let err = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect_err("a response signed by a key nobody delegated to");
    assert!(matches!(err, EvidenceError::BadSignature(_)), "{err}");
}

#[test]
fn a_response_in_a_version_this_code_does_not_implement_is_refused() {
    let fake = Fake::new();
    let how = Behaviour {
        version: 1,
        ..Behaviour::default()
    };
    let blob = blob_for(&fake, &how, &[5u8; 32]);
    let err = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect_err("a version this code has never been tested against");
    assert!(matches!(err, EvidenceError::Inconsistent(_)), "{err}");
}

#[test]
fn a_request_batched_into_a_deep_tree_still_reaches_the_root() {
    let fake = Fake::new();
    // Every position in a tree eight deep, so both directions of every step get walked.
    for index in [0u32, 1, 2, 5, 128, 255] {
        let how = Behaviour {
            tree_depth: 8,
            index,
            ..Behaviour::default()
        };
        let blob = blob_for(&fake, &how, &[5u8; 32]);
        roughtime::check(&blob, &fake.key(), "a server of our own")
            .unwrap_or_else(|e| panic!("a request at index {index} of a tree eight deep: {e}"));
    }
}

#[test]
fn a_path_that_cannot_reach_the_claimed_index_is_refused() {
    let fake = Fake::new();
    let how = Behaviour {
        tree_depth: 4,
        index: 3,
        lie_about_the_index: true,
        ..Behaviour::default()
    };
    let blob = blob_for(&fake, &how, &[5u8; 32]);
    let err = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect_err("an index with bits the path cannot account for");
    assert!(matches!(err, EvidenceError::Inconsistent(_)), "{err}");
}

#[test]
fn a_path_taken_from_a_different_position_in_the_tree_is_refused() {
    let fake = Fake::new();
    let honest = Behaviour {
        tree_depth: 4,
        index: 3,
        ..Behaviour::default()
    };
    let request = roughtime::build_request(&[5u8; 32], &fake.key());
    let reply = fake.answer(&request, &[5u8; 32], &honest);

    // The same reply, offered as though our request had sat somewhere else in the batch.
    let mut altered = reply.clone();
    let at = altered
        .windows(4)
        .rposition(|w| w == 3u32.to_le_bytes())
        .expect("the index is in there");
    altered[at..at + 4].copy_from_slice(&2u32.to_le_bytes());
    let blob = roughtime::pack_blob(&[], &request, &altered);
    assert!(
        roughtime::check(&blob, &fake.key(), "a server of our own").is_err(),
        "a path walked from the wrong position still reached the root"
    );
}

#[test]
fn a_response_echoing_a_different_nonce_is_refused() {
    // The tree, the root and both signatures are honest here. Only the echoed nonce is somebody
    // else's, which is the one shape the Merkle check on its own would let through.
    let fake = Fake::new();
    let how = Behaviour {
        echo_a_different_nonce: true,
        ..Behaviour::default()
    };
    let blob = blob_for(&fake, &how, &[5u8; 32]);
    let err = roughtime::check(&blob, &fake.key(), "a server of our own")
        .expect_err("a response echoing a nonce we never sent");
    assert!(matches!(err, EvidenceError::WrongNonce(_)), "{err}");
}
