//! Real timestamp tokens from real authorities.
//!
//! Ignored by default. Run it by hand:
//!
//! ```text
//! cargo test -p timewitness-sources --test timestamp_live -- --ignored --nocapture
//! ```
//!
//! The second test is the one that decides whether an authority can be used at all, and it is the
//! reason there are two. Pinning a signing certificate works only where an authority answers from
//! the same certificate every time. One of the four tried on 2026-09-07 does not.

use std::collections::BTreeSet;

use timewitness_core::evidence::rfc3161::{self, Authority};
use timewitness_sources::timestamp::TimestampClient;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn candidates() -> Vec<(&'static str, &'static str)> {
    vec![
        ("freetsa.org", "http://freetsa.org/tsr"),
        ("DigiCert", "http://timestamp.digicert.com"),
        ("Sectigo", "http://timestamp.sectigo.com"),
        ("GlobalSign through ai.moda", "http://rfc3161.ai.moda"),
    ]
}

fn client_for(name: &str, url: &str, pins: Vec<[u8; 32]>) -> TimestampClient {
    TimestampClient::new(Authority {
        name: name.to_string(),
        url: url.to_string(),
        accepted_certificates: pins,
    })
}

#[test]
#[ignore = "talks to somebody else's authority"]
fn a_real_token_verifies_against_the_certificate_that_signed_it() {
    // One round trip per authority. The certificate that signed the token is found from the token,
    // then that same token is checked against it as a pin. Discovery and checking on one token
    // proves the parse and the signature arithmetic; whether a pin holds from one request to the
    // next is the next test and is a different question.
    let subject = [0x5au8; 32];
    let mut verified = 0;

    for (name, url) in candidates() {
        let discovering = client_for(name, url, Vec::new());
        let pin = match discovering.discover_pin(&subject) {
            Ok(p) => p,
            Err(e) => {
                println!("{name}: nothing to check, {e}");
                continue;
            }
        };

        let client = client_for(name, url, vec![pin]);
        let attestation = match client.stamp(&subject) {
            Ok(a) => a,
            Err(e) => {
                println!("{name}: answered and would not verify, {e}");
                continue;
            }
        };
        verified += 1;

        println!(
            "{name}: token {} bytes, states {} s, signed by certificate {}",
            attestation.blob.len(),
            attestation.at.as_nanos() / 1_000_000_000,
            hex(&pin)
        );
        for line in client
            .describe(&attestation.blob, &subject)
            .expect("what the client accepted, the check accepts")
        {
            println!("    {line}");
        }

        // The same token, offered as evidence about a different document.
        let mut other = subject;
        other[0] ^= 0x01;
        assert!(
            rfc3161::check(&attestation.blob, client.authority(), &other).is_err(),
            "{name}'s token verified as evidence about a hash it never saw"
        );

        // The same token, checked against a pin that is not the certificate that signed it.
        let mut wrong = client.authority().clone();
        wrong.accepted_certificates[0][0] ^= 0x01;
        assert!(
            rfc3161::check(&attestation.blob, &wrong, &subject).is_err(),
            "{name}'s token verified against a certificate nobody pinned"
        );

        println!("    blob {}", hex(&attestation.blob));

        // Spoil the reply a byte at a time and require that nothing it proves can change.
        //
        // Not every byte of a reply is signed. A token carries the chain the authority would like a
        // reader to have, and this check never looks at those, so a bit flipped inside one of them
        // changes nothing about what was proved. Demanding a refusal there would be demanding that
        // the check care about bytes it is right to ignore. What must hold is the property one
        // step up: no single byte change either passes and says something different, or passes and
        // says the same thing about a different document.
        let original = rfc3161::check(&attestation.blob, client.authority(), &subject)
            .expect("the token we just accepted");
        let stored = rfc3161::unpack_blob(&attestation.blob).expect("our own blob unpacks");
        let (request, reply) = (stored.request.to_vec(), stored.reply.to_vec());
        let mut refused = 0;
        let mut unchanged = 0;
        for step in 1..=40usize {
            let at = reply.len() * step / 41;
            let mut spoiled = reply.clone();
            spoiled[at] ^= 0x01;
            let blob = rfc3161::pack_blob(&request, &spoiled);
            match rfc3161::check(&blob, client.authority(), &subject) {
                Err(_) => refused += 1,
                Ok(changed) => {
                    assert_eq!(
                        (changed.earliest(), changed.latest(), changed.nonce),
                        (
                            original.earliest(),
                            original.latest(),
                            original.nonce.clone()
                        ),
                        "{name} accepted a token with byte {at} flipped and it said something \
                         different"
                    );
                    unchanged += 1;
                }
            }
        }
        println!(
            "    of 40 single byte changes, {refused} were refused and {unchanged} landed in bytes \
             nothing signed and proved the same thing"
        );
    }

    assert!(
        verified > 0,
        "no authority produced a token this code could check"
    );
}

#[test]
#[ignore = "talks to somebody else's authority"]
fn an_authority_that_answers_from_more_than_one_certificate_cannot_be_pinned_to_one() {
    // Four requests each. An authority that answers from one certificate every time can be pinned
    // to that one; an authority that rotates signing units needs every one of them pinned, and an
    // authority that adds units later will break a pin nobody updated. This is the operational
    // property that decides which authorities are worth building in.
    let subject = [0x77u8; 32];
    for (name, url) in candidates() {
        let client = client_for(name, url, Vec::new());
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut failures = 0;
        for _ in 0..4 {
            match client.discover_pin(&subject) {
                Ok(p) => {
                    seen.insert(hex(&p));
                }
                Err(_) => failures += 1,
            }
        }
        println!(
            "{name}: {} distinct signing certificates over four requests, {failures} did not answer",
            seen.len()
        );
        for pin in &seen {
            println!("    {pin}");
        }
    }
}
