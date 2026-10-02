//! Trust material a reader supplies, and the material that ships.
//!
//! "Offline-capable" is only a real property if there is a documented way to hand the verifier the
//! keys it checks against. Otherwise every run quietly needs a network call to look one up, and the
//! claim is an aspiration.
//!
//! So there are two routes and a reader picks. [`published`] is the set that ships: three Roughtime
//! server keys, one drand chain and two timestamp authority certificate pins, every one of them
//! published by a third party who has never heard of this product, and one key of our own, the one
//! that signs the head of our key log. [`parse`] reads a reader's own set out of a plain text file,
//! which is what somebody who would rather not take our word for which keys are which uses.
//!
//! Shipping a key is not being the root of trust for it. Each third-party key is a public fact a
//! reader can compare against its publisher's own list, and the file format exists so that comparing
//! is not the only option. Our own key is different in kind and is said to be: it makes nothing
//! third-party evidence. What it decides is whether a key log in front of the reader is one we
//! signed, so that the step `is that key one of ours` is answered off our list rather than off a
//! list anybody made.
//!
//! ## The file
//!
//! One anchor per line, blank lines and lines starting with `#` ignored, fields separated by spaces:
//!
//! ```text
//! roughtime <name> <32 bytes of hex>
//! drand     <name> <32 bytes of hex, the chain hash> <96 bytes of hex, the group key> <period seconds> <genesis unix second>
//! rfc3161   <name> <32 bytes of hex, a certificate digest> [more certificate digests] [allow=<ns>]
//! keylog    <name> <32 bytes of hex, the key that signs the head of our key log>
//! certification <nanoseconds since the Unix epoch, when certification by the app began>
//! ```
//!
//! `certification` is ours, like `keylog`, and it supports no evidence. It says from when the
//! verifier grades whether a receipt is a TimeWitness certificate, and a key log stating any other
//! moment is refused. What ships leaves it unset until the release that fixes it, so today every
//! receipt is graded as version 0 grades it.
//!
//! ## `allow=` on a timestamp authority
//!
//! A timestamp token may state the authority's own accuracy and may leave the field out, and
//! leaving it out is a statement the authority did not make rather than a statement of nought. A
//! token that states none puts no number on how wrong that authority's clock could be, so on its
//! own it bounds nothing in UTC and this verifier says so. Both authorities that ship are in that
//! state.
//!
//! RFC 3161 section 2.4.2 says where the field is absent "the accuracy may be available through
//! other means, e.g., the TSAPolicyId", meaning from the authority's published practice. A reader
//! who has read that practice writes what they allow as `allow=<whole nanoseconds>`, and from then
//! on the verifier reports a not-later-than edge for that authority and names the figure as the
//! reader's own rather than as anything the authority signed. It is used only where a token states
//! no accuracy; where one states an accuracy the authority's own figure wins.
//!
//! Nothing that ships carries an allowance, because this product has not read either authority's
//! practice statement and will not write a figure it cannot source.

use timewitness_core::evidence::drand::Chain;
use timewitness_core::evidence::rfc3161::{self, Authority};
use timewitness_core::evidence::roughtime;
use timewitness_core::time::Nanos;
use timewitness_core::UnixNanos;
use timewitness_receipt::anchors::TrustAnchors;

/// The key that signs the head of our key log, as of 2026-09-15.
///
/// The secret half is held outside every repository and has signed nothing that was served. A
/// rotation is a new entry here and a new head on the log, and a reader who would rather hold a
/// different key names it in their own anchors file, which replaces this one.
pub const KEY_LOG_SIGNER: [u8; 32] = [
    0x54, 0x85, 0x0c, 0x83, 0x61, 0x0a, 0x33, 0xe4, 0x46, 0x30, 0x9a, 0x31, 0xc1, 0x4e, 0x12, 0x26,
    0x0c, 0x68, 0xe7, 0x24, 0x0c, 0x9b, 0x54, 0x22, 0x90, 0x93, 0xfd, 0x2c, 0x96, 0x39, 0x9a, 0x05,
];

/// The name the shipped key log signer is reported under.
pub const KEY_LOG_SIGNER_NAME: &str = "our key log";

/// When certification by the app began, as this code ships it.
///
/// Unset. It is fixed once, by the release that serves the key log entry stating it under a head
/// carrying a beacon round and a timestamp token, and it never moves after that. Until then every
/// receipt is graded as version 0 grades it, and the certificate grade is reached only by a reader
/// who names a moment in their own trust material.
pub const CERTIFICATION_BEGAN: Option<i128> = None;

/// The anchors that ship with this code.
///
/// Every evidence key on this list is published by somebody else. The reader who wants to check
/// that for themselves compares each against the publisher's own list; the reader who would rather
/// not trust the shipped copy supplies a file instead. The one key that is ours is the key log's
/// signer, and it vouches for no evidence.
#[must_use]
pub fn published() -> TrustAnchors {
    let mut anchors = TrustAnchors::none().with_drand(Chain::quicknet());
    for key in roughtime::published_keys() {
        anchors = anchors.with_roughtime(key.name, key.long_term_public_key);
    }
    for authority in rfc3161::published_authorities() {
        anchors = anchors.with_authority(authority);
    }
    let mut anchors = anchors.with_key_log_signer(KEY_LOG_SIGNER_NAME, KEY_LOG_SIGNER);
    anchors.certification_began = CERTIFICATION_BEGAN.map(UnixNanos);
    anchors
}

/// Why a trust material file could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorError {
    /// Which line, counting from one, so a reader can go straight to it.
    pub line: usize,
    /// What is wrong with it.
    pub detail: String,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "line {}: {}", self.line, self.detail)
    }
}

impl std::error::Error for AnchorError {}

/// Read a reader's own trust material.
///
/// Refuses rather than skipping. A line nobody could parse is a key the reader meant to trust, and
/// dropping it silently would leave them checking a receipt against less than they think, which is
/// the one failure this whole crate is built to avoid.
pub fn parse(text: &str) -> Result<TrustAnchors, AnchorError> {
    let mut anchors = TrustAnchors::none();

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let fail = |detail: String| AnchorError { line, detail };

        match fields[0] {
            "roughtime" => {
                if fields.len() != 3 {
                    return Err(fail(
                        "a roughtime anchor is the word, a name and thirty-two bytes of hex".into(),
                    ));
                }
                let key = fixed::<32>(fields[2]).map_err(&fail)?;
                anchors = anchors.with_roughtime(fields[1].to_string(), key);
            }
            "drand" => {
                if fields.len() != 6 {
                    return Err(fail(
                        "a drand anchor is the word, a name, the chain hash, the group key, the \
                         period in seconds and the genesis second"
                            .into(),
                    ));
                }
                anchors = anchors.with_drand(Chain {
                    // The chain's name is compiled into a receipt's report rather than compared, so
                    // it is leaked here as a static string the reader chose.
                    name: Box::leak(fields[1].to_string().into_boxed_str()),
                    hash: fixed::<32>(fields[2]).map_err(&fail)?,
                    public_key: fixed::<96>(fields[3]).map_err(&fail)?,
                    period_seconds: fields[4]
                        .parse()
                        .map_err(|_| fail("the period is not a whole number of seconds".into()))?,
                    genesis_time: fields[5]
                        .parse()
                        .map_err(|_| fail("the genesis time is not a Unix second".into()))?,
                });
            }
            "rfc3161" => {
                if fields.len() < 3 {
                    return Err(fail(
                        "an rfc3161 anchor is the word, a name and at least one certificate \
                         digest, and may carry allow=<ns> for the authority's own clock where its \
                         tokens state no accuracy"
                            .into(),
                    ));
                }
                // `allow=` is the reader saying what they allow for this authority's clock where a
                // token states no accuracy of its own. It is told from a certificate digest by the
                // equals sign, which no hex digest carries. Written once at most, because two
                // figures for one authority is a reader who has not decided.
                let mut certificates = Vec::new();
                let mut allowance: Option<Nanos> = None;
                for field in &fields[2..] {
                    if let Some(value) = field.strip_prefix("allow=") {
                        if allowance.is_some() {
                            return Err(fail(
                                "an rfc3161 anchor states allow= twice, and one authority has one \
                                 allowance"
                                    .into(),
                            ));
                        }
                        let nanos: Nanos = value
                            .parse()
                            .map_err(|_| fail("allow= is a whole number of nanoseconds".into()))?;
                        if nanos < 0 {
                            return Err(fail(
                                "allow= is negative, and no clock is wrong by less than nothing"
                                    .into(),
                            ));
                        }
                        allowance = Some(nanos);
                        continue;
                    }
                    certificates.push(fixed::<32>(field).map_err(&fail)?);
                }
                if certificates.is_empty() {
                    return Err(fail(
                        "an rfc3161 anchor carries no certificate digest, so there is nothing a \
                         token could be checked against"
                            .into(),
                    ));
                }
                anchors = anchors.with_authority(Authority {
                    name: fields[1].to_string(),
                    // A verifier never fetches, so there is nowhere to ask and the address is empty
                    // rather than invented.
                    url: String::new(),
                    accepted_certificates: certificates,
                    accuracy_where_the_token_states_none: allowance,
                });
            }
            "keylog" => {
                if fields.len() != 3 {
                    return Err(fail(
                        "a keylog anchor is the word, a name and thirty-two bytes of hex".into(),
                    ));
                }
                let key = fixed::<32>(fields[2]).map_err(&fail)?;
                anchors = anchors.with_key_log_signer(fields[1].to_string(), key);
            }
            "certification" => {
                if fields.len() != 2 {
                    return Err(fail(
                        "a certification line is the word and one moment in nanoseconds".into(),
                    ));
                }
                if anchors.certification_began.is_some() {
                    return Err(fail(
                        "certification is stated twice, and it began once".into(),
                    ));
                }
                let at: i128 = fields[1]
                    .parse()
                    .map_err(|_| fail("certification is a whole number of nanoseconds".into()))?;
                anchors.certification_began = Some(UnixNanos(at));
            }
            other => {
                return Err(fail(format!(
                    "{other:?} is not a kind of anchor. This reads roughtime, drand, rfc3161, \
                     keylog and certification"
                )))
            }
        }
    }

    Ok(anchors)
}

/// Exactly `N` bytes of lower or upper case hexadecimal.
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let bytes = unhex(text)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| {
        format!(
            "{N} bytes of hex were expected and {} arrived",
            text.len() / 2
        )
    })
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hexadecimal comes in pairs and this has an odd number of digits".to_string());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = digit(pair[0])?;
        let lo = digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!(
            "{:?} is not a hexadecimal digit",
            char::from(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_set_holds_all_three_kinds_and_our_key_log_signer() {
        let anchors = published();
        assert_eq!(anchors.roughtime_servers.len(), 3);
        assert_eq!(anchors.drand_chains.len(), 1);
        assert_eq!(anchors.timestamp_authorities.len(), 2);
        assert_eq!(anchors.key_log_signer_keys(), vec![KEY_LOG_SIGNER]);
        assert_eq!(
            anchors.count(),
            6,
            "our own key is held and is not counted as evidence material"
        );
    }

    #[test]
    fn a_reader_can_supply_their_own() {
        let text = "\
# my own list
roughtime somewhere 4b70337d92790a349d909db564919bc6a7583ff4a813c7d7298d3e6a272c7a12
rfc3161 an-authority 2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc
keylog my-copy-of-theirs 54850c83610a33e446309a31c14e12260c68e7240c9b54229093fd2c96399a05
";
        let anchors = parse(text).expect("three well-formed lines");
        assert_eq!(anchors.roughtime_servers.len(), 1);
        assert_eq!(anchors.timestamp_authorities.len(), 1);
        assert_eq!(anchors.key_log_signer_keys(), vec![KEY_LOG_SIGNER]);
        assert_eq!(anchors.count(), 2);

        let err = parse("keylog only-two-fields").expect_err("a key is missing");
        assert!(err.detail.contains("thirty-two bytes"), "{}", err.detail);
    }

    #[test]
    fn a_line_nobody_can_parse_refuses_rather_than_being_skipped() {
        // Skipping it would leave the reader checking against less than they think they are.
        let err = parse("roughtime somewhere not-hex").expect_err("that is not a key");
        assert_eq!(err.line, 1);

        let err = parse("\n\nsomething-else name 00").expect_err("that is not a kind of anchor");
        assert_eq!(err.line, 3);

        let err = parse("roughtime only-two-fields").expect_err("a key is missing");
        assert!(err.detail.contains("thirty-two bytes"), "{}", err.detail);
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let err = parse("roughtime somewhere 4b70").expect_err("four hex digits is not a key");
        assert!(err.detail.contains("32 bytes"), "{}", err.detail);
    }

    /// Nothing that ships allows anything for an authority's own clock.
    ///
    /// Changed 2026-09-19. A token that states no accuracy puts no number on how wrong its
    /// authority's clock could be, and both authorities that ship are in that state, so on the
    /// shipped material nothing bounds a receipt from above. Writing a figure here would be
    /// quoting somebody's practice statement we have not read, and this holds it at none.
    #[test]
    fn the_shipped_authorities_allow_nothing_for_their_own_clocks() {
        for authority in published().timestamp_authorities {
            assert_eq!(
                authority.accuracy_where_the_token_states_none, None,
                "{} ships with a figure allowed for its clock that nobody sourced",
                authority.name
            );
        }
    }

    /// A reader says what they allow, once, as whole nanoseconds, and it is told from a pin.
    #[test]
    fn a_reader_can_say_what_they_allow_for_an_authoritys_clock() {
        let pin = "2da09da7f4131f9fe72db6c5e6e9c9656755af043f1ea742cc0d2120e141ebfc";
        let anchors = parse(&format!("rfc3161 an-authority {pin} allow=1000000000\n"))
            .expect("a pin and an allowance");
        let authority = &anchors.timestamp_authorities[0];
        assert_eq!(authority.accepted_certificates.len(), 1);
        assert_eq!(
            authority.accuracy_where_the_token_states_none,
            Some(1_000_000_000)
        );

        // The field is optional and its absence is the ordinary case.
        let plain = parse(&format!("rfc3161 an-authority {pin}\n")).expect("a pin alone");
        assert_eq!(
            plain.timestamp_authorities[0].accuracy_where_the_token_states_none,
            None
        );

        // It may sit before the pins as well as after them, because it is told from a digest by
        // the equals sign rather than by where it is written.
        let first = parse(&format!("rfc3161 an-authority allow=250 {pin}\n"))
            .expect("an allowance before the pin");
        assert_eq!(
            first.timestamp_authorities[0].accuracy_where_the_token_states_none,
            Some(250)
        );
        assert_eq!(
            first.timestamp_authorities[0].accepted_certificates.len(),
            1
        );

        for (line, why) in [
            (
                format!("rfc3161 an-authority {pin} allow=250 allow=500\n"),
                "one authority has one allowance",
            ),
            (
                format!("rfc3161 an-authority {pin} allow=-1\n"),
                "wrong by less than nothing",
            ),
            (
                format!("rfc3161 an-authority {pin} allow=a-second\n"),
                "whole number of nanoseconds",
            ),
            (
                "rfc3161 an-authority allow=250\n".to_string(),
                "nothing a token could be checked against",
            ),
        ] {
            let err = parse(&line).expect_err(&format!("{line:?} was accepted"));
            assert!(err.to_string().contains(why), "{line:?} said {err}");
        }
    }
}
