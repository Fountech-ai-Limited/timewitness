//! The key log as a file, so a reader can be handed one and check it with no network.
//!
//! # Why there is a file format at all
//!
//! [`super`] is the tree, the proofs and the rule for whether a key stood at a moment. None of that
//! reaches a reader: until this file existed the verifier's `is that key one of ours` step read
//! `nothing here can say`, and it would have gone on reading that however good the tree was,
//! because there was no way to put a log in front of the verifier.
//!
//! The honest intermediate step, and it is this one, is a log a reader holds as a file. It needs no
//! server, no account and nothing of ours running, which is the same property the verifier itself
//! has and for the same reason: a check only we can run is not a check.
//!
//! # What a reader with this file can conclude, and what they still cannot
//!
//! They can conclude that the key that signed their receipt appears in this log with a window that
//! covers the reading, that the entries hash to the root the head states, and that the head carries
//! a signature by the key it names. **They cannot conclude that the log is honest**, and nothing in
//! a format fixes that: a log only we sign could have been signed differently for them than for
//! everybody else, which is the split-view attack the module heading above sets out. What the log
//! buys is that a key we published is one we cannot quietly unpublish, to anybody who kept an
//! earlier head.
//!
//! So the rule that our own word is never third-party evidence is untouched by any of this. The
//! weight of a receipt rests on the third-party signatures in it. A key log of ours is our own
//! party twice over, and the verifier says so in the step it answers.
//!
//! # The format
//!
//! Lines, because the file is read by a crate that ships to strangers and every dependency it links
//! is one they have to be comfortable with. The same reasoning is written out in the command line's
//! own argument parser.
//!
//! ```text
//! timewitness-key-log v1
//! entry agent   <public key, 64 hex> <valid from, nanos> <valid until, nanos or -> <deployment>
//! entry server  <public key, 64 hex> <valid from, nanos> <valid until, nanos or -> <deployment>
//! entry retired <public key, 64 hex> <retired at, nanos> - <note>
//! head <size> <root, 64 hex> <at, nanos> <signature, 128 hex> <signed by, 64 hex>
//! ```
//!
//! Blank lines and lines beginning with `#` are ignored, so a log can carry a note about where it
//! came from. The deployment name is last because it is the one field that may hold a space; it may
//! not hold a newline, and the writer refuses one rather than producing a file that reads back as
//! something else.
//!
//! `v1` because the leaf gained a version byte and a role on 2026-09-15, before any head was served,
//! and a `v0` file read under this parser would take the key for a role. No `v0` log was ever
//! served, so a file that says `v0` is refused with that said rather than read.
//!
//! The head is optional in the format and answers nothing when absent: a reader has entries nobody
//! has put their name to, and the verifier says so and leaves its question unanswered. A log with a
//! head whose root disagrees with its own entries is refused outright rather than read as either.
//!
//! # Version 2, for certificates
//!
//! ```text
//! timewitness-key-log v2
//! entry certificate <public key> <valid from> <valid until> <organisation> <method> <label>
//! entry cutoff      <public key> <certification began, nanos> - <note>
//! head <size> <root> <at> <signature> <signed by>
//! beacon <a drand round, as the evidence blob a receipt carries, hex>
//! witness <an rfc3161 token over the head and its signature, as a receipt carries one, hex>
//! ```
//!
//! A `v2` file is a history rather than a snapshot: a head sits directly below the entries it
//! covers, and every head the log ever served stays in the file. That is what lets a reader find
//! the first head that carried an entry, and so the beacon round that entry cannot have been
//! written before. A `beacon` line belongs to the head above it and is signed with it; a `witness`
//! line belongs to the head above it and is about that head's bytes and signature together. The
//! last head covers every entry. A `v1` reader refuses a `v2` file by its first line, which is the
//! refusal it should give, and a `v1` file reads exactly as it always did.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::{root, Issued, KeyEntry, LogError, Role, Standing, TreeHead};
use crate::time::UnixNanos;

/// What the first line of a log says it is.
pub const MAGIC: &str = "timewitness-key-log v1";

/// What the first line of a log carrying certificates, or more than one head, says it is.
pub const MAGIC_V2: &str = "timewitness-key-log v2";

/// What the first line of a log written before the leaf carried a version and a role said.
const RETIRED_MAGIC: &str = "timewitness-key-log v0";

/// A head with the signature somebody put on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    /// What the log held.
    pub head: TreeHead,
    /// The signature over [`TreeHead::canonical`].
    pub signature: [u8; 64],
    /// The key that signature is by.
    ///
    /// Stated in the file rather than assumed, and a reader who does not already know this key
    /// learns nothing from it. It is here so that a reader who **does** know it can tell whether
    /// the head in front of them is the one they think it is, which is the whole of what a head is
    /// for.
    pub signed_by: [u8; 32],
    /// An RFC 3161 token over [`SignedHead::witness_digest`], stored as a receipt stores one.
    ///
    /// Not signed over by the head, because it is about the head. It is what puts the head no
    /// later than a moment on somebody else's clock.
    pub witness: Option<Vec<u8>>,
}

impl SignedHead {
    /// The digest a witness over this head is a token about: the head's bytes and its signature.
    #[must_use]
    pub fn witness_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.head.canonical());
        hasher.update(self.signature);
        hasher.finalize().into()
    }
}

/// A key log as it was read off a file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyLog {
    /// The entries, in the order the log holds them. Order is part of the tree.
    pub entries: Vec<KeyEntry>,
    /// The signed head, where the file carries one. In a `v2` file, the newest.
    pub head: Option<SignedHead>,
    /// Every earlier head, oldest first, each over the entries above it in the file.
    pub checkpoints: Vec<SignedHead>,
}

impl KeyLog {
    /// The root over this log's entries.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        root(
            &self
                .entries
                .iter()
                .map(KeyEntry::leaf_hash)
                .collect::<Vec<_>>(),
        )
    }

    /// Whether this log vouches for an agent key at a moment.
    #[must_use]
    pub fn standing(&self, key: &[u8; 32], at: UnixNanos) -> Standing {
        super::standing(&self.entries, key, at)
    }

    /// Every head, oldest first.
    pub fn heads(&self) -> impl Iterator<Item = &SignedHead> {
        self.checkpoints.iter().chain(self.head.iter())
    }

    /// The first head that covered the entry at `index`, which is when the log first said it.
    #[must_use]
    pub fn first_head_covering(&self, index: usize) -> Option<&SignedHead> {
        self.heads().find(|signed| signed.head.size > index)
    }

    /// Whether this log needs the `v2` format to be written down.
    #[must_use]
    pub fn needs_version_2(&self) -> bool {
        !self.checkpoints.is_empty()
            || self
                .entries
                .iter()
                .any(|e| matches!(e.role, Role::Certificate | Role::Cutoff))
            || self
                .heads()
                .any(|h| h.head.beacon.is_some() || h.witness.is_some())
    }

    /// Whether every earlier head is signed by a key the reader holds for us.
    ///
    /// The newest head is answered by [`KeyLog::check_head`]. An earlier one somebody else signed
    /// would date an entry on their word, so it is reported rather than read past.
    #[must_use]
    pub fn checkpoints_are_ours(&self, held: &[[u8; 32]]) -> bool {
        self.checkpoints.iter().all(|signed| {
            held.contains(&signed.signed_by)
                && VerifyingKey::from_bytes(&signed.signed_by).is_ok_and(|key| {
                    key.verify_strict(
                        &signed.head.canonical(),
                        &Signature::from_bytes(&signed.signature),
                    )
                    .is_ok()
                })
        })
    }

    /// How many entries say an agent key was ours. A log with none has nothing to say about the
    /// key that signed a receipt, and the verifier says that rather than refusing.
    #[must_use]
    pub fn agent_entries(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.role == Role::Agent)
            .count()
    }

    /// Whether the head this log carries is signed by the key it names.
    ///
    /// `None` where there is no head. A head whose signature does not check is a head somebody
    /// edited, and the entries under it are then worth exactly what an unsigned list is worth.
    ///
    /// `verify_strict` rather than `verify`, as a receipt's own signature is checked: the two differ
    /// on keys and signatures with a small order component, which no honest signer produces and
    /// which give one head more than one valid signature.
    #[must_use]
    pub fn head_is_signed_by_the_key_it_names(&self) -> Option<bool> {
        let signed = self.head.as_ref()?;
        let Ok(key) = VerifyingKey::from_bytes(&signed.signed_by) else {
            return Some(false);
        };
        Some(
            key.verify_strict(
                &signed.head.canonical(),
                &Signature::from_bytes(&signed.signature),
            )
            .is_ok(),
        )
    }

    /// The head, checked against the keys a reader holds for us.
    ///
    /// This is the check that makes a log ours rather than somebody's. A head names the key that
    /// signed it, and until 2026-09-15 the verifier checked the signature against that key and
    /// nothing else, so a log signed a minute ago by a key from `os.urandom` read as a list we
    /// signed. The key a reader holds for us is trust material the reader chose, carried the way
    /// the Roughtime keys are: a published default, and a file of their own where they would rather
    /// not take the shipped copy.
    #[must_use]
    pub fn check_head(&self, held: &[[u8; 32]]) -> HeadCheck {
        match self.head_is_signed_by_the_key_it_names() {
            None => HeadCheck::None,
            Some(false) => HeadCheck::BadSignature,
            Some(true) => {
                let signer = self
                    .head
                    .as_ref()
                    .expect("a checked head is a head")
                    .signed_by;
                if held.contains(&signer) {
                    HeadCheck::Checked(signer)
                } else {
                    HeadCheck::SignerNotHeld(signer)
                }
            }
        }
    }
}

/// What a reader established about a log's head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadCheck {
    /// The log carries no head, so nobody has put their name to it.
    None,
    /// The head is not signed by the key it names: the log was edited or the signature was moved.
    BadSignature,
    /// A real signature by the key the head names, and that key is not one the reader holds for
    /// us. Whatever the list says, it is not us saying it.
    SignerNotHeld([u8; 32]),
    /// A real signature by a key the reader holds for us.
    Checked([u8; 32]),
}

impl HeadCheck {
    /// One word for a script.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            HeadCheck::None => "none",
            HeadCheck::BadSignature => "bad-signature",
            HeadCheck::SignerNotHeld(_) => "signer-not-held",
            HeadCheck::Checked(_) => "checked",
        }
    }

    /// The key that signed the head, where a real signature was found.
    #[must_use]
    pub const fn signed_by(self) -> Option<[u8; 32]> {
        match self {
            HeadCheck::SignerNotHeld(key) | HeadCheck::Checked(key) => Some(key),
            HeadCheck::None | HeadCheck::BadSignature => None,
        }
    }
}

/// Sign a head over what a log holds now.
///
/// Here rather than in the caller because the signing and the checking are two halves of one
/// statement, and the thing signed is [`TreeHead::canonical`], which nobody outside this module
/// should be assembling by hand. `at` is when we said the log held this, which is a statement about
/// us rather than a measurement: it carries no bound and claims none.
#[must_use]
pub fn sign_head(log: &KeyLog, secret: &[u8; 32], at: UnixNanos) -> SignedHead {
    sign_head_after(log, secret, at, None)
}

/// Sign a head that carries a beacon round, so the head was made after that round was published.
///
/// `beacon` is a drand round stored as a receipt stores one. The witness is added afterwards, into
/// [`SignedHead::witness`], because it is a token about the signed head.
#[must_use]
pub fn sign_head_after(
    log: &KeyLog,
    secret: &[u8; 32],
    at: UnixNanos,
    beacon: Option<Vec<u8>>,
) -> SignedHead {
    let signing = SigningKey::from_bytes(secret);
    let head = TreeHead {
        size: log.entries.len(),
        root: log.root(),
        at,
        beacon,
    };
    SignedHead {
        signature: signing.sign(&head.canonical()).to_bytes(),
        signed_by: signing.verifying_key().to_bytes(),
        head,
        witness: None,
    }
}

/// Why a file was not a key log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    /// The first line does not say what this is.
    NotAKeyLog(String),
    /// A line could not be read.
    BadLine(usize, String),
    /// The head does not describe the entries under it.
    HeadDisagrees(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::NotAKeyLog(d) => write!(f, "this is not a key log: {d}"),
            FormatError::BadLine(n, d) => write!(f, "line {n}: {d}"),
            FormatError::HeadDisagrees(d) => {
                write!(f, "the head does not describe its own entries: {d}")
            }
        }
    }
}

impl From<FormatError> for LogError {
    fn from(e: FormatError) -> Self {
        LogError::Malformed(e.to_string())
    }
}

/// Read a key log.
///
/// # Errors
///
/// A file that does not begin with [`MAGIC`] or [`MAGIC_V2`], a line that is not an entry or a
/// head, a second head in a `v1` file, and a head whose size or root disagrees with the entries it
/// covers. The last of those is checked here rather than left to the caller: a file that is
/// internally inconsistent is not a log with a problem, it is two different logs in one file, and
/// reading it as either would be a guess.
pub fn parse(text: &str) -> Result<KeyLog, FormatError> {
    let mut lines = text.lines().enumerate();

    let first = lines
        .find(|(_, line)| !is_skipped(line))
        .ok_or_else(|| FormatError::NotAKeyLog("the file is empty".to_string()))?;
    if first.1.trim() == RETIRED_MAGIC {
        return Err(FormatError::NotAKeyLog(format!(
            "this is a {RETIRED_MAGIC:?} log, a format that carried no role on an entry and was \
             never served. Rewrite it as {MAGIC:?} with a role on each entry"
        )));
    }
    let v2 = match first.1.trim() {
        MAGIC => false,
        MAGIC_V2 => true,
        other => {
            return Err(FormatError::NotAKeyLog(format!(
                "the first line reads {other:?} and a key log begins {MAGIC:?} or {MAGIC_V2:?}"
            )))
        }
    };

    let mut log = KeyLog::default();
    // Whether the line above was a head or belonged to one, so a beacon or a witness can only sit
    // directly under the head it is about.
    let mut under_a_head = false;
    for (index, line) in lines {
        let number = index + 1;
        if is_skipped(line) {
            continue;
        }
        let (kind, rest) = split_once(line.trim());
        match kind {
            "entry" => {
                let entry = read_entry(number, rest)?;
                if !v2 && matches!(entry.role, Role::Certificate | Role::Cutoff) {
                    return Err(FormatError::BadLine(
                        number,
                        format!(
                            "a {} entry in a {MAGIC:?} file. It is written in {MAGIC_V2:?}",
                            entry.role.word()
                        ),
                    ));
                }
                log.entries.push(entry);
                under_a_head = false;
            }
            "head" => {
                let signed = read_head(number, rest)?;
                if let Some(previous) = log.head.take() {
                    if !v2 {
                        return Err(FormatError::BadLine(
                            number,
                            "a second head, and a file with two of them states two different logs"
                                .to_string(),
                        ));
                    }
                    if signed.head.size <= previous.head.size {
                        return Err(FormatError::BadLine(
                            number,
                            format!(
                                "a head over {} entries below one over {}. Each head covers more \
                                 than the one above it",
                                signed.head.size, previous.head.size
                            ),
                        ));
                    }
                    log.checkpoints.push(previous);
                }
                if v2 {
                    // In a history each head sits under exactly the entries it covers, so where
                    // it sits is part of what it says.
                    if signed.head.size != log.entries.len() {
                        return Err(FormatError::HeadDisagrees(format!(
                            "the head on line {number} states {} entries and sits under {}",
                            signed.head.size,
                            log.entries.len()
                        )));
                    }
                    if signed.head.root != root_of(&log.entries) {
                        return Err(FormatError::HeadDisagrees(format!(
                            "the entries above line {number} do not hash to the root its head \
                             states"
                        )));
                    }
                }
                log.head = Some(signed);
                under_a_head = true;
            }
            "beacon" | "witness" if v2 => {
                let blob = read_blob(number, rest)?;
                let signed = match (under_a_head, log.head.as_mut()) {
                    (true, Some(signed)) => signed,
                    _ => {
                        return Err(FormatError::BadLine(
                            number,
                            format!("a {kind} line that does not sit under a head"),
                        ))
                    }
                };
                let slot = if kind == "beacon" {
                    &mut signed.head.beacon
                } else {
                    &mut signed.witness
                };
                if slot.is_some() {
                    return Err(FormatError::BadLine(
                        number,
                        format!("a second {kind} on one head"),
                    ));
                }
                *slot = Some(blob);
            }
            other => {
                return Err(FormatError::BadLine(
                    number,
                    format!("{other:?} is not `entry` or `head`"),
                ))
            }
        }
    }

    if let Some(signed) = &log.head {
        if signed.head.size != log.entries.len() {
            return Err(FormatError::HeadDisagrees(format!(
                "the head states {} entries and the file carries {}",
                signed.head.size,
                log.entries.len()
            )));
        }
        if signed.head.root != log.root() {
            return Err(FormatError::HeadDisagrees(
                "the entries in this file do not hash to the root the head states".to_string(),
            ));
        }
    }

    Ok(log)
}

fn root_of(entries: &[KeyEntry]) -> [u8; 32] {
    root(&entries.iter().map(KeyEntry::leaf_hash).collect::<Vec<_>>())
}

/// Write a key log.
///
/// A log that needs nothing `v2` carries is written as `v1`, byte for byte as it always was.
///
/// # Errors
///
/// A deployment name holding a newline, which would read back as a different file from the one that
/// was written. Refused rather than escaped: a log is a thing people copy between machines and a
/// format with an escaping rule is a format two implementations disagree about. Also an entry
/// carrying fields its role does not allow, and heads that are not a history of these entries.
pub fn write(log: &KeyLog) -> Result<String, FormatError> {
    let v2 = log.needs_version_2();
    let mut out = String::from(if v2 { MAGIC_V2 } else { MAGIC });
    out.push('\n');
    let heads: Vec<&SignedHead> = log.heads().collect();
    if v2 {
        for (a, b) in heads.iter().zip(heads.iter().skip(1)) {
            if b.head.size <= a.head.size {
                return Err(FormatError::HeadDisagrees(
                    "two heads that are not in the order the log grew".to_string(),
                ));
            }
        }
        if let Some(last) = heads.last() {
            if last.head.size != log.entries.len() {
                return Err(FormatError::HeadDisagrees(
                    "the newest head does not cover every entry".to_string(),
                ));
            }
        }
    }
    let mut next_head = heads.iter().peekable();
    if v2 {
        while let Some(signed) = next_head.next_if(|h| h.head.size == 0) {
            write_head(&mut out, signed);
        }
    }
    for (index, entry) in log.entries.iter().enumerate() {
        out.push_str(&entry_line(index + 1, entry)?);
        if v2 {
            while let Some(signed) = next_head.next_if(|h| h.head.size == index + 1) {
                write_head(&mut out, signed);
            }
        }
    }
    if !v2 {
        if let Some(signed) = &log.head {
            write_head(&mut out, signed);
        }
    }
    Ok(out)
}

fn entry_line(number: usize, entry: &KeyEntry) -> Result<String, FormatError> {
    if entry.deployment.contains('\n') || entry.deployment.contains('\r') {
        return Err(FormatError::BadLine(
            number,
            "a deployment name with a line break in it".to_string(),
        ));
    }
    check_role_fields(number, entry.role, entry.valid_until, entry.issued.as_ref())?;
    let until = match entry.valid_until {
        Some(until) => until.0.to_string(),
        None => "-".to_string(),
    };
    let issued = match &entry.issued {
        Some(issued) => format!("{} {} ", issued.organisation, issued.method),
        None => String::new(),
    };
    Ok(format!(
        "entry {} {} {} {until} {issued}{}\n",
        entry.role.word(),
        hex(&entry.public_key),
        entry.valid_from.0,
        entry.deployment
    ))
}

fn write_head(out: &mut String, signed: &SignedHead) {
    out.push_str(&format!(
        "head {} {} {} {} {}\n",
        signed.head.size,
        hex(&signed.head.root),
        signed.head.at.0,
        hex(&signed.signature),
        hex(&signed.signed_by)
    ));
    if let Some(beacon) = &signed.head.beacon {
        out.push_str(&format!("beacon {}\n", hex(beacon)));
    }
    if let Some(witness) = &signed.witness {
        out.push_str(&format!("witness {}\n", hex(witness)));
    }
}

/// What each role may and must carry, checked the same way on the way in and on the way out.
fn check_role_fields(
    number: usize,
    role: Role,
    until: Option<UnixNanos>,
    issued: Option<&Issued>,
) -> Result<(), FormatError> {
    let bad = |why: String| Err(FormatError::BadLine(number, why));
    match role {
        Role::Retired | Role::Cutoff if until.is_some() => bad(format!(
            "a {} entry with an end on it. It is one moment and closes every window from it on",
            role.word()
        )),
        Role::Certificate if until.is_none() => bad(
            "a certificate with no end. A certificate is for a short window, and it ends"
                .to_string(),
        ),
        Role::Certificate => match issued {
            None => bad("a certificate that names no organisation and no method".to_string()),
            Some(i)
                if i.organisation.is_empty()
                    || i.method.is_empty()
                    || i.organisation.contains(char::is_whitespace)
                    || i.method.contains(char::is_whitespace) =>
            {
                bad("a certificate's organisation and method are one word each".to_string())
            }
            Some(_) => Ok(()),
        },
        _ if issued.is_some() => {
            bad("an organisation and a method on an entry that is not a certificate".to_string())
        }
        _ => Ok(()),
    }
}

fn is_skipped(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

fn split_once(line: &str) -> (&str, &str) {
    match line.split_once(char::is_whitespace) {
        Some((kind, rest)) => (kind, rest.trim_start()),
        None => (line, ""),
    }
}

fn read_entry(number: usize, rest: &str) -> Result<KeyEntry, FormatError> {
    let mut parts = rest.splitn(5, char::is_whitespace);
    let role = field(number, parts.next(), "a role")?;
    let key = field(number, parts.next(), "a public key")?;
    let from = field(number, parts.next(), "a valid-from in nanoseconds")?;
    let until = field(number, parts.next(), "a valid-until, or -")?;
    // The name takes the rest of the line, spaces and all, which is why it is last.
    let mut deployment = parts.next().unwrap_or("").trim().to_string();

    let role = Role::from_word(role).ok_or_else(|| {
        FormatError::BadLine(
            number,
            format!(
                "{role:?} is not a role. An entry is agent, server, retired, certificate or cutoff"
            ),
        )
    })?;

    // A certificate's organisation and method sit before the name, one word each.
    let issued = if role == Role::Certificate {
        let text = deployment.clone();
        let mut words = text.splitn(3, char::is_whitespace);
        let organisation = field(number, words.next(), "an organisation")?.to_string();
        let method = field(number, words.next(), "a method")?.to_string();
        deployment = words.next().unwrap_or("").trim().to_string();
        Some(Issued {
            organisation,
            method,
        })
    } else {
        None
    };

    if deployment.is_empty() {
        return Err(FormatError::BadLine(
            number,
            "an entry with no deployment name. A name nobody chose is a name nobody can check"
                .to_string(),
        ));
    }

    let valid_until = match until {
        "-" => None,
        text => Some(UnixNanos(number_field(number, text)?)),
    };
    check_role_fields(number, role, valid_until, issued.as_ref())?;

    Ok(KeyEntry {
        public_key: from_hex_32(key)
            .ok_or_else(|| FormatError::BadLine(number, format!("{key:?} is not a 32-byte key")))?,
        role,
        deployment,
        valid_from: UnixNanos(number_field(number, from)?),
        valid_until,
        issued,
    })
}

fn read_blob(number: usize, rest: &str) -> Result<Vec<u8>, FormatError> {
    let text = rest.trim();
    let refused = || FormatError::BadLine(number, "a blob is one run of hexadecimal".to_string());
    if text.is_empty() || text.len() % 2 != 0 || text.contains(char::is_whitespace) {
        return Err(refused());
    }
    let mut out = vec![0u8; text.len() / 2];
    read_hex(text, &mut out).ok_or_else(refused)?;
    Ok(out)
}

fn read_head(number: usize, rest: &str) -> Result<SignedHead, FormatError> {
    let mut parts = rest.split_whitespace();
    let size = field(number, parts.next(), "a size")?;
    let root_hex = field(number, parts.next(), "a root")?;
    let at = field(number, parts.next(), "a moment in nanoseconds")?;
    let signature = field(number, parts.next(), "a signature")?;
    let signed_by = field(number, parts.next(), "the key that signed it")?;
    if parts.next().is_some() {
        return Err(FormatError::BadLine(
            number,
            "more on the head line than a head has".to_string(),
        ));
    }

    let size = size
        .parse::<usize>()
        .map_err(|_| FormatError::BadLine(number, format!("{size:?} is not a size")))?;

    Ok(SignedHead {
        head: TreeHead {
            size,
            root: from_hex_32(root_hex).ok_or_else(|| {
                FormatError::BadLine(number, format!("{root_hex:?} is not a 32-byte root"))
            })?,
            at: UnixNanos(number_field(number, at)?),
            beacon: None,
        },
        signature: from_hex_64(signature).ok_or_else(|| {
            FormatError::BadLine(number, "the signature is not 64 bytes".to_string())
        })?,
        signed_by: from_hex_32(signed_by).ok_or_else(|| {
            FormatError::BadLine(number, "the signing key is not 32 bytes".to_string())
        })?,
        witness: None,
    })
}

fn field<'a>(number: usize, got: Option<&'a str>, wanted: &str) -> Result<&'a str, FormatError> {
    got.filter(|text| !text.is_empty())
        .ok_or_else(|| FormatError::BadLine(number, format!("there is no {wanted} on this line")))
}

fn number_field(number: usize, text: &str) -> Result<i128, FormatError> {
    text.parse()
        .map_err(|_| FormatError::BadLine(number, format!("{text:?} is not a whole number")))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn from_hex_32(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    read_hex(text, &mut out)?;
    Some(out)
}

fn from_hex_64(text: &str) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    read_hex(text, &mut out)?;
    Some(out)
}

fn read_hex(text: &str, into: &mut [u8]) -> Option<()> {
    if text.len() != into.len() * 2 {
        return None;
    }
    for (i, byte) in into.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: u8, from: i128, until: Option<i128>, name: &str) -> KeyEntry {
        KeyEntry {
            issued: None,
            public_key: [key; 32],
            role: Role::Agent,
            deployment: name.to_string(),
            valid_from: UnixNanos(from),
            valid_until: until.map(UnixNanos),
        }
    }

    #[test]
    fn every_role_reads_back_and_a_retirement_has_no_end() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let log = signed(
            vec![
                entry(1, 100, None, "an agent"),
                KeyEntry {
                    role: Role::Server,
                    ..entry(2, 100, None, "a server")
                },
                KeyEntry {
                    role: Role::Retired,
                    ..entry(1, 300, None, "the runner was decommissioned")
                },
            ],
            &signing,
        );
        let text = write(&log).expect("written");
        assert!(text.contains("\nentry agent 0101"), "{text}");
        assert!(text.contains("\nentry server 0202"), "{text}");
        assert!(text.contains("\nentry retired 0101"), "{text}");
        assert_eq!(parse(&text).expect("read back"), log);
        assert_eq!(log.agent_entries(), 1);

        let with_an_end = KeyLog {
            checkpoints: Vec::new(),
            entries: vec![KeyEntry {
                role: Role::Retired,
                ..entry(1, 300, Some(400), "retired")
            }],
            head: None,
        };
        assert!(write(&with_an_end).is_err(), "a retirement is one moment");
        let line = format!(
            "{MAGIC}\nentry retired {} 300 400 retired\n",
            hex(&[1u8; 32])
        );
        assert!(matches!(parse(&line), Err(FormatError::BadLine(2, _))));

        let no_such_role = format!("{MAGIC}\nentry witness {} 300 - x\n", hex(&[1u8; 32]));
        assert!(matches!(
            parse(&no_such_role),
            Err(FormatError::BadLine(2, _))
        ));
    }

    #[test]
    fn a_log_of_the_retired_format_is_refused_by_name() {
        let text = format!(
            "timewitness-key-log v0\nentry {} 100 - old\n",
            hex(&[1u8; 32])
        );
        let refused = parse(&text).expect_err("no v0 log was ever served");
        assert!(refused.to_string().contains("v0"), "{refused}");
        assert!(refused.to_string().contains("v1"), "{refused}");
    }

    #[test]
    fn a_head_is_checked_against_the_keys_the_reader_holds() {
        let ours = SigningKey::from_bytes(&[7u8; 32]);
        let theirs = SigningKey::from_bytes(&[8u8; 32]);
        let held = [ours.verifying_key().to_bytes()];

        let by_us = signed(vec![entry(1, 100, None, "one")], &ours);
        assert_eq!(
            by_us.check_head(&held),
            HeadCheck::Checked(ours.verifying_key().to_bytes())
        );

        // The fault of 2026-09-15: a real signature by a key nobody holds for us.
        let by_them = signed(vec![entry(1, 100, None, "one")], &theirs);
        assert_eq!(
            by_them.check_head(&held),
            HeadCheck::SignerNotHeld(theirs.verifying_key().to_bytes())
        );
        assert_eq!(
            by_them.check_head(&[]),
            HeadCheck::SignerNotHeld(theirs.verifying_key().to_bytes())
        );

        let mut moved = by_us.clone();
        moved.head.as_mut().expect("a head").signature = by_them.head.expect("a head").signature;
        assert_eq!(moved.check_head(&held), HeadCheck::BadSignature);

        let headless = KeyLog {
            checkpoints: Vec::new(),
            entries: by_us.entries.clone(),
            head: None,
        };
        assert_eq!(headless.check_head(&held), HeadCheck::None);
    }

    fn signed(entries: Vec<KeyEntry>, signing: &SigningKey) -> KeyLog {
        let mut log = KeyLog {
            checkpoints: Vec::new(),
            entries,
            head: None,
        };
        let head = TreeHead {
            beacon: None,
            size: log.entries.len(),
            root: log.root(),
            at: UnixNanos(1_800_000_000_000_000_000),
        };
        let signature = signing.sign(&head.canonical()).to_bytes();
        log.head = Some(SignedHead {
            witness: None,
            head,
            signature,
            signed_by: signing.verifying_key().to_bytes(),
        });
        log
    }

    #[test]
    fn a_log_written_here_reads_back_as_the_same_log() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let log = signed(
            vec![
                entry(1, 100, Some(200), "a build runner"),
                entry(2, 150, None, "a name with spaces in it"),
            ],
            &signing,
        );

        let text = write(&log).expect("a log with no line breaks in a name");
        let read = parse(&text).expect("what this wrote, this reads");
        assert_eq!(read, log);
        assert_eq!(read.head_is_signed_by_the_key_it_names(), Some(true));
    }

    /// A public key of small order, and a signature that checks against it under the cofactorless
    /// equation.
    ///
    /// The key is the neutral point, encoded as y = 1 with the sign bit clear, which is the first
    /// of the eight points of small order on this curve. The commitment is the base point and the
    /// scalar is one. Verification without the strict check asks whether [s]B equals R + [k]A; the
    /// neutral point takes [k]A to itself whatever the message hashes to, so the question becomes
    /// whether [1]B equals B, which it does, for every message anybody ever puts in front of it.
    ///
    /// `verify_strict` refuses a key of small order outright, which is why this file calls it. The
    /// test below is what says so, rather than the comment above the call.
    const SMALL_ORDER_KEY: [u8; 32] = {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        bytes
    };

    const SIGNATURE_THAT_CHECKS_AGAINST_IT: [u8; 64] = {
        let mut bytes = [0u8; 64];
        // The base point, compressed: 0x58 and then 0x66 thirty-one times.
        bytes[0] = 0x58;
        let mut i = 1;
        while i < 32 {
            bytes[i] = 0x66;
            i += 1;
        }
        // The scalar one, little-endian.
        bytes[32] = 1;
        bytes
    };

    #[test]
    fn a_head_signed_by_a_malleable_small_order_key_does_not_check() {
        // What this holds. `verify` and `verify_strict` disagree on exactly one thing, and it is
        // this: a key of small order gives one head more than one valid signature, and one of them
        // can be written by somebody who has never held the signing key. A log head is the thing
        // every entry under it rests on, so a second valid spelling of its signature is a second
        // valid history.
        //
        // Swap `verify_strict` for `verify` in `head_is_signed_by_the_key_it_names` and this test
        // goes green with Some(true), which is the whole reason it exists: the suite was green
        // either way before it.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut log = signed(vec![entry(1, 100, None, "one")], &signing);
        let head = log.head.as_mut().expect("a head");
        head.signed_by = SMALL_ORDER_KEY;
        head.signature = SIGNATURE_THAT_CHECKS_AGAINST_IT;

        assert_eq!(
            log.head_is_signed_by_the_key_it_names(),
            Some(false),
            "a head signed by a key of small order has more than one valid signature and is not signed in any sense worth the word"
        );
    }

    #[test]
    fn a_head_signed_over_a_different_log_does_not_check() {
        // The property a head is for. Everything about this file is well-formed: the entries hash
        // to the root, the root is on the head line, and the signature is a real signature. It is a
        // signature over a different head, which is what somebody moving a signature between logs
        // would produce.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut log = signed(vec![entry(1, 100, None, "one")], &signing);
        let elsewhere = TreeHead {
            beacon: None,
            size: 1,
            root: [9u8; 32],
            at: UnixNanos(1_800_000_000_000_000_000),
        };
        log.head.as_mut().expect("a head").signature =
            signing.sign(&elsewhere.canonical()).to_bytes();

        let text = write(&log).expect("written");
        let read = parse(&text).expect("the file is still well-formed");
        assert_eq!(read.head_is_signed_by_the_key_it_names(), Some(false));
    }

    #[test]
    fn a_head_that_does_not_describe_its_own_entries_is_refused_rather_than_read() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let log = signed(
            vec![entry(1, 100, None, "one"), entry(2, 100, None, "two")],
            &signing,
        );
        let text = write(&log).expect("written");

        // An entry removed, which is the edit a log exists to catch. The head still states two.
        let shortened = text
            .lines()
            .filter(|line| !line.starts_with("entry agent 0202"))
            .collect::<Vec<_>>()
            .join("\n");
        let refused = parse(&shortened).expect_err("the head states two entries and one is there");
        assert!(
            matches!(refused, FormatError::HeadDisagrees(_)),
            "{refused:?}"
        );
    }

    #[test]
    fn an_entry_changed_under_a_head_is_refused() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let log = signed(vec![entry(1, 100, Some(200), "one")], &signing);
        let text = write(&log)
            .expect("written")
            .replace(" 100 200 ", " 100 900 ");
        let refused = parse(&text).expect_err("the entries no longer hash to the stated root");
        assert!(
            matches!(refused, FormatError::HeadDisagrees(_)),
            "{refused:?}"
        );
    }

    #[test]
    fn a_log_with_no_head_is_read_and_says_less() {
        let text = format!(
            "{MAGIC}\n# where this came from\n\nentry agent {} 100 - a deployment\n",
            hex(&[3u8; 32])
        );
        let log = parse(&text).expect("a log with no head is still a log");
        assert_eq!(log.entries.len(), 1);
        assert_eq!(log.head_is_signed_by_the_key_it_names(), None);
        assert_eq!(
            log.standing(&[3u8; 32], UnixNanos(150)),
            Standing::Published
        );
        assert_eq!(
            log.standing(&[3u8; 32], UnixNanos(50)),
            Standing::OutsideItsWindow
        );
        assert_eq!(
            log.standing(&[4u8; 32], UnixNanos(150)),
            Standing::NotInTheLog
        );
    }

    #[test]
    fn a_file_that_is_not_a_key_log_is_refused_by_its_first_line() {
        assert!(matches!(
            parse("something else entirely\n"),
            Err(FormatError::NotAKeyLog(_))
        ));
        assert!(matches!(parse(""), Err(FormatError::NotAKeyLog(_))));
    }

    #[test]
    fn the_lines_that_could_be_read_two_ways_are_refused_instead() {
        let cases = [
            format!("{MAGIC}\nentry agent abcd 1 - name\n"),
            format!("{MAGIC}\nentry agent {} x - name\n", hex(&[1u8; 32])),
            format!("{MAGIC}\nentry agent {} 1 -\n", hex(&[1u8; 32])),
            // The line a v0 log carried, which reads here as a key in the role's place.
            format!("{MAGIC}\nentry {} 1 - name\n", hex(&[1u8; 32])),
            format!("{MAGIC}\nwhatever 1 2 3\n"),
            format!(
                "{MAGIC}\nhead 0 {} 1 {} {}\nhead 0 {} 1 {} {}\n",
                hex(&[0u8; 32]),
                hex(&[0u8; 64]),
                hex(&[1u8; 32]),
                hex(&[0u8; 32]),
                hex(&[0u8; 64]),
                hex(&[1u8; 32])
            ),
        ];
        for text in cases {
            assert!(parse(&text).is_err(), "read without complaint: {text:?}");
        }
    }

    #[test]
    fn a_deployment_name_with_a_line_break_is_refused_rather_than_written() {
        // Written out, it would read back as an entry and then as a line that is not one, so the
        // file would either fail to parse or, worse, parse as something nobody wrote.
        let log = KeyLog {
            checkpoints: Vec::new(),
            entries: vec![entry(1, 100, None, "one\nentry agent 00 1 - two")],
            head: None,
        };
        assert!(write(&log).is_err());
    }

    fn certificate(key: u8, from: i128, until: i128) -> KeyEntry {
        KeyEntry {
            public_key: [key; 32],
            role: Role::Certificate,
            deployment: "a runner with a space in its name".to_string(),
            valid_from: UnixNanos(from),
            valid_until: Some(UnixNanos(until)),
            issued: Some(Issued {
                organisation: "org-1".to_string(),
                method: "github-oidc".to_string(),
            }),
        }
    }

    fn cutoff(at: i128) -> KeyEntry {
        KeyEntry {
            public_key: [7u8; 32],
            role: Role::Cutoff,
            deployment: "certification begins".to_string(),
            valid_from: UnixNanos(at),
            valid_until: None,
            issued: None,
        }
    }

    /// A history of three heads: one over the server key, one over the cutoff carrying a beacon and a
    /// witness, and one over a certificate.
    fn history() -> KeyLog {
        let secret = [7u8; 32];
        let mut log = KeyLog::default();
        log.entries.push(KeyEntry {
            role: Role::Server,
            ..entry(2, 0, None, "a roughtime server")
        });
        log.head = Some(sign_head(&log, &secret, UnixNanos(10)));
        log.checkpoints.push(log.head.take().expect("a head"));
        log.entries.push(cutoff(1_000));
        let mut fixing = sign_head_after(&log, &secret, UnixNanos(1_010), Some(vec![0xbe; 12]));
        fixing.witness = Some(vec![0xef; 20]);
        log.checkpoints.push(fixing);
        log.entries.push(certificate(1, 2_000, 3_000));
        log.head = Some(sign_head_after(
            &log,
            &secret,
            UnixNanos(2_010),
            Some(vec![0xbf; 12]),
        ));
        log
    }

    #[test]
    fn a_history_is_written_as_version_2_and_reads_back_as_the_same_history() {
        let log = history();
        assert!(log.needs_version_2());
        let text = write(&log).expect("written");
        assert!(text.starts_with(MAGIC_V2), "{text}");
        assert!(
            text.contains(" org-1 github-oidc a runner with a space in its name\n"),
            "{text}"
        );
        assert!(text.contains("\nbeacon bebebe"), "{text}");
        assert!(text.contains("\nwitness efef"), "{text}");
        let read = parse(&text).expect("what this wrote, this reads");
        assert_eq!(read, log);
        assert_eq!(read.heads().count(), 3);
        assert_eq!(read.first_head_covering(0).map(|h| h.head.size), Some(1));
        assert_eq!(read.first_head_covering(1).map(|h| h.head.size), Some(2));
        assert_eq!(read.first_head_covering(2).map(|h| h.head.size), Some(3));
        assert_eq!(read.first_head_covering(3), None);
        let held = [SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()];
        assert!(read.checkpoints_are_ours(&held));
        assert!(!read.checkpoints_are_ours(&[[1u8; 32]]));
        assert_eq!(read.check_head(&held), HeadCheck::Checked(held[0]));
    }

    #[test]
    fn a_log_with_nothing_of_version_2_in_it_is_still_written_as_version_1() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let log = signed(vec![entry(1, 100, None, "one")], &signing);
        assert!(!log.needs_version_2());
        assert!(write(&log)
            .expect("written")
            .starts_with(&format!("{MAGIC}\n")));
    }

    #[test]
    fn a_beacon_is_signed_with_its_head_and_a_witness_is_not() {
        let log = history();
        let mut moved = log.clone();
        moved.head.as_mut().unwrap().head.beacon = Some(vec![0xaa; 12]);
        assert_eq!(moved.head_is_signed_by_the_key_it_names(), Some(false));

        let mut witnessed = log.clone();
        witnessed.head.as_mut().unwrap().witness = Some(vec![1, 2, 3]);
        assert_eq!(witnessed.head_is_signed_by_the_key_it_names(), Some(true));
        let head = log.head.as_ref().unwrap();
        let mut other = head.clone();
        other.signature[0] ^= 1;
        assert_ne!(head.witness_digest(), other.witness_digest());
    }

    #[test]
    fn a_version_1_file_refuses_everything_version_2_adds() {
        let key = hex(&[1u8; 32]);
        for line in [
            format!("entry certificate {key} 1 2 org-1 github-oidc name"),
            format!("entry cutoff {key} 1 - name"),
        ] {
            let text = format!("{MAGIC}\n{line}\n");
            assert!(
                matches!(parse(&text), Err(FormatError::BadLine(2, _))),
                "read as v1: {line}"
            );
            assert!(parse(&format!("{MAGIC_V2}\n{line}\n")).is_ok(), "{line}");
        }
        let text = write(&history())
            .expect("written")
            .replacen(MAGIC_V2, MAGIC, 1);
        assert!(parse(&text).is_err(), "a history is not a v1 file");
    }

    #[test]
    fn a_history_whose_heads_are_out_of_place_is_refused() {
        let text = write(&history()).expect("written");
        let lines: Vec<&str> = text.lines().collect();

        // A beacon line that does not sit under a head.
        let mut stray = lines.clone();
        let at = stray.iter().position(|l| l.starts_with("beacon")).unwrap();
        let beacon = stray.remove(at);
        stray.insert(1, beacon);
        assert!(parse(&stray.join("\n")).is_err());

        // Two beacons on one head.
        let mut twice = lines.clone();
        twice.insert(at + 1, beacon);
        assert!(parse(&twice.join("\n")).is_err());

        // A head moved above an entry it says it covers.
        let mut early = lines.clone();
        let head = early.iter().position(|l| l.starts_with("head")).unwrap();
        let line = early.remove(head);
        early.insert(1, line);
        assert!(matches!(
            parse(&early.join("\n")),
            Err(FormatError::HeadDisagrees(_))
        ));

        // An entry changed under an earlier head, with the newest head re-signed over it.
        let changed = text.replace(" 2000 3000 ", " 2000 3001 ");
        assert!(parse(&changed).is_err());
    }

    #[test]
    fn each_role_carries_only_the_fields_it_is_allowed() {
        let key = hex(&[1u8; 32]);
        for line in [
            format!("entry certificate {key} 1 - org-1 github-oidc name"),
            format!("entry certificate {key} 1 2 org-1"),
            format!("entry cutoff {key} 1 2 name"),
        ] {
            assert!(
                parse(&format!("{MAGIC_V2}\n{line}\n")).is_err(),
                "read: {line}"
            );
        }
        let mut agent = entry(1, 100, None, "one");
        agent.issued = Some(Issued {
            organisation: "o".to_string(),
            method: "m".to_string(),
        });
        let log = KeyLog {
            entries: vec![agent],
            ..KeyLog::default()
        };
        assert!(write(&log).is_err());
        let mut spaced = certificate(1, 1, 2);
        spaced.issued.as_mut().unwrap().organisation = "two words".to_string();
        let log = KeyLog {
            entries: vec![spaced],
            ..KeyLog::default()
        };
        assert!(write(&log).is_err());
    }
}
