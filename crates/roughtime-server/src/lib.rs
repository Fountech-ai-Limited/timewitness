//! A Roughtime server of our own: the keys, the delegation, the socket and the refusals.
//!
//! The wire format is not here. It is in [`timewitness_core::evidence::roughtime`], next to the
//! checker that reads it, so the two halves cannot drift apart. This crate is everything that is
//! true about *running* a server rather than about the format: where the long-term key lives, how
//! often it delegates, what a bad packet gets, and how many packets one address may send.
//!
//! # What a server of ours may honestly say, and the one number it cannot improve
//!
//! A Roughtime response is a midpoint and a radius, and the radius is a `u32` of **whole seconds**
//! with zero forbidden. So one second is the narrowest any Roughtime server can state, ours
//! included, and a corridor is two seconds wide at its best whoever runs it. Running our own
//! servers does not narrow a bound and cannot. What it buys is a corridor that is there when three
//! volunteers' servers are not, and a key we publish and can be held to.
//!
//! # It states its own uncertainty rather than assuming it
//!
//! The temptation in a time server is to read the machine's clock and call the radius one second
//! because the machine is usually fine. This one takes a [`Reading`] from its caller, and a caller
//! that cannot say how wrong its clock might be has nothing to hand it. A server whose own clock
//! has drifted past what it is willing to claim **stops answering** rather than answering with a
//! radius it cannot justify. That is the whole thesis of this product applied to itself, and it is
//! the one thing a time server run by a time-bounding company would look worst getting wrong.
//!
//! # What it is not
//!
//! It does not batch. One request, one tree, one signature, which [`timewitness_core`] explains and
//! which is the right trade at the load two servers of ours will see. It has no configuration file,
//! no logging framework and no metrics endpoint: it is a socket, a key and a loop, and anything
//! else belongs to whatever runs it.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use timewitness_core::evidence::roughtime::{
    build_response, delegate, read_request, Delegation, MAX_DELEGATION_SECONDS, MIN_RADIUS_SECONDS,
};
use timewitness_core::evidence::EvidenceError;

/// The largest packet this server will read off the socket.
///
/// A Roughtime request is at least 1024 bytes of message and a little framing, and nothing in the
/// draft makes one usefully larger. Reading into a fixed buffer means an oversized datagram is
/// truncated and then fails the encoding check, which is the same silence any other bad packet
/// gets.
pub const MAX_DATAGRAM: usize = 1500;

/// How long a delegation is made for by default.
///
/// One day, against the week the format allows. The trade is how often somebody has to bring the
/// long-term key out against how long a stolen online key is worth anything, and a day is short
/// enough that a theft is a day's exposure while still being something a person can do by hand if
/// the automation is down.
pub const DEFAULT_DELEGATION_SECONDS: u64 = 24 * 60 * 60;

/// How long before a delegation expires this server makes the next one.
///
/// A quarter of the window. Renewing at the last moment means a server whose renewal fails once has
/// no slack at all, and renewing constantly means the long-term key is used far more often than it
/// needs to be.
const RENEW_WHEN_REMAINING: u64 = DEFAULT_DELEGATION_SECONDS / 4;

/// What the caller's clock says, and how wrong it says it might be.
///
/// Both in whole seconds, because that is what the wire format states and rounding at the edge
/// rather than in the middle keeps one rounding rule in one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    /// The moment, in seconds since the Unix epoch.
    pub seconds: u64,
    /// How far from that moment the truth might be, in seconds, rounded **up**.
    ///
    /// Up rather than to nearest, always. A radius rounded down is a claim narrower than the thing
    /// it was computed from, which is the one direction a time server must never round in.
    pub radius_seconds: u32,
}

impl Reading {
    /// A reading from a moment and a half width in nanoseconds.
    ///
    /// The half width is rounded up to whole seconds and then raised to [`MIN_RADIUS_SECONDS`] if
    /// it came out below it, because a radius under one second cannot be put on the wire and
    /// stating one second where the truth is narrower is honest: the interval is wider than it
    /// needs to be, which is the safe direction.
    #[must_use]
    pub fn from_nanos(seconds: u64, half_width_nanos: i128) -> Self {
        let nanos = half_width_nanos.max(0);
        let whole = nanos.div_euclid(1_000_000_000);
        let up = if nanos.rem_euclid(1_000_000_000) == 0 {
            whole
        } else {
            whole + 1
        };
        let radius = u32::try_from(up).unwrap_or(u32::MAX);
        Self {
            seconds,
            radius_seconds: radius.max(MIN_RADIUS_SECONDS),
        }
    }
}

/// Why a packet got no answer.
///
/// Every one of these is silence on the wire. A Roughtime server has no error message to send:
/// whatever it puts on the socket goes to a spoofed source address as readily as to a real one, so
/// the only safe answer to a bad request is nothing at all. These exist so that the process running
/// the server can count them, not so that a client can be told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// The packet was not a request this server should answer.
    NotOurs(String),
    /// The address has sent more than its share lately.
    RateLimited,
    /// The server has no usable statement about its own clock, so it will not date anything.
    NoReading(String),
    /// The response could not be built, which is a fault in this server rather than in the request.
    CouldNotAnswer(String),
}

impl core::fmt::Display for Dropped {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dropped::NotOurs(d) => write!(f, "not a request for this server: {d}"),
            Dropped::RateLimited => write!(f, "over this address's share of the socket"),
            Dropped::NoReading(d) => write!(f, "this server will not date a response: {d}"),
            Dropped::CouldNotAnswer(d) => write!(f, "this server could not build a response: {d}"),
        }
    }
}

/// The long-term key, which identifies the server and is the thing a client trusts.
///
/// It signs delegations and nothing else. In a deployment that is doing this properly it lives
/// offline and signs a delegation now and then; here it lives in a file with owner-only permissions
/// where the process can reach it, which is weaker and is said plainly rather than implied.
pub struct LongTermKey(SigningKey);

impl LongTermKey {
    /// A key from its thirty-two secret bytes.
    #[must_use]
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(secret))
    }

    /// A new key from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// Whatever the platform says when it cannot produce randomness. There is no fallback and there
    /// must not be one: a signing key from a predictable source is worse than no server.
    pub fn generate() -> Result<Self, io::Error> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret)
            .map_err(|e| io::Error::other(format!("no randomness for a long-term key: {e}")))?;
        Ok(Self::from_bytes(&secret))
    }

    /// The public half, which is what a client is told and what the key log carries.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Read a key from a file holding exactly its thirty-two secret bytes.
    ///
    /// # Errors
    ///
    /// The file not being there or not being readable, and a file that is not thirty-two bytes.
    /// The length is checked rather than truncated: a short file is a key somebody has damaged and
    /// signing with the first thirty-two bytes of whatever it holds is how a server quietly starts
    /// answering under a key nobody published.
    pub fn read(path: &Path) -> Result<Self, io::Error> {
        let bytes = std::fs::read(path)?;
        let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the long-term key at {} is {} bytes and a key is 32",
                    path.display(),
                    bytes.len()
                ),
            )
        })?;
        Ok(Self::from_bytes(&secret))
    }

    /// Write the key to a file, refusing to overwrite one that is already there.
    ///
    /// # Errors
    ///
    /// Anything the filesystem says, and an existing file at that path. Refusing is deliberate:
    /// overwriting a long-term key silently retires an identity that clients and the key log both
    /// still name, and the recovery is to find the old bytes, which by then are gone.
    pub fn write_new(&self, path: &Path) -> Result<(), io::Error> {
        if path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "there is already a long-term key at {}, and writing over one retires an \
                     identity that clients and the key log still name",
                    path.display()
                ),
            ));
        }
        write_owner_only(path, &self.0.to_bytes())
    }
}

/// Write a file only the owner can read.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut file, bytes)
    }
    #[cfg(not(unix))]
    {
        // Windows has no mode bits to set at open time. The file inherits the directory's access
        // control, which is why the deployment notes say the key directory is the thing to get
        // right on a Windows host rather than the file.
        std::fs::write(path, bytes)
    }
}

/// A server: a long-term key, the online key it is currently delegating to, and the delegation.
pub struct Server {
    long_term: LongTermKey,
    online: SigningKey,
    certificate: Delegation,
    /// How long each delegation runs for.
    window: u64,
}

impl Server {
    /// A server with its first delegation made, valid from `now` for [`DEFAULT_DELEGATION_SECONDS`].
    ///
    /// # Errors
    ///
    /// Whatever the platform says when it cannot produce randomness for the online key, and
    /// anything the delegation itself refuses.
    pub fn new(long_term: LongTermKey, now: u64) -> Result<Self, io::Error> {
        Self::with_window(long_term, now, DEFAULT_DELEGATION_SECONDS)
    }

    /// The same, with the delegation window stated.
    ///
    /// # Errors
    ///
    /// As [`Server::new`], and a window over [`MAX_DELEGATION_SECONDS`].
    pub fn with_window(long_term: LongTermKey, now: u64, window: u64) -> Result<Self, io::Error> {
        if window > MAX_DELEGATION_SECONDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a delegation window of {window} seconds, and the format allows \
                         {MAX_DELEGATION_SECONDS}"
                ),
            ));
        }
        let online = fresh_online_key()?;
        let certificate = delegation_from(&long_term, &online, now, window)?;
        Ok(Self {
            long_term,
            online,
            certificate,
            window,
        })
    }

    /// The public long-term key, which is what a client is told and what the key log carries.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.long_term.public()
    }

    /// The window the current delegation runs over.
    #[must_use]
    pub fn delegation_window(&self) -> (u64, u64) {
        self.certificate.window()
    }

    /// Make a new online key and delegate to it, if the current delegation is running out.
    ///
    /// Returns whether it did. Call it before each answer; it costs a comparison in the ordinary
    /// case. The old online key is dropped on the spot rather than kept for a grace period: a key
    /// that is no longer delegated is a key that can only produce responses the checker refuses, so
    /// keeping it buys nothing and loses the property that a theft expires.
    ///
    /// # Errors
    ///
    /// As [`Server::new`].
    pub fn renew_if_due(&mut self, now: u64) -> Result<bool, io::Error> {
        let (_, ends) = self.certificate.window();
        if ends.saturating_sub(now) > RENEW_WHEN_REMAINING {
            return Ok(false);
        }
        self.online = fresh_online_key()?;
        self.certificate = delegation_from(&self.long_term, &self.online, now, self.window)?;
        Ok(true)
    }

    /// Answer one request, or say why it got nothing.
    ///
    /// # Errors
    ///
    /// A [`Dropped`] saying which of the four reasons applies. Every one of them is silence on the
    /// wire; the value is for whoever is counting.
    pub fn answer(&self, packet: &[u8], reading: Reading) -> Result<Vec<u8>, Dropped> {
        read_request(packet, &self.long_term.public())
            .map_err(|e| Dropped::NotOurs(e.to_string()))?;

        if !self.certificate.covers(reading.seconds) {
            let (from, to) = self.certificate.window();
            return Err(Dropped::NoReading(format!(
                "the clock reads {} and this server's delegation runs {from} to {to}, so signing \
                 would produce a response its own checker refuses",
                reading.seconds
            )));
        }

        build_response(
            packet,
            &self.online,
            &self.certificate,
            reading.seconds,
            reading.radius_seconds,
        )
        .map_err(|e: EvidenceError| Dropped::CouldNotAnswer(e.to_string()))
    }
}

fn fresh_online_key() -> Result<SigningKey, io::Error> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret)
        .map_err(|e| io::Error::other(format!("no randomness for an online key: {e}")))?;
    Ok(SigningKey::from_bytes(&secret))
}

fn delegation_from(
    long_term: &LongTermKey,
    online: &SigningKey,
    now: u64,
    window: u64,
) -> Result<Delegation, io::Error> {
    // The window starts a little before now rather than at it. A client whose own clock is a few
    // seconds fast asks for a moment this server has not reached, and a delegation that begins
    // exactly now would refuse it for no reason anybody could act on. Sixty seconds is enough for
    // that and is nothing against a day.
    delegate(
        &long_term.0,
        &online.verifying_key().to_bytes(),
        now.saturating_sub(60),
        now.saturating_add(window),
    )
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// How many packets one address may send in a window, and the window.
///
/// It is here because a signature per request is the cost this server pays, so an address that
/// sends a thousand requests a second costs a thousand signatures a second. The size check in the
/// wire format stops the server being a lever for pointing traffic at somebody else; this stops it
/// being a lever for spending its own processor.
///
/// The counts are cleared wholesale at the end of each window rather than decayed, which is coarse
/// and is chosen for it: a decaying counter is one allocation per address that never goes away, and
/// a map that is emptied cannot be grown without bound by an attacker picking new addresses.
pub struct RateLimit {
    per_window: u32,
    window: Duration,
    started: Instant,
    seen: HashMap<SocketAddr, u32>,
}

impl RateLimit {
    /// A limit of `per_window` packets from one address per `window`.
    #[must_use]
    pub fn new(per_window: u32, window: Duration) -> Self {
        Self {
            per_window,
            window,
            started: Instant::now(),
            seen: HashMap::new(),
        }
    }

    /// Whether this address may send another packet now, counting this one.
    pub fn allows(&mut self, from: SocketAddr, now: Instant) -> bool {
        if now.duration_since(self.started) >= self.window {
            self.seen.clear();
            self.started = now;
        }
        let count = self.seen.entry(from).or_insert(0);
        *count += 1;
        *count <= self.per_window
    }
}

impl Default for RateLimit {
    /// Sixty packets an address per minute, which is one a second sustained.
    ///
    /// A client polling every thirty-two seconds, which is this product's own cadence, uses two.
    /// The figure is that far above the intended use because the thing being protected is a
    /// processor rather than a scarce resource, and a limit that catches an honest client is worse
    /// than one that lets a burst through.
    fn default() -> Self {
        Self::new(60, Duration::from_secs(60))
    }
}

/// Serve until `keep_going` says otherwise.
///
/// `clock` is asked for a reading per request rather than once, because a server that cached its
/// own uncertainty would go on stating it after the thing it was measured from had gone. Returning
/// `None` from it is how a caller says its clock is no longer good enough to date anything, and the
/// request then gets silence.
///
/// `watch` is handed every drop, so whatever is running this can count them. It is not a logger and
/// nothing here writes to a stream.
///
/// # Errors
///
/// Anything the socket says other than a timeout. A timeout is how `keep_going` gets looked at, so
/// the socket wants a read timeout set before this is called.
pub fn serve<C, K, W>(
    socket: &UdpSocket,
    server: &mut Server,
    limit: &mut RateLimit,
    mut clock: C,
    mut keep_going: K,
    mut watch: W,
) -> Result<(), io::Error>
where
    C: FnMut() -> Option<Reading>,
    K: FnMut() -> bool,
    W: FnMut(SocketAddr, &Dropped),
{
    let mut buffer = [0u8; MAX_DATAGRAM];
    while keep_going() {
        let (len, from) = match socket.recv_from(&mut buffer) {
            Ok(got) => got,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(e),
        };

        if !limit.allows(from, Instant::now()) {
            watch(from, &Dropped::RateLimited);
            continue;
        }

        let Some(reading) = clock() else {
            watch(
                from,
                &Dropped::NoReading(
                    "the clock this server runs on has no usable bound, so it will not date a \
                     response"
                        .to_string(),
                ),
            );
            continue;
        };

        // Before answering rather than on a timer, so a server that has been idle for a day does
        // not answer its first request under an expired delegation.
        if let Err(e) = server.renew_if_due(reading.seconds) {
            watch(from, &Dropped::CouldNotAnswer(e.to_string()));
            continue;
        }

        match server.answer(&buffer[..len], reading) {
            Ok(response) => {
                socket.send_to(&response, from)?;
            }
            Err(dropped) => watch(from, &dropped),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use timewitness_core::evidence::roughtime::{build_request, check, pack_blob};

    const NOW: u64 = 1_800_000_000;

    fn a_server() -> Server {
        Server::new(LongTermKey::from_bytes(&[42u8; 32]), NOW).expect("a server with a delegation")
    }

    #[test]
    fn a_request_to_this_server_gets_a_response_its_own_checker_accepts() {
        let server = a_server();
        let request = build_request(&[9u8; 32], &server.public_key());

        let response = server
            .answer(
                &request,
                Reading {
                    seconds: NOW,
                    radius_seconds: 1,
                },
            )
            .expect("a request for this server's key is answered");

        let checked = check(
            &pack_blob(&[], &request, &response),
            &server.public_key(),
            "a server of ours",
        )
        .expect("the response checks against the published long-term key");
        assert_eq!(checked.radius(), 1_000_000_000);
    }

    #[test]
    fn a_request_for_another_servers_key_gets_nothing() {
        let server = a_server();
        let elsewhere = LongTermKey::from_bytes(&[1u8; 32]).public();
        let request = build_request(&[9u8; 32], &elsewhere);

        let refused = server.answer(
            &request,
            Reading {
                seconds: NOW,
                radius_seconds: 1,
            },
        );
        assert!(matches!(refused, Err(Dropped::NotOurs(_))), "{refused:?}");
    }

    #[test]
    fn a_short_request_gets_nothing_so_this_is_never_a_reflector() {
        let server = a_server();
        let refused = server.answer(
            b"ROUGHTIM\x04\x00\x00\x00abcd",
            Reading {
                seconds: NOW,
                radius_seconds: 1,
            },
        );
        assert!(matches!(refused, Err(Dropped::NotOurs(_))), "{refused:?}");
    }

    #[test]
    fn a_radius_is_rounded_up_and_never_below_a_second() {
        // Up, always. A radius rounded down is a claim narrower than the thing it was computed
        // from, which is the one direction a time server must never round in.
        assert_eq!(Reading::from_nanos(NOW, 0).radius_seconds, 1);
        assert_eq!(Reading::from_nanos(NOW, 1).radius_seconds, 1);
        assert_eq!(Reading::from_nanos(NOW, 999_999_999).radius_seconds, 1);
        assert_eq!(Reading::from_nanos(NOW, 1_000_000_000).radius_seconds, 1);
        assert_eq!(Reading::from_nanos(NOW, 1_000_000_001).radius_seconds, 2);
        assert_eq!(Reading::from_nanos(NOW, 2_500_000_000).radius_seconds, 3);
        // A negative half width is nonsense and is treated as nothing rather than wrapping.
        assert_eq!(Reading::from_nanos(NOW, -5).radius_seconds, 1);
    }

    #[test]
    fn a_reading_the_delegation_does_not_cover_is_refused_rather_than_signed() {
        let server = a_server();
        let request = build_request(&[9u8; 32], &server.public_key());

        let refused = server.answer(
            &request,
            Reading {
                seconds: NOW + DEFAULT_DELEGATION_SECONDS + 1,
                radius_seconds: 1,
            },
        );
        assert!(matches!(refused, Err(Dropped::NoReading(_))), "{refused:?}");
    }

    #[test]
    fn the_delegation_is_renewed_before_it_runs_out_and_not_after() {
        let mut server = a_server();
        let (_, first_end) = server.delegation_window();

        assert!(!server.renew_if_due(NOW).expect("a fresh one is not due"));
        assert!(!server
            .renew_if_due(first_end - RENEW_WHEN_REMAINING - 1)
            .expect("a moment before the threshold is not due"));
        assert!(server
            .renew_if_due(first_end - RENEW_WHEN_REMAINING)
            .expect("at the threshold it renews"));
        let (_, second_end) = server.delegation_window();
        assert!(second_end > first_end, "the window moved forward");
    }

    #[test]
    fn a_response_under_the_old_online_key_stops_checking_once_the_key_is_replaced() {
        // The property renewal is for. The old key is dropped rather than kept, so a theft of it
        // expires; this shows that it really does.
        let mut server = a_server();
        let request = build_request(&[9u8; 32], &server.public_key());
        let reading = Reading {
            seconds: NOW,
            radius_seconds: 1,
        };
        let before = server.answer(&request, reading).expect("answered");

        let (_, ends) = server.delegation_window();
        assert!(server.renew_if_due(ends - RENEW_WHEN_REMAINING).unwrap());

        // The old response still checks: it was signed under a delegation the long-term key made,
        // and nothing revokes it. What has changed is that the server will not make another one
        // under that key, which is what bounds a theft rather than undoing it.
        check(
            &pack_blob(&[], &request, &before),
            &server.public_key(),
            "a server of ours",
        )
        .expect("a response made under the old delegation is still valid");

        let after = server
            .answer(
                &request,
                Reading {
                    seconds: ends - RENEW_WHEN_REMAINING,
                    radius_seconds: 1,
                },
            )
            .expect("answered under the new delegation");
        assert_ne!(before, after, "a new delegation gives different bytes");
    }

    #[test]
    fn one_address_cannot_have_the_whole_socket() {
        let mut limit = RateLimit::new(3, Duration::from_secs(60));
        let from: SocketAddr = "203.0.113.7:2002".parse().unwrap();
        let other: SocketAddr = "203.0.113.8:2002".parse().unwrap();
        let start = Instant::now();

        assert!(limit.allows(from, start));
        assert!(limit.allows(from, start));
        assert!(limit.allows(from, start));
        assert!(!limit.allows(from, start), "the fourth is over the share");
        assert!(
            limit.allows(other, start),
            "one address being over does not close the socket to anybody else"
        );
        assert!(
            limit.allows(from, start + Duration::from_secs(61)),
            "the window ends and the counts go with it"
        );
    }

    #[test]
    fn a_long_term_key_file_is_not_overwritten() {
        let dir = std::env::temp_dir().join(format!("tw-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("long-term.key");
        let _ = std::fs::remove_file(&path);

        let key = LongTermKey::from_bytes(&[7u8; 32]);
        key.write_new(&path).expect("the first write lands");
        let read = LongTermKey::read(&path).expect("and reads back");
        assert_eq!(read.public(), key.public());

        let another = LongTermKey::from_bytes(&[8u8; 32]);
        let refused = another.write_new(&path);
        assert!(
            refused.is_err(),
            "writing over a long-term key retires an identity clients still name"
        );
        assert_eq!(
            LongTermKey::read(&path).unwrap().public(),
            key.public(),
            "and the refusal left the original alone"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn a_key_file_of_the_wrong_length_is_refused_rather_than_truncated() {
        let dir = std::env::temp_dir().join(format!("tw-key-short-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short.key");
        std::fs::write(&path, [1u8; 31]).unwrap();

        let refused = LongTermKey::read(&path);
        assert!(
            refused.is_err(),
            "a damaged key file must not become a key nobody published"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
