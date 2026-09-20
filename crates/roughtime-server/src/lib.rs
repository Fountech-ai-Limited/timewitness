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
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
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
/// draft makes one usefully larger. What happens to a datagram larger than this depends on the
/// platform, and until 2026-09-16 this comment described one of them as though it were both.
/// Linux cuts the datagram down to the buffer and hands it over, so it fails the encoding check
/// and gets the same silence any other bad packet gets. Windows throws the whole datagram away and
/// returns os error 10040 from the receive in its place, so the loop sees an error and no
/// datagram. [`serve`] treats that error as the datagram it stands for; see
/// [`a_failed_receive`].
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
    /// The network it is on has sent more than its share lately.
    RateLimited,
    /// The server has no usable statement about its own clock, so it will not date anything.
    NoReading(String),
    /// The response could not be built, which is a fault in this server rather than in the request.
    CouldNotAnswer(String),
    /// A datagram was lost on the way in, and the socket said why.
    ///
    /// There is no address on this one because a receive that failed did not bring one. See the
    /// note on [`serve`] about what a failed receive is and is not evidence of.
    CouldNotReceive(String),
    /// A datagram arrived that was larger than any request, and the platform threw it away
    /// rather than hand it over.
    ///
    /// Windows reports one of those as an error on the receive, os error 10040, in place of the
    /// datagram; the address went with it, which is why there is none here. Linux cuts the
    /// datagram down to the buffer and hands it over, where it fails the encoding check and is
    /// [`Dropped::NotOurs`] like any other bad packet. Added 2026-09-16, the evening the first
    /// fix to `serve` shipped, because that fix counted one of these as a fault of the socket.
    Oversize(String),
    /// The response was built and the socket would not send it to that address.
    ///
    /// Dropped and counted rather than returned, from 2026-09-15. Until then one failed send ended
    /// `serve`, the process exited, and the host started it again cold, which on a platform that
    /// disciplines its own clock before answering was two to three minutes of no answers for
    /// whatever made one send fail. A send to one address failing says nothing about the socket
    /// for the next address.
    CouldNotSend(String),
}

impl core::fmt::Display for Dropped {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Dropped::NotOurs(d) => write!(f, "not a request for this server: {d}"),
            Dropped::RateLimited => write!(f, "over this network's share of the socket"),
            Dropped::NoReading(d) => write!(f, "this server will not date a response: {d}"),
            Dropped::CouldNotAnswer(d) => write!(f, "this server could not build a response: {d}"),
            Dropped::CouldNotSend(d) => write!(f, "the socket would not send the response: {d}"),
            Dropped::CouldNotReceive(d) => {
                write!(f, "a datagram was lost before it could be read: {d}")
            }
            Dropped::Oversize(d) => {
                write!(
                    f,
                    "a datagram larger than any request was thrown away unread: {d}"
                )
            }
        }
    }
}

/// What the serve loop needs of a socket, so that a test can hand it one whose sends fail.
///
/// `UdpSocket` is the one that runs. The trait exists because a real socket cannot be made to
/// refuse a send to an address it just received from, and the one path this loop has to survive
/// is exactly that.
pub trait Datagrams {
    /// One packet, and where it came from.
    fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    /// One packet, to there.
    fn send_to(&mut self, response: &[u8], to: SocketAddr) -> io::Result<usize>;
}

impl Datagrams for &UdpSocket {
    fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buffer)
    }

    fn send_to(&mut self, response: &[u8], to: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, response, to)
    }
}

impl<D: Datagrams + ?Sized> Datagrams for &mut D {
    fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        (**self).recv_from(buffer)
    }

    fn send_to(&mut self, response: &[u8], to: SocketAddr) -> io::Result<usize> {
        (**self).send_to(response, to)
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
///
/// Keyed on the network and not the port, and not on the address either.
///
/// The port went first, on 2026-09-15: until then the key was the whole `SocketAddr`, so a client
/// varying its source port was never limited and the map grew by one entry per port it chose. The
/// address followed on 2026-09-20, because an IPv6 client is handed a whole /64 and picks any
/// address inside it at no cost, so an allowance per address is no allowance at all. Measured that
/// day: one /64 filled a 65,536 entry map in under nine milliseconds, sustained at 419 kbit/s, and
/// every packet sat inside its own fresh allowance. So IPv6 counts on the /64 and IPv4 on the
/// address, which is the one host it names.
///
/// The map still has a ceiling of distinct networks per window, because a map keyed on anything is
/// a map somebody can try to fill. **What is past the ceiling is answered and not counted, out of
/// one shared allowance.** Until 2026-09-20 it was refused, and the comment here said that this was
/// "what the emptied map already does for everybody". An emptied map refuses nobody; it gives
/// everybody a fresh allowance. The two are opposites, and the sentence saying they were the same
/// is the part that stopped anybody looking for five days. Refusing there hands an attacker a
/// switch: fill the map and every client not already in it is turned away, which is every agent
/// synchronising for the first time and every agent after a reboot.
///
/// The shared allowance is what stops the other direction. Answering everything past the ceiling
/// would make this a server that signs on demand for anyone willing to send it 65,536 packets
/// first. One allowance the size of one network's bounds the work at the ceiling's share plus one,
/// and it is emptied with the map.
pub struct RateLimit {
    per_window: u32,
    window: Duration,
    started: Instant,
    seen: HashMap<IpAddr, u32>,
    address_ceiling: usize,
    past_the_ceiling: u32,
}

/// How many distinct addresses one window will count before a new one is refused.
///
/// At a few tens of bytes an entry this is under three megabytes, which is the most the map can
/// ever hold, and it is far above what two servers of ours see in a minute.
pub const DEFAULT_ADDRESS_CEILING: usize = 65_536;

impl RateLimit {
    /// A limit of `per_window` packets from one address per `window`.
    #[must_use]
    pub fn new(per_window: u32, window: Duration) -> Self {
        Self {
            per_window,
            window,
            started: Instant::now(),
            seen: HashMap::new(),
            address_ceiling: DEFAULT_ADDRESS_CEILING,
            past_the_ceiling: 0,
        }
    }

    /// The same, counting no more than this many addresses in one window.
    #[must_use]
    pub fn with_address_ceiling(mut self, addresses: usize) -> Self {
        self.address_ceiling = addresses;
        self
    }

    /// How many addresses this window has counted so far.
    #[must_use]
    pub fn addresses(&self) -> usize {
        self.seen.len()
    }

    /// Whether this address may send another packet now, counting this one.
    pub fn allows(&mut self, from: SocketAddr, now: Instant) -> bool {
        if now.duration_since(self.started) >= self.window {
            self.seen.clear();
            self.past_the_ceiling = 0;
            self.started = now;
        }
        let network = Self::network_of(from.ip());
        if !self.seen.contains_key(&network) && self.seen.len() >= self.address_ceiling {
            // Answered rather than refused, and out of one allowance rather than its own, so the
            // map stays bounded and so does the work. See the note on this type for why refusing
            // here is the switch an attacker was being handed.
            self.past_the_ceiling = self.past_the_ceiling.saturating_add(1);
            return self.past_the_ceiling <= self.per_window;
        }
        let count = self.seen.entry(network).or_insert(0);
        *count += 1;
        *count <= self.per_window
    }

    /// The network one allowance is counted against: the /64 for IPv6, the address itself for IPv4.
    ///
    /// A /64 is what an IPv6 client is given, so every address in it is the same client and the low
    /// 64 bits are free for it to vary. An IPv4 address names one host, so it is its own network
    /// and grouping it further would put unrelated clients on one allowance.
    fn network_of(address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        }
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

/// After how many receive faults in a row the loop starts waiting between receives.
///
/// Eight. No honest burst reaches it, because a fault on the way in means a datagram was lost and
/// the next receive normally finds either the next datagram or the read timeout, and both of those
/// put the run back to nought. Eight in a row with neither means the socket is answering
/// instantly and answering nothing, which is a spin rather than traffic.
const FAULTS_BEFORE_WAITING: u32 = 8;

/// How long to wait between receives once faults are arriving with nothing in between.
///
/// Twenty milliseconds. It is short enough to be invisible to a client that is being answered and
/// long enough that a socket failing instantly costs a sleeping thread rather than a core. It also
/// sets the clock on [`FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT`], which is the part that matters.
const FAULT_WAIT: Duration = Duration::from_millis(20);

/// After how many receive faults in a row the loop stops calling them datagrams and returns.
///
/// A thousand and twenty-four, and the count is doing less work here than [`FAULT_WAIT`] beside
/// it. From the eighth fault on, every one of them costs a wait, so a run this long takes over
/// twenty seconds in which the socket produced no datagram and not one timeout. That is the real
/// test: not how many faults, but that the socket gave back nothing else for that long.
///
/// The number is chosen to be out of reach of anything a client can do, which is the whole point.
/// Every fault a remote client can cause needs a packet from that client, and a packet arriving
/// during the wait is a datagram waiting on the next receive, which puts the run back to nought.
/// Reaching this by sending would mean a flood sustained for twenty seconds that never once let a
/// datagram through, and the answer to a flood is not in this function. One packet must never
/// reach it, and before 2026-09-16 one packet did.
///
/// That argument has one exception and it was found the same evening: a packet the platform
/// throws away before the loop sees it is a packet that never becomes a datagram. On Windows an
/// oversize datagram is exactly that, and a flood of nothing else reached this ceiling in 20.8 s
/// on the real command. [`a_failed_receive`] is where each error kind is asked whether it is a
/// datagram in disguise, and that is the function to read before touching this number.
const FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT: u32 = 1024;

/// The Windows error for a datagram larger than the buffer it was to be read into.
///
/// WSAEMSGSIZE. The platform discards the datagram and returns this in its place, so the datagram
/// is consumed and the loop is told about it by an error rather than by a length. The standard
/// library files it under no kind of its own, which is why it is matched on the number.
#[cfg(windows)]
const A_DATAGRAM_TOO_BIG_FOR_THE_BUFFER: i32 = 10040;

/// What a failed receive is evidence of.
///
/// Three answers, and the second is the one that was missing until 2026-09-16.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailedReceive {
    /// Nothing was waiting: the read timeout expired or a signal arrived. The socket is working.
    NothingWaiting,
    /// A datagram arrived and the platform threw it away rather than hand it over. It counts as a
    /// datagram received, because it is one, and it is refused as [`Dropped::Oversize`].
    DatagramThrownAway,
    /// No datagram reached this loop. Counted towards the give-up ceiling.
    Fault,
}

/// Ask a failed receive what it is evidence of.
///
/// # Every kind that ends in the fault counter, and whether a remote sender can put it there
///
/// The give-up ceiling is safe only while every fault a remote sender can cause is followed by a
/// datagram that resets the run. So each kind that reaches [`FailedReceive::Fault`] is asked one
/// question here: can somebody on the network cause it once per packet with no datagram reaching
/// this loop? Written beside the kind, because the first fix to this loop argued the answer was
/// no for all of them and one of them was yes.
///
/// - `WouldBlock`, `TimedOut`, `Interrupted`: not faults at all. The read timeout expiring is how
///   [`serve`] gets to look at `keep_going`, and a signal arriving mid-receive is the process's
///   own business. Both put the run back to nought.
/// - os error 10040 on Windows, the datagram too big for the buffer: **yes, and that is this
///   row.** The sender's packet arrived, Windows discarded it and returned the error in its place,
///   so the loop saw a fault and never a datagram, and a flood of nothing else walked the counter
///   to the ceiling at the loop's own pace. It is now [`FailedReceive::DatagramThrownAway`],
///   which resets the run exactly as the datagram would have. Linux never raises it on a receive,
///   because POSIX truncates and hands the datagram over.
/// - `ConnectionReset`, os error 10054 on Windows, and its relations `NetworkUnreachable`,
///   `HostUnreachable`, `ConnectionRefused` and `NetworkDown`, os errors 10051, 10065, 10061 and
///   10050: **not by a UDP sender.** Each is the host passing on an ICMP message about a datagram
///   this server sent, delivered on the next receive, and this server sends only in answer to a
///   datagram it received, so each ordinarily follows the receive that reset the run. Windows
///   does not check that the ICMP message answers a datagram this socket actually sent, so a
///   forged ICMP unreachable naming this socket's port would raise one with no datagram behind
///   it. That takes a raw socket and the port rather than a UDP packet, it is the one kind left
///   that could walk the counter, and it is recorded rather than defended against here.
///   Linux does not surface ICMP on an unconnected UDP socket without `IP_RECVERR`, which this
///   socket does not set.
/// - `InvalidInput`, `NotConnected`, `Unsupported` and the bad-descriptor family: **no.** These
///   are about how the socket was made or called, they cannot be caused from the network, and
///   they are the socket faults the ceiling exists for, because they fail instantly for ever.
/// - `OutOfMemory`, os error 10055 on Windows: **not per packet.** Buffer exhaustion on the
///   host, which a flood can contribute to and which clears on its own; it is counted and it is
///   waited out at [`FAULT_WAIT`] a time.
/// - Anything else the platform invents: counted, and it is the kind nobody thought of, which is
///   why the ceiling is a length of time and not a list.
fn a_failed_receive(error: &io::Error) -> FailedReceive {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
            FailedReceive::NothingWaiting
        }
        _ if a_datagram_was_thrown_away(error) => FailedReceive::DatagramThrownAway,
        _ => FailedReceive::Fault,
    }
}

/// Whether this receive error stands for a datagram the platform discarded as too big.
///
/// Only Windows reports one. Everywhere else an oversize datagram is cut down to the buffer and
/// handed over as an ordinary receive, so the answer is no before the error is looked at.
#[cfg(windows)]
fn a_datagram_was_thrown_away(error: &io::Error) -> bool {
    error.raw_os_error() == Some(A_DATAGRAM_TOO_BIG_FOR_THE_BUFFER)
}

#[cfg(not(windows))]
fn a_datagram_was_thrown_away(_error: &io::Error) -> bool {
    false
}

/// What [`serve`] does about the `n`th receive fault in a row.
///
/// Split out from the loop so the policy can be read and tested on its own, because the loop
/// having this policy written as a list of error kinds inline is what made the fault of
/// 2026-09-16 possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterAFault {
    /// Count the lost datagram and receive again straight away.
    CarryOn,
    /// Count it, then wait before receiving again, so a socket failing instantly does not spin.
    WaitFirst,
    /// The socket has given back nothing but faults for long enough that it is the socket.
    GiveUp,
}

/// The policy in one place: carry on, wait, or give up, by how long the run of faults is.
fn after_a_fault(consecutive: u32) -> AfterAFault {
    if consecutive >= FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT {
        AfterAFault::GiveUp
    } else if consecutive >= FAULTS_BEFORE_WAITING {
        AfterAFault::WaitFirst
    } else {
        AfterAFault::CarryOn
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
/// # A fault on the way in is about one datagram, and almost never about the socket
///
/// This is the part to read before changing anything here, because getting it wrong once already
/// cost us a server.
///
/// Until 2026-09-16 this loop tolerated two error kinds on `recv_from` and returned on every other
/// one. On Windows a client that asks and then closes its socket has the answer arrive at a port
/// nobody is listening on, the host answers ICMP port-unreachable, and the next receive on this
/// server's own unconnected socket returns `ConnectionReset`, os error 10054. Neither of the two
/// tolerated kinds, so the loop returned and the server answered nobody while the process stayed
/// up. One packet and a close, from anybody, with no authentication. Linux does not surface ICMP
/// on an unconnected UDP socket without `IP_RECVERR`, which is why CI never saw it and why only a
/// desktop run went red.
///
/// A list of tolerated kinds is the wrong shape for this and lengthening it would only push the
/// same fault into whichever kind nobody thought of. What a receive error actually says is that
/// this datagram, or the answer to the last one, did not arrive. It says nothing about whether the
/// socket still works, and the great majority of the kinds that can appear here are the platform
/// passing on news about somebody else's socket. So **no error kind ends this loop**. Every one of
/// them costs one datagram, is handed to `watch` as [`Dropped::CouldNotReceive`], and the loop
/// receives again.
///
/// The one thing left worth defending against is a socket that has genuinely stopped working and
/// so fails instantly for ever, which would be a hot loop burning a core and answering nobody in
/// silence. That is answered by the length of the run rather than by the kind: from
/// [`FAULTS_BEFORE_WAITING`] faults in a row the loop waits [`FAULT_WAIT`] between receives, and
/// at [`FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT`] it gives up and returns, which lets whatever runs
/// this start it again. A single datagram, a single timeout, or a signal puts the run back to
/// nought, and the wait is what keeps that ceiling out of a remote client's reach; see the note on
/// the constant.
///
/// **A datagram the platform throws away is still a datagram.** The paragraph above was written on
/// the morning of 2026-09-16 and was wrong by the evening: on Windows a datagram larger than
/// [`MAX_DATAGRAM`] is discarded and the receive returns os error 10040 instead of it, so the
/// packet arrived and the loop saw only a fault. A flood of nothing else took the real command
/// off the air in 20.8 s. [`a_failed_receive`] now asks every error kind whether it is a datagram
/// in disguise, and that one is: it resets the run and is watched as [`Dropped::Oversize`].
///
/// # Errors
///
/// Only what [`FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT`] describes: the socket gave back nothing but
/// faults for over twenty seconds, so the last of them is returned. A failed send is not an error
/// here and neither is a single failed receive: both are drops, handed to `watch` as
/// [`Dropped::CouldNotSend`] and [`Dropped::CouldNotReceive`], and the loop carries on to the next
/// packet. A read timeout is how `keep_going` gets looked at, so the socket wants one set before
/// this is called.
pub fn serve<D, C, K, W>(
    mut socket: D,
    server: &mut Server,
    limit: &mut RateLimit,
    mut clock: C,
    mut keep_going: K,
    mut watch: W,
) -> Result<(), io::Error>
where
    D: Datagrams,
    C: FnMut() -> Option<Reading>,
    K: FnMut() -> bool,
    W: FnMut(Option<SocketAddr>, &Dropped),
{
    let mut buffer = [0u8; MAX_DATAGRAM];
    // How many receives in a row have come back a fault, with no datagram and no timeout between
    // them. Nought almost always, and the only thing that can end this loop from the inside.
    let mut faults: u32 = 0;
    while keep_going() {
        let (len, from) = match socket.recv_from(&mut buffer) {
            Ok(got) => {
                faults = 0;
                got
            }
            Err(e) if a_failed_receive(&e) == FailedReceive::NothingWaiting => {
                faults = 0;
                continue;
            }
            Err(e) if a_failed_receive(&e) == FailedReceive::DatagramThrownAway => {
                // A datagram arrived and was too big to be a request. That is a received datagram
                // refused, so it resets the run the way any datagram does, and it is watched under
                // its own name rather than as a fault of the socket.
                faults = 0;
                watch(None, &Dropped::Oversize(e.to_string()));
                continue;
            }
            Err(e) => {
                faults += 1;
                match after_a_fault(faults) {
                    AfterAFault::GiveUp => return Err(e),
                    AfterAFault::WaitFirst => {
                        watch(None, &Dropped::CouldNotReceive(e.to_string()));
                        std::thread::sleep(FAULT_WAIT);
                        continue;
                    }
                    AfterAFault::CarryOn => {
                        watch(None, &Dropped::CouldNotReceive(e.to_string()));
                        continue;
                    }
                }
            }
        };

        if !limit.allows(from, Instant::now()) {
            watch(Some(from), &Dropped::RateLimited);
            continue;
        }

        let Some(reading) = clock() else {
            watch(
                Some(from),
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
            watch(Some(from), &Dropped::CouldNotAnswer(e.to_string()));
            continue;
        }

        match server.answer(&buffer[..len], reading) {
            Ok(response) => {
                if let Err(e) = socket.send_to(&response, from) {
                    watch(Some(from), &Dropped::CouldNotSend(e.to_string()));
                }
            }
            Err(dropped) => watch(Some(from), &dropped),
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
        assert_eq!(checked.radius(), Some(1_000_000_000));
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
    fn one_address_is_one_address_whatever_port_it_sends_from() {
        // The fault of 2026-09-15: the limit was keyed on address and port, so a client varying
        // its source port was never limited and the map grew by one entry per port.
        let mut limit = RateLimit::new(3, Duration::from_secs(60));
        let start = Instant::now();
        for port in 1..=3u16 {
            let from: SocketAddr = format!("203.0.113.7:{port}").parse().unwrap();
            assert!(limit.allows(from, start), "port {port} is inside the share");
        }
        let fourth: SocketAddr = "203.0.113.7:4".parse().unwrap();
        assert!(
            !limit.allows(fourth, start),
            "the fourth packet is over the address's share whichever port it came from"
        );
        let other: SocketAddr = "203.0.113.8:4".parse().unwrap();
        assert!(
            limit.allows(other, start),
            "another address has its own share"
        );
    }

    #[test]
    fn the_map_of_addresses_has_a_ceiling_per_window() {
        // The map has a ceiling, because a limit keyed on who is asking is a map an attacker fills
        // by being lots of people. What the ceiling may never do is turn the server off for
        // everybody who is not already in it.
        let mut limit = RateLimit::new(3, Duration::from_secs(60)).with_address_ceiling(2);
        let start = Instant::now();
        let a: SocketAddr = "203.0.113.1:2002".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:2002".parse().unwrap();
        let c: SocketAddr = "203.0.113.3:2002".parse().unwrap();
        assert!(limit.allows(a, start));
        assert!(limit.allows(b, start));
        assert!(
            limit.allows(c, start),
            "a first-ever honest client is answered with the map at its ceiling"
        );
        assert_eq!(limit.addresses(), 2, "and it was not added to the map");
        assert!(
            limit.allows(a, start),
            "the two already counted keep their share"
        );
        assert!(limit.allows(a, start), "which is three packets");
        assert!(
            !limit.allows(a, start),
            "and no more than their share: that was the fourth from a"
        );
        assert!(
            limit.allows(c, start + Duration::from_secs(61)),
            "the window ends and the map is emptied"
        );
    }

    #[test]
    fn past_the_ceiling_the_work_is_still_bounded() {
        // Answering everybody past the ceiling would be a server that signs on demand for anyone
        // who first sends it 65,536 packets. So what is past the ceiling shares one allowance, and
        // the total work in a window stays the ceiling's share plus that one.
        let mut limit = RateLimit::new(3, Duration::from_secs(60)).with_address_ceiling(1);
        let start = Instant::now();
        let inside: SocketAddr = "203.0.113.1:2002".parse().unwrap();
        assert!(limit.allows(inside, start));
        let mut answered = 0;
        for n in 0..50u32 {
            let from: SocketAddr = format!("198.51.100.{}:2002", n % 256).parse().unwrap();
            if limit.allows(from, start) {
                answered += 1;
            }
        }
        assert_eq!(
            answered, 3,
            "everything past the ceiling shares one address's allowance"
        );
        assert_eq!(limit.addresses(), 1, "and none of it grew the map");
        assert!(
            limit.allows(inside, start),
            "the one inside the ceiling still has its own share"
        );
        // The shared allowance is emptied with the map, or the first window's attacker would shut
        // the overflow path for every window after it.
        let later = start + Duration::from_secs(61);
        let fresh: SocketAddr = "198.51.100.200:2002".parse().unwrap();
        assert!(
            limit.allows(fresh, later),
            "the window ends and so does that"
        );
    }

    #[test]
    fn one_network_of_addresses_fills_one_entry_and_not_the_map() {
        // An IPv6 client is handed a whole /64 and picks any address inside it at no cost. Counting
        // addresses there counts nothing: on 2026-09-20 one /64 filled a 65,536 entry map in under
        // nine milliseconds for 419 kbit/s, and every packet was inside its own fresh allowance.
        let mut limit = RateLimit::new(3, Duration::from_secs(60)).with_address_ceiling(1_000);
        let start = Instant::now();
        let mut answered = 0;
        for n in 0..50u32 {
            let from: SocketAddr = format!("[2001:db8::{n:x}]:2002").parse().unwrap();
            if limit.allows(from, start) {
                answered += 1;
            }
        }
        assert_eq!(
            limit.addresses(),
            1,
            "fifty addresses in one /64 are one network and one entry"
        );
        assert_eq!(answered, 3, "and they share one network's allowance");
        // A different /64 is a different client and is counted separately.
        let elsewhere: SocketAddr = "[2001:db8:0:1::1]:2002".parse().unwrap();
        assert!(limit.allows(elsewhere, start));
        assert_eq!(limit.addresses(), 2);
    }

    /// A transport whose sends fail as often as it is told to, and which hands the serve loop the
    /// requests it was given, in order.
    struct Flaky {
        requests: Vec<(Vec<u8>, SocketAddr)>,
        failed_sends_left: u32,
        sent: Vec<SocketAddr>,
    }

    impl Datagrams for Flaky {
        fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if self.requests.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "nothing more"));
            }
            let (packet, from) = self.requests.remove(0);
            buffer[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), from))
        }

        fn send_to(&mut self, _response: &[u8], to: SocketAddr) -> io::Result<usize> {
            if self.failed_sends_left > 0 {
                self.failed_sends_left -= 1;
                return Err(io::Error::other("no route to that address"));
            }
            self.sent.push(to);
            Ok(0)
        }
    }

    #[test]
    fn a_send_that_fails_is_dropped_and_counted_and_the_server_carries_on() {
        // The fault of 2026-09-15: one failed send_to returned out of serve, the process exited,
        // and the host restarted it cold, two to three minutes of no answers for whatever made one
        // send fail. Here the first send fails and the second request still gets its answer.
        let mut server = a_server();
        let request = build_request(&[0x33u8; 32], &server.public_key());
        let first: SocketAddr = "203.0.113.7:2002".parse().unwrap();
        let second: SocketAddr = "203.0.113.8:2002".parse().unwrap();
        let mut transport = Flaky {
            requests: vec![(request.clone(), first), (request, second)],
            failed_sends_left: 1,
            sent: Vec::new(),
        };
        let mut dropped = Vec::new();
        let mut left = 3;
        let outcome = serve(
            &mut transport,
            &mut server,
            &mut RateLimit::default(),
            || {
                Some(Reading {
                    seconds: NOW,
                    radius_seconds: 1,
                })
            },
            || {
                left -= 1;
                left > 0
            },
            |from, why| dropped.push((from, why.clone())),
        );
        assert!(
            outcome.is_ok(),
            "a failed send is not a socket fault: {outcome:?}"
        );
        assert_eq!(
            transport.sent,
            vec![second],
            "the second request was answered"
        );
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, Some(first));
        assert!(
            matches!(dropped[0].1, Dropped::CouldNotSend(_)),
            "{:?}",
            dropped[0].1
        );
    }

    /// A transport reading from a script, so a receive can be made to fail on demand.
    ///
    /// A real socket cannot be asked for `ConnectionReset` on a platform that does not produce it,
    /// and the fault of 2026-09-16 only appears on Windows. This is how the loop's answer to a
    /// failed receive gets tested everywhere rather than on one platform.
    struct Scripted {
        script: Vec<io::Result<(Vec<u8>, SocketAddr)>>,
        sent: Vec<SocketAddr>,
    }

    impl Datagrams for Scripted {
        fn recv_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            if self.script.is_empty() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "nothing more"));
            }
            match self.script.remove(0) {
                Ok((packet, from)) => {
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok((packet.len(), from))
                }
                Err(e) => Err(e),
            }
        }

        fn send_to(&mut self, _response: &[u8], to: SocketAddr) -> io::Result<usize> {
            self.sent.push(to);
            Ok(0)
        }
    }

    /// Run the scripted transport for `rounds` turns of the loop.
    #[allow(clippy::type_complexity)]
    fn serve_script(
        script: Vec<io::Result<(Vec<u8>, SocketAddr)>>,
        rounds: i32,
    ) -> (
        Result<(), io::Error>,
        Vec<SocketAddr>,
        Vec<(Option<SocketAddr>, Dropped)>,
    ) {
        let mut server = a_server();
        let mut transport = Scripted {
            script,
            sent: Vec::new(),
        };
        let mut dropped = Vec::new();
        let mut left = rounds;
        let outcome = serve(
            &mut transport,
            &mut server,
            &mut RateLimit::default(),
            || {
                Some(Reading {
                    seconds: NOW,
                    radius_seconds: 1,
                })
            },
            || {
                left -= 1;
                left > 0
            },
            |from, why| dropped.push((from, why.clone())),
        );
        (outcome, transport.sent, dropped)
    }

    #[test]
    fn a_client_that_walks_away_costs_one_datagram_and_not_the_server() {
        // The fault of 2026-09-16. A client asks and closes its socket, the answer reaches a port
        // nobody is listening on, the host answers ICMP port-unreachable, and Windows hands that
        // to the next receive on this server's own socket as ConnectionReset, os error 10054.
        // Until this was fixed the loop returned on it and the server answered nobody afterwards.
        let server = a_server();
        let request = build_request(&[0x51u8; 32], &server.public_key());
        let next: SocketAddr = "203.0.113.9:2002".parse().unwrap();
        let (outcome, sent, dropped) = serve_script(
            vec![
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "os error 10054",
                )),
                Ok((request, next)),
            ],
            4,
        );

        assert!(
            outcome.is_ok(),
            "one lost datagram is not a socket fault: {outcome:?}"
        );
        assert_eq!(sent, vec![next], "the next request was answered");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].0, None, "a failed receive brings no address");
        assert!(
            matches!(dropped[0].1, Dropped::CouldNotReceive(_)),
            "{:?}",
            dropped[0].1
        );
    }

    #[test]
    fn an_error_nobody_anticipated_does_not_end_the_loop_either() {
        // The point of the fix, and the reason it is not a longer list of tolerated kinds: the
        // kind nobody thought of is the one that takes the server off the air.
        let server = a_server();
        let request = build_request(&[0x52u8; 32], &server.public_key());
        let next: SocketAddr = "203.0.113.10:2002".parse().unwrap();
        let (outcome, sent, dropped) = serve_script(
            vec![
                Err(io::Error::other("a kind this loop was never told about")),
                Ok((request, next)),
            ],
            4,
        );

        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(sent, vec![next]);
        assert_eq!(dropped.len(), 1);
        assert!(matches!(dropped[0].1, Dropped::CouldNotReceive(_)));
    }

    #[test]
    fn a_datagram_between_the_faults_puts_the_run_back_to_nought() {
        // Which is what keeps the give-up ceiling out of a client's reach: every fault a client
        // can cause needs a packet from that client, and that packet is a datagram.
        let server = a_server();
        let request = build_request(&[0x53u8; 32], &server.public_key());
        let one: SocketAddr = "203.0.113.11:2002".parse().unwrap();
        let two: SocketAddr = "203.0.113.12:2002".parse().unwrap();
        let fault = || {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "os error 10054",
            ))
        };
        let (outcome, sent, dropped) = serve_script(
            vec![
                fault(),
                Ok((request.clone(), one)),
                fault(),
                Ok((request, two)),
            ],
            6,
        );

        assert!(outcome.is_ok(), "{outcome:?}");
        assert_eq!(sent, vec![one, two], "both requests were answered");
        assert_eq!(dropped.len(), 2, "and both lost datagrams were counted");
    }

    #[test]
    fn the_policy_on_a_run_of_faults_is_carry_on_then_wait_then_give_up() {
        assert_eq!(after_a_fault(1), AfterAFault::CarryOn);
        assert_eq!(
            after_a_fault(FAULTS_BEFORE_WAITING - 1),
            AfterAFault::CarryOn
        );
        assert_eq!(after_a_fault(FAULTS_BEFORE_WAITING), AfterAFault::WaitFirst);
        assert_eq!(
            after_a_fault(FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT - 1),
            AfterAFault::WaitFirst
        );
        assert_eq!(
            after_a_fault(FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT),
            AfterAFault::GiveUp,
            "a socket answering nothing but faults is a socket, not a datagram"
        );
    }

    #[test]
    fn the_give_up_ceiling_cannot_be_reached_in_under_twenty_seconds() {
        // The property that makes the ceiling safe to have at all. It is arithmetic rather than a
        // measurement, and it is a test because the two constants are edited separately and either
        // one moving alone would take the property away with nothing saying so.
        let waiting = FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT - FAULTS_BEFORE_WAITING;
        let shortest = FAULT_WAIT * waiting;
        assert!(
            shortest >= Duration::from_secs(20),
            "a run of faults reaching the ceiling takes {shortest:?}, which is short enough for a \
             client to sit through"
        );
    }

    #[test]
    fn the_three_kinds_that_mean_nothing_was_waiting_are_not_faults() {
        let reset = io::Error::new(io::ErrorKind::ConnectionReset, "os error 10054");
        assert_eq!(
            a_failed_receive(&reset),
            FailedReceive::Fault,
            "a reset is a lost datagram rather than a quiet socket, so it is counted"
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(
                a_failed_receive(&io::Error::new(kind, "quiet")),
                FailedReceive::NothingWaiting
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_datagram_too_big_for_the_buffer_is_a_datagram_and_not_a_fault() {
        let too_big = io::Error::from_raw_os_error(A_DATAGRAM_TOO_BIG_FOR_THE_BUFFER);
        assert_eq!(
            a_failed_receive(&too_big),
            FailedReceive::DatagramThrownAway,
            "Windows threw the datagram away and reported it; the datagram still arrived"
        );
        assert_eq!(
            a_failed_receive(&io::Error::from_raw_os_error(10054)),
            FailedReceive::Fault,
            "and a reset by number is still a fault"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_run_of_oversize_datagrams_longer_than_the_ceiling_does_not_end_the_loop() {
        // The fault of the evening of 2026-09-16, as arithmetic rather than a minute on a socket:
        // more thrown-away datagrams in a row than the ceiling allows faults, and then an honest
        // request. Before the fix the loop returned at the ceiling and the request was never read.
        let server = a_server();
        let request = build_request(&[0x54u8; 32], &server.public_key());
        let next: SocketAddr = "203.0.113.13:2002".parse().unwrap();
        let rounds = FAULTS_BEFORE_THE_SOCKET_IS_THE_FAULT + 8;
        let mut script: Vec<io::Result<(Vec<u8>, SocketAddr)>> = (0..rounds)
            .map(|_| {
                Err(io::Error::from_raw_os_error(
                    A_DATAGRAM_TOO_BIG_FOR_THE_BUFFER,
                ))
            })
            .collect();
        script.push(Ok((request, next)));
        let (outcome, sent, dropped) = serve_script(script, i32::try_from(rounds).unwrap() + 4);

        assert!(
            outcome.is_ok(),
            "a thousand oversize datagrams are a thousand datagrams, not a socket fault: {outcome:?}"
        );
        assert_eq!(
            sent,
            vec![next],
            "and the honest request after them was answered"
        );
        assert_eq!(
            dropped.len() as u32,
            rounds,
            "every one of them was counted"
        );
        assert!(
            dropped
                .iter()
                .all(|(from, why)| from.is_none() && matches!(why, Dropped::Oversize(_))),
            "each under its own name, with no address, because Windows kept the address with the \
             datagram"
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
