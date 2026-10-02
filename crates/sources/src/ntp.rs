//! The NTP client: a socket, and the arithmetic that turns forty-eight bytes into an exchange.
//!
//! ## What this source is for, and the one thing it can never be
//!
//! Plain NTP is unauthenticated. Anybody on the path can write the reply, and there is no signature
//! in it for anybody to check afterwards, so nothing from this file may ever appear in a receipt as
//! evidence. Our own bound is never third-party evidence and this is not a matter of degree:
//! [`SourceKind::Ntp`] answers no to `carries_third_party_signature`, and the receipt crate is where
//! that answer is enforced.
//!
//! What it is for is the clock. A Roughtime server states its own uncertainty as a radius in whole
//! seconds, because the protocol was designed to prove roughly what time it is rather than to
//! discipline anything. An NTP server states a root delay and a root dispersion in units of about
//! fifteen microseconds, and the round trip to a well-connected one is milliseconds. So a round of
//! Roughtime servers alone can only ever support an interval seconds wide, whatever else is done to
//! it, and this is the source that makes a narrower one possible.
//!
//! Both kinds are wanted for that reason and not out of tidiness. Roughtime carries the evidence and
//! cannot narrow the bound; NTP narrows the bound and carries no evidence. A round with both in it
//! was the first time this product's selection rule had more than one kind of source to choose
//! between.
//!
//! A third kind arrived on 2026-09-09 and it is NTS, in `nts.rs`. It is this protocol with the
//! packet authenticated, so it narrows nothing that this file does not already narrow, and what it
//! adds is the one thing this file can never have: a reply nobody on the path could have written.
//! Everything below about a plain server being trusted only as far as a majority agrees with it is
//! the reason that matters.
//!
//! ## The reply is checked here, and that is a difference from Roughtime worth stating
//!
//! Every rule about a Roughtime response lives in `timewitness_core::evidence` rather than in its
//! client, because a stranger's verifier has to apply the same rules to the same bytes years later.
//! Nothing here has that requirement, because nothing here ever leaves this machine: an NTP reply is
//! used to steer the clock and is then gone. So the checks sit beside the socket, and there is no
//! second copy of them anywhere to drift out of step.
//!
//! ## What is checked, and why each one is not optional
//!
//! The transmit timestamp this client sends is random rather than a reading of the clock. That is
//! the standard hardening and it does two things at once. It stops the request telling anybody on
//! the path what this machine thinks the time is, and it turns the origin field of the reply into a
//! challenge and response: a reply that does not echo those eight bytes is a reply to somebody
//! else's request, or to nobody's, and it is refused rather than used. The bytes come from the nonce
//! the caller generated, so they are the caller's own choice rather than something this file
//! invented, which is the same discipline the Roughtime client works under.
//!
//! Everything else refused here is a server saying its own answer is worthless: the leap indicator
//! at three, which is the server reporting that it has not synchronised; stratum zero, which is a
//! kiss-o'-death packet rather than a time; and a stratum past fifteen, which is unsynchronised by
//! the standard's own reckoning. None of those is turned into a wider interval. A source that says
//! it does not know the time is not a weak source, it is not a source, and the round carries on with
//! whatever else answered.

use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use timewitness_core::time::Nanos;
use timewitness_core::{
    LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale,
    UnixNanos,
};

use crate::{Exchange, SourceError, TimeSource};

/// How long to wait for a reply before giving up.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The bytes in an NTP packet, which is a fixed forty-eight without extensions.
pub(crate) const PACKET: usize = 48;

/// The largest reply either client here will read.
///
/// An extension field or a message authentication code can follow the header. Plain NTP reads
/// neither, and the header is the first forty-eight bytes whatever follows it, so a larger reply is
/// read and its tail ignored rather than refused. NTS does read the tail, and a server returning
/// eight fresh cookies of a hundred bytes or so puts about a kilobyte behind the header, so the
/// ceiling is set well above that rather than at the size one operator happens to send today.
pub(crate) const MAX_REPLY: usize = 4096;

/// Seconds between the NTP epoch of 1900 and the Unix epoch of 1970.
const NTP_TO_UNIX: i128 = 2_208_988_800;

/// Seconds to add to an era one NTP timestamp to reach Unix time.
///
/// NTP counts seconds since 1900 in thirty-two bits, which runs out in February 2036, and the
/// counter then wraps to zero rather than stopping. The wrap is not a fault and it is not far off,
/// so it is handled here rather than left as a surprise: a timestamp below the Unix epoch's own
/// value is read as belonging to the era after the wrap. Two to the thirty-two, less the seconds
/// between the two epochs.
const NTP_ERA_ONE_TO_UNIX: i128 = 2_085_978_496;

/// A public NTP server.
///
/// There is no key here and there is nothing to check a signature against, which is the whole
/// difference between this type and [`crate::roughtime::RoughtimeServer`]. An NTP server is trusted
/// to the extent that a majority of the round agrees with it, and no further.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtpServer {
    /// A name for a person reading a receipt.
    pub name: String,
    /// Host and port.
    pub address: String,
    /// Who runs it. Derived from the host unless a deployment states otherwise.
    pub operator: Operator,
}

impl NtpServer {
    /// A server from its parts.
    #[must_use]
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        let address = address.into();
        Self {
            name: name.into(),
            operator: Operator::from_host(&address),
            address,
        }
    }

    /// The same server with its operator stated rather than derived.
    ///
    /// For the case the derivation cannot see: one company answering on two domains that share no
    /// suffix. Nothing in a reply says who sent it, so this is the only way that fact reaches the
    /// selection.
    #[must_use]
    pub fn operated_by(mut self, operator: impl Into<String>) -> Self {
        self.operator = Operator::new(operator);
        self
    }

    /// The same server, marked as one this deployment runs itself.
    ///
    /// It disciplines the clock like any other source and its interval is a real measurement. What
    /// it stops doing is counting towards the independent operators, because the party behind it is
    /// the party issuing the receipt, and our own word never sits inside the evidence a stranger
    /// checks. [`timewitness_core::Operator`] carries the reasoning.
    ///
    /// Use it for a server this deployment runs and holds the keys for and for nothing else.
    /// Marking somebody else's server as ours throws away a real chance to be wrong separately,
    /// which is the one thing the operator count is made of.
    #[must_use]
    pub fn operated_by_us(mut self, operator: impl Into<String>) -> Self {
        self.operator = Operator::first_party(operator);
        self
    }

    /// The public servers this client has been proved against.
    ///
    /// Three operators rather than three names, which is the part that matters. Sources under one
    /// operator fail together and lie together, so three addresses at one company are one source
    /// wearing three coats as far as a majority is concerned.
    ///
    /// **Three within this list and not three added to the others.** Two of these three answer on
    /// NTS as well, so the three published lists together are nine servers standing behind six
    /// operators rather than nine. That is not an oversight and it is not fixed by adding servers;
    /// it is what the public time ecosystem looks like. It is stated here, enforced by
    /// [`timewitness_core::Operator`] where the survivors are counted, and carried into the receipt
    /// so a reader counts for themselves.
    ///
    /// A pool name that resolves to a different machine on each request was the obvious alternative
    /// and it is refused here. The model keeps a window of samples per source and fits a line
    /// through it, so a name that answers from a different machine each time hands that window
    /// several clocks under one identity, and the scatter of the samples then measures the
    /// difference between machines rather than the wander of ours.
    ///
    /// This is a starting list and not a trust store. A deployment picks its own servers.
    #[must_use]
    pub fn published() -> Vec<NtpServer> {
        vec![
            NtpServer::new("cloudflare", "time.cloudflare.com:123"),
            NtpServer::new("google", "time.google.com:123"),
            NtpServer::new("ptb", "ptbtime1.ptb.de:123"),
        ]
    }
}

/// A client for one NTP server.
#[derive(Clone, Debug)]
pub struct NtpClient {
    id: SourceId,
    server: NtpServer,
    timeout: Duration,
}

impl NtpClient {
    /// A client for one server.
    #[must_use]
    pub fn new(server: NtpServer) -> Self {
        Self {
            id: SourceId::new(format!("ntp:{}", server.name)),
            server,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// How long to wait for a reply.
    #[must_use]
    pub fn waiting(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Which server this client asks.
    #[must_use]
    pub fn server(&self) -> &NtpServer {
        &self.server
    }

    /// Send a request and read the reply, with no checking of any kind.
    fn exchange_bytes(&self, request: &[u8]) -> Result<(Vec<u8>, u128, u128), SourceError> {
        udp_exchange(&self.server.address, request, self.timeout)
    }
}

/// Put a datagram on the wire and read what comes back, with no checking of any kind.
///
/// Returns the reply and the two elapsed times, measured from one instant taken on entry, the same
/// shape the Roughtime client uses. The caller turns those into the two ends of the round trip
/// against its own anchor, which is the only clock allowed in that arithmetic.
///
/// Shared with the NTS client, which sends a longer request over the same socket and reads a longer
/// reply. Both have to charge exactly the same instants to the round trip, so this is one function
/// rather than two that look alike.
pub(crate) fn udp_exchange(
    address: &str,
    request: &[u8],
    timeout: Duration,
) -> Result<(Vec<u8>, u128, u128), SourceError> {
    let started = Instant::now();
    let resolved = address
        .to_socket_addrs()
        .map_err(|e| SourceError::Transport(format!("{address} does not resolve: {e}")))?
        .next()
        .ok_or_else(|| SourceError::Transport(format!("{address} resolves to nothing")))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| SourceError::Transport(format!("no local socket: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| SourceError::Transport(format!("no deadline on the socket: {e}")))?;
    // Connecting a datagram socket makes the kernel drop anything from an address we did not ask,
    // which is the cheapest half of not answering to a stranger.
    socket
        .connect(resolved)
        .map_err(|e| SourceError::Transport(format!("cannot reach {resolved}: {e}")))?;

    let sent_at = started.elapsed().as_nanos();
    socket
        .send(request)
        .map_err(|e| SourceError::Transport(format!("the request did not go out: {e}")))?;
    let mut buffer = vec![0u8; MAX_REPLY];
    let n = socket.recv(&mut buffer).map_err(|_| SourceError::Timeout)?;
    let received_at = started.elapsed().as_nanos();
    buffer.truncate(n);
    Ok((buffer, sent_at, received_at))
}

/// The request a client sends, with `challenge` in the transmit timestamp field.
///
/// Version four, mode three, and every other field left at zero. A client has nothing true to say
/// about the time and the standard does not ask it to: the server reads the transmit timestamp,
/// copies it into the origin field of the reply, and uses nothing else in the packet.
#[must_use]
pub(crate) fn build_request(challenge: [u8; 8]) -> [u8; PACKET] {
    let mut packet = [0u8; PACKET];
    // Leap indicator nought, version four, mode three, which is a client asking a server.
    packet[0] = 0b0010_0011;
    packet[40..48].copy_from_slice(&challenge);
    packet
}

/// What a reply says, once it has been checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reply {
    /// When the server says it received the request.
    pub(crate) receive: UnixNanos,
    /// When the server says it sent the reply.
    pub(crate) transmit: UnixNanos,
    /// The server's own total delay back to its reference, in nanoseconds.
    pub(crate) root_delay: Nanos,
    /// The server's own accumulated dispersion back to its reference, in nanoseconds.
    pub(crate) root_dispersion: Nanos,
    /// What the server last said about an upcoming leap second.
    pub(crate) leap: LeapIndicator,
}

/// Check a reply against the request that provoked it, and read what it says.
///
/// Separate from the socket so the checks can be driven by a test with bytes rather than by a
/// server that has to be having a bad day at the right moment.
pub(crate) fn read_reply(reply: &[u8], challenge: [u8; 8]) -> Result<Reply, SourceError> {
    if reply.len() < PACKET {
        return Err(SourceError::Malformed(format!(
            "a reply of {} bytes, and an NTP header is {PACKET}",
            reply.len()
        )));
    }

    // The origin field is the eight bytes this client sent. A reply that does not carry them back
    // is an answer to something else, and using it would be taking the time from whoever got a
    // packet in first.
    if reply[24..32] != challenge {
        return Err(SourceError::Malformed(
            "the reply does not carry back the bytes this client sent, so it answers a different \
             request"
                .to_string(),
        ));
    }

    read_header(reply)
}

/// Read a reply's header, without asking what provoked it.
///
/// Split out of [`read_reply`] for the NTS client, and the split is a real difference rather than a
/// tidy-up. Plain NTP has nothing but the origin timestamp to tie a reply to a request, so that
/// check is the only thing standing between this machine's clock and whoever answers first. An NTS
/// reply carries a unique identifier this client chose and a message authentication code over the
/// whole packet, both of which say the same thing and say it against an attacker who can write
/// packets rather than only against one who cannot guess eight bytes. So the NTS client checks
/// those and does not require the origin echo, which several servers do not send.
pub(crate) fn read_header(reply: &[u8]) -> Result<Reply, SourceError> {
    if reply.len() < PACKET {
        return Err(SourceError::Malformed(format!(
            "a reply of {} bytes, and an NTP header is {PACKET}",
            reply.len()
        )));
    }

    let leap_bits = reply[0] >> 6;
    let version = (reply[0] >> 3) & 0b111;
    let mode = reply[0] & 0b111;

    // Mode four is a server answering a client. Anything else is a packet that was not addressed to
    // this exchange, including mode five, which is a broadcast nobody here asked for.
    if mode != 4 {
        return Err(SourceError::Malformed(format!(
            "mode {mode}, and only a server's answer is mode 4"
        )));
    }
    if version != 3 && version != 4 {
        return Err(SourceError::Malformed(format!(
            "version {version}, and this client speaks 3 and 4"
        )));
    }

    let leap = match leap_bits {
        1 => LeapIndicator::AddSecond,
        2 => LeapIndicator::DeleteSecond,
        3 => return Err(SourceError::Unsynchronised),
        _ => LeapIndicator::None,
    };

    // Stratum zero is a kiss-o'-death packet: the four bytes where a reference identifier belongs
    // hold a reason instead, and there is no time in it at all. Past fifteen is unsynchronised by
    // the standard's own reckoning.
    let stratum = reply[1];
    if stratum == 0 || stratum > 15 {
        return Err(SourceError::Unsynchronised);
    }

    let receive = timestamp_at(reply, 32);
    let transmit = timestamp_at(reply, 40);
    if raw_timestamp_at(reply, 40) == 0 {
        return Err(SourceError::Malformed(
            "a transmit timestamp of zero, which is a server saying it has no time to give"
                .to_string(),
        ));
    }

    Ok(Reply {
        receive,
        transmit,
        root_delay: short_format_nanos(u32::from_be_bytes([
            reply[4], reply[5], reply[6], reply[7],
        ])),
        root_dispersion: short_format_nanos(u32::from_be_bytes([
            reply[8], reply[9], reply[10], reply[11],
        ])),
        leap,
    })
}

/// The raw sixty-four bit timestamp at `at`.
fn raw_timestamp_at(reply: &[u8], at: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&reply[at..at + 8]);
    u64::from_be_bytes(bytes)
}

/// One NTP timestamp, read as Unix nanoseconds.
///
/// Thirty-two bits of seconds since 1900 and thirty-two bits of fraction. The fraction is scaled by
/// multiplying before shifting, so nothing is lost to integer division: the resolution of the
/// bottom bit is about two hundred and thirty picoseconds and it survives into the answer.
fn timestamp_at(reply: &[u8], at: usize) -> UnixNanos {
    let raw = raw_timestamp_at(reply, at);
    let seconds = i128::from(raw >> 32);
    let fraction = u128::from(raw & 0xffff_ffff);

    let unix_seconds = if seconds >= NTP_TO_UNIX {
        seconds - NTP_TO_UNIX
    } else {
        seconds + NTP_ERA_ONE_TO_UNIX
    };
    let nanos = i128::try_from((fraction * 1_000_000_000) >> 32).unwrap_or(0);
    UnixNanos(unix_seconds * 1_000_000_000 + nanos)
}

/// A root delay or a root dispersion, read as nanoseconds.
///
/// The short format is sixteen bits of seconds and sixteen bits of fraction, so the bottom bit is
/// about fifteen microseconds.
fn short_format_nanos(raw: u32) -> Nanos {
    let nanos = (u128::from(raw) * 1_000_000_000) >> 16;
    Nanos::try_from(nanos).unwrap_or(Nanos::MAX)
}

impl TimeSource for NtpClient {
    fn id(&self) -> &SourceId {
        &self.id
    }

    fn operator(&self) -> &Operator {
        &self.server.operator
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Ntp
    }

    fn poll(&mut self, now: MonotonicNanos, nonce: &[u8]) -> Result<Exchange, SourceError> {
        let challenge: [u8; 8] = nonce
            .get(..8)
            .and_then(|head| head.try_into().ok())
            .ok_or_else(|| {
                SourceError::Malformed(format!(
                    "a nonce of {} bytes, and the challenge in an NTP request is 8",
                    nonce.len()
                ))
            })?;

        let request = build_request(challenge);
        let (reply, sent_at, received_at) = self.exchange_bytes(&request)?;
        let checked = read_reply(&reply, challenge)?;

        Ok(Exchange {
            source: self.id.clone(),
            operator: self.server.operator.clone(),
            kind: SourceKind::Ntp,
            t2: checked.receive,
            t3: checked.transmit,
            mono_t1: now.advanced(i128::try_from(sent_at).unwrap_or(i128::MAX)),
            mono_t4: now.advanced(i128::try_from(received_at).unwrap_or(i128::MAX)),
            root_delay: checked.root_delay,
            root_dispersion: checked.root_dispersion,
            // NTP answers on UTC by definition, and that is the one thing about the timescale a
            // packet does say.
            timescale: Timescale::Utc,
            // And this is the thing it does not say. There is no field in an NTP packet for what a
            // server does with a leap second, and several large operators smear one while several
            // others step it. Reading an operator's blog post and writing the answer in here would
            // be a claim about a machine from a document, so the honest value is that we were not
            // told. The model treats unknown as conflicting with everything, which is the safe
            // direction: near a leap event it refuses rather than blending a smeared source with a
            // stepped one.
            smear: SmearPolicy::Unknown,
            leap: checked.leap,
            // Never third-party evidence, in one field. Nothing an NTP server says is signed,
            // so nothing here can ever be shown to a stranger as evidence of anything.
            attestation: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes of a plausible server reply, which the tests then damage one field at a time.
    fn a_reply(challenge: [u8; 8]) -> Vec<u8> {
        let mut reply = vec![0u8; PACKET];
        // Leap nought, version four, mode four.
        reply[0] = 0b0010_0100;
        reply[1] = 2; // stratum
        reply[2] = 6; // poll
        reply[3] = 0xe9; // precision, about two nanoseconds
        reply[4..8].copy_from_slice(&0x0000_2000u32.to_be_bytes()); // root delay, 0.125 s
        reply[8..12].copy_from_slice(&0x0000_0800u32.to_be_bytes()); // root dispersion, 0.03125 s
        reply[12..16].copy_from_slice(b"GPS\0");
        reply[24..32].copy_from_slice(&challenge);
        // Receive and transmit, a millisecond apart, on 2026-09-09.
        let receive: u64 = ((2_208_988_800 + 1_788_000_000) << 32) | 0x4000_0000;
        let transmit: u64 = receive + (1u64 << 32) / 1_000;
        reply[32..40].copy_from_slice(&receive.to_be_bytes());
        reply[40..48].copy_from_slice(&transmit.to_be_bytes());
        reply
    }

    #[test]
    fn a_request_says_client_version_four_and_nothing_about_this_machine() {
        let challenge = [9u8; 8];
        let request = build_request(challenge);
        assert_eq!(request[0], 0b0010_0011);
        assert_eq!(request[40..48], challenge);
        // Every other byte is zero, which is the point: a request that carried this machine's idea
        // of the time would be telling everybody on the path what this clock reads.
        assert!(request[1..40].iter().all(|b| *b == 0));
    }

    #[test]
    fn a_good_reply_is_read_into_the_two_timestamps_and_the_two_uncertainties() {
        let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        let read = read_reply(&a_reply(challenge), challenge).expect("a plausible reply");

        assert_eq!(read.receive.as_nanos(), 1_788_000_000_250_000_000);
        assert_eq!(read.transmit.as_nanos() - read.receive.as_nanos(), 999_999);
        // 0x2000 of sixty-five thousand five hundred and thirty-six is an eighth of a second.
        assert_eq!(read.root_delay, 125_000_000);
        assert_eq!(read.root_dispersion, 31_250_000);
        assert_eq!(read.leap, LeapIndicator::None);
    }

    #[test]
    fn a_reply_that_does_not_carry_back_the_challenge_is_refused() {
        // The one check that stops somebody who is faster than the server from setting this
        // machine's clock. Without it, the first packet through the door wins.
        let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut reply = a_reply(challenge);
        reply[31] ^= 0x01;
        let refused = read_reply(&reply, challenge).expect_err("a reply to somebody else");
        assert!(
            matches!(refused, SourceError::Malformed(ref d) if d.contains("different request")),
            "{refused:?}"
        );
    }

    #[test]
    fn a_server_that_says_it_is_not_synchronised_is_not_a_weaker_source() {
        // It is not a source at all. The alternative, treating it as a source with a wide interval,
        // would put a clock nobody is steering into the arithmetic.
        let challenge = [1u8; 8];
        let mut reply = a_reply(challenge);
        reply[0] |= 0b1100_0000;
        assert_eq!(
            read_reply(&reply, challenge).expect_err("an unsynchronised server"),
            SourceError::Unsynchronised
        );
    }

    #[test]
    fn a_kiss_of_death_is_not_a_time() {
        let challenge = [1u8; 8];
        let mut reply = a_reply(challenge);
        reply[1] = 0;
        reply[12..16].copy_from_slice(b"RATE");
        assert_eq!(
            read_reply(&reply, challenge).expect_err("a kiss-o'-death"),
            SourceError::Unsynchronised
        );

        let mut too_far = a_reply(challenge);
        too_far[1] = 16;
        assert_eq!(
            read_reply(&too_far, challenge).expect_err("a stratum past the end of the scale"),
            SourceError::Unsynchronised
        );
    }

    #[test]
    fn a_reply_from_the_wrong_mode_or_a_short_one_is_refused() {
        let challenge = [1u8; 8];
        let mut broadcast = a_reply(challenge);
        broadcast[0] = 0b0010_0101;
        assert!(matches!(
            read_reply(&broadcast, challenge),
            Err(SourceError::Malformed(_))
        ));

        let short = a_reply(challenge)[..40].to_vec();
        assert!(matches!(
            read_reply(&short, challenge),
            Err(SourceError::Malformed(_))
        ));
    }

    #[test]
    fn a_leap_announcement_is_carried_rather_than_flattened() {
        let challenge = [1u8; 8];
        let mut adding = a_reply(challenge);
        adding[0] = 0b0110_0100;
        assert_eq!(
            read_reply(&adding, challenge).unwrap().leap,
            LeapIndicator::AddSecond
        );

        let mut deleting = a_reply(challenge);
        deleting[0] = 0b1010_0100;
        assert_eq!(
            read_reply(&deleting, challenge).unwrap().leap,
            LeapIndicator::DeleteSecond
        );
    }

    #[test]
    fn the_wrap_of_2036_is_read_as_the_era_after_it_and_not_as_1900() {
        // Ten seconds past the wrap. Read naively this is 1900-01-01, which is a hundred and
        // twenty-six years of error in a product whose whole claim is an interval.
        let mut reply = a_reply([1u8; 8]);
        let after_the_wrap: u64 = 10u64 << 32;
        reply[32..40].copy_from_slice(&after_the_wrap.to_be_bytes());
        reply[40..48].copy_from_slice(&after_the_wrap.to_be_bytes());
        let read = read_reply(&reply, [1u8; 8]).expect("a reply from after the wrap");

        // 2036-02-07T06:28:26Z, which is the wrap, plus the ten seconds.
        assert_eq!(read.receive.as_nanos(), 2_085_978_506_000_000_000);
    }

    #[test]
    fn a_stated_uncertainty_is_the_dispersion_plus_half_the_delay() {
        // The same arithmetic every source is held to, checked once here because this is the first
        // source that states a delay at all. Roughtime states a radius and no delay.
        let challenge = [1u8; 8];
        let read = read_reply(&a_reply(challenge), challenge).unwrap();
        let exchange = Exchange {
            source: SourceId::new("ntp:test"),
            operator: Operator::new("test"),
            kind: SourceKind::Ntp,
            t2: read.receive,
            t3: read.transmit,
            mono_t1: MonotonicNanos(0),
            mono_t4: MonotonicNanos(1_000_000),
            root_delay: read.root_delay,
            root_dispersion: read.root_dispersion,
            timescale: Timescale::Utc,
            smear: SmearPolicy::Unknown,
            leap: read.leap,
            attestation: None,
        };
        assert_eq!(exchange.stated_uncertainty(), 31_250_000 + 125_000_000 / 2);
    }

    #[test]
    fn the_published_servers_are_three_operators_and_not_three_names() {
        // A majority made of three addresses at one company is one source wearing three coats.
        let published = NtpServer::published();
        assert_eq!(published.len(), 3);
        let mut operators: Vec<&str> = published.iter().map(|s| s.name.as_str()).collect();
        operators.sort_unstable();
        operators.dedup();
        assert_eq!(operators.len(), 3);
    }

    #[test]
    fn an_ntp_source_can_never_be_evidence() {
        // Stated here as well as in the core crate, because this is the file somebody adding a
        // second unauthenticated source would copy.
        assert!(!SourceKind::Ntp.carries_third_party_signature());
    }
}
