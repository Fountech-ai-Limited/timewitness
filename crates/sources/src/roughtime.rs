//! The Roughtime client: the socket, and nothing else.
//!
//! Every rule about what a Roughtime response has to satisfy lives in
//! [`timewitness_core::evidence::roughtime`], because a verifier that has never spoken to us has to
//! apply the same rules to the same bytes years later. This file puts a packet on a socket, takes
//! two counter marks around the wait, and hands the bytes to that check before anything from them
//! is allowed near the clock model.
//!
//! Nothing here decides anything. If the check refuses, the poll fails and no sample is produced;
//! there is no path by which an unverified response becomes a weaker sample rather than no sample.
//! That is the difference between a source that improves a clock and a source that is evidence, and
//! it is why this client is short.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use timewitness_core::evidence::roughtime;
use timewitness_core::evidence::roughtime::published_keys;
use timewitness_core::{
    Attestation, LeapIndicator, MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind,
    Timescale, UnixNanos,
};

use crate::{Exchange, SourceError, TimeSource};

/// How long to wait for a reply before giving up.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The largest reply this client will read.
///
/// The draft forbids a server from answering with more bytes than it received, and our request is a
/// little over a kilobyte, so anything past this is not a response to us.
const MAX_REPLY: usize = 1536;

/// A Roughtime server, and the key its answers are checked against.
///
/// The key is the whole of the trust here. A server address with no key is a server that can say
/// anything, so the two are one type and there is no way to hold one without the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoughtimeServer {
    /// A name for a person reading a receipt.
    pub name: String,
    /// Host and port.
    pub address: String,
    /// The server's published long-term Ed25519 key.
    pub long_term_public_key: [u8; 32],
    /// Who runs it. Derived from the address unless a deployment states otherwise.
    pub operator: Operator,
}

impl RoughtimeServer {
    /// A server from its parts.
    #[must_use]
    pub fn new(name: impl Into<String>, address: impl Into<String>, key: [u8; 32]) -> Self {
        let address = address.into();
        Self {
            name: name.into(),
            operator: Operator::from_host(&address),
            address,
            long_term_public_key: key,
        }
    }

    /// The same server with its operator stated rather than derived.
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

    /// The public servers this client has been proved against, with their published keys.
    ///
    /// The keys are [`timewitness_core::evidence::roughtime::published_keys`], because a verifier
    /// that may not import this crate needs the same ones and two copies of a key is one copy that
    /// can go stale. What is added here is the address, which is a fact about reaching a server
    /// rather than about trusting one.
    ///
    /// This is a starting list and not a trust store. A deployment picks its own servers, and
    /// running two of our own is planned.
    #[must_use]
    pub fn published() -> Vec<RoughtimeServer> {
        published_keys()
            .into_iter()
            .map(|key| {
                let server = RoughtimeServer::new(
                    key.name,
                    format!("{}:2002", key.name),
                    key.long_term_public_key,
                );
                // `roughtime.se` and `nts.netnod.se` share no domain, and the derivation therefore
                // reads them as two operators. Read on this machine on 2026-09-09 with `nslookup`:
                // `roughtime.se` answers on 192.36.143.134, and Netnod's own public time service
                // answers across 192.36.133.195, 192.71.80.206 and 194.58.207.75, which is the
                // neighbouring block of the same Swedish allocation. That is a reason to suspect one
                // operator and it is not a citation, so it does not settle the question.
                //
                // It is merged anyway, and the asymmetry is the reason. Merging two operators that
                // are really separate lowers the count and can only refuse a round. Splitting one
                // operator into two raises the count and inflates the very floor that is supposed to
                // catch it, silently. Where independence is in doubt, the doubt is resolved against
                // the count.
                if server.name == "roughtime.se" {
                    server.operated_by("netnod.se")
                } else {
                    server
                }
            })
            .collect()
    }
}

/// Which transport to use.
///
/// UDP is what every public server answers on. TCP exists in the draft for paths that will not
/// carry a kilobyte datagram, and one of the three servers proved on 2026-09-07 answered on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Transport {
    /// One datagram out, one back.
    #[default]
    Udp,
    /// A stream, for a path that will not carry the datagram.
    Tcp,
}

/// A client for one Roughtime server.
#[derive(Clone, Debug)]
pub struct RoughtimeClient {
    server: RoughtimeServer,
    id: SourceId,
    transport: Transport,
    timeout: Duration,
}

impl RoughtimeClient {
    /// A client for a server, over UDP, with the default timeout.
    #[must_use]
    pub fn new(server: RoughtimeServer) -> Self {
        let id = SourceId::new(server.name.clone());
        Self {
            server,
            id,
            transport: Transport::Udp,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same client over a different transport.
    #[must_use]
    pub fn over(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// The same client with a different deadline.
    #[must_use]
    pub fn waiting(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Which server this client asks.
    #[must_use]
    pub fn server(&self) -> &RoughtimeServer {
        &self.server
    }

    /// Send a request and read the reply, with no checking of any kind.
    ///
    /// Returns the reply and the two elapsed times, measured from one instant taken on entry: the
    /// first is how long the setup took before the packet went out, the second is when the reply
    /// was in hand. The caller turns those into the two ends of the round trip against its own
    /// anchor, which is the only clock allowed in that arithmetic.
    fn exchange_bytes(&self, request: &[u8]) -> Result<(Vec<u8>, u128, u128), SourceError> {
        let started = Instant::now();
        let address = self
            .server
            .address
            .to_socket_addrs()
            .map_err(|e| {
                SourceError::Transport(format!("{} does not resolve: {e}", self.server.address))
            })?
            .next()
            .ok_or_else(|| {
                SourceError::Transport(format!("{} resolves to nothing", self.server.address))
            })?;

        match self.transport {
            Transport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .map_err(|e| SourceError::Transport(format!("no local socket: {e}")))?;
                socket.set_read_timeout(Some(self.timeout)).map_err(|e| {
                    SourceError::Transport(format!("no deadline on the socket: {e}"))
                })?;
                // Connecting a datagram socket makes the kernel drop anything from an address we
                // did not ask, which is the cheapest half of not answering to a stranger.
                socket
                    .connect(address)
                    .map_err(|e| SourceError::Transport(format!("cannot reach {address}: {e}")))?;

                let sent_at = started.elapsed().as_nanos();
                socket.send(request).map_err(|e| {
                    SourceError::Transport(format!("the request did not go out: {e}"))
                })?;
                let mut buffer = vec![0u8; MAX_REPLY];
                let n = socket.recv(&mut buffer).map_err(|_| SourceError::Timeout)?;
                let received_at = started.elapsed().as_nanos();
                buffer.truncate(n);
                Ok((buffer, sent_at, received_at))
            }
            Transport::Tcp => {
                let mut stream = TcpStream::connect_timeout(&address, self.timeout)
                    .map_err(|e| SourceError::Transport(format!("cannot reach {address}: {e}")))?;
                stream.set_read_timeout(Some(self.timeout)).map_err(|e| {
                    SourceError::Transport(format!("no deadline on the stream: {e}"))
                })?;

                let sent_at = started.elapsed().as_nanos();
                stream.write_all(request).map_err(|e| {
                    SourceError::Transport(format!("the request did not go out: {e}"))
                })?;

                // The framing gives the length in the first twelve bytes, so read those, then read
                // exactly what they say and no more.
                let mut header = [0u8; 12];
                stream
                    .read_exact(&mut header)
                    .map_err(|_| SourceError::Timeout)?;
                let length =
                    u32::from_le_bytes([header[8], header[9], header[10], header[11]]) as usize;
                if length > MAX_REPLY {
                    return Err(SourceError::Malformed(format!(
                        "a reply claiming {length} bytes, which is more than the request that \
                         provoked it"
                    )));
                }
                let mut body = vec![0u8; length];
                stream
                    .read_exact(&mut body)
                    .map_err(|_| SourceError::Timeout)?;
                let received_at = started.elapsed().as_nanos();

                let mut reply = header.to_vec();
                reply.extend_from_slice(&body);
                Ok((reply, sent_at, received_at))
            }
        }
    }

    /// Ask the server, verify what comes back, and return the exchange and the stored blob.
    ///
    /// `binding` is what the nonce was derived from, or empty where the nonce was random. It is
    /// carried into the blob so a verifier can recompute the derivation.
    pub fn poll_bound(
        &self,
        now: MonotonicNanos,
        nonce: &[u8; 32],
        binding: &[u8],
    ) -> Result<Exchange, SourceError> {
        let request = roughtime::build_request(nonce, &self.server.long_term_public_key);
        let (reply, sent_at, received_at) = self.exchange_bytes(&request)?;

        let blob = roughtime::pack_blob(binding, &request, &reply);
        let checked = roughtime::check(&blob, &self.server.long_term_public_key, &self.server.name)
            .map_err(|e| SourceError::Malformed(e.to_string()))?;

        // Roughtime states one instant, the moment of processing, so the two the server contributes
        // to the four-timestamp exchange are the same value. The round trip the model computes from
        // that is the whole wait, which is right: nothing in the protocol separates the server's own
        // processing time out of it, so none of it may be discounted.
        let stated = checked.midpoint();
        let radius = checked.radius();

        Ok(Exchange {
            source: self.id.clone(),
            operator: self.server.operator.clone(),
            kind: SourceKind::Roughtime,
            t2: stated,
            t3: stated,
            mono_t1: now.advanced(i128::try_from(sent_at).unwrap_or(i128::MAX)),
            mono_t4: now.advanced(i128::try_from(received_at).unwrap_or(i128::MAX)),
            // Roughtime publishes no root delay. The radius is the server's whole statement about
            // its own uncertainty, so it goes in as dispersion, which the model adds in full rather
            // than halving. A one second radius therefore produces a one second interval and takes
            // almost no weight in the inverse-square combination, which is the honest outcome: this
            // source authenticates the bound and does not tighten it.
            root_delay: 0,
            root_dispersion: radius,
            timescale: Timescale::Utc,
            // The draft's timestamp assumes every day has 86400 seconds, so a leap second has no
            // unambiguous representation in it. That is not a smear and it is not a step, and
            // saying either would be a guess.
            smear: SmearPolicy::Unknown,
            leap: LeapIndicator::None,
            attestation: Some(Attestation::over_interval(
                nonce.to_vec(),
                blob,
                stated,
                radius,
            )),
        })
    }

    /// Ask the server for evidence about one particular thing.
    ///
    /// This is the call the agent makes when it is stamping. The nonce is derived from the hash of
    /// what is being stamped and a fresh salt, so the response is tied to this subject and could
    /// not have been fetched in advance by anybody who knew what was coming. The binding travels in
    /// the blob, so a verifier recomputes the derivation instead of taking our word for it.
    ///
    /// The salt comes from the operating system. A nonce that is only the subject hash is
    /// predictable to whoever knows what is about to be stamped, and a predictable nonce can be
    /// asked for early, which would let a response be older than the moment it is offered as
    /// evidence for.
    pub fn poll_for_subject(
        &self,
        now: MonotonicNanos,
        subject_hash: &[u8],
    ) -> Result<Exchange, SourceError> {
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).map_err(|e| {
            SourceError::Transport(format!("this machine would not give us random bytes: {e}"))
        })?;
        let mut binding = Vec::with_capacity(subject_hash.len() + 32);
        binding.extend_from_slice(subject_hash);
        binding.extend_from_slice(&salt);
        let nonce = roughtime::bind_nonce(&binding);
        self.poll_bound(now, &nonce, &binding)
    }

    /// A nonce with nothing behind it but the machine's own randomness.
    ///
    /// For disciplining the clock, where there is no subject yet and the nonce's only job is to
    /// stop a reply being one the server prepared earlier.
    pub fn random_nonce() -> Result<[u8; 32], SourceError> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|e| {
            SourceError::Transport(format!("this machine would not give us random bytes: {e}"))
        })?;
        Ok(nonce)
    }

    /// What was checked, in words, for a caller that wants to report it.
    ///
    /// Takes the blob rather than doing a round trip, so this is the same call a verifier makes.
    pub fn describe(&self, blob: &[u8]) -> Result<Vec<String>, SourceError> {
        roughtime::check(blob, &self.server.long_term_public_key, &self.server.name)
            .map(|c| c.checks)
            .map_err(|e| SourceError::Malformed(e.to_string()))
    }
}

impl TimeSource for RoughtimeClient {
    fn id(&self) -> &SourceId {
        &self.id
    }

    fn operator(&self) -> &Operator {
        &self.server.operator
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Roughtime
    }

    fn poll(&mut self, now: MonotonicNanos, nonce: &[u8]) -> Result<Exchange, SourceError> {
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| {
            SourceError::Malformed(format!(
                "a nonce of {} bytes, and this protocol signs over 32",
                nonce.len()
            ))
        })?;
        self.poll_bound(now, &nonce, &[])
    }
}

/// The instant a Unix timestamp in whole seconds sits at, for a caller reading a response by hand.
#[must_use]
pub fn seconds_to_unix_nanos(seconds: u64) -> UnixNanos {
    UnixNanos(i128::from(seconds) * timewitness_core::time::NANOS_PER_SEC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_of_the_wrong_length_is_refused_before_a_packet_goes_out() {
        let mut client =
            RoughtimeClient::new(RoughtimeServer::new("nowhere", "127.0.0.1:1", [0u8; 32]));
        let err = client
            .poll(MonotonicNanos(0), b"too short")
            .expect_err("a nine byte nonce is not a Roughtime nonce");
        assert!(matches!(err, SourceError::Malformed(_)));
    }

    #[test]
    fn every_published_server_has_a_key_and_a_port() {
        for server in RoughtimeServer::published() {
            assert!(server.address.contains(':'), "{} has no port", server.name);
            assert_ne!(
                server.long_term_public_key, [0u8; 32],
                "{} has no key",
                server.name
            );
        }
    }
}
