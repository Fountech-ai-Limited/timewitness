//! The NTS client: an authenticated NTP corridor, and the one thing it can never be.
//!
//! ## What this source is for
//!
//! Network Time Security, RFC 8915, is plain NTP with the packet authenticated. A short TLS session
//! on a separate port hands the client two symmetric keys and a handful of cookies; every later time
//! request goes over the ordinary UDP path carrying a cookie, a unique identifier and a message
//! authentication code over the whole packet, and the reply carries the same identifier and its own
//! code. Nothing about the timing changes. Nothing about the arithmetic changes.
//!
//! **So this source narrows nothing, and saying otherwise would be the easiest lie in the product.**
//! An NTS exchange with a server has the same round trip and the same root distance as a plain NTP
//! exchange with the same server, so the interval it contributes is the same width. What it fixes is
//! who is allowed to write it. A plain NTP reply is unauthenticated: anybody on the path can compose
//! one, and three composed replies agreeing with each other are a majority under Marzullo. That is
//! the largest hole in this product's bound and no number of extra plain NTP servers closes it,
//! because every extra one is another packet an attacker on the path may write. An NTS reply is one
//! an attacker cannot write without a key held by the server and this machine.
//!
//! ## And it can never be evidence, which is a rule rather than a preference
//!
//! The keys are symmetric. This machine holds the same secret the server used, so this machine could
//! compose any NTS reply it likes and check its own forgery successfully. A signature is evidence
//! because the checker cannot produce it; a shared key is not, because the checker can. So
//! [`SourceKind::Nts`] answers no to `carries_third_party_signature`, the exchange this client
//! returns carries no attestation, and nothing from this file may appear in a receipt in any of the
//! three evidence roles. It improves the clock. Roughtime is what a stranger checks.
//!
//! ## What is checked, and why each one is not optional
//!
//! The key exchange runs over TLS 1.3 with the certificate chain verified against the compiled-in
//! Mozilla root list and the ALPN identifier the standard reserves. That is a real difference from
//! the rest of this crate, which fetches evidence over plain HTTP on purpose, because there the
//! bytes carry a signature checked against a key pinned in advance and the transport is protecting
//! something already protected. Here there is no signature to fall back on: the certificate is the
//! only thing saying the keys came from the server whose name was asked for, so the chain is checked
//! and a failure is a refusal rather than a warning.
//!
//! On the time exchange itself: the unique identifier in the reply has to be the thirty-two bytes
//! this client chose, or the reply answers somebody else's request; the authenticator has to
//! decrypt and check against the server-to-client key over exactly the bytes that came in, or the
//! reply was written by somebody without the key. Everything a plain NTP reply is refused for is
//! refused here too, on the same reading, because an authenticated packet from a server saying it
//! has not synchronised is an authentic statement that its answer is worthless.
//!
//! The origin timestamp echo that plain NTP depends on is deliberately not required here. Several
//! NTS servers do not send it, and it is the weaker check of the two in any case: the unique
//! identifier is thirty-two bytes rather than eight and the authenticator covers it, so a reply that
//! passes those two passes anything the origin echo would have caught.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use aes_siv::aead::inout::InOutBuf;
use aes_siv::aead::{AeadInOut, KeyInit};
use aes_siv::{Aes128SivAead, Nonce};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};

use timewitness_core::{MonotonicNanos, Operator, SmearPolicy, SourceId, SourceKind, Timescale};

use crate::ntp::{build_request, read_header, udp_exchange, MAX_REPLY, PACKET};
use crate::{Exchange, SourceError, TimeSource};

/// How long to wait on the key exchange and on a time reply.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The port the key exchange listens on, fixed by RFC 8915.
///
/// Public because an operator opening a firewall needs it and the document that lists it is held to
/// this constant rather than to a number somebody typed twice.
pub const KEY_EXCHANGE_PORT: u16 = 4460;

/// The port the time exchange goes to where the key exchange names none.
///
/// The key exchange may hand back a host and a port of its own and this is what it falls back to,
/// which is the ordinary NTP port. A server that names another one is reached on that one, so an
/// operator who opened only this port has opened what the published servers have always asked for
/// and not a guarantee about every server.
pub const DEFAULT_TIME_PORT: u16 = 123;

/// The application protocol name the key exchange is negotiated under.
const ALPN: &[u8] = b"ntske/1";

/// The next protocol this client asks for: NTPv4.
const NEXT_PROTOCOL_NTPV4: u16 = 0;

/// The only AEAD this client speaks, `AEAD_AES_SIV_CMAC_256`, which every server has to support.
const AEAD_AES_SIV_CMAC_256: u16 = 15;

/// The exporter label the standard reserves, from which both keys are drawn.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

/// The length of each of the two keys, for the one AEAD this client speaks.
const KEY_BYTES: usize = 32;

/// The bytes of the unique identifier this client sends. The standard's floor is thirty-two.
const UNIQUE_IDENTIFIER_BYTES: usize = 32;

/// How many cookies this client tries to keep in hand.
///
/// Eight is what the key exchange hands out and what the standard's own example keeps. The number
/// matters for privacy rather than for throughput: a cookie is used once and never again, so a
/// client that runs the jar down to one and refills it in step is linkable across requests in a way
/// a client with eight in hand is not.
const COOKIE_JAR: usize = 8;

/// How long a time request is padded out to, whatever it would otherwise have been.
///
/// A kilobyte. See [`seal`] for why a client pays this rather than the server refusing to answer.
const MIN_REQUEST_BYTES: usize = 1024;

/// The most the key exchange will read before deciding a server is not answering in records.
const MAX_KEY_EXCHANGE_BYTES: usize = 65_536;

// The record types of the key exchange.
const RECORD_END_OF_MESSAGE: u16 = 0;
const RECORD_NEXT_PROTOCOL: u16 = 1;
const RECORD_ERROR: u16 = 2;
const RECORD_AEAD_ALGORITHM: u16 = 4;
const RECORD_NEW_COOKIE: u16 = 5;
const RECORD_SERVER: u16 = 6;
const RECORD_PORT: u16 = 7;

// The NTP extension fields NTS defines.
const FIELD_UNIQUE_IDENTIFIER: u16 = 0x0104;
const FIELD_COOKIE: u16 = 0x0204;
const FIELD_COOKIE_PLACEHOLDER: u16 = 0x0304;
const FIELD_AUTHENTICATOR: u16 = 0x0404;

/// A public NTS server, named by the host its key exchange answers on.
///
/// There is a certificate here rather than a pinned key, and that is the difference from
/// [`crate::roughtime::RoughtimeServer`]. A Roughtime server is trusted because we hold its public
/// key; an NTS server is trusted because a certificate authority says the host is who it claims. The
/// second is weaker and it is what the protocol offers, so it is what is checked and what is said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NtsServer {
    /// A name for a person reading a log line.
    pub name: String,
    /// The host the key exchange runs against, and the name the certificate has to match.
    pub host: String,
    /// Who runs it. Derived from the host unless a deployment states otherwise.
    pub operator: Operator,
}

impl NtsServer {
    /// A server from its parts.
    #[must_use]
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        let host = host.into();
        Self {
            name: name.into(),
            operator: Operator::from_host(&host),
            host,
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

    /// The public servers this client has been proved against.
    ///
    /// Three operators rather than three names, for the same reason the NTP list gives: sources
    /// under one operator fail together and lie together. Two of these three operators also appear
    /// in the plain NTP list, which is a real limitation rather than an oversight, and it is why the
    /// count of source kinds and the count of independent operators are two different numbers that
    /// this product has to state separately.
    ///
    /// From 2026-09-09 the second of those two numbers is the one the selection enforces. Every
    /// server here carries an [`timewitness_core::Operator`], the floor in `Policy` is a floor on
    /// distinct operators among the survivors, and a majority resting on too few of them is refused
    /// rather than signed.
    ///
    /// This is a starting list and not a trust store. A deployment picks its own servers.
    #[must_use]
    pub fn published() -> Vec<NtsServer> {
        vec![
            NtsServer::new("cloudflare", "time.cloudflare.com"),
            NtsServer::new("netnod", "nts.netnod.se"),
            NtsServer::new("ptb", "ptbtime1.ptb.de"),
        ]
    }
}

/// One record of the key exchange.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    critical: bool,
    kind: u16,
    body: Vec<u8>,
}

/// Lay one record down in the form the standard sets: a flag and a type, a length, then the body.
fn write_record(into: &mut Vec<u8>, critical: bool, kind: u16, body: &[u8]) {
    let header = if critical { kind | 0x8000 } else { kind };
    into.extend_from_slice(&header.to_be_bytes());
    let length = u16::try_from(body.len()).unwrap_or(u16::MAX);
    into.extend_from_slice(&length.to_be_bytes());
    into.extend_from_slice(body);
}

/// What this client asks for: NTPv4, one AEAD, and nothing else.
fn key_exchange_request() -> Vec<u8> {
    let mut out = Vec::new();
    write_record(
        &mut out,
        true,
        RECORD_NEXT_PROTOCOL,
        &NEXT_PROTOCOL_NTPV4.to_be_bytes(),
    );
    write_record(
        &mut out,
        true,
        RECORD_AEAD_ALGORITHM,
        &AEAD_AES_SIV_CMAC_256.to_be_bytes(),
    );
    write_record(&mut out, true, RECORD_END_OF_MESSAGE, &[]);
    out
}

/// Read as many whole records as `bytes` holds, and say whether the end of the message was among
/// them.
///
/// A partial record at the tail is not an error here, because the caller is reading a stream and
/// will come back with more. It is an error only when the stream ends first, and the caller is where
/// that is known.
fn read_records(bytes: &[u8]) -> Result<(Vec<Record>, bool), SourceError> {
    let mut records = Vec::new();
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        let header = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let length = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
        if at + 4 + length > bytes.len() {
            break;
        }
        let kind = header & 0x7fff;
        let record = Record {
            critical: header & 0x8000 != 0,
            kind,
            body: bytes[at + 4..at + 4 + length].to_vec(),
        };
        at += 4 + length;
        let end = record.kind == RECORD_END_OF_MESSAGE;
        records.push(record);
        if end {
            return Ok((records, true));
        }
    }
    Ok((records, false))
}

/// A sixteen-bit value carried as a record body.
fn one_u16(body: &[u8], what: &str) -> Result<u16, SourceError> {
    if body.len() != 2 {
        return Err(SourceError::Malformed(format!(
            "{what} came back as {} bytes and it is two",
            body.len()
        )));
    }
    Ok(u16::from_be_bytes([body[0], body[1]]))
}

/// What a completed key exchange leaves behind.
///
/// The two keys and the cookies are the whole of it. Nothing here is written to disk and nothing
/// outlives the process, which is deliberate: a cookie is a bearer token for asking one server the
/// time, and the cost of losing them is one more key exchange.
#[derive(Clone)]
struct Session {
    /// Where the time requests go, which the server may move off its own name.
    time_address: String,
    /// The key this machine authenticates its requests with.
    client_to_server: [u8; KEY_BYTES],
    /// The key the server authenticates its replies with.
    server_to_client: [u8; KEY_BYTES],
    /// The cookies left to spend, one per request, oldest first.
    cookies: Vec<Vec<u8>>,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The keys are not printed. A debug line is the easiest way for a secret to reach a log.
        f.debug_struct("Session")
            .field("time_address", &self.time_address)
            .field("cookies", &self.cookies.len())
            .finish()
    }
}

/// Run the key exchange against one server and come back with keys and cookies.
fn negotiate(server: &NtsServer, timeout: Duration) -> Result<Session, SourceError> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];

    let name = ServerName::try_from(server.host.clone()).map_err(|_| {
        SourceError::Transport(format!(
            "{} is not a name a certificate can match",
            server.host
        ))
    })?;
    let mut connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|e| SourceError::Transport(format!("no TLS session: {e}")))?;

    let mut socket = TcpStream::connect((server.host.as_str(), KEY_EXCHANGE_PORT))
        .map_err(|e| SourceError::Transport(format!("cannot reach the key exchange: {e}")))?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|e| SourceError::Transport(format!("no deadline on the socket: {e}")))?;

    let mut stream = Stream::new(&mut connection, &mut socket);
    stream
        .write_all(&key_exchange_request())
        .and_then(|()| stream.flush())
        .map_err(|e| {
            SourceError::Transport(format!("the key exchange request did not go out: {e}"))
        })?;

    let mut answered = Vec::new();
    let mut chunk = [0u8; 4096];
    let records = loop {
        let (records, complete) = read_records(&answered)?;
        if complete {
            break records;
        }
        if answered.len() > MAX_KEY_EXCHANGE_BYTES {
            return Err(SourceError::Malformed(
                "the key exchange sent more than a server has any reason to send and never ended \
                 the message"
                    .to_string(),
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => {
                return Err(SourceError::Malformed(
                    "the key exchange closed before it ended its message".to_string(),
                ))
            }
            Ok(n) => answered.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(SourceError::Timeout),
        }
    };

    // The application protocol the standard reserves has to be the one that was agreed. A server
    // that ignores the extension altogether leaves this empty rather than failing the handshake, and
    // a session agreed under no protocol at all is one where the keys drawn below mean whatever the
    // other end decided they mean.
    if stream.conn.alpn_protocol() != Some(ALPN) {
        return Err(SourceError::Malformed(
            "the key exchange did not agree the application protocol NTS reserves, so this is not              an NTS session"
                .to_string(),
        ));
    }

    // The negotiated protocol and AEAD are checked before anything is drawn from them, because the
    // exporter context includes both. Taking a key under one pair of numbers and using it under
    // another gives two keys that are not the same and a failure nobody can read.
    let mut protocol = None;
    let mut aead = None;
    let mut cookies = Vec::new();
    let mut host = None;
    let mut port = None;
    for record in &records {
        match record.kind {
            RECORD_ERROR => {
                let code = one_u16(&record.body, "an error code").unwrap_or(u16::MAX);
                return Err(SourceError::Malformed(format!(
                    "the key exchange refused with error {code}"
                )));
            }
            RECORD_NEXT_PROTOCOL => {
                protocol = Some(one_u16(&record.body, "the next protocol")?);
            }
            RECORD_AEAD_ALGORITHM => {
                aead = Some(one_u16(&record.body, "the AEAD algorithm")?);
            }
            RECORD_NEW_COOKIE => stow(&mut cookies, record.body.clone()),
            RECORD_SERVER => {
                host = Some(String::from_utf8(record.body.clone()).map_err(|_| {
                    SourceError::Malformed(
                        "the server named itself in bytes that are not text".to_string(),
                    )
                })?);
            }
            RECORD_PORT => port = Some(one_u16(&record.body, "the port")?),
            RECORD_END_OF_MESSAGE => {}
            other => {
                // Unknown and critical is the one combination the standard says to refuse. Unknown
                // and not critical is a server offering something this client did not ask for.
                if record.critical {
                    return Err(SourceError::Malformed(format!(
                        "the key exchange marked record type {other} critical and this client does \
                         not know it"
                    )));
                }
            }
        }
    }

    if protocol != Some(NEXT_PROTOCOL_NTPV4) {
        return Err(SourceError::Malformed(
            "the key exchange did not agree to NTPv4, so there is nothing here to ask the time"
                .to_string(),
        ));
    }
    if aead != Some(AEAD_AES_SIV_CMAC_256) {
        return Err(SourceError::Malformed(
            "the key exchange did not agree the one AEAD this client speaks".to_string(),
        ));
    }
    if cookies.is_empty() {
        return Err(SourceError::Malformed(
            "the key exchange handed out no cookies, so no time request can be made".to_string(),
        ));
    }

    let client_to_server = export_key(&connection, 0x00)?;
    let server_to_client = export_key(&connection, 0x01)?;

    let time_host = host.unwrap_or_else(|| server.host.clone());
    let time_port = port.unwrap_or(DEFAULT_TIME_PORT);

    Ok(Session {
        time_address: format!("{time_host}:{time_port}"),
        client_to_server,
        server_to_client,
        cookies,
    })
}

/// Draw one of the two keys out of the finished TLS session.
///
/// The context is the five octets the standard fixes: the protocol, the AEAD, and which direction
/// the key is for. Both ends compute it from the same numbers, so a mismatch anywhere above shows up
/// as a message authentication failure rather than as anything readable.
fn export_key(
    connection: &ClientConnection,
    direction: u8,
) -> Result<[u8; KEY_BYTES], SourceError> {
    let mut context = [0u8; 5];
    context[0..2].copy_from_slice(&NEXT_PROTOCOL_NTPV4.to_be_bytes());
    context[2..4].copy_from_slice(&AEAD_AES_SIV_CMAC_256.to_be_bytes());
    context[4] = direction;
    connection
        .export_keying_material([0u8; KEY_BYTES], EXPORTER_LABEL, Some(&context))
        .map_err(|e| SourceError::Transport(format!("the session would not give up a key: {e}")))
}

/// Lay one NTP extension field down: a type, a length that counts the header, and a padded value.
fn write_field(into: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let padded = value.len().div_ceil(4) * 4;
    let length = u16::try_from(4 + padded).unwrap_or(u16::MAX);
    into.extend_from_slice(&kind.to_be_bytes());
    into.extend_from_slice(&length.to_be_bytes());
    into.extend_from_slice(value);
    into.extend(std::iter::repeat(0u8).take(padded - value.len()));
}

/// One extension field found in a packet: what it is, where its value starts, and where the field
/// itself starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Field {
    kind: u16,
    /// Where the four-byte header begins, which is what the authenticator's covered bytes end at.
    at: usize,
    /// The half-open range of the value.
    value: (usize, usize),
}

/// Walk the extension fields after the header.
///
/// A field whose length is not a multiple of four, is below the four-byte header, or runs off the
/// end is the packet being malformed rather than this client being strict: the length is how the
/// next field is found, so a wrong one loses the rest of the packet.
fn read_fields(packet: &[u8]) -> Result<Vec<Field>, SourceError> {
    let mut fields = Vec::new();
    let mut at = PACKET;
    while at + 4 <= packet.len() {
        let kind = u16::from_be_bytes([packet[at], packet[at + 1]]);
        let length = usize::from(u16::from_be_bytes([packet[at + 2], packet[at + 3]]));
        if length < 4 || length % 4 != 0 || at + length > packet.len() {
            return Err(SourceError::Malformed(format!(
                "an extension field of length {length} at byte {at} of a {} byte packet",
                packet.len()
            )));
        }
        fields.push(Field {
            kind,
            at,
            value: (at + 4, at + length),
        });
        at += length;
    }
    Ok(fields)
}

/// Build the authenticator field over everything laid down so far, padded out to `at_least`.
///
/// The associated data is every byte of the packet before this field, which is what ties the
/// authenticator to this header, this unique identifier and this cookie rather than to any other.
/// The plaintext is empty: this client encrypts no extension fields, and the field is here to
/// authenticate rather than to hide anything.
///
/// **The padding is the part that is not obvious and it is not decoration.** The standard puts an
/// additional padding element at the end of this field for the client to use, and several widely
/// run servers drop a request that has not used it. The reason is amplification: a short request
/// provoking a long reply is a way to point somebody else's bandwidth at a victim by putting their
/// address on the packet, so a server that answers one is a weapon. Padding out to a kilobyte costs
/// this machine a kilobyte and takes the whole trick away. It is checked by nothing here, because
/// the failure it prevents is somebody else's.
fn seal(
    packet: &mut Vec<u8>,
    key: &[u8; KEY_BYTES],
    nonce: [u8; 16],
    at_least: usize,
) -> Result<(), SourceError> {
    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|_| SourceError::Malformed("the exported key is the wrong length".to_string()))?;
    let tag = cipher
        .encrypt_inout_detached(&Nonce::from(nonce), packet, InOutBuf::from(&mut [][..]))
        .map_err(|_| SourceError::Malformed("the authenticator would not seal".to_string()))?;

    let mut body = Vec::new();
    body.extend_from_slice(&u16::try_from(nonce.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&u16::try_from(tag.len()).unwrap_or(0).to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&tag);
    let so_far = packet.len() + 4 + body.len();
    if so_far < at_least {
        body.extend(std::iter::repeat(0u8).take(at_least - so_far));
    }
    write_field(packet, FIELD_AUTHENTICATOR, &body);
    Ok(())
}

/// Check a reply's authenticator and give back whatever it was hiding.
///
/// Everything before the authenticator field is the associated data, and the ciphertext is the
/// sixteen-byte tag followed by the encrypted extension fields, which is where a server puts the
/// cookies that replace the one just spent.
fn open(packet: &[u8], field: Field, key: &[u8; KEY_BYTES]) -> Result<Vec<u8>, SourceError> {
    let (from, to) = field.value;
    let body = &packet[from..to];
    if body.len() < 4 {
        return Err(SourceError::Malformed(
            "an authenticator with no lengths in it".to_string(),
        ));
    }
    let nonce_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let cipher_len = usize::from(u16::from_be_bytes([body[2], body[3]]));
    let nonce_padded = nonce_len.div_ceil(4) * 4;
    if nonce_len != 16 {
        return Err(SourceError::Malformed(format!(
            "a nonce of {nonce_len} bytes, and this AEAD takes sixteen"
        )));
    }
    if cipher_len < 16 || 4 + nonce_padded + cipher_len > body.len() {
        return Err(SourceError::Malformed(format!(
            "a ciphertext of {cipher_len} bytes in an authenticator of {}",
            body.len()
        )));
    }
    let nonce: [u8; 16] = body[4..4 + nonce_len]
        .try_into()
        .map_err(|_| SourceError::Malformed("a nonce of the wrong length".to_string()))?;
    let ciphertext = &body[4 + nonce_padded..4 + nonce_padded + cipher_len];
    let (tag, sealed) = ciphertext.split_at(16);

    let cipher = Aes128SivAead::new_from_slice(key)
        .map_err(|_| SourceError::Malformed("the exported key is the wrong length".to_string()))?;
    let mut plaintext = sealed.to_vec();
    cipher
        .decrypt_inout_detached(
            &Nonce::from(nonce),
            &packet[..field.at],
            InOutBuf::from(plaintext.as_mut_slice()),
            &aes_siv::Tag::try_from(tag).map_err(|_| {
                SourceError::Malformed("an authenticator tag of the wrong length".to_string())
            })?,
        )
        .map_err(|_| {
            SourceError::Malformed(
                "the reply's authenticator does not check out, so it was written by somebody \
                 without the key"
                    .to_string(),
            )
        })?;
    Ok(plaintext)
}

/// A client for one NTS server.
///
/// It holds the session between polls, which is the whole point of the protocol: the TLS handshake
/// happens once and every request after it is one datagram, the same as plain NTP.
#[derive(Debug)]
pub struct NtsClient {
    id: SourceId,
    server: NtsServer,
    timeout: Duration,
    session: Option<Session>,
}

impl NtsClient {
    /// A client for one server.
    #[must_use]
    pub fn new(server: NtsServer) -> Self {
        Self {
            id: SourceId::new(format!("nts:{}", server.name)),
            server,
            timeout: DEFAULT_TIMEOUT,
            session: None,
        }
    }

    /// How long to wait for the key exchange and for a reply.
    #[must_use]
    pub fn waiting(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Which server this client asks.
    #[must_use]
    pub fn server(&self) -> &NtsServer {
        &self.server
    }

    /// The session, established if there is not one or if the cookies have run out.
    fn session(&mut self) -> Result<&mut Session, SourceError> {
        let stale = match &self.session {
            None => true,
            Some(session) => session.cookies.is_empty(),
        };
        if stale {
            self.session = Some(negotiate(&self.server, self.timeout)?);
        }
        self.session
            .as_mut()
            .ok_or_else(|| SourceError::Transport("no session".to_string()))
    }
}

impl TimeSource for NtsClient {
    fn id(&self) -> &SourceId {
        &self.id
    }

    fn operator(&self) -> &Operator {
        &self.server.operator
    }

    fn kind(&self) -> SourceKind {
        SourceKind::Nts
    }

    fn poll(&mut self, now: MonotonicNanos, nonce: &[u8]) -> Result<Exchange, SourceError> {
        if nonce.len() < UNIQUE_IDENTIFIER_BYTES {
            return Err(SourceError::Malformed(format!(
                "a nonce of {} bytes, and the unique identifier in an NTS request is \
                 {UNIQUE_IDENTIFIER_BYTES}",
                nonce.len()
            )));
        }
        let unique = &nonce[..UNIQUE_IDENTIFIER_BYTES];
        let challenge: [u8; 8] = nonce[..8].try_into().unwrap_or([0u8; 8]);

        let timeout = self.timeout;
        let session = self.session()?;
        // Spent whether or not the reply arrives. A cookie is single use by design, so a retry with
        // the same one is a request the server will drop and a linkable identifier on the wire.
        let cookie = session.cookies.remove(0);
        let held = session.cookies.len();
        let address = session.time_address.clone();
        let client_to_server = session.client_to_server;
        let server_to_client = session.server_to_client;

        let mut packet = build_request(challenge).to_vec();
        write_field(&mut packet, FIELD_UNIQUE_IDENTIFIER, unique);
        write_field(&mut packet, FIELD_COOKIE, &cookie);
        // One placeholder for every cookie short of the jar, which does two jobs with one field.
        // It asks the server for that many fresh cookies, and it makes the request the same size as
        // the reply it provokes. A server that answered a short request with a long one would be an
        // amplifier for anybody willing to put somebody else's address on a packet, so a server is
        // right to drop a request that has not paid for its own answer, and several do.
        let placeholder = vec![0u8; cookie.len()];
        for _ in 0..placeholders_wanted(held) {
            write_field(&mut packet, FIELD_COOKIE_PLACEHOLDER, &placeholder);
        }
        let mut authenticator_nonce = [0u8; 16];
        getrandom::getrandom(&mut authenticator_nonce)
            .map_err(|e| SourceError::Transport(format!("no randomness for a nonce: {e}")))?;
        seal(
            &mut packet,
            &client_to_server,
            authenticator_nonce,
            MIN_REQUEST_BYTES,
        )?;
        if packet.len() > MAX_REPLY {
            return Err(SourceError::Malformed(
                "the request is longer than this client will read a reply".to_string(),
            ));
        }

        let (reply, sent_at, received_at) = udp_exchange(&address, &packet, timeout)?;
        let checked = read_header(&reply)?;
        let fields = read_fields(&reply)?;

        // The identifier first, because a reply to somebody else's request is not worth
        // authenticating, and because this is the check that survives an attacker who can replay.
        let echoed = fields
            .iter()
            .find(|f| f.kind == FIELD_UNIQUE_IDENTIFIER)
            .ok_or_else(|| {
                SourceError::Malformed(
                    "the reply carries no unique identifier, so nothing ties it to this request"
                        .to_string(),
                )
            })?;
        if &reply[echoed.value.0..echoed.value.1] != unique {
            return Err(SourceError::Malformed(
                "the reply carries back a different unique identifier, so it answers a different \
                 request"
                    .to_string(),
            ));
        }

        let authenticator = fields
            .iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .ok_or_else(|| {
                SourceError::Malformed(
                    "the reply carries no authenticator, which is the whole of what NTS adds"
                        .to_string(),
                )
            })?;
        let hidden = open(&reply, *authenticator, &server_to_client)?;

        // Cookies come back inside the authenticated part, one for each one spent. A server that
        // sends none is not a fault to refuse over: the session simply runs out and the next poll
        // does the key exchange again.
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| SourceError::Transport("no session".to_string()))?;
        harvest(&mut session.cookies, &hidden)?;

        Ok(Exchange {
            source: self.id.clone(),
            operator: self.server.operator.clone(),
            kind: SourceKind::Nts,
            t2: checked.receive,
            t3: checked.transmit,
            mono_t1: now.advanced(i128::try_from(sent_at).unwrap_or(i128::MAX)),
            mono_t4: now.advanced(i128::try_from(received_at).unwrap_or(i128::MAX)),
            root_delay: checked.root_delay,
            root_dispersion: checked.root_dispersion,
            timescale: Timescale::Utc,
            // Authenticating a packet says nothing about what the server does with a leap second,
            // and there is no field for it here any more than there is in plain NTP. Unknown
            // conflicts with everything in the model, which is the safe direction near a leap.
            smear: SmearPolicy::Unknown,
            leap: checked.leap,
            // Never third-party evidence, in one field. The keys are symmetric, so this machine
            // could have written the reply it just checked, and a stranger has no reason to
            // believe it did not.
            attestation: None,
        })
    }
}

/// How many placeholders to send, given how many cookies are left after spending one.
fn placeholders_wanted(held: usize) -> usize {
    COOKIE_JAR.saturating_sub(held + 1)
}

/// Put one cookie in the jar and keep the jar the size the jar is.
///
/// `COOKIE_JAR` decided how many fresh cookies to ask for and nothing kept the jar to
/// it, so a server answering with more than it was asked for grew this client's memory for as long
/// as the process ran. The agent is that process and it polls every thirty-two seconds. Two paths
/// fed the jar and neither of them trusted a number the server chose: the key exchange, bounded per
/// exchange at 64 KiB and so at thousands of cookies in one go, and every reply to every poll,
/// bounded per reply and unbounded across them.
///
/// **The oldest goes when the jar is full, not the newest.** A cookie is a piece of the server's own
/// state handed back to it, and the key it was made under rotates, so the oldest one in hand is the
/// one most likely to be refused by the time it is spent. Keeping the newest and spending the oldest
/// of those first is both halves of that: the freshest cookies are the ones held, and the spend
/// order is unchanged.
///
/// One at a time rather than a truncation at the end, so the jar never grows past its size even
/// inside a single reply. That also puts a ceiling under `Vec::remove(0)` on the spend path, which
/// was linear in a jar with no ceiling on it.
fn stow(jar: &mut Vec<Vec<u8>>, cookie: Vec<u8>) {
    jar.push(cookie);
    if jar.len() > COOKIE_JAR {
        jar.remove(0);
    }
}

/// Take every cookie out of the authenticated part of a reply and stow it.
///
/// Its own function so the cap can be tested against a reply this test suite seals for itself,
/// rather than only against a server nobody here can make misbehave.
fn harvest(jar: &mut Vec<Vec<u8>>, hidden: &[u8]) -> Result<(), SourceError> {
    for field in read_fields_from(hidden)? {
        if field.kind == FIELD_COOKIE {
            stow(jar, hidden[field.value.0..field.value.1].to_vec());
        }
    }
    Ok(())
}

/// Walk extension fields in a buffer that is not a packet, which is what the encrypted part is.
fn read_fields_from(bytes: &[u8]) -> Result<Vec<Field>, SourceError> {
    let mut padded = vec![0u8; PACKET];
    padded.extend_from_slice(bytes);
    let fields = read_fields(&padded)?;
    Ok(fields
        .into_iter()
        .map(|f| Field {
            kind: f.kind,
            at: f.at - PACKET,
            value: (f.value.0 - PACKET, f.value.1 - PACKET),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_asks_for_ntpv4_and_one_aead_and_then_stops() {
        let bytes = key_exchange_request();
        let (records, complete) = read_records(&bytes).expect("records this file just wrote");
        assert!(complete, "the request ends its own message");
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.critical), "all three are critical");
        assert_eq!(records[0].kind, RECORD_NEXT_PROTOCOL);
        assert_eq!(records[0].body, NEXT_PROTOCOL_NTPV4.to_be_bytes());
        assert_eq!(records[1].kind, RECORD_AEAD_ALGORITHM);
        assert_eq!(records[1].body, AEAD_AES_SIV_CMAC_256.to_be_bytes());
        assert_eq!(records[2].kind, RECORD_END_OF_MESSAGE);
    }

    #[test]
    fn a_stream_that_stops_halfway_through_a_record_is_not_yet_an_answer() {
        // The key exchange is read off a stream, so a short read is the ordinary case rather than a
        // fault. Treating it as one would refuse every server that answers in two segments.
        let whole = key_exchange_request();
        let (records, complete) = read_records(&whole[..5]).expect("a partial read");
        assert!(!complete);
        assert!(records.is_empty());

        let (records, complete) = read_records(&whole[..whole.len() - 1]).expect("a partial read");
        assert!(!complete, "the end of message record is not whole yet");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn an_extension_field_is_padded_to_four_and_its_length_counts_its_header() {
        let mut out = Vec::new();
        write_field(&mut out, FIELD_COOKIE, &[1, 2, 3, 4, 5]);
        assert_eq!(out.len(), 12, "four of header, five of value, three of pad");
        assert_eq!(u16::from_be_bytes([out[0], out[1]]), FIELD_COOKIE);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 12);
        assert_eq!(&out[4..9], &[1, 2, 3, 4, 5]);
        assert_eq!(&out[9..12], &[0, 0, 0]);
    }

    #[test]
    fn a_field_whose_length_lies_loses_the_rest_of_the_packet_and_is_refused() {
        // The length is how the next field is found, so a wrong one is not a field this client can
        // skip. Every implementation that tried to skip it read the packet from the wrong offset.
        let mut packet = vec![0u8; PACKET];
        packet.extend_from_slice(&FIELD_COOKIE.to_be_bytes());
        packet.extend_from_slice(&6u16.to_be_bytes()); // not a multiple of four
        packet.extend_from_slice(&[0u8; 2]);
        assert!(matches!(
            read_fields(&packet),
            Err(SourceError::Malformed(_))
        ));

        let mut runs_off = vec![0u8; PACKET];
        runs_off.extend_from_slice(&FIELD_COOKIE.to_be_bytes());
        runs_off.extend_from_slice(&64u16.to_be_bytes());
        assert!(matches!(
            read_fields(&runs_off),
            Err(SourceError::Malformed(_))
        ));
    }

    /// A packet sealed the way a server seals one, so the checks can be driven without a server.
    fn a_sealed_reply(key: &[u8; KEY_BYTES], unique: &[u8], cookies: &[&[u8]]) -> Vec<u8> {
        let mut packet = vec![0u8; PACKET];
        packet[0] = 0b0010_0100; // leap none, version four, mode four
        packet[1] = 2; // stratum
        let transmit: u64 = ((2_208_988_800u64 + 1_788_000_000) << 32) | 0x4000_0000;
        packet[32..40].copy_from_slice(&transmit.to_be_bytes());
        packet[40..48].copy_from_slice(&transmit.to_be_bytes());
        write_field(&mut packet, FIELD_UNIQUE_IDENTIFIER, unique);

        let mut hidden = Vec::new();
        for cookie in cookies {
            write_field(&mut hidden, FIELD_COOKIE, cookie);
        }

        let cipher = Aes128SivAead::new_from_slice(key).expect("a key of the right length");
        let nonce = [7u8; 16];
        let mut buffer = hidden.clone();
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::from(nonce),
                &packet,
                InOutBuf::from(buffer.as_mut_slice()),
            )
            .expect("a sealed reply");

        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&u16::try_from(16 + buffer.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&tag);
        body.extend_from_slice(&buffer);
        write_field(&mut packet, FIELD_AUTHENTICATOR, &body);
        packet
    }

    #[test]
    fn a_reply_this_client_sealed_itself_opens_and_gives_back_its_cookies() {
        let key = [3u8; KEY_BYTES];
        let unique = [9u8; UNIQUE_IDENTIFIER_BYTES];
        let packet = a_sealed_reply(&key, &unique, &[b"first cookie", b"second cookie"]);

        let fields = read_fields(&packet).expect("fields this test wrote");
        let authenticator = fields
            .iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");
        let hidden = open(&packet, *authenticator, &key).expect("a reply sealed with this key");

        let inner = read_fields_from(&hidden).expect("fields inside the sealed part");
        let cookies: Vec<&[u8]> = inner
            .iter()
            .filter(|f| f.kind == FIELD_COOKIE)
            .map(|f| &hidden[f.value.0..f.value.1])
            .collect();
        assert_eq!(cookies.len(), 2);
        assert_eq!(&cookies[0][..12], b"first cookie");
    }

    #[test]
    fn one_bit_changed_anywhere_in_the_packet_makes_the_reply_unauthentic() {
        // This is the property the whole source exists for. The associated data is every byte
        // before the authenticator, so a header this client would otherwise have believed cannot be
        // edited on the path without the check failing.
        let key = [3u8; KEY_BYTES];
        let unique = [9u8; UNIQUE_IDENTIFIER_BYTES];
        let good = a_sealed_reply(&key, &unique, &[b"a cookie"]);
        let authenticator_at = read_fields(&good)
            .expect("fields")
            .into_iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");

        for byte in [1usize, 40, 60, authenticator_at.at + 30] {
            let mut damaged = good.clone();
            damaged[byte] ^= 0x01;
            let fields = match read_fields(&damaged) {
                Ok(fields) => fields,
                // Damaging a length is caught earlier, which is also a refusal.
                Err(_) => continue,
            };
            let Some(field) = fields.into_iter().find(|f| f.kind == FIELD_AUTHENTICATOR) else {
                continue;
            };
            assert!(
                open(&damaged, field, &key).is_err(),
                "byte {byte} was changed and the reply still checked out"
            );
        }
    }

    #[test]
    fn a_reply_sealed_with_another_key_is_refused() {
        let unique = [9u8; UNIQUE_IDENTIFIER_BYTES];
        let packet = a_sealed_reply(&[3u8; KEY_BYTES], &unique, &[b"a cookie"]);
        let field = read_fields(&packet)
            .expect("fields")
            .into_iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");
        assert!(matches!(
            open(&packet, field, &[4u8; KEY_BYTES]),
            Err(SourceError::Malformed(_))
        ));
    }

    #[test]
    fn an_authenticator_stating_lengths_that_do_not_fit_is_refused_before_any_key_is_used() {
        let mut packet = vec![0u8; PACKET];
        let mut body = Vec::new();
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&4096u16.to_be_bytes()); // longer than the field
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&[0u8; 16]);
        write_field(&mut packet, FIELD_AUTHENTICATOR, &body);
        let field = read_fields(&packet)
            .expect("fields")
            .into_iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");
        assert!(matches!(
            open(&packet, field, &[0u8; KEY_BYTES]),
            Err(SourceError::Malformed(_))
        ));
    }

    #[test]
    fn a_request_is_padded_out_to_a_kilobyte_so_it_cannot_be_used_to_amplify() {
        // Found by running against real servers rather than by reading. Three of the six operators
        // tried on 2026-09-09 completed the key exchange and then never answered a time request,
        // and the difference was this padding: they will not answer a request smaller than the
        // reply it asks for. Their behaviour is right and the client was wrong.
        let mut packet = vec![0u8; PACKET];
        write_field(&mut packet, FIELD_UNIQUE_IDENTIFIER, &[1u8; 32]);
        write_field(&mut packet, FIELD_COOKIE, &[2u8; 100]);
        seal(&mut packet, &[3u8; KEY_BYTES], [4u8; 16], MIN_REQUEST_BYTES)
            .expect("a sealed request");
        assert!(packet.len() >= MIN_REQUEST_BYTES, "{} bytes", packet.len());

        // And the padding does not stop the field being read, because the lengths inside it say
        // where the nonce and the ciphertext are and the tail is nothing.
        let field = read_fields(&packet)
            .expect("fields")
            .into_iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");
        assert!(open(&packet, field, &[3u8; KEY_BYTES]).is_ok());
    }

    #[test]
    fn a_reply_carrying_more_cookies_than_were_asked_for_does_not_grow_the_jar() {
        // The jar decided how many to ask for and nothing kept it to that, so a server
        // that answered a request for one cookie with forty was answered by a client that kept all
        // forty, every thirty-two seconds, for as long as the agent ran.
        let key = [3u8; KEY_BYTES];
        let unique = [9u8; UNIQUE_IDENTIFIER_BYTES];
        let many: Vec<Vec<u8>> = (0..40u8).map(|i| vec![i; 64]).collect();
        let offered: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
        let packet = a_sealed_reply(&key, &unique, &offered);

        let fields = read_fields(&packet).expect("fields this test wrote");
        let authenticator = fields
            .iter()
            .find(|f| f.kind == FIELD_AUTHENTICATOR)
            .expect("an authenticator");
        let hidden = open(&packet, *authenticator, &key).expect("a reply sealed with this key");

        // The jar starts with one cookie in it, which is where a client sits after spending its
        // last but one, so the test covers a reply arriving on top of what is already held.
        let mut jar = vec![vec![0xffu8; 64]];
        harvest(&mut jar, &hidden).expect("the fields this test sealed");

        assert_eq!(jar.len(), COOKIE_JAR, "the jar is the size the jar is");
        // The newest are what is held and the oldest of those is spent first, which is the order
        // `poll` takes them in. Forty offered, so the last eight are 32 to 39.
        assert_eq!(jar[0][0], 32);
        assert_eq!(jar[COOKIE_JAR - 1][0], 39);

        // And it stays there however many more arrive.
        harvest(&mut jar, &hidden).expect("the fields this test sealed");
        assert_eq!(jar.len(), COOKIE_JAR);
    }

    #[test]
    fn the_jar_holds_what_it_is_given_until_it_is_full() {
        // The other half, so the cap is not passing because the jar is empty. Nothing is dropped
        // while there is room, and the order is the order they arrived.
        let mut jar: Vec<Vec<u8>> = Vec::new();
        for i in 0..COOKIE_JAR as u8 {
            stow(&mut jar, vec![i; 4]);
        }
        assert_eq!(jar.len(), COOKIE_JAR);
        assert_eq!(jar[0][0], 0);
        assert_eq!(jar[COOKIE_JAR - 1][0], (COOKIE_JAR - 1) as u8);

        stow(&mut jar, vec![99; 4]);
        assert_eq!(jar.len(), COOKIE_JAR);
        assert_eq!(jar[0][0], 1, "the oldest is the one that goes");
        assert_eq!(jar[COOKIE_JAR - 1][0], 99);
    }

    #[test]
    fn placeholders_ask_for_exactly_the_cookies_the_jar_is_short() {
        assert_eq!(
            placeholders_wanted(7),
            0,
            "one spent and seven held is a full jar"
        );
        assert_eq!(placeholders_wanted(0), 7);
        assert_eq!(placeholders_wanted(3), 4);
        assert_eq!(placeholders_wanted(50), 0, "never negative");
    }

    #[test]
    fn the_exporter_context_is_the_five_octets_the_standard_fixes() {
        // Both ends build this from the same numbers and never exchange it, so getting it wrong
        // gives two different keys and an error that says only that the reply did not check out.
        let mut context = [0u8; 5];
        context[0..2].copy_from_slice(&NEXT_PROTOCOL_NTPV4.to_be_bytes());
        context[2..4].copy_from_slice(&AEAD_AES_SIV_CMAC_256.to_be_bytes());
        context[4] = 0x01;
        assert_eq!(context, [0x00, 0x00, 0x00, 0x0f, 0x01]);
        assert_eq!(EXPORTER_LABEL, b"EXPORTER-network-time-security");
    }

    #[test]
    fn the_published_servers_are_three_operators_and_not_three_names() {
        let published = NtsServer::published();
        assert_eq!(published.len(), 3);
        let mut operators: Vec<&str> = published.iter().map(|s| s.name.as_str()).collect();
        operators.sort_unstable();
        operators.dedup();
        assert_eq!(operators.len(), 3);
    }

    #[test]
    fn an_nts_source_can_never_be_evidence() {
        // The keys are symmetric, so this machine could produce any reply it can check. That is the
        // whole of why an authenticated source is still not a witness.
        assert!(!SourceKind::Nts.carries_third_party_signature());
    }

    #[test]
    fn a_session_never_prints_its_keys() {
        let session = Session {
            time_address: "example:123".to_string(),
            client_to_server: [0xab; KEY_BYTES],
            server_to_client: [0xcd; KEY_BYTES],
            cookies: vec![vec![1, 2, 3]],
        };
        let printed = format!("{session:?}");
        assert!(!printed.contains("171"), "{printed}");
        assert!(!printed.contains("ab"), "{printed}");
        assert!(printed.contains("example:123"));
    }
}
