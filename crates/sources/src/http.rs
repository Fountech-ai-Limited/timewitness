//! A very small HTTP/1.1 client, and no transport security at all.
//!
//! **That is deliberate and it is the interesting part of this file.** Everything fetched through
//! here is checked afterwards against a key pinned in advance: a drand round against its chain's
//! group key, a timestamp token against its authority's certificate. A relay that lies is caught by
//! the signature, not by the transport, so a certificate chain would be protecting bytes that are
//! already protected. Adding one would pull a TLS stack, a root store and a policy about expiry into
//! a product whose whole argument is that a stranger can check the evidence without trusting
//! anybody's infrastructure.
//!
//! The one thing plain HTTP does give away is which rounds and which hashes we asked about, to
//! anybody on the path. A hash of a build artefact is not a secret in a product whose output is
//! published beside the artefact, so that is a trade this makes knowingly rather than by accident.
//! Where a caller needs it hidden, it fetches the evidence itself and hands in the bytes.
//!
//! Nothing here is a general purpose client. It speaks to two kinds of endpoint, both of which
//! answer with a content length and close politely, and it refuses anything it has not been taught.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::SourceError;

/// The most body this client will read.
///
/// A beacon round is a few hundred bytes and a timestamp token a few thousand. A megabyte is three
/// orders of magnitude of room and still refuses a server that answers with a stream.
const MAX_BODY: usize = 1_048_576;

/// The port a plain HTTP address is reached on where it names none.
///
/// Public for the same reason as the two in [`crate::nts`]: the document an operator opens a
/// firewall from is held to this rather than to a number written out again beside it.
pub const DEFAULT_PORT: u16 = 80;

/// A URL split into the three parts this client needs.
struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Target, SourceError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        SourceError::Transport(format!(
            "{url} is not a plain HTTP address, and this client speaks nothing else"
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| SourceError::Transport(format!("{p} is not a port")))?,
        ),
        None => (authority.to_string(), DEFAULT_PORT),
    };
    if host.is_empty() {
        return Err(SourceError::Transport(format!("{url} names no host")));
    }
    Ok(Target {
        host,
        port,
        path: path.to_string(),
    })
}

fn send(target: &Target, request: &[u8], timeout: Duration) -> Result<Vec<u8>, SourceError> {
    let address = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| SourceError::Transport(format!("{} does not resolve: {e}", target.host)))?
        .next()
        .ok_or_else(|| SourceError::Transport(format!("{} resolves to nothing", target.host)))?;

    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|e| SourceError::Transport(format!("cannot reach {address}: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| SourceError::Transport(format!("no deadline on the stream: {e}")))?;
    stream
        .write_all(request)
        .map_err(|e| SourceError::Transport(format!("the request did not go out: {e}")))?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_BODY {
                    return Err(SourceError::Malformed(
                        "the answer is larger than this client will read".to_string(),
                    ));
                }
                if let Some(body) = complete_body(&raw) {
                    return Ok(body);
                }
            }
            Err(_) => return Err(SourceError::Timeout),
        }
    }
    // The connection closed. A server that gave no length uses the close itself to mark the end,
    // which is the third framing and the only one where the body is complete precisely because
    // there is no more of it.
    body_at_end_of_stream(&raw)
        .ok_or_else(|| SourceError::Malformed("the answer ended before its body did".to_string()))
}

/// The body, once all of it has arrived, or `None` while it is still coming.
///
/// Three framings, which is all of the ones a server actually uses: a content length, chunked
/// transfer, and a server that closes the connection to mark the end. The third cannot be told
/// apart from a truncated answer by looking at the bytes, so it is handled separately, at the point
/// where the stream really has ended.
fn complete_body(raw: &[u8]) -> Option<Vec<u8>> {
    let (head, body) = split_head(raw)?;
    if head.contains("transfer-encoding: chunked") {
        return dechunk(body);
    }
    let length = content_length(&head)?;
    if body.len() >= length {
        Some(body[..length].to_vec())
    } else {
        None
    }
}

/// The body of an answer whose stream has ended.
fn body_at_end_of_stream(raw: &[u8]) -> Option<Vec<u8>> {
    let (head, body) = split_head(raw)?;
    if head.contains("transfer-encoding: chunked") {
        return dechunk(body);
    }
    match content_length(&head) {
        Some(length) if body.len() >= length => Some(body[..length].to_vec()),
        Some(_) => None,
        None => Some(body.to_vec()),
    }
}

fn split_head(raw: &[u8]) -> Option<(String, &[u8])> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((
        String::from_utf8_lossy(&raw[..split]).to_lowercase(),
        &raw[split + 4..],
    ))
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        line.strip_prefix("content-length:")
            .and_then(|v| v.trim().parse::<usize>().ok())
    })
}

/// Reassemble a chunked body, or `None` while the last chunk has not arrived.
///
/// Every length here comes off the wire, so every one of them is checked against what is actually
/// in hand rather than used to size anything.
///
/// The checking subtracts from what is left rather than adding to an index the server chose, and
/// that shape is the whole of the fix for hostile chunk bytes. `start + size` was guarded and
/// `end + 2` on the next line was not, so a chunk header of `ffffffffffffffed` made the addition
/// wrap, the guard read the wrapped value and passed, and the slice went out the other side: "range
/// end index 18446744073709551615 out of range for slice of length 22". A guard that wraps along
/// with the value it is guarding is not a guard, and a second `checked_add` would only have left the
/// next reader to notice the third addition.
fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let header = std::str::from_utf8(&body[..line_end]).ok()?;
        let size_text = header.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        let start = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        // What is left after the header, then the chunk taken out of it, then the two bytes of
        // line ending that have to follow the chunk. No sum here can exceed what is in hand,
        // because nothing is summed.
        let available = body.len().checked_sub(start)?;
        if available < size || available - size < 2 {
            return None;
        }
        let end = start + size;
        out.extend_from_slice(&body[start..end]);
        if out.len() > MAX_BODY {
            return None;
        }
        body = &body[end + 2..];
    }
}

fn status(raw: &[u8]) -> Option<u16> {
    let line = raw.split(|b| *b == b'\r').next()?;
    let text = String::from_utf8_lossy(line);
    text.split_whitespace().nth(1)?.parse().ok()
}

/// Fetch a URL and return the body.
pub fn get(url: &str, timeout: Duration) -> Result<Vec<u8>, SourceError> {
    let target = parse(url)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path, target.host
    );
    let body = send(&target, request.as_bytes(), timeout)?;
    Ok(body)
}

/// Post a body to a URL and return what came back.
pub fn post(
    url: &str,
    content_type: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, SourceError> {
    let target = parse(url)?;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccept: \
         */*\r\nConnection: close\r\n\r\n",
        target.path,
        target.host,
        content_type,
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    send(&target, &request, timeout)
}

/// The status code an answer carried, for a caller that wants to report it.
#[must_use]
pub fn status_of(raw: &[u8]) -> Option<u16> {
    status(raw)
}

/// Pull one value out of a small flat JSON object.
///
/// Not a JSON parser and not pretending to be one. The two endpoints this client speaks to answer
/// with a handful of fields at the top level, and everything taken out of them is checked against a
/// signature afterwards, so a value read wrongly fails the check rather than being believed. A
/// parser written for these two shapes and refusing everything else is smaller than a general one
/// and has fewer places to be wrong.
#[must_use]
pub fn json_field(body: &[u8], key: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let needle = format!("\"{key}\"");
    let at = text.find(&needle)? + needle.len();
    let rest = text[at..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        Some(quoted[..end].to_string())
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        Some(rest[..end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_is_spoken() {
        assert!(parse("https://example.invalid/x").is_err());
        assert!(parse("ftp://example.invalid/x").is_err());
        let t = parse("http://example.invalid/a/b").expect("a plain address");
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("example.invalid", 80, "/a/b")
        );
        let t = parse("http://example.invalid:8080").expect("a plain address with a port");
        assert_eq!((t.port, t.path.as_str()), (8080, "/"));
    }

    #[test]
    fn a_body_is_only_returned_once_all_of_it_has_arrived() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let mut raw = head.to_vec();
        assert_eq!(complete_body(&raw), None);
        raw.extend_from_slice(b"abc");
        assert_eq!(complete_body(&raw), None);
        raw.extend_from_slice(b"de");
        assert_eq!(complete_body(&raw).as_deref(), Some(&b"abcde"[..]));
        assert_eq!(status(&raw), Some(200));
    }

    #[test]
    fn a_chunked_answer_is_only_returned_once_its_last_chunk_has_arrived() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut raw = head.to_vec();
        raw.extend_from_slice(b"5\r\nabcde\r\n");
        assert_eq!(complete_body(&raw), None, "no final chunk yet");
        raw.extend_from_slice(b"3\r\nfgh\r\n");
        assert_eq!(complete_body(&raw), None, "still no final chunk");
        raw.extend_from_slice(b"0\r\n\r\n");
        assert_eq!(complete_body(&raw).as_deref(), Some(&b"abcdefgh"[..]));
    }

    #[test]
    fn an_answer_with_no_length_is_complete_only_when_the_stream_ends() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcde";
        assert_eq!(complete_body(raw), None, "nothing says how long this is");
        assert_eq!(body_at_end_of_stream(raw).as_deref(), Some(&b"abcde"[..]));
    }

    #[test]
    fn fields_come_out_of_a_flat_object_and_nothing_else_does() {
        let body = br#"{"round":32000297,"randomness":"9518","signature":"856cee"}"#;
        assert_eq!(json_field(body, "round").as_deref(), Some("32000297"));
        assert_eq!(json_field(body, "signature").as_deref(), Some("856cee"));
        assert_eq!(json_field(body, "absent"), None);
        assert_eq!(json_field(b"not json at all", "round"), None);
    }

    // -----------------------------------------------------------------------
    // Hostile bytes.
    //
    // The drand relays are spoken to over plain HTTP, deliberately, because the value that comes
    // back is verified by pairing and a transport cannot protect what is already protected. That
    // reasoning holds for the value and stops at the bytes around it: anybody on the path writes
    // everything this file reads, and nothing here has a signature under it.
    //
    // These tests sit inside the crate rather than in `tests/` because the functions they attack
    // are private and should stay private. The alternative was widening the crate's surface so a
    // test could reach it, which is a worse trade than a test module in an unusual place.
    // -----------------------------------------------------------------------

    /// The chunk header that indexed past the end of the body, kept by name.
    ///
    /// `start + size` was guarded with `checked_add` and `end + 2` on the next line was not, so the
    /// guard passed and the slice went out the other side. A release build said "range end index
    /// 18446744073709551615 out of range for slice of length 22", which is a guard being bypassed
    /// rather than a guard being absent.
    const WATCHED_PANICKING: &[u8] = b"ffffffffffffffed\r\nabcd";

    #[test]
    fn a_chunk_size_that_wraps_the_index_is_refused_rather_than_indexing_past_the_body() {
        assert_eq!(dechunk(WATCHED_PANICKING), None);
        // And the sizes either side of the wrap, because a wrap has edges.
        for size in [
            "fffffffffffffffd",
            "fffffffffffffffe",
            "ffffffffffffffff",
            "7fffffffffffffff",
        ] {
            let mut raw = size.as_bytes().to_vec();
            raw.extend_from_slice(b"\r\nabcd");
            assert_eq!(dechunk(&raw), None, "a chunk claiming {size} bytes");
        }
    }

    #[test]
    fn a_chunk_with_no_room_for_the_line_ending_that_follows_it_is_refused() {
        // Four bytes of chunk and no CRLF behind them.
        assert_eq!(dechunk(b"4\r\nabcd"), None);
        assert_eq!(dechunk(b"4\r\nabcd\r"), None);
        assert_eq!(
            dechunk(b"4\r\nabcd\r\n0\r\n\r\n").as_deref(),
            Some(&b"abcd"[..])
        );
    }

    /// A seeded generator, so a failure reproduces from the seed printed with it.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[test]
    fn no_run_of_random_bytes_makes_the_chunk_reader_panic() {
        // Seeded and in the tree rather than run through a coverage-guided fuzzer. It needs no
        // nightly toolchain, it runs on every push, and a failure reproduces from the seed. What it
        // gives up is depth, and that is worth restating whenever this is read: it is a floor, not
        // a proof.
        let mut rng = Rng(0xda3e_39cb_94b9_5bdb);
        for _ in 0..200_000 {
            let len = rng.below(48);
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                // Weighted towards the characters a chunk header is made of, so the generator
                // reaches the parsing rather than being refused on its first byte.
                bytes.push(match rng.below(4) {
                    1 => b"0123456789abcdefABCDEF"[rng.below(22)],
                    2 => b"\r\n;"[rng.below(3)],
                    _ => rng.byte(),
                });
            }
            let _ = dechunk(&bytes);
        }
    }

    #[test]
    fn no_chunk_header_of_any_width_makes_the_reader_panic() {
        // Aimed at the size arithmetic rather than at the parsing, because a generator producing
        // random bytes almost never writes sixteen hex digits in a row and the fault needed
        // exactly that. Every width from one digit to seventeen, so the values either side of what
        // a `usize` holds are all reached.
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for _ in 0..200_000 {
            let digits = 1 + rng.below(17);
            let mut bytes: Vec<u8> = (0..digits)
                .map(|_| b"0123456789abcdefABCDEF"[rng.below(22)])
                .collect();
            bytes.extend_from_slice(b"\r\n");
            for _ in 0..rng.below(16) {
                bytes.push(rng.byte());
            }
            let _ = dechunk(&bytes);
        }
    }

    #[test]
    fn no_damaged_copy_of_a_real_chunked_answer_makes_the_reader_panic() {
        let original = b"5\r\nhello\r\n3\r\n you\r\n0\r\n\r\n".to_vec();
        let mut rng = Rng(0x1e35_a7bd_2c50_9f11);
        for _ in 0..100_000 {
            let mut damaged = original.clone();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(damaged.len());
                damaged[at] = rng.byte();
            }
            let _ = dechunk(&damaged);
        }
    }

    #[test]
    fn no_run_of_random_bytes_makes_the_whole_answer_reader_panic() {
        // The front door, which is what somebody on the path actually writes.
        let mut rng = Rng(0x5851_f42d_4c95_7f2d);
        for _ in 0..100_000 {
            let len = rng.below(96);
            let mut bytes = b"HTTP/1.1 200 OK\r\n".to_vec();
            for _ in 0..len {
                bytes.push(match rng.below(3) {
                    1 => b"\r\n:-0123456789abcdef"[rng.below(20)],
                    2 => b"transfer-encoding: chunked"[rng.below(26)],
                    _ => rng.byte(),
                });
            }
            let _ = complete_body(&bytes);
            let _ = body_at_end_of_stream(&bytes);
            let _ = status_of(&bytes);
            let _ = json_field(&bytes, "round");
        }
    }
}
