//! The one place the command line names the app, and the one way it talks to it.
//!
//! The app at `app.timewitness.dev` keeps an organisation's receipts. It is never on the path of a
//! stamp: a stamp reads a local clock and signs, and nothing in it waits on us. It is never on the
//! path of a check either, which needs nothing of ours at all. What reaches it is a separate act
//! after the stamp, `timewitness send`, and that act lives here so the address is written once.
//! `crates/architecture` holds both halves: no other source names the host, and neither `stamp`
//! nor `agent` can reach this module.
//!
//! **Why a client of our own, when the tree already links a TLS stack.** NTS brings `rustls` and
//! the public roots in, so a request over HTTPS costs a hundred lines rather than a crate. An HTTP
//! library would bring a second copy of most of that and a runtime besides, for one POST.
//!
//! **A credential never travels in the clear.** Plain HTTP is refused for any host but this machine,
//! which is what a test of this module talks to. A machine credential sent over plain HTTP to a
//! real address would be a credential handed to everyone on the path.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, Stream};

/// Where the app answers, unless a caller names another address of it.
pub const APP: &str = "https://app.timewitness.dev";

/// Where a machine files a receipt it signed.
///
/// With the slash on the end, because the app serves every path that way and answers the bare one
/// with a redirect. A redirect is never followed here: it would carry the credential to wherever it
/// pointed.
pub const RECEIPTS: &str = "/api/machine/receipts/";

/// The most answer this client reads. The app answers a filing in a few hundred bytes.
const MAX_ANSWER: usize = 256 * 1024;

/// How long a connection and each read may take. A send is the last step of a job, so it gives up
/// in seconds rather than holding the job open.
const TIMEOUT: Duration = Duration::from_secs(15);

/// What the app answered: the status and the body as text.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub body: String,
}

/// An address taken apart.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    tls: bool,
    host: String,
    port: u16,
}

/// Reads an address of the app, refusing plain HTTP anywhere but this machine.
fn target(address: &str) -> Result<Target, String> {
    let (tls, rest) = if let Some(rest) = address.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = address.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("{address} is not an https address"));
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if rest.len() > authority.len() && rest[authority.len()..] != *"/" {
        return Err(format!(
            "{address} carries a path; give the app's address alone, such as {APP}"
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| format!("{port} is not a port"))?,
        ),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(format!("{address} names no host"));
    }
    if !tls && !matches!(host.as_str(), "127.0.0.1" | "localhost") {
        return Err(format!(
            "{address} is plain HTTP, and a machine credential is never sent in the clear. Use https"
        ));
    }
    Ok(Target { tls, host, port })
}

/// POSTs a JSON body to a path of the app with a bearer credential, and reads the answer.
pub fn post_json(address: &str, path: &str, bearer: &str, body: &str) -> Result<Answer, String> {
    let target = target(address)?;
    let socket_address = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| format!("{} does not resolve: {e}", target.host))?
        .next()
        .ok_or_else(|| format!("{} resolves to nothing", target.host))?;
    let mut socket = TcpStream::connect_timeout(&socket_address, TIMEOUT)
        .map_err(|e| format!("cannot reach {address}: {e}"))?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| socket.set_write_timeout(Some(TIMEOUT)))
        .map_err(|e| format!("cannot set a timeout: {e}"))?;

    let host_header = if (target.tls && target.port == 443) || (!target.tls && target.port == 80) {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nUser-Agent: timewitness/{}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len(),
        env!("CARGO_PKG_VERSION"),
    );

    let raw = if target.tls {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(target.host.clone())
            .map_err(|_| format!("{} is not a name a certificate can match", target.host))?;
        let mut connection = ClientConnection::new(Arc::new(config), name)
            .map_err(|e| format!("no TLS session: {e}"))?;
        let mut stream = Stream::new(&mut connection, &mut socket);
        exchange(&mut stream, request.as_bytes())?
    } else {
        exchange(&mut socket, request.as_bytes())?
    };
    answer(&raw)
}

/// Writes the request and reads until the other side closes.
///
/// A server that closes without saying goodbye over TLS is read as having finished, since the
/// request asked it to close and the answer is checked for completeness below.
fn exchange(stream: &mut (impl Read + Write), request: &[u8]) -> Result<Vec<u8>, String> {
    stream
        .write_all(request)
        .and_then(|()| stream.flush())
        .map_err(|e| format!("the request did not go out: {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_ANSWER {
                    return Err("the app answered with more than a filing ever needs".to_string());
                }
            }
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("no answer came back: {e}")),
        }
    }
    Ok(raw)
}

/// The status and body of an HTTP/1.1 answer, with a chunked body put back together.
fn answer(raw: &[u8]) -> Result<Answer, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the answer ended before its headers did")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let rest = &raw[split + 4..];
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("the answer has no status line")?;
    let header = |name: &str| {
        head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_ascii_lowercase())
        })
    };
    let body = if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        dechunk(rest).ok_or("a chunked answer ended part way through")?
    } else if let Some(length) = header("content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| "a length that is not a number")?;
        if rest.len() < length {
            return Err("the answer ended before the length it gave".to_string());
        }
        rest[..length].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Answer {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn dechunk(mut body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        if body.len() < size + 2 {
            return None;
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_goes_over_https_or_to_this_machine_and_nowhere_else() {
        assert!(target(APP).unwrap().tls);
        assert_eq!(target("https://dev.timewitness.dev").unwrap().port, 443);
        assert_eq!(target("http://127.0.0.1:4000").unwrap().port, 4000);
        assert!(target("http://localhost:4000").is_ok());
        for refused in [
            "http://app.timewitness.dev",
            "http://192.168.1.4:4000",
            "ftp://app.timewitness.dev",
            "app.timewitness.dev",
            "https://app.timewitness.dev/api/machine/receipts",
            "https://",
        ] {
            assert!(target(refused).is_err(), "taken: {refused}");
        }
    }

    #[test]
    fn an_answer_is_read_whole_or_refused() {
        let plain = answer(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!((plain.status, plain.body.as_str()), (201, "{}"));
        let chunked = answer(
            b"HTTP/1.1 422 Unprocessable\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!((chunked.status, chunked.body.as_str()), (422, "{\"a\":1}"));
        assert!(answer(b"HTTP/1.1 201 Created\r\nContent-Length: 9\r\n\r\n{}").is_err());
        assert!(
            answer(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n{}").is_err()
        );
        assert!(answer(b"not an answer").is_err());
    }
}
