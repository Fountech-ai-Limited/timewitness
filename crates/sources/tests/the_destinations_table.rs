//! The document an operator opens a firewall from, held to the code it describes.
//!
//! A tester installing on a host behind a firewall had to work out for himself what the product
//! needs to reach, and got one of them wrong: the timestamp authority and the beacon are plain HTTP
//! on port 80 and he opened 443. `docs/destinations-and-ports.md` is the list, and a list nothing
//! checks is a list that is right on the day it is written.
//!
//! So this reads the published lists out of the code, reads the table out of the document, and
//! requires the two to be the same set. A source added to the code with nothing written down for it
//! fails, and a line of the table naming a host or a port the code does not carry fails too, because
//! a stale line here is an operator opening a port for nothing or leaving one shut.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use timewitness_core::evidence::rfc3161::published_authorities;
use timewitness_sources::drand::DrandClient;
use timewitness_sources::http::DEFAULT_PORT;
use timewitness_sources::ntp::NtpServer;
use timewitness_sources::nts::{NtsServer, DEFAULT_TIME_PORT, KEY_EXCHANGE_PORT};
use timewitness_sources::roughtime::RoughtimeServer;

/// One thing a host has to be able to reach.
///
/// The transport is part of it because 123 over UDP and 4460 over TCP are two different rules in
/// every firewall anybody runs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Destination {
    host: String,
    port: u16,
    transport: &'static str,
}

impl Destination {
    fn udp(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            transport: "udp",
        }
    }

    fn tcp(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            transport: "tcp",
        }
    }
}

fn document() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/destinations-and-ports.md")
}

/// An address written `host:port`, as the published lists carry it.
fn split(address: &str) -> (String, u16) {
    let (host, port) = address
        .rsplit_once(':')
        .unwrap_or_else(|| panic!("{address} names no port"));
    (
        host.to_string(),
        port.parse()
            .unwrap_or_else(|_| panic!("{port} is not a port")),
    )
}

/// A plain HTTP address, which names a port or means [`DEFAULT_PORT`].
fn from_url(url: &str) -> Destination {
    let rest = url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("{url} is not the plain HTTP this client speaks"));
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((host, port)) => Destination::tcp(
            host,
            port.parse()
                .unwrap_or_else(|_| panic!("{port} is not a port")),
        ),
        None => Destination::tcp(authority, DEFAULT_PORT),
    }
}

/// Everything the shipped lists say this product reaches.
fn what_the_code_carries() -> BTreeSet<Destination> {
    let mut all = BTreeSet::new();

    for server in RoughtimeServer::published() {
        let (host, port) = split(&server.address);
        all.insert(Destination::udp(&host, port));
    }
    for server in NtpServer::published() {
        let (host, port) = split(&server.address);
        all.insert(Destination::udp(&host, port));
    }
    for server in NtsServer::published() {
        // Two rules, not one. The key exchange is TLS over its own port and the time exchange that
        // follows goes to whatever the key exchange names, which is this port unless it says
        // otherwise.
        all.insert(Destination::tcp(&server.host, KEY_EXCHANGE_PORT));
        all.insert(Destination::udp(&server.host, DEFAULT_TIME_PORT));
    }
    for authority in published_authorities() {
        all.insert(from_url(&authority.url));
    }
    for relay in DrandClient::quicknet().relays() {
        all.insert(from_url(relay));
    }

    all
}

/// Everything the document's table says it reaches.
fn what_the_table_says() -> BTreeSet<Destination> {
    let text = std::fs::read_to_string(document()).expect("the destinations document");
    let mut all = BTreeSet::new();

    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("| `") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert!(
            cells.len() >= 3,
            "a row of the table has fewer cells than it has columns: {line}"
        );
        let host = cells[0].trim_matches('`').to_string();
        let (port, transport) = cells[2].split_once('/').unwrap_or_else(|| {
            panic!("the port cell {:?} is not written port/transport", cells[2])
        });
        let port: u16 = port
            .parse()
            .unwrap_or_else(|_| panic!("{port} is not a port"));
        let transport = match transport {
            "udp" => "udp",
            "tcp" => "tcp",
            other => panic!("{other} is not a transport this product speaks"),
        };
        all.insert(Destination {
            host,
            port,
            transport,
        });
    }

    all
}

/// What one set holds that the other does not, in words a reader can act on.
///
/// Its own function so the test below can hand it a planted difference and watch it answer, rather
/// than trusting a comparison that has only ever been run on two sets that agree.
fn differences(code: &BTreeSet<Destination>, table: &BTreeSet<Destination>) -> String {
    let mut said = String::new();
    for missing in code.difference(table) {
        let _ = writeln!(
            said,
            "the code reaches {}:{} over {} and the table has no row for it",
            missing.host, missing.port, missing.transport
        );
    }
    for extra in table.difference(code) {
        let _ = writeln!(
            said,
            "the table says {}:{} over {} and nothing in the code reaches it",
            extra.host, extra.port, extra.transport
        );
    }
    said
}

#[test]
fn every_destination_in_the_code_has_a_row_and_every_row_is_in_the_code() {
    let code = what_the_code_carries();
    let table = what_the_table_says();

    // The shape of failure this product keeps paying for is a guard that passes because nothing
    // reached it. An empty table and an empty code list would agree perfectly.
    assert!(
        table.len() >= 10,
        "only {} rows were read out of the table, so the reader found the wrong thing",
        table.len()
    );
    assert!(
        code.len() >= 10,
        "only {} destinations were read out of the code",
        code.len()
    );

    let said = differences(&code, &table);
    assert!(said.is_empty(), "\n{said}");
}

#[test]
fn a_destination_the_document_does_not_carry_is_named() {
    let code = what_the_code_carries();
    let mut table = what_the_table_says();

    // A source added to the code and not to the document.
    table.remove(code.iter().next().expect("the code carries destinations"));
    assert!(
        differences(&code, &table).contains("the table has no row for it"),
        "a destination missing from the document went unsaid"
    );

    // A line of the table left in the document after the source it named was removed.
    let mut table = what_the_table_says();
    table.insert(Destination::udp("time.example", 123));
    assert!(
        differences(&code, &table).contains("nothing in the code reaches it"),
        "a row for a destination nothing reaches went unsaid"
    );
}
