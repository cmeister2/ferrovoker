//! Local HTTP responses exercise transport limits and server backoff.

use std::io::Write;
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use super::*;

/// Starts a single-response HTTP server on a local ephemeral port.
fn server(response: Vec<u8>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local server binds");
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("local client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("request headers arrive");
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() < 8192);
        }
        stream.write_all(&response).expect("response writes");
    });
    (url, handle)
}

/// Creates a close-delimited response with additional caller headers.
fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Creates a local-HTTP-capable client with a bounded test timeout.
fn downloader() -> Downloader {
    Downloader::with_client(
        Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("ferrovoker-tests/0.0.0")
            .build()
            .unwrap(),
    )
}

/// Supplies a small valid complete OneCRL changeset.
fn onecrl() -> &'static [u8] {
    br#"{"metadata":{},"timestamp":1,"changes":[]}"#
}

/// Creates one matching Omaha application around supplied update attributes.
fn metadata(attributes: &str) -> Vec<u8> {
    format!(
        r#"<gupdate xmlns="http://www.google.com/update2/response"><app appid="{CRLSET_COMPONENT_ID}" status="ok"><updatecheck {attributes}/></app></gupdate>"#
    )
    .into_bytes()
}

/// Valid changeset responses pass through the HTTP layer and parser.
#[test]
fn downloads_onecrl_changeset() {
    let (url, handle) = server(response("200 OK", "", onecrl()));
    assert!(downloader().fetch_onecrl_from(&url).is_ok());
    handle.join().unwrap();
}

/// HTTP failures are reported before attempting JSON parsing.
#[test]
fn rejects_http_error_status() {
    let (url, handle) = server(response("404 Not Found", "", b"not json"));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url),
        Err(Error::Http(_))
    ));
    handle.join().unwrap();
}

/// Oversized Content-Length values fail before body allocation.
#[test]
fn rejects_declared_body_size() {
    let (url, handle) = server(response("200 OK", "Content-Length: 99999\r\n", b""));
    assert!(matches!(
        downloader().with_max_bytes(8).fetch_onecrl_from(&url),
        Err(Error::SizeLimit(8))
    ));
    handle.join().unwrap();
}

/// Responses without a declared length remain bounded while reading.
#[test]
fn rejects_actual_body_size() {
    let (url, handle) = server(response("200 OK", "", b"123456789"));
    assert!(matches!(
        downloader().with_max_bytes(8).fetch_onecrl_from(&url),
        Err(Error::SizeLimit(8))
    ));
    handle.join().unwrap();
}

/// Backoff on a successful response blocks a later request locally.
#[test]
fn retains_backoff_after_success() {
    let (url, handle) = server(response("200 OK", "Backoff: 600\r\n", onecrl()));
    let downloader = downloader();
    assert!(downloader.fetch_onecrl_from(&url).is_ok());
    handle.join().unwrap();
    assert!(matches!(
        downloader.fetch_onecrl_from(&url),
        Err(Error::Backoff(1..=600))
    ));
}

/// Server backoff is retained even when HTTP status validation fails.
#[test]
fn retains_backoff_after_error() {
    let (url, handle) = server(response(
        "429 Too Many Requests",
        "Backoff: 600\r\n",
        b"slow down",
    ));
    let downloader = downloader();
    assert!(matches!(
        downloader.fetch_onecrl_from(&url),
        Err(Error::Http(_))
    ));
    handle.join().unwrap();
    assert!(matches!(
        downloader.fetch_onecrl_from(&url),
        Err(Error::Backoff(1..=600))
    ));
}

/// Truncated bodies fail as transport reads instead of producing data.
#[test]
fn rejects_truncated_response_body() {
    let (url, handle) = server(response("200 OK", "Content-Length: 100\r\n", b"{}"));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url),
        Err(Error::Io(_))
    ));
    handle.join().unwrap();
}

/// Omaha responses for other applications cannot choose the component URL.
#[test]
fn rejects_unrelated_update_application() {
    let body = br#"<gupdate><app appid="wrong" status="ok"/></gupdate>"#;
    let (url, handle) = server(response("200 OK", "", body));
    assert!(matches!(
        downloader().fetch_crlset_from(&url),
        Err(Error::InvalidFormat(
            "update response has no CRLSet component"
        ))
    ));
    handle.join().unwrap();
}

/// Malformed update documents produce XML errors before component fetching.
#[test]
fn rejects_malformed_update_xml() {
    assert!(component_download(b"<gupdate><app", 100).is_err());
}

/// HTTPS, mandatory hashes, byte caps, and successful statuses are required.
#[test]
fn validates_update_metadata() {
    let digest = "00".repeat(32);
    let valid = format!(
        r#"status="ok" codebase="https://example.com/component.crx3" hash_sha256="{digest}" size="3""#
    );
    let component = component_download(&metadata(&valid), 100).unwrap();
    assert_eq!(component.sha256, [0; 32]);
    assert_eq!(component.size, 3);
    assert!(matches!(
        component_download(&metadata(&valid), 2),
        Err(Error::SizeLimit(2))
    ));
    for invalid in [
        valid.replace("https:", "http:"),
        valid.replace("https://", "https://user:password@"),
        valid.replace("status=\"ok\"", "status=\"noupdate\""),
        valid.replace(&format!(r#"hash_sha256="{digest}" "#), ""),
        valid.replace(&digest, "invalid hash"),
        valid.replace("size=\"3\"", ""),
    ] {
        assert!(component_download(&metadata(&invalid), 100).is_err());
    }
}

/// Archive bytes must match both the expected digest and exact byte count.
#[test]
fn validates_component_hash_and_size() {
    let component = ComponentDownload {
        url: reqwest::Url::parse("https://example.com/component.crx3").unwrap(),
        sha256: Sha256::digest(b"abc").into(),
        size: 3,
    };
    assert!(validate_download(b"abc", &component).is_ok());
    assert!(matches!(
        validate_download(b"abd", &component),
        Err(Error::HashMismatch)
    ));
    assert!(matches!(
        validate_download(b"ab", &component),
        Err(Error::InvalidFormat(_))
    ));
}

/// Digest parsing supports uppercase hex and rejects non-ASCII digits.
#[test]
fn validates_hexadecimal_hashes() {
    assert_eq!(parse_sha256(&"aF".repeat(32)).unwrap(), [0xaf; 32]);
    assert!(parse_sha256(&"é".repeat(32)).is_err());
    assert!(parse_sha256(&"z0".repeat(32)).is_err());
}
