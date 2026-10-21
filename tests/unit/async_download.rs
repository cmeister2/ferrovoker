//! Local HTTP fixtures exercise actual asynchronous response handling.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use super::*;

/// Runs a single-response HTTP server on a local ephemeral port.
fn server(response: Vec<u8>) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("local server binds");
    let url = format!("http://{}/", listener.local_addr().expect("server address"));
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("local client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server timeout");
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

/// Frames a response with arbitrary headers and a close-delimited body.
fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Creates an async test client that permits local HTTP and has a timeout.
fn downloader() -> AsyncDownloader {
    AsyncDownloader::with_client(
        Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .user_agent("ferrovoker-tests/0.0.0")
            .build()
            .expect("test HTTP client"),
    )
    .expect("isolated certificate-chain client")
}

/// Supplies a complete but unsigned OneCRL snapshot.
fn onecrl() -> &'static [u8] {
    br#"{"metadata":{},"timestamp":1,"changes":[]}"#
}

#[tokio::test]
/// Async requests enforce publisher authentication inside Tokio.
async fn rejects_unsigned_onecrl_without_blocking_client() {
    let _production = AsyncDownloader::new().expect("async client inside runtime");
    let (url, handle) = server(response("200 OK", "", onecrl()));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url).await,
        Err(Error::InvalidOneCrlSignature)
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// HTTP failures are returned before attempting JSON parsing.
async fn rejects_http_error_status() {
    let (url, handle) = server(response("404 Not Found", "", b"not JSON"));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url).await,
        Err(Error::Http(_))
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Declared response sizes are checked before reading their bodies.
async fn rejects_declared_body_size() {
    let (url, handle) = server(response("200 OK", "Content-Length: 99999\r\n", b""));
    assert!(matches!(
        downloader().with_max_bytes(8).fetch_onecrl_from(&url).await,
        Err(Error::SizeLimit(8))
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Close-delimited responses remain bounded without a Content-Length.
async fn rejects_actual_body_size() {
    let (url, handle) = server(response("200 OK", "", b"123456789"));
    assert!(matches!(
        downloader().with_max_bytes(8).fetch_onecrl_from(&url).await,
        Err(Error::SizeLimit(8))
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Certificate chains use their own one-megabyte transport bound.
async fn rejects_declared_certificate_chain_size() {
    let declared = MAX_CERTIFICATE_CHAIN_BYTES + 1;
    let (url, handle) = server(response(
        "200 OK",
        &format!("Content-Length: {declared}\r\n"),
        b"",
    ));
    let downloader = downloader();
    assert!(matches!(
        downloader
            .download_with_backoff(
                &downloader.client,
                &url,
                false,
                None,
                false,
                MAX_CERTIFICATE_CHAIN_BYTES as u64,
            )
            .await,
        Err(Error::SizeLimit(limit)) if limit == MAX_CERTIFICATE_CHAIN_BYTES as u64
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Chunked transfer encoding cannot bypass the response-size limit.
async fn rejects_chunked_body_size() {
    let (url, handle) = server(response(
        "200 OK",
        "Transfer-Encoding: chunked\r\n",
        b"9\r\n123456789\r\n0\r\n\r\n",
    ));
    assert!(matches!(
        downloader().with_max_bytes(8).fetch_onecrl_from(&url).await,
        Err(Error::SizeLimit(8))
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Valid chunked bodies are decoded before publisher authentication.
async fn rejects_unsigned_decoded_chunked_body() {
    let mut body = format!("{:x}\r\n", onecrl().len()).into_bytes();
    body.extend_from_slice(onecrl());
    body.extend_from_slice(b"\r\n0\r\n\r\n");
    let (url, handle) = server(response("200 OK", "Transfer-Encoding: chunked\r\n", &body));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url).await,
        Err(Error::InvalidOneCrlSignature)
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Truncated bodies fail as asynchronous transport errors.
async fn rejects_truncated_response_body() {
    let (url, handle) = server(response("200 OK", "Content-Length: 100\r\n", b"{}"));
    assert!(matches!(
        downloader().fetch_onecrl_from(&url).await,
        Err(Error::Http(_))
    ));
    handle.join().expect("server completed");
}

#[tokio::test]
/// Backoff applies after transported and HTTP-error responses.
async fn retains_backoff_after_response_and_error() {
    for status in ["200 OK", "429 Too Many Requests"] {
        let (url, handle) = server(response(status, "Backoff: 600\r\n", onecrl()));
        let downloader = downloader();
        let result = downloader.fetch_onecrl_from(&url).await;
        if status == "200 OK" {
            assert!(matches!(result, Err(Error::InvalidOneCrlSignature)));
        } else {
            assert!(matches!(result, Err(Error::Http(_))));
        }
        handle.join().expect("server completed");
        assert!(matches!(
            downloader.fetch_onecrl_from(&url).await,
            Err(Error::Backoff(1..=600))
        ));
    }
}

#[tokio::test]
/// Unrelated Omaha applications cannot select the downloaded component.
async fn rejects_unrelated_update_application() {
    let body = br#"<gupdate><app appid="wrong" status="ok"/></gupdate>"#;
    let (url, handle) = server(response("200 OK", "", body));
    assert!(matches!(
        downloader().fetch_crlset_from(&url).await,
        Err(Error::InvalidFormat(
            "update response has no CRLSet component"
        ))
    ));
    handle.join().expect("server completed");
}

#[test]
/// Download futures may be moved between Tokio executor threads.
fn download_futures_are_send() {
    /// Requires the future's type to implement Send without executing it.
    fn assert_send<T: Send>(_: T) {}
    let downloader = downloader();
    assert_send(downloader.fetch_onecrl());
    assert_send(downloader.fetch_crlset());
}
