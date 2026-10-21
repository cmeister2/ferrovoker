//! Command-line downloads of Mozilla OneCRL and Chrome CRLSets.

use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, Subcommand};
use ferrovoker::Downloader;

/// Download browser revocation feeds as JSON or unpacked binary data.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    long_about = "Download Mozilla OneCRL and Chrome CRLSets. Chrome CRX3 signatures are verified against the pinned CRLSet publisher key. Mozilla OneCRL content signatures are not verified. Downloads do not perform certificate validation."
)]
struct Arguments {
    /// Maximum downloaded or extracted size in bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024, global = true)]
    max_bytes: u64,
    /// Total timeout for each HTTP request in seconds.
    #[arg(long, default_value_t = 60, global = true)]
    timeout: u64,
    /// Feed to download.
    #[command(subcommand)]
    command: Command,
}

/// Supported revocation feed downloads.
#[derive(Debug, Subcommand)]
enum Command {
    /// Download a complete Mozilla OneCRL changeset as JSON.
    Onecrl {
        /// Destination file; omit to write JSON to standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Download and unpack Chrome's full CRLSet as binary data.
    Crlset {
        /// Destination file; omit to write binary data to standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

/// Run the CLI, printing download failures to standard error.
fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ferrovoker: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Fetch the requested artifact before opening its destination.
///
/// # Errors
///
/// Returns errors for client construction, download/format failures, JSON
/// serialization, or writing the destination file or standard output.
fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("ferrovoker/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .retry(reqwest::retry::never())
        .gzip(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(arguments.timeout))
        .build()?;
    let downloader = Downloader::with_client(client).with_max_bytes(arguments.max_bytes);
    let (bytes, output) = match arguments.command {
        Command::Onecrl { output } => {
            let snapshot = downloader.fetch_onecrl()?;
            eprintln!(
                "Downloaded {} OneCRL records (timestamp {})",
                snapshot.changes.len(),
                snapshot.timestamp
            );
            let mut bytes = serde_json::to_vec_pretty(&snapshot)?;
            bytes.push(b'\n');
            (bytes, output)
        }
        Command::Crlset { output } => {
            let snapshot = downloader.fetch_crlset()?;
            eprintln!(
                "Downloaded CRLSet sequence {} ({} bytes)",
                snapshot.header.sequence,
                snapshot.bytes.len()
            );
            (snapshot.bytes, output)
        }
    };
    if let Some(path) = output {
        std::fs::write(path, bytes)?;
    } else {
        io::stdout().lock().write_all(&bytes)?;
    }
    Ok(())
}
