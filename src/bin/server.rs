use anyhow::Result;
use clap::Parser;
use quic3::{FileHeader, ensure_self_signed_certificate, sanitize_file_name, try_decode_header};
use s2n_quic::Server;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
struct Args {
    /// Address to listen on (e.g. 0.0.0.0:4433)
    #[arg(long, default_value = "0.0.0.0:4433")]
    addr: SocketAddr,

    /// Path to the TLS certificate. Generated automatically if missing.
    #[arg(long, default_value = "certs/server-cert.pem")]
    cert: PathBuf,

    /// Path to the TLS private key. Generated automatically if missing.
    #[arg(long, default_value = "certs/server-key.pem")]
    key: PathBuf,

    /// Directory where received files will be written.
    #[arg(long, default_value = "received")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    fs::create_dir_all(&args.output).await?;
    let output_dir = Arc::new(args.output);
    let (cert_path, key_path) =
        ensure_self_signed_certificate(&args.cert, &args.key, &["localhost", "127.0.0.1"])?;

    let mut server = Server::builder()
        .with_tls((cert_path.as_path(), key_path.as_path()))?
        .with_io(args.addr)?
        .start()?;

    println!("Server listening on {}", args.addr);

    while let Some(mut connection) = server.accept().await {
        let output_dir = Arc::clone(&output_dir);
        tokio::spawn(async move {
            let remote_addr = match connection.remote_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    eprintln!("Failed to read peer address: {err}");
                    return;
                }
            };

            println!("Accepted connection from {remote_addr}");
            while let Ok(Some(stream)) = connection.accept_bidirectional_stream().await {
                let output_dir = Arc::clone(&output_dir);
                tokio::spawn(handle_stream(stream, remote_addr, output_dir));
            }
        });
    }

    Ok(())
}

async fn handle_stream(
    mut stream: s2n_quic::stream::BidirectionalStream,
    remote_addr: SocketAddr,
    output_dir: Arc<PathBuf>,
) {
    let mut buffer = Vec::new();
    let header: FileHeader;
    let consumed: usize;

    loop {
        match stream.receive().await {
            Ok(Some(data)) => {
                buffer.extend_from_slice(&data);
                if let Some((parsed, used)) = try_decode_header(&buffer) {
                    header = parsed;
                    consumed = used;
                    break;
                }
            }
            Ok(None) => {
                eprintln!("[{remote_addr}] connection closed before header received");
                return;
            }
            Err(err) => {
                eprintln!("[{remote_addr}] failed to read stream: {err}");
                return;
            }
        }
    }

    let safe_name = sanitize_file_name(&header.file_name);
    let target_path = output_dir.join(safe_name);
    if let Err(err) = receive_file(stream, target_path, header, buffer, consumed, remote_addr).await
    {
        eprintln!("[{remote_addr}] failed to store file: {err}");
    }
}

async fn receive_file(
    mut stream: s2n_quic::stream::BidirectionalStream,
    target_path: PathBuf,
    header: FileHeader,
    buffer: Vec<u8>,
    consumed: usize,
    remote_addr: SocketAddr,
) -> Result<()> {
    let mut file = File::create(&target_path).await?;
    let mut written: u64 = 0;

    if buffer.len() > consumed {
        let remaining = &buffer[consumed..];
        file.write_all(remaining).await?;
        written += remaining.len() as u64;
    }

    while let Some(chunk) = stream.receive().await? {
        file.write_all(&chunk).await?;
        written += chunk.len() as u64;
    }

    file.flush().await?;

    if written == header.file_size {
        println!(
            "[{remote_addr}] received '{}' ({} bytes) at {}",
            header.file_name,
            header.file_size,
            target_path.display()
        );
    } else {
        eprintln!(
            "[{remote_addr}] warning: expected {} bytes for '{}' but wrote {}",
            header.file_size, header.file_name, written
        );
    }

    Ok(())
}
