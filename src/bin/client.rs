use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use quic3::encode_header;
use s2n_quic::client::{Client, Connect};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, BufReader};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Parser, Debug)]
struct Args {
    /// QUIC server address (e.g. 127.0.0.1:4433)
    #[arg(long, default_value = "127.0.0.1:4433")]
    server: SocketAddr,

    /// Expected server name for TLS validation.
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Path to the server certificate used for validation.
    #[arg(long, default_value = "certs/server-cert.pem")]
    ca_cert: PathBuf,

    /// Path to the file that should be sent.
    #[arg(long)]
    file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    if !args.ca_cert.exists() {
        anyhow::bail!("CA certificate not found at {}", args.ca_cert.display());
    }

    let metadata = fs::metadata(&args.file).await?;
    let file_name = args
        .file
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("file path missing file name"))?
        .to_string_lossy()
        .to_string();

    let header = encode_header(&file_name, metadata.len())?;

    let client = Client::builder()
        .with_tls(args.ca_cert.as_path())?
        .with_io("0.0.0.0:0")?
        .start()?;

    println!(
        "Connecting to {} with server name '{}'...",
        args.server, args.server_name
    );

    let connect = Connect::new(args.server).with_server_name(args.server_name.clone());
    let mut connection = client.connect(connect).await?;

    let mut stream = connection.open_bidirectional_stream().await?;
    stream.send(Bytes::from(header)).await?;

    let mut reader = BufReader::new(fs::File::open(&args.file).await?);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total_sent: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        stream
            .send(Bytes::copy_from_slice(&buffer[..bytes_read]))
            .await?;
        total_sent += bytes_read as u64;
    }

    stream.close().await?;
    println!(
        "Sent '{}' ({} bytes) to {}",
        file_name, total_sent, args.server
    );

    Ok(())
}
