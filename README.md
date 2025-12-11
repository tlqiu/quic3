# quic3

A Rust nightly demo for efficient and reliable file transfer between clusters over QUIC using [`s2n-quic`](https://github.com/aws/s2n-quic).

## Prerequisites
- Rust nightly toolchain (pinned via `rust-toolchain.toml`).

## Running the server
```bash
cargo run --bin server -- --addr 0.0.0.0:4433 --cert certs/server-cert.pem --key certs/server-key.pem --output received
```
The server automatically generates a self-signed certificate and private key if they do not exist and stores received files in the `received` directory.

## Sending a file from the client
```bash
cargo run --bin client -- --server 127.0.0.1:4433 --server-name localhost --ca-cert certs/server-cert.pem --file path/to/data.bin
```
The client validates the server using the provided certificate and transmits the file over a bidirectional QUIC stream.
