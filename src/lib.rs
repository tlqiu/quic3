use anyhow::{Result, anyhow};
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::fs;
use std::path::{Path, PathBuf};

/// Metadata describing a single file transfer.
pub struct FileHeader {
    pub file_name: String,
    pub file_size: u64,
}

pub const HEADER_PREFIX_LEN: usize = 2 + 8; // name length (u16) + file size (u64)

/// Encode a file header into a length-prefixed buffer.
pub fn encode_header(file_name: &str, file_size: u64) -> Result<Vec<u8>> {
    let name_bytes = file_name.as_bytes();
    if name_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("file name too long"));
    }

    let mut header = Vec::with_capacity(HEADER_PREFIX_LEN + name_bytes.len());
    header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    header.extend_from_slice(&file_size.to_le_bytes());
    header.extend_from_slice(name_bytes);
    Ok(header)
}

/// Attempt to decode a file header from the provided buffer.
pub fn try_decode_header(buf: &[u8]) -> Option<(FileHeader, usize)> {
    if buf.len() < HEADER_PREFIX_LEN {
        return None;
    }

    let name_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let file_size = u64::from_le_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ]);

    if buf.len() < HEADER_PREFIX_LEN + name_len {
        return None;
    }

    let name_bytes = &buf[HEADER_PREFIX_LEN..HEADER_PREFIX_LEN + name_len];
    let file_name = String::from_utf8_lossy(name_bytes).to_string();
    Some((
        FileHeader {
            file_name,
            file_size,
        },
        HEADER_PREFIX_LEN + name_len,
    ))
}

/// Ensure a self-signed certificate exists at the given locations, creating it if needed.
pub fn ensure_self_signed_certificate(
    cert_path: &Path,
    key_path: &Path,
    subject_alt_names: &[&str],
) -> Result<(PathBuf, PathBuf)> {
    if cert_path.exists() && key_path.exists() {
        return Ok((cert_path.to_path_buf(), key_path.to_path_buf()));
    }

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut params = CertificateParams::new(
        subject_alt_names
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<String>>(),
    );
    params.distinguished_name = DistinguishedName::new();

    let cert = Certificate::from_params(params)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    fs::write(cert_path, cert_pem)?;
    fs::write(key_path, key_pem)?;

    Ok((cert_path.to_path_buf(), key_path.to_path_buf()))
}

/// Sanitize a received file name to avoid directory traversal.
pub fn sanitize_file_name(input: &str) -> String {
    Path::new(input)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "received_file".to_string())
}
