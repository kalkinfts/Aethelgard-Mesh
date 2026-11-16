use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{fs::File, io::BufReader, path::Path};

pub fn load_certificates(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("cannot open certificate file {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse PEM certificates")?;
    if certs.is_empty() {
        return Err(anyhow!("certificate file contains no certificates"));
    }
    Ok(certs)
}

pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path.as_ref())
        .with_context(|| format!("cannot open private-key file {}", path.as_ref().display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .context("failed to parse PEM private key")?
        .ok_or_else(|| anyhow!("private-key file contains no supported key"))
}
