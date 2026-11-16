use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;
use std::{env, net::SocketAddr, path::Path, sync::Arc};
use tokio::io::AsyncWriteExt;
use uqos_cliom_omega_mesh::{
    protocol::{unix_time_ms, TelemetryEnvelope},
    tls::{load_certificates, load_private_key},
};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        bail!("Usage: cliom-send <server-socket-addr> <server-dns-name> <node-id> <sequence> <message>");
    }

    let server_address: SocketAddr = args[1].parse().context("invalid server socket address")?;
    let server_name = &args[2];
    let node_id = &args[3];
    let sequence: u64 = args[4].parse().context("sequence must be a positive integer")?;
    let message = args[5..].join(" ");
    if message.is_empty() {
        bail!("message cannot be empty");
    }

    let ca_path = env::var("CLIOM_CA_CERT").unwrap_or_else(|_| "certs/ca.pem".into());
    let client_cert_path = env::var("CLIOM_CLIENT_CERT").unwrap_or_else(|_| "certs/client.pem".into());
    let client_key_path = env::var("CLIOM_CLIENT_KEY").unwrap_or_else(|_| "certs/client-key.pem".into());
    let node_key_path = env::var("CLIOM_NODE_SIGNING_KEY").unwrap_or_else(|_| "certs/node-signing.key".into());

    let mut roots = RootCertStore::empty();
    for certificate in load_certificates(&ca_path)? {
        roots.add(certificate).context("could not add CA to client trust store")?;
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            load_certificates(&client_cert_path)?,
            load_private_key(&client_key_path)?,
        )
        .context("invalid client certificate or private key")?;

    let mut tls_config = tls_config;
    tls_config.alpn_protocols = vec![b"uqos-cliom/1".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .context("failed to adapt rustls configuration for QUIC")?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));

    let node_seed = hex::decode(std::fs::read_to_string(Path::new(&node_key_path))?.trim())?;
    let node_seed: [u8; 32] = node_seed.as_slice().try_into()
        .map_err(|_| "node signing key must decode to exactly 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&node_seed);
    let frequency_tag = env::var("CLIOM_FREQUENCY_TAG").ok();

    let envelope = TelemetryEnvelope::sign(
        node_id,
        sequence,
        unix_time_ms()?,
        frequency_tag,
        message,
        &signing_key,
    )?;
    let payload = serde_json::to_vec(&envelope)?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint.connect(server_address, server_name)
        .context("could not start QUIC connection")?
        .await
        .context("QUIC connection or mutual TLS authentication failed")?;

    let mut stream = connection.open_uni().await?;
    stream.write_all(&payload).await?;
    stream.finish()?;
    log::info!("Sent signed telemetry sequence {sequence} for node {node_id}");

    connection.close(0_u32.into(), b"telemetry sent");
    endpoint.wait_idle().await;
    Ok(())
}
