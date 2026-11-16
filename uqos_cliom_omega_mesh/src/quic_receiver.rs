use crate::{
    node_registry::NodeRegistry,
    protocol::{unix_time_ms, TelemetryEnvelope, TelemetryEvent},
    tls::{load_certificates, load_private_key},
};
use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig};
use rustls::{
    pki_types::CertificateDer,
    server::WebPkiClientVerifier,
    RootCertStore,
};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::sync::broadcast;

const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_UNI_STREAMS_PER_CONNECTION: u32 = 16;

pub async fn start_uqos_quic_receiver(
    bind_address: SocketAddr,
    server_cert_path: impl AsRef<Path>,
    server_key_path: impl AsRef<Path>,
    client_ca_path: impl AsRef<Path>,
    registry: Arc<NodeRegistry>,
    telemetry_tx: broadcast::Sender<String>,
) -> Result<()> {
    let cert_chain: Vec<CertificateDer<'static>> = load_certificates(server_cert_path)?;
    let private_key = load_private_key(server_key_path)?;
    let client_ca_certs = load_certificates(client_ca_path)?;

    let mut roots = RootCertStore::empty();
    for cert in client_ca_certs {
        roots.add(cert).context("failed to add client CA certificate")?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to configure mandatory client-certificate verification")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .context("invalid server certificate or private key")?;
    tls_config.alpn_protocols = vec![b"uqos-cliom/1".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .context("failed to adapt rustls configuration for QUIC")?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .expect("new QUIC server config has unique transport ownership");
    transport.max_concurrent_uni_streams(MAX_UNI_STREAMS_PER_CONNECTION.into());
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(60))
            .context("invalid QUIC idle timeout")?,
    ));

    let endpoint = Endpoint::server(server_config, bind_address)
        .with_context(|| format!("failed to bind QUIC endpoint at {bind_address}"))?;
    log::info!("CLIOM authenticated QUIC receiver listening on {bind_address} (UDP)");

    while let Some(incoming) = endpoint.accept().await {
        let registry = Arc::clone(&registry);
        let telemetry_tx = telemetry_tx.clone();
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(error) => {
                    publish_event(
                        &telemetry_tx,
                        rejected_event("unknown".into(), format!("QUIC handshake rejected: {error}")),
                    );
                    return;
                }
            };

            let remote_address = connection.remote_address().to_string();
            log::info!("Authenticated CLIOM node connected from {remote_address}");
            publish_event(
                &telemetry_tx,
                TelemetryEvent {
                    status: "connected".into(),
                    received_at_unix_ms: unix_time_ms().unwrap_or_default(),
                    node_id: None,
                    sequence: None,
                    remote_address: remote_address.clone(),
                    frequency_tag: None,
                    message: "Mutual TLS handshake accepted".into(),
                },
            );

            while let Ok(stream) = connection.accept_uni().await {
                let registry = Arc::clone(&registry);
                let telemetry_tx = telemetry_tx.clone();
                let remote_address = remote_address.clone();
                tokio::spawn(async move {
                    process_stream(stream, registry, telemetry_tx, remote_address).await;
                });
            }

            log::info!("CLIOM QUIC connection closed: {remote_address}");
        });
    }

    Ok(())
}

async fn process_stream(
    mut stream: quinn::RecvStream,
    registry: Arc<NodeRegistry>,
    telemetry_tx: broadcast::Sender<String>,
    remote_address: String,
) {
    let bytes = match stream.read_to_end(MAX_FRAME_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            publish_event(
                &telemetry_tx,
                rejected_event(remote_address, format!("stream rejected or exceeded {MAX_FRAME_BYTES}-byte limit: {error}")),
            );
            return;
        }
    };

    let envelope: TelemetryEnvelope = match serde_json::from_slice(&bytes) {
        Ok(envelope) => envelope,
        Err(error) => {
            publish_event(
                &telemetry_tx,
                rejected_event(remote_address, format!("invalid telemetry envelope: {error}")),
            );
            return;
        }
    };

    match registry.verify_and_record(&envelope).await {
        Ok(()) => {
            let event = TelemetryEvent {
                status: "verified".into(),
                received_at_unix_ms: unix_time_ms().unwrap_or_default(),
                node_id: Some(envelope.node_id),
                sequence: Some(envelope.sequence),
                remote_address,
                frequency_tag: envelope.frequency_tag,
                message: envelope.message,
            };
            publish_event(&telemetry_tx, event);
        }
        Err(error) => {
            publish_event(
                &telemetry_tx,
                rejected_event(remote_address, format!("ONTOPOLICE policy rejection: {error}")),
            );
        }
    }
}

fn rejected_event(remote_address: String, message: String) -> TelemetryEvent {
    TelemetryEvent {
        status: "rejected".into(),
        received_at_unix_ms: unix_time_ms().unwrap_or_default(),
        node_id: None,
        sequence: None,
        remote_address,
        frequency_tag: None,
        message,
    }
}

fn publish_event(tx: &broadcast::Sender<String>, event: TelemetryEvent) {
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = tx.send(json);
    }
}
