use anyhow::{bail, Context, Result};
use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::broadcast;
use uqos_cliom_omega_mesh::{
    dashboard::create_dashboard_router,
    node_registry::NodeRegistry,
    quic_receiver::start_uqos_quic_receiver,
};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let dashboard_address: SocketAddr = env::var("UQOS_DASHBOARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .context("invalid UQOS_DASHBOARD_BIND address")?;
    if !dashboard_address.ip().is_loopback() {
        bail!("dashboard must bind to loopback; expose it only through an authenticated TLS reverse proxy");
    }

    let quic_binds = env::var("UQOS_QUIC_BINDS")
        .unwrap_or_else(|_| "0.0.0.0:4433".to_string());
    let quic_addresses: Vec<SocketAddr> = quic_binds
        .split(',')
        .map(|address| address.trim().parse().context("invalid address in UQOS_QUIC_BINDS"))
        .collect::<Result<Vec<_>>>()?;
    if quic_addresses.is_empty() {
        bail!("at least one QUIC bind address is required");
    }

    let server_cert = PathBuf::from(env::var("UQOS_SERVER_CERT").unwrap_or_else(|_| "certs/server.pem".into()));
    let server_key = PathBuf::from(env::var("UQOS_SERVER_KEY").unwrap_or_else(|_| "certs/server-key.pem".into()));
    let client_ca = PathBuf::from(env::var("UQOS_CLIENT_CA").unwrap_or_else(|_| "certs/ca.pem".into()));
    let allowlist = PathBuf::from(env::var("UQOS_NODE_ALLOWLIST").unwrap_or_else(|_| "authorized_nodes.json".into()));
    let sequence_file = PathBuf::from(env::var("UQOS_SEQUENCE_FILE").unwrap_or_else(|_| "state/node-sequences.json".into()));

    let registry = Arc::new(NodeRegistry::load(&allowlist, &sequence_file)?);
    let (telemetry_tx, _) = broadcast::channel::<String>(2048);

    let receiver_registry = Arc::clone(&registry);
    let receiver_tx = telemetry_tx.clone();
    let receiver_task = tokio::spawn(async move {
        let mut receivers = tokio::task::JoinSet::new();
        for address in quic_addresses {
            let registry = Arc::clone(&receiver_registry);
            let tx = receiver_tx.clone();
            let cert = server_cert.clone();
            let key = server_key.clone();
            let ca = client_ca.clone();
            receivers.spawn(async move {
                start_uqos_quic_receiver(address, cert, key, ca, registry, tx).await
            });
        }

        while let Some(result) = receivers.join_next().await {
            match result {
                Ok(Ok(())) => bail!("QUIC receiver stopped unexpectedly"),
                Ok(Err(error)) => return Err(error),
                Err(error) => return Err(error.into()),
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let listener = tokio::net::TcpListener::bind(dashboard_address).await
        .with_context(|| format!("failed to bind dashboard at {dashboard_address}"))?;
    log::info!("CLIOM dashboard listening at http://{dashboard_address}");
    log::info!("Configured QUIC ingress: {quic_binds}");
    log::info!("Mutual TLS and Ed25519 node signatures are mandatory");

    let dashboard = axum::serve(listener, create_dashboard_router(telemetry_tx));
    tokio::select! {
        result = dashboard => result.context("dashboard server failed")?,
        result = receiver_task => match result {
            Ok(Ok(())) => bail!("QUIC receiver supervisor stopped unexpectedly"),
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(error.into()),
        },
    }
    Ok(())
}
