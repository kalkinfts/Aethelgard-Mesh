use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Deserialize, Serialize)]
struct NodeAllowlist {
    nodes: BTreeMap<String, String>,
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn write_private(path: &Path, contents: &str) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let node_id = std::env::args().nth(1)
        .ok_or_else(|| anyhow::anyhow!("Usage: provision-node <node-id>"))?;
    if !valid_node_id(&node_id) {
        bail!("node ID must be 1-64 ASCII letters, digits, hyphens, or underscores");
    }

    let ca_cert_path = Path::new("certs/ca.pem");
    let ca_key_path = Path::new("certs/ca-key.pem");
    let allowlist_path = Path::new("authorized_nodes.json");
    if !ca_cert_path.exists() || !ca_key_path.exists() || !allowlist_path.exists() {
        bail!("run the provision-certs command before provisioning nodes");
    }

    let ca_pem = fs::read_to_string(ca_cert_path)?;
    let ca_key_pem = fs::read_to_string(ca_key_path)?;
    let ca_params = CertificateParams::from_ca_cert_pem(&ca_pem)
        .context("could not load CA certificate parameters")?;
    let ca_key = KeyPair::from_pem(&ca_key_pem)
        .context("could not load CA private key")?;
    let ca_cert = ca_params.self_signed(&ca_key)
        .context("could not reconstruct local CA certificate")?;

    let mut allowlist: NodeAllowlist = serde_json::from_slice(&fs::read(allowlist_path)?)
        .context("invalid node allowlist JSON")?;
    if allowlist.nodes.contains_key(&node_id) {
        bail!("node ID {node_id} is already authorized");
    }

    let mut client_params = CertificateParams::new(vec![node_id.clone()])?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    client_params.use_authority_key_identifier_extension = true;

    let client_key = KeyPair::generate().context("could not generate client TLS key")?;
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("could not sign client certificate")?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let cert_dir = Path::new("certs");
    fs::create_dir_all(cert_dir)?;

    write_private(
        &cert_dir.join(format!("{node_id}-client-key.pem")),
        &client_key.serialize_pem(),
    )?;
    fs::write(cert_dir.join(format!("{node_id}-client.pem")), client_cert.pem())?;
    write_private(
        &cert_dir.join(format!("{node_id}-signing.key")),
        &hex::encode(signing_key.to_bytes()),
    )?;
    fs::write(cert_dir.join(format!("{node_id}-signing.pub")), format!("{public_key}\n"))?;

    allowlist.nodes.insert(node_id.clone(), public_key);
    fs::write(allowlist_path, serde_json::to_vec_pretty(&allowlist)?)?;

    println!("Provisioned mTLS and Ed25519 identity for node {node_id}.");
    println!("Transfer its client certificate, client private key, and signing key securely to that device.");
    println!("The node is now included in authorized_nodes.json.");
    Ok(())
}
