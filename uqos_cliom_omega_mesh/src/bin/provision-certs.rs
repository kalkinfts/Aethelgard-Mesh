use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use std::{fs, path::Path};

#[derive(Serialize)]
struct NodeAllowlist<'a> {
    nodes: std::collections::BTreeMap<&'a str, String>,
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
    let server_name = std::env::args().nth(1).unwrap_or_else(|| "localhost".into());
    if server_name.trim().is_empty() {
        bail!("server DNS name cannot be empty");
    }

    let cert_dir = Path::new("certs");
    fs::create_dir_all(cert_dir)?;
    if cert_dir.join("ca.pem").exists() {
        bail!("certificates already exist; back them up before provisioning a new identity set");
    }

    let ca_key = KeyPair::generate().context("could not generate CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).context("could not create local CA certificate")?;

    let server_key = KeyPair::generate().context("could not generate server key")?;
    let mut server_params = CertificateParams::new(vec![
        server_name.clone(),
        "localhost".into(),
        "127.0.0.1".into(),
    ])?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("could not sign server certificate")?;

    let client_key = KeyPair::generate().context("could not generate client TLS key")?;
    let mut client_params = CertificateParams::new(vec!["cliom-node-1".into()])?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("could not sign client certificate")?;

    let node_signing_key = SigningKey::generate(&mut OsRng);
    let node_public_key = hex::encode(node_signing_key.verifying_key().to_bytes());

    fs::write(cert_dir.join("ca.pem"), ca_cert.pem())?;
    write_private(&cert_dir.join("ca-key.pem"), &ca_key.serialize_pem())?;
    fs::write(cert_dir.join("server.pem"), server_cert.pem())?;
    write_private(&cert_dir.join("server-key.pem"), &server_key.serialize_pem())?;
    fs::write(cert_dir.join("client.pem"), client_cert.pem())?;
    write_private(&cert_dir.join("client-key.pem"), &client_key.serialize_pem())?;
    write_private(
        &cert_dir.join("node-signing.key"),
        &hex::encode(node_signing_key.to_bytes()),
    )?;
    fs::write(cert_dir.join("node-signing.pub"), format!("{node_public_key}\n"))?;

    let mut nodes = std::collections::BTreeMap::new();
    nodes.insert("cliom-node-1", node_public_key);
    let allowlist = NodeAllowlist { nodes };
    fs::write("authorized_nodes.json", serde_json::to_vec_pretty(&allowlist)?)?;

    println!("Provisioned a local CA, server certificate, and one mTLS client identity.");
    println!("Server name: {server_name}");
    println!("Node ID: cliom-node-1");
    println!("Copy certs/ca.pem, certs/client.pem, certs/client-key.pem, and certs/node-signing.key securely to the authorized mobile node.");
    println!("Never share certs/ca-key.pem, certs/server-key.pem, or the node signing key.");
    Ok(())
}
