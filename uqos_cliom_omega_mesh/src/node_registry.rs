use crate::protocol::{unix_time_ms, TelemetryEnvelope};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;

const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Deserialize)]
struct NodeAllowlist {
    nodes: HashMap<String, String>,
}

pub struct NodeRegistry {
    authorized: Arc<HashMap<String, String>>,
    sequences: Mutex<HashMap<String, u64>>,
    sequence_path: PathBuf,
}

impl NodeRegistry {
    pub fn load(
        allowlist_path: impl AsRef<Path>,
        sequence_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let allowlist_bytes = fs::read(allowlist_path.as_ref())
            .with_context(|| format!("cannot read node allowlist {}", allowlist_path.as_ref().display()))?;
        let allowlist: NodeAllowlist = serde_json::from_slice(&allowlist_bytes)
            .context("invalid node allowlist JSON")?;
        if allowlist.nodes.is_empty() {
            bail!("node allowlist is empty; provision and authorize at least one node");
        }
        for (node_id, public_key) in &allowlist.nodes {
            if node_id.is_empty() || node_id.len() > 64 {
                bail!("invalid node identifier in allowlist");
            }
            let bytes = hex::decode(public_key)
                .with_context(|| format!("invalid public key for node {node_id}"))?;
            if bytes.len() != 32 {
                bail!("public key for node {node_id} must be 32 bytes");
            }
        }

        let sequence_path = sequence_path.as_ref().to_path_buf();
        let sequences = if sequence_path.exists() {
            serde_json::from_slice(&fs::read(&sequence_path)?)
                .context("invalid persisted node sequence state")?
        } else {
            HashMap::new()
        };

        Ok(Self {
            authorized: Arc::new(allowlist.nodes),
            sequences: Mutex::new(sequences),
            sequence_path,
        })
    }

    pub async fn verify_and_record(&self, envelope: &TelemetryEnvelope) -> Result<()> {
        let trusted_key = self.authorized.get(&envelope.node_id)
            .ok_or_else(|| anyhow!("node is not on the authorized allowlist"))?;

        if !valid_node_id(&envelope.node_id) {
            bail!("invalid node identifier");
        }
        if envelope.sequence == 0 {
            bail!("sequence number must be positive");
        }
        if envelope.message.len() > 4096 {
            bail!("message exceeds 4096-byte limit");
        }
        if envelope.frequency_tag.as_ref().is_some_and(|tag| tag.len() > 32) {
            bail!("frequency tag exceeds 32-byte limit");
        }

        let now = unix_time_ms()?;
        if now.abs_diff(envelope.timestamp_unix_ms) > MAX_CLOCK_SKEW_MS {
            bail!("telemetry timestamp is outside the allowed clock-skew window");
        }
        if !envelope.verify_signature(trusted_key) {
            bail!("node signature verification failed");
        }

        let mut sequences = self.sequences.lock().await;
        let previous = sequences.get(&envelope.node_id).copied().unwrap_or(0);
        if envelope.sequence <= previous {
            bail!("replayed or out-of-order node sequence");
        }

        let mut updated = sequences.clone();
        updated.insert(envelope.node_id.clone(), envelope.sequence);
        if let Some(parent) = self.sequence_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let temp_path = self.sequence_path.with_extension("tmp");
        tokio::fs::write(&temp_path, serde_json::to_vec(&updated)?).await?;
        tokio::fs::rename(&temp_path, &self.sequence_path).await?;
        *sequences = updated;
        Ok(())
    }
}

fn valid_node_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::NodeRegistry;
    use crate::protocol::{unix_time_ms, TelemetryEnvelope};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn test_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir().join(format!("cliom-registry-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        (root.join("nodes.json"), root.join("state/sequences.json"))
    }

    #[tokio::test]
    async fn allowlisted_signed_node_is_accepted_once_and_replay_is_rejected() {
        let (allowlist_path, sequence_path) = test_paths();
        let key = SigningKey::generate(&mut OsRng);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        fs::write(
            &allowlist_path,
            serde_json::json!({"nodes":{"node-1":public_key}}).to_string(),
        ).unwrap();
        let registry = NodeRegistry::load(&allowlist_path, &sequence_path).unwrap();
        let envelope = TelemetryEnvelope::sign(
            "node-1", 1, unix_time_ms().unwrap(), Some("963Hz".into()), "test packet", &key,
        ).unwrap();

        assert!(registry.verify_and_record(&envelope).await.is_ok());
        assert!(registry.verify_and_record(&envelope).await.is_err());

        let restored = NodeRegistry::load(&allowlist_path, &sequence_path).unwrap();
        assert!(restored.verify_and_record(&envelope).await.is_err());
        let _ = fs::remove_dir_all(allowlist_path.parent().unwrap());
    }

    #[tokio::test]
    async fn unauthorized_key_is_rejected() {
        let (allowlist_path, sequence_path) = test_paths();
        let allowed = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        fs::write(
            &allowlist_path,
            serde_json::json!({"nodes":{"node-1":hex::encode(allowed.verifying_key().to_bytes())}}).to_string(),
        ).unwrap();
        let registry = NodeRegistry::load(&allowlist_path, &sequence_path).unwrap();
        let envelope = TelemetryEnvelope::sign(
            "node-1", 1, unix_time_ms().unwrap(), None, "forged sender", &attacker,
        ).unwrap();
        assert!(registry.verify_and_record(&envelope).await.is_err());
        let _ = fs::remove_dir_all(allowlist_path.parent().unwrap());
    }
}
