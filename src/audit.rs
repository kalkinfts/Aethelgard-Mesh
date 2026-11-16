use aethelgard_mesh::crypto::{ExecutionManifest, SignedExecution};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{fs, path::{Path, PathBuf}};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    last_record_sha256: Option<String>,
}

impl AuditLog {
    /// Opens an append-only JSONL audit file and verifies its existing chain.
    pub fn open(path: impl AsRef<Path>, key: &VerifyingKey) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let path = path.as_ref().to_path_buf();
        let mut last_record_sha256: Option<String> = None;
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let trusted_key = hex::encode(key.to_bytes());
            for (line_number, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    return Err(format!("empty audit record at line {}", line_number + 1).into());
                }
                let record: SignedExecution = serde_json::from_str(line)?;
                if record.manifest.previous_record_sha256 != last_record_sha256 {
                    return Err(format!("audit chain link mismatch at line {}", line_number + 1).into());
                }
                if !record.verify_with_trusted_key(&trusted_key) {
                    return Err(format!("invalid audit signature or digest at line {}", line_number + 1).into());
                }
                last_record_sha256 = Some(record.record_sha256);
            }
        }
        Ok(Self { path, last_record_sha256 })
    }

    pub async fn append(
        &mut self,
        mut manifest: ExecutionManifest,
        key: &SigningKey,
    ) -> Result<SignedExecution, Box<dyn std::error::Error + Send + Sync>> {
        manifest.previous_record_sha256 = self.last_record_sha256.clone();
        let record = SignedExecution::sign(manifest, key)?;
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path).await?;
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        file.write_all(&line).await?;
        file.sync_data().await?;
        self.last_record_sha256 = Some(record.record_sha256.clone());
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::AuditLog;
    use aethelgard_mesh::crypto::ExecutionManifest;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};

    fn temp_path() -> std::path::PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("aethelgard-audit-{}-{nonce}.jsonl", std::process::id()))
    }

    fn manifest(id: &str) -> ExecutionManifest {
        ExecutionManifest {
            schema_version: 1,
            execution_id: id.into(),
            created_at_unix_ms: 1,
            policy_version: "aethelgard.policy.v1".into(),
            operation: "graph.shortest_path".into(),
            input_sha256: "test".into(),
            result: Some(12),
            previous_record_sha256: None,
        }
    }

    #[tokio::test]
    async fn appends_and_reopens_a_verified_chain() {
        let path = temp_path();
        let key = SigningKey::generate(&mut OsRng);
        let mut log = AuditLog::open(&path, &key.verifying_key()).unwrap();
        let first = log.append(manifest("one"), &key).await.unwrap();
        let second = log.append(manifest("two"), &key).await.unwrap();
        assert_eq!(second.manifest.previous_record_sha256.as_deref(), Some(first.record_sha256.as_str()));
        drop(log);
        assert!(AuditLog::open(&path, &key.verifying_key()).is_ok());
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn rejects_tampered_existing_record() {
        let path = temp_path();
        let key = SigningKey::generate(&mut OsRng);
        let mut log = AuditLog::open(&path, &key.verifying_key()).unwrap();
        log.append(manifest("one"), &key).await.unwrap();
        drop(log);
        let contents = fs::read_to_string(&path).unwrap().replace("\"result\":12", "\"result\":13");
        fs::write(&path, contents).unwrap();
        assert!(AuditLog::open(&path, &key.verifying_key()).is_err());
        let _ = fs::remove_file(path);
    }
}
