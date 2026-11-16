use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionManifest {
    pub schema_version: u32,
    pub execution_id: String,
    pub created_at_unix_ms: u128,
    pub policy_version: String,
    pub operation: String,
    pub input_sha256: String,
    pub result: Option<u64>,
    pub previous_record_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedExecution {
    pub manifest: ExecutionManifest,
    pub record_sha256: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl SignedExecution {
    pub fn sign(manifest: ExecutionManifest, key: &SigningKey) -> Result<Self, serde_json::Error> {
        let canonical = serde_json::to_vec(&manifest)?;
        let record_sha256 = sha256_hex(&canonical);
        let signature = key.sign(record_sha256.as_bytes());
        Ok(Self {
            manifest,
            record_sha256,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    /// Verify against an independently trusted key. Never trust the embedded key alone.
    pub fn verify_with_trusted_key(&self, trusted_public_key_hex: &str) -> bool {
        if self.public_key_hex != trusted_public_key_hex {
            return false;
        }
        let Ok(canonical) = serde_json::to_vec(&self.manifest) else { return false; };
        if sha256_hex(&canonical) != self.record_sha256 { return false; }

        let Ok(public_key_bytes) = hex::decode(trusted_public_key_hex) else { return false; };
        let Ok(public_key_array) = <[u8; 32]>::try_from(public_key_bytes.as_slice()) else { return false; };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_array) else { return false; };
        let Ok(signature_bytes) = hex::decode(&self.signature_hex) else { return false; };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else { return false; };

        verifying_key.verify_strict(self.record_sha256.as_bytes(), &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionManifest, SignedExecution};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn manifest() -> ExecutionManifest {
        ExecutionManifest {
            schema_version: 1,
            execution_id: "test-1".into(),
            created_at_unix_ms: 1,
            policy_version: "aethelgard.policy.v1".into(),
            operation: "graph.shortest_path".into(),
            input_sha256: "abc".into(),
            result: Some(12),
            previous_record_sha256: None,
        }
    }

    #[test]
    fn signed_record_verifies_with_pinned_key() {
        let key = SigningKey::generate(&mut OsRng);
        let record = SignedExecution::sign(manifest(), &key).unwrap();
        assert!(record.verify_with_trusted_key(&hex::encode(key.verifying_key().to_bytes())));
    }

    #[test]
    fn modified_manifest_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut record = SignedExecution::sign(manifest(), &key).unwrap();
        record.manifest.result = Some(999);
        assert!(!record.verify_with_trusted_key(&hex::encode(key.verifying_key().to_bytes())));
    }

    #[test]
    fn a_different_trusted_key_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let record = SignedExecution::sign(manifest(), &key).unwrap();
        assert!(!record.verify_with_trusted_key(&hex::encode(other.verifying_key().to_bytes())));
    }
}
