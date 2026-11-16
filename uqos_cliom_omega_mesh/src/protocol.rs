use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEnvelope {
    pub version: u8,
    pub node_id: String,
    pub sequence: u64,
    pub timestamp_unix_ms: u64,
    pub frequency_tag: Option<String>,
    pub message: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize)]
struct SigningPayload<'a> {
    version: u8,
    node_id: &'a str,
    sequence: u64,
    timestamp_unix_ms: u64,
    frequency_tag: Option<&'a str>,
    message: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryAck {
    pub accepted: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    pub status: String,
    pub received_at_unix_ms: u64,
    pub node_id: Option<String>,
    pub sequence: Option<u64>,
    pub remote_address: String,
    pub frequency_tag: Option<String>,
    pub message: String,
}

impl TelemetryEnvelope {
    pub fn sign(
        node_id: impl Into<String>,
        sequence: u64,
        timestamp_unix_ms: u64,
        frequency_tag: Option<String>,
        message: impl Into<String>,
        key: &SigningKey,
    ) -> Result<Self, serde_json::Error> {
        let node_id = node_id.into();
        let message = message.into();
        let payload = SigningPayload {
            version: 1,
            node_id: &node_id,
            sequence,
            timestamp_unix_ms,
            frequency_tag: frequency_tag.as_deref(),
            message: &message,
        };
        let bytes = serde_json::to_vec(&payload)?;
        let signature = key.sign(&bytes);
        Ok(Self {
            version: 1,
            node_id,
            sequence,
            timestamp_unix_ms,
            frequency_tag,
            message,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    pub fn verify_signature(&self, trusted_public_key_hex: &str) -> bool {
        if self.public_key_hex != trusted_public_key_hex
            || self.version != 1
            || self.node_id.is_empty()
            || self.node_id.len() > 64
            || self.sequence == 0
            || self.message.len() > 4096
            || self.frequency_tag.as_ref().is_some_and(|tag| tag.len() > 32)
        {
            return false;
        }

        let Ok(public_key_bytes) = hex::decode(trusted_public_key_hex) else {
            return false;
        };
        let Ok(public_key_array) = <[u8; 32]>::try_from(public_key_bytes.as_slice()) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key_array) else {
            return false;
        };
        let Ok(signature_bytes) = hex::decode(&self.signature_hex) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            return false;
        };

        let payload = SigningPayload {
            version: self.version,
            node_id: &self.node_id,
            sequence: self.sequence,
            timestamp_unix_ms: self.timestamp_unix_ms,
            frequency_tag: self.frequency_tag.as_deref(),
            message: &self.message,
        };
        let Ok(bytes) = serde_json::to_vec(&payload) else {
            return false;
        };
        verifying_key.verify_strict(&bytes, &signature).is_ok()
    }
}

pub fn unix_time_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::{unix_time_ms, TelemetryEnvelope};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn signed_telemetry_verifies_against_pinned_key() {
        let key = SigningKey::generate(&mut OsRng);
        let record = TelemetryEnvelope::sign(
            "node-1", 1, unix_time_ms().unwrap(), Some("963Hz".into()), "hello", &key,
        ).unwrap();
        let public_key = hex::encode(key.verifying_key().to_bytes());
        assert!(record.verify_signature(&public_key));
    }

    #[test]
    fn tampered_message_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut record = TelemetryEnvelope::sign(
            "node-1", 1, unix_time_ms().unwrap(), None, "original", &key,
        ).unwrap();
        record.message = "tampered".into();
        assert!(!record.verify_signature(&hex::encode(key.verifying_key().to_bytes())));
    }

    #[test]
    fn a_different_node_key_is_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let record = TelemetryEnvelope::sign(
            "node-1", 1, unix_time_ms().unwrap(), None, "hello", &key,
        ).unwrap();
        assert!(!record.verify_signature(&hex::encode(other.verifying_key().to_bytes())));
    }
}
