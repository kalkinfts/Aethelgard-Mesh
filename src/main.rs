mod audit;
mod crypto;

use audit::AuditLog;
use axum::{
    extract::{DefaultBodyLimit, Json, Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use crypto::{sha256_hex, ExecutionManifest, SignedExecution};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use aethelgard_mesh::shortest_path;

const POLICY_VERSION: &str = "aethelgard.policy.v1";

#[derive(Clone)]
struct AppState {
    signing_key: Arc<SigningKey>,
    audit: Arc<Mutex<AuditLog>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExecuteRequest {
    graph: Vec<Vec<u64>>,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct ExecuteResponse {
    distance: Option<u64>,
    execution: SignedExecution,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    execution: SignedExecution,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    trust_note: &'static str,
}

async fn health() -> &'static str {
    "ok"
}

async fn public_key(State(state): State<AppState>) -> String {
    hex::encode(state.signing_key.verifying_key().to_bytes())
}

async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    let trusted_key = hex::encode(state.signing_key.verifying_key().to_bytes());
    Json(VerifyResponse {
        valid: request.execution.verify_with_trusted_key(&trusted_key),
        trust_note: "Verification uses this node's configured public key. Distribute and pin that key through a trusted channel.",
    })
}

async fn execute(
    State(state): State<AppState>,
    Json(request): Json<ExecuteRequest>,
) -> Response {
    let input = match serde_json::to_vec(&request) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() })).into_response();
        }
    };

    let distance = match shortest_path(&request.graph, request.start, request.end) {
        Ok(distance) => distance,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() })).into_response();
        }
    };

    let created_at_unix_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: error.to_string() })).into_response();
        }
    };

    let manifest = ExecutionManifest {
        schema_version: 1,
        execution_id: format!("{}-{}", created_at_unix_ms, std::process::id()),
        created_at_unix_ms,
        policy_version: POLICY_VERSION.to_string(),
        operation: "graph.shortest_path".to_string(),
        input_sha256: sha256_hex(&input),
        result: distance,
        previous_record_sha256: None,
    };

    let signed = {
        let mut audit = state.audit.lock().await;
        match audit.append(manifest, &state.signing_key).await {
            Ok(record) => record,
            Err(error) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                    error: format!("audit append failed; execution result not returned: {error}"),
                })).into_response();
            }
        }
    };

    (StatusCode::OK, Json(ExecuteResponse { distance, execution: signed })).into_response()
}

async fn require_bearer(
    State(token): State<Option<Arc<str>>>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(token) = token {
        let supplied = request.headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let expected = format!("Bearer {token}");
        let valid = supplied.len() == expected.len()
            && supplied.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1;
        if !valid {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    next.run(request).await
}

fn load_signing_key() -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    if let Ok(encoded) = env::var("AETHELGARD_SIGNING_KEY") {
        let bytes = hex::decode(encoded.trim())?;
        let seed: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| "AETHELGARD_SIGNING_KEY must decode to exactly 32 bytes")?;
        return Ok(SigningKey::from_bytes(&seed));
    }

    let path = env::var("AETHELGARD_KEY_FILE")
        .unwrap_or_else(|_| ".aethelgard/signing.key".to_string());
    let path = Path::new(&path);

    if path.exists() {
        let encoded = fs::read_to_string(path)?;
        let bytes = hex::decode(encoded.trim())?;
        let seed: [u8; 32] = bytes.as_slice().try_into()
            .map_err(|_| "stored signing key must decode to exactly 32 bytes")?;
        return Ok(SigningKey::from_bytes(&seed));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let key = SigningKey::generate(&mut OsRng);
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let encoded = fs::read_to_string(path)?;
            let bytes = hex::decode(encoded.trim())?;
            let seed: [u8; 32] = bytes.as_slice().try_into()
                .map_err(|_| "stored signing key must decode to exactly 32 bytes")?;
            return Ok(SigningKey::from_bytes(&seed));
        }
        Err(error) => return Err(error.into()),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    file.write_all(hex::encode(key.to_bytes()).as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let address = env::var("AETHELGARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let socket_address: SocketAddr = address.parse()?;
    let api_token = env::var("AETHELGARD_API_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Arc::<str>::from);

    if !socket_address.ip().is_loopback() && api_token.is_none() {
        return Err("refusing non-loopback bind without AETHELGARD_API_TOKEN".into());
    }

    let signing_key = Arc::new(load_signing_key()?);
    let audit_path = env::var("AETHELGARD_AUDIT_FILE")
        .unwrap_or_else(|_| ".aethelgard/audit.jsonl".to_string());
    let audit = AuditLog::open(audit_path, &signing_key.verifying_key())?;

    let state = AppState {
        signing_key,
        audit: Arc::new(Mutex::new(audit)),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/public-key", get(public_key))
        .route("/v1/verify", post(verify))
        .route("/v1/execute", post(execute))
        .with_state(state)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(api_token, require_bearer));

    let listener = tokio::net::TcpListener::bind(socket_address).await?;
    log::info!("Aethelgard Mesh listening on http://{socket_address}");
    log::info!("Policy: {POLICY_VERSION}; signed audit chain loaded");
    axum::serve(listener, app).await?;
    Ok(())
}
