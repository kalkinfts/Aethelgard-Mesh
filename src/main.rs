use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{env, time::Instant};

use aethelgard_mesh::shortest_path;

#[derive(Debug, Deserialize)]
struct ExecuteRequest {
    graph: Vec<Vec<u64>>,
    start: usize,
    end: usize,
}

#[derive(Serialize)]
struct ExecuteResponse {
    distance: Option<u64>,
    execution_time_ms: f64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn health() -> &'static str {
    "ok"
}

async fn execute(Json(request): Json<ExecuteRequest>) -> Response {
    let started = Instant::now();

    match shortest_path(&request.graph, request.start, request.end) {
        Ok(distance) => (
            StatusCode::OK,
            Json(ExecuteResponse {
                distance,
                execution_time_ms: started.elapsed().as_secs_f64() * 1_000.0,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.to_string(),
            }),
        )
            .into_response(),
    }
}

fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/execute", post(execute))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = env::var("AETHELGARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&address).await?;

    println!("Aethelgard Mesh listening on http://{address}");
    axum::serve(listener, app()).await?;

    Ok(())
}
