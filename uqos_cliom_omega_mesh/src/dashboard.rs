use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use tokio::sync::broadcast;

pub fn create_dashboard_router(broadcaster: broadcast::Sender<String>) -> Router {
    Router::new()
        .route("/", get(serve_html))
        .route("/ws", get(ws_handler))
        .with_state(broadcaster)
}

async fn serve_html() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/index.html"))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(broadcaster): State<broadcast::Sender<String>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, broadcaster))
}

async fn handle_socket(mut socket: WebSocket, broadcaster: broadcast::Sender<String>) {
    let mut receiver = broadcaster.subscribe();
    let welcome = serde_json::json!({
        "status": "system",
        "message": "CLIOM dashboard connected; waiting for authenticated node telemetry"
    });
    if socket.send(Message::Text(welcome.to_string())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            event = receiver.recv() => {
                match event {
                    Ok(message) => {
                        if socket.send(Message::Text(message)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        let notice = serde_json::json!({
                            "status": "system",
                            "message": format!("Dashboard fell behind; skipped {skipped} telemetry events")
                        });
                        if socket.send(Message::Text(notice.to_string())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
