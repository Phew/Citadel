//! Blobstore service stub (M0).
//!
//! Stores only client-encrypted attachment bytes (INV-1). Real presigned upload
//! path and MinIO integration land in M5 (K3).

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::info;

const SERVICE_NAME: &str = "blobstore-service";
const DEFAULT_PORT: u16 = 8084;

#[tokio::main]
async fn main() {
    init_tracing();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .layer(TraceLayer::new_for_http());

    info!(%addr, service = SERVICE_NAME, "listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind blobstore-service");
    axum::serve(listener, app)
        .await
        .expect("serve blobstore-service");
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(health_body()))
}

async fn ready() -> impl IntoResponse {
    (StatusCode::OK, Json(health_body()))
}

fn health_body() -> Value {
    json!({
        "status": "ok",
        "service": SERVICE_NAME,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_body_names_service() {
        let body = health_body();
        assert_eq!(body["service"], SERVICE_NAME);
        assert_eq!(body["status"], "ok");
    }
}
