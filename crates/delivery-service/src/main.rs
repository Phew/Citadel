//! Delivery service binary.
//!
//! Connects to PostgreSQL (DATABASE_URL is required — a service without its
//! store is useless, and missing infrastructure must fail loudly, PLAN.md
//! §13), then serves the router: the M2 message path and the WS gateway
//! (ADR-0005). The service applies NO migrations at startup: schema changes
//! are the canonical citadel-migrate job's exclusive authority (ADR-0006 §1).

use delivery_service::server::{self, AppState};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tracing::info;

const SERVICE_NAME: &str = "delivery-service";
const DEFAULT_PORT: u16 = 8082;

#[tokio::main]
async fn main() {
    init_tracing();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required; delivery-service serves nothing without its store");
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await
        .expect("connect to PostgreSQL");

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = server::router(AppState::new(pool));

    info!(%addr, service = SERVICE_NAME, "listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind delivery-service");
    axum::serve(listener, app)
        .await
        .expect("serve delivery-service");
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
