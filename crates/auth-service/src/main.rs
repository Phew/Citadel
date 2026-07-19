//! Auth service binary.
//!
//! Connects to PostgreSQL (DATABASE_URL is required — a service without its
//! store is useless, and missing infrastructure must fail loudly, PLAN.md
//! §13), applies the committed migrations, rebuilds the KT log from
//! `kt_leaves` with the fatal startup root check (ADR-0001 §4(c)), then
//! serves the router.

use auth_service::kt_store;
use auth_service::server::{self, AppState, KtState};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tracing::info;

const SERVICE_NAME: &str = "auth-service";
const DEFAULT_PORT: u16 = 8081;

#[tokio::main]
async fn main() {
    init_tracing();

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required; auth-service serves nothing without its store");
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&database_url)
        .await
        .expect("connect to PostgreSQL");
    auth_service::store::migrate(&pool)
        .await
        .expect("apply migrations");

    // ADR-0001 §3: the log signing seed comes from the service secret
    // store (M1: the CITADEL_KT_LOG_SEED env var, base64 of 32 bytes).
    // This is a server operational key, not user key material (INV-2).
    let signer = load_log_signer();

    // ADR-0001 §4(c): rebuild from kt_leaves and verify against the latest
    // persisted STH. A mismatch (tamper / partial write) is fatal — the
    // service must refuse to start, not serve a suspect log.
    let log = kt_store::rebuild_and_verify(&pool)
        .await
        .expect("KT startup root check failed; refusing to start");

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let app = server::router(AppState {
        pool,
        kt: Arc::new(KtState {
            log: Mutex::new(log),
            signer,
        }),
    });

    info!(%addr, service = SERVICE_NAME, "listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind auth-service");
    axum::serve(listener, app)
        .await
        .expect("serve auth-service");
}

fn load_log_signer() -> kt_log::TreeHeadSigner {
    let b64 = std::env::var("CITADEL_KT_LOG_SEED").expect(
        "CITADEL_KT_LOG_SEED is required (base64 of the 32-byte log signing seed); \
         the KT log may not serve unsigned heads",
    );
    let seed = B64
        .decode(b64.trim())
        .expect("CITADEL_KT_LOG_SEED is not valid base64");
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .expect("CITADEL_KT_LOG_SEED must decode to exactly 32 bytes");
    kt_log::TreeHeadSigner::from_seed(&seed)
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
