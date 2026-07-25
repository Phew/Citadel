//! citadel-migrate: the migration runner binary (ADR-0006 §1).
//!
//! The only production component that applies schema changes to the shared
//! database. Deployment runs this artifact as an explicit migration job
//! (Compose: the one-shot `migrate` service) BEFORE any service version that
//! requires the new schema starts; failure is a non-zero exit and services
//! stay stopped.

use sqlx::postgres::PgPoolOptions;
use std::process::ExitCode;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();

    let database_url = std::env::var("DATABASE_URL").expect(
        "DATABASE_URL is required; citadel-migrate applies the canonical corpus (ADR-0006) \
         and cannot run without its database",
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect to PostgreSQL");

    match citadel_migrations::migrate(&pool).await {
        Ok(()) => {
            info!("canonical migration job complete (corpus applied or already at head)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Fatal and loud (PLAN.md §13): the migration job failing must
            // stop the rollout, not be retried into a divergent history.
            tracing::error!(error = %e, "canonical migration job failed");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}
