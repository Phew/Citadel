//! Poll all M0 service `/health` endpoints until they succeed or timeout.
//!
//! Missing infrastructure must fail loudly (PLAN.md §13) — this binary exits
//! non-zero on timeout so `just dev` never reports a false-green stack.

use anyhow::{bail, Context, Result};
use std::time::{Duration, Instant};
use test_harness::{health_url, HealthBody, SERVICE_ENDPOINTS};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let timeout = parse_timeout();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("build HTTP client")?;

    let deadline = Instant::now() + timeout;
    info!(?timeout, "waiting for service health endpoints");

    loop {
        match check_all(&client).await {
            Ok(()) => {
                info!("all services healthy");
                return Ok(());
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    bail!("services not healthy within {:?}: {err}", timeout);
                }
                warn!(error = %err, "not ready yet");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn check_all(client: &reqwest::Client) -> Result<()> {
    for (name, port) in SERVICE_ENDPOINTS {
        let url = health_url(*port);
        let resp = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("{name} unreachable at {url}"))?;
        if !resp.status().is_success() {
            bail!("{name} returned HTTP {}", resp.status());
        }
        let body: HealthBody = resp
            .json()
            .await
            .with_context(|| format!("{name} returned non-JSON health body"))?;
        if !body.is_ok() {
            bail!("{name} status is {:?}", body.status);
        }
        if body.service != *name {
            bail!("{name} health.service mismatch: got {:?}", body.service);
        }
    }
    Ok(())
}

fn parse_timeout() -> Duration {
    let mut timeout_secs: u64 = 120;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--timeout-secs" {
            if let Some(v) = args.next() {
                timeout_secs = v.parse().unwrap_or(120);
            }
        }
    }
    Duration::from_secs(timeout_secs)
}
