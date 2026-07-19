//! Live-stack discovery and loud health assertions.
//!
//! Hard rule (PLAN.md §13, scope rule 6): a harness test that cannot reach
//! its required infrastructure must FAIL, never skip or silently pass. CI
//! provisions the stack; a green check must mean the property was exercised.
//! Every stack-backed test starts with [`require_stack`] and propagates its
//! error instead of returning early.

use crate::{HealthBody, DEFAULT_HOST};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use std::time::Duration;

/// Base URLs for every service in the compose stack, resolved from
/// `CITADEL_{AUTH,DELIVERY,DIRECTORY,BLOBSTORE}_URL` with the published
/// localhost ports as defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackEndpoints {
    pub auth: String,
    pub delivery: String,
    pub directory: String,
    pub blobstore: String,
}

impl StackEndpoints {
    pub fn from_env() -> Self {
        let lookup = |env_key: &str, default_port: u16| {
            std::env::var(env_key)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| format!("http://{DEFAULT_HOST}:{default_port}"))
        };
        Self {
            auth: lookup("CITADEL_AUTH_URL", 8081),
            delivery: lookup("CITADEL_DELIVERY_URL", 8082),
            directory: lookup("CITADEL_DIRECTORY_URL", 8083),
            blobstore: lookup("CITADEL_BLOBSTORE_URL", 8084),
        }
    }

    /// `(service name, base URL)` for every service, in probe order.
    pub fn all(&self) -> [(&'static str, &str); 4] {
        [
            ("auth-service", self.auth.as_str()),
            ("delivery-service", self.delivery.as_str()),
            ("directory-service", self.directory.as_str()),
            ("blobstore-service", self.blobstore.as_str()),
        ]
    }
}

/// HTTP client for harness probes. Short timeouts: a hung service is a
/// failure to report, not a test to leave running.
pub fn probe_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build harness probe client")
}

/// Prove every service in the stack answers a valid `/health`, or fail
/// loudly with which service is missing and how to bring the stack up.
pub async fn require_stack(client: &Client) -> Result<StackEndpoints> {
    let endpoints = StackEndpoints::from_env();
    for (name, base) in endpoints.all() {
        let url = format!("{base}/health");
        let resp = client.get(&url).send().await.with_context(|| {
            format!("{name} unreachable at {url} — start the stack (just dev); harness tests fail loudly without it")
        })?;
        if !resp.status().is_success() {
            bail!("{name} at {url} returned HTTP {}", resp.status());
        }
        let body: HealthBody = resp
            .json()
            .await
            .with_context(|| format!("{name} at {url} returned a non-JSON health body"))?;
        if !body.is_ok() {
            bail!("{name} at {url} reports status {:?}", body.status);
        }
        if body.service != name {
            bail!("{name} at {url} identifies as {:?}", body.service);
        }
    }
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERVICE_ENDPOINTS;

    #[test]
    fn endpoints_default_to_compose_ports() {
        let eps = StackEndpoints::from_env();
        // Only assert shapes when the env overrides are absent; CI sets none.
        for (name, base) in eps.all() {
            assert!(base.starts_with("http"), "{name} base URL must be absolute");
        }
        let default = StackEndpoints {
            auth: format!("http://{DEFAULT_HOST}:8081"),
            delivery: format!("http://{DEFAULT_HOST}:8082"),
            directory: format!("http://{DEFAULT_HOST}:8083"),
            blobstore: format!("http://{DEFAULT_HOST}:8084"),
        };
        if std::env::var("CITADEL_AUTH_URL").is_err() {
            assert_eq!(eps, default);
        }
        // The table must cover exactly the M0 service set, in sync with
        // SERVICE_ENDPOINTS.
        let names: Vec<&str> = eps.all().iter().map(|(n, _)| *n).collect();
        let const_names: Vec<&str> = SERVICE_ENDPOINTS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, const_names);
    }
}
