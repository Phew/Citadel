//! Multi-client integration test utilities.
//!
//! M0: stack health probes and shared constants.
//! M1+: F-flow harness, canary plaintext injection, adversarial suite hooks (K3/Opus).

use serde::Deserialize;

/// Default host for local docker-compose published ports.
pub const DEFAULT_HOST: &str = "127.0.0.1";

/// Service name + default published port for the M0 compose stack.
pub const SERVICE_ENDPOINTS: &[(&str, u16)] = &[
    ("auth-service", 8081),
    ("delivery-service", 8082),
    ("directory-service", 8083),
    ("blobstore-service", 8084),
];

/// JSON body returned by each service `/health` endpoint.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HealthBody {
    pub status: String,
    pub service: String,
    pub version: String,
}

impl HealthBody {
    pub fn is_ok(&self) -> bool {
        self.status == "ok"
    }
}

/// Build the health URL for a service on the default host.
pub fn health_url(port: u16) -> String {
    format!("http://{DEFAULT_HOST}:{port}/health")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_endpoint_table_is_complete() {
        assert_eq!(SERVICE_ENDPOINTS.len(), 4);
        let ports: Vec<u16> = SERVICE_ENDPOINTS.iter().map(|(_, p)| *p).collect();
        assert!(ports.contains(&8081));
        assert!(ports.contains(&8084));
    }

    #[test]
    fn health_url_shape() {
        assert_eq!(health_url(8081), "http://127.0.0.1:8081/health");
    }
}
