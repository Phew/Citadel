//! Stack-backed smoke test: every service answers a valid `/health` through
//! the harness TestClient. Exercises the framework against the real compose
//! stack end to end.
//!
//! Ignored by default so plain `cargo test --workspace` stays infra-free, but
//! NEVER silently green: the CI `compose-smoke` job provisions the stack and
//! runs exactly these tests with `--include-ignored` (PLAN.md §13 — a green
//! check means the property was exercised).

use test_harness::client::TestClient;
use test_harness::stack::{probe_client, require_stack};
use test_harness::HealthBody;

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn all_services_healthy_via_test_client() {
    let http = probe_client().expect("harness probe client must build");
    let endpoints = require_stack(&http)
        .await
        .expect("compose stack must be up; CI provisions it before this test runs");

    for (name, base) in endpoints.all() {
        let client = TestClient::new(http.clone(), base);
        let health: HealthBody = client
            .get_json("/health")
            .await
            .unwrap_or_else(|e| panic!("{name} /health must answer: {e}"));
        assert!(health.is_ok(), "{name} reports status {:?}", health.status);
        assert_eq!(health.service, name, "{name} identity mismatch");
    }
}
