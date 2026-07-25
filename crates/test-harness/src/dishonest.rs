//! A genuinely dishonest server for the adversarial suite (ADR-0005 §5).
//!
//! This is NOT a stubbed verifier: it is a live HTTP proxy that sits in
//! front of the real auth-service, forwards the KeyPackage fetch untouched
//! at the transport layer, and then rewrites the response body — serving
//! swapped KeyPackage bytes for the target account. The client under test
//! runs the exact fetch path it runs against an honest server and receives
//! exactly the bytes a compromised server would serve. Rejecting them is
//! the client's (INV-4) job, exercised end to end.

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use citadel_proto::auth::FetchKeyPackagesResponse;
use citadel_proto::ids::AccountId;

/// A running dishonest proxy. Dropping it stops the server.
pub struct DishonestKeyPackageServer {
    /// `http://127.0.0.1:<port>` — pass to the client under test in place
    /// of the real auth-service base URL.
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for DishonestKeyPackageServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[derive(Clone)]
struct ProxyState {
    upstream: String,
    http: reqwest::Client,
    /// The replacement package bytes served for EVERY package in the
    /// target account's fetch response.
    swapped: Vec<Vec<u8>>,
}

/// Spawn the dishonest proxy: `GET /v1/accounts/{id}/key-packages` is
/// forwarded to the real auth-service (bearer header passed through), and
/// every package in the response is replaced with the attacker's bytes.
/// Every other path 404s — the suite routes only the fetch through here,
/// so anything else reaching the proxy is a test bug that fails loudly.
pub async fn spawn_swapped_keypackage_proxy(
    upstream_auth_base: &str,
    swapped_packages: Vec<Vec<u8>>,
) -> Result<DishonestKeyPackageServer> {
    let state = ProxyState {
        upstream: upstream_auth_base.trim_end_matches('/').to_string(),
        http: reqwest::Client::new(),
        swapped: swapped_packages,
    };
    let app = Router::new()
        .route(
            "/v1/accounts/{id}/key-packages",
            get(swapped_fetch).fallback(fallback_404),
        )
        .fallback(fallback_404)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind dishonest proxy")?;
    let addr = listener.local_addr().context("proxy local addr")?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });
    Ok(DishonestKeyPackageServer {
        base_url: format!("http://{addr}"),
        shutdown: Some(shutdown_tx),
    })
}

async fn swapped_fetch(
    State(state): State<ProxyState>,
    Path(account_id): Path<AccountId>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let upstream = format!("{}/v1/accounts/{account_id}/key-packages", state.upstream);
    let mut req = state.http.get(&upstream);
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        req = req.header(axum::http::header::AUTHORIZATION, auth);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("dishonest proxy upstream failure: {e}"),
            )
                .into_response()
        }
    };
    let status = resp.status();
    if !status.is_success() {
        return (
            axum::http::StatusCode::from_u16(status.as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
            format!("upstream rejected the fetch with HTTP {status}"),
        )
            .into_response();
    }
    let mut body: FetchKeyPackagesResponse = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("upstream returned an undecodable body: {e}"),
            )
                .into_response()
        }
    };
    // The attack: every package the target's devices uploaded is replaced
    // with the attacker's. Device addressing metadata passes through —
    // only the key material is swapped, exactly the ADR-0005 §5 case.
    for (i, pkg) in body.packages.iter_mut().enumerate() {
        pkg.package =
            citadel_proto::auth::KeyPackageBytes(state.swapped[i % state.swapped.len()].clone());
    }
    Json(body).into_response()
}

async fn fallback_404() -> impl IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        "dishonest proxy serves only the swapped KeyPackage fetch",
    )
}
