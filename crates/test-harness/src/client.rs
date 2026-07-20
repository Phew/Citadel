//! Typed HTTP client for driving services under test.
//!
//! Responses are decoded into `citadel-proto` types only (AGENTS.md rule 5:
//! proto is canonical for wire contracts). Rejections surface as the wire
//! [`ErrorResponse`] so tests assert on error codes, not message strings.

use citadel_proto::ErrorResponse;
use reqwest::{Client, StatusCode};
use serde::{de::DeserializeOwned, Serialize};

/// One service under test, addressed by base URL.
#[derive(Clone, Debug)]
pub struct TestClient {
    http: Client,
    base: String,
}

/// How a service call failed.
#[derive(Debug)]
pub enum ServiceError {
    /// The service rejected the call with the wire error contract.
    Rejected {
        status: StatusCode,
        error: ErrorResponse,
    },
    /// Transport, non-contract error body, or decode failure.
    Transport(anyhow::Error),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { status, error } => {
                write!(f, "service rejected with HTTP {status}: {error:?}")
            }
            Self::Transport(err) => write!(f, "transport failure: {err:#}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl TestClient {
    pub fn new(http: Client, base: impl Into<String>) -> Self {
        let mut base = base.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self { http, base }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// POST a JSON body, decoding a 2xx response into `Resp`.
    pub async fn post_json<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, ServiceError> {
        let resp = self.send(self.http.post(self.url(path)).json(body)).await?;
        decode_success(resp).await
    }

    /// POST a JSON body with a bearer token (ADR-0003 §2).
    pub async fn post_json_bearer<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
        body: &Req,
    ) -> Result<Resp, ServiceError> {
        let resp = self
            .send(self.http.post(self.url(path)).bearer_auth(token).json(body))
            .await?;
        decode_success(resp).await
    }

    /// GET a JSON resource, decoding a 2xx response into `Resp`.
    pub async fn get_json<Resp: DeserializeOwned>(&self, path: &str) -> Result<Resp, ServiceError> {
        let resp = self.send(self.http.get(self.url(path))).await?;
        decode_success(resp).await
    }

    /// GET a JSON resource with a bearer token (ADR-0003 §2).
    pub async fn get_json_bearer<Resp: DeserializeOwned>(
        &self,
        path: &str,
        token: &str,
    ) -> Result<Resp, ServiceError> {
        let resp = self
            .send(self.http.get(self.url(path)).bearer_auth(token))
            .await?;
        decode_success(resp).await
    }

    /// POST expecting rejection: returns the status and wire error contract.
    /// Succeeding here fails the caller's test — this is for negative paths.
    pub async fn post_json_expect_error<Req: Serialize>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<(StatusCode, ErrorResponse), ServiceError> {
        let resp = self.send(self.http.post(self.url(path)).json(body)).await?;
        decode_rejection(resp).await
    }

    /// GET expecting rejection, with a bearer token (negative paths on
    /// authenticated endpoints).
    pub async fn get_json_bearer_expect_error(
        &self,
        path: &str,
        token: &str,
    ) -> Result<(StatusCode, ErrorResponse), ServiceError> {
        let resp = self
            .send(self.http.get(self.url(path)).bearer_auth(token))
            .await?;
        decode_rejection(resp).await
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn send(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, ServiceError> {
        builder
            .send()
            .await
            .map_err(|e| ServiceError::Transport(anyhow::Error::new(e)))
    }
}

async fn decode_success<Resp: DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<Resp, ServiceError> {
    let status = resp.status();
    if status.is_success() {
        resp.json::<Resp>()
            .await
            .map_err(|e| ServiceError::Transport(anyhow::Error::new(e)))
    } else {
        Err(rejection(status, resp).await)
    }
}

async fn decode_rejection(
    resp: reqwest::Response,
) -> Result<(StatusCode, ErrorResponse), ServiceError> {
    let status = resp.status();
    if status.is_success() {
        return Err(ServiceError::Transport(anyhow::anyhow!(
            "expected an error response but the service returned HTTP {status}"
        )));
    }
    let error = resp
        .json::<ErrorResponse>()
        .await
        .map_err(|e| ServiceError::Transport(anyhow::Error::new(e)))?;
    Ok((status, error))
}

async fn rejection(status: StatusCode, resp: reqwest::Response) -> ServiceError {
    match resp.json::<ErrorResponse>().await {
        Ok(error) => ServiceError::Rejected { status, error },
        Err(e) => ServiceError::Transport(anyhow::Error::new(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_trailing_slashes_are_trimmed() {
        let http = Client::new();
        let c = TestClient::new(http, "http://127.0.0.1:8081///");
        assert_eq!(c.url("/health"), "http://127.0.0.1:8081/health");
    }
}
