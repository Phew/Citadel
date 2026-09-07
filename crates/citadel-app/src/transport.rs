//! HTTP and WebSocket transports to auth-service and delivery-service.
//!
//! JSON over HTTP(S) for requests, JSON text frames over ws(s) for the
//! gateway, exactly the `citadel-proto` contracts. Nothing here interprets
//! message content: envelopes are opaque base64 payloads in both directions.

use crate::error::AppError;
use citadel_proto::auth::{
    ChallengeRequest, ChallengeResponse, EnrollDeviceRequest, EnrollDeviceResponse,
    FetchKeyPackagesResponse, PublishKeyPackagesRequest, PublishKeyPackagesResponse,
    RegisterAccountRequest, RegisterAccountResponse, VerifyRequest, VerifyResponse,
};
use citadel_proto::delivery::{
    GatewayClientFrame, GatewayServerFrame, MessagesPage, SubmitMessageRequest,
    SubmitMessageResponse,
};
use citadel_proto::error::ErrorResponse;
use citadel_proto::ids::{AccountId, DeviceId, GroupId};
use citadel_proto::kt::{ConsistencyProof, KtLeafInfo, KtProofResponse, SignedTreeHead};
use futures_util::{SinkExt, StreamExt};
use serde::{de::DeserializeOwned, Serialize};
use tokio_tungstenite::tungstenite;

/// One base URL plus a shared `reqwest` client.
#[derive(Clone, Debug)]
pub struct HttpClient {
    http: reqwest::Client,
    base: String,
}

impl HttpClient {
    pub fn new(http: reqwest::Client, base: impl Into<String>) -> Self {
        let mut base = base.into();
        while base.ends_with('/') {
            base.pop();
        }
        Self { http, base }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    async fn run<Resp: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<Resp, AppError> {
        let response = builder.send().await.map_err(AppError::transport)?;
        let status = response.status();
        if status.is_success() {
            return response.json::<Resp>().await.map_err(AppError::transport);
        }
        let body = response.text().await.map_err(AppError::transport)?;
        match serde_json::from_str::<ErrorResponse>(&body) {
            Ok(error) => Err(AppError::Rejected {
                status: status.as_u16(),
                code: error.code,
                message: error.message,
            }),
            Err(_) => Err(AppError::Transport(format!(
                "HTTP {status} with a non-JSON body: {}",
                body.chars().take(200).collect::<String>()
            ))),
        }
    }

    pub async fn get<Resp: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
    ) -> Result<Resp, AppError> {
        let mut builder = self.http.get(self.url(path));
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
        self.run(builder).await
    }

    pub async fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &Req,
    ) -> Result<Resp, AppError> {
        let mut builder = self.http.post(self.url(path)).json(body);
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
        self.run(builder).await
    }
}

/// auth-service.
#[derive(Clone, Debug)]
pub struct AuthApi(pub HttpClient);

impl AuthApi {
    pub async fn register(
        &self,
        request: &RegisterAccountRequest,
    ) -> Result<RegisterAccountResponse, AppError> {
        self.0.post("/v1/accounts", None, request).await
    }

    pub async fn enroll(
        &self,
        token: &str,
        request: &EnrollDeviceRequest,
    ) -> Result<EnrollDeviceResponse, AppError> {
        self.0.post("/v1/devices", Some(token), request).await
    }

    pub async fn challenge(&self, device_id: DeviceId) -> Result<ChallengeResponse, AppError> {
        self.0
            .post("/v1/auth/challenge", None, &ChallengeRequest { device_id })
            .await
    }

    pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, AppError> {
        self.0.post("/v1/auth/verify", None, request).await
    }

    pub async fn publish_key_packages(
        &self,
        token: &str,
        device_id: DeviceId,
        request: &PublishKeyPackagesRequest,
    ) -> Result<PublishKeyPackagesResponse, AppError> {
        self.0
            .post(
                &format!("/v1/devices/{device_id}/key-packages"),
                Some(token),
                request,
            )
            .await
    }

    /// Consumes one KeyPackage per device of `account` (ADR-0003 §4).
    pub async fn fetch_key_packages(
        &self,
        token: &str,
        account: AccountId,
    ) -> Result<FetchKeyPackagesResponse, AppError> {
        self.0
            .get(&format!("/v1/accounts/{account}/key-packages"), Some(token))
            .await
    }

    pub async fn tree_head(&self) -> Result<SignedTreeHead, AppError> {
        self.0.get("/v1/kt/tree-head", None).await
    }

    pub async fn proof(&self, leaf: u64, tree_size: u64) -> Result<KtProofResponse, AppError> {
        self.0
            .get(
                &format!("/v1/kt/proof?leaf={leaf}&tree_size={tree_size}"),
                None,
            )
            .await
    }

    pub async fn consistency(&self, first: u64, second: u64) -> Result<ConsistencyProof, AppError> {
        self.0
            .get(
                &format!("/v1/kt/consistency?first={first}&second={second}"),
                None,
            )
            .await
    }

    pub async fn leaf_by_account(&self, account: AccountId) -> Result<KtLeafInfo, AppError> {
        self.0
            .get(&format!("/v1/kt/leaf?account={account}"), None)
            .await
    }

    pub async fn leaf_by_handle(&self, handle: &str) -> Result<KtLeafInfo, AppError> {
        let encoded: String = handle
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                other => format!("%{other:02X}"),
            })
            .collect();
        self.0
            .get(&format!("/v1/kt/leaf?handle={encoded}"), None)
            .await
    }
}

/// delivery-service.
#[derive(Clone, Debug)]
pub struct DeliveryApi(pub HttpClient);

impl DeliveryApi {
    pub async fn submit(
        &self,
        token: &str,
        request: &SubmitMessageRequest,
    ) -> Result<SubmitMessageResponse, AppError> {
        let group_id = request
            .envelope
            .group_id
            .ok_or_else(|| AppError::MalformedEnvelope("submit without a group id".into()))?;
        self.0
            .post(
                &format!("/v1/groups/{group_id}/messages"),
                Some(token),
                request,
            )
            .await
    }

    pub async fn fetch(
        &self,
        token: &str,
        group_id: GroupId,
        after: u64,
    ) -> Result<MessagesPage, AppError> {
        self.0
            .get(
                &format!("/v1/groups/{group_id}/messages?after={after}"),
                Some(token),
            )
            .await
    }

    /// Open the gateway. Bearer auth happens on the HTTP upgrade, so a bad
    /// token is a plain 401 before any socket exists.
    pub async fn gateway(&self, token: &str) -> Result<Gateway, AppError> {
        let ws_base = if let Some(rest) = self.0.base().strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.0.base().strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            return Err(AppError::Transport(format!(
                "delivery base url must be http(s): {}",
                self.0.base()
            )));
        };
        let url = format!("{ws_base}/v1/gateway");
        let host = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .ok_or_else(|| AppError::Transport(format!("gateway url has no host: {url}")))?
            .to_string();
        let request = tungstenite::http::Request::builder()
            .uri(&url)
            .header("Host", &host)
            .header("Authorization", format!("Bearer {token}"))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .map_err(AppError::transport)?;
        let (socket, response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(AppError::transport)?;
        if response.status() != 101 {
            return Err(AppError::Transport(format!(
                "gateway upgrade returned HTTP {}",
                response.status()
            )));
        }
        Ok(Gateway { socket })
    }
}

pub type WebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A live gateway connection.
pub struct Gateway {
    socket: WebSocket,
}

impl Gateway {
    pub async fn send(&mut self, frame: &GatewayClientFrame) -> Result<(), AppError> {
        let text = serde_json::to_string(frame).map_err(AppError::transport)?;
        self.socket
            .send(tungstenite::Message::Text(text.into()))
            .await
            .map_err(AppError::transport)
    }

    /// The next server frame, or `GatewayClosed`. Non-text frames (pings are
    /// answered by tungstenite itself) are skipped.
    pub async fn next(&mut self) -> Result<GatewayServerFrame, AppError> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .ok_or(AppError::GatewayClosed)?
                .map_err(AppError::transport)?;
            match message {
                tungstenite::Message::Text(text) => {
                    return serde_json::from_str(&text).map_err(|error| {
                        AppError::MalformedEnvelope(format!("gateway frame: {error}"))
                    });
                }
                tungstenite::Message::Close(_) => return Err(AppError::GatewayClosed),
                _ => continue,
            }
        }
    }
}
