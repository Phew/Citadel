//! WebSocket gateway (`/v1/gateway`, ADR-0005 §1): receive + subscription
//! control only. Sends NEVER arrive here — there is no send frame (decision
//! #4: one write path, so seq assignment and idempotency have one home).
//!
//! Connection lifecycle for an authenticated device:
//! 1. Push its undelivered welcomes as `Message` frames, then mark exactly
//!    those as delivered. This is at-least-once: if the socket dies
//!    mid-push, the unmarked rows redeliver on the next connect and the
//!    client dedups (MLS state / message id). Marking before pushing would
//!    be at-most-once and could lose a Welcome — the wrong tradeoff.
//! 2. Subscribe to the live fanout broadcast.
//! 3. Loop over socket frames and broadcast events: `Subscribe`/`Unsubscribe`
//!    manage a per-connection group set; fanned-out envelopes forward to the
//!    socket only for subscribed groups.
//!
//! Subscription authorization is spam hygiene, never confidentiality
//! (decision #5): a device may subscribe iff delivery metadata shows it as
//! an addressee/sender in G (`store::is_participant`); ciphertext is useless
//! to anyone else (INV-1) and MLS membership is the client-verified
//! authority (INV-4). All server frames are JSON text, `type`-tagged per
//! citadel_proto::delivery.

use axum::extract::ws::{Message as WsMessage, WebSocket};
use citadel_proto::delivery::{GatewayClientFrame, GatewayServerFrame};
use citadel_proto::error::ErrorCode;
use citadel_proto::ids::{DeviceId, GroupId};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use tokio::sync::broadcast::error::RecvError;

use crate::server::AppState;
use crate::store;

/// Serve one authenticated gateway connection until close or error.
pub async fn run(socket: WebSocket, state: AppState, device: DeviceId) {
    let (mut sink, mut stream) = socket.split();

    // ---- (1) F2 welcome delivery (ADR-0005 §1): push first, mark after.
    match store::undelivered_welcomes(&state.pool, device).await {
        Ok(welcomes) => {
            let mut pushed = Vec::with_capacity(welcomes.len());
            for (message_id, envelope) in welcomes {
                let frame = GatewayServerFrame::Message { envelope };
                let Ok(text) = serde_json::to_string(&frame) else {
                    continue;
                };
                if sink.send(WsMessage::Text(text.into())).await.is_err() {
                    // Socket died mid-push: nothing below is marked, so every
                    // welcome redelivers on the next connect (at-least-once).
                    return;
                }
                pushed.push(message_id);
            }
            if let Err(e) = store::mark_welcomes_delivered(&state.pool, device, &pushed).await {
                // Non-fatal: rows stay undelivered and the client dedups.
                tracing::warn!(error = %e, "could not mark welcomes delivered");
            }
        }
        Err(e) => {
            // Non-fatal: fanout still works; welcomes retry next connect.
            tracing::error!(error = %e, "undelivered-welcome query failed");
        }
    }

    // ---- (2) Live fanout subscription (before frame processing, so no
    // fanout between connect and subscribe is missed beyond what sync covers).
    let mut fanout_rx = state.fanout.subscribe();
    let mut subscribed: HashSet<GroupId> = HashSet::new();

    // ---- (3) Frame/event loop.
    loop {
        tokio::select! {
            frame = stream.next() => {
                match frame {
                    None | Some(Ok(WsMessage::Close(_))) => break,
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, "gateway socket receive error");
                        break;
                    }
                    Some(Ok(WsMessage::Text(text))) => {
                        if !handle_client_frame(&state, device, text.as_str(), &mut subscribed, &mut sink).await {
                            break;
                        }
                    }
                    // Ping/pong are answered by the ws layer; binary frames
                    // are not part of the v1 gateway contract.
                    Some(Ok(_)) => {}
                }
            }
            event = fanout_rx.recv() => {
                match event {
                    Ok((gid, envelope)) if subscribed.contains(&gid) => {
                        let frame = GatewayServerFrame::Message {
                            envelope: (*envelope).clone(),
                        };
                        match serde_json::to_string(&frame) {
                            Ok(text) => {
                                if sink.send(WsMessage::Text(text.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => tracing::error!(error = %e, "fanout frame serialize failed"),
                        }
                    }
                    // Not subscribed to this group: drop.
                    Ok(_) => {}
                    // Lagged: missed frames are recovered via GET ?after=
                    // sync (the seq cursor is the authoritative catch-up
                    // path); keep serving.
                    Err(RecvError::Lagged(n)) => {
                        tracing::debug!(missed = n, "gateway fanout lagged; client syncs")
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }
    }
}

/// Handle one client text frame. Returns false when the connection must
/// close (socket write failure).
async fn handle_client_frame(
    state: &AppState,
    device: DeviceId,
    text: &str,
    subscribed: &mut HashSet<GroupId>,
    sink: &mut futures_util::stream::SplitSink<WebSocket, WsMessage>,
) -> bool {
    let parsed: Result<GatewayClientFrame, _> = serde_json::from_str(text);
    match parsed {
        Ok(GatewayClientFrame::Subscribe { group_ids }) => {
            let mut accepted = Vec::new();
            let mut rejected = Vec::new();
            for gid in group_ids {
                // Decision #5: metadata-only authorization. A store error
                // fails closed (treated as not a participant).
                match store::is_participant(&state.pool, device, gid).await {
                    Ok(true) => {
                        subscribed.insert(gid);
                        accepted.push(gid);
                    }
                    Ok(false) => rejected.push(gid),
                    Err(e) => {
                        tracing::error!(error = %e, %gid, "participant check failed");
                        rejected.push(gid);
                    }
                }
            }
            if !accepted.is_empty() {
                let frame = GatewayServerFrame::Subscribed {
                    group_ids: accepted,
                };
                if !send_frame(sink, &frame).await {
                    return false;
                }
            }
            for gid in rejected {
                let frame = GatewayServerFrame::Error {
                    code: ErrorCode::Forbidden,
                    message: "not an addressee in this group (ADR-0005 §1)".to_string(),
                    group_id: Some(gid),
                };
                if !send_frame(sink, &frame).await {
                    return false;
                }
            }
            true
        }
        Ok(GatewayClientFrame::Unsubscribe { group_ids }) => {
            // The contract has no Unsubscribed frame: remove silently.
            for gid in group_ids {
                subscribed.remove(&gid);
            }
            true
        }
        Err(_) => {
            let frame = GatewayServerFrame::Error {
                code: ErrorCode::InvalidRequest,
                message: "unparseable gateway frame".to_string(),
                group_id: None,
            };
            send_frame(sink, &frame).await
        }
    }
}

async fn send_frame(
    sink: &mut futures_util::stream::SplitSink<WebSocket, WsMessage>,
    frame: &GatewayServerFrame,
) -> bool {
    match serde_json::to_string(frame) {
        Ok(text) => sink.send(WsMessage::Text(text.into())).await.is_ok(),
        Err(e) => {
            tracing::error!(error = %e, "gateway frame serialize failed");
            true
        }
    }
}
