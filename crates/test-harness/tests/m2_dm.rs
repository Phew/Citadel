//! M2 exit acceptance (PLAN.md §9 M2, ADR-0005 Evidence): encrypted DMs end
//! to end across 3 clients on the REAL compose stack, driven through
//! citadel-core's actual MLS engine (never a reimplementation) with KT
//! verification against the live log (INV-4).
//!
//! - `f2_three_client_dm_creation` — create + KT-verified join across 3
//!   clients; all converge on the same member COUNT and epoch. Membership
//!   identity is not compared: three different three-member trees at one
//!   epoch would satisfy these assertions (docs/issues/014). Comparing full
//!   member identity needs a deterministic membership view from citadel-core,
//!   which does not exist yet.
//! - `f4_send_receive_roundtrip` — application messages over REST submit,
//!   received via WS fanout AND via `GET ?after=` sync; the wire carries
//!   only ciphertext.
//! - `no_plaintext_scan_delivery_tables` — canary plaintext through the F4
//!   send path; zero hits in the delivery tables (and the fetched wire
//!   envelope carries no encoding of it), with non-vacuous coverage.
//! - `self_update_recovery_converges_all_members` — a member's self-update
//!   commit flows through the live delivery path; every member merges it,
//!   the epoch advances everywhere, and post-update messages round-trip.
//!   This is a recovery/convergence test: no compromised pre-update state is
//!   captured and no oracle attempts the post-update ciphertext, so it
//!   proves functional self-update recovery, NOT post-compromise security
//!   (docs/issues/014). The PCS evidence ADR-0007 §6 requires
//!   (`post_restart_update_proves_post_compromise_security`, the `mls-spec`/
//!   AWS-LC differential oracle) is unwritten; M2's PCS criterion is OPEN.
//! - `adversarial_ds_swapped_keypackage_rejected` — a genuinely dishonest
//!   server (live HTTP proxy rewriting the KeyPackage fetch, see
//!   `test_harness::dishonest`) serves a swapped package claiming the
//!   target's account; the initiator rejects it before any commit, Welcome,
//!   or server-side group state exists (INV-4).
//!
//! `device_compromise_past_messages_unreadable_fs` is deliberately ABSENT.
//! It was absent because MLS state was in-memory, so there was nothing to
//! capture and wipe and an "FS test" would have passed while proving
//! nothing. The local encrypted client store (ADR-0007) has since landed in
//! `citadel_core::store`, so persisted state now exists and the test is
//! writable — but it stays absent until it is written for real, against the
//! live stack, because a vacuous green test is still worse than a missing
//! one. The store-level proof
//! (`citadel_core::store::tests::post_restart_snapshot_proves_mls_forward_secrecy`)
//! is evidence the machinery works, not a substitute for this criterion.
//! `docs/status/core.md` names the persisted-state API this test drives.
//!
//! Ignored by default so plain `cargo test --workspace` stays infra-free,
//! but NEVER silently green: compose-smoke provisions the stack and runs
//! exactly these tests with `--include-ignored` (PLAN.md §13).

use anyhow::{bail, Context, Result};
use citadel_core::credential::CredentialError;
use citadel_core::group::{DmGroup, GroupError, ReceiveOutcome};
use citadel_proto::credential::{
    DeviceCredential, DeviceCredentialTbs, DevicePublicKey, IdentityPublicKey,
    Signature as ProtoSig,
};
use citadel_proto::delivery::{GatewayClientFrame, GatewayServerFrame};
use citadel_proto::envelope::EnvelopeKind;
use citadel_proto::ids::GroupId;
use test_harness::client::TestClient;
use test_harness::dbscan;
use test_harness::dishonest;
use test_harness::dm::{self, log_anchor, DmClient, GatewaySocket, LiveKtVerifier};
use test_harness::stack::{probe_client, require_stack};
use tls_codec::Serialize as _;
use zeroize::Zeroizing;

/// The fixture: `n` provisioned clients plus a KT verifier that has already
/// attested each one against the LIVE log.
async fn provision(tag: &str, n: usize) -> Result<(Vec<DmClient>, LiveKtVerifier)> {
    let http = probe_client().context("harness probe client must build")?;
    let endpoints = require_stack(&http)
        .await
        .context("compose stack must be up; CI provisions it before this test runs")?;
    let mut verifier = LiveKtVerifier::new(
        TestClient::new(http.clone(), endpoints.auth.clone()),
        log_anchor(),
    );

    let mut clients = Vec::with_capacity(n);
    for i in 0..n {
        let handle = format!("m2-{tag}-{i}-{}", uuid::Uuid::new_v4().simple());
        let (client, leaf) =
            DmClient::register(http.clone(), &endpoints.auth, &endpoints.delivery, &handle).await?;
        verifier.register_leaf(client.account_id, leaf);
        clients.push(client);
    }
    // The REAL KT verification for every party, done up front against the
    // live log; the sync IdentityVerifier then answers from verified facts
    // only (see test_harness::dm module docs).
    for c in &clients {
        if !verifier.attest(c.account_id, &c.identity_pubkey).await {
            bail!("KT attestation failed for {}", c.handle);
        }
    }
    Ok((clients, verifier))
}

/// An established DM group: every client's group state and live gateway
/// socket, aligned with the `clients` slice (initiator first).
struct Established {
    group_id: GroupId,
    groups: Vec<DmGroup>,
    sockets: Vec<GatewaySocket>,
}

/// F2 across the given clients: joiners publish KeyPackages, the initiator
/// fetches (consuming), creates the group, adds everyone in one commit,
/// submits the Welcome addressed to the joiners' devices; each joiner
/// receives it on gateway connect, verifies every member credential against
/// the KT log (inside citadel-core), joins, and subscribes. The initiator
/// subscribes too (it is the founding participant).
async fn establish_group(clients: &[DmClient], verifier: &LiveKtVerifier) -> Result<Established> {
    let (initiator, joiners) = clients.split_first().expect("at least one client");

    for j in joiners {
        j.publish_key_packages(1).await?;
    }
    let mut key_packages = Vec::new();
    for j in joiners {
        key_packages.extend(
            initiator
                .fetch_key_packages(j.auth.base(), j.account_id)
                .await?,
        );
    }

    let group_id = GroupId::new();
    let mut initiator_group = initiator.create_group(group_id)?;
    let out = initiator.add_members(&mut initiator_group, &key_packages, verifier)?;
    let recipient_ids = joiners.iter().map(|j| j.device_id).collect();
    initiator
        .submit(
            group_id,
            EnvelopeKind::Welcome,
            initiator_group.epoch(),
            &out.welcome_bytes,
            recipient_ids,
        )
        .await?;

    let mut groups = vec![initiator_group];
    let mut sockets = Vec::with_capacity(clients.len());

    for j in joiners {
        let mut ws = j.gateway_connect().await?;
        let welcome = dm::recv_message_for(&mut ws, group_id, EnvelopeKind::Welcome).await?;
        let welcome_bytes = welcome.payload_bytes().context("decode welcome payload")?;
        let group = j.join_from_welcome(&welcome_bytes, verifier)?;
        dm::send_frame(
            &mut ws,
            &GatewayClientFrame::Subscribe {
                group_ids: vec![group_id],
            },
        )
        .await?;
        match dm::recv_frame(&mut ws).await? {
            GatewayServerFrame::Subscribed { group_ids } => {
                if group_ids != vec![group_id] {
                    bail!("subscribe ack for wrong groups: {group_ids:?}");
                }
            }
            other => bail!("expected Subscribed, got {other:?}"),
        }
        groups.push(group);
        sockets.push(ws);
    }

    // The initiator subscribes as the founding participant.
    let mut ws = initiator.gateway_connect().await?;
    dm::send_frame(
        &mut ws,
        &GatewayClientFrame::Subscribe {
            group_ids: vec![group_id],
        },
    )
    .await?;
    match dm::recv_frame(&mut ws).await? {
        GatewayServerFrame::Subscribed { .. } => {}
        other => bail!("initiator expected Subscribed, got {other:?}"),
    }
    sockets.insert(0, ws);

    Ok(Established {
        group_id,
        groups,
        sockets,
    })
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn f2_three_client_dm_creation() -> Result<()> {
    let (clients, verifier) = provision("f2", 3).await?;
    let est = establish_group(&clients, &verifier).await?;

    // All three converge on identical membership and epoch (ADR-0005
    // Evidence: each target verified GroupInfo + every member credential
    // against the KT log inside citadel-core's join).
    for (client, group) in clients.iter().zip(est.groups.iter()) {
        assert_eq!(
            group.member_count(),
            3,
            "{} must see all three members",
            client.handle
        );
        assert_eq!(
            group.epoch(),
            est.groups[0].epoch(),
            "{} must converge on the initiator's epoch",
            client.handle
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn f4_send_receive_roundtrip() -> Result<()> {
    let (clients, verifier) = provision("f4", 3).await?;
    let mut est = establish_group(&clients, &verifier).await?;
    let (initiator, rest) = clients.split_first().expect("three clients");
    let gid = est.group_id;

    // ---- WS fanout: A sends; B and C receive live and decrypt to the
    // exact plaintext (unpad after decrypt inside citadel-core).
    let m1 = b"the operator cannot read this";
    initiator.send_text(&mut est.groups[0], gid, m1).await?;
    for (i, client) in rest.iter().enumerate() {
        let envelope = dm::recv_foreign_message_for(
            &mut est.sockets[i + 1],
            gid,
            EnvelopeKind::Application,
            client.device_id,
        )
        .await?;
        assert!(
            envelope.seq.is_some() && envelope.sender_device_id.is_some(),
            "fanned-out envelope must carry server-assigned seq and stamped sender"
        );
        match est.groups[i + 1]
            .receive(
                &client.provider,
                &envelope.payload_bytes().context("payload")?,
                &verifier,
            )
            .map_err(|e| anyhow::anyhow!("receive: {e}"))?
        {
            ReceiveOutcome::Application(plaintext) => assert_eq!(plaintext, m1),
            other => bail!("expected application plaintext, got {other:?}"),
        }
    }

    // ---- Bidirectional: B replies; A decrypts.
    let m2 = b"nor this";
    rest[0].send_text(&mut est.groups[1], gid, m2).await?;
    let reply_env = dm::recv_foreign_message_for(
        &mut est.sockets[0],
        gid,
        EnvelopeKind::Application,
        initiator.device_id,
    )
    .await?;
    match est.groups[0]
        .receive(
            &initiator.provider,
            &reply_env.payload_bytes().context("payload")?,
            &verifier,
        )
        .map_err(|e| anyhow::anyhow!("receive: {e}"))?
    {
        ReceiveOutcome::Application(plaintext) => assert_eq!(plaintext, m2),
        other => bail!("expected application plaintext, got {other:?}"),
    }

    // ---- Offline catch-up via GET ?after= (the authoritative cursor): C
    // drops its socket, A sends, C syncs from its last seq and decrypts.
    let c = &rest[1];
    let c_cursor = 2u64; // C processed the welcome (seq 1) and m1 (seq 2).
    est.sockets.pop(); // C's socket, aligned at index 2
    let m3 = b"catch-up over sync";
    initiator.send_text(&mut est.groups[0], gid, m3).await?;
    let page = c.sync(gid, c_cursor).await?;
    assert!(
        !page.messages.is_empty(),
        "sync must return the missed rows"
    );
    let mut synced = Vec::new();
    for envelope in &page.messages {
        if envelope.sender_device_id == Some(c.device_id) {
            continue; // a client never processes its own messages
        }
        if let Some(ReceiveOutcome::Application(plaintext)) =
            c.process_envelope(&mut est.groups[2], envelope, &verifier)?
        {
            synced.push(plaintext);
        }
    }
    // The page may also carry B's reply (seq 3) if it postdates C's cursor;
    // what must hold is that A's offline message arrives intact, in order.
    assert_eq!(
        synced.last().map(Vec::as_slice),
        Some(m3.as_slice()),
        "C must decrypt the missed message via sync, got {synced:?}"
    );
    assert!(
        page.messages.windows(2).all(|w| w[0].seq < w[1].seq),
        "seq must be ascending in a page"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn no_plaintext_scan_delivery_tables() -> Result<()> {
    let (clients, verifier) = provision("canary", 2).await?;
    let mut est = establish_group(&clients, &verifier).await?;
    let (initiator, rest) = clients.split_first().expect("two clients");
    let target = &rest[0];
    let gid = est.group_id;

    // Canary plaintext through the real F4 send path (INV-1: only
    // ciphertext may cross or persist).
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let canaries = test_harness::canary::generate(&run_id, 2);
    for canary in &canaries {
        initiator
            .send_text(&mut est.groups[0], gid, canary.as_bytes())
            .await?;
    }

    // The messages really flowed: the recipient syncs them back and
    // decrypts to the exact canaries (non-vacuous delivery).
    let page = target.sync(gid, 0).await?;
    let mut decrypted = Vec::new();
    for envelope in &page.messages {
        if envelope.sender_device_id == Some(target.device_id) {
            continue;
        }
        if let Some(ReceiveOutcome::Application(plaintext)) =
            target.process_envelope(&mut est.groups[1], envelope, &verifier)?
        {
            decrypted.push(String::from_utf8(plaintext).expect("canary is utf-8"));
        }
        // The wire itself must not carry the canary in any encoding —
        // not in the base64 envelope, not in the decoded MLS ciphertext.
        let payload = envelope.payload_bytes().context("payload")?;
        for canary in &canaries {
            for needle in test_harness::canary::encodings(canary) {
                assert!(
                    !envelope.payload_b64.contains(&needle),
                    "canary encoding found in the wire envelope"
                );
                assert!(
                    !payload
                        .windows(needle.len())
                        .any(|w| w == needle.as_bytes()),
                    "canary encoding found in the MLS ciphertext"
                );
            }
        }
    }
    assert_eq!(decrypted, canaries, "recipient must read both canaries");

    // The delivery tables must not contain the canary in any encoding
    // (dbscan renders every public table row, bytea as \x<hex>).
    let pool = dbscan::connect().await?;
    let mut hits = Vec::new();
    let coverage = dbscan::scan_all_tables(&pool, &canaries, &mut hits).await?;
    assert!(
        hits.is_empty(),
        "plaintext canary found server-side: {hits:?}"
    );
    assert!(
        coverage.tables_scanned > 0 && coverage.rows_scanned > 0,
        "scan covered nothing — vacuous verdict"
    );

    // Non-vacuous delivery evidence: the group's ciphertext rows and the
    // welcome addressing rows exist in the scanned tables.
    let message_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM group_messages WHERE mls_group_id = $1")
            .bind(gid.as_uuid())
            .fetch_one(&pool)
            .await?;
    assert!(
        message_rows >= 3,
        "welcome + 2 canary messages must be stored"
    );
    let welcome_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM welcome_deliveries wd \
         JOIN group_messages gm ON gm.id = wd.welcome_message_id \
         WHERE gm.mls_group_id = $1",
    )
    .bind(gid.as_uuid())
    .fetch_one(&pool)
    .await?;
    assert_eq!(welcome_rows, 1, "one welcome delivery row for the joiner");

    Ok(())
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
// Renamed from `pcs_recover_after_update` (docs/issues/014): every assertion
// here is a success assertion — a liveness proof of the self-update path, not
// a PCS proof. The name now says what the test is, and the ADR-0005 Evidence
// name stays reserved for the differential PCS oracle that is still unwritten.
async fn self_update_recovery_converges_all_members() -> Result<()> {
    let (clients, verifier) = provision("self-update", 3).await?;
    let mut est = establish_group(&clients, &verifier).await?;
    let gid = est.group_id;
    let epoch_before = est.groups[0].epoch();

    // Baseline: member B can still transact pre-update.
    clients[1]
        .send_text(&mut est.groups[1], gid, b"pre-update baseline")
        .await?;
    for i in [0usize, 2] {
        let envelope = dm::recv_foreign_message_for(
            &mut est.sockets[i],
            gid,
            EnvelopeKind::Application,
            clients[i].device_id,
        )
        .await?;
        match est.groups[i]
            .receive(
                &clients[i].provider,
                &envelope.payload_bytes().context("payload")?,
                &verifier,
            )
            .map_err(|e| anyhow::anyhow!("receive: {e}"))?
        {
            ReceiveOutcome::Application(p) => assert_eq!(p, b"pre-update baseline"),
            other => bail!("expected application, got {other:?}"),
        }
    }

    // B simulates post-compromise recovery: an MLS self-update rotating its
    // leaf, transported as a Commit envelope through the live stack.
    let prepared = est.groups[1]
        .prepare_self_update(&clients[1].provider, &clients[1].identity)
        .map_err(|e| anyhow::anyhow!("prepare self-update: {e}"))?;
    assert_eq!(prepared.proposed_epoch(), epoch_before + 1);
    clients[1]
        .submit(
            gid,
            EnvelopeKind::Commit,
            prepared.proposed_epoch(),
            prepared.commit_bytes(),
            vec![],
        )
        .await?;
    est.groups[1]
        .confirm_self_update(&clients[1].provider, &prepared)
        .map_err(|e| anyhow::anyhow!("confirm self-update: {e}"))?;

    // A and C receive the commit over fanout and merge it (citadel-core
    // KT-verifies the update-path leaf before merging).
    for i in [0usize, 2] {
        let envelope = dm::recv_foreign_message_for(
            &mut est.sockets[i],
            gid,
            EnvelopeKind::Commit,
            clients[i].device_id,
        )
        .await?;
        match est.groups[i]
            .receive(
                &clients[i].provider,
                &envelope.payload_bytes().context("payload")?,
                &verifier,
            )
            .map_err(|e| anyhow::anyhow!("merge commit: {e}"))?
        {
            ReceiveOutcome::CommitMerged { epoch } => {
                assert_eq!(epoch, prepared.proposed_epoch())
            }
            other => bail!("expected merged commit, got {other:?}"),
        }
    }

    // Convergence at the new epoch; post-update traffic round-trips in
    // both directions — the rotated leaf signs and decrypts.
    for group in &est.groups {
        assert_eq!(group.epoch(), prepared.proposed_epoch());
    }
    clients[0]
        .send_text(&mut est.groups[0], gid, b"post-update traffic round-trips")
        .await?;
    for i in [1usize, 2] {
        let envelope = dm::recv_foreign_message_for(
            &mut est.sockets[i],
            gid,
            EnvelopeKind::Application,
            clients[i].device_id,
        )
        .await?;
        match est.groups[i]
            .receive(
                &clients[i].provider,
                &envelope.payload_bytes().context("payload")?,
                &verifier,
            )
            .map_err(|e| anyhow::anyhow!("receive: {e}"))?
        {
            ReceiveOutcome::Application(p) => assert_eq!(p, b"post-update traffic round-trips"),
            other => bail!("expected application, got {other:?}"),
        }
    }

    Ok(())
}

#[tokio::test]
#[ignore = "requires live docker compose stack; CI compose-smoke job runs it"]
async fn adversarial_ds_swapped_keypackage_rejected() -> Result<()> {
    let (clients, mut verifier) = provision("adv", 2).await?;
    let (initiator, rest) = clients.split_first().expect("two clients");
    let target = &rest[0];

    // The target publishes genuine KeyPackages to its pool.
    target.publish_key_packages(2).await?;

    // CONTROL: the genuine package is accepted — the rejection below is
    // the KT check working, not a broken client.
    let honest = initiator
        .fetch_key_packages(target.auth.base(), target.account_id)
        .await?;
    let mut control_group = initiator.create_group(GroupId::new())?;
    initiator
        .add_members(&mut control_group, &honest, &verifier)
        .expect("the genuine KeyPackage must be accepted");

    // THE ATTACK (ADR-0005 §5): a KeyPackage that claims the target's
    // account but binds the attacker's identity and device keys, signed by
    // the attacker's identity key — well-formed and self-consistent, but
    // not what the KT log attests for that account.
    let attacker_identity = ed25519_dalek::SigningKey::from_bytes(&[0xE1; 32]);
    let attacker_device = ed25519_dalek::SigningKey::from_bytes(&[0xE2; 32]);
    let attacker_tbs = DeviceCredentialTbs {
        account_id: target.account_id, // claims the victim's account
        device_id: citadel_proto::ids::DeviceId::new(),
        identity_pubkey: IdentityPublicKey(attacker_identity.verifying_key().to_bytes()),
        device_pubkey: DevicePublicKey(attacker_device.verifying_key().to_bytes()),
        issued_at: 1_700_000_000,
    };
    let attacker_credential = DeviceCredential {
        signature: ProtoSig(
            ed25519_dalek::Signer::sign(&attacker_identity, &attacker_tbs.signing_input())
                .to_bytes(),
        ),
        tbs: attacker_tbs,
    };
    let attacker_identity_mls = citadel_core::identity::DeviceIdentity::from_parts(
        attacker_credential,
        Zeroizing::new(attacker_device.to_bytes()),
        attacker_device.verifying_key().to_bytes(),
    )
    .expect("the attacker's self-consistent identity builds");
    let attacker_provider = citadel_core::crypto::EphemeralProvider::default();
    let attacker_package = attacker_identity_mls
        .new_key_package(&attacker_provider)
        .expect("the attacker's KeyPackage builds")
        .tls_serialize_detached()
        .expect("serialize attacker package");

    // The dishonest DS: a live proxy that rewrites the target's fetch to
    // serve the attacker's bytes (test_harness::dishonest).
    let dishonest_ds =
        dishonest::spawn_swapped_keypackage_proxy(target.auth.base(), vec![attacker_package])
            .await?;

    // The initiator runs its REAL fetch path against the dishonest server.
    let swapped = initiator
        .fetch_key_packages(&dishonest_ds.base_url, target.account_id)
        .await?;
    assert_eq!(swapped.len(), 1, "one package per active device");

    // The swap really happened, byte-for-byte on the real path: the served
    // credential claims the victim's account with the attacker's keys.
    let leaf = swapped[0].leaf_node();
    let served: DeviceCredential = serde_json::from_slice(leaf.credential().serialized_content())
        .expect("served credential parses");
    assert_eq!(served.tbs.account_id, target.account_id);
    assert_eq!(
        served.tbs.identity_pubkey.0,
        attacker_identity.verifying_key().to_bytes()
    );

    // The KT log itself does not bind the victim's account to the
    // attacker's key — verified against the live log, not a static list.
    assert!(
        !verifier
            .attest(target.account_id, &served.tbs.identity_pubkey)
            .await,
        "the live KT log must not attest the attacker's key for the victim"
    );

    // INV-4: the initiator rejects the swapped package before any commit
    // or Welcome exists.
    let attack_gid = GroupId::new();
    let mut attack_group = initiator.create_group(attack_gid)?;
    let err = attack_group
        .add_members(
            &initiator.provider,
            &initiator.identity,
            &swapped,
            &verifier,
        )
        .expect_err("the swapped KeyPackage must be rejected");
    assert!(
        matches!(
            err,
            GroupError::MemberRejected(CredentialError::NotKtAttested)
        ),
        "expected NotKtAttested rejection, got {err:?}"
    );

    // No group is created server-side and nothing was ever submitted: the
    // attack group has zero rows on the delivery service.
    let page = initiator.sync(attack_gid, 0).await?;
    assert!(
        page.messages.is_empty(),
        "no message may exist for a group the client aborted"
    );

    Ok(())
}
