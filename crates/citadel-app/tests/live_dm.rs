//! The app core against the live compose stack: two devices register, one
//! KT-verifies the other by handle, creates a DM, and they exchange messages
//! — one receiving over the gateway, the other over REST sync — and the
//! conversation survives a restart of the process that owns it.
//!
//! `#[ignore]` by default; run with `--include-ignored`. It FAILS when the
//! stack is absent (PLAN.md §13), it never skips.

use citadel_app::{AppEvent, CitadelApp, Config};
use citadel_core::store::credentials::double::CredentialStoreDouble;
use citadel_core::store::{CredentialStore, ProfilePaths};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

fn open(config: &Config, root: &std::path::Path) -> (Arc<CitadelApp>, Arc<CredentialStoreDouble>) {
    let credentials = Arc::new(CredentialStoreDouble::new());
    let app = CitadelApp::open(
        config.clone(),
        ProfilePaths::at_root(root.join("profile")),
        credentials.clone() as Arc<dyn CredentialStore>,
    )
    .expect("open profile");
    (app, credentials)
}

async fn wait_for(
    events: &mut broadcast::Receiver<AppEvent>,
    what: &str,
    mut predicate: impl FnMut(&AppEvent) -> bool,
) -> AppEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = tokio::time::timeout(remaining, events.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("event channel open");
        if let AppEvent::Warning(text) = &event {
            eprintln!("warning: {text}");
        }
        if predicate(&event) {
            return event;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the compose stack; run with --include-ignored (fails, never skips, when absent)"]
async fn two_devices_exchange_an_encrypted_dm_through_the_live_stack() {
    let _ = tracing_subscriber::fmt::try_init();
    let probe = test_harness::stack::probe_client().expect("http client");
    test_harness::stack::require_stack(&probe)
        .await
        .expect("the compose stack must be up (just dev)");
    let config = Config::dev();

    let alice_dir = tempfile::tempdir().expect("tempdir");
    let bob_dir = tempfile::tempdir().expect("tempdir");
    let alice_root = alice_dir.path().canonicalize().expect("canonical");
    let bob_root = bob_dir.path().canonicalize().expect("canonical");
    let (alice, alice_credentials) = open(&config, &alice_root);
    let (bob, _) = open(&config, &bob_root);

    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let alice_handle = format!("alice-{suffix}");
    let bob_handle = format!("bob-{suffix}");
    assert!(alice.profile().unwrap().is_none());
    let alice_profile = alice
        .register(&alice_handle)
        .await
        .expect("alice registers");
    let bob_profile = bob.register(&bob_handle).await.expect("bob registers");
    assert_eq!(alice.profile().unwrap().as_ref(), Some(&alice_profile));

    // Bob goes online first, so the Welcome must reach him LIVE, not only on
    // a reconnect.
    let mut bob_events = bob.events();
    let bob_gateway = {
        let bob = bob.clone();
        tokio::spawn(async move { bob.run_gateway().await })
    };
    wait_for(&mut bob_events, "bob's gateway", |e| {
        matches!(e, AppEvent::GatewayConnected)
    })
    .await;

    // Alice KT-verifies Bob by handle and opens the DM.
    let bob_info = alice.lookup(&bob_handle).await.expect("lookup bob");
    assert_eq!(bob_info.account_id, bob_profile.account_id);
    assert_eq!(bob_info.identity_pubkey.0, bob_profile.identity_pubkey);
    let group_id = alice
        .create_dm(&[bob_info.account_id], Some("alice & bob".into()))
        .await
        .expect("create dm");
    alice
        .send(group_id, b"hello bob")
        .await
        .expect("alice sends");

    wait_for(
        &mut bob_events,
        "bob to join",
        |e| matches!(e, AppEvent::ConversationJoined(g) if *g == group_id),
    )
    .await;
    wait_for(&mut bob_events, "bob to receive alice's message", |e| {
        matches!(e, AppEvent::MessageReceived { group_id: g, plaintext, .. }
            if *g == group_id && plaintext == b"hello bob")
    })
    .await;
    let bob_messages = bob.messages(group_id).expect("bob messages");
    assert_eq!(bob_messages.len(), 1);
    assert!(!bob_messages[0].outgoing);

    // Bob replies; Alice catches up over REST sync, no gateway needed.
    bob.send(group_id, b"hi alice").await.expect("bob sends");
    alice.sync().await.expect("alice syncs");
    let alice_messages = alice.messages(group_id).expect("alice messages");
    assert_eq!(
        alice_messages
            .iter()
            .map(|m| (m.outgoing, m.plaintext.clone()))
            .collect::<Vec<_>>(),
        vec![(true, b"hello bob".to_vec()), (false, b"hi alice".to_vec())]
    );
    // Neither side holds the other's plaintext in the clear on the wire: the
    // harness canary scan covers the server; here we only assert the peer
    // list is KT-backed on both ends.
    assert!(alice
        .store()
        .peers()
        .unwrap()
        .iter()
        .any(|p| p.account_id == bob_profile.account_id));
    assert!(bob
        .store()
        .peers()
        .unwrap()
        .iter()
        .any(|p| p.account_id == alice_profile.account_id));

    // Restart Alice: same profile directory, same credential store, a fresh
    // process. Login, history, and the group all survive.
    bob_gateway.abort();
    drop(alice);
    let alice2 = CitadelApp::open(
        config.clone(),
        ProfilePaths::at_root(alice_root.join("profile")),
        alice_credentials as Arc<dyn CredentialStore>,
    )
    .expect("reopen alice");
    assert_eq!(alice2.profile().unwrap(), Some(alice_profile.clone()));
    alice2.login().await.expect("alice logs in again");
    assert_eq!(alice2.messages(group_id).unwrap().len(), 2);
    bob.send(group_id, b"still there?")
        .await
        .expect("bob sends again");
    alice2.sync().await.expect("alice syncs after restart");
    let last = alice2.messages(group_id).unwrap().pop().unwrap();
    assert_eq!(last.plaintext, b"still there?");
    assert!(!last.outgoing);
}
