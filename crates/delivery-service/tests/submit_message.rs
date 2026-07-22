//! M2 delivery store tests (ADR-0005 Evidence):
//! `submit_is_idempotent_and_seq_monotonic`, `submit_rejects_non_participant`
//! (Amendment 1 §B), bounded pagination, and welcome-delivery tracking.
//!
//! Runs against REAL PostgreSQL 16 only — never a mock (PLAN.md §13, scope
//! rule 6). Ignored by default so plain `cargo test` stays infra-free; the
//! CI `db-tests` job provisions postgres:16 and runs these with
//! `--include-ignored`. Without DATABASE_URL the tests fail loudly.
//!
//! Isolation: fresh random group/device UUIDs per case, never TRUNCATE —
//! these tests share one database with auth-service's db tests in the same
//! CI job, and truncation would race them mid-drain.

use std::collections::HashSet;

use citadel_proto::delivery::SubmitMessageRequest;
use citadel_proto::envelope::{Envelope, EnvelopeKind};
use citadel_proto::ids::{DeviceId, GroupId, MessageId};
use delivery_service::store::{self, StoreError, SubmitOutcome};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

fn db_url() -> String {
    std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must point at real PostgreSQL 16 for the delivery store tests; \
         CI db-tests job provisions it. Missing infrastructure is a failure, not a skip.",
    )
}

/// Connect and migrate. Delivery's migrator runs with `ignore_missing` so it
/// coexists with auth-service's rows in the shared `_sqlx_migrations` table.
async fn fresh_pool() -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(32)
        .connect(&db_url())
        .await
        .expect("connect to real PostgreSQL (CI provisions it)");
    store::migrate(&pool).await.expect("apply migrations");
    pool
}

fn request(gid: GroupId, kind: EnvelopeKind, epoch: u64, payload: &[u8]) -> SubmitMessageRequest {
    let mut envelope = Envelope::new(kind, Some(gid), payload);
    envelope.epoch = Some(epoch);
    SubmitMessageRequest {
        envelope,
        idempotency_key: Uuid::new_v4(),
        recipient_device_ids: vec![],
    }
}

fn welcome_request(
    gid: GroupId,
    epoch: u64,
    payload: &[u8],
    recipients: Vec<DeviceId>,
) -> SubmitMessageRequest {
    let mut req = request(gid, EnvelopeKind::Welcome, epoch, payload);
    req.recipient_device_ids = recipients;
    req
}

/// Found a group with a Welcome (Amendment 1 §B: the first submit must be a
/// Welcome) and return its assigned response.
async fn found_group(pool: &PgPool, founder: DeviceId, recipients: Vec<DeviceId>) -> GroupId {
    let gid = GroupId::new();
    let outcome = store::submit_message(
        pool,
        founder,
        gid,
        welcome_request(gid, 0, b"opaque-mls-welcome", recipients),
    )
    .await
    .expect("founding welcome must submit");
    match outcome {
        SubmitOutcome::Created(response, fanout) => {
            assert_eq!(response.seq, 1, "founding welcome takes seq 1");
            assert_eq!(response.group_id, gid);
            assert_eq!(fanout.seq, Some(1));
            assert_eq!(fanout.sender_device_id, Some(founder));
        }
        SubmitOutcome::Replayed(_) => panic!("fresh idempotency key cannot replay"),
    }
    gid
}

async fn message_count(pool: &PgPool, gid: GroupId) -> i64 {
    let row =
        sqlx::query("SELECT count(*)::bigint AS n FROM group_messages WHERE mls_group_id = $1")
            .bind(gid.as_uuid())
            .fetch_one(pool)
            .await
            .expect("count group_messages");
    row.get("n")
}

async fn group_row_exists(pool: &PgPool, gid: GroupId) -> bool {
    sqlx::query("SELECT 1 AS one FROM groups WHERE mls_group_id = $1")
        .bind(gid.as_uuid())
        .fetch_optional(pool)
        .await
        .expect("probe groups row")
        .is_some()
}

/// Race `n` distinct-key application submits from one participant and
/// return their assigned seqs.
async fn hammer_submits(pool: &PgPool, sender: DeviceId, gid: GroupId, n: usize) -> Vec<u64> {
    let mut tasks = Vec::new();
    for i in 0..n {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let req = request(
                gid,
                EnvelopeKind::Application,
                1,
                format!("opaque-ciphertext-{i}").as_bytes(),
            );
            match store::submit_message(&pool, sender, gid, req).await {
                Ok(SubmitOutcome::Created(response, _)) => Ok(response.seq),
                Ok(SubmitOutcome::Replayed(_)) => {
                    Err("distinct idempotency keys must never replay".to_string())
                }
                Err(e) => Err(format!("concurrent submit failed: {e}")),
            }
        }));
    }
    let mut seqs = Vec::with_capacity(n);
    for t in tasks {
        let seq = t.await.expect("submit task panicked");
        seqs.push(seq.expect("concurrent submit must succeed"));
    }
    seqs
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn submit_is_idempotent_and_seq_monotonic() {
    let pool = fresh_pool().await;
    let founder = DeviceId::new();
    let recipient = DeviceId::new();
    let gid = GroupId::new();

    // Found the group with a Welcome.
    let req = welcome_request(gid, 3, b"opaque-mls-welcome", vec![recipient]);
    let first = store::submit_message(&pool, founder, gid, req.clone())
        .await
        .expect("founding welcome");
    let SubmitOutcome::Created(original, _) = first else {
        panic!("first submit must create");
    };
    assert_eq!(original.seq, 1);
    assert_eq!(original.epoch, 3, "epoch is client-declared, echoed");

    // Replay the same idempotency key: identical assignment, no second row.
    let replayed = store::submit_message(&pool, founder, gid, req)
        .await
        .expect("replay must succeed");
    let SubmitOutcome::Replayed(replay) = replayed else {
        panic!("same idempotency key must replay, not create");
    };
    assert_eq!(replay, original, "replay echoes the original assignment");
    assert_eq!(message_count(&pool, gid).await, 1, "replay inserts nothing");

    // N concurrent distinct-key submits: gap-free, unique, exactly 2..=N+1.
    const N: usize = 32;
    let seqs = hammer_submits(&pool, founder, gid, N).await;
    let unique: HashSet<u64> = seqs.iter().copied().collect();
    assert_eq!(unique.len(), N, "seqs must be unique under concurrency");
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    let want: Vec<u64> = (2..=(N as u64 + 1)).collect();
    assert_eq!(sorted, want, "seqs must be gap-free after the welcome");
    assert_eq!(message_count(&pool, gid).await, 1 + N as i64);
}

#[test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
fn seq_gap_free_proptest_random_concurrency() {
    use proptest::test_runner::{Config, TestRunner};

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let pool = rt.block_on(fresh_pool());

    let mut runner = TestRunner::new(Config {
        cases: 8,
        ..Config::default()
    });
    let strategy = 2usize..=24;
    runner
        .run(&strategy, |n| {
            rt.block_on(async {
                let founder = DeviceId::new();
                let gid = found_group(&pool, founder, vec![DeviceId::new()]).await;
                let seqs = hammer_submits(&pool, founder, gid, n).await;
                let mut sorted = seqs.clone();
                sorted.sort_unstable();
                let want: Vec<u64> = (2..=(n as u64 + 1)).collect();
                if sorted != want {
                    return Err(format!(
                        "seq gap/dup under {n} racing submits: got {sorted:?}"
                    ));
                }
                Ok(())
            })
            .map_err(proptest::test_runner::TestCaseError::fail)
        })
        .expect("gap-free monotonic seq holds for randomized concurrency");
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn submit_rejects_non_participant() {
    let pool = fresh_pool().await;
    let founder = DeviceId::new();
    let recipient = DeviceId::new();
    let stranger = DeviceId::new();

    // (a) First submit to a fresh gid with kind != Welcome: Forbidden, AND
    // the groups row must NOT materialize (a rejected first submit returning
    // after the upsert would permanently lock the gid — Amendment 1 §B).
    let gid = GroupId::new();
    let err = store::submit_message(
        &pool,
        founder,
        gid,
        request(gid, EnvelopeKind::Application, 0, b"opaque"),
    )
    .await
    .expect_err("non-welcome first submit must be forbidden");
    assert!(
        matches!(err, StoreError::Forbidden(_)),
        "expected Forbidden, got {err:?}"
    );
    assert!(
        !group_row_exists(&pool, gid).await,
        "rejected first submit must not materialize the groups row"
    );

    // Found a real group.
    let gid = found_group(&pool, founder, vec![recipient]).await;
    let rows_before = message_count(&pool, gid).await;

    // (b) A stranger (not founder, not recipient) is Forbidden and inserts
    // nothing.
    let err = store::submit_message(
        &pool,
        stranger,
        gid,
        request(gid, EnvelopeKind::Application, 1, b"stranger-payload"),
    )
    .await
    .expect_err("stranger submit must be forbidden");
    assert!(matches!(err, StoreError::Forbidden(_)));
    assert_eq!(
        message_count(&pool, gid).await,
        rows_before,
        "rejected submit inserts no row"
    );

    // (c) A welcome RECIPIENT is a participant (predicate's third arm).
    let outcome = store::submit_message(
        &pool,
        recipient,
        gid,
        request(gid, EnvelopeKind::Application, 1, b"recipient-payload"),
    )
    .await
    .expect("welcome recipient may submit");
    assert!(matches!(outcome, SubmitOutcome::Created(_, _)));

    // (d) The founder keeps submitting.
    let outcome = store::submit_message(
        &pool,
        founder,
        gid,
        request(gid, EnvelopeKind::Application, 1, b"founder-payload"),
    )
    .await
    .expect("founder may keep submitting");
    let SubmitOutcome::Created(response, _) = outcome else {
        panic!("founder submit must create");
    };
    assert_eq!(response.seq, 3);
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn fetch_pages_are_bounded_and_complete() {
    let pool = fresh_pool().await;
    let founder = DeviceId::new();
    let gid = found_group(&pool, founder, vec![DeviceId::new()]).await;

    // 505 application messages after the founding welcome: 506 rows total,
    // seqs 1..=506.
    for i in 0..505u32 {
        let outcome = store::submit_message(
            &pool,
            founder,
            gid,
            request(
                gid,
                EnvelopeKind::Application,
                1,
                format!("page-payload-{i:04}").as_bytes(),
            ),
        )
        .await
        .expect("page-fill submit");
        assert!(matches!(outcome, SubmitOutcome::Created(_, _)));
    }

    // Page 1 (after=0): exactly MESSAGES_PAGE_LIMIT rows, has_more, cursor
    // at the last seq served.
    let page1 = store::fetch_messages(&pool, gid, 0)
        .await
        .expect("first page");
    assert_eq!(page1.group_id, gid);
    assert_eq!(page1.messages.len(), 500);
    assert!(page1.has_more);
    assert_eq!(page1.next_after, 500);
    assert_eq!(page1.messages[0].seq, Some(1));
    assert_eq!(page1.messages[499].seq, Some(500));
    // Synced envelopes are fully populated (ADR-0005 §1).
    let app = &page1.messages[1];
    assert_eq!(app.version, citadel_proto::envelope::WIRE_VERSION);
    assert_eq!(app.kind, EnvelopeKind::Application);
    assert_eq!(app.group_id, Some(gid));
    assert_eq!(app.epoch, Some(1));
    assert_eq!(app.sender_device_id, Some(founder));
    assert_eq!(
        app.payload_bytes().expect("payload re-encodes as base64"),
        b"page-payload-0000"
    );

    // Page 2 drains the rest and reports completion.
    let page2 = store::fetch_messages(&pool, gid, page1.next_after as i64)
        .await
        .expect("second page");
    assert_eq!(page2.messages.len(), 6);
    assert!(!page2.has_more);
    assert_eq!(page2.next_after, 506);
    assert_eq!(page2.messages[0].seq, Some(501));

    // An empty page echoes the cursor (fresh-sync semantics).
    let empty = store::fetch_messages(&pool, gid, 506)
        .await
        .expect("tail page");
    assert!(empty.messages.is_empty());
    assert!(!empty.has_more);
    assert_eq!(empty.next_after, 506);
}

#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn welcome_deliveries_track_recipients_and_delivery() {
    let pool = fresh_pool().await;
    let founder = DeviceId::new();
    let recip_b = DeviceId::new();
    let recip_c = DeviceId::new();

    // A Welcome with two recipients writes one delivery row each (F2
    // addressing, ADR-0005 §1).
    let gid = GroupId::new();
    let outcome = store::submit_message(
        &pool,
        founder,
        gid,
        welcome_request(gid, 0, b"opaque-mls-welcome", vec![recip_b, recip_c]),
    )
    .await
    .expect("welcome submit");
    let SubmitOutcome::Created(response, _) = outcome else {
        panic!("welcome submit must create");
    };
    let welcome_id: MessageId = response.message_id;

    let row = sqlx::query(
        "SELECT count(*)::bigint AS n FROM welcome_deliveries WHERE welcome_message_id = $1",
    )
    .bind(welcome_id.as_uuid())
    .fetch_one(&pool)
    .await
    .expect("count welcome_deliveries");
    let n: i64 = row.get("n");
    assert_eq!(n, 2, "one delivery row per recipient");

    // Each recipient sees exactly the pending welcome; the founder sees none.
    for recip in [recip_b, recip_c] {
        let pending = store::undelivered_welcomes(&pool, recip)
            .await
            .expect("undelivered welcomes");
        assert_eq!(pending.len(), 1);
        let (id, env) = &pending[0];
        assert_eq!(*id, welcome_id);
        assert_eq!(env.kind, EnvelopeKind::Welcome);
        assert_eq!(env.seq, Some(1));
        assert_eq!(env.group_id, Some(gid));
        assert_eq!(env.sender_device_id, Some(founder));
        assert_eq!(env.payload_bytes().unwrap(), b"opaque-mls-welcome");
    }
    assert!(store::undelivered_welcomes(&pool, founder)
        .await
        .unwrap()
        .is_empty());

    // Marking B's deliveries in this group (the Subscribe-path function)
    // clears only B; C's row is untouched.
    store::mark_welcomes_delivered_for_groups(&pool, recip_b, &[gid])
        .await
        .expect("mark delivered");
    assert!(store::undelivered_welcomes(&pool, recip_b)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store::undelivered_welcomes(&pool, recip_c)
            .await
            .unwrap()
            .len(),
        1,
        "marking one recipient must not clear the other"
    );

    // Marking is group-scoped: an unrelated gid touches nothing.
    store::mark_welcomes_delivered_for_groups(&pool, recip_c, &[GroupId::new()])
        .await
        .expect("mark for unrelated group");
    assert_eq!(
        store::undelivered_welcomes(&pool, recip_c)
            .await
            .unwrap()
            .len(),
        1,
        "an unrelated group must not clear the pending welcome"
    );
    store::mark_welcomes_delivered_for_groups(&pool, recip_c, &[gid])
        .await
        .expect("mark delivered");
    assert!(store::undelivered_welcomes(&pool, recip_c)
        .await
        .unwrap()
        .is_empty());
}

/// The founding race (Amendment 1 §B): two devices that are NEITHER members
/// race a first-Welcome to the same fresh gid. Founder status must be atomic
/// with groups-row creation (the upsert's rows_affected), so exactly one
/// transaction founds the group and the loser fails the participant check —
/// never admitted, never a second message row.
#[tokio::test]
#[ignore = "requires real PostgreSQL; CI db-tests job runs it"]
async fn founding_race_admits_only_winning_founder() {
    let pool = fresh_pool().await;

    for round in 0..16u32 {
        let gid = GroupId::new();
        let dev_a = DeviceId::new();
        let dev_b = DeviceId::new();
        // Disjoint addressing: neither racer is an addressee of the other's
        // welcome, so the loser has no participant claim on the winner's row.
        let recip_a = DeviceId::new();
        let recip_b = DeviceId::new();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let race = |device: DeviceId, recip: DeviceId, tag: &str| {
            let pool = pool.clone();
            let barrier = barrier.clone();
            let req = welcome_request(
                gid,
                0,
                format!("race-welcome-{round}-{tag}").as_bytes(),
                vec![recip],
            );
            tokio::spawn(async move {
                barrier.wait().await;
                store::submit_message(&pool, device, gid, req).await
            })
        };
        let (res_a, res_b) = (race(dev_a, recip_a, "a"), race(dev_b, recip_b, "b"));
        let res_a = res_a.await.expect("racer A panicked");
        let res_b = res_b.await.expect("racer B panicked");

        let created = [&res_a, &res_b]
            .iter()
            .filter(|r| matches!(r, Ok(SubmitOutcome::Created(_, _))))
            .count();
        let forbidden = [&res_a, &res_b]
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Forbidden(_))))
            .count();
        assert_eq!(
            (created, forbidden),
            (1, 1),
            "round {round}: exactly one founder may be admitted, got A={res_a:?} B={res_b:?}"
        );

        // One message row, seq 1, addressed only by the winner's welcome.
        assert_eq!(
            message_count(&pool, gid).await,
            1,
            "round {round}: exactly one group_messages row"
        );
        let page = store::fetch_messages(&pool, gid, 0).await.expect("sync");
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].seq, Some(1));

        let (loser, loser_device) = if matches!(res_a, Ok(SubmitOutcome::Created(_, _))) {
            (&res_b, dev_b)
        } else {
            (&res_a, dev_a)
        };
        assert!(
            matches!(loser, Err(StoreError::Forbidden(_))),
            "round {round}: the loser must be Forbidden"
        );
        let deliveries = store::undelivered_welcomes(&pool, recip_a)
            .await
            .unwrap()
            .len()
            + store::undelivered_welcomes(&pool, recip_b)
                .await
                .unwrap()
                .len();
        assert_eq!(
            deliveries, 1,
            "round {round}: only the winner's welcome_deliveries rows exist"
        );

        // The loser stays rejected on retry — no silent admission.
        let retry = store::submit_message(
            &pool,
            loser_device,
            gid,
            welcome_request(gid, 0, b"race-retry", vec![DeviceId::new()]),
        )
        .await;
        assert!(
            matches!(retry, Err(StoreError::Forbidden(_))),
            "round {round}: the loser must stay Forbidden on retry, got {retry:?}"
        );
        assert_eq!(message_count(&pool, gid).await, 1);
    }
}
